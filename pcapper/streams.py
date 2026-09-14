from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .pcap_cache import PcapMeta, iter_packets
from .reassembly import reassemble
from .utils import (
    env_int,
    extract_packet_endpoints,
    packet_length,
    safe_float,
    tcp_flags_int,
    tcp_flags_text,
)

try:
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    IPv6 = None  # type: ignore
    Raw = None  # type: ignore


STREAM_MAX_BYTES = 4 * 1024 * 1024
# Per-direction cap above, and a cap on the total retained across *all*
# streams: a capture with 100 k connections could otherwise hold gigabytes.
STREAM_TOTAL_MAX_BYTES = env_int("PCAPPER_STREAM_TOTAL_MAX_BYTES", 512 * 1024 * 1024, minimum=1)


@dataclass
class StreamRecord:
    stream_id: str
    src: str
    dst: str
    src_port: int
    dst_port: int
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    packets: int
    bytes: int
    first_seen: Optional[float]
    last_seen: Optional[float]
    first_packet_number: Optional[int]
    syn_packet_number: Optional[int]
    client_payload_preview: bytes
    server_payload_preview: bytes
    client_gaps: list[dict[str, int]]
    server_gaps: list[dict[str, int]]
    # TCP connection state derived from the handshake, NOT from reassembly.
    # "established" = full 3-way handshake observed; "syn-only" = SYN(s) sent but
    # never answered (blocked/dropped egress, scans); "half-open" = SYN-ACK seen
    # but no final ACK; "refused" = SYN answered with RST; "reset" = RST without a
    # captured SYN; "no-handshake" = data/flags seen without a captured SYN.
    conn_state: str = "unknown"


@dataclass
class StreamPacketDetail:
    packet_number: int
    ts: Optional[float]
    direction: str
    src: str
    dst: str
    src_port: int
    dst_port: int
    flags: str
    seq: int
    ack: int
    window: int
    packet_bytes: int
    payload_bytes: int


@dataclass
class StreamSummary:
    path: Path
    total_streams: int
    streams: list[StreamRecord]
    top_streams: list[str]
    errors: list[str]
    observed_streams: int = 0
    followed_stream_id: Optional[str] = None
    followed_client_payload: Optional[bytes] = None
    followed_server_payload: Optional[bytes] = None
    followed_client_gaps: list[dict[str, int]] | None = None
    followed_server_gaps: list[dict[str, int]] | None = None
    followed_packets: list[StreamPacketDetail] | None = None
    lookup_stream_id: Optional[str] = None
    lookup_tuple: Optional[str] = None
    streams_full: bool = False
    stream_search: Optional[str] = None
    filter_ip: Optional[str] = None
    filter_port: Optional[int] = None
    established_only: bool = False
    view_content: bool = False


def _canonical_key(
    src: str, dst: str, sport: int, dport: int
) -> tuple[str, int, str, int]:
    left = (src, sport)
    right = (dst, dport)
    if left <= right:
        return (src, sport, dst, dport)
    return (dst, dport, src, sport)


def _stream_id(src: str, sport: int, dst: str, dport: int) -> str:
    raw = f"{src}:{sport}<->{dst}:{dport}"
    return hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _client_server_tuple(
    src: str,
    sport: int,
    dst: str,
    dport: int,
    syn_dir: object,
) -> tuple[str, int, str, int]:
    if syn_dir == "ab":
        return src, sport, dst, dport
    if syn_dir == "ba":
        return dst, dport, src, sport

    # Fallback when handshake direction is unavailable: lower well-known port is likely server.
    if sport == dport:
        return src, sport, dst, dport
    if sport < dport:
        return dst, dport, src, sport
    return src, sport, dst, dport


def _conn_state(
    info: dict, has_client_payload: bool, has_server_payload: bool
) -> str:
    """Classify a stream's TCP connection state from observed handshake flags.

    This is deliberately distinct from reassembly completeness: a SYN-only flow
    that never connected carries no data, so it has no reassembly gaps and would
    otherwise look "complete". The state below reflects whether the TCP
    connection actually came up.
    """
    if info.get("established"):
        return "established"
    if info.get("synack_seen"):
        return "half-open"
    saw_syn = info.get("syn_pkt") is not None
    if saw_syn and info.get("rst_seen"):
        return "refused"
    if saw_syn:
        return "syn-only"
    # No SYN captured. If application data flowed in BOTH directions the session
    # was clearly up -- the capture just started after the handshake.
    if has_client_payload and has_server_payload:
        return "active"
    if info.get("rst_seen"):
        return "reset"
    return "no-handshake"


def _reassemble(
    segments: list[tuple[int, bytes]], max_bytes: int
) -> tuple[bytes, list[dict[str, int]]]:
    """Rebuild one direction of a stream for preview and search.

    Delegates to the shared implementation so stream following and carving
    cannot drift apart again — in particular so both order segments in stream
    space rather than by raw 32-bit sequence number, which mis-assembles any
    stream whose ISN sits high enough to wrap mid-transfer.

    Gaps are recorded but *not* zero-filled here: these bytes become payload
    previews and the ``--follow``/search corpus, where padding a snaplen-
    truncated capture with NUL runs would crowd real content out of the preview
    budget. Carving makes the opposite choice, for the reasons in
    ``carving._reassemble``.
    """
    result = reassemble(segments, max_bytes, fill_gaps=False)
    return result.data, [gap.as_dict() for gap in result.gaps]


def analyze_streams(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
    stream_id: Optional[str] = None,
    stream_search: Optional[str] = None,
    streams_full: bool = False,
    filter_ip: Optional[str] = None,
    filter_port: Optional[int] = None,
    established_only: bool = False,
    view_content: bool = False,
) -> StreamSummary:
    # When the caller wants to VIEW stream content (-view), retain a much larger
    # reassembled slice per record for the HEX/ASCII dump; otherwise keep the
    # small 512-byte preview that only feeds the followed-stream display.
    preview_cap = 65536 if view_content else 512
    if TCP is None:
        return StreamSummary(
            path=path,
            total_streams=0,
            observed_streams=0,
            streams=[],
            top_streams=[],
            errors=["Scapy TCP unavailable"],
            followed_stream_id=stream_id,
            lookup_tuple=None,
            streams_full=streams_full,
            stream_search=stream_search,
            filter_ip=filter_ip,
            filter_port=filter_port,
            established_only=established_only,
        )

    errors: list[str] = []
    stats = defaultdict(
        lambda: {
            "packets": 0,
            "bytes": 0,
            "first": None,
            "last": None,
            "first_pkt": None,
            "syn_pkt": None,
            "syn_dir": None,
            "synack_seen": False,
            "established": False,
            "rst_seen": False,
        }
    )
    segments_ab: dict[tuple[str, int, str, int], list[tuple[int, bytes]]] = defaultdict(
        list
    )
    segments_ba: dict[tuple[str, int, str, int], list[tuple[int, bytes]]] = defaultdict(
        list
    )
    segments_ab_bytes: dict[tuple[str, int, str, int], int] = defaultdict(int)
    segments_ba_bytes: dict[tuple[str, int, str, int], int] = defaultdict(int)
    followed_client_payload: Optional[bytes] = None
    followed_server_payload: Optional[bytes] = None
    followed_client_gaps: list[dict[str, int]] | None = None
    followed_server_gaps: list[dict[str, int]] | None = None
    followed_packets: list[StreamPacketDetail] = []
    followed_id: Optional[str] = None
    target_followed_id: Optional[str] = stream_id.strip() if stream_id else None
    total_streams = 0
    stream_bytes: Counter[str] = Counter()
    stream_ids: dict[tuple[str, int, str, int], str] = {}
    packet_number = 0

    search_term_text = (stream_search or "").strip()
    search_term_bytes: Optional[bytes] = (
        search_term_text.encode("utf-8", errors="ignore").lower()
        if search_term_text
        else None
    )
    retained_bytes = 0
    budget_exhausted = False

    for pkt in iter_packets(path, packets=packets, meta=meta, show_status=show_status):
        packet_number += 1
        tcp = pkt.getlayer(TCP)  # type: ignore[arg-type]
        if tcp is None:
            continue

        src_ip, dst_ip = extract_packet_endpoints(pkt)
        if not src_ip or not dst_ip:
            continue

        sport = int(getattr(tcp, "sport", 0) or 0)
        dport = int(getattr(tcp, "dport", 0) or 0)
        if sport == 0 or dport == 0:
            continue
        if filter_ip and src_ip != filter_ip and dst_ip != filter_ip:
            continue
        if (
            filter_port is not None
            and sport != filter_port
            and dport != filter_port
        ):
            continue

        stream_key = _canonical_key(src_ip, dst_ip, sport, dport)
        sid = stream_ids.get(stream_key)
        if sid is None:
            sid = _stream_id(
                stream_key[0], stream_key[1], stream_key[2], stream_key[3]
            )
            stream_ids[stream_key] = sid
        info = stats[stream_key]
        info["packets"] += 1
        pkt_len = packet_length(pkt)
        info["bytes"] += pkt_len
        if info["first_pkt"] is None:
            info["first_pkt"] = packet_number
        ts = safe_float(getattr(pkt, "time", None))
        if ts is not None:
            info["first"] = ts if info["first"] is None else min(info["first"], ts)
            info["last"] = ts if info["last"] is None else max(info["last"], ts)
        flags = tcp_flags_int(getattr(tcp, "flags", 0))
        # Prefer the first SYN without ACK as stream start packet.
        is_ab = (src_ip, sport, dst_ip, dport) == stream_key
        direction = "ab" if is_ab else "ba"
        if flags & 0x04:  # RST
            info["rst_seen"] = True
        if (flags & 0x02) and not (flags & 0x10) and info["syn_pkt"] is None:
            info["syn_pkt"] = packet_number
            info["syn_dir"] = direction
        syn_dir = info.get("syn_dir")
        if syn_dir in {"ab", "ba"}:
            expected_synack_dir = "ba" if syn_dir == "ab" else "ab"
            if (
                (flags & 0x02)
                and (flags & 0x10)
                and direction == expected_synack_dir
            ):
                info["synack_seen"] = True
            if (
                info.get("synack_seen")
                and (flags & 0x10)
                and not (flags & 0x02)
                and direction == syn_dir
            ):
                info["established"] = True

        payload = b""
        # A TCP segment carrying application data always exposes a Raw layer.
        # When there is none, the segment is a pure ACK/control packet -- do
        # NOT fall back to bytes(tcp.payload), which would pull in the
        # Ethernet frame Padding (null bytes) Scapy attaches to short frames
        # and corrupt the reassembled stream content.
        raw = tcp.getlayer(Raw) if Raw is not None else None
        if raw is not None:
            try:
                payload = bytes(raw.load)
            except Exception:
                payload = b""
        if payload and not budget_exhausted:
            seq = int(getattr(tcp, "seq", 0) or 0)
            if is_ab:
                seg_list, seg_bytes = segments_ab, segments_ab_bytes
            else:
                seg_list, seg_bytes = segments_ba, segments_ba_bytes
            current = seg_bytes[stream_key]
            remaining = min(
                STREAM_MAX_BYTES - current,
                STREAM_TOTAL_MAX_BYTES - retained_bytes,
            )
            if remaining > 0:
                chunk = payload[:remaining] if len(payload) > remaining else payload
                seg_list[stream_key].append((seq, chunk))
                seg_bytes[stream_key] += len(chunk)
                retained_bytes += len(chunk)
            if retained_bytes >= STREAM_TOTAL_MAX_BYTES:
                budget_exhausted = True
                errors.append(
                    f"Stream reassembly budget of {STREAM_TOTAL_MAX_BYTES} bytes "
                    f"reached at packet {packet_number}; later payload was "
                    "counted but not retained (PCAPPER_STREAM_TOTAL_MAX_BYTES)."
                )
        if target_followed_id and sid == target_followed_id:
            try:
                seq_value = int(getattr(tcp, "seq", 0) or 0)
            except Exception:
                seq_value = 0
            try:
                ack_value = int(getattr(tcp, "ack", 0) or 0)
            except Exception:
                ack_value = 0
            try:
                window_value = int(getattr(tcp, "window", 0) or 0)
            except Exception:
                window_value = 0
            followed_packets.append(
                StreamPacketDetail(
                    packet_number=packet_number,
                    ts=ts,
                    direction="A->B" if direction == "ab" else "B->A",
                    src=src_ip,
                    dst=dst_ip,
                    src_port=sport,
                    dst_port=dport,
                    flags=tcp_flags_text(flags),
                    seq=seq_value,
                    ack=ack_value,
                    window=window_value,
                    packet_bytes=pkt_len,
                    payload_bytes=len(payload),
                )
            )

    observed_streams = len(stats)
    records: list[StreamRecord] = []
    for key, info in stats.items():
        src, sport, dst, dport = key
        sid = stream_ids.get(key) or _stream_id(src, sport, dst, dport)
        if established_only and not bool(info.get("established")):
            if not (target_followed_id and sid == target_followed_id):
                continue
        client_ip, client_port, server_ip, server_port = _client_server_tuple(
            src,
            sport,
            dst,
            dport,
            info.get("syn_dir"),
        )
        payload_ab, gaps_ab = _reassemble(segments_ab.get(key, []), STREAM_MAX_BYTES)
        payload_ba, gaps_ba = _reassemble(segments_ba.get(key, []), STREAM_MAX_BYTES)
        if search_term_bytes and not target_followed_id:
            payload_match = (search_term_bytes in payload_ab.lower()) or (
                search_term_bytes in payload_ba.lower()
            )
            if not payload_match:
                continue
        elif search_term_bytes and target_followed_id and sid != target_followed_id:
            payload_match = (search_term_bytes in payload_ab.lower()) or (
                search_term_bytes in payload_ba.lower()
            )
            if not payload_match:
                continue
        total_streams += 1
        stream_bytes[sid] = info["bytes"]
        records.append(
            StreamRecord(
                stream_id=sid,
                src=src,
                dst=dst,
                src_port=sport,
                dst_port=dport,
                client_ip=client_ip,
                client_port=client_port,
                server_ip=server_ip,
                server_port=server_port,
                packets=info["packets"],
                bytes=info["bytes"],
                first_seen=info["first"],
                last_seen=info["last"],
                first_packet_number=info["first_pkt"],
                syn_packet_number=info["syn_pkt"],
                client_payload_preview=payload_ab[:preview_cap],
                server_payload_preview=payload_ba[:preview_cap],
                client_gaps=gaps_ab,
                server_gaps=gaps_ba,
                conn_state=_conn_state(info, bool(payload_ab), bool(payload_ba)),
            )
        )
        if target_followed_id and sid == target_followed_id:
            followed_id = sid
            followed_client_payload = payload_ab
            followed_server_payload = payload_ba
            followed_client_gaps = gaps_ab
            followed_server_gaps = gaps_ba

    top_streams = [sid for sid, _ in stream_bytes.most_common(10)]
    if target_followed_id and not followed_id:
        followed_id = target_followed_id

    lookup_tuple: Optional[str] = None
    if (
        followed_id
        and followed_client_payload is None
        and followed_server_payload is None
    ):
        for rec in records:
            if rec.stream_id == followed_id:
                followed_client_payload = rec.client_payload_preview
                followed_server_payload = rec.server_payload_preview
                followed_client_gaps = rec.client_gaps
                followed_server_gaps = rec.server_gaps
                break
    if followed_id:
        for rec in records:
            if rec.stream_id == followed_id:
                lookup_tuple = (
                    f"TCP {rec.src}:{rec.src_port} <-> {rec.dst}:{rec.dst_port}"
                )
                break

    return StreamSummary(
        path=path,
        total_streams=total_streams,
        observed_streams=observed_streams,
        streams=records,
        top_streams=top_streams,
        errors=errors,
        followed_stream_id=followed_id,
        followed_client_payload=followed_client_payload,
        followed_server_payload=followed_server_payload,
        followed_client_gaps=followed_client_gaps,
        followed_server_gaps=followed_server_gaps,
        followed_packets=followed_packets if target_followed_id else None,
        lookup_stream_id=None,
        lookup_tuple=lookup_tuple,
        streams_full=streams_full,
        stream_search=search_term_text or None,
        filter_ip=filter_ip,
        filter_port=filter_port,
        established_only=established_only,
        view_content=view_content,
    )
