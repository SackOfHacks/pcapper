from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from collections import defaultdict, Counter
import hashlib

from .pcap_cache import get_reader
from .utils import safe_float

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


@dataclass
class StreamRecord:
    stream_id: str
    src: str
    dst: str
    src_port: int
    dst_port: int
    packets: int
    bytes: int
    first_seen: Optional[float]
    last_seen: Optional[float]
    client_payload_preview: bytes
    server_payload_preview: bytes
    client_gaps: list[dict[str, int]]
    server_gaps: list[dict[str, int]]


@dataclass
class StreamSummary:
    path: Path
    total_streams: int
    streams: list[StreamRecord]
    top_streams: list[str]
    errors: list[str]
    followed_stream_id: Optional[str] = None
    followed_client_payload: Optional[bytes] = None
    followed_server_payload: Optional[bytes] = None
    followed_client_gaps: list[dict[str, int]] | None = None
    followed_server_gaps: list[dict[str, int]] | None = None
    lookup_stream_id: Optional[str] = None
    lookup_tuple: Optional[str] = None
    streams_full: bool = False


def _canonical_key(src: str, dst: str, sport: int, dport: int) -> tuple[str, int, str, int]:
    left = (src, sport)
    right = (dst, dport)
    if left <= right:
        return (src, sport, dst, dport)
    return (dst, dport, src, sport)


def _stream_id(src: str, sport: int, dst: str, dport: int) -> str:
    raw = f"{src}:{sport}<->{dst}:{dport}"
    return hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _reassemble(segments: list[tuple[int, bytes]], max_bytes: int) -> tuple[bytes, list[dict[str, int]]]:
    if not segments:
        return b"", []
    segments.sort(key=lambda item: item[0])
    out = bytearray()
    current_end = None
    gaps: list[dict[str, int]] = []
    for seq, data in segments:
        if not data:
            continue
        if current_end is None:
            out.extend(data)
            current_end = seq + len(data)
        else:
            if seq >= current_end:
                gap = seq - current_end
                if gap > 0:
                    gaps.append({"at_seq": current_end, "gap_bytes": gap})
                out.extend(data)
                current_end = seq + len(data)
            else:
                overlap = current_end - seq
                if overlap < len(data):
                    out.extend(data[overlap:])
                    current_end += len(data) - overlap
        if len(out) >= max_bytes:
            return bytes(out[:max_bytes]), gaps
    return bytes(out), gaps


def analyze_streams(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
    follow: Optional[str] = None,
    follow_id: Optional[str] = None,
    lookup_id: Optional[str] = None,
    streams_full: bool = False,
) -> StreamSummary:
    if TCP is None:
        return StreamSummary(
            path=path,
            total_streams=0,
            streams=[],
            top_streams=[],
            errors=["Scapy TCP unavailable"],
            lookup_stream_id=lookup_id,
            lookup_tuple=None,
            streams_full=streams_full,
        )

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, packets=packets, meta=meta, show_status=show_status
    )

    errors: list[str] = []
    stats = defaultdict(lambda: {"packets": 0, "bytes": 0, "first": None, "last": None})
    segments_ab: dict[tuple[str, int, str, int], list[tuple[int, bytes]]] = defaultdict(list)
    segments_ba: dict[tuple[str, int, str, int], list[tuple[int, bytes]]] = defaultdict(list)
    segments_ab_bytes: dict[tuple[str, int, str, int], int] = defaultdict(int)
    segments_ba_bytes: dict[tuple[str, int, str, int], int] = defaultdict(int)
    followed_client_payload: Optional[bytes] = None
    followed_server_payload: Optional[bytes] = None
    followed_client_gaps: list[dict[str, int]] | None = None
    followed_server_gaps: list[dict[str, int]] | None = None
    followed_id: Optional[str] = None
    total_streams = 0
    stream_bytes: Counter[str] = Counter()

    follow_key: Optional[tuple[str, int, str, int]] = None
    if follow:
        try:
            left, right = follow.split("->", 1)
            src_ip, src_port = left.split(":", 1)
            dst_ip, dst_port = right.split(":", 1)
            follow_key = (src_ip.strip(), int(src_port), dst_ip.strip(), int(dst_port))
        except Exception:
            errors.append("Invalid --follow format. Use src_ip:src_port->dst_ip:dst_port")

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    status.update(int(min(100, (pos / size_bytes) * 100)))
                except Exception:
                    pass

            if not pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                continue

            src_ip = None
            dst_ip = None
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                src_ip = str(pkt[IP].src)  # type: ignore[index]
                dst_ip = str(pkt[IP].dst)  # type: ignore[index]
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                src_ip = str(pkt[IPv6].src)  # type: ignore[index]
                dst_ip = str(pkt[IPv6].dst)  # type: ignore[index]
            if not src_ip or not dst_ip:
                continue

            tcp = pkt[TCP]  # type: ignore[index]
            sport = int(getattr(tcp, "sport", 0) or 0)
            dport = int(getattr(tcp, "dport", 0) or 0)
            if sport == 0 or dport == 0:
                continue

            stream_key = _canonical_key(src_ip, dst_ip, sport, dport)
            info = stats[stream_key]
            info["packets"] += 1
            pkt_len = int(len(pkt)) if hasattr(pkt, "__len__") else 0
            info["bytes"] += pkt_len
            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                info["first"] = ts if info["first"] is None else min(info["first"], ts)
                info["last"] = ts if info["last"] is None else max(info["last"], ts)

            payload = b""
            if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                try:
                    payload = bytes(pkt[Raw].load)  # type: ignore[index]
                except Exception:
                    payload = b""
            else:
                try:
                    payload = bytes(getattr(tcp, "payload", b""))
                except Exception:
                    payload = b""
            if payload:
                seq = int(getattr(tcp, "seq", 0) or 0)
                if (src_ip, sport, dst_ip, dport) == stream_key:
                    current = segments_ab_bytes[stream_key]
                    if current < STREAM_MAX_BYTES:
                        remaining = STREAM_MAX_BYTES - current
                        if remaining <= 0:
                            continue
                        if len(payload) > remaining:
                            payload = payload[:remaining]
                        segments_ab[stream_key].append((seq, payload))
                        segments_ab_bytes[stream_key] += len(payload)
                else:
                    current = segments_ba_bytes[stream_key]
                    if current < STREAM_MAX_BYTES:
                        remaining = STREAM_MAX_BYTES - current
                        if remaining <= 0:
                            continue
                        if len(payload) > remaining:
                            payload = payload[:remaining]
                        segments_ba[stream_key].append((seq, payload))
                        segments_ba_bytes[stream_key] += len(payload)

    finally:
        status.finish()
        reader.close()

    records: list[StreamRecord] = []
    for key, info in stats.items():
        src, sport, dst, dport = key
        sid = _stream_id(src, sport, dst, dport)
        total_streams += 1
        stream_bytes[sid] = info["bytes"]
        payload_ab, gaps_ab = _reassemble(segments_ab.get(key, []), STREAM_MAX_BYTES)
        payload_ba, gaps_ba = _reassemble(segments_ba.get(key, []), STREAM_MAX_BYTES)
        records.append(
            StreamRecord(
                stream_id=sid,
                src=src,
                dst=dst,
                src_port=sport,
                dst_port=dport,
                packets=info["packets"],
                bytes=info["bytes"],
                first_seen=info["first"],
                last_seen=info["last"],
                client_payload_preview=payload_ab[:512],
                server_payload_preview=payload_ba[:512],
                client_gaps=gaps_ab,
                server_gaps=gaps_ba,
            )
        )

    top_streams = [sid for sid, _ in stream_bytes.most_common(10)]
    if follow_key:
        followed_id = _stream_id(follow_key[0], follow_key[1], follow_key[2], follow_key[3])
    if follow_id:
        followed_id = follow_id.strip()

    lookup_tuple: Optional[str] = None
    if followed_id:
        for rec in records:
            if rec.stream_id == followed_id:
                followed_client_payload = rec.client_payload_preview
                followed_server_payload = rec.server_payload_preview
                followed_client_gaps = rec.client_gaps
                followed_server_gaps = rec.server_gaps
                break
    if lookup_id:
        for rec in records:
            if rec.stream_id == lookup_id:
                lookup_tuple = f"TCP {rec.src}:{rec.src_port} <-> {rec.dst}:{rec.dst_port}"
                break

    return StreamSummary(
        path=path,
        total_streams=total_streams,
        streams=records,
        top_streams=top_streams,
        errors=errors,
        followed_stream_id=followed_id,
        followed_client_payload=followed_client_payload,
        followed_server_payload=followed_server_payload,
        followed_client_gaps=followed_client_gaps,
        followed_server_gaps=followed_server_gaps,
        lookup_stream_id=lookup_id,
        lookup_tuple=lookup_tuple,
        streams_full=streams_full,
    )
