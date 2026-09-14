from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .pcap_cache import PcapMeta, iter_packets
from .utils import extract_packet_endpoints, memoize_analysis, safe_float

try:
    from scapy.layers.inet import TCP  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:  # pragma: no cover
    TCP = None  # type: ignore
    Raw = None  # type: ignore


HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
# An HTTP/1.1 request offering an upgrade to cleartext HTTP/2 (RFC 7540 §3.2)
# and the server's acceptance. Both are cleartext, and the client is the side
# that sent the request line.
_REQUEST_LINE_RE = re.compile(rb"\A[A-Z]{3,10} \S+ HTTP/1\.[01]\Z")
_SWITCHING_LINE_RE = re.compile(rb"\AHTTP/1\.[01] 101\b")
_UPGRADE_H2C_RE = re.compile(rb"(?im)^upgrade:[ \t]*h2c[ \t]*$")
_HEADER_SCAN_BYTES = 4096


def _h2c_upgrade(head: bytes) -> Optional[str]:
    """``"request"`` / ``"response"`` when the segment starts an h2c upgrade.

    Only the header block (up to the first blank line) is inspected, line by
    line, so a body that happens to mention an upgrade does not count and the
    scan is linear in the segment size.
    """
    end = head.find(b"\r\n\r\n")
    headers = head[:end] if end >= 0 else head
    start_line, _sep, rest = headers.partition(b"\r\n")
    if _REQUEST_LINE_RE.match(start_line):
        kind = "request"
    elif _SWITCHING_LINE_RE.match(start_line):
        kind = "response"
    else:
        return None
    return kind if _UPGRADE_H2C_RE.search(rest) else None


@dataclass(frozen=True)
class Http2Summary:
    path: Path
    total_packets: int
    http2_packets: int
    client_counts: Counter[str]
    server_counts: Counter[str]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]
    # TLS sessions that negotiated HTTP/2 through ALPN. Almost all real HTTP/2
    # is carried this way; the cleartext preface above is the exception.
    alpn_h2_sessions: int = 0
    alpn_h2_clients: Counter[str] = field(default_factory=Counter)


def _tcp_payload(pkt: object) -> bytes:
    if Raw is not None:
        raw = pkt.getlayer(Raw)  # type: ignore[attr-defined]
        if raw is not None:
            try:
                return bytes(raw.load)
            except Exception:
                return b""
    try:
        return bytes(getattr(pkt[TCP], "payload", b""))  # type: ignore[index]
    except Exception:
        return b""


def _empty(path: Path, error: str) -> Http2Summary:
    return Http2Summary(
        path, 0, 0, Counter(), Counter(), [], [error], None, None, None
    )


@memoize_analysis
def analyze_http2(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> Http2Summary:
    if TCP is None:
        return _empty(path, "Scapy TCP unavailable")

    total_packets = 0
    http2_packets = 0
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    detections: list[dict[str, object]] = []
    errors: list[str] = []
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    # (client_ip, client_port, server_ip, server_port) of every connection on
    # which the HTTP/2 preface or an h2c upgrade was seen. Later segments of
    # those connections are binary frames with nothing to grep for, so they are
    # attributed by connection, with the roles fixed by who sent the preface.
    h2_connections: set[tuple[str, int, str, int]] = set()

    for pkt in iter_packets(path, packets=packets, meta=meta, show_status=show_status):
        total_packets += 1
        tcp = pkt.getlayer(TCP)  # type: ignore[arg-type]
        if tcp is None:
            continue
        payload = _tcp_payload(pkt)
        if not payload:
            continue
        src_ip, dst_ip = extract_packet_endpoints(pkt)
        if not src_ip or not dst_ip:
            continue
        sport = int(getattr(tcp, "sport", 0) or 0)
        dport = int(getattr(tcp, "dport", 0) or 0)

        head = payload[:_HEADER_SCAN_BYTES]
        client: Optional[str] = None
        server: Optional[str] = None
        upgrade = _h2c_upgrade(head)
        if head.startswith(HTTP2_PREFACE) or upgrade == "request":
            client, server = src_ip, dst_ip
            h2_connections.add((src_ip, sport, dst_ip, dport))
        elif upgrade == "response":
            client, server = dst_ip, src_ip
            h2_connections.add((dst_ip, dport, src_ip, sport))
        elif (src_ip, sport, dst_ip, dport) in h2_connections:
            client, server = src_ip, dst_ip
        elif (dst_ip, dport, src_ip, sport) in h2_connections:
            client, server = dst_ip, src_ip
        if client is None or server is None:
            continue

        http2_packets += 1
        # The report window spans HTTP/2 traffic, not every packet in scope.
        ts = safe_float(getattr(pkt, "time", None))
        if ts is not None:
            if first_seen is None or ts < first_seen:
                first_seen = ts
            if last_seen is None or ts > last_seen:
                last_seen = ts
        client_counts[client] += 1
        server_counts[server] += 1

    if http2_packets:
        detections.append(
            {
                "severity": "info",
                "summary": "HTTP/2 cleartext or upgrade indicators observed",
                "details": (
                    f"{http2_packets} packet(s) on {len(h2_connections)} connection(s) "
                    "carrying the HTTP/2 preface or an h2c upgrade."
                ),
            }
        )

    alpn_h2_sessions = 0
    alpn_h2_clients: Counter[str] = Counter()
    try:
        from .tls import analyze_tls

        tls_summary = analyze_tls(path, show_status=False, packets=packets, meta=meta)
        for client_ip, alpns in getattr(tls_summary, "client_alpn_counts", {}).items():
            for alpn, count in alpns.items():
                if str(alpn).lower() == "h2":
                    alpn_h2_clients[str(client_ip)] += int(count)
        alpn_h2_sessions = sum(alpn_h2_clients.values())
    except Exception as exc:  # pragma: no cover - defensive
        errors.append(f"TLS ALPN check unavailable: {type(exc).__name__}: {exc}")
    if alpn_h2_sessions:
        detections.append(
            {
                "severity": "info",
                "summary": "HTTP/2 negotiated over TLS (ALPN h2)",
                "details": (
                    f"{alpn_h2_sessions} TLS ClientHello(s) offered ALPN h2 from "
                    f"{len(alpn_h2_clients)} client(s); content is encrypted."
                ),
            }
        )

    duration = (
        (last_seen - first_seen)
        if first_seen is not None and last_seen is not None
        else None
    )
    return Http2Summary(
        path=path,
        total_packets=total_packets,
        http2_packets=http2_packets,
        client_counts=client_counts,
        server_counts=server_counts,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
        alpn_h2_sessions=alpn_h2_sessions,
        alpn_h2_clients=alpn_h2_clients,
    )
