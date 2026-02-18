from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

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


HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


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


def analyze_http2(path: Path, show_status: bool = True) -> Http2Summary:
    if TCP is None:
        return Http2Summary(path, 0, 0, Counter(), Counter(), [], ["Scapy TCP unavailable"], None, None, None)

    reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)
    total_packets = 0
    http2_packets = 0
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    detections: list[dict[str, object]] = []
    errors: list[str] = []
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    status.update(int(min(100, (pos / size_bytes) * 100)))
                except Exception:
                    pass

            total_packets += 1
            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            if not pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                continue
            payload = b""
            if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                try:
                    payload = bytes(pkt[Raw].load)  # type: ignore[index]
                except Exception:
                    payload = b""
            else:
                try:
                    payload = bytes(getattr(pkt[TCP], "payload", b""))  # type: ignore[index]
                except Exception:
                    payload = b""
            if not payload:
                continue

            if HTTP2_PREFACE not in payload and b"HTTP/2.0" not in payload and b"h2c" not in payload:
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

            http2_packets += 1
            client_counts[src_ip] += 1
            server_counts[dst_ip] += 1

    finally:
        status.finish()
        reader.close()

    if http2_packets:
        detections.append({
            "severity": "info",
            "summary": "HTTP/2 cleartext or upgrade indicators observed",
            "details": "HTTP/2 preface or upgrade markers detected in TCP payloads.",
        })

    duration = (last_seen - first_seen) if first_seen is not None and last_seen is not None else None
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
    )
