from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .pcap_cache import get_reader
from .utils import safe_float

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore


@dataclass(frozen=True)
class Iec101103Summary:
    path: Path
    total_packets: int
    candidate_packets: int
    client_counts: Counter[str]
    server_counts: Counter[str]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


def _iec_apdu_candidate(payload: bytes) -> bool:
    if not payload or len(payload) < 4:
        return False
    if payload[0] != 0x68:
        return False
    length = payload[1]
    return 4 <= length <= 255


def analyze_iec101_103(path: Path, show_status: bool = True) -> Iec101103Summary:
    reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)
    total_packets = 0
    candidate_packets = 0
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

            payload = b""
            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                payload = bytes(getattr(pkt[TCP], "payload", b""))  # type: ignore[index]
            elif UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                payload = bytes(getattr(pkt[UDP], "payload", b""))  # type: ignore[index]
            if not _iec_apdu_candidate(payload):
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

            candidate_packets += 1
            client_counts[src_ip] += 1
            server_counts[dst_ip] += 1

    finally:
        status.finish()
        reader.close()

    if candidate_packets:
        detections.append({
            "severity": "info",
            "summary": "IEC 60870-5-101/103 candidate traffic observed",
            "details": f"{candidate_packets} packets matched IEC 101/103 APDU framing heuristics.",
        })

    duration = (last_seen - first_seen) if first_seen is not None and last_seen is not None else None
    return Iec101103Summary(
        path=path,
        total_packets=total_packets,
        candidate_packets=candidate_packets,
        client_counts=client_counts,
        server_counts=server_counts,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
