from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .pcap_cache import get_reader
from .utils import safe_float

try:
    from scapy.layers.inet import IP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore


QUIC_PORTS = {443, 4433, 8443, 9443, 784}


@dataclass(frozen=True)
class QuicSummary:
    path: Path
    total_packets: int
    quic_packets: int
    clients: Counter[str]
    servers: Counter[str]
    versions: Counter[str]
    flow_counts: Counter[str]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


def _looks_like_quic(payload: bytes) -> bool:
    if not payload:
        return False
    first = payload[0]
    # QUIC long header has 0x80 bit set
    if first & 0x80:
        return True
    # short header has 0x40 bit set and fixed bit 0x40; check for 0x40 or 0x50+ variants
    return (first & 0x40) == 0x40


def _parse_version(payload: bytes) -> Optional[str]:
    if len(payload) < 6:
        return None
    if (payload[0] & 0x80) == 0:
        return None
    version = int.from_bytes(payload[1:5], "big")
    return f"0x{version:08x}"


def analyze_quic(path: Path, show_status: bool = True) -> QuicSummary:
    if UDP is None:
        return QuicSummary(path, 0, 0, Counter(), Counter(), Counter(), Counter(), [], ["Scapy UDP unavailable"], None, None, None)

    reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)
    total_packets = 0
    quic_packets = 0
    clients: Counter[str] = Counter()
    servers: Counter[str] = Counter()
    versions: Counter[str] = Counter()
    flow_counts: Counter[str] = Counter()
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

            if not pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                continue
            udp = pkt[UDP]  # type: ignore[index]
            sport = int(getattr(udp, "sport", 0) or 0)
            dport = int(getattr(udp, "dport", 0) or 0)
            if sport not in QUIC_PORTS and dport not in QUIC_PORTS:
                continue

            payload = bytes(getattr(udp, "payload", b""))
            if not _looks_like_quic(payload):
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

            quic_packets += 1
            if dport in QUIC_PORTS:
                clients[src_ip] += 1
                servers[dst_ip] += 1
            else:
                servers[src_ip] += 1
                clients[dst_ip] += 1

            version = _parse_version(payload)
            if version:
                versions[version] += 1
            flow_counts[f"{src_ip}->{dst_ip}:{dport}"] += 1

    finally:
        status.finish()
        reader.close()

    if quic_packets:
        detections.append({
            "severity": "info",
            "summary": "QUIC traffic observed",
            "details": f"{quic_packets} QUIC-like packets detected; check for HTTP/3 usage.",
        })

    duration = (last_seen - first_seen) if first_seen is not None and last_seen is not None else None
    return QuicSummary(
        path=path,
        total_packets=total_packets,
        quic_packets=quic_packets,
        clients=clients,
        servers=servers,
        versions=versions,
        flow_counts=flow_counts,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
