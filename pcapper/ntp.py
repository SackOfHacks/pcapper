from __future__ import annotations

from collections import Counter
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


NTP_PORT = 123


@dataclass(frozen=True)
class NtpSummary:
    path: Path
    total_packets: int
    ntp_packets: int
    client_counts: Counter[str]
    server_counts: Counter[str]
    mode_counts: Counter[str]
    version_counts: Counter[int]
    stratum_counts: Counter[int]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


def _mode_name(value: int) -> str:
    return {
        0: "reserved",
        1: "symmetric_active",
        2: "symmetric_passive",
        3: "client",
        4: "server",
        5: "broadcast",
        6: "control",
        7: "private",
    }.get(value, f"mode_{value}")


def analyze_ntp(path: Path, show_status: bool = True) -> NtpSummary:
    if UDP is None:
        return NtpSummary(path, 0, 0, Counter(), Counter(), Counter(), Counter(), Counter(), [], ["Scapy UDP unavailable"], None, None, None)

    reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)

    total_packets = 0
    ntp_packets = 0
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    mode_counts: Counter[str] = Counter()
    version_counts: Counter[int] = Counter()
    stratum_counts: Counter[int] = Counter()
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
            if sport != NTP_PORT and dport != NTP_PORT:
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

            ntp_packets += 1
            payload = bytes(getattr(udp, "payload", b""))
            if len(payload) < 2:
                continue
            first_byte = payload[0]
            li = (first_byte >> 6) & 0x3
            version = (first_byte >> 3) & 0x7
            mode = first_byte & 0x7
            mode_name = _mode_name(mode)
            mode_counts[mode_name] += 1
            version_counts[version] += 1
            if len(payload) > 1:
                stratum = payload[1]
                stratum_counts[int(stratum)] += 1

            if mode == 3:
                client_counts[src_ip] += 1
                server_counts[dst_ip] += 1
            elif mode == 4:
                server_counts[src_ip] += 1
                client_counts[dst_ip] += 1

    finally:
        status.finish()
        reader.close()

    if ntp_packets and mode_counts.get("control", 0) > 0:
        detections.append({
            "severity": "warning",
            "summary": "NTP control mode traffic detected",
            "details": "Control mode traffic can indicate management or misuse on NTP services.",
        })
    if ntp_packets and stratum_counts:
        if any(stratum >= 16 for stratum in stratum_counts.keys()):
            detections.append({
                "severity": "warning",
                "summary": "NTP stratum 16/unsynchronized observed",
                "details": "Stratum 16 indicates unsynchronized sources; investigate NTP health.",
            })

    duration = (last_seen - first_seen) if first_seen is not None and last_seen is not None else None
    return NtpSummary(
        path=path,
        total_packets=total_packets,
        ntp_packets=ntp_packets,
        client_counts=client_counts,
        server_counts=server_counts,
        mode_counts=mode_counts,
        version_counts=version_counts,
        stratum_counts=stratum_counts,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
