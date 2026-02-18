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


VPN_PORTS = {
    500: "IKE",
    4500: "IPsec NAT-T",
    1194: "OpenVPN",
    51820: "WireGuard",
    1701: "L2TP",
    1723: "PPTP",
    443: "SSTP/HTTPS VPN",
}


@dataclass(frozen=True)
class VpnSummary:
    path: Path
    total_packets: int
    vpn_packets: int
    service_counts: Counter[str]
    client_counts: Counter[str]
    server_counts: Counter[str]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


def analyze_vpn(path: Path, show_status: bool = True) -> VpnSummary:
    reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)
    total_packets = 0
    vpn_packets = 0
    service_counts: Counter[str] = Counter()
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

            proto = getattr(pkt, "proto", None)
            if proto == 47:
                vpn_packets += 1
                service_counts["GRE"] += 1
                client_counts[src_ip] += 1
                server_counts[dst_ip] += 1
                continue

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp = pkt[TCP]  # type: ignore[index]
                sport = int(getattr(tcp, "sport", 0) or 0)
                dport = int(getattr(tcp, "dport", 0) or 0)
                if sport in VPN_PORTS or dport in VPN_PORTS:
                    vpn_packets += 1
                    service = VPN_PORTS.get(dport) or VPN_PORTS.get(sport) or "VPN"
                    service_counts[service] += 1
                    client_counts[src_ip] += 1
                    server_counts[dst_ip] += 1

            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp = pkt[UDP]  # type: ignore[index]
                sport = int(getattr(udp, "sport", 0) or 0)
                dport = int(getattr(udp, "dport", 0) or 0)
                if sport in VPN_PORTS or dport in VPN_PORTS:
                    vpn_packets += 1
                    service = VPN_PORTS.get(dport) or VPN_PORTS.get(sport) or "VPN"
                    service_counts[service] += 1
                    client_counts[src_ip] += 1
                    server_counts[dst_ip] += 1

    finally:
        status.finish()
        reader.close()

    if vpn_packets:
        detections.append({
            "severity": "info",
            "summary": "VPN/Tunnel indicators observed",
            "details": f"{vpn_packets} packets mapped to VPN/Tunnel ports or GRE.",
        })

    duration = (last_seen - first_seen) if first_seen is not None and last_seen is not None else None
    return VpnSummary(
        path=path,
        total_packets=total_packets,
        vpn_packets=vpn_packets,
        service_counts=service_counts,
        client_counts=client_counts,
        server_counts=server_counts,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
