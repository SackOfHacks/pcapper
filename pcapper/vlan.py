from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .pcap_cache import get_reader
try:
    from scapy.layers.inet import IP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    IPv6 = None  # type: ignore

from .utils import safe_float, detect_file_type

try:
    from scapy.layers.l2 import Dot1Q  # type: ignore
except Exception:  # pragma: no cover
    Dot1Q = None  # type: ignore


@dataclass(frozen=True)
class VlanStat:
    vlan_id: int
    packets: int
    bytes: int
    src_macs: set[str]
    dst_macs: set[str]
    src_ips: set[str]
    dst_ips: set[str]
    protocols: Counter[str]
    first_seen: Optional[float]
    last_seen: Optional[float]


@dataclass(frozen=True)
class VlanSummary:
    path: Path
    total_tagged_packets: int
    total_tagged_bytes: int
    vlan_stats: list[VlanStat]
    detections: list[dict[str, str]]
    errors: list[str]


def _layer_names(packet) -> list[str]:
    names = []
    for layer in packet.layers():
        names.append(layer.__name__)
    return names


def analyze_vlans(path: Path, show_status: bool = True) -> VlanSummary:
    errors: list[str] = []
    if Dot1Q is None:
        errors.append("Scapy Dot1Q layer unavailable; install scapy for VLAN analysis.")
        return VlanSummary(path=path, total_tagged_packets=0, total_tagged_bytes=0, vlan_stats=[], detections=[], errors=errors)

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, show_status=show_status
    )

    vlan_stats: dict[int, dict[str, object]] = defaultdict(lambda: {
        "packets": 0,
        "bytes": 0,
        "src_macs": set(),
        "dst_macs": set(),
        "src_ips": set(),
        "dst_ips": set(),
        "protocols": Counter(),
        "first_seen": None,
        "last_seen": None,
    })

    total_tagged_packets = 0
    total_tagged_bytes = 0

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            if not pkt.haslayer(Dot1Q):  # type: ignore[truthy-bool]
                continue

            vlan_layer = pkt[Dot1Q]  # type: ignore[index]
            vlan_id = int(getattr(vlan_layer, "vlan", 0) or 0)
            if vlan_id == 0:
                continue

            total_tagged_packets += 1
            pkt_len = int(len(pkt)) if hasattr(pkt, "__len__") else 0
            total_tagged_bytes += pkt_len

            info = vlan_stats[vlan_id]
            info["packets"] = int(info["packets"]) + 1
            info["bytes"] = int(info["bytes"]) + pkt_len

            src_mac = getattr(pkt, "src", None)
            dst_mac = getattr(pkt, "dst", None)
            if src_mac:
                info["src_macs"].add(str(src_mac))
            if dst_mac:
                info["dst_macs"].add(str(dst_mac))

            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                ip_layer = pkt[IP]  # type: ignore[index]
                if getattr(ip_layer, "src", None):
                    info["src_ips"].add(str(ip_layer.src))
                if getattr(ip_layer, "dst", None):
                    info["dst_ips"].add(str(ip_layer.dst))
            if IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                ip6_layer = pkt[IPv6]  # type: ignore[index]
                if getattr(ip6_layer, "src", None):
                    info["src_ips"].add(str(ip6_layer.src))
                if getattr(ip6_layer, "dst", None):
                    info["dst_ips"].add(str(ip6_layer.dst))

            protocols = info["protocols"]
            for name in set(_layer_names(pkt)):
                protocols[name] += 1

            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if info["first_seen"] is None or ts < info["first_seen"]:
                    info["first_seen"] = ts
                if info["last_seen"] is None or ts > info["last_seen"]:
                    info["last_seen"] = ts
    finally:
        status.finish()
        reader.close()

    stats_list: list[VlanStat] = []
    for vlan_id, info in vlan_stats.items():
        stats_list.append(
            VlanStat(
                vlan_id=vlan_id,
                packets=int(info["packets"]),
                bytes=int(info["bytes"]),
                src_macs=set(info["src_macs"]),
                dst_macs=set(info["dst_macs"]),
                src_ips=set(info["src_ips"]),
                dst_ips=set(info["dst_ips"]),
                protocols=Counter(info["protocols"]),
                first_seen=info["first_seen"],
                last_seen=info["last_seen"],
            )
        )

    stats_list.sort(key=lambda item: item.packets, reverse=True)

    detections: list[dict[str, str]] = []
    if stats_list:
        vlan_ids = sorted(v.vlan_id for v in stats_list)
        if 1 in vlan_ids:
            detections.append({
                "type": "vlan_default_used",
                "severity": "warning",
                "summary": "VLAN 1 (default) observed",
                "details": "Default VLAN is in use; consider verifying network segmentation policy.",
            })

        total_packets = sum(v.packets for v in stats_list)
        for stat in stats_list:
            if total_packets > 0:
                ratio = stat.packets / total_packets
                if ratio > 0.8 and stat.packets > 1000:
                    detections.append({
                        "type": "vlan_traffic_concentration",
                        "severity": "warning",
                        "summary": f"VLAN {stat.vlan_id} carries {ratio:.1%} of tagged traffic",
                        "details": "Check for misconfiguration or single-VLAN dependency.",
                    })
                if stat.packets < 10:
                    detections.append({
                        "type": "vlan_low_activity",
                        "severity": "info",
                        "summary": f"VLAN {stat.vlan_id} has low activity ({stat.packets} packets)",
                        "details": "Low activity VLANs can be normal; validate against expectations.",
                    })

    return VlanSummary(
        path=path,
        total_tagged_packets=total_tagged_packets,
        total_tagged_bytes=total_tagged_bytes,
        vlan_stats=stats_list,
        detections=detections,
        errors=errors,
    )
