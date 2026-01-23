from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from collections import Counter, defaultdict

from scapy.utils import PcapReader, PcapNgReader

from .progress import build_statusbar
from .utils import safe_float, detect_file_type
from .icmp import analyze_icmp
from .dns import analyze_dns
from .beacon import analyze_beacons

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore


@dataclass(frozen=True)
class ThreatSummary:
    path: Path
    detections: list[dict[str, object]]
    errors: list[str]


def analyze_threats(path: Path, show_status: bool = True) -> ThreatSummary:
    errors: list[str] = []
    detections: list[dict[str, object]] = []

    # Aggregate detections from specialized modules
    icmp_summary = analyze_icmp(path, show_status=show_status)
    dns_summary = analyze_dns(path, show_status=show_status)
    beacon_summary = analyze_beacons(path, show_status=show_status)

    for item in icmp_summary.detections:
        detections.append({
            "source": "ICMP",
            **item,
        })
    for item in dns_summary.detections:
        detections.append({
            "source": "DNS",
            **item,
        })
    for item in beacon_summary.detections:
        detections.append({
            "source": "Beacon",
            **item,
        })

    if beacon_summary.candidates:
        for candidate in beacon_summary.candidates[:10]:
            detections.append({
                "source": "Beacon",
                "severity": "info",
                "summary": "Beacon candidate flow",
                "details": f"{candidate.src_ip} -> {candidate.dst_ip} ({candidate.proto}) {candidate.count} events, mean {candidate.mean_interval:.2f}s, jitter {candidate.jitter:.2f}",
                "top_sources": [(candidate.src_ip, candidate.count)],
                "top_destinations": [(candidate.dst_ip, candidate.count)],
            })

    file_type = detect_file_type(path)
    reader = PcapNgReader(str(path)) if file_type == "pcapng" else PcapReader(str(path))

    size_bytes = 0
    try:
        size_bytes = path.stat().st_size
    except Exception:
        pass
        
    status = build_statusbar(path, enabled=show_status)
    stream = None
    for attr in ("fd", "f", "fh", "_fh", "_file", "file"):
        candidate = getattr(reader, attr, None)
        if candidate is not None:
            stream = candidate
            break

    dst_port_counts: Counter[tuple[str, str]] = Counter()
    syn_counts: Counter[str] = Counter()
    udp_target_counts: Counter[str] = Counter()
    src_counts: Counter[str] = Counter()
    dst_counts: Counter[str] = Counter()
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            src_ip = None
            dst_ip = None
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                ip_layer = pkt[IP]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                ip_layer = pkt[IPv6]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))

            if src_ip:
                src_counts[src_ip] += 1
            if dst_ip:
                dst_counts[dst_ip] += 1

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp_layer = pkt[TCP]  # type: ignore[index]
                dport = int(getattr(tcp_layer, "dport", 0))
                if src_ip and dst_ip and dport:
                    dst_port_counts[(src_ip, dst_ip)] += 1

                flags = getattr(tcp_layer, "flags", None)
                if flags is not None and "S" in str(flags) and "A" not in str(flags):
                    if src_ip:
                        syn_counts[src_ip] += 1

            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp_layer = pkt[UDP]  # type: ignore[index]
                if dst_ip and getattr(udp_layer, "dport", None) is not None:
                    udp_target_counts[dst_ip] += 1
    finally:
        status.finish()
        reader.close()

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    # Port scan heuristics
    for (src_ip, dst_ip), count in dst_port_counts.items():
        if count > 200:
            detections.append({
                "source": "Flow",
                "severity": "warning",
                "summary": "Potential port scan activity",
                "details": f"{src_ip} contacted many ports on {dst_ip} ({count} SYN/ports)",
                "top_sources": [(src_ip, count)],
                "top_destinations": [(dst_ip, count)],
            })
            break

    # SYN flood / scan rate
    if syn_counts:
        top_src, top_count = syn_counts.most_common(1)[0]
        if top_count > 2000:
            detections.append({
                "source": "TCP",
                "severity": "warning",
                "summary": "High SYN volume",
                "details": f"Source {top_src} sent {top_count} SYN packets.",
                "top_sources": syn_counts.most_common(3),
            })

    # UDP amplification / flood indicator
    if udp_target_counts:
        top_dst, top_count = udp_target_counts.most_common(1)[0]
        if top_count > 5000:
            detections.append({
                "source": "UDP",
                "severity": "warning",
                "summary": "Potential UDP flood",
                "details": f"Destination {top_dst} received {top_count} UDP packets.",
                "top_destinations": udp_target_counts.most_common(3),
            })

    # Generic high-volume target indicator
    if dst_counts:
        top_dst, top_dst_count = dst_counts.most_common(1)[0]
        if duration_seconds and duration_seconds > 0:
            rate = top_dst_count / duration_seconds
            if rate > 5000:
                detections.append({
                    "source": "Traffic",
                    "severity": "warning",
                    "summary": "High traffic concentration on a target",
                    "details": f"{top_dst} received {top_dst_count} packets (~{rate:.1f} pkt/s).",
                    "top_destinations": dst_counts.most_common(3),
                })

    return ThreatSummary(path=path, detections=detections, errors=errors)
