from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from collections import Counter
from typing import Optional
import ipaddress

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


SAFETY_PORTS: dict[int, str] = {
    1502: "Triconex/TriStation",
}


@dataclass(frozen=True)
class SafetyHit:
    ts: Optional[float]
    protocol: str
    src: str
    dst: str
    src_port: int
    dst_port: int
    service: str


@dataclass(frozen=True)
class SafetySummary:
    path: Path
    total_packets: int
    hits: list[SafetyHit]
    source_counts: Counter[str]
    destination_counts: Counter[str]
    service_counts: Counter[str]
    detections: list[dict[str, object]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except Exception:
        return False


def merge_safety_summaries(summaries: list[SafetySummary]) -> SafetySummary:
    if not summaries:
        return SafetySummary(
            path=Path("ALL_PCAPS"),
            total_packets=0,
            hits=[],
            source_counts=Counter(),
            destination_counts=Counter(),
            service_counts=Counter(),
            detections=[],
            errors=[],
        )
    total_packets = sum(item.total_packets for item in summaries)
    hits: list[SafetyHit] = []
    source_counts: Counter[str] = Counter()
    destination_counts: Counter[str] = Counter()
    service_counts: Counter[str] = Counter()
    detections: list[dict[str, object]] = []
    errors: list[str] = []
    for summary in summaries:
        hits.extend(summary.hits)
        source_counts.update(summary.source_counts)
        destination_counts.update(summary.destination_counts)
        service_counts.update(summary.service_counts)
        detections.extend(summary.detections)
        errors.extend(summary.errors)
    return SafetySummary(
        path=Path("ALL_PCAPS"),
        total_packets=total_packets,
        hits=hits[:200],
        source_counts=source_counts,
        destination_counts=destination_counts,
        service_counts=service_counts,
        detections=detections,
        errors=sorted({err for err in errors if err}),
    )


def analyze_safety(path: Path, show_status: bool = True) -> SafetySummary:
    if TCP is None and UDP is None:
        return SafetySummary(
            path=path,
            total_packets=0,
            hits=[],
            source_counts=Counter(),
            destination_counts=Counter(),
            service_counts=Counter(),
            detections=[],
            errors=["Scapy TCP/UDP unavailable"],
        )

    reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)
    total_packets = 0
    hits: list[SafetyHit] = []
    source_counts: Counter[str] = Counter()
    destination_counts: Counter[str] = Counter()
    service_counts: Counter[str] = Counter()
    errors: list[str] = []

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

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp = pkt[TCP]  # type: ignore[index]
                sport = int(getattr(tcp, "sport", 0) or 0)
                dport = int(getattr(tcp, "dport", 0) or 0)
                service = SAFETY_PORTS.get(sport) or SAFETY_PORTS.get(dport)
                if service:
                    hits.append(
                        SafetyHit(
                            ts=ts,
                            protocol="TCP",
                            src=src_ip,
                            dst=dst_ip,
                            src_port=sport,
                            dst_port=dport,
                            service=service,
                        )
                    )
                    source_counts[src_ip] += 1
                    destination_counts[dst_ip] += 1
                    service_counts[service] += 1

            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp = pkt[UDP]  # type: ignore[index]
                sport = int(getattr(udp, "sport", 0) or 0)
                dport = int(getattr(udp, "dport", 0) or 0)
                service = SAFETY_PORTS.get(sport) or SAFETY_PORTS.get(dport)
                if service:
                    hits.append(
                        SafetyHit(
                            ts=ts,
                            protocol="UDP",
                            src=src_ip,
                            dst=dst_ip,
                            src_port=sport,
                            dst_port=dport,
                            service=service,
                        )
                    )
                    source_counts[src_ip] += 1
                    destination_counts[dst_ip] += 1
                    service_counts[service] += 1

    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        status.finish()
        reader.close()

    detections: list[dict[str, object]] = []
    if hits:
        public_hits = [hit for hit in hits if _is_public(hit.src) or _is_public(hit.dst)]
        severity = "high" if public_hits else "warning"
        evidence = [
            f"{hit.protocol} {hit.src}:{hit.src_port}->{hit.dst}:{hit.dst_port} {hit.service}"
            for hit in hits[:8]
        ]
        details = f"{len(hits)} packet(s) across {len(service_counts)} safety service(s)."
        if public_hits:
            details = f"{details} Public endpoints observed."
        detections.append(
            {
                "severity": severity,
                "summary": "Safety PLC/SIS protocol traffic observed",
                "details": details,
                "source": "Safety",
                "top_sources": source_counts.most_common(5),
                "top_destinations": destination_counts.most_common(5),
                "evidence": evidence,
            }
        )

    return SafetySummary(
        path=path,
        total_packets=total_packets,
        hits=hits,
        source_counts=source_counts,
        destination_counts=destination_counts,
        service_counts=service_counts,
        detections=detections,
        errors=errors,
    )
