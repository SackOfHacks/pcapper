from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .pcap_cache import PcapMeta, iter_packets
from .utils import extract_packet_endpoints, is_public_ip, memoize_analysis, safe_float

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore


SAFETY_PORTS: dict[int, str] = {
    1500: "Triconex TSAA",        # Triconex System Access Application
    1501: "Triconex TSAA",
    1502: "Triconex/TriStation",  # the engineering protocol Triton/TRISIS abused
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


def _safety_service(sport: int, dport: int) -> Optional[str]:
    """Service name when a safety-system port is on the server side: the
    destination, or the source paired with an ephemeral destination."""
    service = SAFETY_PORTS.get(dport)
    if service:
        return service
    if dport >= 1024:
        return SAFETY_PORTS.get(sport)
    return None


@memoize_analysis
def analyze_safety(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> SafetySummary:
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

    total_packets = 0
    hits: list[SafetyHit] = []
    source_counts: Counter[str] = Counter()
    destination_counts: Counter[str] = Counter()
    service_counts: Counter[str] = Counter()
    errors: list[str] = []

    try:
        for pkt in iter_packets(path, packets=packets, meta=meta, show_status=show_status):
            total_packets += 1
            ts = safe_float(getattr(pkt, "time", None))

            src_ip, dst_ip = extract_packet_endpoints(pkt)
            if not src_ip or not dst_ip:
                continue

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp = pkt[TCP]  # type: ignore[index]
                sport = int(getattr(tcp, "sport", 0) or 0)
                dport = int(getattr(tcp, "dport", 0) or 0)
                service = _safety_service(sport, dport)
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
                service = _safety_service(sport, dport)
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

    detections: list[dict[str, object]] = []
    if hits:
        public_hits = [
            hit for hit in hits if is_public_ip(hit.src) or is_public_ip(hit.dst)
        ]
        severity = "high" if public_hits else "warning"
        # When public endpoints drive the high-severity escalation, show them
        # first in the evidence sample — otherwise hits[:8] can omit the very
        # hosts the "Public endpoints observed" claim is about.
        ordered_hits = public_hits + [
            hit for hit in hits if not (is_public_ip(hit.src) or is_public_ip(hit.dst))
        ]
        evidence = [
            f"{hit.protocol} {hit.src}:{hit.src_port}->{hit.dst}:{hit.dst_port} {hit.service}"
            for hit in ordered_hits[:8]
        ]
        details = (
            f"{len(hits)} packet(s) across {len(service_counts)} safety service(s). "
            "Safety Instrumented Systems are the highest-consequence OT target "
            "(Triton/TRISIS) — any TriStation/SIS engineering traffic from a "
            "non-engineering host, or program-download activity, warrants "
            "investigation (ATT&CK ICS T0843 Program Download to a SIS)."
        )
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
