from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from collections import Counter, defaultdict
import ipaddress

from .hosts import HostSummary
from .services import ServiceSummary


@dataclass(frozen=True)
class CorrelationSummary:
    path: Path
    total_pcaps: int
    host_counts: Counter[str]
    service_counts: Counter[str]
    host_presence: dict[str, list[str]]
    service_presence: dict[str, list[str]]
    detections: list[dict[str, object]]
    errors: list[str]


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except Exception:
        return False


def correlate(
    host_summaries: Iterable[HostSummary],
    service_summaries: Iterable[ServiceSummary],
    min_count: int = 2,
) -> CorrelationSummary:
    host_map: dict[str, set[str]] = defaultdict(set)
    service_map: dict[str, set[str]] = defaultdict(set)
    errors: list[str] = []

    host_list = list(host_summaries)
    svc_list = list(service_summaries)
    total_pcaps = len({summary.path for summary in host_list}) or len({summary.path for summary in svc_list})

    for summary in host_list:
        pcap_name = summary.path.name
        for host in getattr(summary, "hosts", []) or []:
            ip = str(getattr(host, "ip", "") or "")
            if not ip:
                continue
            host_map[ip].add(pcap_name)
        for err in getattr(summary, "errors", []) or []:
            if err:
                errors.append(err)

    for summary in svc_list:
        pcap_name = summary.path.name
        for asset in getattr(summary, "assets", []) or []:
            ip = str(getattr(asset, "ip", "") or "")
            port = int(getattr(asset, "port", 0) or 0)
            proto = str(getattr(asset, "protocol", "") or "")
            if not ip or port <= 0:
                continue
            key = f"{ip}:{port}/{proto}"
            service_map[key].add(pcap_name)
        for err in getattr(summary, "errors", []) or []:
            if err:
                errors.append(err)

    host_counts = Counter({ip: len(pcaps) for ip, pcaps in host_map.items()})
    service_counts = Counter({svc: len(pcaps) for svc, pcaps in service_map.items()})

    detections: list[dict[str, object]] = []
    public_reused = [ip for ip, count in host_counts.items() if count >= min_count and _is_public(ip)]
    if public_reused:
        detections.append(
            {
                "severity": "medium",
                "summary": "Public endpoints observed across multiple pcaps",
                "details": ", ".join(public_reused[:6]),
                "source": "correlation",
            }
        )

    repeated_services = [svc for svc, count in service_counts.items() if count >= min_count]
    if repeated_services:
        detections.append(
            {
                "severity": "low",
                "summary": "Service endpoints reused across captures",
                "details": ", ".join(repeated_services[:6]),
                "source": "correlation",
            }
        )

    return CorrelationSummary(
        path=Path("ALL_PCAPS"),
        total_pcaps=total_pcaps,
        host_counts=host_counts,
        service_counts=service_counts,
        host_presence={ip: sorted(pcaps) for ip, pcaps in host_map.items()},
        service_presence={svc: sorted(pcaps) for svc, pcaps in service_map.items()},
        detections=detections,
        errors=sorted({err for err in errors if err}),
    )
