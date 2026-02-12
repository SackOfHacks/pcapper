from __future__ import annotations

from collections import Counter
from pathlib import Path

from .equipment import equipment_artifacts
from .industrial_helpers import (
    IndustrialAnalysis,
    analyze_ethertype_protocol,
    analyze_port_protocol,
    default_artifacts,
)

PROFINET_PORTS = {34962, 34963, 34964}
PROFINET_ETHERTYPE = 0x8892


def _parse_commands(payload: bytes) -> list[str]:
    if len(payload) < 2:
        return []
    frame_id = int.from_bytes(payload[:2], "big")
    return [f"FrameID 0x{frame_id:04x}"]


def _parse_artifacts(payload: bytes) -> list[tuple[str, str]]:
    artifacts = default_artifacts(payload)
    artifacts.extend(equipment_artifacts(payload))
    return artifacts




def _merge(left: IndustrialAnalysis, right: IndustrialAnalysis) -> IndustrialAnalysis:
    left.total_packets += right.total_packets
    left.protocol_packets += right.protocol_packets
    left.total_bytes += right.total_bytes
    left.protocol_bytes += right.protocol_bytes
    left.requests += right.requests
    left.responses += right.responses
    left.src_ips.update(right.src_ips)
    left.dst_ips.update(right.dst_ips)
    left.client_ips.update(right.client_ips)
    left.server_ips.update(right.server_ips)
    left.sessions.update(right.sessions)
    left.ports.update(right.ports)
    left.commands.update(right.commands)
    for service, endpoints in right.service_endpoints.items():
        left.service_endpoints.setdefault(service, Counter()).update(endpoints)
    left.artifacts.extend(right.artifacts)
    left.anomalies.extend(right.anomalies)
    left.errors.extend(right.errors)
    left.duration = max(left.duration, right.duration)
    left.packet_size_buckets = _merge_size_buckets(
        left.packet_size_buckets, right.packet_size_buckets
    )
    left.payload_size_buckets = _merge_size_buckets(
        left.payload_size_buckets, right.payload_size_buckets
    )
    return left


def _merge_size_buckets(left: list, right: list) -> list:
    if not left:
        return list(right)
    if not right:
        return list(left)
    merged = []
    for l_bucket, r_bucket in zip(left, right):
        count = l_bucket.count + r_bucket.count
        if count:
            avg = ((l_bucket.avg * l_bucket.count) + (r_bucket.avg * r_bucket.count)) / count
            min_val = min(val for val in (l_bucket.min, r_bucket.min) if val is not None)
            max_val = max(val for val in (l_bucket.max, r_bucket.max) if val is not None)
        else:
            avg = 0.0
            min_val = 0
            max_val = 0
        merged.append(
            l_bucket.__class__(
                label=l_bucket.label,
                count=count,
                avg=avg,
                min=min_val,
                max=max_val,
                pct=0.0,
            )
        )
    total = sum(bucket.count for bucket in merged)
    if not total:
        return merged
    updated = []
    for bucket in merged:
        updated.append(
            bucket.__class__(
                label=bucket.label,
                count=bucket.count,
                avg=bucket.avg,
                min=bucket.min,
                max=bucket.max,
                pct=(bucket.count / total) * 100,
            )
        )
    return updated


def analyze_profinet(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    port_analysis = analyze_port_protocol(
        path=path,
        protocol_name="Profinet",
        tcp_ports=PROFINET_PORTS,
        udp_ports=PROFINET_PORTS,
        command_parser=_parse_commands,
        artifact_parser=_parse_artifacts,
        enable_enrichment=True,
        show_status=show_status,
    )
    eth_analysis = analyze_ethertype_protocol(
        path=path,
        protocol_name="Profinet RT",
        ethertype=PROFINET_ETHERTYPE,
        command_parser=_parse_commands,
        artifact_parser=_parse_artifacts,
        enable_enrichment=True,
        show_status=show_status,
    )
    return _merge(port_analysis, eth_analysis)
