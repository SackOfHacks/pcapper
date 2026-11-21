"""Rendered output for udp analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable
from ..udp import UdpConversation, UdpSummary
from ._transport import SIZE, http_counters, transport_report

from ._common import (
    _apply_verbose_limit,
    _limit_value,
)


def render_udp_summary(summary: UdpSummary, limit: int = 12, verbose: bool = False) -> str:
    """UDP: amplification, recon, tunneling, cadence and OT boundary
    crossings first, then the top conversations, destination ports and
    services; zone posture, reliability, endpoint roles and sizes are -v."""
    return transport_report(
        "UDP", summary,
        packets=summary.udp_packets, total_bytes=summary.udp_bytes, payload_bytes=summary.udp_payload_bytes,
        flags=False,
        profiles=[
            ("Amplification", "amplification_profiles", [("Client", "client", None), ("Server", "server", None), ("Port", "port", None),
                                                         ("Ratio", "ratio", None), ("Confidence", "confidence", None)], True),
            ("Recon", "recon_profiles", [("Source", "source", None), ("Port", "port", None), ("Unique ports", "unique_ports", None),
                                         ("Targets", "targets", None), ("Confidence", "confidence", None)], True),
            ("Tunneling", "tunneling_profiles", [("Host", "host", None), ("Queries", "queries", None), ("Unique ratio", "unique_ratio", None),
                                                 ("Avg length", "avg_len", None), ("Entropy", "avg_entropy", None),
                                                 ("Confidence", "confidence", None)], True),
            ("Cadence", "cadence_profiles", [("Flow", "flow", None), ("Packets", "packets", None), ("Duration (s)", "duration_s", None),
                                             ("Packets/s", "pps", None), ("Avg packet", "avg_packet", None)], True),
            ("OT boundary", "ot_boundary_profiles", [("Source", "src", None), ("Destination", "dst", None), ("Port", "port", None),
                                                     ("Packets", "packets", None), ("Confidence", "confidence", None)], True),
            ("Role drift", "role_drift_profiles", [("Host", "host", None), ("Destination", "dst", None), ("Port", "port", None),
                                                   ("Reason", "reason", None), ("Confidence", "confidence", None)], True),
            ("Corroborated hosts", "corroborated_findings", [("Host", "host", None), ("Score", "score", None),
                                                             ("Confidence", "confidence", None), ("Reasons", "reasons", None)], True),
            ("Asymmetry", "asymmetry_profiles", [("Flow", "flow", None), ("Packets", "packets", None), ("Avg packet", "avg_packet", None),
                                                 ("Confidence", "confidence", None)], False),
            ("Zones", "zone_profiles", [("Source", "src", None), ("Destination", "dst", None), ("Port", "port", None), ("Zone", "zone", None),
                                        ("Packets", "packets", None), ("Confidence", "confidence", None)], False),
            ("Transport reliability", "transport_profiles", [("Source", "src", None), ("Destination", "dst", None), ("Type", "type", None),
                                                             ("Bytes", "bytes", SIZE), ("Confidence", "confidence", None)], False),
        ],
        counters=http_counters(summary),
        deterministic=("Deterministic UDP Security Checks", [
            ("reflection_amplification_risk", "Reflection/amplification risk"),
            ("udp_recon_scan_behavior", "UDP recon/scan behavior"),
            ("udp_periodic_cadence", "UDP periodic cadence"),
            ("udp_tunneling_signal", "UDP tunneling/covert signal"),
            ("udp_transport_fragmentation_reliability", "UDP transport/reliability abuse"),
        ]),
    )


def _udp_bucket_ranges() -> list[tuple[str, int, int]]:
    return [
        ("<=64", 0, 64),
        ("65-128", 65, 128),
        ("129-256", 129, 256),
        ("257-512", 257, 512),
        ("513-1024", 513, 1024),
        ("1025-1500", 1025, 1500),
        ("1501-9000", 1501, 9000),
        (">9000", 9001, 9001),
    ]


def _approx_hist_stats(hist: Counter[str]) -> dict[str, float]:
    if not hist:
        return {"min": 0.0, "max": 0.0, "avg": 0.0, "p50": 0.0, "p95": 0.0}

    ranges = _udp_bucket_ranges()
    total = sum(hist.values())
    if total <= 0:
        return {"min": 0.0, "max": 0.0, "avg": 0.0, "p50": 0.0, "p95": 0.0}

    min_val = 0.0
    max_val = 0.0
    for range_label, low, high in ranges:
        if hist.get(range_label, 0) > 0:
            min_val = float(low)
            break
    for range_label, low, high in reversed(ranges):
        if hist.get(range_label, 0) > 0:
            max_val = float(high)
            break

    def _quantile(target_pct: float) -> float:
        target = total * (target_pct / 100.0)
        running = 0
        for range_label, low, high in ranges:
            running += hist.get(range_label, 0)
            if running >= target:
                if range_label == ">9000":
                    return float(low)
                return float((low + high) / 2)
        return max_val

    weighted_sum = 0.0
    for range_label, low, high in ranges:
        mid = float(low) if range_label == ">9000" else float((low + high) / 2)
        weighted_sum += mid * hist.get(range_label, 0)

    return {
        "min": min_val,
        "max": max_val,
        "avg": weighted_sum / total,
        "p50": _quantile(50.0),
        "p95": _quantile(95.0),
    }


def render_udp_rollup(
    summaries: Iterable[UdpSummary], limit: int = 12, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit)
    summary_list = list(summaries)
    if not summary_list:
        return ""

    total_packets = sum(item.total_packets for item in summary_list)
    total_bytes = sum(item.total_bytes for item in summary_list)
    udp_packets = sum(item.udp_packets for item in summary_list)
    udp_bytes = sum(item.udp_bytes for item in summary_list)
    udp_payload_bytes = sum(item.udp_payload_bytes for item in summary_list)
    zero_payload_packets = sum(item.zero_payload_packets for item in summary_list)

    client_counts: Counter[str] = Counter()
    client_bytes: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    server_bytes: Counter[str] = Counter()
    port_counts: Counter[int] = Counter()
    port_destinations: dict[int, Counter[str]] = defaultdict(Counter)
    endpoint_packets: Counter[str] = Counter()
    endpoint_bytes: Counter[str] = Counter()
    packet_size_hist: Counter[str] = Counter()
    payload_size_hist: Counter[str] = Counter()
    http_methods: Counter[str] = Counter()
    http_statuses: Counter[str] = Counter()
    http_urls: Counter[str] = Counter()
    http_user_agents: Counter[str] = Counter()
    http_files: Counter[str] = Counter()
    file_artifacts: Counter[str] = Counter()
    errors: list[str] = []

    first_seen = None
    last_seen = None

    conversations: dict[tuple[str, str, int, int], dict[str, object]] = defaultdict(
        lambda: {
            "packets": 0,
            "bytes": 0,
            "first_seen": None,
            "last_seen": None,
        }
    )

    detections: dict[tuple[str, str], dict[str, object]] = {}
    artifact_counts: Counter[str] = Counter()

    services_agg: dict[tuple[str, str, int, str], dict[str, object]] = {}

    for item in summary_list:
        client_counts.update(
            item.client_counts if isinstance(item.client_counts, Counter) else Counter()
        )
        client_bytes.update(
            item.client_bytes if isinstance(item.client_bytes, Counter) else Counter()
        )
        server_counts.update(
            item.server_counts if isinstance(item.server_counts, Counter) else Counter()
        )
        server_bytes.update(
            item.server_bytes if isinstance(item.server_bytes, Counter) else Counter()
        )
        port_counts.update(
            item.port_counts if isinstance(item.port_counts, Counter) else Counter()
        )
        endpoint_packets.update(
            item.endpoint_packets
            if isinstance(item.endpoint_packets, Counter)
            else Counter()
        )
        endpoint_bytes.update(
            item.endpoint_bytes
            if isinstance(item.endpoint_bytes, Counter)
            else Counter()
        )
        packet_size_hist.update(
            item.packet_size_hist
            if isinstance(item.packet_size_hist, Counter)
            else Counter()
        )
        payload_size_hist.update(
            item.payload_size_hist
            if isinstance(item.payload_size_hist, Counter)
            else Counter()
        )
        http_methods.update(
            item.http_methods if isinstance(item.http_methods, Counter) else Counter()
        )
        http_statuses.update(
            item.http_statuses if isinstance(item.http_statuses, Counter) else Counter()
        )
        http_urls.update(
            item.http_urls if isinstance(item.http_urls, Counter) else Counter()
        )
        http_user_agents.update(
            item.http_user_agents
            if isinstance(item.http_user_agents, Counter)
            else Counter()
        )
        http_files.update(
            item.http_files if isinstance(item.http_files, Counter) else Counter()
        )
        file_artifacts.update(
            item.file_artifacts
            if isinstance(item.file_artifacts, Counter)
            else Counter()
        )
        errors.extend(item.errors if isinstance(item.errors, list) else [])

        port_map = (
            item.port_destinations if isinstance(item.port_destinations, dict) else {}
        )
        for port, counter in port_map.items():
            if isinstance(counter, Counter):
                port_destinations[port].update(counter)

        for convo in item.conversations:
            key = (convo.src_ip, convo.dst_ip, convo.src_port, convo.dst_port)
            info = conversations[key]
            info["packets"] = int(info["packets"]) + convo.packets
            info["bytes"] = int(info["bytes"]) + convo.bytes
            if convo.first_seen is not None:
                if info["first_seen"] is None or convo.first_seen < info["first_seen"]:
                    info["first_seen"] = convo.first_seen
            if convo.last_seen is not None:
                if info["last_seen"] is None or convo.last_seen > info["last_seen"]:
                    info["last_seen"] = convo.last_seen

        for det in item.detections:
            summary_text = str(det.get("summary", ""))
            details = str(det.get("details", ""))
            if not summary_text:
                continue
            detections.setdefault((summary_text, details), det)

        for artifact in item.artifacts:
            artifact_counts[artifact] += 1

        for svc in item.services:
            service = str(svc.get("service", "-"))
            endpoint = str(svc.get("endpoint", "-"))
            port = int(svc.get("port", 0)) if str(svc.get("port", "")).isdigit() else 0
            proto = str(svc.get("proto", "UDP"))
            key = (service, endpoint, port, proto)
            entry = services_agg.setdefault(
                key,
                {
                    "service": service,
                    "endpoint": endpoint,
                    "port": port,
                    "proto": proto,
                    "count": 0,
                    "client_count": 0,
                    "clients": set(),
                },
            )
            entry["count"] = int(entry["count"]) + int(svc.get("count", 0) or 0)
            entry["client_count"] = int(entry["client_count"]) + int(
                svc.get("client_count", 0) or 0
            )
            clients_text = str(svc.get("clients", "-"))
            if clients_text and clients_text != "-":
                for part in clients_text.split(","):
                    value = part.strip()
                    if value:
                        entry["clients"].add(value)

        if item.first_seen is not None:
            if first_seen is None or item.first_seen < first_seen:
                first_seen = item.first_seen
        if item.last_seen is not None:
            if last_seen is None or item.last_seen > last_seen:
                last_seen = item.last_seen

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    conversation_rows: list[UdpConversation] = []
    for (src_ip, dst_ip, sport, dport), info in conversations.items():
        conversation_rows.append(
            UdpConversation(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=sport,
                dst_port=dport,
                packets=int(info["packets"]),
                bytes=int(info["bytes"]),
                first_seen=info["first_seen"],
                last_seen=info["last_seen"],
            )
        )

    services: list[dict[str, object]] = []
    for entry in services_agg.values():
        clients_list = sorted(entry["clients"])[: _limit_value(5)]
        services.append(
            {
                "service": entry["service"],
                "endpoint": entry["endpoint"],
                "port": entry["port"],
                "proto": entry["proto"],
                "count": entry["count"],
                "client_count": entry["client_count"],
                "clients": ", ".join(clients_list) if clients_list else "-",
            }
        )

    services.sort(key=lambda value: int(value.get("count", 0)), reverse=True)
    errors = sorted({err for err in errors if err})

    rollup = UdpSummary(
        path=Path("ALL_PCAPS"),
        total_packets=total_packets,
        total_bytes=total_bytes,
        udp_packets=udp_packets,
        udp_bytes=udp_bytes,
        udp_payload_bytes=udp_payload_bytes,
        conversations=sorted(
            conversation_rows, key=lambda item: item.packets, reverse=True
        ),
        client_counts=client_counts,
        client_bytes=client_bytes,
        server_counts=server_counts,
        server_bytes=server_bytes,
        port_counts=port_counts,
        port_destinations=port_destinations,
        endpoint_packets=endpoint_packets,
        endpoint_bytes=endpoint_bytes,
        packet_size_hist=packet_size_hist,
        payload_size_hist=payload_size_hist,
        packet_size_stats=_approx_hist_stats(packet_size_hist),
        payload_size_stats=_approx_hist_stats(payload_size_hist),
        zero_payload_packets=zero_payload_packets,
        http_requests=sum(item.http_requests for item in summary_list),
        http_responses=sum(item.http_responses for item in summary_list),
        http_methods=http_methods,
        http_statuses=http_statuses,
        http_urls=http_urls,
        http_user_agents=http_user_agents,
        http_files=http_files,
        file_artifacts=file_artifacts,
        services=services,
        detections=list(detections.values()),
        artifacts=[
            f"{name} ({count})"
            for name, count in artifact_counts.most_common(_limit_value(20))
        ],
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )

    return render_udp_summary(rollup, limit=limit, verbose=verbose)
