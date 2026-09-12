"""Rendered output for udp analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable
from ..coloring import (
    danger,
    header,
    muted,
    ok,
    warn,
)
from ..udp import UdpConversation, UdpSummary
from ..utils import (
    format_bytes_as_mb,
    format_duration,
    format_ts,
    sparkline,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _FULL_OUTPUT_LIMIT,
    _apply_verbose_limit,
    _counter_table,
    _filtered_detections,
    _finalize_output,
    _format_kv,
    _format_sessions_table,
    _format_table,
    _limit_value,
)


def render_udp_summary(
    summary: UdpSummary, limit: int = 12, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit) or limit
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"UDP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    verdict = str(getattr(summary, "analyst_verdict", "") or "")
    confidence = str(getattr(summary, "analyst_confidence", "") or "").upper()
    reasons = [str(v) for v in list(getattr(summary, "analyst_reasons", []) or [])]
    if verdict:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Analyst Verdict"))
        if confidence:
            lines.append(_format_kv("Verdict", f"{verdict} (confidence: {confidence})"))
        else:
            lines.append(_format_kv("Verdict", verdict))
        for reason in reasons[: _limit_value(8)]:
            lines.append(muted(f"- {reason}"))

    udp_packet_ratio = (
        (summary.udp_packets / summary.total_packets) if summary.total_packets else 0.0
    )
    udp_byte_ratio = (
        (summary.udp_bytes / summary.total_bytes) if summary.total_bytes else 0.0
    )
    avg_udp_pkt = (
        (summary.udp_bytes / summary.udp_packets) if summary.udp_packets else 0.0
    )
    avg_udp_payload = (
        (summary.udp_payload_bytes / summary.udp_packets)
        if summary.udp_packets
        else 0.0
    )
    udp_pps = (
        (summary.udp_packets / summary.duration_seconds)
        if summary.duration_seconds
        else 0.0
    )
    udp_bps = (
        (summary.udp_bytes / summary.duration_seconds)
        if summary.duration_seconds
        else 0.0
    )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Protocol Statistics"))
    lines.append(
        _format_kv("UDP Packets", f"{summary.udp_packets} ({udp_packet_ratio:.1%})")
    )
    lines.append(
        _format_kv(
            "UDP Bytes",
            f"{format_bytes_as_mb(summary.udp_bytes)} ({udp_byte_ratio:.1%})",
        )
    )
    lines.append(_format_kv("Unique Clients", str(len(summary.client_counts))))
    lines.append(_format_kv("Unique Servers", str(len(summary.server_counts))))
    lines.append(_format_kv("Unique Endpoints", str(len(summary.endpoint_packets))))
    lines.append(_format_kv("Conversations", str(len(summary.conversations))))
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Overall Traffic Statistics"))
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(
        _format_kv("UDP Payload Bytes", format_bytes_as_mb(summary.udp_payload_bytes))
    )
    lines.append(_format_kv("Avg UDP Packet Size", f"{avg_udp_pkt:.1f} bytes"))
    lines.append(_format_kv("Avg UDP Payload Size", f"{avg_udp_payload:.1f} bytes"))
    lines.append(_format_kv("UDP Packets/sec", f"{udp_pps:.2f}"))
    lines.append(_format_kv("UDP Bytes/sec", f"{udp_bps:.2f}"))

    checks = dict(getattr(summary, "deterministic_checks", {}) or {})
    if checks:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Deterministic UDP Security Checks"))
        check_labels = {
            "reflection_amplification_risk": "Reflection/amplification risk",
            "udp_recon_scan_behavior": "UDP recon/scan behavior",
            "udp_periodic_cadence": "UDP periodic cadence",
            "udp_tunneling_signal": "UDP tunneling/covert signal",
            "udp_transport_fragmentation_reliability": "UDP transport/reliability abuse",
        }
        for key, label_text in check_labels.items():
            values = [str(v) for v in list(checks.get(key, []) or [])]
            if values:
                lines.append(warn(f"[!] {label_text}: {len(values)}"))
                for item in values[: _limit_value(8)]:
                    lines.append(muted(f"  - {item}"))
            else:
                lines.append(ok(f"[ ] {label_text}: none"))


    asymmetry_profiles = list(getattr(summary, "asymmetry_profiles", []) or [])
    if asymmetry_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("UDP Asymmetry Matrix"))
        rows = [["Flow", "Packets", "Avg Packet", "Confidence"]]
        for profile in asymmetry_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("flow", "-")),
                    str(profile.get("packets", 0)),
                    str(profile.get("avg_packet", "-")),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    amplification_profiles = list(getattr(summary, "amplification_profiles", []) or [])
    if amplification_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Reflection/Amplification Candidates"))
        rows = [["Client", "Server", "Port", "Ratio", "Confidence"]]
        for profile in amplification_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("client", "-")),
                    str(profile.get("server", "-")),
                    str(profile.get("port", "-")),
                    str(profile.get("ratio", "-")),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    recon_profiles = list(getattr(summary, "recon_profiles", []) or [])
    if recon_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Recon Indicators"))
        rows = [["Source", "Port", "Unique Ports", "Targets", "Confidence"]]
        for profile in recon_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("source", "-")),
                    str(profile.get("port", "-")),
                    str(profile.get("unique_ports", "-")),
                    str(profile.get("targets", "-")),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    cadence_profiles = list(getattr(summary, "cadence_profiles", []) or [])
    if cadence_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("UDP Cadence Anomalies"))
        rows = [["Flow", "Packets", "Duration", "PPS", "Avg Packet"]]
        for profile in cadence_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("flow", "-")),
                    str(profile.get("packets", 0)),
                    str(profile.get("duration_s", "-")),
                    str(profile.get("pps", "-")),
                    str(profile.get("avg_packet", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    tunneling_profiles = list(getattr(summary, "tunneling_profiles", []) or [])
    if tunneling_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Encapsulation/Tunneling Suspicion"))
        rows = [["Host", "Queries", "Unique Ratio", "Avg Len", "Entropy", "Confidence"]]
        for profile in tunneling_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("host", "-")),
                    str(profile.get("queries", 0)),
                    str(profile.get("unique_ratio", "-")),
                    str(profile.get("avg_len", "-")),
                    str(profile.get("avg_entropy", "-")),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    zone_profiles = list(getattr(summary, "zone_profiles", []) or [])
    if zone_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Zone Posture (East-West / North-South)"))
        rows = [["Src", "Dst", "Port", "Zone", "Packets", "Confidence"]]
        for profile in zone_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("src", "-")),
                    str(profile.get("dst", "-")),
                    str(profile.get("port", "-")),
                    str(profile.get("zone", "-")),
                    str(profile.get("packets", 0)),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    role_profiles = list(getattr(summary, "role_drift_profiles", []) or [])
    if role_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Role Drift by UDP Behavior"))
        rows = [["Host", "Dst", "Port", "Reason", "Confidence"]]
        for profile in role_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("host", "-")),
                    str(profile.get("dst", "-")),
                    str(profile.get("port", "-")),
                    str(profile.get("reason", "-")),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    ot_profiles = list(getattr(summary, "ot_boundary_profiles", []) or [])
    if ot_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT Boundary Crossing Profiles"))
        rows = [["Src", "Dst", "Port", "Packets", "Confidence"]]
        for profile in ot_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("src", "-")),
                    str(profile.get("dst", "-")),
                    str(profile.get("port", "-")),
                    str(profile.get("packets", 0)),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    transport_profiles = list(getattr(summary, "transport_profiles", []) or [])
    if transport_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("UDP Transport Reliability Anomalies"))
        rows = [["Src", "Dst", "Type", "Bytes", "Confidence"]]
        for profile in transport_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("src", "-")),
                    str(profile.get("dst", "-")),
                    str(profile.get("type", "-")),
                    format_bytes_as_mb(int(profile.get("bytes", 0) or 0)),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    corroborated_findings = list(getattr(summary, "corroborated_findings", []) or [])
    if corroborated_findings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Corroborated Findings"))
        rows = [["Host", "Score", "Confidence", "Reasons"]]
        for finding in corroborated_findings[:limit]:
            if not isinstance(finding, dict):
                continue
            rows.append(
                [
                    str(finding.get("host", "-")),
                    str(finding.get("score", "-")),
                    str(finding.get("confidence", "-")),
                    ", ".join(str(v) for v in list(finding.get("reasons", []) or []))
                    or "-",
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    false_positive_context = [
        str(v)
        for v in list(getattr(summary, "false_positive_context", []) or [])
        if str(v).strip()
    ]
    if false_positive_context:
        lines.append(SUBSECTION_BAR)
        lines.append(header("False-Positive Context"))
        for item in false_positive_context[: _limit_value(8)]:
            lines.append(muted(f"- {item}"))

    if summary.packet_size_hist or summary.payload_size_hist:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Packet & Payload Size Distribution"))
        bucket_labels = [
            "<=64",
            "65-128",
            "129-256",
            "257-512",
            "513-1024",
            "1025-1500",
            "1501-9000",
            ">9000",
        ]
        if summary.packet_size_hist:
            packet_series = [
                summary.packet_size_hist.get(label, 0) for label in bucket_labels
            ]
            lines.append(_format_kv("Packet Size Buckets", ", ".join(bucket_labels)))
            lines.append(_format_kv("Packet Size Spark", sparkline(packet_series)))
            stats = summary.packet_size_stats
            lines.append(
                _format_kv(
                    "Packet Size Stats",
                    f"min {stats.get('min', 0):.0f} / p50 {stats.get('p50', 0):.0f} / p95 {stats.get('p95', 0):.0f} / max {stats.get('max', 0):.0f}",
                )
            )
        if summary.payload_size_hist:
            payload_series = [
                summary.payload_size_hist.get(label, 0) for label in bucket_labels
            ]
            lines.append(_format_kv("Payload Size Buckets", ", ".join(bucket_labels)))
            lines.append(_format_kv("Payload Size Spark", sparkline(payload_series)))
            stats = summary.payload_size_stats
            lines.append(
                _format_kv(
                    "Payload Size Stats",
                    f"min {stats.get('min', 0):.0f} / p50 {stats.get('p50', 0):.0f} / p95 {stats.get('p95', 0):.0f} / max {stats.get('max', 0):.0f}",
                )
            )
        if summary.zero_payload_packets:
            lines.append(
                _format_kv("Zero Payload Packets", str(summary.zero_payload_packets))
            )

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("UDP Conversations"))
        rows = [["Src", "Dst", "Sport", "Dport", "Packets", "Bytes"]]
        for convo in summary.conversations[:limit]:
            rows.append(
                [
                    convo.src_ip,
                    convo.dst_ip,
                    str(convo.src_port),
                    str(convo.dst_port),
                    str(convo.packets),
                    format_bytes_as_mb(convo.bytes),
                ]
            )
        lines.append(_format_table(rows))
        lines.append(SUBSECTION_BAR)
        lines.append(header("UDP Sessions"))
        lines.append(_format_sessions_table(summary.conversations, limit))

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("UDP Client/Server Statistics"))
        client_bytes = (
            summary.client_bytes
            if isinstance(summary.client_bytes, Counter)
            else Counter()
        )
        server_bytes = (
            summary.server_bytes
            if isinstance(summary.server_bytes, Counter)
            else Counter()
        )
        rows = [["Client", "Server"]]
        client_list = [
            f"{ip}({summary.client_counts[ip]}/{format_bytes_as_mb(client_bytes.get(ip, 0))})"
            for ip, _count in summary.client_counts.most_common(_FULL_OUTPUT_LIMIT)
        ]
        server_list = [
            f"{ip}({summary.server_counts[ip]}/{format_bytes_as_mb(server_bytes.get(ip, 0))})"
            for ip, _count in summary.server_counts.most_common(_FULL_OUTPUT_LIMIT)
        ]
        max_rows = max(len(client_list), len(server_list))
        for idx in range(max_rows):
            rows.append(
                [
                    client_list[idx] if idx < len(client_list) else "-",
                    server_list[idx] if idx < len(server_list) else "-",
                ]
            )
        lines.append(_format_table(rows))

    if summary.endpoint_packets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("UDP Endpoint Statistics"))
        rows = [["Endpoint", "Packets", "Bytes"]]
        endpoint_bytes = (
            summary.endpoint_bytes
            if isinstance(summary.endpoint_bytes, Counter)
            else Counter()
        )
        for ip, count in summary.endpoint_packets.most_common(limit):
            rows.append([ip, str(count), format_bytes_as_mb(endpoint_bytes.get(ip, 0))])
        lines.append(_format_table(rows))

    if summary.port_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top UDP Destination Ports"))
        rows = [["Port", "Count", "Destinations"]]
        port_destinations = (
            summary.port_destinations
            if isinstance(summary.port_destinations, dict)
            else {}
        )
        for port, count in summary.port_counts.most_common(limit):
            dsts = port_destinations.get(port, Counter())
            dst_text = (
                ", ".join(
                    f"{ip}({cnt})" for ip, cnt in dsts.most_common(_FULL_OUTPUT_LIMIT)
                )
                or "-"
            )
            rows.append([str(port), str(count), dst_text])
        lines.append(_format_table(rows))

    if summary.services:
        lines.append(SUBSECTION_BAR)
        lines.append(header("UDP Services (Endpoints)"))
        rows = [["Service", "Endpoint", "Port", "Clients", "Count"]]
        for svc in summary.services[:limit]:
            client_note = str(svc.get("clients", "-"))
            if svc.get("client_count"):
                client_note = f"{svc.get('client_count')} :: {client_note}"
            rows.append(
                [
                    str(svc.get("service", "-")),
                    str(svc.get("endpoint", "-")),
                    str(svc.get("port", "-")),
                    client_note,
                    str(svc.get("count", "-")),
                ]
            )
        lines.append(_format_table(rows))

    if summary.file_artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files Discovered (All Protocols)"))
        lines.append(_counter_table(summary.file_artifacts, "Filename", limit=limit))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity == "critical":
                marker = danger("[CRIT]")
            elif severity == "high":
                marker = danger("[HIGH]")
            elif severity == "warning":
                marker = warn("[WARN]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts"))
        for item in summary.artifacts:
            lines.append(muted(f"- {item}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)


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
