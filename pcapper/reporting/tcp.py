"""Rendered output for tcp analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from collections import Counter
from ..coloring import (
    danger,
    header,
    muted,
    ok,
    warn,
)
from ..tcp import TcpSummary
from ..utils import (
    format_bytes_as_mb,
    format_duration,
    format_ts,
    sparkline,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _apply_verbose_limit,
    _counter_table,
    _filtered_detections,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
)


def render_tcp_summary(
    summary: TcpSummary, limit: int = 12, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit) or limit
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"TCP ANALYSIS :: {summary.path.name}"))
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

    tcp_packet_ratio = (
        (summary.tcp_packets / summary.total_packets) if summary.total_packets else 0.0
    )
    tcp_byte_ratio = (
        (summary.tcp_bytes / summary.total_bytes) if summary.total_bytes else 0.0
    )
    avg_tcp_pkt = (
        (summary.tcp_bytes / summary.tcp_packets) if summary.tcp_packets else 0.0
    )
    avg_tcp_payload = (
        (summary.tcp_payload_bytes / summary.tcp_packets)
        if summary.tcp_packets
        else 0.0
    )
    tcp_pps = (
        (summary.tcp_packets / summary.duration_seconds)
        if summary.duration_seconds
        else 0.0
    )
    tcp_bps = (
        (summary.tcp_bytes / summary.duration_seconds)
        if summary.duration_seconds
        else 0.0
    )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Protocol Statistics"))
    lines.append(
        _format_kv("TCP Packets", f"{summary.tcp_packets} ({tcp_packet_ratio:.1%})")
    )
    lines.append(
        _format_kv(
            "TCP Bytes",
            f"{format_bytes_as_mb(summary.tcp_bytes)} ({tcp_byte_ratio:.1%})",
        )
    )
    lines.append(_format_kv("Unique Clients", str(len(summary.client_counts))))
    lines.append(_format_kv("Unique Servers", str(len(summary.server_counts))))
    lines.append(
        _format_kv(
            "Unique Endpoints", str(len(getattr(summary, "endpoint_packets", {})))
        )
    )
    lines.append(_format_kv("Conversations", str(len(summary.conversations))))
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Overall Traffic Statistics"))
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(
        _format_kv("TCP Payload Bytes", format_bytes_as_mb(summary.tcp_payload_bytes))
    )
    lines.append(_format_kv("Avg TCP Packet Size", f"{avg_tcp_pkt:.1f} bytes"))
    lines.append(_format_kv("Avg TCP Payload Size", f"{avg_tcp_payload:.1f} bytes"))
    lines.append(_format_kv("TCP Packets/sec", f"{tcp_pps:.2f}"))
    lines.append(_format_kv("TCP Bytes/sec", f"{tcp_bps:.2f}"))

    checks = dict(getattr(summary, "deterministic_checks", {}) or {})
    if checks:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Deterministic TCP Security Checks"))
        check_labels = {
            "handshake_asymmetry_or_recon": "Handshake asymmetry/recon",
            "rst_teardown_abuse": "RST/teardown abuse",
            "tcp_periodic_cadence": "TCP periodic cadence",
            "lateral_movement_surface": "Lateral movement surface",
            "egress_exfil_outlier": "Egress exfil outlier",
            "transport_window_or_retrans_abuse": "Transport retrans/window abuse",
        }
        for key, label_text in check_labels.items():
            values = [str(v) for v in list(checks.get(key, []) or [])]
            if values:
                lines.append(warn(f"[!] {label_text}: {len(values)}"))
                for item in values[: _limit_value(8)]:
                    lines.append(muted(f"  - {item}"))
            else:
                lines.append(ok(f"[ ] {label_text}: none"))


    session_profiles = list(getattr(summary, "session_integrity_profiles", []) or [])
    if session_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Session State Integrity"))
        rows = [["Flow", "Issue", "Packets", "Confidence"]]
        for profile in session_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("flow", "-")),
                    str(profile.get("issue", "-")),
                    str(profile.get("packets", 0)),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    recon_profiles = list(getattr(summary, "recon_profiles", []) or [])
    if recon_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Recon and Scan Indicators"))
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

    teardown_profiles = list(getattr(summary, "teardown_profiles", []) or [])
    if teardown_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Connection Teardown Anomalies"))
        rows = [["Flow", "RST", "FIN", "Confidence"]]
        for profile in teardown_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("flow", "-")),
                    str(profile.get("rst", 0)),
                    str(profile.get("fin", 0)),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    cadence_profiles = list(getattr(summary, "cadence_profiles", []) or [])
    if cadence_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TCP Cadence Anomalies"))
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

    lateral_profiles = list(getattr(summary, "lateral_movement_profiles", []) or [])
    if lateral_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Lateral Movement Candidates"))
        rows = [["Source", "Targets", "Admin Ports", "Confidence"]]
        for profile in lateral_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("source", "-")),
                    str(profile.get("targets", "-")),
                    str(profile.get("admin_ports", "-")),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    egress_profiles = list(getattr(summary, "egress_outlier_profiles", []) or [])
    if egress_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Egress Outlier Matrix"))
        rows = [["Src", "Dst", "Bytes", "Confidence"]]
        for profile in egress_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("src", "-")),
                    str(profile.get("dst", "-")),
                    format_bytes_as_mb(int(profile.get("bytes", 0) or 0)),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    role_profiles = list(getattr(summary, "role_drift_profiles", []) or [])
    if role_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Role Drift by TCP Behavior"))
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

    transport_profiles = list(getattr(summary, "transport_abuse_profiles", []) or [])
    if transport_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Transport Reliability Anomalies"))
        rows = [["Host", "Type", "Count", "Confidence"]]
        for profile in transport_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("host", "-")),
                    str(profile.get("type", "-")),
                    str(profile.get("count", 0)),
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
        lines.append(header("TCP Conversations (Grouped by Src/Dst/Service)"))
        grouped_conversations: dict[tuple[str, str, int], dict[str, object]] = {}
        for convo in summary.conversations:
            key = (convo.src_ip, convo.dst_ip, int(convo.dst_port))
            bucket = grouped_conversations.get(key)
            if bucket is None:
                bucket = {
                    "src_ip": convo.src_ip,
                    "dst_ip": convo.dst_ip,
                    "dst_port": int(convo.dst_port),
                    "packets": 0,
                    "bytes": 0,
                    "syn": 0,
                    "syn_ack": 0,
                    "rst": 0,
                    "fin": 0,
                    "sports": set(),
                    "first_seen": convo.first_seen,
                    "last_seen": convo.last_seen,
                }
                grouped_conversations[key] = bucket
            bucket["packets"] = int(bucket["packets"]) + int(convo.packets)
            bucket["bytes"] = int(bucket["bytes"]) + int(convo.bytes)
            bucket["syn"] = int(bucket["syn"]) + int(convo.syn)
            bucket["syn_ack"] = int(bucket["syn_ack"]) + int(convo.syn_ack)
            bucket["rst"] = int(bucket["rst"]) + int(convo.rst)
            bucket["fin"] = int(bucket["fin"]) + int(convo.fin)
            cast_sports = bucket["sports"]
            if isinstance(cast_sports, set):
                cast_sports.add(int(convo.src_port))
            first_seen = bucket.get("first_seen")
            if first_seen is None or (
                convo.first_seen is not None and convo.first_seen < first_seen
            ):
                bucket["first_seen"] = convo.first_seen
            last_seen = bucket.get("last_seen")
            if last_seen is None or (
                convo.last_seen is not None and convo.last_seen > last_seen
            ):
                bucket["last_seen"] = convo.last_seen

        grouped_rows = sorted(
            grouped_conversations.values(),
            key=lambda item: (
                -int(item.get("packets", 0) or 0),
                -int(item.get("bytes", 0) or 0),
                -len(item.get("sports", set()) or set()),
                str(item.get("src_ip", "")),
                str(item.get("dst_ip", "")),
                int(item.get("dst_port", 0) or 0),
            ),
        )
        conversation_group_limit = 40
        rows = [
            [
                "Src",
                "Dst",
                "Dport",
                "Flows",
                "Packets",
                "Bytes",
                "SYN",
                "SYN-ACK",
                "RST",
                "FIN",
                "Duration",
            ]
        ]
        for item in grouped_rows[:conversation_group_limit]:
            sports = item.get("sports", set())
            flow_count = len(sports) if isinstance(sports, set) else 0
            first_seen = item.get("first_seen")
            last_seen = item.get("last_seen")
            duration = None
            if isinstance(first_seen, (int, float)) and isinstance(
                last_seen, (int, float)
            ):
                duration = max(0.0, float(last_seen) - float(first_seen))
            rows.append(
                [
                    str(item.get("src_ip", "-")),
                    str(item.get("dst_ip", "-")),
                    str(item.get("dst_port", "-")),
                    str(flow_count),
                    str(item.get("packets", 0)),
                    format_bytes_as_mb(int(item.get("bytes", 0) or 0)),
                    str(item.get("syn", 0)),
                    str(item.get("syn_ack", 0)),
                    str(item.get("rst", 0)),
                    str(item.get("fin", 0)),
                    format_duration(duration),
                ]
            )
        lines.append(_format_table(rows))
        if len(grouped_rows) > conversation_group_limit:
            remaining = grouped_rows[conversation_group_limit:]
            remaining_packets = sum(
                int(item.get("packets", 0) or 0) for item in remaining
            )
            remaining_bytes = sum(int(item.get("bytes", 0) or 0) for item in remaining)
            lines.append(
                muted(
                    f"{len(remaining)} additional grouped conversations "
                    f"({remaining_packets} packets, {format_bytes_as_mb(remaining_bytes)})."
                )
            )

        lines.append(SUBSECTION_BAR)
        lines.append(header("TCP Sessions (Grouped by Client/Server)"))
        session_rows = sorted(
            grouped_rows,
            key=lambda item: (
                -len(item.get("sports", set()) or set()),
                -int(item.get("packets", 0) or 0),
                -int(item.get("bytes", 0) or 0),
                str(item.get("src_ip", "")),
                str(item.get("dst_ip", "")),
                int(item.get("dst_port", 0) or 0),
            ),
        )
        session_group_limit = 35
        rows = [
            ["Client", "Server", "Flows", "Start", "End", "Duration", "Packets", "Size"]
        ]
        for item in session_rows[:session_group_limit]:
            sports = item.get("sports", set())
            flow_count = len(sports) if isinstance(sports, set) else 0
            first_seen = item.get("first_seen")
            last_seen = item.get("last_seen")
            duration = None
            if isinstance(first_seen, (int, float)) and isinstance(
                last_seen, (int, float)
            ):
                duration = max(0.0, float(last_seen) - float(first_seen))
            rows.append(
                [
                    str(item.get("src_ip", "-")),
                    f"{item.get('dst_ip', '-')}:{item.get('dst_port', '-')}",
                    str(flow_count),
                    format_ts(
                        first_seen if isinstance(first_seen, (int, float)) else None
                    ),
                    format_ts(
                        last_seen if isinstance(last_seen, (int, float)) else None
                    ),
                    format_duration(duration),
                    str(item.get("packets", 0)),
                    format_bytes_as_mb(int(item.get("bytes", 0) or 0)),
                ]
            )
        lines.append(_format_table(rows))
        if len(session_rows) > session_group_limit:
            remaining = session_rows[session_group_limit:]
            remaining_packets = sum(
                int(item.get("packets", 0) or 0) for item in remaining
            )
            lines.append(
                muted(
                    f"{len(remaining)} additional grouped sessions "
                    f"({remaining_packets} packets) omitted from table."
                )
            )

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TCP Client/Server Statistics (Grouped by Endpoint)"))
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
        endpoints = set(summary.client_counts) | set(summary.server_counts)
        endpoint_rollups: list[dict[str, object]] = []
        for endpoint in endpoints:
            client_pkts = int(summary.client_counts.get(endpoint, 0))
            server_pkts = int(summary.server_counts.get(endpoint, 0))
            client_byte_count = int(client_bytes.get(endpoint, 0))
            server_byte_count = int(server_bytes.get(endpoint, 0))
            total_pkts = client_pkts + server_pkts
            total_bytes = client_byte_count + server_byte_count
            if client_pkts > server_pkts:
                role = "mostly-client"
            elif server_pkts > client_pkts:
                role = "mostly-server"
            elif total_pkts > 0:
                role = "balanced"
            else:
                role = "-"
            endpoint_rollups.append(
                {
                    "endpoint": str(endpoint),
                    "client_pkts": client_pkts,
                    "client_bytes": client_byte_count,
                    "server_pkts": server_pkts,
                    "server_bytes": server_byte_count,
                    "total_pkts": total_pkts,
                    "total_bytes": total_bytes,
                    "role": role,
                }
            )
        endpoint_rollups.sort(
            key=lambda row: (
                -int(row["total_pkts"]),
                -int(row["total_bytes"]),
                str(row["endpoint"]),
            )
        )
        role_limit = 40
        rows = [
            [
                "Endpoint",
                "As Client",
                "Client Bytes",
                "As Server",
                "Server Bytes",
                "Total Pkts",
                "Total Bytes",
                "Role",
            ]
        ]
        for row in endpoint_rollups[:role_limit]:
            rows.append(
                [
                    str(row["endpoint"]),
                    str(row["client_pkts"]),
                    format_bytes_as_mb(int(row["client_bytes"])),
                    str(row["server_pkts"]),
                    format_bytes_as_mb(int(row["server_bytes"])),
                    str(row["total_pkts"]),
                    format_bytes_as_mb(int(row["total_bytes"])),
                    str(row["role"]),
                ]
            )
        lines.append(_format_table(rows))
        if len(endpoint_rollups) > role_limit:
            remaining = endpoint_rollups[role_limit:]
            remaining_total_packets = sum(int(row["total_pkts"]) for row in remaining)
            remaining_total_bytes = sum(int(row["total_bytes"]) for row in remaining)
            lines.append(
                muted(
                    f"{len(remaining)} additional endpoints omitted "
                    f"({remaining_total_packets} packets, {format_bytes_as_mb(remaining_total_bytes)} total)."
                )
            )

    if getattr(summary, "endpoint_packets", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("TCP Endpoint Statistics (Top Endpoints)"))
        rows = [["Endpoint", "Packets", "Bytes"]]
        endpoint_bytes = (
            summary.endpoint_bytes
            if isinstance(summary.endpoint_bytes, Counter)
            else Counter()
        )
        endpoint_limit = 40
        endpoint_ranked = summary.endpoint_packets.most_common()
        for ip, count in endpoint_ranked[:endpoint_limit]:
            rows.append([ip, str(count), format_bytes_as_mb(endpoint_bytes.get(ip, 0))])
        lines.append(_format_table(rows))
        if len(endpoint_ranked) > endpoint_limit:
            remaining = endpoint_ranked[endpoint_limit:]
            remaining_packets = sum(int(count) for _ip, count in remaining)
            remaining_bytes = sum(
                int(endpoint_bytes.get(ip, 0)) for ip, _count in remaining
            )
            lines.append(
                muted(
                    f"{len(remaining)} additional endpoints omitted "
                    f"({remaining_packets} packets, {format_bytes_as_mb(remaining_bytes)})."
                )
            )

    if summary.port_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top TCP Destination Ports"))
        rows = [["Port", "Count", "Unique Dsts", "Top Destinations"]]
        port_destinations = (
            summary.port_destinations
            if isinstance(summary.port_destinations, dict)
            else {}
        )
        port_limit = 40
        top_destination_limit = 8
        port_rows = summary.port_counts.most_common(port_limit)
        for port, count in port_rows:
            dsts = port_destinations.get(port, Counter())
            unique_dsts = len(dsts) if isinstance(dsts, Counter) else 0
            if isinstance(dsts, Counter):
                preview_items = dsts.most_common(top_destination_limit)
            else:
                preview_items = []
            dst_text = ", ".join(f"{ip}({cnt})" for ip, cnt in preview_items) or "-"
            if unique_dsts > top_destination_limit:
                dst_text = (
                    f"{dst_text}, ... +{unique_dsts - top_destination_limit} more"
                )
            rows.append([str(port), str(count), str(unique_dsts), dst_text])
        lines.append(_format_table(rows))
        if len(summary.port_counts) > port_limit:
            remaining = summary.port_counts.most_common()[port_limit:]
            remaining_count = sum(int(count) for _port, count in remaining)
            lines.append(
                muted(
                    f"{len(remaining)} additional destination ports account for "
                    f"{remaining_count} packets."
                )
            )

    if summary.services:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TCP Services (Endpoints)"))
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
