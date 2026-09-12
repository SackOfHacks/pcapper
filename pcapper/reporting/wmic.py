"""Rendered output for wmic analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    danger,
    header,
    muted,
    ok,
    warn,
)
from ..utils import (
    format_bytes_as_mb,
    format_duration,
)
from ..wmic import WmicSummary

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _annotate_macs,
    _apply_verbose_limit,
    _counter_table,
    _filtered_detections,
    _finalize_output,
    _format_client_server_table,
    _format_kv,
    _format_sessions_table,
    _format_table,
    _limit_value,
    _meaningful_plaintext_items,
    _render_deterministic_checks,
    _render_protocol_verdict,
    _truncate_text,
)


def render_wmic_summary(
    summary: WmicSummary, limit: int = 12, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit)
    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"WMIC/WMI ANALYSIS :: {summary.path.name}"))
    _render_protocol_verdict(
        lines,
        label="WMI/WMIC",
        detections=getattr(summary, "detections", None),
        anomalies=getattr(summary, "anomalies", None),
    )
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("WMIC Packets", str(summary.wmic_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    if summary.client_bytes or summary.server_bytes:
        lines.append(
            _format_kv("Client -> Server", format_bytes_as_mb(summary.client_bytes))
        )
        lines.append(
            _format_kv("Server -> Client", format_bytes_as_mb(summary.server_bytes))
        )
    if summary.duration_seconds is not None:
        lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))
    lines.append(_format_kv("Sessions", str(summary.total_sessions)))
    lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))

    if summary.server_ports:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server Ports"))
        lines.append(_counter_table(summary.server_ports, "Port", limit=limit))

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top WMIC Clients & Servers"))
        lines.append(
            _format_client_server_table(summary.client_counts, summary.server_counts)
        )

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("WMIC Sessions"))
        lines.append(_format_sessions_table(summary.conversations, limit))

    if summary.ip_to_macs:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed MACs"))
        rows = [["IP", "MACs"]]
        ranked_ips = sorted(
            summary.ip_to_macs.keys(),
            key=lambda ip: summary.client_counts.get(ip, 0)
            + summary.server_counts.get(ip, 0),
            reverse=True,
        )
        for ip in ranked_ips[:limit]:
            macs = _annotate_macs(summary.ip_to_macs.get(ip, []))
            rows.append([ip, _truncate_text(macs, 60)])
        lines.append(_format_table(rows))

    if summary.hostnames or summary.ip_strings or summary.mac_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Host Details"))
        rows = [["Hostnames", "IPs", "MACs"]]
        host_text = (
            ", ".join(
                name for name, _count in summary.hostnames.most_common(_limit_value(8))
            )
            if summary.hostnames
            else "-"
        )
        ip_text = (
            ", ".join(
                ip for ip, _count in summary.ip_strings.most_common(_limit_value(8))
            )
            if summary.ip_strings
            else "-"
        )
        mac_text = (
            ", ".join(
                mac for mac, _count in summary.mac_strings.most_common(_limit_value(6))
            )
            if summary.mac_strings
            else "-"
        )
        rows.append(
            [
                _truncate_text(host_text, 60),
                _truncate_text(ip_text, 60),
                _truncate_text(mac_text, 60),
            ]
        )
        lines.append(_format_table(rows))

    if summary.domains or summary.usernames:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Domain & Users"))
        rows = [["Domains", "Users"]]
        domain_text = (
            ", ".join(
                dom for dom, _count in summary.domains.most_common(_limit_value(8))
            )
            if summary.domains
            else "-"
        )
        user_text = (
            ", ".join(
                user for user, _count in summary.usernames.most_common(_limit_value(8))
            )
            if summary.usernames
            else "-"
        )
        rows.append([_truncate_text(domain_text, 60), _truncate_text(user_text, 60)])
        lines.append(_format_table(rows))

    if summary.wmi_namespaces:
        lines.append(SUBSECTION_BAR)
        lines.append(header("WMI Namespaces"))
        rows = [["Namespace", "Count"]]
        for name, count in summary.wmi_namespaces.most_common(limit):
            rows.append([_truncate_text(name, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.wmi_classes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("WMI Classes"))
        rows = [["Class", "Count"]]
        for name, count in summary.wmi_classes.most_common(limit):
            rows.append([_truncate_text(name, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.wmic_commands:
        lines.append(SUBSECTION_BAR)
        lines.append(header("WMIC Commands"))
        rows = [["Command", "Count"]]
        for cmd, count in summary.wmic_commands.most_common(limit):
            rows.append([_truncate_text(cmd, 70), str(count)])
        lines.append(_format_table(rows))

    if summary.wmi_queries:
        lines.append(SUBSECTION_BAR)
        lines.append(header("WMI Queries"))
        rows = [["Query", "Count"]]
        for query, count in summary.wmi_queries.most_common(limit):
            rows.append([_truncate_text(query, 70), str(count)])
        lines.append(_format_table(rows))

    if summary.plaintext_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Plaintext"))
        rows = [["String", "Count"]]
        for text, count in _meaningful_plaintext_items(summary.plaintext_strings, limit):
            rows.append([_truncate_text(text, 70), str(count)])
        lines.append(_format_table(rows))

    if summary.services:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Service Indicators"))
        rows = [["Indicator", "Count"]]
        for name, count in summary.services.most_common(limit):
            rows.append([_truncate_text(name, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.error_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Auth & RPC Errors"))
        rows = [["Error", "Count"]]
        for name, count in summary.error_counts.most_common(limit):
            rows.append([_truncate_text(name, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.suspicious_commands:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Suspicious Commands"))
        rows = [["Indicator", "Count"]]
        for name, count in summary.suspicious_commands.most_common(limit):
            rows.append([_truncate_text(name, 70), str(count)])
        lines.append(_format_table(rows))

    if summary.anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies"))
        for item in summary.anomalies[:limit]:
            title = str(item.get("title", "Event"))
            details = str(item.get("details", ""))
            if details:
                lines.append(warn(f"- {title}: {details}"))
            else:
                lines.append(warn(f"- {title}"))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity in {"critical", "high"}:
                marker = danger("[HIGH]")
                summary_text = danger(summary_text)
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
        for item in summary.artifacts[:limit]:
            lines.append(f"- {_truncate_text(item, 80)}")

    if summary.conversations and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Sessions"))
        rows = [["Client", "Server", "C->S MB", "S->C MB", "Packets", "Hints"]]
        top_sessions = sorted(
            summary.conversations, key=lambda conv: conv.bytes, reverse=True
        )[:limit]
        for conv in top_sessions:
            rows.append(
                [
                    f"{conv.client_ip}:{conv.client_port}",
                    f"{conv.server_ip}:{conv.server_port}",
                    f"{conv.client_bytes / (1024 * 1024):.1f}",
                    f"{conv.server_bytes / (1024 * 1024):.1f}",
                    str(conv.packets),
                    ", ".join(conv.hints) if conv.hints else "-",
                ]
            )
        lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    _render_deterministic_checks(
        lines, summary, "Deterministic WMI/WMIC Security Checks", [
            ("wmic_remote_execution_tradecraft", "Remote-Execution Tradecraft"),
            ("wmic_namespace_persistence_context", "Namespace/Persistence Context"),
            ("wmic_auth_failure_burst", "Auth Failure Burst"),
            ("wmic_node_fanout", "Source Node Fan-out"),
            ("wmic_target_fanout", "Target Fan-out"),
            ("wmic_periodic_activity", "Periodic Activity"),
            ("wmic_data_exfil_asymmetry", "Data-Exfil Asymmetry"),
            ("wmic_public_endpoint_exposure", "Public Endpoint Exposure"),
        ]
    )
    return _finalize_output(lines)
