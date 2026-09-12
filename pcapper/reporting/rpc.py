"""Rendered output for rpc analysis.

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
from ..rpc import RpcSummary
from ..utils import (
    format_bytes_as_mb,
    format_duration,
    format_ts,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _apply_verbose_limit,
    _counter_table,
    _filtered_detections,
    _finalize_output,
    _format_client_server_table,
    _format_kv,
    _format_sessions_table,
    _format_table,
    _meaningful_plaintext_items,
    _redact_in_text,
    _render_deterministic_checks,
    _render_protocol_verdict,
    _truncate_text,
)


def render_rpc_summary(
    summary: RpcSummary, limit: int = 12, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit)
    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"RPC ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)
    _render_protocol_verdict(
        lines,
        label="RPC",
        detections=getattr(summary, "detections", None),
        anomalies=getattr(summary, "anomalies", None),
    )

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("RPC Packets", str(summary.rpc_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    if summary.duration_seconds is not None:
        lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))
    lines.append(_format_kv("Messages", str(summary.total_messages)))
    lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))

    if summary.protocol_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Protocol Activity"))
        lines.append(_counter_table(summary.protocol_counts, "Protocol", limit=limit))

    if summary.server_ports:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server Ports"))
        lines.append(_counter_table(summary.server_ports, "Port", limit=limit))

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top RPC Clients & Servers"))
        lines.append(
            _format_client_server_table(summary.client_counts, summary.server_counts)
        )

    if summary.pdu_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("RPC PDU Types"))
        lines.append(_counter_table(summary.pdu_counts, "PDU", limit=limit))

    if summary.interface_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("RPC Interfaces"))
        rows = [["Interface", "Count"]]
        for name, count in summary.interface_counts.most_common(limit):
            rows.append([_truncate_text(name, 70), str(count)])
        lines.append(_format_table(rows))

    if getattr(summary, "command_counts", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("RPC Commands"))
        rows = [["Command", "Count"]]
        for name, count in summary.command_counts.most_common(limit):
            rows.append([_truncate_text(name, 70), str(count)])
        lines.append(_format_table(rows))

    if summary.share_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Shares"))
        rows = [["Share", "Count", "Type"]]
        for share, count in summary.share_counts.most_common(limit):
            share_name = str(share).split("\\")[-1]
            share_type = "Admin" if share_name.upper().endswith("$") else "Normal"
            rows.append(
                [
                    _truncate_text(_redact_in_text(str(share)), 70),
                    str(count),
                    share_type,
                ]
            )
        lines.append(_format_table(rows))

    if summary.pipe_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Named Pipes"))
        rows = [["Pipe", "Count"]]
        for name, count in summary.pipe_counts.most_common(limit):
            rows.append([_truncate_text(_redact_in_text(str(name)), 70), str(count)])
        lines.append(_format_table(rows))

    if summary.hostname_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Hostnames"))
        rows = [["Hostname", "Count"]]
        for name, count in summary.hostname_counts.most_common(limit):
            rows.append([_truncate_text(name, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.domain_user_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Domain Users"))
        rows = [["Domain\\User", "Count"]]
        for name, count in summary.domain_user_counts.most_common(limit):
            rows.append([_truncate_text(name, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.ip_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("IP Strings"))
        lines.append(_counter_table(summary.ip_strings, "IP", limit=limit))

    if summary.mac_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("MAC Strings"))
        lines.append(_counter_table(summary.mac_strings, "MAC", limit=limit))

    if summary.plaintext_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Plaintext"))
        rows = [["String", "Count"]]
        for text, count in _meaningful_plaintext_items(summary.plaintext_strings, limit):
            rows.append([_truncate_text(text, 70), str(count)])
        lines.append(_format_table(rows))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("RPC Sessions"))
        lines.append(_format_sessions_table(summary.conversations, limit))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = _redact_in_text(str(item.get("details", "")))
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
        rows = [["Type", "Detail", "Src", "Dst"]]
        for item in summary.artifacts[:limit]:
            rows.append(
                [
                    str(item.kind),
                    _truncate_text(str(item.detail), 60),
                    str(item.src),
                    str(item.dst),
                ]
            )
        lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    _render_deterministic_checks(
        lines, summary, "Deterministic RPC Security Checks", [
            ("rpc_admin_share_or_pipe_access", "Admin-Share/Named-Pipe Access"),
            ("rpc_lateral_tooling", "Lateral-Movement Tooling"),
            ("rpc_samr_enum_activity", "SAMR/Directory Enumeration"),
            ("rpc_bind_failure_burst", "Bind Failure Burst"),
            ("rpc_scanning_fanout", "Scanning Fan-out"),
            ("rpc_beaconing_pattern", "Beaconing Pattern"),
            ("rpc_data_asymmetry_exfil", "Data-Asymmetry Exfil"),
            ("rpc_public_exposure", "Public Exposure"),
        ]
    )
    return _finalize_output(lines)
