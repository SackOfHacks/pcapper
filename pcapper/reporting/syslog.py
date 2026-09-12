"""Rendered output for syslog analysis.

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
from ..syslog import SyslogSummary
from ..utils import (
    format_bytes_as_mb,
    format_duration,
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
    _limit_value,
    _meaningful_plaintext_items,
    _render_protocol_verdict,
    _truncate_text,
)


def render_syslog_summary(
    summary: SyslogSummary, limit: int = 12, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit)
    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"SYSLOG ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)
    _render_protocol_verdict(
        lines,
        label="Syslog",
        detections=getattr(summary, "detections", None),
        anomalies=getattr(summary, "anomalies", None),
    )

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("Syslog Packets", str(summary.syslog_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    if summary.duration_seconds is not None:
        lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))
    lines.append(_format_kv("Messages", str(summary.total_messages)))
    lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))

    if summary.server_ports:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server Ports"))
        lines.append(_counter_table(summary.server_ports, "Port", limit=limit))

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Syslog Clients & Servers"))
        lines.append(
            _format_client_server_table(summary.client_counts, summary.server_counts)
        )

    if summary.hostname_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Hostnames"))
        rows = [["Hostname", "Count"]]
        for name, count in summary.hostname_counts.most_common(limit):
            rows.append([_truncate_text(name, 50), str(count)])
        lines.append(_format_table(rows))

    if summary.appname_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Applications"))
        rows = [["App", "Count"]]
        for name, count in summary.appname_counts.most_common(limit):
            rows.append([_truncate_text(name, 50), str(count)])
        lines.append(_format_table(rows))

    if summary.version_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Syslog Versions"))
        lines.append(_counter_table(summary.version_counts, "Version", limit=limit))

    if summary.facility_counts or summary.severity_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Facility & Severity"))
        rows = [["Facilities", "Severities"]]
        facility_text = (
            ", ".join(
                f"{name}({count})"
                for name, count in summary.facility_counts.most_common(_limit_value(6))
            )
            or "-"
        )
        severity_text = (
            ", ".join(
                f"{name}({count})"
                for name, count in summary.severity_counts.most_common(_limit_value(6))
            )
            or "-"
        )
        rows.append([facility_text, severity_text])
        lines.append(_format_table(rows))

    if summary.request_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Request Summary"))
        rows = [["Request", "Count"]]
        for name, count in summary.request_counts.most_common(limit):
            rows.append([_truncate_text(name, 50), str(count)])
        lines.append(_format_table(rows))

    if summary.response_codes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Response Codes"))
        rows = [["Code", "Count"]]
        for name, count in summary.response_codes.most_common(limit):
            rows.append([_truncate_text(name, 30), str(count)])
        lines.append(_format_table(rows))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Syslog Sessions"))
        lines.append(_format_sessions_table(summary.conversations, limit))

    if summary.plaintext_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Plaintext"))
        rows = [["String", "Count"]]
        for text, count in _meaningful_plaintext_items(summary.plaintext_strings, limit):
            rows.append([_truncate_text(text, 70), str(count)])
        lines.append(_format_table(rows))

    if summary.file_artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files Discovered"))
        rows = [["File", "Count"]]
        for name, count in summary.file_artifacts.most_common(limit):
            rows.append([_truncate_text(name, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies"))
        for item in summary.anomalies[:limit]:
            title = item.title
            details = item.details
            sev = item.severity
            sev_color = danger if sev in ("HIGH", "CRITICAL") else warn
            lines.append(sev_color(f"[{sev}] {title}: {details}"))

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
    return _finalize_output(lines)
