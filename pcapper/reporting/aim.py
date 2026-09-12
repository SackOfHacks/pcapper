"""Rendered output for aim analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..aim import AimSummary
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
    _format_table,
    _limit_value,
    _render_protocol_verdict,
    _truncate_text,
)


def render_aim_summary(
    summary: AimSummary, limit: int = 12, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit)
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"AIM ANALYSIS :: {summary.path.name}"))
    _render_protocol_verdict(
        lines,
        label="AIM",
        detections=getattr(summary, "detections", None),
        anomalies=getattr(summary, "anomalies", None),
    )
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Packets Scanned", str(summary.total_packets)))
    lines.append(_format_kv("AIM Packets", str(summary.aim_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(_format_kv("AIM Bytes", format_bytes_as_mb(summary.aim_bytes)))
    lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Clients & Servers"))
        lines.append(
            _format_client_server_table(summary.client_counts, summary.server_counts)
        )

    if summary.server_ports:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server Ports"))
        lines.append(_counter_table(summary.server_ports, "Port", limit=limit))

    if summary.username_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Usernames"))
        rows = [["Username", "Count"]]
        for user, count in summary.username_counts.most_common(limit):
            rows.append([_truncate_text(user, 48), str(count)])
        lines.append(_format_table(rows))

    if summary.password_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Passwords"))
        rows = [["Password", "Count"]]
        for secret, count in summary.password_counts.most_common(limit):
            rows.append([_truncate_text(secret, 64), str(count)])
        lines.append(_format_table(rows))

    if summary.secret_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Secrets"))
        rows = [["Secret", "Count"]]
        for secret, count in summary.secret_counts.most_common(limit):
            rows.append([_truncate_text(secret, 64), str(count)])
        lines.append(_format_table(rows))

    if summary.message_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Recovered Messages"))
        rows = [["Message", "Count"]]
        for message, count in summary.message_counts.most_common(limit):
            rows.append([_truncate_text(message, 96), str(count)])
        lines.append(_format_table(rows))

    if summary.file_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Recovered Files"))
        rows = [["Filename", "Count"]]
        for name, count in summary.file_counts.most_common(limit):
            rows.append([_truncate_text(name, 80), str(count)])
        lines.append(_format_table(rows))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Conversations"))
        rows = [["Client", "Server", "Port", "Packets", "Bytes", "First", "Last"]]
        conversations = sorted(
            summary.conversations,
            key=lambda item: (item.packets, item.bytes),
            reverse=True,
        )
        for conv in conversations[:limit]:
            rows.append(
                [
                    conv.client_ip,
                    conv.server_ip,
                    str(conv.server_port),
                    str(conv.packets),
                    format_bytes_as_mb(conv.bytes),
                    format_ts(conv.first_seen),
                    format_ts(conv.last_seen),
                ]
            )
        lines.append(_format_table(rows))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Forensic Artifacts"))
        rows = [["Kind", "Detail", "Packet", "Src", "Dst"]]
        for item in summary.artifacts[: _limit_value(30)]:
            rows.append(
                [
                    item.kind,
                    _truncate_text(item.detail, 96),
                    str(item.packet_index),
                    item.src,
                    item.dst,
                ]
            )
        lines.append(_format_table(rows))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections[: _limit_value(20)]:
            severity = str(item.get("severity", "info")).lower()
            prefix = (
                danger("[HIGH]")
                if severity in {"high", "critical"}
                else warn("[WARN]")
                if severity == "warning"
                else ok("[INFO]")
            )
            lines.append(f"{prefix} {item.get('summary', '-')}")
            details = str(item.get("details", "") or "").strip()
            if details:
                lines.append(muted(f"  {details}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)
