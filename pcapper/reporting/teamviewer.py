"""Rendered output for teamviewer analysis.

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
from ..teamviewer import TeamviewerSummary
from ..utils import (
    format_bytes_as_mb,
    format_duration,
)

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
    _meaningful_plaintext_items,
    _render_protocol_verdict,
    _truncate_text,
)


def render_teamviewer_summary(
    summary: TeamviewerSummary, limit: int = 12, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit)
    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"TEAMVIEWER ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)
    _render_protocol_verdict(
        lines,
        label="TeamViewer",
        detections=getattr(summary, "detections", None),
        anomalies=getattr(summary, "anomalies", None),
    )

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("TeamViewer Packets", str(summary.tv_packets)))
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
    lines.append(_format_kv("TCP Sessions", str(summary.tcp_sessions)))
    lines.append(_format_kv("UDP Sessions", str(summary.udp_sessions)))
    lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))

    if summary.server_tcp_ports:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server TCP Ports"))
        lines.append(_counter_table(summary.server_tcp_ports, "Port", limit=limit))

    if summary.server_udp_ports:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server UDP Ports"))
        lines.append(_counter_table(summary.server_udp_ports, "Port", limit=limit))

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top TeamViewer Clients & Servers"))
        lines.append(
            _format_client_server_table(summary.client_counts, summary.server_counts)
        )

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TeamViewer Sessions"))
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

    if summary.hints:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TeamViewer Hints"))
        rows = [["Hint", "Count"]]
        for hint, count in summary.hints.most_common(limit):
            rows.append([_truncate_text(hint, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.plaintext_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Plaintext"))
        rows = [["String", "Count"]]
        for text, count in _meaningful_plaintext_items(summary.plaintext_strings, limit):
            rows.append([_truncate_text(text, 60), str(count)])
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
        rows = [["Client", "Server", "C->S MB", "S->C MB", "Packets", "UDP", "Hints"]]
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
                    "yes" if conv.udp_detected else "no",
                    ", ".join(conv.hints) if conv.hints else "-",
                ]
            )
        lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
