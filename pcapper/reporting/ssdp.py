"""Rendered output for ssdp analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    header,
    muted,
    warn,
)
from ..ssdp import SsdpSummary

from ._common import (
    _finalize_output,
    _format_counter,
    _format_kv,
    _limit_value,
    _render_protocol_verdict,
    _truncate_text,
)


def render_ssdp_summary(summary: SsdpSummary, verbose: bool = False) -> str:
    lines = [header("SSDP ANALYSIS")]
    _render_protocol_verdict(
        lines,
        label="SSDP",
        detections=getattr(summary, "detections", None),
        anomalies=getattr(summary, "anomalies", None),
    )
    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("UDP Packets", str(summary.udp_packets)))
    lines.append(_format_kv("SSDP Packets", str(summary.ssdp_packets)))
    lines.append(_format_kv("M-SEARCH", str(summary.msearch_count)))
    lines.append(_format_kv("NOTIFY", str(summary.notify_count)))
    lines.append(_format_kv("Responses", str(summary.response_count)))
    lines.append(_format_kv("Top Clients", _format_counter(summary.client_counts, 6)))
    lines.append(_format_kv("Top Servers", _format_counter(summary.server_counts, 6)))
    lines.append(_format_kv("Targets", _format_counter(summary.target_port_counts, 6)))
    lines.append(_format_kv("USN", _format_counter(summary.usn_counts, 6)))
    lines.append(_format_kv("Location", _format_counter(summary.location_counts, 4)))
    findings = (
        summary.detections
        if verbose
        else [
            d
            for d in summary.detections
            if str(d.get("severity", "")).lower() not in {"info", "informational"}
        ]
    )
    if findings:
        lines.append(header("Detections"))
        for item in findings[: _limit_value(8)]:
            sev = str(item.get("severity", "info")).upper()
            title = str(item.get("title") or item.get("summary") or "Detection")
            details = str(item.get("details", ""))
            lines.append(warn(f"[{sev}] {title}"))
            if details:
                lines.append(muted(f"  {details}"))
    if summary.anomalies:
        lines.append(header("Anomalies"))
        for item in summary.anomalies[: _limit_value(6)]:
            lines.append(muted(f"- {_truncate_text(str(item), 120)}"))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors[: _limit_value(4)])))
    return _finalize_output(lines)
