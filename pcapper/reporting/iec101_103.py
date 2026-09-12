"""Rendered output for iec101_103 analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    danger,
    header,
    muted,
    warn,
)
from ..iec101_103 import Iec101103Summary

from ._common import (
    _filtered_detections,
    _finalize_output,
    _format_counter,
    _format_kv,
    _limit_value,
    _ot_full_render,
    _render_ot_verdict,
)


@_ot_full_render
def render_iec101_103_summary(summary: Iec101103Summary, verbose: bool = False) -> str:
    lines = [header("IEC 101/103 ANALYSIS")]
    _render_ot_verdict(lines, "IEC 60870-5-101/103", getattr(summary, "detections", []))
    lines.append(_format_kv("Candidate Packets", str(summary.candidate_packets)))
    lines.append(_format_kv("Top Clients", _format_counter(summary.client_counts, 5)))
    lines.append(_format_kv("Top Servers", _format_counter(summary.server_counts, 5)))
    if getattr(summary, "type_counts", None):
        lines.append(_format_kv("ASDU Types", _format_counter(summary.type_counts, 5)))
    if getattr(summary, "cause_counts", None):
        lines.append(_format_kv("COT", _format_counter(summary.cause_counts, 5)))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors)))
    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(header("Detections"))
        for item in detections[: _limit_value(6)]:
            sev = str(item.get("severity", "info")).upper()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            sev_color = danger if sev in {"CRITICAL", "HIGH"} else warn
            if sev in {"INFO", "LOW"}:
                sev_color = muted
            lines.append(sev_color(f"[{sev}] {summary_text}"))
            if details:
                lines.append(muted(f"  {details}"))
    return _finalize_output(lines)
