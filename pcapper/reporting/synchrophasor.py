"""Rendered output for synchrophasor analysis.

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
from ..synchrophasor import SynchrophasorSummary

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
def render_synchrophasor_summary(
    summary: SynchrophasorSummary, verbose: bool = False
) -> str:
    lines = [header("SYNCHROPHASOR ANALYSIS")]
    _render_ot_verdict(lines, "Synchrophasor (C37.118)", getattr(summary, "detections", []))
    lines.append(_format_kv("C37.118 Frames", str(summary.synchrophasor_packets)))
    lines.append(_format_kv("Frame Types", _format_counter(summary.frame_types, 6)))
    if summary.id_codes:
        lines.append(
            _format_kv(
                "PMU/PDC ID Codes",
                ", ".join(str(c) for c, _ in summary.id_codes.most_common(8)),
            )
        )
    if summary.commands:
        lines.append(_format_kv("Command Frames", _format_counter(summary.commands, 6)))
    lines.append(_format_kv("Top Sources", _format_counter(summary.src_ips, 5)))
    lines.append(_format_kv("Top Destinations", _format_counter(summary.dst_ips, 5)))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors)))
    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(header("Detections"))
        for item in detections[: _limit_value(8)]:
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
