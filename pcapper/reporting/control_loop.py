"""Rendered output for control_loop analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    header,
)

from ._common import (
    _finalize_output,
    _format_counter,
    _format_kv,
    _format_table,
    _limit_value,
)


def render_control_loop_summary(summary) -> str:
    if not summary:
        return ""
    lines = [header("CONTROL LOOP ANALYSIS")]
    lines.append(_format_kv("Value Changes", str(summary.total_changes)))
    lines.append(_format_kv("Targets", str(summary.total_targets)))
    if summary.kind_counts:
        lines.append(_format_kv("Findings", _format_counter(summary.kind_counts, 6)))
    if summary.source_counts:
        lines.append(
            _format_kv("Top Sources", _format_counter(summary.source_counts, 6))
        )
    if summary.destination_counts:
        lines.append(
            _format_kv(
                "Top Destinations", _format_counter(summary.destination_counts, 6)
            )
        )
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors)))
    if summary.findings:
        rows = [["Proto", "Target", "Kind", "Delta", "Src", "Dst"]]
        for item in summary.findings[: _limit_value(10)]:
            delta = item.delta
            delta_text = f"{delta:.1f}" if isinstance(delta, (int, float)) else "-"
            rows.append(
                [
                    item.protocol,
                    item.target,
                    item.kind,
                    delta_text,
                    item.src or "-",
                    item.dst or "-",
                ]
            )
        lines.append(_format_table(rows))
    return _finalize_output(lines)
