"""Rendered output for safety analysis.

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


def render_safety_summary(summary) -> str:
    if not summary:
        return ""
    lines = [header("SAFETY SYSTEMS")]
    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("Hits", str(len(summary.hits))))
    if summary.service_counts:
        lines.append(_format_kv("Services", _format_counter(summary.service_counts, 6)))
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
    if summary.hits:
        rows = [["Proto", "Service", "Src", "Dst"]]
        for hit in summary.hits[: _limit_value(10)]:
            rows.append(
                [
                    hit.protocol,
                    hit.service,
                    f"{hit.src}:{hit.src_port}",
                    f"{hit.dst}:{hit.dst_port}",
                ]
            )
        lines.append(_format_table(rows))
    return _finalize_output(lines)
