"""Rendered output for carve analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    danger,
    header,
)

from ._common import (
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
)


def render_carve_summary(summary) -> str:
    if not summary:
        return ""
    lines = [header("STREAM CARVING")]
    lines.append(_format_kv("Streams", str(summary.total_streams)))
    lines.append(_format_kv("Hits", str(summary.total_hits)))
    if summary.extracted:
        lines.append(_format_kv("Extracted", str(len(summary.extracted))))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors)))
    incomplete = [hit for hit in summary.hits if getattr(hit, "gap_count", 0)]
    if incomplete:
        # A carve taken across a hole in the reassembled stream is a partial
        # reconstruction. Say so next to the table rather than letting a
        # confident SHA-256 travel into a report unqualified.
        lines.append(
            danger(
                f"{len(incomplete)} of {len(summary.hits)} hit(s) span gaps in the"
                " reassembled stream: those artifacts are incomplete and their"
                " SHA-256 will not match the original file."
            )
        )
    if summary.hits:
        rows = [["Stream", "Dir", "Type", "Len", "Missing", "Src", "Dst"]]
        for hit in summary.hits[: _limit_value(10)]:
            gap_bytes = getattr(hit, "gap_bytes", 0)
            gap_count = getattr(hit, "gap_count", 0)
            rows.append(
                [
                    hit.stream_id,
                    hit.direction,
                    hit.file_type,
                    str(hit.length),
                    f"{gap_bytes}B/{gap_count}" if gap_count else "-",
                    f"{hit.src}:{hit.src_port}",
                    f"{hit.dst}:{hit.dst_port}",
                ]
            )
        lines.append(_format_table(rows))
    return _finalize_output(lines)
