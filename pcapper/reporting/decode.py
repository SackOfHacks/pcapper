"""Rendered output for decode analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    header,
)
from ..decode import DecodeSummary

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _finalize_output,
    _format_kv,
    _format_table,
    _redact_in_text,
    _truncate_text,
)


def render_decode_summary(summary: DecodeSummary) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header("DECODE OVERVIEW"))
    lines.append(SECTION_BAR)
    lines.append(_format_kv("Input Length", str(len(str(summary.source or "")))))
    source_preview = _truncate_text(_redact_in_text(str(summary.source or "")), 220)
    lines.append(_format_kv("Input Preview", source_preview or "-"))
    lines.append(SUBSECTION_BAR)
    results = list(getattr(summary, "results", []) or [])
    result_count = len(results)
    lines.append(header(f"Decode Formats ({result_count})"))
    rows = [["Format", "Status", "Output"]]
    for item in results:
        rows.append(
            [
                str(getattr(item, "format_name", "-")),
                "ok" if bool(getattr(item, "success", False)) else "-",
                _truncate_text(_redact_in_text(str(getattr(item, "value", "-"))), 180),
            ]
        )
    lines.append(_format_table(rows))
    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)
