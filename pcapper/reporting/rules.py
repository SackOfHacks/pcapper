"""Rendered output for rules analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    header,
    muted,
)

from ._common import (
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
)


def render_rules_summary(summary) -> str:
    if not summary:
        return ""
    lines = [header("RULES ANALYSIS")]
    lines.append(_format_kv("Rules Loaded", str(summary.total_rules)))
    lines.append(_format_kv("Matches", str(summary.total_matches)))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors)))
    if summary.hits:
        lines.append(header("Rule Hits"))
        rows = [["Rule", "Severity", "Count", "Sources"]]
        for hit in summary.hits[: _limit_value(10)]:
            sources = ", ".join(hit.sources) if hit.sources else "-"
            rows.append([hit.title, hit.severity.upper(), str(hit.count), sources])
        lines.append(_format_table(rows))
        for hit in summary.hits[: _limit_value(5)]:
            if hit.examples:
                lines.append(muted(f"{hit.title} examples:"))
                for example in hit.examples[: _limit_value(3)]:
                    lines.append(muted(f"  {example}"))
    return _finalize_output(lines)
