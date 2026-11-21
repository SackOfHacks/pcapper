"""Rendered output for --decode: one input string tried against every
supported encoding."""

from __future__ import annotations

from ..decode import DecodeSummary
from . import _style as st
from ._common import _redact_in_text


def render_decode_summary(summary: DecodeSummary) -> str:
    rep = st.Report("Decode", "input")
    results = list(getattr(summary, "results", []) or [])
    decoded = [r for r in results if getattr(r, "success", False)]
    source = _redact_in_text(str(summary.source or ""))
    rep.headline(False, f"{st.plural(len(decoded), 'format')} decoded of {len(results)} tried",
                 f"{st.count(len(str(summary.source or '')))} characters: {st.cut(source, 100)}")
    rep.section("Decoded", st.table(
        ["Format", "Output"],
        [[getattr(r, "format_name", "-"), _redact_in_text(str(getattr(r, "value", "-")))] for r in decoded],
        widths=(None, 180), max_rows=None,
    ))
    rep.section("Not decoded", [f"  {', '.join(str(getattr(r, 'format_name', '-')) for r in results if not getattr(r, 'success', False))}"]
                if len(decoded) < len(results) else [], detail=True)
    rep.section("Input", [f"  {source}"], detail=True)
    return rep.render()
