"""Rendered output for --rules: which user rules matched, how often, from
which sources, with example matches (all examples with -v)."""

from __future__ import annotations

from . import _style as st


def render_rules_summary(summary) -> str:
    if not summary:
        return ""
    rep = st.Report("Rules", summary.path)
    hits = sorted(summary.hits or [], key=lambda h: (-st.sev_rank(h.severity), -h.count, h.title))
    severity = next((h.severity for h in hits), None)
    rep.headline(severity, f"{st.plural(summary.total_matches, 'match', 'matches')} from {st.plural(len(hits), 'rule')}"
                 if hits else "no rule matched", f"{st.plural(summary.total_rules, 'rule')} loaded")
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Matches", st.table(
        ["Severity", "Rule", "Matches", "Sources"],
        [[st.badge(h.severity), h.title, st.count(h.count), ", ".join(h.sources) if h.sources else "-"] for h in hits],
        align="llrl", widths=(None, 60, None, 60), max_rows=15, noun="rule",
    ))
    rep.section("Examples", st.table(
        ["Rule", "Example"],
        [[h.title, example] for h in (hits if st.verbose() else hits[:5]) for example in (h.examples or [])[: None if st.verbose() else 1]],
        widths=(None, 120), max_rows=None,
    ))
    return rep.render()
