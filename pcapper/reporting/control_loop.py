"""Rendered output for control-loop (process value) analysis: setpoints and
process values that jumped, oscillated or left their range."""

from __future__ import annotations

from . import _style as st
from ._kv import counter_line


def render_control_loop_summary(summary) -> str:  # type: ignore[no-untyped-def]
    if not summary:
        return ""
    rep = st.Report("Control loop", summary.path)
    if not summary.total_changes and not summary.findings:
        return rep.absent("process value changes", summary.errors)
    # The analyzer does not grade its findings; they are leads, shown as INFO.
    rep.headline(
        "info" if summary.findings else None,
        st.join([st.plural(len(summary.findings), "value-change finding"),
                 st.top(summary.kind_counts, 4) if summary.kind_counts else ""]) if summary.findings
        else "no anomalous value changes",
        st.join([st.plural(summary.total_changes, "value change"), st.plural(summary.total_targets, "target")]),
    )
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])

    def _delta(value: object) -> str:
        return f"{value:.1f}" if isinstance(value, (int, float)) else "-"

    rep.section("Findings", st.table(
        ["Time", "Protocol", "Target", "Kind", "Old", "New", "Delta", "Flow"],
        [[st.ts(f.ts), f.protocol, f.target, f.kind, f.old, f.new, _delta(f.delta), st.flow(f.src or "-", f.dst or "-")]
         for f in summary.findings],
        align="llllrrrl", noun="finding",
    ))
    rep.section("Endpoints", st.kv([
        counter_line("Sources", summary.source_counts, 6),
        counter_line("Destinations", summary.destination_counts, 6),
    ]))
    rep.section("Targets", st.kv([counter_line("Targets", summary.target_counts, None)]), detail=True)
    rep.section("Notes", st.table(["Target", "Note"], [[f.target, f.note] for f in summary.findings if f.note],
                                  max_rows=None), detail=True)
    return rep.render()
