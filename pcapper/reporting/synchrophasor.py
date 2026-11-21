"""Rendered output for IEEE C37.118 synchrophasor (PMU/PDC) analysis."""

from __future__ import annotations

from ..synchrophasor import SynchrophasorSummary
from . import _style as st
from ._kv import counter_line, findings_for, window


def render_synchrophasor_summary(summary: SynchrophasorSummary, verbose: bool = False) -> str:
    rep = st.Report("Synchrophasor", summary.path)
    findings = findings_for(summary)
    if not summary.synchrophasor_packets and not st.material(findings):
        return rep.absent("IEEE C37.118 traffic", summary.errors)
    severity, text = st.verdict(
        findings,
        high="high-severity PMU/PDC activity (commands or configuration change): confirm it is authorized",
        medium="synchrophasor anomalies to review",
    )
    rep.headline(severity, text, st.join([
        f"{st.count(summary.synchrophasor_packets)} C37.118 frames",
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
        window(summary),
    ]))
    rep.scope(st.join([
        f"{st.plural(len(summary.src_ips), 'source')} -> {st.plural(len(summary.dst_ips), 'destination')}",
        st.plural(len(summary.id_codes), "PMU/PDC ID code") if summary.id_codes else "",
    ]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))
    rep.section("Stream", st.kv([
        counter_line("Command frames", summary.commands, 6),
        counter_line("Frame types", summary.frame_types, 6),
        ("PMU/PDC ID codes", ", ".join(str(c) for c, _ in summary.id_codes.most_common(None if st.verbose() else 8))),
        counter_line("Sources", summary.src_ips),
        counter_line("Destinations", summary.dst_ips),
    ]))
    rep.section("Capture", st.kv([("Total packets", st.count(summary.total_packets))]), detail=True)
    return rep.render()
