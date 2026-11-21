"""Rendered output for IEC 60870-5-101/103 (serial-over-IP telecontrol)."""

from __future__ import annotations

from ..iec101_103 import Iec101103Summary
from . import _style as st
from ._kv import counter_line, findings_for, window


def render_iec101_103_summary(summary: Iec101103Summary, verbose: bool = False) -> str:
    rep = st.Report("IEC 101/103", summary.path)
    findings = findings_for(summary)
    if not summary.candidate_packets and not st.material(findings):
        return rep.absent("IEC 60870-5-101/103 traffic", summary.errors)
    severity, text = st.verdict(
        findings,
        high="high-severity telecontrol activity: confirm the command source is authorized",
        medium="telecontrol anomalies to review",
    )
    rep.headline(severity, text, st.join([
        f"{st.count(summary.candidate_packets)} candidate packets",
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
        window(summary),
    ]))
    rep.scope(f"{st.plural(len(summary.client_counts), 'client')} -> {st.plural(len(summary.server_counts), 'server')}")
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))
    rep.section("Telecontrol", st.kv([
        counter_line("ASDU types", summary.type_counts),
        counter_line("Causes of transmission", summary.cause_counts),
        counter_line("Clients", summary.client_counts),
        counter_line("Servers", summary.server_counts),
    ]))
    rep.section("Capture", st.kv([("Total packets", st.count(summary.total_packets))]), detail=True)
    return rep.render()
