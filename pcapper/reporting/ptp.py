"""Rendered output for PTP (IEEE 1588 precision time) analysis. Message
types are PTP's commands; a Management SET changes clock state."""

from __future__ import annotations

from ..ptp import PtpSummary
from . import _style as st
from ._kv import counter_line, findings_for, window


def render_ptp_summary(summary: PtpSummary, verbose: bool = False) -> str:
    rep = st.Report("PTP", summary.path)
    findings = findings_for(summary)
    if not summary.ptp_packets and not st.material(findings):
        return rep.absent("PTP traffic", summary.errors)
    severity, text = st.verdict(
        findings,
        high="high-severity time-sync activity: a rogue or manipulated clock can desynchronise the process",
        medium="time-sync anomalies to review",
    )
    sources = summary.src_macs or summary.src_ips
    dests = getattr(summary, "dst_macs", None) or getattr(summary, "dst_ips", None) or {}
    rep.headline(severity, text, st.join([
        f"{st.count(summary.ptp_packets)} PTP packets",
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
        window(summary),
    ]))
    rep.scope(st.join([
        f"{st.plural(len(sources), 'clock source')} -> {st.plural(len(dests), 'destination')}",
        st.plural(len(summary.domain_numbers or {}), "domain") if summary.domain_numbers else "",
    ]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))
    rep.section("Clocks", st.kv([
        counter_line("Message types", summary.msg_types, 6),
        counter_line("Domains", summary.domain_numbers, 6),
        counter_line("Sources (masters/clocks)", sources),
        counter_line("Destinations", dests),
    ]))
    seq = [v for v in (summary.sequence_ids or []) if isinstance(v, int)]
    rep.section("Capture", st.kv([
        ("Sequence IDs", f"{len(seq)} distinct, {min(seq)}..{max(seq)}" if seq else ""),
        counter_line("Source IPs", summary.src_ips) if summary.src_macs and summary.src_ips else ("", ""),
        ("Total packets", st.count(summary.total_packets)),
    ]), detail=True)
    return rep.render()
