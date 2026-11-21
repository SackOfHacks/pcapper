"""Rendered output for Sampled Values (IEC 61850-9-2) analysis. Default:
findings and the merging units publishing samples. -v adds confRev, sample
counters, sequence shapes and sample values."""

from __future__ import annotations

from ..sv import SvSummary
from . import _style as st
from ._kv import counter_line, findings_for, window


def render_sv_summary(summary: SvSummary, verbose: bool = False) -> str:
    rep = st.Report("Sampled Values", summary.path)
    findings = findings_for(summary)
    if not summary.sv_packets and not st.material(findings):
        return rep.absent("Sampled Values traffic", summary.errors)
    severity, text = st.verdict(
        findings,
        high="high-severity sampled-value activity: confirm the merging unit is authorized",
        medium="sampled-value anomalies to review",
    )
    rep.headline(severity, text, st.join([
        f"{st.count(summary.sv_packets)} SV packets",
        st.duration(getattr(summary, "duration_seconds", 0.0) or 0.0),
        window(summary),
    ]))
    rep.scope(st.join([
        f"{st.plural(len(summary.src_macs), 'publisher')} -> {st.plural(len(summary.dst_macs), 'group')}",
        st.plural(len(summary.app_ids), "APPID"),
        st.plural(len(summary.sv_ids or {}), "svID"),
    ]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))
    rep.section("Publications", st.kv([
        counter_line("Publishers (src MAC)", summary.src_macs),
        counter_line("Groups (dst MAC)", summary.dst_macs),
        counter_line("APPIDs", summary.app_ids),
        counter_line("svID", summary.sv_ids),
    ]))
    smp = [v for v in (summary.smp_counts or []) if isinstance(v, int)]
    rep.section("Stream", st.kv([
        counter_line("ConfRev", summary.conf_revs),
        ("smpCnt", f"{len(smp)} distinct, {min(smp)}..{max(smp)}" if smp else ""),
        counter_line("SeqOfData length", summary.seq_data_lengths),
        counter_line("SeqOfData types", summary.data_type_counts),
        ("Sample values", st.top(summary.data_value_samples, 5,
                                 lambda k, v: f"{st.cut(k, 40)} ({st.count(v)})") if summary.data_value_samples else ""),
        counter_line("Frame lengths", summary.lengths),
        ("Total packets", st.count(summary.total_packets)),
    ]), detail=True)
    return rep.render()
