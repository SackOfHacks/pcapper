"""Rendered output for GOOSE (IEC 61850) analysis, including routable
R-GOOSE. Default: findings, the publishers and what they publish, R-GOOSE
security. -v adds state/sequence numbers, dataset shapes and sample values."""

from __future__ import annotations

from ..goose import GooseSummary
from . import _style as st
from ._kv import counter_line, findings_for, int_range, window


def render_goose_summary(summary: GooseSummary, verbose: bool = False) -> str:
    rep = st.Report("GOOSE", summary.path)
    findings = findings_for(summary)
    if not summary.goose_packets and not getattr(summary, "rgoose_packets", 0) and not st.material(findings):
        return rep.absent("GOOSE traffic", summary.errors)
    routed = bool(getattr(summary, "rgoose_packets", 0))
    severity, text = st.verdict(
        findings,
        high="high-severity GOOSE activity: confirm the publisher and the change are authorized",
        medium="GOOSE anomalies to review",
    )
    dur = float(getattr(summary, "duration_seconds", 0.0) or 0.0)
    rep.headline(severity, text, st.join([
        f"{st.count(summary.goose_packets)} GOOSE packets" if summary.goose_packets else "",
        f"{st.count(summary.rgoose_packets)} R-GOOSE session PDUs" if routed else "",
        st.duration(dur) if dur else "",
        window(summary),
    ]))
    publishers = summary.src_macs or getattr(summary, "rgoose_publishers", None) or {}
    groups = summary.dst_macs or getattr(summary, "rgoose_groups", None) or {}
    rep.scope(st.join([
        f"{st.plural(len(publishers), 'publisher')} -> {st.plural(len(groups), 'group')}",
        st.plural(len(summary.app_ids), "APPID") if summary.app_ids else "",
    ]))

    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))
    rep.section("Publications", st.kv([
        counter_line("Publishers (src MAC/IP)" if routed else "Publishers (src MAC)", summary.src_macs),
        counter_line("Groups (dst MAC/IP)" if routed else "Groups (dst MAC)", summary.dst_macs),
        counter_line("APPIDs", summary.app_ids),
        counter_line("Datasets", summary.datasets),
        counter_line("GoCB refs", summary.gocb_refs),
    ]))
    if routed:
        rep.section("R-GOOSE", st.kv([
            ("Session PDUs", st.count(summary.rgoose_packets)),
            ("Security", f"signed {summary.rgoose_signed}, unsigned {summary.rgoose_unsigned}, "
                         f"encrypted {summary.rgoose_encrypted}"),
            ("Key IDs", ", ".join(str(k) for k in sorted(summary.rgoose_key_ids)) or "none"),
            counter_line("Publishers (IP)", summary.rgoose_publishers),
            counter_line("Groups (dst IP)", summary.rgoose_groups),
            ("UDP ports", ", ".join(f"{p} ({c})" for p, c in summary.rgoose_ports.most_common(5))),
            ("R-SV APDUs", st.count(summary.rsv_packets) if getattr(summary, "rsv_packets", 0) else ""),
        ]))

    rep.section("State and sequence", st.kv([
        ("stNum", int_range(summary.st_nums or [])),
        ("sqNum", int_range(summary.sq_nums or [])),
        counter_line("confRev", summary.conf_revs),
        counter_line("numDatSetEntries", summary.num_entries),
    ]), detail=True)
    rep.section("Data", st.kv([
        counter_line("allData length", summary.all_data_lengths),
        counter_line("Data types", summary.data_type_counts, 6),
        ("Sample values", st.top(summary.data_value_samples, 5,
                                 lambda k, v: f"{st.cut(k, 40)} ({st.count(v)})") if summary.data_value_samples else ""),
        counter_line("Frame lengths", summary.lengths),
        ("Total packets", st.count(summary.total_packets)),
    ]), detail=True)
    return rep.render()
