"""Rendered output for IOC matching: traffic that matched a supplied
indicator list (IPs, domains, hashes), with the indicators' context."""

from __future__ import annotations

from ..ioc import IocSummary
from . import _style as st
from ._kv import counter_line, findings_for


def render_ioc_summary(summary: IocSummary) -> str:
    rep = st.Report("IOC matches", summary.path)
    findings = findings_for(summary, ot=False)
    hits = len(summary.ip_hits or {}) + len(summary.domain_hits or {}) + len(summary.hash_hits or {})
    severity, text = st.verdict(
        findings,
        high=("known-malicious file hash in the capture" if st.worst(findings) >= 4 else
              "traffic matched known-bad indicators: scope the hosts involved"),
        medium="indicator matches to review",
        clean="no indicator matched",
    )
    rep.headline(severity, text, st.join([
        f"{st.plural(len(summary.ip_hits or {}), 'IP')}, {st.plural(len(summary.domain_hits or {}), 'domain')}, "
        f"{st.plural(len(summary.hash_hits or {}), 'hash', 'hashes')} matched" if hits else "",
        f"{st.count(summary.total_packets)} packets checked",
    ]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Matches", st.findings_block(findings, max_groups=15))
    rep.section("Indicators", st.kv([
        counter_line("IP hits", summary.ip_hits, 6), counter_line("Domain hits", summary.domain_hits, 6),
        counter_line("Hash hits", summary.hash_hits, 6), counter_line("Sources", summary.source_counts, 6),
        counter_line("Tags", summary.tag_counts, 6), counter_line("MITRE", summary.mitre_counts, 6),
        ("Avg confidence", f"{summary.avg_confidence:.1f}" if getattr(summary, "avg_confidence", None) is not None else ""),
    ]))
    meta = getattr(summary, "indicator_meta", None) or {}
    rep.section("Indicator context", st.table(
        ["Indicator", "Context"], [[k, str(v)] for k, v in (meta.items() if isinstance(meta, dict) else [])], max_rows=None,
    ), detail=True)
    return rep.render()
