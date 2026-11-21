"""Rendered output for --correlate (multi-capture): the hosts and services
that recur across captures -- infrastructure reuse is the cue. Which
captures each one appeared in is -v detail."""

from __future__ import annotations

from pathlib import Path

from . import _style as st
from ._kv import findings_for


def _names(paths: object) -> str:
    return ", ".join(Path(str(p)).name for p in (paths or []))


def render_correlation_summary(summary, min_count: int = 2, verbose: bool = False) -> str:
    if not summary:
        return ""
    rep = st.Report("Correlation", "all captures")
    findings = findings_for(summary, ot=False)
    hosts = [(ip, n) for ip, n in summary.host_counts.most_common() if n >= min_count]
    services = [(svc, n) for svc, n in summary.service_counts.most_common() if n >= min_count]
    severity, text = st.verdict(findings, high="infrastructure reused across captures", medium="reuse across captures to review",
                                clean="nothing recurs across captures")
    rep.headline(severity, text, st.join([
        st.plural(summary.total_pcaps, "capture"),
        st.plural(len(summary.host_counts), "host") if summary.host_counts else "",
        st.plural(len(summary.service_counts), "service") if summary.service_counts else "",
        f"recurring = in {min_count}+ captures",
    ]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))
    presence = summary.host_presence or {}
    rep.section("Recurring hosts", st.table(
        ["Host", "Captures"] + (["In"] if st.verbose() else []),
        [[ip, n] + ([_names(presence.get(ip))] if st.verbose() else []) for ip, n in hosts],
        align="lrl", max_rows=10, noun="host",
    ))
    service_presence = summary.service_presence or {}
    rep.section("Recurring services", st.table(
        ["Service", "Captures"] + (["In"] if st.verbose() else []),
        [[svc, n] + ([_names(service_presence.get(svc))] if st.verbose() else []) for svc, n in services],
        align="lrl", max_rows=10, noun="service",
    ))
    rep.section("Host presence", st.table(
        ["Host", "Captures"], [[ip, _names(p)] for ip, p in sorted(presence.items(), key=lambda kv: (-len(kv[1]), kv[0]))],
        max_rows=None,
    ), detail=True)
    return rep.render()
