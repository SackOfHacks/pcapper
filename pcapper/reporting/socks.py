"""Rendered output for SOCKS proxy / tunnel analysis (SOCKS4/4a/5): which
proxies exist, who uses them, where they tunnel to, how they authenticate, and
the hunt reads (reverse proxies, cleartext/failed auth, sensitive-service
tunnels)."""

from __future__ import annotations

from ..socks import SocksSummary
from ..utils import output_redaction_enabled
from . import _style as st
from ._kv import counter_line, findings_for


def _secret(value: object) -> str:
    return "[REDACTED]" if output_redaction_enabled() else str(value)


def render_socks_summary(summary: SocksSummary) -> str:
    rep = st.Report("SOCKS proxies and tunnels", summary.path)
    findings = findings_for(summary, ot=False)
    if not summary.flows and not st.material(findings):
        return rep.absent("SOCKS proxy or tunnel traffic", summary.errors)
    severity, text = st.verdict(
        findings,
        high="high-severity proxy tunneling (reverse proxy / sensitive pivot): investigate",
        medium="proxy tunneling to review",
    )
    rep.headline(severity, text, st.join([
        f"{st.plural(summary.flows, 'tunnel')}",
        f"{st.count(summary.socks_packets)} control packets",
        st.top(summary.version_counts, 3),
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
        st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else "",
    ]))
    rep.scope(f"{st.plural(len(summary.client_counts), 'client')} -> {st.plural(len(summary.server_counts), 'proxy', 'proxies')}")
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))
    rep.section("Proxies", st.kv([
        counter_line("Versions", summary.version_counts, 6),
        counter_line("Commands", summary.command_counts, 6),
        counter_line("Auth methods", summary.auth_method_counts, 6),
        counter_line("Reply status", summary.reply_status_counts, 6),
        counter_line("Proxy ports", summary.proxy_port_counts, 6),
        counter_line("Clients", summary.client_counts, 5),
        counter_line("Proxies", summary.server_counts, 5),
    ]))
    rep.section("Tunnel targets", st.kv([counter_line("Targets", summary.target_counts, 10)]))
    if summary.credential_items:
        rep.section("Credentials", st.table(
            ["User", "Secret", "Proxy", "Result"],
            [[str(c.get("user", "-")), _secret(c.get("secret", "-")), str(c.get("proxy", "-")), str(c.get("result", "-"))]
             for c in summary.credential_items],
            align="llll", max_rows=20, noun="credential",
        ))
    rep.section("Indicators", st.kv([
        counter_line("Threats", summary.threat_counts, 5),
        counter_line("Anomalies", summary.anomaly_counts, 5),
    ]))
    rep.section("Correlations", st.table(
        ["Artifact / client / server", "Count"],
        [[r, st.count(n)] for r, n in summary.artifact_correlations.most_common()],
        align="lr", max_rows=None,
    ), detail=True)
    rep.section("Offered auth", st.kv([counter_line("Methods offered", summary.offered_method_counts, None)]), detail=True)
    rep.section("Capture", st.kv([("Total packets", st.count(summary.total_packets))]), detail=True)
    return rep.render()
