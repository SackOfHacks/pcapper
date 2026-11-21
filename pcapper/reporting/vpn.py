"""Rendered output for VPN and tunnel analysis (IPsec/IKE, OpenVPN,
WireGuard, PPTP/L2TP, GRE, SSL VPNs): which tunnels exist, to where, and
what their certificates say."""

from __future__ import annotations

from ..vpn import VpnSummary
from . import _style as st
from ._kv import counter_line, findings_for


def render_vpn_summary(summary: VpnSummary) -> str:
    rep = st.Report("VPN and tunnels", summary.path)
    findings = findings_for(summary, ot=False)
    if not summary.vpn_packets and not st.material(findings):
        return rep.absent("VPN or tunnel traffic", summary.errors)
    severity, text = st.verdict(findings, high="high-severity tunnel activity (unsanctioned VPN, weak crypto): investigate",
                                medium="tunnel activity to review")
    rep.headline(severity, text, st.join([
        f"{st.count(summary.vpn_packets)} VPN packets", st.top(summary.service_counts, 4),
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
        st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else "",
    ]))
    rep.scope(f"{st.plural(len(summary.client_counts), 'client')} -> {st.plural(len(summary.server_counts), 'server')}")
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))
    rep.section("Tunnels", st.kv([
        counter_line("Services", summary.service_counts, 6), counter_line("Protocols", summary.protocol_counts, 6),
        counter_line("Server ports", summary.server_port_counts, 6), counter_line("Handshakes", summary.handshake_counts, 6),
        counter_line("Clients", summary.client_counts, 5), counter_line("Servers", summary.server_counts, 5),
    ]))
    if summary.certificate_count:
        rep.section("Certificates", st.kv([
            ("Certificates", f"{summary.certificate_count}"
                             + (f" · {st.caution(str(summary.self_signed_cert_count) + ' self-signed')}" if summary.self_signed_cert_count else "")
                             + (f" · {st.bad(str(summary.weak_cert_count) + ' weak')}" if summary.weak_cert_count else "")),
            counter_line("Subjects", summary.certificate_subjects, 4), counter_line("Issuers", summary.certificate_issuers, 4),
        ]))
    rep.section("Indicators", st.kv([
        counter_line("Threats", summary.threat_counts, 5), counter_line("Anomalies", summary.anomaly_counts, 5),
    ]))
    rep.section("Correlations", st.table(
        ["Artifact / client / server", "Count"],
        [[r, st.count(n)] for r, n in (summary.artifact_correlations or {}).items()] if not hasattr(summary.artifact_correlations, "most_common")
        else [[r, st.count(n)] for r, n in summary.artifact_correlations.most_common()],
        align="lr", max_rows=None,
    ), detail=True)
    rep.section("Certificate names", st.kv([counter_line("SANs", summary.certificate_sans, None)]), detail=True)
    rep.section("Capture", st.kv([("Total packets", st.count(summary.total_packets))]), detail=True)
    return rep.render()
