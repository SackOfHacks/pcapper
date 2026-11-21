"""Rendered output for domain analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..services import COMMON_PORTS
from . import _style as st
from ._common import _redact_in_text, _redact_secret, _render_deterministic_checks
from ._kv import counter_line, findings_for

if TYPE_CHECKING:
    from ..domain import DomainAnalysis



_CHECK_LABELS = [
    ("dc_role_consistency", "DC Role Consistency"),
    ("kerberos_ticket_abuse", "Kerberos Ticket Abuse"),
    ("kerberos_roast_or_cipher_risk", "Kerberoasting / Weak Cipher Risk"),
    ("dcsync_replication_activity", "DCSync/Replication-like Activity"),
    ("dcsync_fingerprint_evidence", "DCSync Fingerprint Evidence"),
    ("adcs_or_certificate_abuse_context", "AD CS / Certificate Abuse Context"),
    ("ldap_bind_risk", "LDAP Bind Risk"),
    ("ldap_directory_abuse_context", "LDAP Directory Abuse Context"),
    ("ntlm_downgrade_or_relay_exposure", "NTLM Downgrade/Relay Exposure"),
    ("relay_coercion_chain_context", "Relay/Coercion Chain Context"),
    ("credential_material_in_domain_flows", "Credential Material in Domain Flows"),
    ("auth_sequence_plausibility", "Authentication Sequence Plausibility"),
    ("name_resolution_poisoning_context", "Name Resolution Poisoning Context"),
    ("privileged_account_spread", "Privileged Account Spread"),
    ("identity_attack_path_correlation", "Identity Attack-Path Correlation"),
    ("public_domain_service_exposure", "Public Domain Service Exposure"),
    ("baseline_service_deviation", "Baseline Service Deviation"),
    ("ot_identity_attack_surface_overlap", "OT Identity Attack-Surface Overlap"),
]


def _assessment(summary: "DomainAnalysis") -> tuple[str, str, int, list[str]]:
    checks = getattr(summary, "deterministic_checks", {}) or {}
    score = 0
    reasons: list[str] = []
    for key, weight in {"dcsync_replication_activity": 4, "kerberos_ticket_abuse": 3, "ntlm_downgrade_or_relay_exposure": 3,
                        "ldap_bind_risk": 2, "auth_sequence_plausibility": 2, "dc_role_consistency": 2,
                        "name_resolution_poisoning_context": 1, "privileged_account_spread": 1}.items():
        n = len([v for v in (checks.get(key, []) if isinstance(checks, dict) else []) or [] if str(v).strip()])
        if n:
            score += min(4, weight + min(2, n - 1))
            reasons.append(f"{key.replace('_', ' ')} evidence ({n})")
    detections = summary.detections or []
    high = sum(1 for d in detections if str(d.get("severity", "")).lower() in {"high", "critical"})
    warning = sum(1 for d in detections if str(d.get("severity", "")).lower() == "warning")
    if high:
        score += min(3, high)
        reasons.append(f"high-severity domain detections ({high})")
    if warning >= 2:
        score += 1
        reasons.append(f"multiple warning-level domain detections ({warning})")
    if score >= 8:
        return "YES - high-confidence malicious or compromised domain activity", "High", score, reasons
    if score >= 5:
        return "LIKELY - suspicious domain activity with compromise indicators", "Medium", score, reasons
    if score >= 2:
        return "POSSIBLE - risky domain behavior; corroboration recommended", "Low", score, reasons
    return "NO STRONG SIGNAL from the current heuristics", "Low", score, reasons


def _records(items: object) -> list[str]:
    out = []
    for item in items or []:
        if isinstance(item, dict):
            out.append("  ".join(f"{k}={', '.join(str(x) for x in v) if isinstance(v, (list, tuple, set)) else v}"
                                 for k, v in item.items()))
        else:
            out.append(str(item))
    return [_redact_in_text(o) for o in out]


def render_domain_summary(summary: "DomainAnalysis", limit: int = 25, verbose: bool = False) -> str:
    """Active Directory as seen on the wire: replication (DCSync), ticket and
    relay abuse, attack paths and clusters first; then the domains, domain
    controllers, accounts and computers named. Services, conversations and
    the analyzer's scoring are -v."""
    if not summary:
        return ""
    rep = st.Report("Domain", summary.path)
    findings = findings_for(summary, ot=False)
    # total_packets is the whole capture; the domain services (Kerberos, LDAP,
    # SMB, RPC, DNS ...) are what service_counts tallies.
    domain_packets = sum(int(v) for v in (summary.service_counts or {}).values())
    identities = summary.users or summary.computer_names or summary.domains or summary.dc_hosts
    if not domain_packets and not identities and not st.material(findings):
        return rep.absent("domain (AD) traffic", summary.errors)
    severity, text = st.verdict(findings, high="Active Directory attack activity: investigate", medium="domain activity to review")
    rep.headline(severity, text, st.join([
        f"{st.count(domain_packets)} domain-service packets" if domain_packets else "",
        st.duration(summary.duration) if summary.duration else "",
    ]))
    rep.scope(st.join([
        "domain " + ", ".join(str(d) for d, _ in summary.domains.most_common(3)) if summary.domains else "",
        "DC " + ", ".join(str(d) for d, _ in summary.dc_hosts.most_common(3)) if summary.dc_hosts else "",
        f"{st.plural(len(summary.clients), 'client')} -> {st.plural(len(summary.servers), 'server')}"
        if summary.clients or summary.servers else "",
    ]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    for title, field in (("DCSync", "dcsync_signals"), ("Kerberos abuse", "kerberos_abuse_profiles"),
                         ("NTLM relay", "ntlm_relay_signals"), ("LDAP bind risks", "ldap_bind_risks"),
                         ("Sequence violations", "sequence_violations"), ("DC role drift", "dc_role_drift")):
        rep.section(title, st.bullets(_records(getattr(summary, field, None)), max_items=8))
    paths = list(getattr(summary, "host_attack_paths", None) or [])
    rep.section("Attack paths", st.table(
        ["Host", "Confidence", "Targets", "Steps"],
        [[p.get("host", "-"), p.get("confidence", "-"), ", ".join(str(t) for t in p.get("targets", []) or []),
          "; ".join(str(x) for x in p.get("steps", []) or [])] for p in paths if isinstance(p, dict)],
        widths=(None, None, 50, 80), max_rows=8,
    ))
    clusters = list(getattr(summary, "incident_clusters", None) or [])
    rep.section("Incident clusters", st.table(
        ["Cluster", "Host", "Signals", "Targets", "Confidence"],
        [[c.get("cluster", "-"), c.get("host", "-"), len(c.get("indicators", []) or []), c.get("target_count", "-"),
          c.get("confidence", "-")] for c in clusters if isinstance(c, dict)], max_rows=8,
    ))
    campaigns = list(getattr(summary, "campaign_indicators", None) or [])
    rep.section("Campaign indicators", st.table(
        ["Indicator", "Value", "Hosts"],
        [[c.get("indicator", "-"), _redact_in_text(str(c.get("value", "-"))), ", ".join(str(h) for h in c.get("hosts", []) or [])]
         for c in campaigns if isinstance(c, dict)], max_rows=8,
    ))
    browser_roles = getattr(summary, "browser_roles", None) or {}
    rep.section("Domain", st.kv([
        counter_line("Domains", summary.domains, 6),
        counter_line("Domain controllers", summary.dc_hosts, 6),
        ("Announced workgroups", st.top(getattr(summary, "netbios_domains", None), 6)),
    ]) + st.table(["Host", "Announced roles"],
                  [[ip, ", ".join(roles)] for ip, roles in browser_roles.items()], max_rows=10, noun="host"))
    rep.section("Identities", st.kv([
        ("Users", st.top(summary.users, 10, fmt=lambda k, v: f"{_redact_in_text(str(k))} ({st.count(v)})")),
        counter_line("Computers", summary.computer_names, 10),
        ("Credentials", st.top(summary.credentials, 6, fmt=lambda k, v: f"{_redact_secret(str(k))} ({st.count(v)})")),
    ]))

    verdict, confidence, score, reasons = _assessment(summary)
    rep.section("Assessment", st.kv([("Verdict", verdict), ("Confidence", f"{confidence} (score={score})")])
                + st.bullets(reasons, max_items=None), detail=True)

    def _svc(svc: object) -> str:
        try:
            name = COMMON_PORTS.get(int(str(svc).split("/", 1)[1]))
        except (IndexError, ValueError):
            name = None
        return f"{svc} ({name})" if name else str(svc)

    rep.section("Services and endpoints", st.kv([
        ("Services", st.top(summary.service_counts, None, fmt=lambda k, v: f"{_svc(k)} ({v})")),
        counter_line("Servers", summary.servers, None),
        counter_line("Clients", summary.clients, None),
        counter_line("Response codes", summary.response_codes, None),
        counter_line("Requests", summary.request_counts, None),
        counter_line("URLs", summary.urls, None),
        counter_line("User agents", summary.user_agents, None),
        ("Files", ", ".join(str(f) for f in summary.files or [])),
    ]), detail=True)
    rep.section("Conversations", st.table(
        ["Source", "Destination", "Port", "Proto", "Packets"],
        [[c.src_ip, c.dst_ip, c.dst_port, c.proto, st.count(c.packets)] for c in summary.conversations],
        align="llrlr", max_rows=None,
    ), detail=True)
    rep.section("Baseline anomalies", st.bullets(_records(getattr(summary, "baseline_anomalies", None)), max_items=None), detail=True)
    rep.section("False-positive context", st.bullets([_redact_in_text(str(b)) for b in (summary.benign_context or [])],
                                                     max_items=None), detail=True)
    rep.section("Traffic", st.kv([("Duration", f"{summary.duration:.2f}s"), ("Packets", str(summary.total_packets))]), detail=True)
    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic Domain Security Checks", _CHECK_LABELS)
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
