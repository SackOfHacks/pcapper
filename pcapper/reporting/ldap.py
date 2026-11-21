"""Rendered output for LDAP: who bound as whom (and in cleartext with which
password), what was searched for (base, filter, attributes), what was
written, and what the directory returned (accounts, computers, SPNs).
Decoded from cleartext LDAP; SASL-sealed sessions show only their binds'
mechanisms and result codes."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from ..services import COMMON_PORTS
from . import _style as st
from ._common import _redact_in_text, _redact_secret, _render_deterministic_checks
from ._kv import counter_line, findings_for
from ._remote import counts

if TYPE_CHECKING:
    from ..ldap import LdapAnalysis


def render_ldap_summary(summary: "LdapAnalysis", limit: int = 25, verbose: bool = False) -> str:
    if not summary:
        return ""
    rep = st.Report("LDAP", summary.path)
    findings = findings_for(summary, ot=False)
    total_ldap = summary.cleartext_packets + summary.ldaps_packets
    if not total_ldap and not summary.conversations and not st.material(findings):
        return rep.absent("LDAP traffic", summary.errors)
    severity, text = st.verdict(findings, high="LDAP credential exposure or directory abuse: investigate",
                                medium="LDAP activity to review")
    rep.headline(severity, text, st.join([
        f"{st.count(summary.cleartext_packets)} LDAP packets",
        f"{st.count(summary.ldaps_packets)} LDAPS" if summary.ldaps_packets else "",
        st.duration(summary.duration) if summary.duration else "",
    ]))
    stats = summary.session_stats or {}
    rep.scope(st.join([f"{st.plural(len(summary.clients), 'client')} -> {st.plural(len(summary.servers), 'server')}",
                       st.plural(int(stats.get("total_sessions", 0) or 0), "session") if stats else ""]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    binds = sorted(summary.bind_identities or [], key=lambda b: b.get("ts") or 0.0)
    rep.section("Binds", st.table(
        ["Time", "Flow", "Identity", "Auth"],
        [[st.ts(b.get("ts")), st.flow(b.get("src_ip"), f"{b.get('dst_ip')}:{b.get('dst_port')}"),
          _redact_in_text(str(b.get("identity", "-"))), b.get("auth") or "-"] for b in binds],
        max_rows=10, noun="bind",
    ))
    rep.section("Credentials", st.bullets([f"{_redact_secret(str(k))}" + (st.dim(f"  ×{v}") if v > 1 else "")
                                           for k, v in summary.secrets.most_common()], max_items=10, noun="credential"))

    searches = list(getattr(summary, "search_requests", None) or [])
    if searches:
        grouped: Counter = Counter((s.get("base", ""), s.get("scope", ""), s.get("filter", ""),
                                    ", ".join(s.get("attributes") or [])) for s in searches)
        rep.section("Searches", st.table(
            ["Base", "Scope", "Filter", "Attributes", "Count"],
            [[base or "(root DSE)", scope, flt, attrs or "(all)", st.count(n)] for (base, scope, flt, attrs), n in grouped.most_common()],
            align="llllr", widths=(40, None, 60, 40), max_rows=st.TOP_ROWS, tail=st.TOP_ROWS, noun="search",
        ))
    else:
        rep.section("Queries", counts(summary.ldap_queries, "Query", width=90, max_rows=10, noun="query"))
    writes = list(getattr(summary, "writes", None) or [])
    rep.section("Writes", st.table(
        ["Time", "Client", "Operation", "DN", "Attributes"],
        [[st.ts(w.get("ts")), w.get("client", "-"), w.get("op", "-"), w.get("dn", "-"), ", ".join(w.get("changes") or []) or "-"]
         for w in writes],
        widths=(None, None, None, 60, 60), max_rows=10, noun="write",
    ))
    rep.section("Directory data", st.kv([
        ("Entries returned", st.count(getattr(summary, "entries_returned", 0)) if getattr(summary, "entries_returned", 0) else ""),
        ("Users", st.top(summary.ldap_users, 12, fmt=lambda k, v: f"{_redact_in_text(str(k))} ({st.count(v)})")),
        counter_line("Computers", summary.ldap_systems, 8),
        counter_line("SPNs", getattr(summary, "spns", None), 6),
        counter_line("Sensitive attributes", summary.suspicious_attributes, 8),
    ]))
    rep.section("Protocol", st.kv([
        counter_line("Operations", getattr(summary, "operations", None), 8),
        counter_line("Errors", summary.ldap_error_codes, 6),
        counter_line("Diagnostics", getattr(summary, "diagnostics", None), 3),
        ("Transport", f"LDAP (389/3268) {summary.cleartext_packets} · LDAPS (636/3269) {summary.ldaps_packets}"
                      if total_ldap else ""),
    ]))
    rep.section("Bind bursts", st.table(["Client", "Peak binds per minute"],
                                        [[c, st.count(n)] for c, n in summary.bind_bursts.most_common()], align="lr",
                                        noun="client"),
                detail=max(summary.bind_bursts.values(), default=0) < 10)
    rep.section("Public endpoints", counts(summary.public_endpoints, "Endpoint"))

    rep.section("Conversations", st.table(
        ["Source", "Destination", "Port", "Proto", "Packets"],
        [[c.src_ip, c.dst_ip, c.dst_port, c.proto, st.count(c.packets)] for c in summary.conversations],
        align="llrlr", max_rows=None, noun="conversation",
    ), detail=True)
    rep.section("Search requests", st.table(
        ["Time", "Client", "Base", "Scope", "Filter", "Attributes"],
        [[st.ts(s.get("ts")), s.get("client", "-"), s.get("base") or "(root DSE)", s.get("scope", "-"), s.get("filter", "-"),
          ", ".join(s.get("attributes") or []) or "(all)"] for s in searches],
        max_rows=None, noun="search",
    ), detail=True)
    rep.section("Account evidence", st.table(
        ["Flow", "Attribute", "Value"],
        [[st.flow(e.get("src_ip"), e.get("dst_ip")), e.get("attr", "-"), _redact_in_text(str(e.get("value", "-")))]
         for e in (summary.user_evidence or [])], max_rows=None, noun="value",
    ), detail=True)

    def _svc(svc: object) -> str:
        try:
            name = COMMON_PORTS.get(int(str(svc).split("/", 1)[1]))
        except (IndexError, ValueError):
            name = None
        return f"{svc} ({name})" if name else str(svc)

    rep.section("Context", st.kv([
        counter_line("LDAP-related DNS", summary.ldap_domains, None),
        ("Service ports", st.top(summary.service_counts, None, fmt=lambda k, v: f"{_svc(k)} ({v})")),
        counter_line("Response codes", summary.response_codes, None),
        counter_line("Requests", summary.request_counts, None),
        counter_line("Filter types", summary.ldap_filter_types, None),
        counter_line("Bind identities", summary.ldap_binds, None),
        counter_line("HTTP methods", summary.http_methods, None),
        counter_line("HTTP clients", summary.http_clients, None),
        counter_line("URLs", summary.urls, None),
        counter_line("User agents", summary.user_agents, None),
        ("Files", ", ".join(summary.files or [])),
    ]), detail=True)
    rep.section("Artifacts", st.bullets([_redact_in_text(str(a)) for a in summary.artifacts], max_items=None), detail=True)
    hyp = [f"[{h.get('confidence', '?')}] {h.get('hypothesis', '-')} (evidence={h.get('evidence', '')})"
           for h in (summary.threat_hypotheses or [])]
    rep.section("Threat hypotheses", st.bullets(hyp, max_items=None), detail=True)
    rep.section("Benign context", st.bullets(summary.benign_context or [], max_items=None), detail=True)
    rep.section("Traffic", st.kv([("Duration", f"{summary.duration:.2f}s"),
                                  ("Packets", f"{summary.total_packets} total · {total_ldap} LDAP"),
                                  ("Clients / servers", f"{stats.get('unique_clients', 0)} / {stats.get('unique_servers', 0)}")]),
                detail=True)

    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic LDAP Security Checks", [
            ("cleartext_ldap_exposure", "Cleartext LDAP Exposure"),
            ("bind_auth_risk", "Bind Authentication Risk"),
            ("anonymous_or_guest_bind_activity", "Anonymous/Guest Bind Activity"),
            ("credential_error_burst", "Credential Error Burst"),
            ("enumeration_burst_activity", "Enumeration Burst Activity"),
            ("sensitive_attribute_access", "Sensitive Attribute Access"),
            ("secret_material_exposure", "Secret Material Exposure"),
            ("directory_write_activity", "Directory Write Activity"),
            ("public_ldap_endpoint_exposure", "Public LDAP Endpoint Exposure"),
        ])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
