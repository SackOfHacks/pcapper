"""Rendered output for Kerberos: roasting, spraying and ticket abuse first,
then the accounts, hosts and SPNs the KDC traffic names, the encryption types
requested (RC4/DES are crackable) and the KDC errors; per-flow evidence and
conversations are -v detail."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from ..services import COMMON_PORTS
from . import _style as st
from ._common import _redact_in_text, _render_deterministic_checks
from ._kv import counter_line, findings_for
from ._remote import counts

if TYPE_CHECKING:
    from ..kerberos import KerberosAnalysis


def _users(principals: Counter) -> Counter:
    """Account names among the principals: the local part, without SPNs
    (service/host) or host-like names."""
    users: Counter[str] = Counter()
    for principal, n in principals.items():
        local = str(principal).split("@", 1)[0]
        if not local or "/" in local or "." in local or len(local) < 3:
            continue
        users[local] += int(n)
    return users


def _spn_hosts(spns: Counter) -> Counter:
    hosts: Counter[str] = Counter()
    for spn, n in spns.items():
        name = str(spn).split("@", 1)[0]
        if "/" not in name:
            continue
        host = name.split("/", 1)[1]
        if len(host) >= 3:
            hosts[host] += int(n)
    return hosts


def render_kerberos_summary(summary: "KerberosAnalysis", limit: int = 25, verbose: bool = False) -> str:
    if not summary:
        return ""
    rep = st.Report("Kerberos", summary.path)
    findings = findings_for(summary, ot=False)
    # total_packets is the whole capture; Kerberos is what rode 88 / 464.
    tcp, udp = int(getattr(summary, "tcp_packets", 0) or 0), int(getattr(summary, "udp_packets", 0) or 0)
    if not (tcp + udp) and not st.material(findings):
        return rep.absent("Kerberos traffic", summary.errors)
    severity, text = st.verdict(findings, high="Kerberos attack activity (roasting, spraying, ticket abuse): investigate",
                                medium="Kerberos activity to review")
    stats = summary.session_stats or {}
    rep.headline(severity, text, st.join([
        f"{st.count(tcp + udp)} Kerberos packets" + (f" ({tcp} TCP, {udp} UDP)" if tcp and udp else ""),
        st.duration(summary.duration) if summary.duration else "",
        st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else "",
    ]))
    rep.scope(st.join([
        f"{st.plural(len(summary.clients), 'client')} -> {st.plural(len(summary.servers), 'KDC')}",
        st.plural(int(stats.get("total_sessions", 0) or 0), "session") if stats else "",
        "realm " + ", ".join(str(r) for r, _ in summary.realms.most_common(3)) if summary.realms else "",
    ]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    users = _users(summary.principals)
    rep.section("Accounts", st.kv([
        ("Users", st.top(users, 10, fmt=lambda k, v: f"{_redact_in_text(str(k))} ({st.count(v)})")),
        ("Hosts (from SPNs)", st.top(_spn_hosts(summary.spns), 8, fmt=lambda k, v: f"{_redact_in_text(str(k))} ({st.count(v)})")),
        counter_line("Realms", summary.realms, 4),
    ]))
    rep.section("Service principals", counts(summary.spns, "SPN", width=80, max_rows=10, noun="SPN"))

    etypes = getattr(summary, "etype_counts", None) or Counter()
    etype_text = ""
    if etypes:
        from ..kerberos import _KRB_ETYPE_NAMES, _KRB_STRONG_ETYPES, _KRB_WEAK_ETYPES

        def _etype(k: object, v: object) -> str:
            name = f"{k} {_KRB_ETYPE_NAMES.get(k, 'unknown')}"
            if k in _KRB_WEAK_ETYPES:
                return st.caution(f"{name} weak ({st.count(v)})")
            return f"{name}{'' if k in _KRB_STRONG_ETYPES else ' ?'} ({st.count(v)})"

        etype_text = st.top(etypes, 8, fmt=_etype)
    rep.section("Protocol", st.kv([
        counter_line("Messages", summary.request_types, 8),
        ("Encryption types", etype_text),
        counter_line("KDC errors", summary.error_codes, 6),
    ]))
    rep.section("Request bursts", st.table(
        ["Client", "Peak AS/TGS requests per minute"], [[c, st.count(n)] for c, n in summary.bind_bursts.most_common()],
        align="lr", noun="client",
    ))
    rep.section("Suspicious indicators", counts(summary.suspicious_attributes, "Indicator", width=90))
    rep.section("Public endpoints", counts(summary.public_endpoints, "Endpoint"))
    rep.section("Endpoints", st.kv([counter_line("Clients", summary.clients, 8), counter_line("KDCs", summary.servers, 8)]))

    rep.section("Principal evidence", st.table(
        ["Flow", "Port", "Proto", "Principal", "Kind"],
        [[st.flow(i.get("src_ip", "-"), i.get("dst_ip", "-")), i.get("dst_port", "-"), i.get("protocol", "-"),
          _redact_in_text(str(i.get("principal", "-"))), i.get("kind", "-")] for i in (summary.principal_evidence or [])],
        max_rows=None, noun="principal",
    ), detail=True)
    rep.section("Principals", counts(summary.principals, "Principal", width=None, max_rows=None,
                                     fmt=lambda k: _redact_in_text(str(k))), detail=True)
    rep.section("Conversations", st.table(
        ["Source", "Destination", "Port", "Proto", "Packets"],
        [[c.src_ip, c.dst_ip, c.dst_port, c.proto, st.count(c.packets)] for c in summary.conversations],
        align="llrlr", max_rows=None, noun="conversation",
    ), detail=True)

    def _svc(svc: object) -> str:
        try:
            port = int(str(svc).split("/", 1)[1])
        except (IndexError, ValueError):
            return str(svc)
        name = COMMON_PORTS.get(port)
        return f"{svc} ({name})" if name else str(svc)

    rep.section("Service ports", st.kv([("Ports", st.top(summary.service_counts, None, fmt=lambda k, v: f"{_svc(k)} ({v})"))]),
                detail=True)
    rep.section("Artifacts", st.bullets([_redact_in_text(str(a)) for a in summary.artifacts], max_items=None), detail=True)
    rep.section("Traffic", st.kv([
        ("Start / end", f"{st.ts(summary.first_seen)} / {st.ts(summary.last_seen)}"),
        ("Duration", f"{summary.duration:.2f}s"),
        ("Packets", f"{summary.total_packets} total · {tcp} TCP · {udp} UDP"),
        ("Sessions", str(stats.get("total_sessions", 0)) if stats else ""),
        ("Clients / servers", f"{stats.get('unique_clients', 0)} / {stats.get('unique_servers', 0)}" if stats else ""),
    ]), detail=True)

    if st.analysis_sections():
        matrix = [i for i in (getattr(summary, "attack_matrix", None) or []) if isinstance(i, dict)]
        rep.section("Attack overview", st.table(
            ["Attack", "Status", "Severity", "Evidence"],
            [[i.get("attack", "-"), i.get("status", "-"), i.get("severity", "-"), _redact_in_text(str(i.get("evidence", "-")))]
             for i in matrix], max_rows=None,
        ))
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic Kerberos Checks", [
            ("kerberoasting", "Kerberoasting"), ("asrep_roasting", "AS-REP roasting"),
            ("password_spray_bruteforce", "Password spray/brute-force"), ("delegation_abuse", "Delegation abuse"),
            ("ticket_forgery_ptt", "Ticket forgery/pass-the-ticket"), ("user_enumeration", "Principal enumeration"),
            ("public_kdc_exposure", "Public Kerberos exposure"), ("cross_realm_or_realm_spray", "Cross-realm spray"),
        ])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
