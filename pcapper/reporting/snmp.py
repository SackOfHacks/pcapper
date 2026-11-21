"""Rendered output for SNMP: who manages which agents, with what access
(versions, community strings, SNMPv3 users, writes), and the inventory the
responses disclose (hostnames, addresses, services)."""

from __future__ import annotations

from ..snmp import SnmpSummary
from . import _style as st
from ._common import _meaningful_plaintext_items, _redact_secret
from ._kv import counter_line, findings_for
from ._remote import counts, session_table

_WRITE_PDUS = ("set", "trap", "inform")


def render_snmp_summary(summary: SnmpSummary, limit: int = 12, verbose: bool = False) -> str:
    if not summary:
        return ""
    rep = st.Report("SNMP", summary.path)
    findings = findings_for(summary, ot=False)
    if not summary.snmp_packets and not st.material(findings):
        return rep.absent("SNMP traffic", summary.errors)
    severity, text = st.verdict(findings, high="high-severity SNMP activity (writes, exposure): investigate",
                                medium="SNMP activity to review")
    rep.headline(severity, text, st.join([
        f"{st.count(summary.snmp_packets)} SNMP packets · {st.plural(summary.total_messages, 'message')}",
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
        st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else "",
    ]))
    ports = ", ".join(str(p) for p, _ in summary.server_ports.most_common(4))
    rep.scope(st.join([f"{st.plural(summary.unique_clients, 'manager')} -> {st.plural(summary.unique_servers, 'agent')}",
                       f"port {ports}" if ports else ""]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    def _pdu(name: object, n: object) -> str:
        label = f"{name} ({st.count(n)})"
        return st.caution(label) if any(w in str(name).lower() for w in _WRITE_PDUS) else label

    rep.section("Access", st.kv([
        counter_line("Versions", summary.version_counts, 4),
        ("Communities", st.top(summary.community_counts, 8, fmt=lambda k, v: f"{_redact_secret(k)} ({st.count(v)})")),
        counter_line("SNMPv3 users", getattr(summary, "usm_users", None), 8),
        ("PDU types", st.top(summary.pdu_counts, 8, fmt=_pdu)),
    ]))
    rep.section("OIDs", counts(summary.oid_counts, "OID", width=80, max_rows=10, noun="OID"))
    rep.section("Inventory", st.kv([
        counter_line("Hostnames", summary.hostnames, 8),
        counter_line("IP addresses", summary.ip_addresses, 8),
        counter_line("MAC addresses", summary.mac_addresses, 6),
        counter_line("Services", summary.services, 6),
    ]))
    rep.section("Sessions", session_table(summary.conversations, [("Proto", lambda c: c.protocol)], max_rows=8))

    rep.section("Endpoints", st.kv([counter_line("Managers", summary.client_counts, None),
                                    counter_line("Agents", summary.server_counts, None),
                                    counter_line("Ports", summary.server_ports, None),
                                    counter_line("Transports", getattr(summary, "protocol_counts", None), None)]), detail=True)
    rep.section("Plaintext", st.table(["String", "Count"], [[t, st.count(n)] for t, n in
                                                          _meaningful_plaintext_items(summary.plaintext_strings, 10**9)],
                                      align="lr", max_rows=None), detail=True)
    rep.section("Artifacts", st.table(["Kind", "Detail", "Flow"],
                                      [[a.kind, a.detail, st.flow(a.src, a.dst)] for a in summary.artifacts], max_rows=None),
                detail=True)
    rep.section("Traffic", st.kv([("Packets", f"{summary.total_packets} total · {summary.snmp_packets} SNMP"),
                                  ("Bytes", st.size(summary.total_bytes))]), detail=True)
    if getattr(summary, "usm_users", None):
        rep.section("Notes", [st.dim("  SNMPv3 msgUserName is cleartext even in authPriv: the users above are the "
                                     "device-management accounts")], detail=True)
    return rep.render()
