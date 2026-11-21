"""Rendered output for MS-RPC / DCE-RPC: the interfaces and operations
called (service control, SAMR, DRSUAPI, ...), the named pipes and shares
used, and the accounts named; strings carved from (often encrypted) stubs
are -v detail."""

from __future__ import annotations

from ..rpc import RpcSummary
from . import _style as st
from ._common import _meaningful_plaintext_items, _redact_in_text, _render_deterministic_checks
from ._kv import counter_line, findings_for
from ._remote import counts, session_table


def render_rpc_summary(summary: RpcSummary, limit: int = 12, verbose: bool = False) -> str:
    if not summary:
        return ""
    rep = st.Report("RPC", summary.path)
    findings = findings_for(summary, ot=False)
    if not summary.rpc_packets and not st.material(findings):
        return rep.absent("MS-RPC traffic", summary.errors)
    severity, text = st.verdict(findings, high="high-severity RPC activity (remote execution, replication): investigate",
                                medium="RPC activity to review")
    rep.headline(severity, text, st.join([
        f"{st.count(summary.rpc_packets)} RPC packets · {st.plural(summary.total_messages, 'message')}",
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
        st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else "",
    ]))
    ports = ", ".join(str(p) for p, _ in summary.server_ports.most_common(4))
    rep.scope(st.join([f"{st.plural(summary.unique_clients, 'client')} -> {st.plural(summary.unique_servers, 'server')}",
                       f"port {ports}" if ports else ""]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    rep.section("Interfaces", counts(summary.interface_counts, "Interface", width=80, noun="interface"))
    rep.section("Operations", counts(summary.command_counts, "Operation", width=80, noun="operation"))
    fullnames = list(getattr(summary, "samr_fullnames", None) or [])
    rep.section("Accounts", st.kv([
        ("Domain users", st.top(summary.domain_user_counts, 10, fmt=lambda k, v: f"{_redact_in_text(str(k))} ({st.count(v)})")),
        ("SAMR full names", ", ".join(sorted({_redact_in_text(str(f.get("full_name", ""))) for f in fullnames if f.get("full_name")}))),
    ]))
    rep.section("Pipes and shares", st.kv([counter_line("Named pipes", summary.pipe_counts, 8),
                                           counter_line("Shares", summary.share_counts, 8)]))
    rep.section("Protocol", st.kv([counter_line("PDU types", summary.pdu_counts, 8),
                                   counter_line("Transports", summary.protocol_counts, 4)]))
    rep.section("Sessions", session_table(summary.conversations, [("Proto", lambda c: c.protocol)], max_rows=8))

    rep.section("SAMR lookups", st.table(
        ["Flow", "Port", "Opnum", "Full name"],
        [[st.flow(f.get("src_ip"), f.get("dst_ip")), f.get("server_port", "-"), f.get("opnum", "-"),
          _redact_in_text(str(f.get("full_name", "-")))] for f in fullnames], max_rows=None,
    ), detail=True)
    rep.section("Carved strings", st.kv([
        counter_line("Hostnames", summary.hostname_counts, None),
        counter_line("IP addresses", summary.ip_strings, None),
        counter_line("MAC addresses", summary.mac_strings, None),
    ]) + st.table(["String", "Count"], [[t, st.count(n)] for t, n in
                                       _meaningful_plaintext_items(summary.plaintext_strings, 10**9)],
                  align="lr", max_rows=None), detail=True)
    rep.section("Artifacts", st.table(["Kind", "Detail", "Flow"],
                                      [[a.kind, a.detail, st.flow(a.src, a.dst)] for a in summary.artifacts], max_rows=None),
                detail=True)
    hyp = [f"[{h.get('confidence', '?')}] {h.get('hypothesis', '-')} (evidence={h.get('evidence', '')})"
           for h in (getattr(summary, "threat_hypotheses", None) or [])]
    rep.section("Threat hypotheses", st.bullets(hyp, max_items=None), detail=True)
    rep.section("Benign context", st.bullets(getattr(summary, "benign_context", None) or [], max_items=None), detail=True)
    rep.section("Traffic", st.kv([
        ("Packets", f"{summary.total_packets} total · {summary.rpc_packets} RPC"),
        ("Bytes", st.size(summary.total_bytes)),
        counter_line("Clients", summary.client_counts, None),
        counter_line("Servers", summary.server_counts, None),
        counter_line("Ports", summary.server_ports, None),
    ]), detail=True)

    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic RPC Security Checks", [
            ("rpc_admin_share_or_pipe_access", "Admin-Share/Named-Pipe Access"),
            ("rpc_lateral_tooling", "Lateral-Movement Tooling"),
            ("rpc_samr_enum_activity", "SAMR/Directory Enumeration"),
            ("rpc_bind_failure_burst", "Bind Failure Burst"),
            ("rpc_scanning_fanout", "Scanning Fan-out"),
            ("rpc_beaconing_pattern", "Beaconing Pattern"),
            ("rpc_data_asymmetry_exfil", "Data-Asymmetry Exfil"),
            ("rpc_public_exposure", "Public Exposure"),
        ])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
