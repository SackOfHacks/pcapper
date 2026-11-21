"""Rendered output for OPC Classic (DA / A&E / HDA over DCOM): the items a
client wrote and the values, the items it touched, and who the OPC servers
and clients are."""

from __future__ import annotations

from ..opc_classic import OpcClassicSummary
from . import _style as st
from ._kv import counter_line, findings_for, window


def render_opc_classic_summary(summary: OpcClassicSummary, verbose: bool = False) -> str:
    rep = st.Report("OPC Classic", summary.path)
    findings = findings_for(summary)
    if not summary.opc_packets and not st.material(findings):
        return rep.absent("OPC Classic (DCOM) traffic", summary.errors)
    severity, text = st.verdict(
        findings,
        high="item writes or other state changes: confirm the OPC client is authorized",
        medium="OPC Classic activity to review",
    )
    writes = list(getattr(summary, "writes", None) or [])
    items = dict(getattr(summary, "items", None) or {})
    rep.headline(severity, text, st.join([
        f"{st.count(summary.opc_packets)} OPC packets",
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
        window(summary),
    ]))
    rep.scope(st.join([
        f"{st.plural(len(summary.client_counts), 'client')} -> {st.plural(len(summary.server_counts), 'server')}",
        st.plural(len(items), "item"),
        st.plural(len(writes), "item write"),
    ]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    rep.section("Item writes", st.table(
        ["Time", "Client -> server", "Operation", "Item", "Value"],
        [[st.ts(e.ts), st.flow(e.client, e.server), e.operation, e.item, f"{e.value} ({e.vartype})"] for e in writes],
        widths=(None, None, None, 40, 48), noun="write",
    ) + ([f"  {st.dim('As ASCII:')} {summary.write_value_text!r}"] if getattr(summary, "write_value_text", "") else []))

    ranked = sorted(items.values(), key=lambda i: (i.writes, i.updates + i.reads), reverse=True)
    rep.section("Items", st.table(
        ["Item ID", "Type", "Rights", "Reads", "Writes", "Updates", "Last value"],
        [[i.item_id, i.canonical_type or "-", i.access_rights or "-", st.count(i.reads),
          st.bad(str(i.writes)) if i.writes else "0", st.count(i.updates), i.last_value or "-"] for i in ranked],
        align="lllrrrl", widths=(48, None, None, None, None, None, 40), noun="item",
    ))
    rep.section("Operations", st.kv([counter_line("Operations", getattr(summary, "operation_counts", None), 12)]))
    rep.section("Identity", st.kv([
        counter_line("Server ProgIDs", getattr(summary, "server_progids", None), 6),
        counter_line("Client names", getattr(summary, "client_names", None), 6),
        counter_line("Group names", getattr(summary, "group_names", None), 6),
        counter_line("Faults", getattr(summary, "faults", None), 6),
        counter_line("Clients", summary.client_counts),
        counter_line("Servers", summary.server_counts),
    ]))

    unattributed = getattr(summary, "unattributed_requests", None)
    browse = list(getattr(summary, "browse_names", None) or [])
    rep.section("Protocol", st.kv([
        counter_line("Interfaces", summary.interface_counts, 8),
        ("Unattributed", f"{sum(unattributed.values())} request(s) on contexts bound before the capture started: "
                         f"{st.top(unattributed, None)}" if unattributed else ""),
        ("Browsed names", ", ".join(browse)),
        ("Total packets", st.count(summary.total_packets)),
    ]), detail=True)
    return rep.render()
