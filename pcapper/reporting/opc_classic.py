"""Rendered output for OPC Classic (DA / A&E / HDA over DCOM) analysis."""

from __future__ import annotations

from ..coloring import danger, header, muted, warn
from ..opc_classic import OpcClassicSummary
from ..utils import format_ts
from ._common import (
    _filtered_detections,
    _finalize_output,
    _format_counter,
    _format_kv,
    _format_table,
    _limit_value,
    _ot_full_render,
    _render_ot_verdict,
    _truncate_text,
)


@_ot_full_render
def render_opc_classic_summary(
    summary: OpcClassicSummary, verbose: bool = False
) -> str:
    lines = [header("OPC CLASSIC ANALYSIS")]
    _render_ot_verdict(lines, "OPC Classic (DCOM)", getattr(summary, "detections", []))
    lines.append(_format_kv("OPC Packets", str(summary.opc_packets)))
    lines.append(_format_kv("Interfaces", _format_counter(summary.interface_counts, 8)))
    lines.append(_format_kv("Top Clients", _format_counter(summary.client_counts, 5)))
    lines.append(_format_kv("Top Servers", _format_counter(summary.server_counts, 5)))
    operations = getattr(summary, "operation_counts", None)
    if operations:
        lines.append(_format_kv("Operations", _format_counter(operations, _limit_value(12), 60)))
    unattributed = getattr(summary, "unattributed_requests", None)
    if unattributed:
        lines.append(
            _format_kv(
                "Unattributed",
                f"{sum(unattributed.values())} request(s) on contexts bound before "
                f"the capture started: {_format_counter(unattributed, 4, 40)}",
            )
        )
    for label, attr in (
        ("Server ProgIDs", "server_progids"),
        ("Client Names", "client_names"),
        ("Group Names", "group_names"),
        ("Faults", "faults"),
    ):
        value = getattr(summary, attr, None)
        if value:
            lines.append(_format_kv(label, _format_counter(value, 6, 60)))

    items = getattr(summary, "items", None) or {}
    if items:
        lines.append(header(f"Items ({len(items)})"))
        rows = [["Item ID", "Type", "Rights", "Reads", "Writes", "Updates", "Last Value"]]
        ranked = sorted(
            items.values(),
            key=lambda item: (item.writes, item.updates + item.reads),
            reverse=True,
        )
        for item in ranked[: _limit_value(25)]:
            rows.append(
                [
                    _truncate_text(item.item_id, 48),
                    item.canonical_type or "-",
                    item.access_rights or "-",
                    str(item.reads),
                    str(item.writes),
                    str(item.updates),
                    _truncate_text(item.last_value or "-", 40),
                ]
            )
        lines.append(_format_table(rows))

    writes = getattr(summary, "writes", None) or []
    if writes:
        lines.append(header(f"Item Writes ({len(writes)})"))
        rows = [["Time", "Client -> Server", "Operation", "Item", "Value"]]
        for event in writes[: _limit_value(30)]:
            rows.append(
                [
                    format_ts(event.ts),
                    f"{event.client} -> {event.server}",
                    event.operation,
                    _truncate_text(event.item, 40),
                    _truncate_text(f"{event.value} ({event.vartype})", 48),
                ]
            )
        lines.append(_format_table(rows))
        text = getattr(summary, "write_value_text", "")
        if text:
            lines.append(_format_kv("Writes as ASCII", repr(text)))

    browse = getattr(summary, "browse_names", None) or []
    if browse:
        shown = ", ".join(_truncate_text(name, 40) for name in browse[: _limit_value(15)])
        more = f" (+{len(browse) - _limit_value(15)} more)" if len(browse) > _limit_value(15) else ""
        lines.append(_format_kv("Browsed Names", shown + more))

    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors[:5])))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(header("Detections"))
        for item in detections[: _limit_value(8)]:
            sev = str(item.get("severity", "info")).upper()
            sev_color = danger if sev in {"CRITICAL", "HIGH"} else warn
            if sev in {"INFO", "LOW"}:
                sev_color = muted
            lines.append(sev_color(f"[{sev}] {item.get('summary', '')}"))
            details = str(item.get("details", "") or "")
            if details:
                lines.append(muted(f"  {details}"))
            for line in list(item.get("evidence", []) or [])[: _limit_value(6)]:
                lines.append(muted(f"    - {_truncate_text(str(line), 140)}"))
    return _finalize_output(lines)
