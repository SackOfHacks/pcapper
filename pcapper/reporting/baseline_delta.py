"""Rendered output for baseline_delta analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    header,
    muted,
)

from ._common import (
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
)


def render_baseline_delta(delta) -> str:
    if not delta:
        return ""
    lines = [header("BASELINE DRIFT")]
    lines.append(_format_kv("Baseline Version", delta.baseline_version or "-"))
    lines.append(_format_kv("Current Version", delta.current_version or "-"))
    if delta.notes:
        lines.append(_format_kv("Notes", "; ".join(delta.notes)))
    lines.append(_format_kv("New Hosts", str(len(delta.new_hosts))))
    lines.append(_format_kv("Missing Hosts", str(len(delta.missing_hosts))))
    lines.append(_format_kv("Host Changes", str(len(delta.host_changes))))
    lines.append(_format_kv("New Services", str(len(delta.new_services))))
    lines.append(_format_kv("Missing Services", str(len(delta.missing_services))))
    lines.append(_format_kv("Service Changes", str(len(delta.service_changes))))
    lines.append(_format_kv("New OT Commands", str(len(delta.new_ot_commands))))
    lines.append(_format_kv("Missing OT Commands", str(len(delta.missing_ot_commands))))
    lines.append(_format_kv("OT Command Changes", str(len(delta.ot_command_changes))))
    lines.append(_format_kv("New Control Targets", str(len(delta.new_control_targets))))
    lines.append(
        _format_kv("Missing Control Targets", str(len(delta.missing_control_targets)))
    )

    if delta.new_hosts:
        lines.append(header("New Hosts"))
        lines.append(muted(", ".join(delta.new_hosts[: _limit_value(10)])))
    if delta.missing_hosts:
        lines.append(header("Missing Hosts"))
        lines.append(muted(", ".join(delta.missing_hosts[: _limit_value(10)])))
    if delta.host_changes:
        lines.append(header("Host Changes"))
        rows = [["Host", "Change"]]
        for item in delta.host_changes[: _limit_value(8)]:
            ip = item.get("ip", "")
            changes = []
            if item.get("new_hostnames"):
                changes.append(f"new_hostnames={len(item.get('new_hostnames'))}")
            if item.get("missing_hostnames"):
                changes.append(
                    f"missing_hostnames={len(item.get('missing_hostnames'))}"
                )
            if item.get("new_ports"):
                changes.append(f"new_ports={len(item.get('new_ports'))}")
            if item.get("missing_ports"):
                changes.append(f"missing_ports={len(item.get('missing_ports'))}")
            if item.get("os_change"):
                changes.append("os_change")
            rows.append([str(ip), ", ".join(changes)])
        lines.append(_format_table(rows))
    if delta.service_changes:
        lines.append(header("Service Changes"))
        rows = [["Service", "Change"]]
        for item in delta.service_changes[: _limit_value(8)]:
            label = f"{item.get('ip')}:{item.get('port')}/{item.get('protocol')}"
            change = f"{item.get('from_service')} -> {item.get('to_service')}"
            if item.get("from_software") or item.get("to_software"):
                change = f"{change} ({item.get('from_software')} -> {item.get('to_software')})"
            rows.append([label, change])
        lines.append(_format_table(rows))
    if delta.ot_command_changes:
        lines.append(header("OT Command Drift"))
        rows = [["Command", "Baseline", "Current", "Delta"]]
        for item in delta.ot_command_changes[: _limit_value(8)]:
            rows.append(
                [
                    str(item.get("command", "")),
                    str(item.get("baseline", "")),
                    str(item.get("current", "")),
                    str(item.get("delta", "")),
                ]
            )
        lines.append(_format_table(rows))
    return _finalize_output(lines)
