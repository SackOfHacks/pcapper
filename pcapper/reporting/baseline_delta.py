"""Rendered output for --baseline-compare: what changed against a saved
baseline -- new or missing hosts, services, OT commands and control
targets, and changed services. Additions lead (a new host, service or
control target is the rogue-device / new-access cue); full per-host
change detail is -v."""

from __future__ import annotations

from . import _style as st


def _service(item: dict) -> str:
    return f"{item.get('ip', '-')}:{item.get('port', '-')}/{item.get('protocol', '-')}"


def _value(value: object) -> str:
    """A baseline port key (port, protocol, service, software) as 139/tcp NetBIOS."""
    if isinstance(value, (list, tuple)) and len(value) >= 2 and str(value[0]).isdigit():
        return st.join([f"{value[0]}/{str(value[1]).lower()}", *(str(v) for v in value[2:] if v and v != "-")], " ")
    return str(value)


def _host_change(item: dict) -> str:
    parts = []
    for key, label in (("new_hostnames", "+name"), ("missing_hostnames", "-name"), ("new_macs", "+MAC"), ("missing_macs", "-MAC"),
                       ("new_ports", "+port"), ("missing_ports", "-port")):
        values = [_value(v) for v in (item.get(key) or [])]
        if values:
            parts.append(f"{label} {st.listing(values, 4)}" if st.verbose() or len(values) <= 4 else f"{label} {len(values)}")
    for change in item.get("port_changes") or []:
        if isinstance(change, dict):
            label = st.join([str(v) for v in change.get("from") or [] if v and v != "-"], " ") or "-"
            now = st.join([str(v) for v in change.get("to") or [] if v and v != "-"], " ") or "-"
            parts.append(f"{change.get('port', '?')}/{str(change.get('protocol', '?')).lower()} {label} -> {now}")
    os_change = item.get("os_change")
    if isinstance(os_change, dict):
        parts.append(f"OS {os_change.get('from', '?')} -> {os_change.get('to', '?')}")
    return "; ".join(parts) or "-"


def render_baseline_delta(delta) -> str:
    if not delta:
        return ""
    rep = st.Report("Baseline drift", "baseline vs current")
    added = len(delta.new_hosts) + len(delta.new_services) + len(delta.new_ot_commands) + len(delta.new_control_targets)
    removed = len(delta.missing_hosts) + len(delta.missing_services) + len(delta.missing_ot_commands) + len(delta.missing_control_targets)
    changed = len(delta.host_changes) + len(delta.service_changes) + len(delta.ot_command_changes)
    if added:
        severity, text = "medium", "new hosts, services or OT activity since the baseline: review"
    elif removed or changed:
        severity, text = "low", "drift from the baseline"
    else:
        severity, text = None, "matches the baseline"
    rep.headline(severity, text, st.join([f"{added} added", f"{removed} missing", f"{changed} changed"]) if added + removed + changed else "")
    rep.scope(f"baseline {delta.baseline_version or '-'} · current {delta.current_version or '-'}")
    for note in delta.notes or []:
        rep.scope(str(note))
    rep.section("Hosts", st.kv([("New", st.bad(st.listing(delta.new_hosts)) if delta.new_hosts else ""),
                                ("Missing", st.listing(delta.missing_hosts))])
                + st.table(["Host", "Change"], [[i.get("ip", "-"), _host_change(i)] for i in delta.host_changes],
                           widths=(None, 100), max_rows=10, noun="host"))
    rep.section("New services", st.table(
        ["Service", "Name", "Software"],
        [[st.bad(_service(i)), i.get("service") or "-", i.get("software") or "-"] for i in delta.new_services],
        max_rows=10, noun="service",
    ))
    rep.section("Missing services", st.table(
        ["Service", "Name", "Software"], [[_service(i), i.get("service") or "-", i.get("software") or "-"] for i in delta.missing_services],
        max_rows=10, noun="service",
    ))
    rep.section("Changed services", st.table(
        ["Service", "Was", "Now"],
        [[_service(i), st.join([i.get("from_service"), i.get("from_software")], " ") or "-",
          st.join([i.get("to_service"), i.get("to_software")], " ") or "-"] for i in delta.service_changes],
        max_rows=10, noun="service",
    ))
    rep.section("OT commands", st.kv([("New", st.bad(st.listing(delta.new_ot_commands)) if delta.new_ot_commands else ""),
                                      ("Missing", st.listing(delta.missing_ot_commands))])
                + st.table(["Command", "Baseline", "Current", "Delta"],
                           [[i.get("command", "-"), st.count(i.get("baseline", 0)), st.count(i.get("current", 0)), f"{int(i.get('delta', 0)):+d}"]
                            for i in delta.ot_command_changes], align="lrrr", max_rows=10, noun="command"))
    rep.section("Control targets", st.table(
        ["", "Target"], [[st.bad("new"), t] for t in delta.new_control_targets] + [["missing", t] for t in delta.missing_control_targets],
        max_rows=10, noun="target",
    ))
    return rep.render()
