"""Rendered output for --baseline (the profile just recorded) and
--baseline-diff (what deviates from a saved baseline or a reference capture).

The drift report leads with its findings, one per deviation rule that fired
(pcapper.baseline.compare_baseline), worst first; the tables below are the
evidence: new, absent and changed conversations, per-pair commands, layer-2
streams, MAC bindings, hosts and services. Additions lead each table (a new
pair, writer or MAC is the rogue-device / new-access cue); -v prints every
row and the reference sections."""

from __future__ import annotations

from pathlib import Path

from . import _style as st

_CATEGORY_ORDER = {"OT": 0, "IoT": 1, "IT": 2, "other": 3}


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


def _describe(flow: dict) -> str:
    from ..baseline import describe_flow

    return describe_flow(flow)


def _cadence(flow: dict) -> str:
    median = flow.get("interval_median")
    if not median:
        return "-"
    text = f"every {st.duration(float(median))}" if float(median) >= 1 else f"every {float(median) * 1000:.0f} ms"
    jitter = flow.get("interval_jitter")
    if jitter is not None and float(jitter) >= 0.3:
        text += " (irregular)"
    return text


def _sources(sources: list) -> str:
    names = [Path(str(s)).name for s in sources or []]
    if not names:
        return "-"
    return names[0] if len(names) == 1 else f"{names[0]} +{len(names) - 1}"


def _window(capture: dict) -> str:
    if not capture:
        return ""
    return st.join([
        f"{st.count(capture.get('packets', 0))} packets" if capture.get("packets") else "",
        st.duration(capture.get("duration_seconds")) if capture.get("duration_seconds") else "",
        st.ts_range(capture.get("first_seen"), capture.get("last_seen")) if capture.get("first_seen") else "",
    ])


def _flow_rows(flows: list, status: str, style=None) -> list[list[str]]:
    rows = []
    for f in sorted(flows, key=lambda f: (_CATEGORY_ORDER.get(str(f.get("category")), 9), -int(f.get("packets", 0) or 0))):
        mark = style(status) if style else status
        rows.append([mark, st.flow(f.get("client"), f.get("server")), _describe(f), str(f.get("category", "-")),
                     st.count(f.get("packets", 0)), _cadence(f)])
    return rows


def render_baseline_delta(delta) -> str:
    if not delta:
        return ""
    rep = st.Report("Baseline drift", "baseline vs current")
    findings = [st.finding(d) for d in (delta.deviations or [])]
    material = [f for f in findings if st.sev_rank(f.severity) >= 1]
    if material:
        severity, text = st.verdict(
            material,
            high="new access or control activity since the baseline: review",
            medium="drift from the baseline: review",
            low="minor drift from the baseline",
        )
    else:
        severity, text = None, "matches the baseline" + (" (absences only)" if findings else "")
    rep.headline(severity, text)
    rep.scope(f"baseline  {_sources(delta.baseline_sources)}  {st.join([_window(delta.baseline_capture), 'pcapper ' + (delta.baseline_version or '-')])}")
    rep.scope(f"current   {_sources(delta.current_sources)}  {st.join([_window(delta.current_capture), 'pcapper ' + (delta.current_version or '-')])}")
    for note in delta.notes or []:
        rep.note("NOTE", str(note))

    rep.section("Findings", st.findings_block(findings))

    rows = (_flow_rows(delta.new_flows, "new", st.bad) + _flow_rows(delta.missing_flows, "absent"))
    rep.section("Conversations", st.table(
        ["", "Flow", "Protocol", "Class", "Packets", "Cadence"], rows, align="llllrl", max_rows=12, noun="conversation"))

    change_rows = []
    for change in delta.flow_changes or []:
        flow = change.get("flow") or {}
        parts = []
        if "rate" in change:
            parts.append(f"{change['rate']['baseline']:,.1f} -> {change['rate']['current']:,.1f} pkts/min")
        if "cadence" in change:
            b, c = float(change["cadence"]["baseline"]), float(change["cadence"]["current"])
            parts.append(f"every {_short(b)} -> {_short(c)}")
        if "jitter" in change:
            parts.append(f"jitter {change['jitter']['baseline']:.2f} -> {change['jitter']['current']:.2f}")
        change_rows.append([st.flow(flow.get("client"), flow.get("server")), _describe(flow), "; ".join(parts)])
    rep.section("Changed conversations", st.table(["Flow", "Protocol", "Change"], change_rows, max_rows=10, noun="conversation"))

    cmd_rows = []
    for item in delta.new_pair_commands or []:
        cmd_rows.append([st.bad("new"), st.flow(item.get("src"), item.get("dst")), str(item.get("protocol", "")),
                         str(item.get("command", "")), st.bad("W") if item.get("write") else "R", st.count(item.get("count", 0))])
    for change in delta.pair_command_changes or []:
        item = change.get("item") or {}
        cmd_rows.append(["rate", st.flow(item.get("src"), item.get("dst")), str(item.get("protocol", "")), str(item.get("command", "")),
                         "W", f"{change.get('baseline_per_min', 0):,.1f} -> {change.get('current_per_min', 0):,.1f}/min"])
    for item in delta.missing_pair_commands or []:
        cmd_rows.append(["absent", st.flow(item.get("src"), item.get("dst")), str(item.get("protocol", "")),
                         str(item.get("command", "")), "W" if item.get("write") else "R", st.count(item.get("count", 0))])
    rep.section("OT commands per pair", st.table(
        ["", "Flow", "Protocol", "Command", "R/W", "Count"], cmd_rows, align="lllllr", max_rows=12, noun="command"))

    l2_rows = [[st.bad("new"), st.flow(f.get("src_mac"), f.get("dst_mac")), str(f.get("protocol", "")), st.count(f.get("packets", 0))]
               for f in delta.new_l2_flows or []]
    l2_rows += [["absent", st.flow(f.get("src_mac"), f.get("dst_mac")), str(f.get("protocol", "")), st.count(f.get("packets", 0))]
                for f in delta.missing_l2_flows or []]
    rep.section("Layer-2 streams", st.table(["", "Flow", "Protocol", "Frames"], l2_rows, align="lllr", max_rows=10, noun="stream"))

    reg_rows = []
    for change in delta.register_changes or []:
        reg = change.get("register") or {}
        reg_rows.append([str(reg.get("server", "-")), f"unit {reg.get('unit')} {reg.get('type')}[{reg.get('address')}]",
                         _range(change.get("baseline")), st.bad(_range(change.get("current")))])
    rep.section("Register values", st.table(["Server", "Register", "Baseline", "Current"], reg_rows,
                                            max_rows=12, noun="register"))

    mac_rows = []
    for change in delta.mac_changes or []:
        was = ", ".join(st.join([m, v], " ") for m, v in (change.get("baseline") or {}).items())
        now = ", ".join(st.join([m, v], " ") for m, v in (change.get("current") or {}).items())
        mac_rows.append([str(change.get("ip", "")), was or "-", st.bad(now) if now else "-"])
    rep.section("MAC bindings", st.table(["IP", "Baseline MAC", "Current MAC"], mac_rows, max_rows=10, noun="address"))

    rep.section("Hosts", st.kv([("New", st.bad(st.listing(delta.new_hosts)) if delta.new_hosts else ""),
                                ("Absent", st.listing(delta.missing_hosts))])
                + st.table(["Host", "Change"], [[i.get("ip", "-"), _host_change(i)] for i in delta.host_changes],
                           widths=(None, 100), max_rows=10, noun="host"))
    svc_rows = [[st.bad("new"), _service(i), i.get("service") or "-", i.get("software") or "-"] for i in delta.new_services]
    svc_rows += [["changed", _service(i), st.join([i.get("from_service"), i.get("from_software")], " ") + " -> "
                  + st.join([i.get("to_service"), i.get("to_software")], " "), ""] for i in delta.service_changes]
    svc_rows += [["absent", _service(i), i.get("service") or "-", i.get("software") or "-"] for i in delta.missing_services]
    rep.section("Services", st.table(["", "Service", "Name", "Software"], svc_rows, max_rows=10, noun="service"))

    # Schema-1 baselines: the protocol-level totals are all there is.
    if not (delta.new_pair_commands or delta.missing_pair_commands or delta.pair_command_changes):
        rep.section("OT command totals", st.kv([("New", st.bad(st.listing(delta.new_ot_commands)) if delta.new_ot_commands else ""),
                                                ("Absent", st.listing(delta.missing_ot_commands))])
                    + st.table(["Command", "Baseline", "Current", "Delta"],
                               [[i.get("command", "-"), st.count(i.get("baseline", 0)), st.count(i.get("current", 0)), f"{int(i.get('delta', 0)):+d}"]
                                for i in delta.ot_command_changes], align="lrrr", max_rows=10, noun="command"))
        rep.section("Control targets", st.table(
            ["", "Target"], [[st.bad("new"), t] for t in delta.new_control_targets] + [["absent", t] for t in delta.missing_control_targets],
            max_rows=10, noun="target"))
    return rep.render()


def _range(values: object) -> str:
    if not isinstance(values, (list, tuple)) or len(values) < 2:
        return "-"
    return str(values[0]) if values[0] == values[1] else f"{values[0]}..{values[1]}"


def _short(seconds: float) -> str:
    return st.duration(seconds) if seconds >= 1 else f"{seconds * 1000:.0f} ms"


def render_baseline_profile(snapshot, saved_to: object = None) -> str:
    """What a --baseline recorded: the OT/ICS/IoT communication first, then
    commands per pair, IT on OT hosts, layer-2 streams; identities, other
    conversations, hosts and services with -v."""
    if snapshot is None:
        return ""
    from ..baseline import _ot_hosts

    name = _sources(snapshot.sources)
    rep = st.Report("Baseline", name if len(snapshot.sources) == 1 else f"{st.ROLLUP_NAME}_{len(snapshot.sources)}")
    flows = list(snapshot.flows or [])
    ot = [f for f in flows if f.get("category") in ("OT", "IoT")]
    ot_hosts = _ot_hosts(snapshot)
    it_on_ot = [f for f in flows if f.get("category") not in ("OT", "IoT")
                and (f.get("client") in ot_hosts or f.get("server") in ot_hosts)]
    other = [f for f in flows if f not in ot and f not in it_on_ot]
    writes = [i for i in snapshot.pair_commands or [] if i.get("write")]
    counts = st.join([
        st.plural(len(snapshot.hosts or []), "host"),
        f"{st.plural(len(ot), 'OT/IoT conversation')}",
        st.plural(len(snapshot.pair_commands or []), "pair command"),
        f"{len(writes)} write" + ("s" if len(writes) != 1 else "") if writes else "",
        st.plural(len(snapshot.l2_flows or []), "L2 stream") if snapshot.l2_flows else "",
        st.plural(len(flows) - len(ot), "other conversation") if len(flows) > len(ot) else "",
    ])
    rep.headline(False, f"baseline recorded · {counts}")
    rep.scope(st.join([_window(snapshot.capture), f"pcapper {snapshot.pcapper_version}",
                       f"OT commands: {snapshot.ot_command_mode} scan" if snapshot.ot_command_mode else ""]))
    if saved_to:
        rep.scope(f"saved to {saved_to}")
    for note in snapshot.notes or []:
        rep.note("NOTE", str(note))

    rep.section("OT/ICS & IoT conversations", st.table(
        ["Flow", "Protocol", "Class", "Packets", "Bytes", "Cadence"],
        [r[1:5] + [st.size(f.get("bytes", 0)), r[5]] for r, f in zip(_flow_rows(ot, ""), _sorted(ot))],
        align="lllrrl", max_rows=15, noun="conversation"))

    cmd_rows = []
    for item in sorted(snapshot.pair_commands or [], key=lambda i: (not i.get("write"), -int(i.get("count", 0) or 0))):
        cmd_rows.append([st.flow(item.get("src"), item.get("dst")), str(item.get("protocol", "")), str(item.get("command", "")),
                         st.caution("W") if item.get("write") else "R", st.count(item.get("count", 0))])
    rep.section("OT commands per pair", st.table(["Flow", "Protocol", "Command", "R/W", "Count"], cmd_rows,
                                                 align="llllr", max_rows=12, noun="command"))

    rep.section("IT protocols on OT hosts", st.table(
        ["Flow", "Protocol", "Packets", "Cadence"],
        [[r[1], r[2], r[4], r[5]] for r in _flow_rows(it_on_ot, "")], align="llrl", max_rows=10, noun="conversation"))

    rep.section("Layer-2 streams", st.table(
        ["Flow", "Protocol", "Frames", "Cadence"],
        [[st.flow(f.get("src_mac"), f.get("dst_mac")), str(f.get("protocol", "")), st.count(f.get("packets", 0)), _cadence(f)]
         for f in sorted(snapshot.l2_flows or [], key=lambda f: -int(f.get("packets", 0) or 0))],
        align="llrl", max_rows=10, noun="stream"))

    rep.section("Modbus register values", st.table(
        ["Server", "Register", "Range", "Samples"],
        [[r.get("server", "-"), f"unit {r.get('unit')} {r.get('type')}[{r.get('address')}]",
          _range([r.get("min"), r.get("max")]), st.count(r.get("samples", 0))] for r in snapshot.registers or []],
        align="lllr", max_rows=None, noun="register"), detail=True)
    rep.section("MAC bindings", st.table(
        ["IP", "MAC", "Vendor"],
        [[ip, e.get("mac", "-"), e.get("vendor") or "-"] for ip, entries in sorted((snapshot.ip_macs or {}).items()) for e in entries],
        max_rows=None, noun="binding"), detail=True)
    rep.section("Other conversations", st.table(
        ["Flow", "Protocol", "Class", "Packets", "Cadence"],
        [r[1:] for r in _flow_rows(other, "")], align="lllrl", max_rows=None, noun="conversation"), detail=True)
    rep.section("Services", st.table(
        ["Service", "Name", "Software", "Clients"],
        [[_service(s), s.get("service") or "-", s.get("software") or "-", st.count(len(s.get("clients") or []))]
         for s in snapshot.services or []], align="lllr", max_rows=None, noun="service"), detail=True)
    return rep.render()


def _sorted(flows: list) -> list:
    return sorted(flows, key=lambda f: (_CATEGORY_ORDER.get(str(f.get("category")), 9), -int(f.get("packets", 0) or 0)))
