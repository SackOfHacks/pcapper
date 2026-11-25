"""Rendered output for --baseline (the profile just recorded) and
--baseline-diff (what deviates from a saved baseline or a reference capture).

The drift report reads like an incident report. The headline names the lead
incident; Incidents tell what happened per actor (who, to what, when, the
ATT&CK for ICS technique, the evidence, and the pcapper command to run next);
Findings list every deviation rule that fired, worst first; the Timeline
orders them by first sighting; the tables below are the evidence. Background
chatter (broadcast, multicast, link-local and unspecified addresses coming
and going) and informational absences are counted in the headline and shown
with -v."""

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


def _capture_arg(sources: list) -> str:
    """The capture to name in a suggested command."""
    names = [Path(str(s)).name for s in sources or []]
    if len(names) != 1:
        return "<capture>"
    name = names[0]
    return f'"{name}"' if " " in name else name


def _incident_lines(incidents: list, deviations: list, capture: str) -> list[str]:
    lines: list[str] = []
    pad = " " * (st.BADGE_W + 4)
    shown = incidents if st.verbose() else incidents[:6]
    width = None if st.verbose() else 150
    for incident in shown:
        attack = str(incident.get("attack") or "")
        lines.append(f"  {st.badge(incident.get('severity'))}  {st.strong(str(incident.get('title', '')))}")
        rows: list[tuple[str, str]] = []
        first, last = incident.get("first_seen"), incident.get("last_seen")
        if first:
            span = float(last) - float(first) if last else 0.0
            rows.append(("when", st.ts_range(first, last) + (f" ({st.duration(span)})" if span >= 1 else "")))
        if attack:
            # Whole techniques per line, never cut mid-name.
            line_parts: list[str] = []
            for technique in attack.split("; "):
                if line_parts and len("; ".join(line_parts + [technique])) > 110:
                    rows.append(("att&ck" if not any(r[0] == "att&ck" for r in rows) else "", "; ".join(line_parts)))
                    line_parts = []
                line_parts.append(technique)
            rows.append(("att&ck" if not any(r[0] == "att&ck" for r in rows) else "", "; ".join(line_parts)))
        members = [deviations[i] for i in incident.get("members") or [] if i < len(deviations)]
        members.sort(key=lambda d: (-st.sev_rank(d.get("severity")), d.get("kind") == "register", str(d.get("summary"))))
        evidence = [d for d in members if d.get("kind") != "register"]
        impact = [d for d in members if d.get("kind") == "register"]
        limit = None if st.verbose() else 3
        for d in evidence[:limit]:
            rows.append(("what", _member_text(d)))
        for d in impact[:limit]:
            rows.append(("impact", _member_text(d)))
        hidden = (len(evidence) - 3 if len(evidence) > 3 else 0) + (len(impact) - 3 if len(impact) > 3 else 0)
        if hidden and not st.verbose():
            rows.append(("", f"+{hidden} more {'deviation' if hidden == 1 else 'deviations'} (-v)"))
        pivots = incident.get("pivots") or []
        for flags in pivots if st.verbose() else pivots[:2]:
            rows.append(("next", f"pcapper {capture} {' '.join(flags)}"))
        for label_text, value in rows:
            lines.append(pad + st.dim(st.cut(f"{(label_text + ':').ljust(9) if label_text else ' ' * 9}{value}", width)))
    if len(incidents) > len(shown):
        lines.append(st.more(len(incidents) - len(shown), "incident"))
    return lines


def _member_text(d: dict) -> str:
    details = str(d.get("details") or "")
    where = ""
    if d.get("src") and d.get("dst"):
        where = f"{d['src']} -> {d['dst']}  "
    elif d.get("src") or d.get("dst"):
        where = f"{d.get('src') or d.get('dst')}  "
    return f"{d.get('summary')}: {where}{details}".rstrip(": ").rstrip()


def _timeline_rows(deviations: list) -> list[list[str]]:
    rows = []
    for d in sorted((d for d in deviations if d.get("ts") and not d.get("background")
                     and st.sev_rank(d.get("severity")) >= 1), key=lambda d: (float(d["ts"]), str(d.get("summary")))):
        flow = st.flow(d.get("src"), d.get("dst")) if d.get("src") and d.get("dst") else str(d.get("src") or d.get("dst") or "-")
        rows.append([st.ts(d.get("ts")), st.badge(d.get("severity")), str(d.get("summary", "")), flow])
    return rows


def render_baseline_delta(delta) -> str:
    if not delta:
        return ""
    from ..baseline import _background_ip

    rep = st.Report("Baseline drift", "baseline vs current")
    deviations = list(delta.deviations or [])
    signal = [d for d in deviations if not d.get("background")]
    background = [d for d in deviations if d.get("background")]
    material = [d for d in signal if st.sev_rank(d.get("severity")) >= 1]
    informational = [d for d in signal if st.sev_rank(d.get("severity")) < 1]
    incidents = list(getattr(delta, "incidents", None) or [])
    capture = _capture_arg(delta.current_sources)

    if incidents:
        severity = incidents[0].get("severity")
        lead = str(incidents[0].get("title", ""))
        text = lead if len(incidents) == 1 else f"{st.plural(len(incidents), 'incident')} · lead: {lead}"
    elif material:
        severity, text = st.verdict(
            [st.finding(d) for d in material],
            high="new access or control activity since the baseline: review",
            medium="drift from the baseline: review",
            low="minor drift from the baseline",
        )
    else:
        severity, text = None, "matches the baseline" + (" (absences and background changes only)" if deviations else "")
    rep.headline(severity, text, st.join([
        st.plural(len(material), "deviation") if material else "",
        f"{len(informational)} informational" if informational else "",
        f"{len(background)} background" if background else "",
    ]))
    rep.scope(f"baseline  {_sources(delta.baseline_sources)}  {st.join([_window(delta.baseline_capture), 'pcapper ' + (delta.baseline_version or '-')])}")
    rep.scope(f"current   {_sources(delta.current_sources)}  {st.join([_window(delta.current_capture), 'pcapper ' + (delta.current_version or '-')])}")
    for note in delta.notes or []:
        rep.note("NOTE", str(note))

    rep.section("Incidents", _incident_lines(incidents, deviations, capture))
    quiet = len(informational) + len(background)
    rep.section("Findings", st.findings_block([st.finding(d) for d in material])
                + ([st.dim(f"  + {quiet} informational and background changes (-v shows them)")] if quiet and not st.verbose() else []))
    rep.section("Timeline", st.table(["First seen", "Severity", "Deviation", "Where"], _timeline_rows(deviations),
                                     max_rows=12, noun="event"))
    rep.section("Informational", st.findings_block([st.finding(d) for d in informational]), detail=True)

    def _foreground(flow: dict) -> bool:
        return not (_background_ip(flow.get("client")) or _background_ip(flow.get("server")))

    new_flows = [f for f in delta.new_flows if st.verbose() or _foreground(f)]
    missing_flows = [f for f in delta.missing_flows if st.verbose() or _foreground(f)]
    rows = (_flow_rows(new_flows, "new", st.bad) + _flow_rows(missing_flows, "absent"))
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

    new_hosts = [h for h in delta.new_hosts if st.verbose() or not _background_ip(h)]
    missing_hosts = [h for h in delta.missing_hosts if st.verbose() or not _background_ip(h)]
    rep.section("Hosts", st.kv([("New", st.bad(st.listing(new_hosts)) if new_hosts else ""),
                                ("Absent", st.listing(missing_hosts))])
                + st.table(["Host", "Change"], [[i.get("ip", "-"), _host_change(i)] for i in delta.host_changes
                                                if st.verbose() or not _background_ip(i.get("ip"))],
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
    rep.section("Background changes", st.table(
        ["Change", "Where", "Detail"],
        [[str(d.get("summary", "")).replace("Background chatter: ", ""),
          st.flow(d.get("src"), d.get("dst")) if d.get("src") and d.get("dst") else str(d.get("src") or d.get("dst") or "-"),
          str(d.get("details") or "-")] for d in background],
        max_rows=None, noun="change"), detail=True)
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
