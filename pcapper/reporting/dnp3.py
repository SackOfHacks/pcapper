"""Rendered output for DNP3 analysis.

Default view: the control commands that actuate outstation outputs, the
findings, the function codes by role, outstation trouble indications, value
changes and the master/outstation endpoints. -v adds conversations, protocol
statistics, object groups and data-link addresses.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import TYPE_CHECKING, Iterable

from . import _style as st

if TYPE_CHECKING:
    from ..dnp3 import Dnp3Analysis

# Master function codes that change outstation state, and those worth review.
_CONTROL = {
    "Write", "Operate", "Direct Operate", "Direct Operate No Ack", "Select", "Cold Restart",
    "Warm Restart", "Stop Application", "Initialize Application", "Start Application",
    "Save Configuration", "Delete File", "Write File", "Activate Configuration",
}
_REVIEW = {
    "Enable Unsolicited", "Disable Unsolicited", "Assign Class", "Initialize Data",
    "Record Current Time", "Immediate Freeze", "Freeze and Clear", "Authenticate",
    "Open File", "Get File Info",
}
# Internal indications (IIN) worth an analyst's attention, and the alarming ones.
_NOTABLE_IIN = {
    "Device Restart", "Device Trouble", "Local Control", "Configuration corrupt",
    "Event buffer overflow", "Operation already executing", "Function code not supported",
    "Parameter error", "Object unknown",
}
_ALARM_IIN = {"Device Restart", "Device Trouble", "Configuration corrupt"}


def _master_class(name: str) -> str:
    if name in _CONTROL or any(k in name for k in ("Restart", "Operate", "Write", "Stop")):
        return "control"
    if name in _REVIEW or "Unsolicited" in name or "File" in name:
        return "review"
    return "normal"


def _styled(klass: str, text: str) -> str:
    return st.bad(text) if klass == "control" else st.caution(text) if klass == "review" else text


def render_dnp3_summary(summary: "Dnp3Analysis") -> str:
    """Render DNP3 analysis results."""
    if not summary:
        return ""
    rep = st.Report("DNP3", summary.path)
    findings = [st.finding(a) for a in (summary.anomalies or [])]
    packets = int(getattr(summary, "dnp3_packets", 0) or 0)
    if not packets and not st.material(findings):
        return rep.absent("DNP3 traffic", summary.errors)

    masters: Counter = getattr(summary, "master_ips", None) or Counter()
    outstations: Counter = getattr(summary, "outstation_ips", None) or Counter()
    control_cmds = list(getattr(summary, "control_commands", []) or [])
    sav5 = bool(getattr(summary, "sav5_present", False))
    severity, text = st.verdict(
        findings,
        high="state-changing control (operate/restart/write): confirm it is authorized",
        medium="notable DNP3 activity to review",
        clean="monitoring/poll traffic only: no control commands",
    )
    dur = float(getattr(summary, "duration", 0.0) or 0.0)
    rep.headline(severity, text, st.join([f"{st.count(packets)} DNP3 packets", st.duration(dur)]))
    rep.scope(st.join([
        f"{st.plural(len(masters), 'master')} -> {st.plural(len(outstations), 'outstation')}",
        st.plural(int(summary.unique_dnp3_addresses), "DNP3 address", "DNP3 addresses"),
        "Secure Authentication (SAv5) present" if sav5 else "no Secure Authentication (SAv5)",
    ]))
    if getattr(summary, "noncontiguous_capture", False):
        days = dur / 86400.0
        rep.note("SPAN", f"{days:,.0f} days (~{days / 365:.1f}y): a merged, non-contiguous capture; "
                         "timestamps are not a monitoring window")
    if control_cmds and not sav5:
        rep.note("UNAUTH", f"{st.plural(len(control_cmds), 'control command')} sent without Secure Authentication")
    sel, op = int(getattr(summary, "select_count", 0)), int(getattr(summary, "operate_count", 0))
    if sel and not op:
        rep.note("SBO", f"{st.plural(sel, 'Select')} without Operate: incomplete select-before-operate "
                        "or control-point probing")

    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {err}" for err in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    rep.section("Control commands", st.table(
        ["Time", "Master", "Outstation", "Output addr", "Function"],
        [[st.ts(cc.get("ts")), f"{cc.get('src_ip')} (addr {cc.get('src_addr')})", cc.get("dst_ip"),
          cc.get("dst_addr"), st.bad(str(cc.get("func")))] for cc in control_cmds],
        align="lllrl",
    ))

    master_funcs: Counter = getattr(summary, "master_funcs", None) or Counter()
    outstation_funcs: Counter = getattr(summary, "outstation_funcs", None) or Counter()
    rank = {"control": 0, "review": 1, "normal": 2}
    rows = []
    for func, cnt in sorted(master_funcs.items(), key=lambda kv: (rank[_master_class(kv[0])], -kv[1], kv[0])):
        klass = _master_class(func)
        rows.append(["master", _styled(klass, func), st.count(cnt), klass])
    for func, cnt in outstation_funcs.most_common():
        klass = "review" if "Unsolicited" in func else "normal"
        rows.append(["outstation", _styled(klass, func), st.count(cnt), klass])
    if not rows:  # functions without a known role
        rows = [["", f, st.count(c), _master_class(f)] for f, c in summary.func_counts.most_common()]
    rep.section("Commands", st.table(["Role", "Function", "Count", "Class"], rows, align="llrl", max_rows=12))

    iin = getattr(summary, "iin_flags", None) or Counter()
    notable = sorted(((k, v) for k, v in iin.items() if k in _NOTABLE_IIN), key=lambda kv: -kv[1])
    rep.section("Outstation indications", st.table(
        ["Indication (IIN)", "Count"],
        [[st.bad(k) if k in _ALARM_IIN else k, st.count(v)] for k, v in notable],
        align="lr", max_rows=None,
    ))

    rep.section("Value changes", st.table(
        ["Time", "Point", "Old", "New", "From", "To"],
        [[st.ts(c.get("ts")), f"{c.get('group')}.{c.get('variation')}[{c.get('index')}]",
          c.get("old", ""), c.get("new", ""), c.get("src", ""), c.get("dst", "")]
         for c in (getattr(summary, "value_changes", None) or [])],
        align="llrrll",
    ))

    ip_addrs = getattr(summary, "ip_dnp3_addrs", {}) or {}
    src_req = getattr(summary, "src_requests", None) or Counter()
    src_resp = getattr(summary, "src_responses", None) or Counter()
    role_ips = set(summary.ip_endpoints) | set(masters) | set(outstations)
    endpoint_rows = []
    for ip in sorted(role_ips, key=lambda i: (-int(summary.ip_endpoints.get(i, 0)), str(i))):
        is_m, is_o = int(masters.get(ip, 0)) > 0, int(outstations.get(ip, 0)) > 0
        role = "master+outstation" if is_m and is_o else "master" if is_m else "outstation" if is_o else "-"
        endpoint_rows.append([
            ip, role, ", ".join(str(a) for a in sorted(ip_addrs.get(ip, []))) or "-",
            st.count(src_req.get(ip, 0)), st.count(src_resp.get(ip, 0)),
            st.count(summary.ip_endpoints.get(ip, 0)),
        ])
    rep.section("Endpoints", st.table(
        ["Address", "Role", "DNP3 addr", "Requests", "Responses", "Packets"], endpoint_rows,
        align="lllrrr", widths=(None, None, 24),
    ))

    # ---- reference material (-v) ----------------------------------------
    directed = getattr(summary, "directed_conversations", {}) or {}
    conversations = directed or (getattr(summary, "conversations", {}) or {})
    master_set, outstation_set = set(masters), set(outstations)
    conv_rows = []
    for (a_ip, b_ip), fcounts in sorted(conversations.items(), key=lambda kv: -sum(kv[1].values())):
        role = ("master" if a_ip in master_set and a_ip not in outstation_set
                else "outstation" if a_ip in outstation_set and a_ip not in master_set
                else "master+outstation" if a_ip in master_set and a_ip in outstation_set else "-")
        conv_rows.append([a_ip, role, b_ip, ", ".join(f"{n} ({c})" for n, c in sorted(fcounts.items(), key=lambda x: -x[1]))])
    rep.section("Conversations", st.table(["Sender", "Role", "Receiver", "Functions sent"], conv_rows, max_rows=None), detail=True)

    rep.section("Statistics", st.kv([
        ("Duration", f"{dur:.2f}s"),
        ("DNP3 packets", str(packets)),
        ("Requests / responses", f"{getattr(summary, 'requests', 0)} / {getattr(summary, 'responses', 0)}"),
        ("Unsolicited responses", str(getattr(summary, "unsolicited_responses", 0))),
        ("Control commands", str(getattr(summary, "control_count", 0))),
        ("Select / operate", f"{sel} / {op}"),
        ("Active TCP/UDP IPs", str(len(summary.ip_endpoints))),
        ("DNP3 addresses", str(summary.unique_dnp3_addresses)),
    ]), detail=True)
    objects = []
    if getattr(summary, "object_group_counts", None):
        objects.append(("Groups", st.top(summary.object_group_counts, None)))
    if getattr(summary, "object_counts", None):
        objects.append(("Variations", st.top(summary.object_counts, None)))
    rep.section("Objects", st.kv(objects), detail=True)
    addresses = summary.src_addrs + summary.dst_addrs
    rep.section("Data-link addresses", [f"  {st.top(addresses, None, lambda k, v: f'addr {k} ({st.count(v)})')}"]
                if addresses else [], detail=True)
    iin_other = sorted(((k, v) for k, v in iin.items() if k not in _NOTABLE_IIN), key=lambda kv: -kv[1])
    rep.section("Other indications", st.table(["Indication (IIN)", "Count"], [[k, st.count(v)] for k, v in iin_other],
                                              align="lr", max_rows=None), detail=True)
    return rep.render()


def merge_dnp3_rollup(summaries: Iterable["Dnp3Analysis"]) -> "Dnp3Analysis | None":
    """DNP3 across several captures (-summarize): merged into one summary and
    rendered exactly like a single capture."""
    from dataclasses import replace
    from pathlib import Path

    from ..rollup import merge_records

    items = [s for s in summaries if s]
    if not items:
        return None

    def merged(name: str) -> Counter:
        total: Counter = Counter()
        for s in items:
            total.update(getattr(s, name, None) or {})
        return total

    conversations: dict = defaultdict(Counter)
    directed: dict = defaultdict(Counter)
    ip_addrs: dict = defaultdict(set)
    errors: list[str] = []
    for s in items:
        for key, counts in (getattr(s, "conversations", {}) or {}).items():
            conversations[key].update(counts)
        for key, counts in (getattr(s, "directed_conversations", {}) or {}).items():
            directed[key].update(counts)
        for ip, addrs in (getattr(s, "ip_dnp3_addrs", {}) or {}).items():
            ip_addrs[ip].update(addrs)
        errors += [e for e in s.errors if e not in errors]
    total = replace(
        items[0],
        path=Path(f"ALL_PCAPS_{len(items)}"),
        duration=sum(s.duration for s in items),
        total_packets=sum(s.total_packets for s in items),
        dnp3_packets=sum(int(getattr(s, "dnp3_packets", 0) or 0) for s in items),
        func_counts=merged("func_counts"),
        src_addrs=merged("src_addrs"),
        dst_addrs=merged("dst_addrs"),
        ip_endpoints=merged("ip_endpoints"),
        requests=sum(s.requests for s in items),
        responses=sum(s.responses for s in items),
        unsolicited_responses=sum(s.unsolicited_responses for s in items),
        control_count=sum(s.control_count for s in items),
        src_requests=merged("src_requests"),
        src_responses=merged("src_responses"),
        master_ips=merged("master_ips"),
        outstation_ips=merged("outstation_ips"),
        conversations=dict(conversations),
        iin_flags=merged("iin_flags"),
        control_commands=merge_records([list(s.control_commands or []) for s in items]),
        directed_conversations=dict(directed),
        master_funcs=merged("master_funcs"),
        outstation_funcs=merged("outstation_funcs"),
        select_count=sum(s.select_count for s in items),
        operate_count=sum(s.operate_count for s in items),
        noncontiguous_capture=any(s.noncontiguous_capture for s in items),
        messages=merge_records([list(s.messages) for s in items]),
        object_counts=merged("object_counts"),
        object_group_counts=merged("object_group_counts"),
        anomalies=merge_records([list(s.anomalies) for s in items]),
        value_changes=[c for s in items for c in (s.value_changes or [])],
        ip_dnp3_addrs=dict(ip_addrs),
        sav5_present=any(getattr(s, "sav5_present", False) for s in items),
        errors=errors,
    )
    from ..rollup import merge_window

    merge_window(total, items)
    return total


def render_dnp3_rollup(summaries: Iterable["Dnp3Analysis"]) -> str:
    """DNP3 across several captures (-summarize), rendered like one capture."""
    merged = merge_dnp3_rollup(summaries)
    return render_dnp3_summary(merged) if merged is not None else ""
