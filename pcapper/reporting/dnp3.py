"""Rendered output for dnp3 analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from collections import Counter
from typing import TYPE_CHECKING, Iterable
from ..coloring import (
    danger,
    header,
    highlight,
    muted,
    ok,
    warn,
)
if TYPE_CHECKING:
    from ..dnp3 import Dnp3Analysis

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _counter_table,
    _finalize_output,
    _format_counter,
    _format_kv,
    _format_table,
    _limit_value,
    _ot_full_render,
)


@_ot_full_render
def render_dnp3_summary(summary: "Dnp3Analysis") -> str:
    """
    Render DNP3 analysis results (threat-hunt / IR / triage aligned).
    """
    from ..utils import format_ts

    if not summary:
        return ""

    lines = []
    lines.append(SECTION_BAR)
    lines.append(header(f"DNP3 ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    # 1. Overview
    dur = float(getattr(summary, "duration", 0.0))
    if getattr(summary, "noncontiguous_capture", False):
        days = dur / 86400.0
        lines.append(_format_kv(
            "Capture Span",
            warn(f"{days:,.0f} days (~{days/365:.1f}y) — non-contiguous / merged "
                 "capture; timestamps are not a real monitoring window"),
        ))
    else:
        lines.append(_format_kv("Scan Duration", f"{dur:.2f}s"))
    lines.append(_format_kv("DNP3 Packets", str(summary.dnp3_packets)))
    lines.append(_format_kv("Active TCP/UDP IPs", str(len(summary.ip_endpoints))))
    lines.append(_format_kv("DNP3 Addresses", str(summary.unique_dnp3_addresses)))
    lines.append(
        _format_kv(
            "Secure Auth (SAv5)",
            "present"
            if getattr(summary, "sav5_present", False)
            else "NOT observed (unauthenticated DNP3)",
        )
    )

    # ---- Analyst Verdict ------------------------------------------------
    anoms = list(summary.anomalies or [])
    _sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    worst = max((_sev_rank.get(a.severity, 0) for a in anoms), default=0)
    control_cmds = list(getattr(summary, "control_commands", []) or [])
    restart_n = sum(
        1 for a in anoms if "Restart" in a.title and a.title == "DNP3 Restart"
    )
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if worst >= 3:
        verdict = (
            "HIGH - DNP3 control-plane activity that changes device state "
            "(operate/restart/write) was observed; confirm it is authorized."
        )
        lines.append(danger(verdict))
    elif worst >= 2:
        lines.append(warn("REVIEW - notable DNP3 activity observed."))
    elif summary.dnp3_packets:
        lines.append(
            ok("LOW - DNP3 monitoring/poll traffic only; no control commands seen.")
        )
    else:
        lines.append(ok("No DNP3 traffic detected."))
    focus = []
    if control_cmds:
        focus.append(f"{len(control_cmds)} control command(s) to outstation outputs")
    if restart_n:
        focus.append(f"{restart_n} device restart command(s)")
    if getattr(summary, "unsolicited_responses", 0):
        focus.append(f"{summary.unsolicited_responses} unsolicited response(s)")
    if not getattr(summary, "sav5_present", False) and control_cmds:
        focus.append("control commands sent UNAUTHENTICATED (no SAv5)")
    if focus:
        lines.append(muted("Focus Here First: " + "; ".join(focus)))

    # ---- Endpoints & roles (master / outstation) ------------------------
    lines.append(SUBSECTION_BAR)
    lines.append(header("Endpoints & Roles"))
    master_ips = getattr(summary, "master_ips", Counter())
    outstation_ips = getattr(summary, "outstation_ips", Counter())
    ip_addrs = getattr(summary, "ip_dnp3_addrs", {}) or {}
    role_ips = set(summary.ip_endpoints) | set(master_ips) | set(outstation_ips)
    if role_ips:
        rows = [["IP", "Role", "DNP3 Addr(s)", "Requests", "Responses"]]
        for ip in sorted(
            role_ips, key=lambda i: -int(summary.ip_endpoints.get(i, 0))
        )[: _limit_value(12)]:
            is_m = int(master_ips.get(ip, 0)) > 0
            is_o = int(outstation_ips.get(ip, 0)) > 0
            role = (
                "Master+Outstation"
                if is_m and is_o
                else "Master"
                if is_m
                else "Outstation"
                if is_o
                else "-"
            )
            addrs = ",".join(str(a) for a in sorted(ip_addrs.get(ip, []))[:6]) or "-"
            rows.append(
                [
                    ip,
                    role,
                    addrs,
                    str(int(getattr(summary, "src_requests", Counter()).get(ip, 0))),
                    str(int(getattr(summary, "src_responses", Counter()).get(ip, 0))),
                ]
            )
        lines.append(_format_table(rows))

    # ---- Top masters (clients) / outstations (servers) ------------------
    masters = getattr(summary, "master_ips", Counter())
    outstations = getattr(summary, "outstation_ips", Counter())
    src_req = getattr(summary, "src_requests", Counter())
    src_resp = getattr(summary, "src_responses", Counter())
    if masters or outstations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Masters (clients) / Outstations (servers)"))
        col = 45
        lines.append(highlight(f"{'Master (requests)':<{col}} | {'Outstation (responses)'}"))
        lines.append(muted("-" * 90))
        m_rank = sorted(set(masters), key=lambda i: -int(src_req.get(i, 0)))
        o_rank = sorted(set(outstations), key=lambda i: -int(src_resp.get(i, 0)))
        for i in range(max(len(m_rank), len(o_rank))):
            m = f"{m_rank[i]} ({int(src_req.get(m_rank[i], 0))} req)" if i < len(m_rank) else ""
            o = f"{o_rank[i]} ({int(src_resp.get(o_rank[i], 0))} resp)" if i < len(o_rank) else ""
            lines.append(f"{m:<{col}} | {o}")

    # ---- Conversations (direction-aware: actual sender -> receiver) ------
    directed = getattr(summary, "directed_conversations", {}) or {}
    conversations = directed or (getattr(summary, "conversations", {}) or {})
    if conversations:
        master_set = set(masters)
        outstation_set = set(outstations)
        lines.append(SUBSECTION_BAR)
        lines.append(header("DNP3 Conversations (sender -> receiver)"))
        rows = [["Sender", "Role", "Receiver", "Functions Sent"]]
        for (a_ip, b_ip), fcounts in sorted(
            conversations.items(), key=lambda kv: -sum(kv[1].values())
        )[: _limit_value(12)]:
            role = (
                "Master" if a_ip in master_set and a_ip not in outstation_set
                else "Outstation" if a_ip in outstation_set and a_ip not in master_set
                else "Master+Out" if a_ip in master_set and a_ip in outstation_set
                else "-"
            )
            fc = ", ".join(
                f"{n}({c})"
                for n, c in sorted(fcounts.items(), key=lambda x: -x[1])[:5]
            )
            rows.append([a_ip, role, b_ip, fc])
        lines.append(_format_table(rows))

    # ---- Protocol statistics --------------------------------------------
    lines.append(SUBSECTION_BAR)
    lines.append(header("DNP3 Protocol Statistics"))
    lines.append(
        _format_kv(
            "Requests / Responses",
            f"{getattr(summary, 'requests', 0)} / {getattr(summary, 'responses', 0)}",
        )
    )
    lines.append(
        _format_kv("Unsolicited Responses", str(getattr(summary, "unsolicited_responses", 0)))
    )
    lines.append(
        _format_kv("Control Commands", str(getattr(summary, "control_count", 0)))
    )

    # 2. DNP3 Command Summary — observed function codes split by role (master
    # requests vs outstation responses) and classified by risk, so a triager
    # sees the control-plane commands separately from monitoring/poll traffic.
    master_funcs = getattr(summary, "master_funcs", Counter()) or Counter()
    outstation_funcs = getattr(summary, "outstation_funcs", Counter()) or Counter()
    if not master_funcs and not outstation_funcs and not summary.func_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("DNP3 Command Summary"))
        lines.append(muted("No DNP3 functions detected."))
    else:
        # Control/state-changing (HIGH), config/session (REVIEW), monitoring (normal).
        _high = {"Write", "Operate", "Direct Operate", "Direct Operate No Ack",
                 "Select", "Cold Restart", "Warm Restart", "Stop Application",
                 "Initialize Application", "Start Application", "Save Configuration",
                 "Delete File", "Write File", "Activate Configuration"}
        _review = {"Enable Unsolicited", "Disable Unsolicited", "Assign Class",
                   "Initialize Data", "Record Current Time", "Immediate Freeze",
                   "Freeze and Clear", "Authenticate", "Open File", "Get File Info"}

        def _risk_of(name: str) -> str:
            if name in _high or any(k in name for k in ("Restart", "Operate", "Write", "Stop")):
                return "CONTROL"
            if name in _review or "Unsolicited" in name or "File" in name:
                return "REVIEW"
            return "Normal"

        lines.append(SUBSECTION_BAR)
        lines.append(header("DNP3 Command Summary — Master Requests"))
        if master_funcs:
            rows = [["Function", "Count", "Class"]]
            for func, count in master_funcs.most_common(_limit_value(20)):
                risk = _risk_of(func)
                disp = danger(func) if risk == "CONTROL" else warn(func) if risk == "REVIEW" else func
                rows.append([disp, str(count), risk])
            lines.append(_format_table(rows))
        else:
            lines.append(muted("No master-issued requests observed."))

        lines.append(SUBSECTION_BAR)
        lines.append(header("DNP3 Command Summary — Outstation Responses"))
        if outstation_funcs:
            rows = [["Function", "Count", "Class"]]
            for func, count in outstation_funcs.most_common(_limit_value(10)):
                cls = "REVIEW" if "Unsolicited" in func else "Normal"
                disp = warn(func) if cls == "REVIEW" else func
                rows.append([disp, str(count), cls])
            lines.append(_format_table(rows))
        else:
            lines.append(muted("No outstation responses observed."))

        sel = int(getattr(summary, "select_count", 0))
        op = int(getattr(summary, "operate_count", 0))
        if sel or op:
            note = f"Select={sel}, Operate={op}"
            if sel and not op:
                note += "  [Select without Operate — incomplete SBO / control-point probing]"
            lines.append(muted(f"  Select-before-Operate: {note}"))

    # 2a. Control commands (with evidence) -- the load-bearing artifact.
    if control_cmds:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Control Commands (output actuation)"))
        rows = [["Time", "Master", "Outstation", "Out Addr", "Function"]]
        for cc in control_cmds[: _limit_value(12)]:
            rows.append(
                [
                    format_ts(cc.get("ts")),
                    f"{cc.get('src_ip')} (Addr {cc.get('src_addr')})",
                    str(cc.get("dst_ip")),
                    str(cc.get("dst_addr")),
                    str(cc.get("func")),
                ]
            )
        lines.append(_format_table(rows))

    # 2b. IIN flags (outstation state from responses).
    iin_flags = getattr(summary, "iin_flags", Counter()) or Counter()
    notable_iin = {
        k: v
        for k, v in iin_flags.items()
        if k in {
            "Device Restart", "Device Trouble", "Local Control", "Configuration corrupt",
            "Event buffer overflow", "Operation already executing",
            "Function code not supported", "Parameter error", "Object unknown",
        }
    }
    if notable_iin:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Outstation Internal Indications (IIN)"))
        for name, cnt in sorted(notable_iin.items(), key=lambda x: -x[1]):
            painter = danger if name in {"Device Restart", "Device Trouble", "Configuration corrupt"} else muted
            lines.append(painter(f"- {name} x{cnt}"))

    # 2b. Object Groups / Variations
    if getattr(summary, "object_group_counts", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Object Groups"))
        lines.append(
            _format_kv("Groups", _format_counter(summary.object_group_counts, 6))
        )
    if getattr(summary, "object_counts", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Object Variations"))
        lines.append(_format_kv("Objects", _format_counter(summary.object_counts, 6)))

    if getattr(summary, "value_changes", None):
        if summary.value_changes:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Value Changes (Preview)"))
            rows = [["Point", "Old", "New", "Src", "Dst", "TS"]]
            for item in summary.value_changes[: _limit_value(8)]:
                group = item.get("group")
                variation = item.get("variation")
                index = item.get("index")
                label = f"{group}.{variation}[{index}]"
                rows.append(
                    [
                        label,
                        str(item.get("old", "")),
                        str(item.get("new", "")),
                        str(item.get("src", "")),
                        str(item.get("dst", "")),
                        format_ts(item.get("ts")),
                    ]
                )
            lines.append(_format_table(rows))

    # 3. Addresses
    lines.append(SUBSECTION_BAR)
    lines.append(header("Top DNP3 Addresses (Data Link)"))
    if not summary.src_addrs:
        lines.append(muted("No DNP3 addresses found."))
    else:
        # Combine src and dst
        all_addrs = summary.src_addrs + summary.dst_addrs
        top_units = all_addrs.most_common(_limit_value(10))
        u_strs = [f"Addr {addr} ({cnt})" for addr, cnt in top_units]
        lines.append("  " + ", ".join(u_strs))

    # 4. Anomalies (severity-ranked, with ATT&CK-for-ICS + evidence)
    if summary.anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Threats (severity-ranked)"))

        sev_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_anoms = sorted(
            summary.anomalies, key=lambda x: sev_map.get(x.severity, 99)
        )
        attack_ids: list[str] = []
        for a in sorted_anoms:
            sev_color = danger if a.severity in ("CRITICAL", "HIGH") else warn
            if a.severity == "LOW":
                sev_color = muted

            lines.append(sev_color(f"[{a.severity}] {a.title}"))
            lines.append(f"  {a.description}")
            attack = str(getattr(a, "attack", "") or "")
            if attack:
                lines.append(muted(f"  ATT&CK ICS: {attack}"))
                for tid in attack.replace(";", ",").split(","):
                    tid = tid.strip()
                    if tid and tid not in attack_ids:
                        attack_ids.append(tid)
            evidence = str(getattr(a, "evidence", "") or "")
            if evidence:
                lines.append(muted(f"  Evidence: {evidence}"))
            elif a.src or a.dst:
                lines.append(muted(f"  Src: {a.src} -> Dst: {a.dst}"))
            lines.append("")

        if attack_ids:
            lines.append(SUBSECTION_BAR)
            lines.append(header("ATT&CK for ICS Mapping"))
            for tid in attack_ids[: _limit_value(12)]:
                lines.append(muted(f"- {tid}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_dnp3_rollup(summaries: Iterable["Dnp3Analysis"]) -> str:
    """
    Render DNP3 rollup results across multiple pcaps.
    """

    summary_list = list(summaries)
    if not summary_list:
        return ""

    total_pcaps = len(summary_list)
    total_duration = 0.0
    total_dnp3_packets = 0
    func_counts = Counter()
    src_addrs = Counter()
    dst_addrs = Counter()
    ip_endpoints = Counter()
    all_anomalies = []
    errors = Counter()

    for summary in summary_list:
        total_duration += summary.duration
        total_dnp3_packets += summary.dnp3_packets
        func_counts.update(summary.func_counts)
        src_addrs.update(summary.src_addrs)
        dst_addrs.update(summary.dst_addrs)
        ip_endpoints.update(summary.ip_endpoints)
        all_anomalies.extend(summary.anomalies)
        for err in summary.errors:
            errors[err] += 1

    lines = []
    lines.append(SECTION_BAR)
    lines.append(header(f"DNP3 ANALYSIS :: ALL PCAPS ({total_pcaps})"))
    lines.append(SECTION_BAR)

    if errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err, count in errors.most_common(_limit_value(10)):
            suffix = f" (x{count})" if count > 1 else ""
            lines.append(danger(f"- {err}{suffix}"))

    lines.append(_format_kv("PCAPs Analyzed", str(total_pcaps)))
    lines.append(_format_kv("Combined Duration", f"{total_duration:.2f}s"))
    lines.append(_format_kv("DNP3 Packets", str(total_dnp3_packets)))
    lines.append(_format_kv("Active TCP/UDP IPs", str(len(ip_endpoints))))
    unique_addrs = len(set(list(src_addrs.keys()) + list(dst_addrs.keys())))
    lines.append(_format_kv("DNP3 Addresses", str(unique_addrs)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Function Code Usage"))
    if not func_counts:
        lines.append(muted("No DNP3 functions detected."))
    else:
        for func, count in func_counts.most_common():
            is_risk = any(x in func for x in ["Write", "Restart", "File", "Freeze"])
            c = danger if is_risk else lambda x: x
            lines.append(c(f"{func:<40} : {count}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Top DNP3 Addresses (Data Link)"))
    if not src_addrs and not dst_addrs:
        lines.append(muted("No DNP3 addresses found."))
    else:
        all_addrs = src_addrs + dst_addrs
        top_units = all_addrs.most_common(_limit_value(10))
        u_strs = [f"Addr {addr} ({cnt})" for addr, cnt in top_units]
        lines.append("  " + ", ".join(u_strs))

    if all_anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Threats (Aggregated)"))
        lines.append(_format_kv("Total Anomalies", str(len(all_anomalies))))
        sev_counts = Counter(a.severity for a in all_anomalies)
        sev_rows = [["Severity", "Count"]]
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if sev_counts.get(severity):
                sev_rows.append([severity, str(sev_counts[severity])])
        if len(sev_rows) > 1:
            lines.append(_format_table(sev_rows))
        title_counts = Counter(a.title for a in all_anomalies)
        if title_counts:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Top Anomaly Types"))
            lines.append(_counter_table(title_counts, "Type", limit=_limit_value(10)))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
