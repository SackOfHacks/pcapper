"""Rendered output for LLDP and PROFINET DCP (layer-2 discovery): which
devices announced themselves, and who enumerated or renamed them."""

from __future__ import annotations

from collections import Counter

from ..lldp_dcp import LldpDcpSummary
from . import _style as st
from ._kv import counter_line, findings_for, window


def render_lldp_dcp_summary(summary: LldpDcpSummary, verbose: bool = False) -> str:
    rep = st.Report("LLDP/DCP", summary.path)
    findings = findings_for(summary)
    if not summary.lldp_packets and not summary.dcp_packets and not st.material(findings):
        return rep.absent("LLDP or PROFINET DCP traffic", summary.errors)
    severity, text = st.verdict(
        findings,
        high="high-severity discovery activity (e.g. DCP Set): confirm the change is authorized",
        medium="discovery activity to review",
    )
    rep.headline(severity, text, st.join([
        f"{st.count(summary.lldp_packets)} LLDP",
        f"{st.count(summary.dcp_packets)} DCP packets",
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
        window(summary),
    ]))
    rep.scope(st.join([
        st.plural(len(summary.system_names or {}), "LLDP system") if summary.system_names else "",
        st.plural(len(summary.dcp_device_names or {}), "DCP device name") if summary.dcp_device_names else "",
    ]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))
    fingerprints = Counter(
        str(getattr(a, "detail", "")) for a in (summary.artifacts or []) if str(getattr(a, "kind", "")) == "device"
    )
    rep.section("Devices", st.kv([
        counter_line("LLDP system names", summary.system_names),
        counter_line("DCP device names", summary.dcp_device_names),
        counter_line("DCP IPs", summary.dcp_ips),
        ("Fingerprints", st.top(fingerprints, 5, lambda k, v: f"{st.cut(k, 60)} ({st.count(v)})") if fingerprints else ""),
    ]))
    rep.section("DCP", st.kv([counter_line("Services", summary.dcp_services)]))
    other = [a for a in (summary.artifacts or []) if str(getattr(a, "kind", "")) != "device"]
    rep.section("Identifiers", st.kv([
        counter_line("Chassis IDs", summary.chassis_ids),
        counter_line("Port IDs", summary.port_ids),
        counter_line("DCP frame IDs", summary.dcp_frame_ids),
        ("Total packets", st.count(summary.total_packets)),
    ]), detail=True)
    rep.section("Artifacts", st.table(
        ["Kind", "Detail", "Flow"],
        [[a.kind, a.detail, st.flow(a.src, a.dst)] for a in other],
        max_rows=None,
    ), detail=True)
    return rep.render()
