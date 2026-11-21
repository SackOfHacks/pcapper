"""Rendered output for QoS marking analysis (DSCP/ECN, VLAN PCP, WMM)."""

from __future__ import annotations

from ..qos import QosSummary
from ._kv import counter_line, simple_report


def render_qos_summary(summary: QosSummary, verbose: bool = False) -> str:
    return simple_report(
        "QoS", summary, packets=summary.qos_packets, unit="QoS-marked packets",
        facts_title="Markings",
        facts=[("Marked packets", f"{summary.qos_packets} of {summary.total_packets} "
                                  f"({summary.ip_qos_packets} IP, {summary.wireless_qos_packets} wireless)"),
               ("High priority", str(summary.high_priority_packets)),
               counter_line("DSCP", summary.dscp_counts, 8), counter_line("ECN", summary.ecn_counts, 4),
               counter_line("VLAN PCP", summary.vlan_pcp_counts, 6), counter_line("WMM TID", summary.wmm_tid_counts, 8),
               counter_line("Sources", summary.src_counts, 6), counter_line("Destinations", summary.dst_counts, 6)],
        details=[("IP packets", str(summary.total_ip_packets)),
                 ("Wireless QoS open / protected", f"{summary.wireless_qos_open_packets} / {summary.wireless_qos_protected_packets}"),
                 counter_line("Services", summary.service_counts, None),
                 counter_line("WLAN TID direction", summary.wlan_tid_direction_counts, None),
                 counter_line("WLAN sources", summary.wlan_src_counts, None),
                 counter_line("WLAN destinations", summary.wlan_dst_counts, None),
                 ("Flows", "; ".join(str(r) for r in (summary.flow_rows or []))),
                 ("WLAN flows", "; ".join(str(r) for r in (summary.wlan_flow_rows or []))),
                 ("Plaintext hits", "; ".join(str(r) for r in (summary.plaintext_hits or [])))],
        high="QoS abuse (priority flooding, covert marking): investigate", medium="QoS markings to review",
        absent="QoS-marked traffic",
    )
