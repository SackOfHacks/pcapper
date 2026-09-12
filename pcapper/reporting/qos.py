"""Rendered output for qos analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    header,
    muted,
    warn,
)
from ..qos import QosSummary

from ._common import (
    _filtered_detections,
    _finalize_output,
    _format_counter,
    _format_kv,
    _limit_value,
    _render_protocol_verdict,
)


def render_qos_summary(summary: QosSummary, verbose: bool = False) -> str:
    lines = [header("QOS ANALYSIS")]
    _render_protocol_verdict(
        lines,
        label="QoS",
        detections=getattr(summary, "detections", None),
        anomalies=getattr(summary, "anomalies", None),
    )
    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("IP Packets", str(summary.total_ip_packets)))
    lines.append(_format_kv("QoS Packets", str(summary.qos_packets)))
    lines.append(_format_kv("IP QoS", str(summary.ip_qos_packets)))
    lines.append(_format_kv("Wireless QoS", str(summary.wireless_qos_packets)))
    lines.append(_format_kv("High Priority", str(summary.high_priority_packets)))
    lines.append(_format_kv("DSCP", _format_counter(summary.dscp_counts, 8)))
    lines.append(_format_kv("ECN", _format_counter(summary.ecn_counts, 4)))
    lines.append(_format_kv("VLAN PCP", _format_counter(summary.vlan_pcp_counts, 6)))
    lines.append(_format_kv("WMM TID", _format_counter(summary.wmm_tid_counts, 8)))
    lines.append(_format_kv("Top Sources", _format_counter(summary.src_counts, 6)))
    lines.append(_format_kv("Top Destinations", _format_counter(summary.dst_counts, 6)))
    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(header("Detections"))
        for item in detections[: _limit_value(8)]:
            sev = str(item.get("severity", "info")).upper()
            title = str(item.get("title") or item.get("summary") or "Detection")
            details = str(item.get("details", ""))
            lines.append(warn(f"[{sev}] {title}"))
            if details:
                lines.append(muted(f"  {details}"))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors[: _limit_value(4)])))
    return _finalize_output(lines)
