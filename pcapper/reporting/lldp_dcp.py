"""Rendered output for lldp_dcp analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from collections import Counter
from ..coloring import (
    danger,
    header,
    muted,
    warn,
)
from ..lldp_dcp import LldpDcpSummary

from ._common import (
    _filtered_detections,
    _finalize_output,
    _format_counter,
    _format_kv,
    _limit_value,
    _render_protocol_verdict,
    _truncate_text,
)


def render_lldp_dcp_summary(summary: LldpDcpSummary, verbose: bool = False) -> str:
    lines = [header("LLDP/DCP ANALYSIS")]
    _render_protocol_verdict(
        lines,
        label="LLDP/DCP",
        detections=getattr(summary, "detections", None),
        anomalies=getattr(summary, "anomalies", None),
    )
    lines.append(_format_kv("LLDP Packets", str(summary.lldp_packets)))
    lines.append(_format_kv("DCP Packets", str(summary.dcp_packets)))
    lines.append(_format_kv("System Names", _format_counter(summary.system_names, 5)))
    lines.append(_format_kv("Chassis IDs", _format_counter(summary.chassis_ids, 5)))
    lines.append(_format_kv("Port IDs", _format_counter(summary.port_ids, 5)))
    lines.append(_format_kv("DCP Frame IDs", _format_counter(summary.dcp_frame_ids, 5)))
    if getattr(summary, "dcp_services", None):
        lines.append(
            _format_kv("DCP Services", _format_counter(summary.dcp_services, 5))
        )
    if getattr(summary, "dcp_device_names", None):
        lines.append(
            _format_kv("DCP Device Names", _format_counter(summary.dcp_device_names, 5))
        )
    if getattr(summary, "dcp_ips", None):
        lines.append(_format_kv("DCP IPs", _format_counter(summary.dcp_ips, 5)))
    if getattr(summary, "artifacts", None):
        device_counts = Counter(
            str(getattr(item, "detail", ""))
            for item in summary.artifacts
            if str(getattr(item, "kind", "")) == "device"
        )
        if device_counts:
            preview = ", ".join(
                f"{_truncate_text(detail, 60)}({count})"
                for detail, count in device_counts.most_common(5)
            )
            lines.append(_format_kv("Device Fingerprints", preview))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors)))
    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(header("Detections"))
        for item in detections[: _limit_value(6)]:
            sev = str(item.get("severity", "info")).upper()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            sev_color = danger if sev in {"CRITICAL", "HIGH"} else warn
            if sev in {"INFO", "LOW"}:
                sev_color = muted
            lines.append(sev_color(f"[{sev}] {summary_text}"))
            if details:
                lines.append(muted(f"  {details}"))
    return _finalize_output(lines)
