"""Rendered output for wlan analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    header,
    muted,
    warn,
)
from ..wlan import WlanSummary

from ._common import (
    _finalize_output,
    _format_counter,
    _format_kv,
    _limit_value,
    _render_protocol_verdict,
)


def render_wlan_summary(summary: WlanSummary) -> str:
    lines = [header("WLAN ANALYSIS")]
    _render_protocol_verdict(
        lines,
        label="WLAN",
        detections=getattr(summary, "detections", None),
        anomalies=getattr(summary, "anomalies", None),
    )
    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("WLAN Packets", str(summary.wlan_packets)))
    lines.append(
        _format_kv(
            "Mgmt/Data/Ctrl",
            f"{summary.mgmt_packets}/{summary.data_packets}/{summary.control_packets}",
        )
    )
    lines.append(_format_kv("Protected Data", str(summary.protected_data_packets)))
    lines.append(_format_kv("Open Data", str(summary.open_data_packets)))
    lines.append(_format_kv("EAPOL", str(summary.eapol_packets)))
    lines.append(_format_kv("Networks", str(summary.unique_networks)))
    lines.append(_format_kv("Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Security", _format_counter(summary.security_counts, 6)))
    lines.append(_format_kv("PHY", _format_counter(summary.phy_counts, 6)))
    lines.append(_format_kv("Top SSIDs", _format_counter(summary.ssid_counts, 8)))
    lines.append(_format_kv("Channels", _format_counter(summary.channel_counts, 8)))
    if summary.detections:
        lines.append(header("Detections"))
        for item in summary.detections[: _limit_value(8)]:
            sev = str(item.get("severity", "info")).upper()
            title = str(item.get("title") or item.get("summary") or "Detection")
            details = str(item.get("details", ""))
            lines.append(warn(f"[{sev}] {title}"))
            if details:
                lines.append(muted(f"  {details}"))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors[: _limit_value(4)])))
    return _finalize_output(lines)
