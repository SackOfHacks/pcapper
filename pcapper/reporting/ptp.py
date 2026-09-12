"""Rendered output for ptp analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    danger,
    header,
    muted,
    warn,
)
from ..ptp import PtpSummary

from ._common import (
    _filtered_detections,
    _finalize_output,
    _format_counter,
    _format_kv,
    _limit_value,
    _render_protocol_verdict,
)


def render_ptp_summary(summary: PtpSummary, verbose: bool = False) -> str:
    lines = [header("PTP ANALYSIS")]
    _render_protocol_verdict(
        lines,
        label="PTP",
        detections=getattr(summary, "detections", None),
        anomalies=getattr(summary, "anomalies", None),
    )
    lines.append(_format_kv("PTP Packets", str(summary.ptp_packets)))
    # PTP message types are the "commands" (Sync / Follow_Up / Delay_Req /
    # Announce / Signaling / Management) — a Management SET is state-changing.
    lines.append(_format_kv("Message Types", _format_counter(summary.msg_types, 6)))
    if getattr(summary, "domain_numbers", None):
        lines.append(_format_kv("Domains", _format_counter(summary.domain_numbers, 6)))
    lines.append(
        _format_kv(
            "Top Sources (masters/clocks)",
            _format_counter(summary.src_macs or summary.src_ips, 5),
        )
    )
    _ptp_dst = getattr(summary, "dst_macs", None) or getattr(summary, "dst_ips", None)
    if _ptp_dst:
        lines.append(_format_kv("Top Destinations", _format_counter(_ptp_dst, 5)))
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
