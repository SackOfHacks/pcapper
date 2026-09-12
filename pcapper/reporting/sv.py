"""Rendered output for sv analysis.

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
from ..sv import SvSummary

from ._common import (
    _filtered_detections,
    _finalize_output,
    _format_counter,
    _format_kv,
    _limit_value,
    _ot_full_render,
    _render_ot_verdict,
    _truncate_text,
)


@_ot_full_render
def render_sv_summary(summary: SvSummary, verbose: bool = False) -> str:
    lines = [header("SV ANALYSIS")]
    _render_ot_verdict(lines, "Sampled Values (IEC 61850)", getattr(summary, "detections", []))
    lines.append(_format_kv("SV Packets", str(summary.sv_packets)))
    # Sampled Values is Layer-2 publisher -> multicast (merging unit -> subscribers);
    # source MAC is the publisher, no request/response.
    lines.append(_format_kv("Top Publishers (src MAC)", _format_counter(summary.src_macs, 5)))
    lines.append(_format_kv("Top Subscriber Groups (dst MAC)", _format_counter(summary.dst_macs, 5)))
    lines.append(_format_kv("APPIDs", _format_counter(summary.app_ids, 5)))
    if getattr(summary, "sv_ids", None):
        lines.append(_format_kv("svID", _format_counter(summary.sv_ids, 5)))
    if getattr(summary, "conf_revs", None):
        lines.append(_format_kv("ConfRev", _format_counter(summary.conf_revs, 5)))
    if getattr(summary, "seq_data_lengths", None):
        lines.append(
            _format_kv("SeqOfData Len", _format_counter(summary.seq_data_lengths, 5))
        )
    if getattr(summary, "data_type_counts", None):
        lines.append(
            _format_kv("SeqOfData Types", _format_counter(summary.data_type_counts, 5))
        )
    if getattr(summary, "data_value_samples", None):
        samples = ", ".join(
            f"{_truncate_text(name, 40)}({count})"
            for name, count in summary.data_value_samples.most_common(5)
        )
        if samples:
            lines.append(_format_kv("Sample Values", samples))
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
