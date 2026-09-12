"""Rendered output for goose analysis.

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
from ..goose import GooseSummary

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
def render_goose_summary(summary: GooseSummary, verbose: bool = False) -> str:
    lines = [header("GOOSE ANALYSIS")]
    _render_ot_verdict(lines, "GOOSE (IEC 61850)", getattr(summary, "detections", []))
    lines.append(_format_kv("GOOSE Packets", str(summary.goose_packets)))
    # GOOSE is Layer-2 publisher -> multicast group (publish/subscribe), so the
    # source MAC IS the publisher direction; there is no request/response.
    lines.append(_format_kv("Top Publishers (src MAC)", _format_counter(summary.src_macs, 5)))
    lines.append(_format_kv("Top Subscriber Groups (dst MAC)", _format_counter(summary.dst_macs, 5)))
    lines.append(_format_kv("APPIDs", _format_counter(summary.app_ids, 5)))
    if getattr(summary, "datasets", None):
        lines.append(_format_kv("Datasets", _format_counter(summary.datasets, 5)))
    if getattr(summary, "gocb_refs", None):
        lines.append(_format_kv("GOCB Refs", _format_counter(summary.gocb_refs, 5)))
    if getattr(summary, "st_nums", None):
        lines.append(_format_kv("stNum", _format_counter(summary.st_nums, 5)))
    if getattr(summary, "sq_nums", None):
        lines.append(_format_kv("sqNum", _format_counter(summary.sq_nums, 5)))
    if getattr(summary, "conf_revs", None):
        lines.append(_format_kv("confRev", _format_counter(summary.conf_revs, 5)))
    if getattr(summary, "num_entries", None):
        lines.append(
            _format_kv("numDatSetEntries", _format_counter(summary.num_entries, 5))
        )
    if getattr(summary, "all_data_lengths", None):
        lines.append(
            _format_kv("allData Len", _format_counter(summary.all_data_lengths, 5))
        )
    if getattr(summary, "data_type_counts", None):
        lines.append(
            _format_kv("Data Types", _format_counter(summary.data_type_counts, 6))
        )
    if getattr(summary, "data_value_samples", None):
        samples = ", ".join(
            f"{_truncate_text(name, 40)}({count})"
            for name, count in summary.data_value_samples.most_common(5)
        )
        if samples:
            lines.append(_format_kv("Sample Values", samples))
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
