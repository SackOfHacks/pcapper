"""Rendered output for safety analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    header,
)
from ..utils import format_ts

from ._common import (
    _finalize_output,
    _format_counter,
    _format_kv,
    _format_table,
    _limit_value,
)


def render_safety_summary(summary) -> str:
    if not summary:
        return ""
    lines = [header("SAFETY SYSTEMS")]
    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("Hits", str(len(summary.hits))))
    if summary.service_counts:
        lines.append(_format_kv("Services", _format_counter(summary.service_counts, 6)))
    if summary.source_counts:
        lines.append(
            _format_kv("Top Sources", _format_counter(summary.source_counts, 6))
        )
    if summary.destination_counts:
        lines.append(
            _format_kv(
                "Top Destinations", _format_counter(summary.destination_counts, 6)
            )
        )
    frames = int(getattr(summary, "tristation_frames", 0) or 0)
    if frames:
        lines.append(header("TriStation (Triconex)"))
        lines.append(_format_kv("Frames", str(frames)))
        lines.append(_format_kv("TCM Messages", _format_counter(summary.tristation_tcm, 6)))
        lines.append(_format_kv("Requests", _format_counter(summary.tristation_requests, _limit_value(12), 50)))
        lines.append(_format_kv("Replies", _format_counter(summary.tristation_replies, _limit_value(8), 50)))
        if summary.tristation_rejects:
            lines.append(_format_kv("Rejected", _format_counter(summary.tristation_rejects, 6, 50)))
        if summary.key_states:
            lines.append(_format_kv("Key Switch", _format_counter(summary.key_states, 4)))
        if summary.run_states:
            lines.append(_format_kv("Program State", _format_counter(summary.run_states, 4)))
        if summary.projects:
            lines.append(_format_kv("Project", _format_counter(summary.projects, 4)))
        timeline = list(summary.tristation_timeline or [])
        if timeline:
            rows = [["Time", "Workstation -> Controller", "Function"]]
            previous = None
            for ts, src, dst, name in timeline:
                if (src, dst, name) == previous:
                    continue  # collapse runs of the same command
                previous = (src, dst, name)
                rows.append([format_ts(ts), f"{src} -> {dst}", name])
                if len(rows) > _limit_value(25):
                    break
            lines.append(header("State-changing / logic commands (consecutive repeats collapsed)"))
            lines.append(_format_table(rows))
    for item in getattr(summary, "detections", []) or []:
        if item.get("summary") == "Safety PLC/SIS protocol traffic observed":
            continue
        sev = str(item.get("severity", "info")).upper()
        if sev in {"INFO"}:
            continue
        lines.append(f"[{sev}] {item.get('summary', '')}")
        lines.append(f"  {item.get('details', '')}")
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors)))
    if summary.hits:
        rows = [["Proto", "Service", "Src", "Dst"]]
        for hit in summary.hits[: _limit_value(10)]:
            rows.append(
                [
                    hit.protocol,
                    hit.service,
                    f"{hit.src}:{hit.src_port}",
                    f"{hit.dst}:{hit.dst_port}",
                ]
            )
        lines.append(_format_table(rows))
    return _finalize_output(lines)
