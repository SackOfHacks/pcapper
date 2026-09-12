"""Rendered output for sizes analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    danger,
    header,
    muted,
    ok,
    warn,
)
from ..sizes import SizeSummary, render_size_sparkline
from ..utils import (
    format_bytes_as_mb,
    format_duration,
    format_ts,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _apply_verbose_limit,
    _filtered_detections,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
    _redact_in_text,
    _render_protocol_verdict,
)


def render_sizes_summary(
    summary: SizeSummary, limit: int = 12, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit)
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"PACKET SIZE ANALYSIS :: {summary.path.name}"))
    _render_protocol_verdict(
        lines,
        label="Packet Sizes",
        detections=getattr(summary, "detections", None),
        anomalies=getattr(summary, "anomalies", None),
    )
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))

    if summary.buckets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Packet Size Distribution"))
        rows = [
            [
                "Bucket",
                "Count",
                "Avg",
                "Min",
                "Max",
                "Rate(pkt/s)",
                "%",
                "Burst Rate",
                "Burst Start",
            ]
        ]
        for bucket in summary.buckets:
            rows.append(
                [
                    bucket.label,
                    str(bucket.count),
                    f"{bucket.avg:.1f}",
                    str(bucket.min),
                    str(bucket.max),
                    f"{bucket.rate:.2f}",
                    f"{bucket.pct:.1f}%",
                    f"{bucket.burst_rate:.0f}",
                    format_ts(bucket.burst_start) if bucket.burst_start else "-",
                ]
            )
        lines.append(_format_table(rows))
        lines.append("")
        lines.append(
            muted(f"Distribution Sparkline: {render_size_sparkline(summary.buckets)}")
        )

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
            severity = item.get("severity", "info")
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity == "critical":
                marker = danger("[CRIT]")
            elif severity == "high":
                marker = danger("[HIGH]")
            elif severity == "warning":
                marker = warn("[WARN]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))
            evidence_items = item.get("evidence", [])
            if isinstance(evidence_items, list):
                for evidence in evidence_items[: _limit_value(8)]:
                    lines.append(muted(f"    - {_redact_in_text(str(evidence))}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
