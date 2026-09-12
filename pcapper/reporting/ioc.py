"""Rendered output for ioc analysis.

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
from ..ioc import IocSummary

from ._common import (
    SUBSECTION_BAR,
    _finalize_output,
    _format_counter,
    _format_kv,
    _limit_value,
    _truncate_text,
)


def render_ioc_summary(summary: IocSummary) -> str:
    lines = [header("IOC ANALYSIS")]

    # The match detections (severity-tagged IP/domain/hash hits) are the whole
    # point of this analyzer — render them with an Analyst Verdict instead of
    # dropping them and showing only raw hit counters.
    detections = list(getattr(summary, "detections", []) or [])
    if detections:
        sev_rank = {"critical": 3, "high": 2, "warning": 1, "medium": 1, "info": 0}
        worst = max(sev_rank.get(str(d.get("severity", "info")).lower(), 0) for d in detections)
        lines.append(SUBSECTION_BAR)
        lines.append(header("Analyst Verdict"))
        if worst >= 3:
            lines.append(danger("CRITICAL - known-malicious indicator (hash) observed in capture."))
        elif worst >= 2:
            lines.append(danger("HIGH - traffic matched a known-bad IP/domain/hash IOC."))
        else:
            lines.append(warn("Indicator matches present — review below."))
        lines.append(SUBSECTION_BAR)
        lines.append(header("IOC Matches"))
        for det in sorted(
            detections,
            key=lambda d: sev_rank.get(str(d.get("severity", "info")).lower(), 0),
            reverse=True,
        )[: _limit_value(15)]:
            sev = str(det.get("severity", "info")).upper()
            marker = danger(f"[{sev}]") if worst >= 2 else warn(f"[{sev}]")
            lines.append(f"{marker} {det.get('summary', '-')}")
            details = str(det.get("details", "") or "")
            if details:
                lines.append(muted(f"  {_truncate_text(details, 220)}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Indicator Hit Counts"))
    lines.append(_format_kv("IP Hits", _format_counter(summary.ip_hits, 6)))
    lines.append(_format_kv("Domain Hits", _format_counter(summary.domain_hits, 6)))
    lines.append(_format_kv("Hash Hits", _format_counter(summary.hash_hits, 6)))
    if getattr(summary, "source_counts", None):
        if summary.source_counts:
            lines.append(
                _format_kv("Sources", _format_counter(summary.source_counts, 6))
            )
    if getattr(summary, "tag_counts", None):
        if summary.tag_counts:
            lines.append(_format_kv("Tags", _format_counter(summary.tag_counts, 6)))
    if getattr(summary, "mitre_counts", None):
        if summary.mitre_counts:
            lines.append(_format_kv("MITRE", _format_counter(summary.mitre_counts, 6)))
    if getattr(summary, "avg_confidence", None) is not None:
        lines.append(_format_kv("Avg Confidence", f"{summary.avg_confidence:.1f}"))
    return _finalize_output(lines)
