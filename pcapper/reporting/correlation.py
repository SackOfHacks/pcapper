"""Rendered output for correlation analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    header,
    muted,
)

from ._common import (
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
)


def render_correlation_summary(
    summary, min_count: int = 2, verbose: bool = False
) -> str:
    if not summary:
        return ""
    lines = [header("CORRELATION (MULTI-PCAP)")]
    lines.append(_format_kv("PCAPs", str(summary.total_pcaps)))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors)))
    if summary.host_counts:
        lines.append(_format_kv("Hosts Seen", str(len(summary.host_counts))))
        rows = [["Host", "PCAPs"]]
        for ip, count in summary.host_counts.most_common(_limit_value(10)):
            if count < min_count:
                continue
            rows.append([ip, str(count)])
        if len(rows) > 1:
            lines.append(_format_table(rows))
    if summary.service_counts:
        rows = [["Service", "PCAPs"]]
        for svc, count in summary.service_counts.most_common(_limit_value(10)):
            if count < min_count:
                continue
            rows.append([svc, str(count)])
        if len(rows) > 1:
            lines.append(header("Repeated Services"))
            lines.append(_format_table(rows))
    if verbose:
        if summary.host_presence:
            lines.append(header("Host Presence"))
            for ip, pcaps in list(summary.host_presence.items())[: _limit_value(6)]:
                lines.append(muted(f"{ip}: {', '.join(pcaps)}"))
    return _finalize_output(lines)
