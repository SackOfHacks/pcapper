"""Rendered output for packet-size analysis: the size distribution and the
bursts within it (tunneling, exfiltration and scans have distinct shapes)."""

from __future__ import annotations

from ..sizes import SizeSummary, render_size_sparkline
from ..utils import format_bytes_as_mb, format_duration
from . import _style as st
from ._kv import findings_for


def render_sizes_summary(summary: SizeSummary, limit: int = 12, verbose: bool = False) -> str:
    rep = st.Report("Packet sizes", summary.path)
    findings = findings_for(summary, ot=False)
    if not summary.total_packets and not st.material(findings):
        return rep.absent("packets", summary.errors)
    severity, text = st.verdict(findings, high="size patterns of tunneling or exfiltration: investigate the bursts",
                                medium="size anomalies to review")
    rep.headline(severity, text, st.join([
        f"{st.count(summary.total_packets)} packets", st.size(summary.total_bytes),
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
        st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else "",
    ]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))
    buckets = list(summary.buckets or [])
    rep.section("Distribution", st.table(
        ["Bucket", "Packets", "Share", "Avg", "Min", "Max", "Rate pkt/s", "Burst rate", "Burst start"],
        [[b.label, st.count(b.count), f"{b.pct:.1f}%", f"{b.avg:.1f}", b.min, b.max, f"{b.rate:.2f}",
          f"{b.burst_rate:.0f}", st.ts(b.burst_start) if b.burst_start else "-"] for b in buckets],
        align="lrrrrrrrl", max_rows=None,
    ) + ([f"  {st.dim('shape')} {render_size_sparkline(buckets)}"] if buckets else []))
    rep.section("Capture", st.kv([
        ("Total packets", str(summary.total_packets)), ("Total bytes", format_bytes_as_mb(summary.total_bytes)),
        ("Start / end", f"{st.ts(summary.first_seen)} / {st.ts(summary.last_seen)}"),
        ("Duration", format_duration(summary.duration_seconds)),
    ]), detail=True)
    return rep.render()
