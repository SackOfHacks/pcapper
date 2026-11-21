"""Rendered output for NTP analysis (time sources, modes, strata)."""

from __future__ import annotations

from ..ntp import NtpSummary
from ._kv import counter_line, simple_report


def render_ntp_summary(summary: NtpSummary) -> str:
    return simple_report(
        "NTP", summary, packets=summary.ntp_packets, unit="NTP packets",
        clients=summary.client_counts, servers=summary.server_counts,
        facts_title="Time sources",
        facts=[counter_line("Modes", summary.mode_counts), counter_line("Stratum", summary.stratum_counts),
               counter_line("Versions", summary.version_counts), counter_line("Clients", summary.client_counts),
               counter_line("Servers", summary.server_counts)],
        high="NTP abuse (amplification, rogue time source): investigate", medium="NTP activity to review",
    )
