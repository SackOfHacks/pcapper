"""Rendered output for ntp analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    header,
)
from ..ntp import NtpSummary

from ._common import (
    _finalize_output,
    _format_counter,
    _format_kv,
)


def render_ntp_summary(summary: NtpSummary) -> str:
    lines = [header("NTP ANALYSIS")]
    lines.append(_format_kv("NTP Packets", str(summary.ntp_packets)))
    lines.append(_format_kv("Modes", _format_counter(summary.mode_counts, 5)))
    lines.append(_format_kv("Versions", _format_counter(summary.version_counts, 5)))
    lines.append(_format_kv("Stratum", _format_counter(summary.stratum_counts, 5)))
    lines.append(_format_kv("Top Clients", _format_counter(summary.client_counts, 5)))
    lines.append(_format_kv("Top Servers", _format_counter(summary.server_counts, 5)))
    return _finalize_output(lines)
