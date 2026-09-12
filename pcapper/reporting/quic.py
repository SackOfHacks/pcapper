"""Rendered output for quic analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    header,
)
from ..quic import QuicSummary

from ._common import (
    _finalize_output,
    _format_counter,
    _format_kv,
)


def render_quic_summary(summary: QuicSummary) -> str:
    lines = [header("QUIC ANALYSIS")]
    lines.append(_format_kv("QUIC Packets", str(summary.quic_packets)))
    lines.append(_format_kv("Top Clients", _format_counter(summary.clients, 5)))
    lines.append(_format_kv("Top Servers", _format_counter(summary.servers, 5)))
    if summary.versions:
        lines.append(_format_kv("Versions", _format_counter(summary.versions, 5)))
    return _finalize_output(lines)
