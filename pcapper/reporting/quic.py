"""Rendered output for QUIC analysis."""

from __future__ import annotations

from ..quic import QuicSummary
from ._kv import counter_line, simple_report


def render_quic_summary(summary: QuicSummary) -> str:
    return simple_report(
        "QUIC", summary, packets=summary.quic_packets, unit="QUIC packets",
        clients=summary.clients, servers=summary.servers,
        facts=[counter_line("Versions", summary.versions), counter_line("Clients", summary.clients),
               counter_line("Servers", summary.servers)],
        details=[counter_line("Flows", getattr(summary, "flow_counts", None), None)],
        medium="QUIC activity to review",
    )
