"""Rendered output for TeamViewer: sessions (TCP and UDP) and the protocol
hints that identified them."""

from __future__ import annotations

from ..teamviewer import TeamviewerSummary
from ._remote import counts, remote_report, yes_no


def render_teamviewer_summary(summary: TeamviewerSummary, limit: int = 12, verbose: bool = False) -> str:
    if not summary:
        return ""
    return remote_report(
        "TeamViewer", summary,
        packets=summary.tv_packets,
        high="high-severity TeamViewer activity: investigate",
        medium="remote-control activity to review",
        ports=[("tcp", summary.server_tcp_ports), ("udp", summary.server_udp_ports)],
        sections=[("Hints", counts(summary.hints, "Hint"), False)],
        files_default=False,  # names carved from encrypted payload are mostly noise
        session_cols=[("UDP", lambda c: yes_no(c.udp_detected)), ("Hints", lambda c: ", ".join(c.hints) if c.hints else "-")],
        traffic=[("TCP / UDP sessions", f"{summary.tcp_sessions} / {summary.udp_sessions}")],
    )
