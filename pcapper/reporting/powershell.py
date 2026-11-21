"""Rendered output for PowerShell remoting and PowerShell content on the
wire: suspicious indicators and commands (encoded ones decoded), URLs, AD and
network discovery, then sessions."""

from __future__ import annotations

from ..powershell import PowershellSummary
from . import _style as st
from ._remote import counts, labelled_commands, remote_report


def render_powershell_summary(summary: PowershellSummary, limit: int = 12, verbose: bool = False) -> str:
    if not summary:
        return ""
    return remote_report(
        "PowerShell", summary,
        packets=summary.powershell_packets,
        high="high-severity PowerShell activity: investigate",
        medium="PowerShell activity to review",
        ports=[("tcp", summary.server_ports)],
        sections=[
            ("Suspicious indicators", labelled_commands(summary.suspicious_indicators, label_text="Indicator"), False),
            ("Commands", counts(summary.commands, "Command", width=100, decode=True), False),
            ("URLs", counts(summary.urls, "URL", width=100, noun="URL"), False),
            ("AD queries", counts(summary.ad_queries, "Cmdlet"), False),
            ("Network discovery", counts(summary.network_discovery, "Cmdlet"), False),
            ("Accounts and hosts", st.kv([
                ("Users", st.top(summary.usernames, 8)),
                ("Domains", st.top(summary.domains, 8)),
                ("Hostnames", st.top(summary.hostnames, 8)),
                ("IPs in payload", st.top(summary.ip_strings, 8)),
                ("MACs in payload", st.top(summary.mac_strings, 6)),
            ]), False),
        ],
        session_cols=[("Hints", lambda c: ", ".join(c.hints) if c.hints else "-")],
    )
