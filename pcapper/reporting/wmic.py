"""Rendered output for WMI/WMIC (DCOM): remote execution first -- the
commands, queries and classes used -- then sessions; encoded PowerShell
payloads are decoded in place."""

from __future__ import annotations

from ..wmic import WmicSummary
from . import _style as st
from ._remote import counts, labelled_commands, remote_report


def render_wmic_summary(summary: WmicSummary, limit: int = 12, verbose: bool = False) -> str:
    if not summary:
        return ""
    return remote_report(
        "WMI", summary,
        packets=summary.wmic_packets,
        high="remote execution over WMI: investigate",
        medium="WMI activity to review",
        ports=[("tcp", summary.server_ports)],
        sections=[
            ("Suspicious commands", labelled_commands(summary.suspicious_commands), False),
            ("Commands", counts(summary.wmic_commands, "Command", width=100, decode=True), False),
            ("Queries", counts(summary.wmi_queries, "Query", width=100), False),
            ("WMI", st.kv([
                ("Namespaces", st.top(summary.wmi_namespaces, 6)),
                ("Classes", st.top(summary.wmi_classes, 8)),
                ("Services", st.top(summary.services, 6)),
                ("Auth/RPC errors", st.top(summary.error_counts, 6)),
            ]), False),
            ("Accounts and hosts", st.kv([
                ("Users", st.top(summary.usernames, 8)),
                ("Domains", st.top(summary.domains, 8)),
                ("Hostnames", st.top(summary.hostnames, 8)),
                ("IPs in payload", st.top(summary.ip_strings, 8)),
                ("MACs in payload", st.top(summary.mac_strings, 6)),
            ]), False),
        ],
        session_cols=[("Hints", lambda c: ", ".join(c.hints) if c.hints else "-")],
        deterministic=("Deterministic WMI/WMIC Security Checks", [
            ("wmic_remote_execution_tradecraft", "Remote-Execution Tradecraft"),
            ("wmic_namespace_persistence_context", "Namespace/Persistence Context"),
            ("wmic_auth_failure_burst", "Auth Failure Burst"),
            ("wmic_node_fanout", "Source Node Fan-out"),
            ("wmic_target_fanout", "Target Fan-out"),
            ("wmic_periodic_activity", "Periodic Activity"),
            ("wmic_data_exfil_asymmetry", "Data-Exfil Asymmetry"),
            ("wmic_public_endpoint_exposure", "Public Endpoint Exposure"),
        ]),
    )
