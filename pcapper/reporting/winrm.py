"""Rendered output for WinRM (WS-Management over HTTP/S): sessions, the auth
scheme (Basic = cleartext credentials) and the SOAP actions invoked."""

from __future__ import annotations

from ..winrm import WinrmSummary
from . import _style as st
from ._remote import counts, remote_report


def render_winrm_summary(summary: WinrmSummary, limit: int = 12, verbose: bool = False) -> str:
    if not summary:
        return ""

    def _transport(c: object) -> str:
        kinds = [k for k, on in (("http", getattr(c, "http_detected", False)), ("https", getattr(c, "https_detected", False))) if on]
        return "+".join(kinds) or "-"

    return remote_report(
        "WinRM", summary,
        packets=summary.winrm_packets,
        high="high-severity WinRM activity: investigate",
        medium="remote management activity to review",
        ports=[("tcp", summary.server_ports)],
        sections=[
            ("HTTP", st.kv([
                ("Auth schemes", st.top(summary.auth_schemes, 6)),
                ("Hosts", st.top(summary.http_hosts, 6)),
                ("User agents", st.top(summary.user_agents, 4)),
            ]), False),
            ("SOAP actions", counts(summary.soap_actions, "Action", width=100), False),
        ],
        session_cols=[("Transport", _transport)],
        traffic=[("HTTP / HTTPS sessions", f"{summary.http_sessions} / {summary.https_sessions}")],
        deterministic=("Deterministic WinRM Security Checks", [
            ("winrm_command_exec_telemetry", "Command-Execution Telemetry"),
            ("winrm_weak_auth_scheme", "Weak Auth Scheme"),
            ("winrm_plaintext_exposure", "Plaintext Exposure"),
            ("winrm_scanning_or_bruteforce", "Scanning/Bruteforce"),
            ("winrm_periodic_beaconing", "Periodic Beaconing"),
            ("winrm_data_staging_asymmetry", "Data-Staging Asymmetry"),
            ("winrm_nonstandard_port_usage", "Non-Standard Port Usage"),
            ("winrm_public_endpoint_exposure", "Public Endpoint Exposure"),
        ]),
    )
