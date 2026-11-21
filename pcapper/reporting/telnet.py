"""Rendered output for Telnet: cleartext logins, the commands typed and the
session transcript."""

from __future__ import annotations

from ..telnet import TelnetSummary
from . import _style as st
from ._common import _redact_secret
from ._remote import counts, remote_report


def render_telnet_summary(summary: TelnetSummary, limit: int = 12, verbose: bool = False) -> str:
    if not summary:
        return ""
    creds = [
        [f"{c.client_ip}:{c.client_port} -> {c.server_ip}:{c.server_port}", st.ts(c.first_seen),
         ", ".join(c.usernames) or "-", ", ".join(_redact_secret(p) for p in c.password_values) or "-"]
        for c in sorted(summary.conversations, key=lambda c: c.first_seen or 0.0)
        if c.usernames or c.password_values
    ]
    if creds:
        cred_lines = st.table(["Session", "Start", "Users", "Passwords"], creds, noun="session")
    else:
        cred_lines = st.kv([("Users", st.top(summary.usernames, 8)),
                            ("Passwords", st.top(summary.passwords, 8, fmt=lambda k, v: f"{_redact_secret(k)} ({v})"))])
    return remote_report(
        "Telnet", summary,
        packets=summary.telnet_packets,
        high="high-severity Telnet activity: investigate",
        medium="cleartext remote access: review the logins and commands",
        ports=[("tcp", summary.server_ports)],
        sections=[
            ("Credentials", cred_lines, False),
            ("Commands", counts(summary.commands, "Command", width=100, decode=True), False),
            ("Suspicious strings", counts(getattr(summary, "suspicious_plaintext", None), "String", width=100), False),
            ("Devices", counts(getattr(summary, "device_fingerprints", None), "Fingerprint", width=100), False),
        ],
        session_cols=[("Users", lambda c: ", ".join(c.usernames) or "-")],
        plaintext_title="Transcript",
        plaintext_default=True,
    )
