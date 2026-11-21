"""Rendered output for RDP: who connected where, the mstshash cookie (usually
the username), negotiated security and any decrypted identity."""

from __future__ import annotations

from ..rdp import RdpSummary
from . import _style as st
from ._remote import counts, remote_report


def render_rdp_summary(summary: RdpSummary, limit: int = 12, verbose: bool = False) -> str:
    if not summary:
        return ""
    cookies = counts(summary.client_names, "Cookie", width=60, noun="cookie")
    if cookies:
        cookies.append(st.dim("  the mstshash cookie usually carries the username typed in the client (truncated)"))
    dtls = getattr(summary, "dtls_handshakes", 0) or 0
    return remote_report(
        "RDP", summary,
        packets=summary.rdp_packets,
        high="high-severity RDP activity: investigate",
        medium="RDP activity to review",
        ports=[("tcp", summary.server_tcp_ports), ("udp", summary.server_udp_ports)],
        sections=[
            ("Cookies (mstshash)", cookies, False),
            ("Decrypted identity", st.kv([
                ("Users", st.top(getattr(summary, "decrypted_username", None), 6)),
                ("Domains", st.top(getattr(summary, "decrypted_domain", None), 6)),
                ("Client names", st.top(getattr(summary, "decrypted_client_name", None), 6)),
            ]), False),
            ("Negotiation", st.kv([
                ("Requested", st.top(getattr(summary, "requested_protocols", None), 6)),
                ("Selected", st.top(getattr(summary, "selected_protocols", None), 6)),
                ("Client builds", st.top(getattr(summary, "client_builds", None), 6)),
                ("Handshakes", st.join([f"TLS {summary.tls_handshakes}" if summary.tls_handshakes else "",
                                        f"DTLS {dtls}" if dtls else ""])),
            ]), False),
            ("Suspicious strings", counts(summary.suspicious_plaintext, "String", width=100), False),
        ],
        files_default=False,  # names carved from encrypted payload are mostly noise
        session_cols=[("Cookie", lambda c: c.client_name or "-"),
                      ("Transport", lambda c: "UDP" if c.udp_detected else ("TLS" if c.tls_detected else "TCP"))],
        plaintext_title="Plaintext (pre-encryption / decrypted)",
        traffic=[("TCP / UDP sessions", f"{summary.tcp_sessions} / {summary.udp_sessions}")],
    )
