"""Rendered output for VNC (RFB): sessions -- with reverse connections (the
desktop dialling a listening viewer, as backconnect malware does), the
UltraVNC repeater ID and how far each handshake got -- protocol versions and
the security types offered (None = no password). Client = viewer, server =
the desktop being controlled."""

from __future__ import annotations

from ..vnc import VncSummary
from . import _style as st
from ._remote import remote_report


def render_vnc_summary(summary: VncSummary, limit: int = 12, verbose: bool = False) -> str:
    if not summary:
        return ""
    return remote_report(
        "VNC", summary,
        packets=summary.vnc_packets,
        high="high-severity VNC activity: investigate",
        medium="VNC activity to review",
        ports=[("tcp", summary.server_ports)],
        sections=[
            ("Protocol", st.kv([
                ("Client RFB", st.top(summary.client_banners, 6)),
                ("Server RFB", st.top(summary.server_banners, 6)),
                ("Auth types", st.top(summary.auth_types, 6)),
            ]), False),
        ],
        files_default=False,  # names carved from encrypted payload are mostly noise
        session_cols=[
            ("Direction", lambda c: st.bad("reverse") if getattr(c, "reverse", False) else "-"),
            ("Handshake", lambda c: getattr(c, "handshake", "") or "-"),
            ("Repeater ID", lambda c: getattr(c, "repeater_id", "") or "-"),
            ("Client RFB", lambda c: c.client_banner or "-"),
            ("Server RFB", lambda c: c.server_banner or "-"),
        ],
    )
