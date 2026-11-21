"""Rendered output for HTTP/2 (cleartext h2c and TLS sessions negotiating
h2 through ALPN)."""

from __future__ import annotations

from ..http2 import Http2Summary
from ._kv import counter_line, simple_report


def render_http2_summary(summary: Http2Summary) -> str:
    alpn = int(getattr(summary, "alpn_h2_sessions", 0) or 0)
    return simple_report(
        "HTTP/2", summary, packets=summary.http2_packets + alpn, unit="HTTP/2 packets and ALPN h2 sessions",
        clients=summary.client_counts, servers=summary.server_counts,
        facts=[("HTTP/2 packets", str(summary.http2_packets)),
               ("TLS ALPN h2 sessions", str(alpn) if alpn else ""),
               counter_line("ALPN h2 clients", getattr(summary, "alpn_h2_clients", None)),
               counter_line("Clients", summary.client_counts), counter_line("Servers", summary.server_counts)],
        absent="HTTP/2 traffic",
    )
