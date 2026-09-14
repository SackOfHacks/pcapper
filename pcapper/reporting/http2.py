"""Rendered output for http2 analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    header,
)
from ..http2 import Http2Summary

from ._common import (
    _finalize_output,
    _format_counter,
    _format_kv,
)


def render_http2_summary(summary: Http2Summary) -> str:
    lines = [header("HTTP/2 ANALYSIS")]
    lines.append(_format_kv("HTTP/2 Packets", str(summary.http2_packets)))
    lines.append(_format_kv("Top Clients", _format_counter(summary.client_counts, 5)))
    lines.append(_format_kv("Top Servers", _format_counter(summary.server_counts, 5)))
    alpn_sessions = int(getattr(summary, "alpn_h2_sessions", 0) or 0)
    if alpn_sessions:
        lines.append(_format_kv("TLS ALPN h2 Sessions", str(alpn_sessions)))
        lines.append(
            _format_kv(
                "ALPN h2 Clients",
                _format_counter(getattr(summary, "alpn_h2_clients", {}), 5),
            )
        )
    return _finalize_output(lines)
