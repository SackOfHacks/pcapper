"""Rendered output for encrypted_dns analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    header,
)
from ..encrypted_dns import EncryptedDnsSummary

from ._common import (
    _finalize_output,
    _format_counter,
    _format_kv,
)


def render_encrypted_dns_summary(summary: EncryptedDnsSummary) -> str:
    lines = [header("ENCRYPTED DNS ANALYSIS")]
    lines.append(_format_kv("DoT Packets", str(summary.dot_packets)))
    lines.append(_format_kv("DoH Packets", str(summary.doh_packets)))
    lines.append(_format_kv("DoQ Packets", str(summary.doq_packets)))
    lines.append(_format_kv("Top Clients", _format_counter(summary.clients, 5)))
    lines.append(_format_kv("Top Servers", _format_counter(summary.servers, 5)))
    return _finalize_output(lines)
