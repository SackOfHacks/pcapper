"""Rendered output for opc_classic analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    header,
)
from ..opc_classic import OpcClassicSummary

from ._common import (
    _finalize_output,
    _format_counter,
    _format_kv,
)


def render_opc_classic_summary(summary: OpcClassicSummary) -> str:
    lines = [header("OPC CLASSIC ANALYSIS")]
    lines.append(_format_kv("OPC Packets", str(summary.opc_packets)))
    lines.append(_format_kv("Interfaces", _format_counter(summary.interface_counts, 6)))
    lines.append(_format_kv("Top Clients", _format_counter(summary.client_counts, 5)))
    lines.append(_format_kv("Top Servers", _format_counter(summary.server_counts, 5)))
    return _finalize_output(lines)
