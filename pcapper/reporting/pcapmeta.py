"""Rendered output for pcapmeta analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    header,
)
from ..pcapmeta import PcapMetaSummary

from ._common import (
    _finalize_output,
    _format_kv,
    _limit_value,
)


def render_pcapmeta_summary(summary: PcapMetaSummary) -> str:
    lines = [header("PCAP METADATA")]
    lines.append(_format_kv("File Type", summary.file_type))
    lines.append(_format_kv("Size Bytes", str(summary.size_bytes)))
    lines.append(_format_kv("Linktype", str(summary.linktype or "-")))
    lines.append(_format_kv("Snaplen", str(summary.snaplen or "-")))
    lines.append(_format_kv("Interfaces", str(summary.interface_count)))
    if summary.interface_names:
        lines.append(
            _format_kv(
                "Interface Names", ", ".join(summary.interface_names[: _limit_value(6)])
            )
        )
    if summary.dropcount is not None:
        lines.append(_format_kv("Drop Count", str(summary.dropcount)))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors)))
    return _finalize_output(lines)
