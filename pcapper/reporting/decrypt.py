"""Rendered output for decrypt analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    header,
)

from ._common import (
    _finalize_output,
    _format_kv,
)


def render_decrypt_summary(summary) -> str:
    if not summary:
        return ""
    lines = [header(f"{summary.protocol} DECRYPTION")]
    lines.append(_format_kv("Streams", str(summary.stream_count)))
    lines.append(_format_kv("Output Dir", str(summary.output_dir)))
    if summary.outputs:
        lines.append(_format_kv("Outputs", str(len(summary.outputs))))
    if summary.notes:
        lines.append(_format_kv("Notes", "; ".join(summary.notes)))
    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors)))
    return _finalize_output(lines)
