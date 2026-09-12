"""Rendered output for profinet analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..industrial_helpers import IndustrialAnalysis

from ._common import (
    _render_ot_protocol_summary,
)


def render_profinet_summary(summary: "IndustrialAnalysis") -> str:
    return _render_ot_protocol_summary(
        "Profinet",
        summary,
        packet_label="Profinet Packets",
        dangerous_tokens={"set", "write", "alarm", "download", "upload"},
        suspicious_tokens={"identify", "query", "scan"},
    )
