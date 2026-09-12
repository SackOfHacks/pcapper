"""Rendered output for s7 analysis.

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


def render_s7_summary(summary: "IndustrialAnalysis") -> str:
    return _render_ot_protocol_summary(
        "S7",
        summary,
        packet_label="S7 Packets",
        dangerous_tokens={"write", "stop", "download", "upload", "start", "plc"},
        suspicious_tokens={"read", "setup", "userdata", "block", "diag"},
        include_detected_devices=True,
    )
