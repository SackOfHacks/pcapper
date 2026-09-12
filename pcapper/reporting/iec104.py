"""Rendered output for iec104 analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..industrial_helpers import IndustrialAnalysis

from ._common import (
    _render_industrial_summary,
)


def render_iec104_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary(
        "IEC-104", summary, packet_label="IEC-104 Packets"
    )
