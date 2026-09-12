"""Rendered output for srtp analysis.

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


def render_srtp_summary(summary: "IndustrialAnalysis") -> str:
    return _render_industrial_summary("GE SRTP", summary, packet_label="SRTP Packets")
