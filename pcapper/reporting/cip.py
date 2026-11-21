"""Rendered output for CIP analysis: the EtherNet/IP report (see
:func:`.enip.cip_family_report`) for the CIP analyzer, which adds legacy
Allen-Bradley PCCC commands carried in Execute_PCCC."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .enip import cip_family_report

if TYPE_CHECKING:
    from ..cip import CIPAnalysis


def render_cip_summary(summary: "CIPAnalysis") -> str:
    if not summary:
        return ""
    return cip_family_report(summary, name="CIP", unit="CIP", packets=summary.cip_packets,
                             size_bytes=summary.cip_bytes)
