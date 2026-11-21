"""Rendered output for the table-driven OT analyzers (see :mod:`pcapper.ot_extra`)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ._common import _render_industrial_summary

if TYPE_CHECKING:
    from ..ot_extra import OtAnalyzerSpec


def render_ot_extra_summary(spec: "OtAnalyzerSpec", summary: object) -> str:
    return _render_industrial_summary(spec.label, summary, packet_label=f"{spec.label} Packets")
