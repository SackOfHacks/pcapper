from __future__ import annotations

from pathlib import Path

from .industrial_helpers import IndustrialAnalysis, analyze_port_protocol

CRIMSON_PORT = 789


def analyze_crimson(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_port_protocol(
        path=path,
        protocol_name="Crimson V3",
        tcp_ports={CRIMSON_PORT},
        show_status=show_status,
    )
