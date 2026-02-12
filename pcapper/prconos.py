from __future__ import annotations

from pathlib import Path

from .industrial_helpers import IndustrialAnalysis, analyze_port_protocol

PRCONOS_PORT = 20547


def analyze_prconos(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_port_protocol(
        path=path,
        protocol_name="ProConOS",
        tcp_ports={PRCONOS_PORT},
        show_status=show_status,
    )
