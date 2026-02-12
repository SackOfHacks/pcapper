from __future__ import annotations

from pathlib import Path

from .industrial_helpers import IndustrialAnalysis, analyze_port_protocol

ODESYS_PORTS = {2455, 1217}


def analyze_odesys(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_port_protocol(
        path=path,
        protocol_name="ODESYS",
        tcp_ports=ODESYS_PORTS,
        show_status=show_status,
    )
