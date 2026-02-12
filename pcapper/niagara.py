from __future__ import annotations

from pathlib import Path

from .industrial_helpers import IndustrialAnalysis, analyze_port_protocol

NIAGARA_PORTS = {1911, 4911}


def analyze_niagara(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_port_protocol(
        path=path,
        protocol_name="Niagara Fox",
        tcp_ports=NIAGARA_PORTS,
        show_status=show_status,
    )
