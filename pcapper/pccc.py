from __future__ import annotations

from pathlib import Path

from .industrial_helpers import IndustrialAnalysis, analyze_port_protocol

PCCC_PORTS = {2222, 44818}


def analyze_pccc(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_port_protocol(
        path=path,
        protocol_name="PCCC",
        tcp_ports=PCCC_PORTS,
        udp_ports=PCCC_PORTS,
        show_status=show_status,
    )
