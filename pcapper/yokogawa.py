from __future__ import annotations

from pathlib import Path

from .industrial_helpers import IndustrialAnalysis, analyze_port_protocol

YOKOGAWA_PORTS = {34378, 34379, 34380}


def analyze_yokogawa(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_port_protocol(
        path=path,
        protocol_name="Yokogawa Vnet/IP",
        tcp_ports=YOKOGAWA_PORTS,
        show_status=show_status,
    )
