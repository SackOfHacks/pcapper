from __future__ import annotations

from pathlib import Path

from .industrial_helpers import IndustrialAnalysis, analyze_port_protocol

HART_PORT = 5094


def analyze_hart(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_port_protocol(
        path=path,
        protocol_name="HART-IP",
        tcp_ports={HART_PORT},
        udp_ports={HART_PORT},
        show_status=show_status,
    )
