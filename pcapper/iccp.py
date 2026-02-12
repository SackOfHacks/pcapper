from __future__ import annotations

from pathlib import Path

from .industrial_helpers import IndustrialAnalysis, analyze_port_protocol

ICCP_PORT = 102


def analyze_iccp(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_port_protocol(
        path=path,
        protocol_name="ICCP/TASE.2",
        tcp_ports={ICCP_PORT},
        show_status=show_status,
    )
