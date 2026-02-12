from __future__ import annotations

from pathlib import Path

from .industrial_helpers import IndustrialAnalysis, analyze_port_protocol

CSP_PORTS = {2222, 44818}


def analyze_csp(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_port_protocol(
        path=path,
        protocol_name="CSP",
        tcp_ports=CSP_PORTS,
        udp_ports=CSP_PORTS,
        show_status=show_status,
    )
