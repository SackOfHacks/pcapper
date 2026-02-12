from __future__ import annotations

from pathlib import Path

from .industrial_helpers import IndustrialAnalysis, analyze_port_protocol

SRTP_TCP_PORTS = {18245, 18246}
SRTP_UDP_PORTS = {18246}


def analyze_srtp(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_port_protocol(
        path=path,
        protocol_name="GE SRTP",
        tcp_ports=SRTP_TCP_PORTS,
        udp_ports=SRTP_UDP_PORTS,
        show_status=show_status,
    )
