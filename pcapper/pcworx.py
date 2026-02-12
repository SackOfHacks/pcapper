from __future__ import annotations

from pathlib import Path

from .industrial_helpers import IndustrialAnalysis, analyze_port_protocol

PCWORX_PORT = 1962


def analyze_pcworx(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_port_protocol(
        path=path,
        protocol_name="PCWorx",
        tcp_ports={PCWORX_PORT},
        show_status=show_status,
    )
