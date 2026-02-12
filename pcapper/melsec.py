from __future__ import annotations

from pathlib import Path

from .industrial_helpers import IndustrialAnalysis, analyze_port_protocol

MELSEC_TCP_PORT = 5007
MELSEC_UDP_PORT = 5006


def _parse_commands(payload: bytes) -> list[str]:
    if not payload:
        return []
    if payload.startswith(b"5000") or payload.startswith(b"5001"):
        return ["MC ASCII"]
    if len(payload) >= 2 and payload[0] == 0x50 and payload[1] == 0x00:
        return ["MC Binary"]
    return []


def analyze_melsec(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_port_protocol(
        path=path,
        protocol_name="MELSEC-Q",
        tcp_ports={MELSEC_TCP_PORT},
        udp_ports={MELSEC_UDP_PORT},
        command_parser=_parse_commands,
        show_status=show_status,
    )
