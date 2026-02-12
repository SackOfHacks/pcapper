from __future__ import annotations

from pathlib import Path

from .industrial_helpers import IndustrialAnalysis, analyze_port_protocol

FINS_PORT = 9600


def _parse_commands(payload: bytes) -> list[str]:
    if len(payload) < 12:
        return []
    cmd = int.from_bytes(payload[10:12], "big")
    return [f"CMD 0x{cmd:04x}"]


def analyze_fins(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_port_protocol(
        path=path,
        protocol_name="Omron FINS",
        tcp_ports={FINS_PORT},
        udp_ports={FINS_PORT},
        command_parser=_parse_commands,
        show_status=show_status,
    )
