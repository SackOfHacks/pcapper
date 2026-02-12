from __future__ import annotations

from pathlib import Path

from .industrial_helpers import IndustrialAnalysis, analyze_port_protocol

MMS_PORT = 102


def _parse_commands(payload: bytes) -> list[str]:
    if len(payload) >= 4 and payload[0] == 0x03 and payload[1] == 0x00:
        return ["TPKT"]
    return []


def analyze_mms(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_port_protocol(
        path=path,
        protocol_name="IEC 61850 MMS",
        tcp_ports={MMS_PORT},
        command_parser=_parse_commands,
        show_status=show_status,
    )
