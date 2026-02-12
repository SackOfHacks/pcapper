from __future__ import annotations

from pathlib import Path

from .industrial_helpers import IndustrialAnalysis, analyze_port_protocol

OPC_UA_PORT = 4840

OPC_TYPES = {
    b"HEL": "Hello",
    b"ACK": "Acknowledge",
    b"OPN": "OpenSecureChannel",
    b"CLO": "CloseSecureChannel",
    b"MSG": "Message",
    b"ERR": "Error",
}


def _parse_commands(payload: bytes) -> list[str]:
    if len(payload) < 3:
        return []
    msg_type = payload[:3]
    name = OPC_TYPES.get(msg_type)
    return [name] if name else []


def analyze_opc(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_port_protocol(
        path=path,
        protocol_name="OPC UA",
        tcp_ports={OPC_UA_PORT},
        command_parser=_parse_commands,
        show_status=show_status,
    )
