from __future__ import annotations

from pathlib import Path
import struct

from .industrial_helpers import IndustrialAnalysis, analyze_port_protocol

MODICON_PORT = 502

FUNC_NAMES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
}


def _parse_commands(payload: bytes) -> list[str]:
    if len(payload) < 8:
        return []
    try:
        _trans_id, proto_id, _length, _unit_id = struct.unpack(">HHHB", payload[:7]
        )
        if proto_id != 0:
            return []
        func = payload[7]
        return [FUNC_NAMES.get(func, f"Func {func}")]
    except Exception:
        return []


def analyze_modicon(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_port_protocol(
        path=path,
        protocol_name="Modicon",
        tcp_ports={MODICON_PORT},
        command_parser=_parse_commands,
        show_status=show_status,
    )
