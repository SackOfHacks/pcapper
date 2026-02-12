from __future__ import annotations

from pathlib import Path

from .industrial_helpers import IndustrialAnalysis, analyze_port_protocol

COAP_PORTS = {5683, 5684}

METHODS = {
    1: "GET",
    2: "POST",
    3: "PUT",
    4: "DELETE",
}


def _parse_commands(payload: bytes) -> list[str]:
    if len(payload) < 2:
        return []
    ver = payload[0] >> 6
    code = payload[1]
    if ver != 1:
        return []
    if code in METHODS:
        return [f"REQ {METHODS[code]}"]
    if code >= 64:
        return [f"RESP {code//32}.{code%32:02d}"]
    return []


def analyze_coap(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_port_protocol(
        path=path,
        protocol_name="CoAP",
        udp_ports=COAP_PORTS,
        command_parser=_parse_commands,
        show_status=show_status,
    )
