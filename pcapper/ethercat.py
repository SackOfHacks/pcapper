from __future__ import annotations

from pathlib import Path

from .industrial_helpers import IndustrialAnalysis, analyze_ethertype_protocol

ETHERCAT_ETHERTYPE = 0x88A4

ETHERCAT_CMDS = {
    0x01: "APRD",
    0x02: "APWR",
    0x03: "APRW",
    0x04: "FPRD",
    0x05: "FPWR",
    0x06: "FPRW",
    0x07: "BRD",
    0x08: "BWR",
    0x09: "BRW",
    0x0A: "LRD",
    0x0B: "LWR",
    0x0C: "LRW",
    0x0D: "ARMW",
    0x0E: "FRMW",
}


def _parse_commands(payload: bytes) -> list[str]:
    if not payload:
        return []
    cmd = payload[0]
    return [ETHERCAT_CMDS.get(cmd, f"CMD 0x{cmd:02x}")]


def analyze_ethercat(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_ethertype_protocol(
        path=path,
        protocol_name="EtherCAT",
        ethertype=ETHERCAT_ETHERTYPE,
        command_parser=_parse_commands,
        show_status=show_status,
    )
