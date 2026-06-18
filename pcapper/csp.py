from __future__ import annotations

import ipaddress
from pathlib import Path

from .industrial_helpers import (
    append_public_exposure_anomaly,
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
)

CSP_PORTS = {2222, 44818}

# CSP (Allen-Bradley AB/Ethernet, port 2222) carries PCCC. AB does not publish
# the CSP framing, but the embedded PCCC command is spec-defined: a PLC-5/SLC
# command is CMD(1) STS(1) TNS(2) FNC(1), so the FNC sits 4 bytes after the CMD.
# CMD 0x0F (protected typed) is the carrier; the FNC selects the operation.
# (Confirmed: 0F 67 = PLC-5 typed WRITE, 0F 68 = PLC-5 typed READ.)
PCCC_WRITE_FNCS = {0x67, 0xAA, 0xAB, 0xA9}   # PLC-5 write, SLC protected/typed/bit writes
PCCC_READ_FNCS = {0x68, 0xA2, 0xA1}          # PLC-5 read, SLC protected/typed reads
PCCC_SETCPUMODE_FNC = 0x80                    # SET CPU MODE (run/program) = control


def _pccc_funcs_in(payload: bytes) -> set[int]:
    """Find PCCC function codes carried in a CSP payload: a CMD byte 0x0F with a
    plausible FNC 4 bytes later (CMD STS TNS[2] FNC)."""
    fncs: set[int] = set()
    interesting = PCCC_WRITE_FNCS | PCCC_READ_FNCS | {PCCC_SETCPUMODE_FNC}
    for i in range(len(payload) - 4):
        if payload[i] == 0x0F and payload[i + 4] in interesting:
            fncs.add(payload[i + 4])
    return fncs


def _parse_commands(payload: bytes) -> list[str]:
    cmds: list[str] = []
    for fnc in sorted(_pccc_funcs_in(payload)):
        if fnc in PCCC_WRITE_FNCS:
            cmds.append(f"PCCC Write (FNC 0x{fnc:02x})")
        elif fnc == PCCC_SETCPUMODE_FNC:
            cmds.append("PCCC Set CPU Mode")
        else:
            cmds.append(f"PCCC Read (FNC 0x{fnc:02x})")
    return cmds


def _detect_anomalies(
    payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]
) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []

    def add(sev: str, title: str, desc: str, attack: str) -> None:
        anomalies.append(
            IndustrialAnomaly(
                severity=sev, title=title, description=desc, src=src_ip,
                dst=dst_ip, ts=ts, attack=attack,
                evidence=[c for c in commands if c],
            )
        )

    if any("Set CPU Mode" in c for c in commands):
        add("HIGH", "CSP/PCCC CPU Mode Change",
            "PCCC Set-CPU-Mode over CSP (run/program/halt) — changes PLC operating state.",
            "T0858 Change Operating Mode")
    if any("Write" in c for c in commands):
        add("HIGH", "CSP/PCCC Write Operation",
            f"PCCC write to PLC data table over CSP: {'; '.join(commands)}",
            "T0836 Modify Parameter")
    return anomalies


def analyze_csp(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="CSP",
        tcp_ports=CSP_PORTS,
        udp_ports=CSP_PORTS,
        command_parser=_parse_commands,
        anomaly_detector=_detect_anomalies,
        enable_enrichment=True,
        show_status=show_status,
    )
    append_public_exposure_anomaly(analysis, "CSP")
    return analysis
