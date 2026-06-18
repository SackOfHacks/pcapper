from __future__ import annotations

import ipaddress
from pathlib import Path

from .industrial_helpers import (
    append_public_exposure_anomaly,
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
)

HART_PORT = 5094

# HART common-practice command numbers (universal + common practice). Only the
# names needed to classify intent are mapped; unknowns show as "Command N".
HART_COMMANDS = {
    0: "Read Unique Identifier",
    1: "Read Primary Variable",
    2: "Read Loop Current",
    3: "Read Dynamic Variables",
    35: "Write Range Values",
    40: "Enter/Exit Fixed Current Mode",
    41: "Perform Self Test",
    42: "Perform Device Reset",
    44: "Write PV Units",
    47: "Write PV Transfer Function",
    51: "Write Dynamic Variable Assignments",
    52: "Set Device Variable Zero",
    53: "Write Device Variable Units",
    71: "Lock Device",
    79: "Write Device Variable",
}
# Forces the analog loop output / changes control -> Manipulation of Control.
HART_FIXED_CURRENT = {40}
HART_RESET = {42}
HART_LOCK = {71}
# Configuration / variable writes -> Modify Parameter.
HART_WRITE_CMDS = {35, 44, 47, 51, 52, 53, 79}


def _parse_commands(payload: bytes) -> list[str]:
    # HART-IP header (8 bytes): version, msg-type, msg-id, status, seq(2), len(2).
    # Only Message ID 3 (HART PDU pass-through) carries a HART command.
    if len(payload) < 8 or payload[0] not in (1, 2) or payload[2] != 3:
        return []
    body = payload[8:]
    if len(body) < 3:
        return []
    delim = body[0]
    # delimiter: bit7 = long(5-byte) vs short(1-byte) address; bits5-6 = number
    # of expansion bytes preceding the command.
    addr_len = 5 if (delim & 0x80) else 1
    num_exp = (delim >> 5) & 0x03
    cmd_off = 1 + addr_len + num_exp
    if cmd_off >= len(body):
        return []
    cmd = body[cmd_off]
    return [HART_COMMANDS.get(cmd, f"Command {cmd}")]


def _detect_anomalies(
    payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]
) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []

    def add(sev: str, title: str, desc: str, attack: str) -> None:
        anomalies.append(
            IndustrialAnomaly(
                severity=sev,
                title=title,
                description=desc,
                src=src_ip,
                dst=dst_ip,
                ts=ts,
                attack=attack,
                evidence=[c for c in commands if c],
            )
        )

    joined = "; ".join(commands)
    if any("Fixed Current" in c for c in commands):
        add(
            "HIGH",
            "HART Fixed Current Mode",
            f"HART Enter/Exit Fixed Current Mode — forces the 4-20mA loop output, "
            f"overriding the process value: {joined}",
            "T0831 Manipulation of Control",
        )
    if any("Device Reset" in c for c in commands):
        add("HIGH", "HART Device Reset", f"HART device reset command: {joined}",
            "T0816 Device Restart/Shutdown")
    if any("Lock Device" in c for c in commands):
        add("MEDIUM", "HART Device Lock", f"HART lock-device command: {joined}",
            "T0878 Alarm Suppression")
    if any("Write" in c for c in commands):
        add("MEDIUM", "HART Write Operation",
            f"HART configuration/variable write: {joined}", "T0836 Modify Parameter")
    return anomalies


def analyze_hart(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="HART-IP",
        tcp_ports={HART_PORT},
        udp_ports={HART_PORT},
        command_parser=_parse_commands,
        anomaly_detector=_detect_anomalies,
        enable_enrichment=True,
        show_status=show_status,
    )
    append_public_exposure_anomaly(analysis, "HART-IP")
    return analysis
