from __future__ import annotations

from pathlib import Path

from .industrial_helpers import (
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
)

IEC104_PORT = 2404

ASDU_TYPES = {
    1: "M_SP_NA_1 (Single-point)",
    3: "M_DP_NA_1 (Double-point)",
    9: "M_ME_NA_1 (Measured value)",
    11: "M_ME_NB_1 (Measured value scaled)",
    13: "M_ME_NC_1 (Measured value short)",
    45: "C_SC_NA_1 (Single command)",
    46: "C_DC_NA_1 (Double command)",
    47: "C_RC_NA_1 (Regulating command)",
    48: "C_SE_NA_1 (Setpoint) ",
    49: "C_SE_NB_1 (Setpoint scaled)",
    50: "C_SE_NC_1 (Setpoint short)",
    51: "C_BO_NA_1 (Bitstring command)",
}

UFRAME_TYPES = {
    0x07: "STARTDT act",
    0x0B: "STARTDT con",
    0x13: "STOPDT act",
    0x23: "STOPDT con",
    0x43: "TESTFR act",
    0x83: "TESTFR con",
}


def _parse_commands(payload: bytes) -> list[str]:
    if not payload or len(payload) < 6:
        return []
    if payload[0] != 0x68:
        return []

    ctrl0 = payload[2]
    cmds: list[str] = []
    if ctrl0 & 0x01 == 0:
        cmds.append("I-Frame")
    elif ctrl0 & 0x03 == 1:
        cmds.append("S-Frame")
    elif ctrl0 & 0x03 == 3:
        cmds.append("U-Frame")
        if ctrl0 in UFRAME_TYPES:
            cmds.append(UFRAME_TYPES[ctrl0])

    if len(payload) > 6:
        type_id = payload[6]
        type_name = ASDU_TYPES.get(type_id, f"ASDU {type_id}")
        cmds.append(type_name)
    return cmds


def _detect_anomalies(
    payload: bytes,
    src_ip: str,
    dst_ip: str,
    ts: float,
    commands: list[str],
) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    if any(cmd.startswith("C_") or "command" in cmd.lower() for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="IEC-104 Control Command",
                description="Control/Setpoint ASDU observed in IEC-104 traffic.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any("STOPDT" in cmd or "STARTDT" in cmd for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="MEDIUM",
                title="IEC-104 Session Control",
                description="IEC-104 start/stop data transfer observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    return anomalies


def analyze_iec104(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_port_protocol(
        path=path,
        protocol_name="IEC-104",
        tcp_ports={IEC104_PORT},
        command_parser=_parse_commands,
        anomaly_detector=_detect_anomalies,
        show_status=show_status,
    )
