from __future__ import annotations

from pathlib import Path
import ipaddress
import struct

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

CONTROL_ASDU_TYPES = {45, 46, 47, 48, 49, 50, 51}

CAUSES = {
    1: "Periodic",
    2: "Background",
    3: "Spontaneous",
    4: "Initialized",
    5: "Request",
    6: "Activation",
    7: "Activation Confirmation",
    8: "Deactivation",
    9: "Deactivation Confirmation",
    10: "Activation Termination",
    20: "Interrogated by station",
    21: "Interrogated by group 1",
    22: "Interrogated by group 2",
    23: "Interrogated by group 3",
    24: "Interrogated by group 4",
    25: "Interrogated by group 5",
    26: "Interrogated by group 6",
    27: "Interrogated by group 7",
    28: "Interrogated by group 8",
    29: "Interrogated by group 9",
    30: "Interrogated by group 10",
    31: "Interrogated by group 11",
    32: "Interrogated by group 12",
    33: "Interrogated by group 13",
    34: "Interrogated by group 14",
    35: "Interrogated by group 15",
    36: "Interrogated by group 16",
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
        if type_id in CONTROL_ASDU_TYPES:
            cmds.append("Control ASDU")
    asdu_cmds, _ = _parse_asdu(payload)
    for cmd in asdu_cmds:
        if cmd not in cmds:
            cmds.append(cmd)
    return cmds


def _parse_asdu(payload: bytes) -> tuple[list[str], list[tuple[str, str]]]:
    commands: list[str] = []
    artifacts: list[tuple[str, str]] = []
    if len(payload) < 10 or payload[0] != 0x68:
        return commands, artifacts
    if len(payload) < 6:
        return commands, artifacts
    if len(payload) < 7:
        return commands, artifacts
    if len(payload) <= 6:
        return commands, artifacts
    asdu = payload[6:]
    if len(asdu) < 6:
        return commands, artifacts
    type_id = asdu[0]
    vsq = asdu[1]
    cot_raw = int.from_bytes(asdu[2:4], "little")
    cot = cot_raw & 0x3F
    test = bool(cot_raw & 0x80)
    neg = bool(cot_raw & 0x40)
    addr = int.from_bytes(asdu[4:6], "little")
    type_name = ASDU_TYPES.get(type_id, f"ASDU {type_id}")
    cause_name = CAUSES.get(cot, f"COT {cot}")
    cause_text = cause_name
    if test:
        cause_text += " TEST"
    if neg:
        cause_text += " NEG"

    commands.append(type_name)
    commands.append(cause_text)
    artifacts.append(("iec104_asdu_addr", str(addr)))
    artifacts.append(("iec104_cot", cause_text))
    artifacts.append(("iec104_vsq", f"{vsq}"))

    if len(asdu) >= 9:
        ioa = asdu[6] | (asdu[7] << 8) | (asdu[8] << 16)
        artifacts.append(("iec104_ioa", str(ioa)))
        commands.append(f"IOA {ioa}")
        if type_id in CONTROL_ASDU_TYPES and len(asdu) >= 10:
            cmd_byte = asdu[9]
            select = bool(cmd_byte & 0x80)
            mode = "SELECT" if select else "EXECUTE"
            if type_id == 45:
                state = "ON" if cmd_byte & 0x01 else "OFF"
                commands.append(f"SC {mode} {state}")
                artifacts.append(("iec104_command", f"SC {mode} {state} IOA {ioa}"))
            elif type_id == 46:
                state_code = cmd_byte & 0x03
                state = {0: "OFF", 1: "ON", 2: "OFF", 3: "ON"}.get(state_code, f"STATE {state_code}")
                commands.append(f"DC {mode} {state}")
                artifacts.append(("iec104_command", f"DC {mode} {state} IOA {ioa}"))
            elif type_id == 47:
                state_code = cmd_byte & 0x03
                commands.append(f"RC {mode} {state_code}")
                artifacts.append(("iec104_command", f"RC {mode} code={state_code} IOA {ioa}"))
            elif type_id in {48, 49, 50}:
                value_text = None
                if type_id in {48, 49} and len(asdu) >= 12:
                    value_text = str(int.from_bytes(asdu[9:11], "little", signed=True))
                if type_id == 50 and len(asdu) >= 14:
                    try:
                        value_text = f"{struct.unpack('<f', asdu[9:13])[0]:.3f}"
                    except Exception:
                        value_text = None
                if value_text is not None:
                    commands.append(f"Setpoint {value_text}")
                    artifacts.append(("iec104_setpoint", f"IOA {ioa} value={value_text}"))
    return commands, artifacts


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
    if any("TESTFR" in cmd for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="LOW",
                title="IEC-104 Test Frame",
                description="IEC-104 test frame (TESTFR) observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    return anomalies


def analyze_iec104(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="IEC-104",
        tcp_ports={IEC104_PORT},
        command_parser=_parse_commands,
        artifact_parser=lambda payload: _parse_asdu(payload)[1],
        anomaly_detector=_detect_anomalies,
        enable_enrichment=True,
        show_status=show_status,
    )
    public_endpoints = []
    for ip_value in set(analysis.src_ips) | set(analysis.dst_ips):
        try:
            if ipaddress.ip_address(ip_value).is_global:
                public_endpoints.append(ip_value)
        except Exception:
            continue
    if public_endpoints and len(analysis.anomalies) < 200:
        analysis.anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="IEC-104 Exposure to Public IP",
                description=f"IEC-104 traffic observed with public endpoint(s): {', '.join(sorted(public_endpoints)[:5])}.",
                src="*",
                dst="*",
                ts=0.0,
            )
        )
    return analysis
