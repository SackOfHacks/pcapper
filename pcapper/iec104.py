from __future__ import annotations

import struct
from collections import OrderedDict
from pathlib import Path

try:
    from scapy.layers.inet import TCP
except ImportError:
    TCP = None

from .industrial_helpers import (
    append_public_exposure_anomaly,
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
)
from .utils import memoize_analysis

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
    # System/control-direction commands (names deliberately not prefixed with
    # "C_" so the generic control-command check doesn't double-flag them).
    100: "General Interrogation (C_IC_NA_1)",
    101: "Counter Interrogation (C_CI_NA_1)",
    103: "Clock Synchronization (C_CS_NA_1)",
    105: "Reset Process (C_RP_NA_1)",
    107: "Test Command (C_TS_TA_1)",
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

_MAX_APDU_LENGTH = 253
_MAX_STREAMS = 4096


def _complete_apdus(data: bytes) -> tuple[list[bytes], bytes]:
    """Split complete IEC-104 APDUs from a TCP byte stream."""
    frames: list[bytes] = []
    offset = 0
    while offset < len(data):
        start = data.find(b"\x68", offset)
        if start < 0:
            return frames, b""
        if start + 2 > len(data):
            return frames, data[start:]
        length = data[start + 1]
        if length < 4 or length > _MAX_APDU_LENGTH:
            offset = start + 1
            continue
        end = start + 2 + length
        if end > len(data):
            return frames, data[start:]
        frames.append(data[start:end])
        offset = end
    return frames, b""


class _IEC104TCPReassembler:
    def __init__(self) -> None:
        self._streams: OrderedDict[
            tuple[str, str, int, int], tuple[int, bytes]
        ] = OrderedDict()
        self.errors: list[str] = []

    @property
    def pending_streams(self) -> int:
        return len(self._streams)

    def __call__(self, packet: object, match: object) -> bytes:
        payload = getattr(match, "payload", b"")
        if TCP is None:
            return payload
        tcp = packet.getlayer(TCP)  # type: ignore[attr-defined]
        if tcp is None:
            return payload
        key = (
            str(getattr(match, "src")),
            str(getattr(match, "dst")),
            int(getattr(match, "sport")),
            int(getattr(match, "dport")),
        )
        sequence = int(getattr(tcp, "seq", 0))
        flags = int(getattr(tcp, "flags", 0))
        previous = self._streams.pop(key, None)
        if flags & 0x02 and previous is not None:
            self._report_incomplete()
            previous = None

        if not payload:
            if previous is not None and flags & 0x05:
                self._report_incomplete()
            elif previous is not None:
                self._streams[key] = previous
            return b""

        if previous is not None:
            expected, buffered = previous
            delta = (sequence - expected + (1 << 31)) % (1 << 32) - (1 << 31)
            if delta < 0:
                overlap = -delta
                if overlap >= len(payload):
                    self._streams[key] = previous
                    return b""
                payload = payload[overlap:]
            elif delta > 0:
                self._report_gap()
                buffered = b""
            payload = buffered + payload

        frames, remainder = _complete_apdus(payload)
        if remainder and not flags & 0x05:
            if len(remainder) <= _MAX_APDU_LENGTH + 2:
                if len(self._streams) >= _MAX_STREAMS:
                    self._streams.popitem(last=False)
                    self._report_limit()
                self._streams[key] = (
                    (
                        sequence
                        + len(getattr(match, "payload", b""))
                        + int(bool(flags & 0x02))
                    )
                    & 0xFFFFFFFF,
                    remainder,
                )
            else:
                self._report_incomplete()
        elif remainder:
            self._report_incomplete()
        return b"".join(frames)

    def _report_gap(self) -> None:
        message = "IEC-104 TCP sequence gap discarded an incomplete APDU."
        if message not in self.errors:
            self.errors.append(message)

    def _report_incomplete(self) -> None:
        message = "IEC-104 TCP stream ended with an incomplete APDU."
        if message not in self.errors:
            self.errors.append(message)

    def _report_limit(self) -> None:
        message = "IEC-104 TCP stream limit reached; oldest partial stream discarded."
        if message not in self.errors:
            self.errors.append(message)

    def finish(self) -> None:
        if self._streams:
            self._report_incomplete()
            self._streams.clear()


def _parse_commands(payload: bytes) -> list[str]:
    cmds: list[str] = []
    # A single TCP segment can carry MULTIPLE IEC-104 APDUs back-to-back
    # (0x68, length, 4 control octets, ASDU). The previous code read only the
    # first APDU, so a C_SC/STARTDT in the 2nd+ APDU (common) was missed.
    apdus, _ = _complete_apdus(payload)
    for apdu in apdus:
        ctrl0 = apdu[2]
        apdu_commands: list[str] = []
        if ctrl0 & 0x01 == 0:
            apdu_commands.append("I-Frame")
        elif ctrl0 & 0x03 == 1:
            apdu_commands.append("S-Frame")
        elif ctrl0 & 0x03 == 3:
            apdu_commands.append("U-Frame")
            if ctrl0 in UFRAME_TYPES:
                apdu_commands.append(UFRAME_TYPES[ctrl0])
        if len(apdu) > 6:
            type_id = apdu[6]
            type_name = ASDU_TYPES.get(type_id, f"ASDU {type_id}")
            apdu_commands.append(type_name)
            if type_id in CONTROL_ASDU_TYPES:
                apdu_commands.append("Control ASDU")
        asdu_cmds, _ = _parse_asdu(apdu)
        for cmd in asdu_cmds:
            if cmd not in apdu_commands:
                apdu_commands.append(cmd)
        cmds.extend(apdu_commands)
    return cmds


def _parse_asdu(payload: bytes) -> tuple[list[str], list[tuple[str, str]]]:
    commands: list[str] = []
    artifacts: list[tuple[str, str]] = []
    if len(payload) < 12 or payload[0] != 0x68:
        return commands, artifacts
    if payload[1] < 4 or payload[1] > _MAX_APDU_LENGTH:
        return commands, artifacts
    if len(payload) != 2 + payload[1]:
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

    count = vsq & 0x7F
    if count == 0 or len(asdu) < 9:
        return commands, artifacts
    ioa_base = asdu[6] | (asdu[7] << 8) | (asdu[8] << 16)
    object_sizes = {45: 1, 46: 1, 47: 1, 48: 3, 49: 3, 50: 5, 51: 5}
    object_size = object_sizes.get(type_id)
    if object_size is None:
        artifacts.append(("iec104_ioa", str(ioa_base)))
        commands.append(f"IOA {ioa_base}")
        return commands, artifacts

    sequence = bool(vsq & 0x80)
    expected_asdu_length = (
        9 + count * object_size
        if sequence
        else 6 + count * (3 + object_size)
    )
    if len(asdu) < expected_asdu_length:
        return commands, artifacts
    for index in range(count):
        if sequence:
            ioa = ioa_base + index
            if ioa > 0xFFFFFF:
                break
            data_offset = 9 + index * object_size
        else:
            object_offset = 6 + index * (3 + object_size)
            data_offset = object_offset + 3
            if object_offset + 3 > len(asdu):
                break
            ioa = (
                asdu[object_offset]
                | (asdu[object_offset + 1] << 8)
                | (asdu[object_offset + 2] << 16)
            )
        if data_offset + object_size > len(asdu):
            break
        artifacts.append(("iec104_ioa", str(ioa)))
        commands.append(f"IOA {ioa}")
        value = asdu[data_offset : data_offset + object_size]
        if type_id == 45:
            cmd_byte = value[0]
            mode = "SELECT" if cmd_byte & 0x80 else "EXECUTE"
            state = "ON" if cmd_byte & 0x01 else "OFF"
            commands.append(f"SC {mode} {state}")
            artifacts.append(("iec104_command", f"SC {mode} {state} IOA {ioa}"))
        elif type_id == 46:
            cmd_byte = value[0]
            mode = "SELECT" if cmd_byte & 0x80 else "EXECUTE"
            state_code = cmd_byte & 0x03
            state = {1: "OFF", 2: "ON"}.get(
                state_code, f"INVALID ({state_code})"
            )
            commands.append(f"DC {mode} {state}")
            artifacts.append(("iec104_command", f"DC {mode} {state} IOA {ioa}"))
        elif type_id == 47:
            cmd_byte = value[0]
            mode = "SELECT" if cmd_byte & 0x80 else "EXECUTE"
            state_code = cmd_byte & 0x03
            commands.append(f"RC {mode} {state_code}")
            artifacts.append(
                ("iec104_command", f"RC {mode} code={state_code} IOA {ioa}")
            )
        elif type_id in {48, 49}:
            value_text = str(int.from_bytes(value[:2], "little", signed=True))
            commands.append(f"Setpoint {value_text}")
            artifacts.append(("iec104_setpoint", f"IOA {ioa} value={value_text}"))
        elif type_id == 50:
            value_text = f"{struct.unpack('<f', value[:4])[0]:.3f}"
            commands.append(f"Setpoint {value_text}")
            artifacts.append(("iec104_setpoint", f"IOA {ioa} value={value_text}"))
        elif type_id == 51:
            cmd_byte = value[4]
            mode = "SELECT" if cmd_byte & 0x80 else "EXECUTE"
            bitstring = int.from_bytes(value[:4], "little")
            commands.append(f"BO {mode} 0x{bitstring:08x}")
            artifacts.append(
                ("iec104_command", f"BO {mode} 0x{bitstring:08x} IOA {ioa}")
            )
    return commands, artifacts


def _parse_artifacts(payload: bytes) -> list[tuple[str, str]]:
    apdus, _ = _complete_apdus(payload)
    return [
        artifact
        for apdu in apdus
        for artifact in _parse_asdu(apdu)[1]
    ]


def _detect_anomalies(
    payload: bytes,
    src_ip: str,
    dst_ip: str,
    ts: float,
    commands: list[str],
) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    apdus, _ = _complete_apdus(payload)
    for apdu in apdus:
        apdu_commands = _parse_commands(apdu)
        if any("STOPDT" in cmd or "STARTDT" in cmd for cmd in apdu_commands):
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
        if any("TESTFR" in cmd for cmd in apdu_commands):
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
        if len(apdu) < 9:
            continue
        type_id = apdu[6]
        cot = apdu[8] & 0x3F
        if cot == 6 and type_id in CONTROL_ASDU_TYPES:
            detail_parts = [
                cmd
                for cmd in apdu_commands
                if cmd.startswith(
                    ("C_", "SC ", "DC ", "RC ", "BO ", "Setpoint")
                )
                or cmd.startswith("IOA ")
                or "command" in cmd.lower()
            ]
            detail = "; ".join(dict.fromkeys(detail_parts))
            is_execute = any("execute" in cmd.lower() for cmd in apdu_commands)
            description = f"IEC-104 control/setpoint command: {detail}"
            if is_execute:
                description += " [EXECUTE — actual actuation, not select]"
            evidence = [detail] if detail else []
            if is_execute:
                evidence.append("EXECUTE qualifier (actual actuation)")
            anomalies.append(
                IndustrialAnomaly(
                    severity="HIGH",
                    title="IEC-104 Control Command",
                    description=description,
                    src=src_ip,
                    dst=dst_ip,
                    ts=ts,
                    attack="T0855 Unauthorized Command Message; T0831 Manipulation of Control",
                    evidence=evidence,
                )
            )
        if cot == 6 and type_id == 105:
            anomalies.append(
                IndustrialAnomaly(
                    severity="HIGH",
                    title="IEC-104 Reset Process",
                    description=(
                        "Reset-process command (C_RP_NA_1) observed; reinitialises "
                        "the RTU/outstation (ATT&CK T0816)."
                    ),
                    src=src_ip,
                    dst=dst_ip,
                    ts=ts,
                )
            )
        elif cot == 6 and type_id == 103:
            anomalies.append(
                IndustrialAnomaly(
                    severity="MEDIUM",
                    title="IEC-104 Clock Synchronization",
                    description=(
                        "Clock-sync command (C_CS_NA_1) observed; confirm the source "
                        f"({src_ip}) is the authorised time master — clock manipulation "
                        "corrupts sequence-of-events forensics."
                    ),
                    src=src_ip,
                    dst=dst_ip,
                    ts=ts,
                )
            )
    return anomalies


@memoize_analysis
def analyze_iec104(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    reassembler = _IEC104TCPReassembler()
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="IEC-104",
        tcp_ports={IEC104_PORT},
        command_parser=_parse_commands,
        artifact_parser=_parse_artifacts,
        anomaly_detector=_detect_anomalies,
        enable_enrichment=True,
        show_status=show_status,
        payload_reassembler=reassembler,
    )
    reassembler.finish()
    analysis.errors.extend(reassembler.errors)
    append_public_exposure_anomaly(analysis, "IEC-104")
    return analysis
