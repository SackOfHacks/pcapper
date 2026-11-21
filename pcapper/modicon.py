from __future__ import annotations

from pathlib import Path

from .industrial_helpers import (
    append_public_exposure_anomaly,
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
)
from .utils import memoize_analysis

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
    90: "UMAS (Schneider Unity)",  # 0x5A — Schneider engineering protocol
    91: "UMAS (Schneider Unity)",  # 0x5B
}

WRITE_FUNCTIONS = {5, 6, 15, 16}
UMAS_FUNC = 0x5A

# Schneider UMAS sub-function codes (Modbus FC 0x5A) — the Unity Pro / EcoStruxure
# Control Expert engineering protocol abused by PIPEDREAM/INCONTROLLER. Framing:
# [MBAP 7][FC 0x5A][session 1][umas-func 1]; a response carries 0xFE/0xFD in the
# umas-func position, so requests are distinguished cleanly.
UMAS_FUNCTIONS = {
    0x01: "INIT_COMM", 0x02: "READ_ID", 0x03: "READ_PROJECT_INFO",
    0x04: "READ_PLC_INFO", 0x06: "READ_CARD_INFO", 0x0A: "REPEAT",
    0x10: "TAKE_PLC_RESERVATION", 0x11: "RELEASE_PLC_RESERVATION", 0x12: "KEEP_ALIVE",
    0x20: "READ_MEMORY_BLOCK", 0x21: "WRITE_MEMORY_BLOCK",
    0x22: "READ_VARIABLES", 0x23: "WRITE_VARIABLES",
    0x24: "READ_COILS_REGISTERS", 0x25: "WRITE_COILS_REGISTERS", 0x26: "DATA_DICTIONARY",
    # Schneider's "upload" copies a project INTO the PLC, its "download"
    # copies it OUT -- the reverse of ATT&CK's Program Download / Upload.
    0x30: "INITIALIZE_UPLOAD", 0x31: "UPLOAD_BLOCK", 0x32: "END_STRATEGY_UPLOAD",
    0x33: "INITIALIZE_DOWNLOAD", 0x34: "DOWNLOAD_BLOCK", 0x35: "END_STRATEGY_DOWNLOAD",
    0x39: "READ_ETH_MASTER_DATA", 0x40: "START_PLC", 0x41: "STOP_PLC",
    0x50: "MONITOR_PLC", 0x58: "CHECK_PLC", 0x70: "READ_IO_OBJECT",
    0x71: "WRITE_IO_OBJECT", 0x73: "GET_STATUS_MODULE",
}
# Sub-functions that change PLC state or memory (write / program / control).
_UMAS_CONTROL = {0x40: "Start PLC", 0x41: "Stop PLC"}
_UMAS_WRITE = {
    0x21: "Write Memory Block (program download)",
    0x23: "Write Variables",
    0x25: "Write Coils/Registers",
    0x30: "Initialize Strategy Upload (program download to the PLC)",
    0x31: "Upload Strategy Block (program download to the PLC)",
    0x32: "End Strategy Upload (program download to the PLC)",
    0x71: "Write I/O Object",
}
_UMAS_PROGRAM_TO_PLC = {0x21, 0x30, 0x31, 0x32}
# Reading the PLC program out (ATT&CK ICS T0845 Program Upload).
_UMAS_PROGRAM_FROM_PLC = {
    0x33: "Initialize Strategy Download (program read from the PLC)",
    0x34: "Download Strategy Block (program read from the PLC)",
    0x35: "End Strategy Download (program read from the PLC)",
}
_UMAS_RESERVATION = {0x10: "Take PLC Reservation (claim exclusive control)"}


def _modicon_frame(payload: bytes) -> tuple[int, bytes] | None:
    if len(payload) < 8:
        return None
    proto_id = int.from_bytes(payload[2:4], "big")
    length = int.from_bytes(payload[4:6], "big")
    if proto_id != 0 or not 2 <= length <= 254 or length + 6 > len(payload):
        return None
    return payload[7], payload[: length + 6]


def _umas_signature(payload: bytes) -> bool:
    """A UMAS frame: Modbus/TCP with function 0x5A carrying a known UMAS
    sub-function or a UMAS response code."""
    frame = _modicon_frame(payload)
    if frame is None or frame[0] != UMAS_FUNC or len(frame[1]) < 10:
        return False
    return frame[1][9] in UMAS_FUNCTIONS or frame[1][9] in (0xFE, 0xFD)


def _parse_commands(payload: bytes) -> list[str]:
    frame = _modicon_frame(payload)
    if frame is None:
        return []
    func, modbus_frame = frame
    if func == UMAS_FUNC:
        if len(modbus_frame) < 10:
            return []
        umas_fn = modbus_frame[9]
        if umas_fn in (0xFE, 0xFD):  # response, not a request command
            return ["UMAS Response"]
        name = UMAS_FUNCTIONS.get(umas_fn, f"0x{umas_fn:02x}")
        return [f"UMAS {name} (0x{umas_fn:02x})"]
    return [FUNC_NAMES.get(func, f"Func {func}")]


def _detect_anomalies(
    payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]
) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    if any(cmd.startswith("Write") for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="Modicon Write Operation",
                description="Modicon write function observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    # Decode the UMAS sub-function directly so the dangerous engineering
    # operations (PLC start/stop, memory/variable writes, program download,
    # control reservation) are flagged — these are the PIPEDREAM/INCONTROLLER
    # Schneider abuse primitives.
    frame = _modicon_frame(payload)
    if frame is not None and frame[0] == UMAS_FUNC and len(frame[1]) >= 10:
        umas_fn = frame[1][9]
        if umas_fn in _UMAS_CONTROL:
            anomalies.append(
                IndustrialAnomaly(
                    severity="HIGH",
                    title="Modicon UMAS CPU Control",
                    description=(
                        f"Schneider UMAS {_UMAS_CONTROL[umas_fn]} command "
                        f"(0x{umas_fn:02x}) — changes PLC operating mode "
                        "(ATT&CK ICS T0858)."
                    ),
                    src=src_ip,
                    dst=dst_ip,
                    ts=ts,
                    attack="T0858 Change Operating Mode",
                    evidence=[
                        f"UMAS function 0x{umas_fn:02x} ({_UMAS_CONTROL[umas_fn]})",
                        f"{src_ip} -> {dst_ip}",
                    ],
                )
            )
        elif umas_fn in _UMAS_WRITE:
            is_program_download = umas_fn in _UMAS_PROGRAM_TO_PLC
            anomalies.append(
                IndustrialAnomaly(
                    severity="HIGH",
                    title="Modicon UMAS Write/Program",
                    description=(
                        f"Schneider UMAS {_UMAS_WRITE[umas_fn]} (0x{umas_fn:02x}) "
                        "— writes PLC memory or changes process data."
                    ),
                    src=src_ip,
                    dst=dst_ip,
                    ts=ts,
                    attack=(
                        "T0843 Program Download"
                        if is_program_download
                        else "T0836 Modify Parameter"
                    ),
                    evidence=[
                        f"UMAS function 0x{umas_fn:02x} ({_UMAS_WRITE[umas_fn]})",
                        f"{src_ip} -> {dst_ip}",
                    ],
                )
            )
        elif umas_fn in _UMAS_PROGRAM_FROM_PLC:
            anomalies.append(
                IndustrialAnomaly(
                    severity="HIGH",
                    title="Modicon UMAS Program Upload",
                    description=(
                        f"Schneider UMAS {_UMAS_PROGRAM_FROM_PLC[umas_fn]} (0x{umas_fn:02x}) "
                        "-- the controller logic is being copied off the PLC: routine from the "
                        "engineering workstation, reconnaissance from anywhere else."
                    ),
                    src=src_ip,
                    dst=dst_ip,
                    ts=ts,
                    attack="T0845 Program Upload",
                    evidence=[
                        f"UMAS function 0x{umas_fn:02x} ({_UMAS_PROGRAM_FROM_PLC[umas_fn]})",
                        f"{src_ip} -> {dst_ip}",
                    ],
                )
            )
        elif umas_fn in _UMAS_RESERVATION:
            anomalies.append(
                IndustrialAnomaly(
                    severity="MEDIUM",
                    title="Modicon UMAS Reservation",
                    description=(
                        f"Schneider UMAS {_UMAS_RESERVATION[umas_fn]} (0x{umas_fn:02x}) "
                        "— a controller is being claimed for exclusive engineering "
                        "access, typically preceding writes/program changes."
                    ),
                    src=src_ip,
                    dst=dst_ip,
                    ts=ts,
                )
            )
    return anomalies


@memoize_analysis
def analyze_modicon(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        port_key="modicon",
        path=path,
        protocol_name="Modicon",
        tcp_ports={MODICON_PORT},
        # Only Schneider's UMAS engineering protocol (Modbus function 0x5A):
        # plain Modbus on 502 belongs to --modbus, and counting it here
        # labelled every Modbus device a Modicon and doubled its write alerts.
        signature_matcher=_umas_signature,
        signature_required=True,
        command_parser=_parse_commands,
        anomaly_detector=_detect_anomalies,
        enable_enrichment=True,
        show_status=show_status,
    )
    append_public_exposure_anomaly(analysis, "Modicon")
    return analysis
