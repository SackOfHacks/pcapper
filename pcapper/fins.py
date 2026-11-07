from __future__ import annotations

from pathlib import Path

from .industrial_helpers import (
    append_public_exposure_anomaly,
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
)
from .utils import memoize_analysis

FINS_PORT = 9600

# Omron FINS command codes (MRC/SRC), per the FINS Commands Reference (W227).
FINS_COMMANDS = {
    0x0101: "Memory Area Read",
    0x0102: "Memory Area Write",
    0x0103: "Memory Area Fill",
    0x0104: "Multiple Memory Area Read",
    0x0105: "Memory Area Transfer",
    0x0201: "Parameter Area Read",
    0x0202: "Parameter Area Write",
    0x0203: "Parameter Area Clear",
    0x0306: "Program Area Read",
    0x0307: "Program Area Write",
    0x0308: "Program Area Clear",
    0x0401: "RUN (operating mode -> RUN/MONITOR)",
    0x0402: "STOP (operating mode -> PROGRAM / halt)",
    0x0501: "CPU Unit Data Read",
    0x0601: "CPU Unit Status Read",
    0x0701: "Clock Read",
    0x0702: "Clock Write",
    0x2101: "Error Log Read",
    0x2102: "Error Log Clear",
    0x2201: "File Name Read",
    0x2203: "File Write",
}


def _fins_frame(payload: bytes) -> bytes | None:
    if payload.startswith(b"FINS"):
        if len(payload) < 16:
            return None
        length = int.from_bytes(payload[4:8], "big")
        command = int.from_bytes(payload[8:12], "big")
        if command != 2 or length < 20 or length + 8 > len(payload):
            return None
        payload = payload[16 : 8 + length]
    if len(payload) < 12:
        return None
    icf, reserved, gateway_count = payload[:3]
    if icf & 0x3F or reserved != 0 or gateway_count > 7:
        return None
    return payload


def _parse_commands(payload: bytes) -> list[str]:
    frame = _fins_frame(payload)
    if frame is None:
        return []
    cmd = int.from_bytes(frame[10:12], "big")
    label = FINS_COMMANDS.get(cmd, f"CMD 0x{cmd:04x}")
    if frame[0] & 0x40:
        label += " (response)"
    return [label]


def _detect_anomalies(
    payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]
) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    frame = _fins_frame(payload)
    if frame is None or frame[0] & 0x40:
        return anomalies

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
    # STOP halts the PLC (operating mode -> PROGRAM) = denial of control.
    if any(cmd.startswith("STOP") for cmd in commands):
        add(
            "HIGH",
            "FINS CPU Stop",
            f"FINS STOP command (PLC -> PROGRAM mode, halts logic execution): {joined}",
            "T0816 Device Restart/Shutdown",
        )
    if any(cmd.startswith("RUN") for cmd in commands):
        add(
            "HIGH",
            "FINS CPU Run / Mode Change",
            f"FINS RUN command (operating-mode change): {joined}",
            "T0858 Change Operating Mode",
        )
    if any(cmd.startswith("Program Area Read") for cmd in commands):
        add(
            "MEDIUM",
            "FINS Program Upload",
            f"FINS program-area read observed: {joined}",
            "T0845 Program Upload",
        )
    if any(cmd.startswith("Program Area Write") for cmd in commands):
        add(
            "HIGH",
            "FINS Program Download",
            f"FINS program-area write observed: {joined}",
            "T0843 Program Download",
        )
    if any("Clear" in cmd for cmd in commands):
        add(
            "HIGH",
            "FINS Parameter/Program Clear",
            f"FINS clear operation (destructive): {joined}",
            "T0809 Data Destruction",
        )
    if any(
        ("Write" in cmd and not cmd.startswith("Program Area Write"))
        or "Fill" in cmd
        or "Transfer" in cmd
        for cmd in commands
    ):
        add(
            "MEDIUM",
            "FINS Write Operation",
            f"FINS memory/parameter write: {joined}",
            "T0836 Modify Parameter",
        )
    return anomalies


@memoize_analysis
def analyze_fins(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="Omron FINS",
        tcp_ports={FINS_PORT},
        udp_ports={FINS_PORT},
        command_parser=_parse_commands,
        anomaly_detector=_detect_anomalies,
        enable_enrichment=True,
        show_status=show_status,
    )
    append_public_exposure_anomaly(analysis, "FINS")
    return analysis
