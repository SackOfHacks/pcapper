from __future__ import annotations

from pathlib import Path

from .industrial_helpers import (
    append_public_exposure_anomaly,
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
)
from .utils import memoize_analysis

PRCONOS_PORT = 20547
_PROCONOS_CPU_MODE_SERVICE = 0x400E

# ProConOS / ProConOS eCLR is the IEC 61131 runtime on Phoenix Contact (and many
# OEM) PLCs. Messages start with marker byte 0xcc. The Redpoint proconos-info
# probe (`cc01000b4002000047ee`) reads the ladder-logic runtime, PLC type,
# project name, boot project and PROJECT SOURCE CODE — i.e. it uploads the
# control logic, which is both reconnaissance and logic theft.


def _parse_commands(payload: bytes) -> list[str]:
    if len(payload) < 6 or payload[0] != 0xCC:
        return []
    direction = "Response" if payload[1] == 0x00 else "Request"
    # bytes 4-5 carry the service/command selector (0x4002 = read project info).
    svc = int.from_bytes(payload[4:6], "big")
    if svc == 0x4002:
        label = "Read Project/Program Info"
    elif svc == 0x4007:
        label = "Read CPU State"
    elif svc == _PROCONOS_CPU_MODE_SERVICE:
        length = int.from_bytes(payload[2:4], "big")
        if length == 4:
            label = "Start CPU"
        elif length == 1:
            label = "Stop CPU"
        else:
            label = "CPU Mode Change"
    else:
        label = f"Service 0x{svc:04x}"
    return [f"{direction}: {label}"]


def _detect_anomalies(
    payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]
) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    if any("Read Project/Program Info" in c and "Request" in c for c in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="ProConOS Program/Project Disclosure",
                description=(
                    "ProConOS read-project request — discloses the ladder-logic "
                    "runtime, PLC type and PROJECT SOURCE CODE (control-logic "
                    "upload / theft + device fingerprinting). Confirm it is an "
                    "authorized engineering station."
                ),
                src=src_ip,
                dst=dst_ip,
                ts=ts,
                attack="T0845 Program Upload; T0888 Remote System Information Discovery",
                evidence=[c for c in commands if c],
            )
        )
    if any(
        command.startswith("Request: ")
        and any(action in command for action in ("Start CPU", "Stop CPU", "CPU Mode Change"))
        for command in commands
    ):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="ProConOS CPU Mode Change",
                description=(
                    "ProConOS request to start or stop the PLC CPU observed. "
                    "Confirm the change was authorized."
                ),
                src=src_ip,
                dst=dst_ip,
                ts=ts,
                attack="T0858 Change Operating Mode",
                evidence=[c for c in commands if c],
            )
        )
    return anomalies


@memoize_analysis
def analyze_prconos(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="ProConOS",
        tcp_ports={PRCONOS_PORT},
        command_parser=_parse_commands,
        anomaly_detector=_detect_anomalies,
        enable_enrichment=True,
        show_status=show_status,
    )
    append_public_exposure_anomaly(analysis, "ProConOS")
    return analysis
