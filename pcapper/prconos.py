from __future__ import annotations

import ipaddress
from pathlib import Path

from .industrial_helpers import (
    append_public_exposure_anomaly,
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
)

PRCONOS_PORT = 20547

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
    return anomalies


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
