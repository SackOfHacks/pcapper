from __future__ import annotations

import ipaddress
from pathlib import Path

from .industrial_helpers import (
    append_public_exposure_anomaly,
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
)

FINS_PORT = 9600

FINS_COMMANDS = {
    0x0101: "Memory Area Read",
    0x0102: "Memory Area Write",
}


def _parse_commands(payload: bytes) -> list[str]:
    if len(payload) < 12:
        return []
    cmd = int.from_bytes(payload[10:12], "big")
    label = FINS_COMMANDS.get(cmd, f"CMD 0x{cmd:04x}")
    return [label]


def _detect_anomalies(
    payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]
) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    if any("Write" in cmd for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="MEDIUM",
                title="FINS Write Operation",
                description="FINS memory write operation observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    return anomalies


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
