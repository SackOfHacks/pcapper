from __future__ import annotations

import ipaddress
from pathlib import Path

from .industrial_helpers import (
    append_public_exposure_anomaly,
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
)

PCWORX_PORT = 1962

# PCWorx (Phoenix Contact ILC/AXC PLCs) message types. byte0 = 0x01 request /
# 0x81 response; byte1 = function. Derived from the Redpoint pcworx-info probe
# and validated against 4SICS PCWorx traffic.
PCWORX_FUNCTIONS = {
    0x01: "Connect/Init",
    0x05: "Setup Communication",
    0x06: "Read PLC Info (type/firmware)",
}


def _parse_commands(payload: bytes) -> list[str]:
    if len(payload) < 2 or payload[0] not in (0x01, 0x81):
        return []
    direction = "Request" if payload[0] == 0x01 else "Response"
    func = PCWORX_FUNCTIONS.get(payload[1], f"Function 0x{payload[1]:02x}")
    return [f"{direction}: {func}"]


def _detect_anomalies(
    payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]
) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    # Reading the PLC type / firmware is the device-fingerprinting step that
    # precedes targeted OT attacks (the Redpoint pcworx-info probe). Flag it as
    # remote system information discovery.
    if any("Read PLC Info" in c and "Request" in c for c in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="MEDIUM",
                title="PCWorx PLC Information Disclosure",
                description=(
                    "PCWorx Read-PLC-Info request (type/firmware enumeration) — "
                    "device fingerprinting that precedes targeted OT attacks. "
                    "Confirm it originates from an authorized engineering station."
                ),
                src=src_ip,
                dst=dst_ip,
                ts=ts,
                attack="T0888 Remote System Information Discovery",
                evidence=[c for c in commands if c],
            )
        )
    return anomalies


def analyze_pcworx(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="PCWorx",
        tcp_ports={PCWORX_PORT},
        command_parser=_parse_commands,
        anomaly_detector=_detect_anomalies,
        enable_enrichment=True,
        show_status=show_status,
    )
    append_public_exposure_anomaly(analysis, "PCWorx")
    return analysis
