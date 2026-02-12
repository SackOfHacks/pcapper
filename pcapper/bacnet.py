from __future__ import annotations

from pathlib import Path

from .industrial_helpers import IndustrialAnalysis, IndustrialAnomaly, analyze_port_protocol

BACNET_PORT = 47808

BVLC_FUNCTIONS = {
    0x00: "BVLC-Result",
    0x01: "Write-Broadcast-Distribution-Table",
    0x02: "Read-Broadcast-Distribution-Table",
    0x03: "Read-Broadcast-Distribution-Table-Ack",
    0x04: "Forwarded-NPDU",
    0x05: "Register-Foreign-Device",
    0x06: "Read-Foreign-Device-Table",
    0x07: "Delete-Foreign-Device-Table",
    0x08: "Distribute-Broadcast-To-Network",
    0x09: "Original-Unicast-NPDU",
    0x0A: "Original-Broadcast-NPDU",
}


def _parse_commands(payload: bytes) -> list[str]:
    if len(payload) < 2:
        return []
    bvlc_type = payload[0]
    bvlc_func = payload[1]
    cmds = []
    if bvlc_type == 0x81:
        cmds.append("BVLC")
        cmds.append(BVLC_FUNCTIONS.get(bvlc_func, f"BVLC Func {bvlc_func}"))
    return cmds


def _detect_anomalies(payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    if any("Register-Foreign-Device" in cmd for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="LOW",
                title="BACnet Foreign Device Registration",
                description="Foreign device registration observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any("Delete-Foreign-Device-Table" in cmd for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="MEDIUM",
                title="BACnet Foreign Device Table Modification",
                description="Foreign device table deletion observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    return anomalies


def analyze_bacnet(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_port_protocol(
        path=path,
        protocol_name="BACnet",
        tcp_ports={BACNET_PORT},
        udp_ports={BACNET_PORT},
        command_parser=_parse_commands,
        anomaly_detector=_detect_anomalies,
        show_status=show_status,
    )
