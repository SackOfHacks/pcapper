from __future__ import annotations

from pathlib import Path
import ipaddress

from .industrial_helpers import IndustrialAnalysis, IndustrialAnomaly, analyze_port_protocol

PCCC_PORTS = {2222, 44818}

PCCC_COMMANDS = {
    0x0A: "Unprotected Logical Read",
    0x0B: "Unprotected Logical Write",
    0x0C: "Typed Logical Read",
    0x0D: "Typed Logical Write",
    0x0E: "Protected Typed Logical Read",
    0x0F: "Protected Typed Logical Write",
}

PCCC_WRITE_CMDS = {0x0B, 0x0D, 0x0F}


def _extract_pccc_frames(payload: bytes) -> list[bytes]:
    frames: list[bytes] = []
    idx = 0
    while idx + 1 < len(payload):
        if payload[idx] == 0x10 and payload[idx + 1] == 0x02:
            idx += 2
            data = bytearray()
            while idx + 1 < len(payload):
                if payload[idx] == 0x10:
                    if payload[idx + 1] == 0x10:
                        data.append(0x10)
                        idx += 2
                        continue
                    if payload[idx + 1] == 0x03:
                        idx += 2
                        break
                data.append(payload[idx])
                idx += 1
            if data:
                frames.append(bytes(data))
            continue
        idx += 1
    return frames


def _parse_commands(payload: bytes) -> list[str]:
    commands: list[str] = []
    for frame in _extract_pccc_frames(payload):
        if len(frame) < 4:
            continue
        cmd = frame[2]
        name = PCCC_COMMANDS.get(cmd, f"Command 0x{cmd:02x}")
        commands.append(f"PCCC {name}")
    if not commands and payload:
        commands.append("PCCC Frame")
    return commands


def _detect_anomalies(payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    if any("Logical Write" in cmd for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="PCCC Write Operation",
                description="PCCC logical write command observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    for frame in _extract_pccc_frames(payload):
        if len(frame) < 4:
            continue
        cmd = frame[2]
        if cmd in PCCC_WRITE_CMDS and len(frame) > 256:
            anomalies.append(
                IndustrialAnomaly(
                    severity="HIGH",
                    title="PCCC Large Write Payload",
                    description="Large PCCC write payload observed (possible program download).",
                    src=src_ip,
                    dst=dst_ip,
                    ts=ts,
                )
            )
            break
    return anomalies


def analyze_pccc(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="PCCC",
        tcp_ports=PCCC_PORTS,
        udp_ports=PCCC_PORTS,
        command_parser=_parse_commands,
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
                title="PCCC Exposure to Public IP",
                description=f"PCCC traffic observed with public endpoint(s): {', '.join(sorted(public_endpoints)[:5])}.",
                src="*",
                dst="*",
                ts=0.0,
            )
        )
    return analysis
