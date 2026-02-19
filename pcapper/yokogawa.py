from __future__ import annotations

from pathlib import Path
import ipaddress

from .industrial_helpers import IndustrialAnalysis, IndustrialAnomaly, analyze_port_protocol

YOKOGAWA_PORTS = {34378, 34379, 34380}

YOKOGAWA_KEYWORDS = {
    "read": "Read",
    "write": "Write",
    "set": "Set",
    "control": "Control",
    "cmd": "Command",
}


def _parse_commands(payload: bytes) -> list[str]:
    commands: list[str] = []
    if payload:
        commands.append(f"YOKO Cmd 0x{payload[0]:02x}")
    text = payload[:200].decode("utf-8", errors="ignore").lower()
    for key, label in YOKOGAWA_KEYWORDS.items():
        if key in text:
            commands.append(f"YOKO {label}")
    return commands


def _detect_anomalies(payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    if any(cmd == "YOKO Write" for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="Yokogawa Write Operation",
                description="Yokogawa Vnet/IP write/control operation observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    return anomalies


def analyze_yokogawa(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="Yokogawa Vnet/IP",
        tcp_ports=YOKOGAWA_PORTS,
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
                title="Yokogawa Vnet/IP Exposure to Public IP",
                description=f"Yokogawa Vnet/IP traffic observed with public endpoint(s): {', '.join(sorted(public_endpoints)[:5])}.",
                src="*",
                dst="*",
                ts=0.0,
            )
        )
    return analysis
