from __future__ import annotations

from pathlib import Path
import ipaddress

from .industrial_helpers import IndustrialAnalysis, IndustrialAnomaly, analyze_port_protocol

SRTP_TCP_PORTS = {18245, 18246}
SRTP_UDP_PORTS = {18246}

SRTP_KEYWORDS = {
    "read": "Read",
    "write": "Write",
    "set": "Set",
    "control": "Control",
    "cmd": "Command",
}


def _parse_commands(payload: bytes) -> list[str]:
    commands: list[str] = []
    if payload:
        commands.append(f"SRTP Cmd 0x{payload[0]:02x}")
    text = payload[:200].decode("utf-8", errors="ignore").lower()
    for key, label in SRTP_KEYWORDS.items():
        if key in text:
            commands.append(f"SRTP {label}")
    return commands


def _detect_anomalies(payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    if any(cmd == "SRTP Write" for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="GE SRTP Write Operation",
                description="SRTP write/control operation observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    return anomalies


def analyze_srtp(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="GE SRTP",
        tcp_ports=SRTP_TCP_PORTS,
        udp_ports=SRTP_UDP_PORTS,
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
                title="GE SRTP Exposure to Public IP",
                description=f"GE SRTP traffic observed with public endpoint(s): {', '.join(sorted(public_endpoints)[:5])}.",
                src="*",
                dst="*",
                ts=0.0,
            )
        )
    return analysis
