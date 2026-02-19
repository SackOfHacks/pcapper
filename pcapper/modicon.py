from __future__ import annotations

from pathlib import Path
import ipaddress
import struct

from .industrial_helpers import IndustrialAnalysis, IndustrialAnomaly, analyze_port_protocol

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
}

WRITE_FUNCTIONS = {5, 6, 15, 16}


def _parse_commands(payload: bytes) -> list[str]:
    if len(payload) < 8:
        return []
    try:
        _trans_id, proto_id, _length, _unit_id = struct.unpack(">HHHB", payload[:7]
        )
        if proto_id != 0:
            return []
        func = payload[7]
        return [FUNC_NAMES.get(func, f"Func {func}")]
    except Exception:
        return []

def _detect_anomalies(payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]) -> list[IndustrialAnomaly]:
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
    return anomalies


def analyze_modicon(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="Modicon",
        tcp_ports={MODICON_PORT},
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
                title="Modicon Exposure to Public IP",
                description=f"Modicon traffic observed with public endpoint(s): {', '.join(sorted(public_endpoints)[:5])}.",
                src="*",
                dst="*",
                ts=0.0,
            )
        )
    return analysis
