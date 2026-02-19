from __future__ import annotations

from pathlib import Path
import ipaddress

from .industrial_helpers import IndustrialAnalysis, IndustrialAnomaly, analyze_port_protocol

HART_PORT = 5094


def analyze_hart(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="HART-IP",
        tcp_ports={HART_PORT},
        udp_ports={HART_PORT},
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
                title="HART-IP Exposure to Public IP",
                description=f"HART-IP traffic observed with public endpoint(s): {', '.join(sorted(public_endpoints)[:5])}.",
                src="*",
                dst="*",
                ts=0.0,
            )
        )
    return analysis
