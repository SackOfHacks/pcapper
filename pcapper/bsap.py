from __future__ import annotations

import ipaddress
from pathlib import Path

from .industrial_helpers import (
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
)

# Bristol Standard Asynchronous Protocol over IP (BSAP-IP) — Emerson/Bristol
# Babcock SCADA for gas/oil flow computers and RTUs, carried on UDP 1234/1235.
# The framing is vendor-specific (no authoritative public function-code map), so
# this is a presence + internet-exposure detector (an exposed BSAP RTU network
# is a high-value finding) rather than a command-level decoder.
BSAP_PORTS = {1234, 1235}


def analyze_bsap(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="BSAP-IP",
        udp_ports=BSAP_PORTS,
        tcp_ports=BSAP_PORTS,
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
                title="BSAP Exposure to Public IP",
                description=(
                    "BSAP-IP (Bristol/Emerson SCADA) traffic observed with public "
                    f"endpoint(s): {', '.join(sorted(public_endpoints)[:5])}."
                ),
                src="*",
                dst="*",
                ts=0.0,
            )
        )
    return analysis
