from __future__ import annotations

import ipaddress
from pathlib import Path

from .industrial_helpers import (
    append_public_exposure_anomaly,
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
)

CSP_PORTS = {2222, 44818}


def analyze_csp(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="CSP",
        tcp_ports=CSP_PORTS,
        udp_ports=CSP_PORTS,
        enable_enrichment=True,
        show_status=show_status,
    )
    append_public_exposure_anomaly(analysis, "CSP")
    return analysis
