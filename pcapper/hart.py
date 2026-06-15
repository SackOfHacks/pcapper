from __future__ import annotations

import ipaddress
from pathlib import Path

from .industrial_helpers import (
    append_public_exposure_anomaly,
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
)

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
    append_public_exposure_anomaly(analysis, "HART-IP")
    return analysis
