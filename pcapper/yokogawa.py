from __future__ import annotations

from pathlib import Path

from .industrial_helpers import (
    append_public_exposure_anomaly,
    IndustrialAnalysis,
    analyze_port_protocol,
)
from .utils import memoize_analysis

YOKOGAWA_VNET_IP_UDP_PORT = 5313


@memoize_analysis
def analyze_yokogawa(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="Yokogawa Vnet/IP",
        udp_ports={YOKOGAWA_VNET_IP_UDP_PORT},
        enable_enrichment=True,
        show_status=show_status,
    )
    append_public_exposure_anomaly(analysis, "Yokogawa Vnet/IP")
    return analysis
