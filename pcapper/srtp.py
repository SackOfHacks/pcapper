from __future__ import annotations

from pathlib import Path

from .industrial_helpers import (
    append_public_exposure_anomaly,
    IndustrialAnalysis,
    analyze_port_protocol,
)
from .utils import memoize_analysis

SRTP_TCP_PORTS = {18245, 18246}
SRTP_UDP_PORTS = {18246}


@memoize_analysis
def analyze_srtp(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="GE SRTP",
        tcp_ports=SRTP_TCP_PORTS,
        udp_ports=SRTP_UDP_PORTS,
        enable_enrichment=True,
        show_status=show_status,
    )
    append_public_exposure_anomaly(analysis, "GE SRTP")
    return analysis
