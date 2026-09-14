from __future__ import annotations

from pathlib import Path

from .industrial_helpers import (
    IndustrialAnalysis,
    analyze_port_protocol,
    append_public_exposure_anomaly,
)
from .utils import memoize_analysis

# Bristol Standard Asynchronous Protocol over IP (BSAP-IP) — Emerson/Bristol
# Babcock SCADA for gas/oil flow computers and RTUs, carried on UDP 1234/1235.
# The framing is vendor-specific (no authoritative public function-code map), so
# this is a presence + internet-exposure detector (an exposed BSAP RTU network
# is a high-value finding) rather than a command-level decoder.
BSAP_PORTS = {1234, 1235}


@memoize_analysis
def analyze_bsap(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="BSAP-IP",
        udp_ports=BSAP_PORTS,
        tcp_ports=BSAP_PORTS,
        enable_enrichment=True,
        show_status=show_status,
    )
    append_public_exposure_anomaly(analysis, "BSAP-IP")
    return analysis
