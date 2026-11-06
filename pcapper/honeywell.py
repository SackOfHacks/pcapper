from __future__ import annotations

from pathlib import Path

from .industrial_helpers import (
    append_public_exposure_anomaly,
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
)
from .utils import memoize_analysis

HONEYWELL_CDA_PORT = 55565


def _detect_anomalies(
    payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]
) -> list[IndustrialAnomaly]:
    # CDA is proprietary, so identify its documented service port without
    # claiming command-level visibility.
    return [
        IndustrialAnomaly(
            severity="info",
            title="Honeywell CDA Traffic",
            description=(
                "Traffic on the Honeywell CDA/Experion service port observed. "
                "The protocol is proprietary, so command content is not decoded; "
                "confirm the endpoints are authorized."
            ),
            src=src_ip,
            dst=dst_ip,
            ts=ts,
            attack="T0888 Remote System Information Discovery",
            evidence=[],
        )
    ]


@memoize_analysis
def analyze_honeywell(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="Honeywell CDA",
        tcp_ports={HONEYWELL_CDA_PORT},
        anomaly_detector=_detect_anomalies,
        enable_enrichment=True,
        show_status=show_status,
    )
    append_public_exposure_anomaly(analysis, "Honeywell CDA")
    return analysis
