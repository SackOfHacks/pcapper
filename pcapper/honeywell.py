from __future__ import annotations

import ipaddress
from pathlib import Path

from .industrial_helpers import (
    append_public_exposure_anomaly,
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
)

# NOTE: the 3-byte token b"CDA" was removed -- with no port constraint this
# matcher scans every payload, and "CDA" occurs constantly in unrelated traffic
# ("CDATA" in XML, base64, random binary), producing rampant false "Honeywell
# CDA" detections (and public-IP-exposure anomalies) on non-OT captures. Only
# the unambiguous vendor strings are kept.
HONEYWELL_SIGNATURES = (b"Honeywell", b"HONEYWELL")


def _match_signature(payload: bytes) -> bool:
    return any(sig in payload for sig in HONEYWELL_SIGNATURES)


def _detect_anomalies(
    payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]
) -> list[IndustrialAnomaly]:
    # The Honeywell CDA / Experion protocol is proprietary and undocumented, so
    # only asset identification is possible (no command-level parsing). Flag the
    # presence of Honeywell control-system traffic so the analyst can scope the
    # DCS/asset and confirm the talkers are authorized.
    if not _match_signature(payload):
        return []
    return [
        IndustrialAnomaly(
            severity="info",
            title="Honeywell Control-System Traffic",
            description=(
                "Honeywell DCS/control-system (CDA/Experion) traffic observed — "
                "asset identification; the protocol is proprietary so command "
                "content is not decoded. Confirm the endpoints are authorized."
            ),
            src=src_ip,
            dst=dst_ip,
            ts=ts,
            attack="T0888 Remote System Information Discovery",
            evidence=[],
        )
    ]


def analyze_honeywell(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="Honeywell CDA",
        signature_matcher=_match_signature,
        anomaly_detector=_detect_anomalies,
        enable_enrichment=True,
        show_status=show_status,
    )
    append_public_exposure_anomaly(analysis, "Honeywell CDA")
    return analysis
