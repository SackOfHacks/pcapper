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


def analyze_honeywell(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="Honeywell CDA",
        signature_matcher=_match_signature,
        enable_enrichment=True,
        show_status=show_status,
    )
    append_public_exposure_anomaly(analysis, "Honeywell CDA")
    return analysis
