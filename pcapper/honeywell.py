from __future__ import annotations

from pathlib import Path

from .industrial_helpers import IndustrialAnalysis, analyze_port_protocol

HONEYWELL_SIGNATURES = (b"CDA", b"Honeywell", b"HONEYWELL")


def _match_signature(payload: bytes) -> bool:
    return any(sig in payload for sig in HONEYWELL_SIGNATURES)


def analyze_honeywell(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_port_protocol(
        path=path,
        protocol_name="Honeywell CDA",
        signature_matcher=_match_signature,
        show_status=show_status,
    )
