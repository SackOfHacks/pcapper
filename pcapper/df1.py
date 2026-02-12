from __future__ import annotations

from pathlib import Path

from .industrial_helpers import IndustrialAnalysis, analyze_port_protocol

DF1_SIGNATURES = (b"\x10\x02", b"\x10\x03", b"\x10\x06")


def _match_signature(payload: bytes) -> bool:
    return any(sig in payload for sig in DF1_SIGNATURES)


def _parse_commands(payload: bytes) -> list[str]:
    if _match_signature(payload):
        return ["DF1 Frame"]
    return []


def analyze_df1(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_port_protocol(
        path=path,
        protocol_name="DF1",
        signature_matcher=_match_signature,
        command_parser=_parse_commands,
        show_status=show_status,
    )
