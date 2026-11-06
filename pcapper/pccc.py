from __future__ import annotations

from pathlib import Path

from .industrial_helpers import (
    append_public_exposure_anomaly,
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
)
from .df1 import _extract_df1_frames, _parse_df1_frame
from .utils import memoize_analysis

def _match_signature(payload: bytes) -> bool:
    return any(_parse_df1_frame(frame) is not None for frame in _extract_df1_frames(payload))


def _parse_commands(payload: bytes) -> list[str]:
    commands: list[str] = []
    for frame in _extract_df1_frames(payload):
        parsed = _parse_df1_frame(frame)
        if parsed is not None:
            command, _is_write = parsed
            commands.append(command.replace("DF1 ", "PCCC ", 1))
    return commands


def _detect_anomalies(
    payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]
) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    if any("Logical Write" in cmd for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="PCCC Write Operation",
                description="PCCC logical write command observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    for frame in _extract_df1_frames(payload):
        parsed = _parse_df1_frame(frame)
        if parsed is None:
            continue
        _command, is_write = parsed
        if is_write and len(frame) > 256:
            anomalies.append(
                IndustrialAnomaly(
                    severity="HIGH",
                    title="PCCC Large Write Payload",
                    description="Large PCCC write payload observed (possible program download).",
                    src=src_ip,
                    dst=dst_ip,
                    ts=ts,
                )
            )
            break
    return anomalies


@memoize_analysis
def analyze_pccc(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="PCCC",
        signature_matcher=_match_signature,
        command_parser=_parse_commands,
        anomaly_detector=_detect_anomalies,
        enable_enrichment=True,
        show_status=show_status,
    )
    append_public_exposure_anomaly(analysis, "PCCC")
    return analysis
