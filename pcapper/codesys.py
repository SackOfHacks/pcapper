from __future__ import annotations

import re
from pathlib import Path

from .industrial_helpers import (
    append_public_exposure_anomaly,
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
)
from .opcode_models import format_opcode, load_opcode_model
from .utils import memoize_analysis

# CoDeSys runtime (2455) + gateway (1217). Used by Schneider/Wago/Beckhoff and
# many CoDeSys-based PLCs; PIPEDREAM's Codesys module targets this stack.
CODESYS_PORTS = {2455, 1217}
CODESYS_MODEL_PATH = Path(__file__).with_name("codesys_opcodes.json")

CODESYS_KEYWORDS = {
    "login": "Login",
    "logout": "Logout",
    "download": "Download",
    "upload": "Upload",
    "start": "Start",
    "stop": "Stop",
    "reset": "Reset",
    "project": "Project",
    "application": "Application",
    "debug": "Debug",
    "codesys": "Banner",
}

CODESYS_OPCODE_PATTERN = re.compile(
    r"(?:opcode|op|cmd)\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)", re.IGNORECASE
)


def _load_model() -> object | None:
    return load_opcode_model(CODESYS_MODEL_PATH)


def _parse_commands(payload: bytes) -> list[str]:
    if not payload:
        return []
    text = payload[:400].decode("utf-8", errors="ignore").lower()
    commands: list[str] = []
    for key, label in CODESYS_KEYWORDS.items():
        if key in text:
            commands.append(f"CODESYS {label}")
    model = _load_model()
    for match in CODESYS_OPCODE_PATTERN.findall(text):
        commands.append(f"CODESYS Opcode {match}")
        if model is not None:
            try:
                opcode = (
                    int(match, 16)
                    if str(match).lower().startswith("0x")
                    else int(match)
                )
                label = getattr(model, "opcodes", {}).get(opcode)
                if label:
                    commands.append(f"CODESYS {label}")
            except Exception:
                pass
    if model is not None:
        for opcode, label, _offset in model.extract_opcodes(payload):
            commands.append(f"CODESYS Opcode {format_opcode(opcode, label)}")
    return commands


def _parse_artifacts(payload: bytes) -> list[tuple[str, str]]:
    artifacts: list[tuple[str, str]] = []
    if not payload:
        return artifacts
    text = payload[:400].decode("utf-8", errors="ignore")
    for match in CODESYS_OPCODE_PATTERN.findall(text):
        artifacts.append(("codesys_opcode", match))
    model = _load_model()
    if model is not None:
        for opcode, label, _offset in model.extract_opcodes(payload):
            artifacts.append(("codesys_opcode", format_opcode(opcode, label)))
    return artifacts


def _detect_anomalies(
    payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]
) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    if any(cmd in {"CODESYS Download", "CODESYS Upload"} for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="CODESYS Program Transfer",
                description="Download/upload activity observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(cmd in {"CODESYS Stop", "CODESYS Reset"} for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="CODESYS Control Operation",
                description="Stop/reset command observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    return anomalies


@memoize_analysis
def analyze_codesys(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="CODESYS",
        tcp_ports=CODESYS_PORTS,
        command_parser=_parse_commands,
        artifact_parser=_parse_artifacts,
        anomaly_detector=_detect_anomalies,
        enable_enrichment=True,
        show_status=show_status,
    )
    append_public_exposure_anomaly(analysis, "CODESYS")
    return analysis
