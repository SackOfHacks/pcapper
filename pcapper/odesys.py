from __future__ import annotations

from pathlib import Path
import ipaddress
import re

from .industrial_helpers import IndustrialAnalysis, IndustrialAnomaly, analyze_port_protocol
from .opcode_models import load_opcode_model, format_opcode

ODESYS_PORTS = {2455, 1217}
ODESYS_MODEL_PATH = Path(__file__).with_name("odesys_opcodes.json")

ODESYS_KEYWORDS = {
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
    "codesys": "CODESYS",
}

ODESYS_OPCODE_PATTERN = re.compile(r"(?:opcode|op|cmd)\\s*[:=]\\s*(0x[0-9a-fA-F]+|\\d+)", re.IGNORECASE)


def _load_model() -> object | None:
    return load_opcode_model(ODESYS_MODEL_PATH)


def _parse_commands(payload: bytes) -> list[str]:
    if not payload:
        return []
    text = payload[:400].decode("utf-8", errors="ignore").lower()
    commands: list[str] = []
    for key, label in ODESYS_KEYWORDS.items():
        if key in text:
            commands.append(f"ODESYS {label}")
    model = _load_model()
    for match in ODESYS_OPCODE_PATTERN.findall(text):
        commands.append(f"ODESYS Opcode {match}")
        if model is not None:
            try:
                opcode = int(match, 16) if str(match).lower().startswith("0x") else int(match)
                label = getattr(model, "opcodes", {}).get(opcode)
                if label:
                    commands.append(f"ODESYS {label}")
            except Exception:
                pass
    if model is not None:
        for opcode, label, _offset in model.extract_opcodes(payload):
            commands.append(f"ODESYS Opcode {format_opcode(opcode, label)}")
    return commands


def _parse_artifacts(payload: bytes) -> list[tuple[str, str]]:
    artifacts: list[tuple[str, str]] = []
    if not payload:
        return artifacts
    text = payload[:400].decode("utf-8", errors="ignore")
    for match in ODESYS_OPCODE_PATTERN.findall(text):
        artifacts.append(("odesys_opcode", match))
    model = _load_model()
    if model is not None:
        for opcode, label, _offset in model.extract_opcodes(payload):
            artifacts.append(("odesys_opcode", format_opcode(opcode, label)))
    return artifacts


def _detect_anomalies(payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    if any(cmd in {"ODESYS Download", "ODESYS Upload"} for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="ODESYS Program Transfer",
                description="Download/upload activity observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(cmd in {"ODESYS Stop", "ODESYS Reset"} for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="ODESYS Control Operation",
                description="Stop/reset command observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    return anomalies


def analyze_odesys(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="ODESYS",
        tcp_ports=ODESYS_PORTS,
        command_parser=_parse_commands,
        artifact_parser=_parse_artifacts,
        anomaly_detector=_detect_anomalies,
        enable_enrichment=True,
        show_status=show_status,
    )
    public_endpoints = []
    for ip_value in set(analysis.src_ips) | set(analysis.dst_ips):
        try:
            if ipaddress.ip_address(ip_value).is_global:
                public_endpoints.append(ip_value)
        except Exception:
            continue
    if public_endpoints and len(analysis.anomalies) < 200:
        analysis.anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="ODESYS Exposure to Public IP",
                description=f"ODESYS traffic observed with public endpoint(s): {', '.join(sorted(public_endpoints)[:5])}.",
                src="*",
                dst="*",
                ts=0.0,
            )
        )
    return analysis
