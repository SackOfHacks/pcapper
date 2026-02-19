from __future__ import annotations

from pathlib import Path
import ipaddress
import re

from .industrial_helpers import IndustrialAnalysis, IndustrialAnomaly, analyze_port_protocol
from .opcode_models import load_opcode_model, format_opcode

NIAGARA_PORTS = {1911, 4911}
NIAGARA_MODEL_PATH = Path(__file__).with_name("niagara_opcodes.json")

NIAGARA_KEYWORDS = {
    "fox": "FOX",
    "station": "Station",
    "slot": "Slot",
    "ord": "ORD",
    "baja": "Baja",
    "query": "Query",
    "put": "Put",
    "delete": "Delete",
    "invoke": "Invoke",
}

ORD_PATTERN = re.compile(r"ord:[^\\s\\x00]+", re.IGNORECASE)
OPCODE_PATTERN = re.compile(r"(?:opcode|op)\\s*[:=]\\s*(0x[0-9a-fA-F]+|\\d+)", re.IGNORECASE)


def _load_model() -> object | None:
    return load_opcode_model(NIAGARA_MODEL_PATH)


def _parse_commands(payload: bytes) -> list[str]:
    if not payload:
        return []
    text = payload[:400].decode("utf-8", errors="ignore").lower()
    commands: list[str] = []
    for key, label in NIAGARA_KEYWORDS.items():
        if key in text:
            commands.append(f"Niagara {label}")
    for match in OPCODE_PATTERN.findall(text):
        commands.append(f"Niagara Opcode {match}")
    model = _load_model()
    if model is not None:
        for opcode, label, _offset in model.extract_opcodes(payload):
            commands.append(f"Niagara Opcode {format_opcode(opcode, label)}")
    return commands


def _parse_artifacts(payload: bytes) -> list[tuple[str, str]]:
    artifacts: list[tuple[str, str]] = []
    text = payload[:800].decode("utf-8", errors="ignore")
    for match in ORD_PATTERN.findall(text):
        artifacts.append(("niagara_ord", match))
    if "slot:" in text.lower():
        for token in text.split():
            if token.lower().startswith("slot:"):
                artifacts.append(("niagara_slot", token))
    for match in OPCODE_PATTERN.findall(text):
        artifacts.append(("niagara_opcode", match))
    model = _load_model()
    if model is not None:
        for opcode, label, _offset in model.extract_opcodes(payload):
            artifacts.append(("niagara_opcode", format_opcode(opcode, label)))
    return artifacts


def _detect_anomalies(payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    if any(cmd in {"Niagara Put", "Niagara Delete", "Niagara Invoke"} for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="Niagara Fox Write/Invoke",
                description="Niagara Fox write/invoke operation observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    return anomalies


def analyze_niagara(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="Niagara Fox",
        tcp_ports=NIAGARA_PORTS,
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
                title="Niagara Exposure to Public IP",
                description=f"Niagara Fox traffic observed with public endpoint(s): {', '.join(sorted(public_endpoints)[:5])}.",
                src="*",
                dst="*",
                ts=0.0,
            )
        )
    return analysis
