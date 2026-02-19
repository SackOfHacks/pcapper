from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from collections import Counter

from .modbus import analyze_modbus
from .dnp3 import analyze_dnp3
from .iec104 import analyze_iec104
from .s7 import analyze_s7
from .cip import analyze_cip
from .opc import analyze_opc
from .odesys import analyze_odesys
from .pccc import analyze_pccc
from .pcworx import analyze_pcworx
from .prconos import analyze_prconos
from .niagara import analyze_niagara
from .mqtt import analyze_mqtt


@dataclass(frozen=True)
class OtCommandSummary:
    path: Path
    command_counts: Counter[str]
    sources: Counter[str]
    destinations: Counter[str]
    detections: list[dict[str, object]]
    errors: list[str]


WRITE_MARKERS = ("write", "operate", "select", "control", "set", "download", "stop", "start", "close", "open")


def _count_from_counter(counter: Counter[str], label: str, out: Counter[str]) -> None:
    for key, count in counter.items():
        text = str(key).lower()
        if any(marker in text for marker in WRITE_MARKERS):
            out[f"{label}:{key}"] += count


def _count_from_artifacts(artifacts: list[object], label: str, out: Counter[str], sources: Counter[str], destinations: Counter[str]) -> None:
    for item in artifacts or []:
        detail = str(getattr(item, "detail", "")).lower()
        if not detail:
            continue
        if any(marker in detail for marker in WRITE_MARKERS):
            out[f"{label}:payload"] += 1
            sources[str(getattr(item, "src", "-"))] += 1
            destinations[str(getattr(item, "dst", "-"))] += 1


def analyze_ot_commands(path: Path, show_status: bool = True) -> OtCommandSummary:
    command_counts: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    destinations: Counter[str] = Counter()
    errors: list[str] = []

    modbus = analyze_modbus(path, show_status=show_status)
    _count_from_counter(modbus.func_counts, "Modbus", command_counts)
    errors.extend(modbus.errors or [])
    for msg in getattr(modbus, "messages", []) or []:
        if "write" in msg.func_name.lower():
            sources[msg.src_ip] += 1
            destinations[msg.dst_ip] += 1

    dnp3 = analyze_dnp3(path, show_status=show_status)
    _count_from_counter(dnp3.func_counts, "DNP3", command_counts)
    errors.extend(dnp3.errors or [])
    for msg in getattr(dnp3, "messages", []) or []:
        if any(marker in msg.func_name.lower() for marker in WRITE_MARKERS):
            sources[msg.src_ip] += 1
            destinations[msg.dst_ip] += 1

    iec = analyze_iec104(path, show_status=show_status)
    _count_from_counter(getattr(iec, "type_counts", Counter()), "IEC104", command_counts)
    errors.extend(getattr(iec, "errors", []) or [])
    for art in getattr(iec, "artifacts", []) or []:
        detail = str(getattr(art, "detail", "")).lower()
        if any(marker in detail for marker in WRITE_MARKERS):
            sources[str(getattr(art, "src", "-"))] += 1
            destinations[str(getattr(art, "dst", "-"))] += 1

    s7 = analyze_s7(path, show_status=show_status)
    _count_from_counter(getattr(s7, "command_counts", Counter()), "S7", command_counts)
    errors.extend(getattr(s7, "errors", []) or [])
    for art in getattr(s7, "artifacts", []) or []:
        detail = str(getattr(art, "detail", "")).lower()
        if any(marker in detail for marker in WRITE_MARKERS):
            sources[str(getattr(art, "src", "-"))] += 1
            destinations[str(getattr(art, "dst", "-"))] += 1

    cip = analyze_cip(path, show_status=show_status)
    _count_from_counter(getattr(cip, "cip_services", Counter()), "CIP", command_counts)
    errors.extend(getattr(cip, "errors", []) or [])
    for art in getattr(cip, "artifacts", []) or []:
        detail = str(getattr(art, "detail", "")).lower()
        if any(marker in detail for marker in WRITE_MARKERS):
            sources[str(getattr(art, "src", "-"))] += 1
            destinations[str(getattr(art, "dst", "-"))] += 1

    opc = analyze_opc(path, show_status=show_status)
    _count_from_artifacts(getattr(opc, "artifacts", []) or [], "OPC", command_counts, sources, destinations)
    errors.extend(getattr(opc, "errors", []) or [])

    odesys = analyze_odesys(path, show_status=show_status)
    _count_from_artifacts(getattr(odesys, "artifacts", []) or [], "ODESYS", command_counts, sources, destinations)
    errors.extend(getattr(odesys, "errors", []) or [])

    pccc = analyze_pccc(path, show_status=show_status)
    _count_from_artifacts(getattr(pccc, "artifacts", []) or [], "PCCC", command_counts, sources, destinations)
    errors.extend(getattr(pccc, "errors", []) or [])

    pcworx = analyze_pcworx(path, show_status=show_status)
    _count_from_artifacts(getattr(pcworx, "artifacts", []) or [], "PCWorx", command_counts, sources, destinations)
    errors.extend(getattr(pcworx, "errors", []) or [])

    prconos = analyze_prconos(path, show_status=show_status)
    _count_from_artifacts(getattr(prconos, "artifacts", []) or [], "ProConOS", command_counts, sources, destinations)
    errors.extend(getattr(prconos, "errors", []) or [])

    niagara = analyze_niagara(path, show_status=show_status)
    _count_from_artifacts(getattr(niagara, "artifacts", []) or [], "Niagara", command_counts, sources, destinations)
    errors.extend(getattr(niagara, "errors", []) or [])

    mqtt = analyze_mqtt(path, show_status=show_status)
    _count_from_artifacts(getattr(mqtt, "artifacts", []) or [], "MQTT", command_counts, sources, destinations)
    errors.extend(getattr(mqtt, "errors", []) or [])

    detections: list[dict[str, object]] = []
    if command_counts:
        detections.append({
            "severity": "warning",
            "summary": "OT control/write command activity observed",
            "details": "; ".join(f"{cmd} ({count})" for cmd, count in command_counts.most_common(8)),
        })

    return OtCommandSummary(
        path=path,
        command_counts=command_counts,
        sources=sources,
        destinations=destinations,
        detections=detections,
        errors=errors,
    )
