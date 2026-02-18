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


def analyze_ot_commands(path: Path, show_status: bool = True) -> OtCommandSummary:
    command_counts: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    destinations: Counter[str] = Counter()
    errors: list[str] = []

    modbus = analyze_modbus(path, show_status=show_status)
    _count_from_counter(modbus.func_counts, "Modbus", command_counts)
    for msg in getattr(modbus, "messages", []) or []:
        if "write" in msg.func_name.lower():
            sources[msg.src_ip] += 1
            destinations[msg.dst_ip] += 1

    dnp3 = analyze_dnp3(path, show_status=show_status)
    _count_from_counter(dnp3.func_counts, "DNP3", command_counts)
    for msg in getattr(dnp3, "messages", []) or []:
        if any(marker in msg.func_name.lower() for marker in WRITE_MARKERS):
            sources[msg.src_ip] += 1
            destinations[msg.dst_ip] += 1

    iec = analyze_iec104(path, show_status=show_status)
    _count_from_counter(getattr(iec, "type_counts", Counter()), "IEC104", command_counts)
    for art in getattr(iec, "artifacts", []) or []:
        detail = str(getattr(art, "detail", "")).lower()
        if any(marker in detail for marker in WRITE_MARKERS):
            sources[str(getattr(art, "src", "-"))] += 1
            destinations[str(getattr(art, "dst", "-"))] += 1

    s7 = analyze_s7(path, show_status=show_status)
    _count_from_counter(getattr(s7, "command_counts", Counter()), "S7", command_counts)
    for art in getattr(s7, "artifacts", []) or []:
        detail = str(getattr(art, "detail", "")).lower()
        if any(marker in detail for marker in WRITE_MARKERS):
            sources[str(getattr(art, "src", "-"))] += 1
            destinations[str(getattr(art, "dst", "-"))] += 1

    cip = analyze_cip(path, show_status=show_status)
    _count_from_counter(getattr(cip, "cip_services", Counter()), "CIP", command_counts)
    for art in getattr(cip, "artifacts", []) or []:
        detail = str(getattr(art, "detail", "")).lower()
        if any(marker in detail for marker in WRITE_MARKERS):
            sources[str(getattr(art, "src", "-"))] += 1
            destinations[str(getattr(art, "dst", "-"))] += 1

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
