from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .pcap_cache import get_reader
from .utils import safe_float

try:
    from scapy.layers.l2 import Ether  # type: ignore
except Exception:  # pragma: no cover
    Ether = None  # type: ignore


GOOSE_ETHERTYPE = 0x88B8


@dataclass(frozen=True)
class GooseSummary:
    path: Path
    total_packets: int
    goose_packets: int
    src_macs: Counter[str]
    dst_macs: Counter[str]
    app_ids: Counter[str]
    lengths: Counter[int]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


def _extract_appid(payload: bytes) -> Optional[int]:
    if len(payload) < 4:
        return None
    return int.from_bytes(payload[0:2], "big")


def _extract_length(payload: bytes) -> Optional[int]:
    if len(payload) < 4:
        return None
    return int.from_bytes(payload[2:4], "big")


def analyze_goose(path: Path, show_status: bool = True) -> GooseSummary:
    if Ether is None:
        return GooseSummary(path, 0, 0, Counter(), Counter(), Counter(), Counter(), [], ["Scapy Ether unavailable"], None, None, None)

    reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)
    total_packets = 0
    goose_packets = 0
    src_macs: Counter[str] = Counter()
    dst_macs: Counter[str] = Counter()
    app_ids: Counter[str] = Counter()
    lengths: Counter[int] = Counter()
    detections: list[dict[str, object]] = []
    errors: list[str] = []
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    status.update(int(min(100, (pos / size_bytes) * 100)))
                except Exception:
                    pass

            total_packets += 1
            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            if not pkt.haslayer(Ether):  # type: ignore[truthy-bool]
                continue
            eth = pkt[Ether]  # type: ignore[index]
            eth_type = int(getattr(eth, "type", 0) or 0)
            if eth_type != GOOSE_ETHERTYPE:
                continue

            goose_packets += 1
            src_macs[str(getattr(eth, "src", "-"))] += 1
            dst_macs[str(getattr(eth, "dst", "-"))] += 1
            try:
                payload = bytes(eth.payload)
            except Exception:
                payload = b""
            appid = _extract_appid(payload)
            if appid is not None:
                app_ids[f"0x{appid:04x}"] += 1
            length = _extract_length(payload)
            if length is not None:
                lengths[length] += 1

    finally:
        status.finish()
        reader.close()

    if goose_packets:
        detections.append({
            "severity": "info",
            "summary": "IEC 61850 GOOSE traffic observed",
            "details": f"{goose_packets} GOOSE frames detected at L2.",
        })

    duration = (last_seen - first_seen) if first_seen is not None and last_seen is not None else None
    return GooseSummary(
        path=path,
        total_packets=total_packets,
        goose_packets=goose_packets,
        src_macs=src_macs,
        dst_macs=dst_macs,
        app_ids=app_ids,
        lengths=lengths,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
