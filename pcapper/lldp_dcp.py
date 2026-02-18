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


LLDP_ETHERTYPE = 0x88CC
PROFINET_ETHERTYPE = 0x8892


@dataclass(frozen=True)
class LldpDcpSummary:
    path: Path
    total_packets: int
    lldp_packets: int
    dcp_packets: int
    system_names: Counter[str]
    chassis_ids: Counter[str]
    port_ids: Counter[str]
    dcp_frame_ids: Counter[str]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


def _parse_lldp_tlvs(payload: bytes) -> tuple[Optional[str], Optional[str], Optional[str]]:
    chassis = None
    port = None
    sysname = None
    idx = 0
    while idx + 2 <= len(payload):
        tlv_header = int.from_bytes(payload[idx:idx + 2], "big")
        tlv_type = (tlv_header >> 9) & 0x7F
        tlv_len = tlv_header & 0x1FF
        idx += 2
        if tlv_len == 0:
            if tlv_type == 0:
                break
            continue
        value = payload[idx:idx + tlv_len]
        idx += tlv_len
        if tlv_type == 1 and value:
            chassis = value[1:].decode("utf-8", errors="ignore")
        elif tlv_type == 2 and value:
            port = value[1:].decode("utf-8", errors="ignore")
        elif tlv_type == 5:
            sysname = value.decode("utf-8", errors="ignore")
    return chassis, port, sysname


def analyze_lldp_dcp(path: Path, show_status: bool = True) -> LldpDcpSummary:
    if Ether is None:
        return LldpDcpSummary(path, 0, 0, 0, Counter(), Counter(), Counter(), Counter(), [], ["Scapy Ether unavailable"], None, None, None)

    reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)
    total_packets = 0
    lldp_packets = 0
    dcp_packets = 0
    system_names: Counter[str] = Counter()
    chassis_ids: Counter[str] = Counter()
    port_ids: Counter[str] = Counter()
    dcp_frame_ids: Counter[str] = Counter()
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
            try:
                payload = bytes(eth.payload)
            except Exception:
                payload = b""

            if eth_type == LLDP_ETHERTYPE:
                lldp_packets += 1
                chassis, port, sysname = _parse_lldp_tlvs(payload)
                if chassis:
                    chassis_ids[chassis] += 1
                if port:
                    port_ids[port] += 1
                if sysname:
                    system_names[sysname] += 1

            if eth_type == PROFINET_ETHERTYPE and len(payload) >= 2:
                dcp_packets += 1
                frame_id = int.from_bytes(payload[0:2], "big")
                dcp_frame_ids[f"0x{frame_id:04x}"] += 1

    finally:
        status.finish()
        reader.close()

    if lldp_packets:
        detections.append({
            "severity": "info",
            "summary": "LLDP asset discovery traffic observed",
            "details": f"{lldp_packets} LLDP frames detected.",
        })
    if dcp_packets:
        detections.append({
            "severity": "info",
            "summary": "PROFINET DCP discovery traffic observed",
            "details": f"{dcp_packets} PROFINET DCP frames detected.",
        })

    duration = (last_seen - first_seen) if first_seen is not None and last_seen is not None else None
    return LldpDcpSummary(
        path=path,
        total_packets=total_packets,
        lldp_packets=lldp_packets,
        dcp_packets=dcp_packets,
        system_names=system_names,
        chassis_ids=chassis_ids,
        port_ids=port_ids,
        dcp_frame_ids=dcp_frame_ids,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
