from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .pcap_cache import get_reader
from .utils import safe_float

try:
    from scapy.layers.inet import IP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.layers.l2 import Ether  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore
    Ether = None  # type: ignore


PTP_EVENT_PORT = 319
PTP_GENERAL_PORT = 320
PTP_ETHERTYPE = 0x88F7


@dataclass(frozen=True)
class PtpSummary:
    path: Path
    total_packets: int
    ptp_packets: int
    msg_types: Counter[str]
    src_macs: Counter[str]
    dst_macs: Counter[str]
    src_ips: Counter[str]
    dst_ips: Counter[str]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


def _msg_type_name(value: int) -> str:
    return {
        0x0: "Sync",
        0x1: "Delay_Req",
        0x2: "Pdelay_Req",
        0x3: "Pdelay_Resp",
        0x8: "Follow_Up",
        0x9: "Delay_Resp",
        0xA: "Pdelay_Resp_Follow_Up",
        0xB: "Announce",
        0xC: "Signaling",
        0xD: "Management",
    }.get(value, f"type_{value}")


def _parse_ptp_message_type(payload: bytes) -> Optional[str]:
    if not payload:
        return None
    msg_type = payload[0] & 0x0F
    return _msg_type_name(msg_type)


def analyze_ptp(path: Path, show_status: bool = True) -> PtpSummary:
    reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)
    total_packets = 0
    ptp_packets = 0
    msg_types: Counter[str] = Counter()
    src_macs: Counter[str] = Counter()
    dst_macs: Counter[str] = Counter()
    src_ips: Counter[str] = Counter()
    dst_ips: Counter[str] = Counter()
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

            is_ptp = False
            payload = b""
            if Ether is not None and pkt.haslayer(Ether):  # type: ignore[truthy-bool]
                eth = pkt[Ether]  # type: ignore[index]
                if int(getattr(eth, "type", 0) or 0) == PTP_ETHERTYPE:
                    try:
                        payload = bytes(eth.payload)
                    except Exception:
                        payload = b""
                    is_ptp = True
                    src_macs[str(getattr(eth, "src", "-"))] += 1
                    dst_macs[str(getattr(eth, "dst", "-"))] += 1

            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp = pkt[UDP]  # type: ignore[index]
                sport = int(getattr(udp, "sport", 0) or 0)
                dport = int(getattr(udp, "dport", 0) or 0)
                if sport in {PTP_EVENT_PORT, PTP_GENERAL_PORT} or dport in {PTP_EVENT_PORT, PTP_GENERAL_PORT}:
                    is_ptp = True
                    payload = bytes(getattr(udp, "payload", b""))
                    if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                        src_ips[str(pkt[IP].src)] += 1  # type: ignore[index]
                        dst_ips[str(pkt[IP].dst)] += 1  # type: ignore[index]
                    elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                        src_ips[str(pkt[IPv6].src)] += 1  # type: ignore[index]
                        dst_ips[str(pkt[IPv6].dst)] += 1  # type: ignore[index]

            if not is_ptp:
                continue

            ptp_packets += 1
            msg_type = _parse_ptp_message_type(payload)
            if msg_type:
                msg_types[msg_type] += 1

    finally:
        status.finish()
        reader.close()

    if ptp_packets:
        detections.append({
            "severity": "info",
            "summary": "PTP time-sync traffic observed",
            "details": f"{ptp_packets} PTP packets detected (UDP 319/320 or L2).",
        })

    duration = (last_seen - first_seen) if first_seen is not None and last_seen is not None else None
    return PtpSummary(
        path=path,
        total_packets=total_packets,
        ptp_packets=ptp_packets,
        msg_types=msg_types,
        src_macs=src_macs,
        dst_macs=dst_macs,
        src_ips=src_ips,
        dst_ips=dst_ips,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
