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
    domain_numbers: Counter[int]
    sequence_ids: Counter[int]
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


def _parse_ptp_domain(payload: bytes) -> Optional[int]:
    if len(payload) < 5:
        return None
    return payload[4]


def _parse_ptp_sequence(payload: bytes) -> Optional[int]:
    if len(payload) < 32:
        return None
    return int.from_bytes(payload[30:32], "big")


def analyze_ptp(path: Path, show_status: bool = True) -> PtpSummary:
    reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)
    total_packets = 0
    ptp_packets = 0
    msg_types: Counter[str] = Counter()
    domain_numbers: Counter[int] = Counter()
    sequence_ids: Counter[int] = Counter()
    src_macs: Counter[str] = Counter()
    dst_macs: Counter[str] = Counter()
    src_ips: Counter[str] = Counter()
    dst_ips: Counter[str] = Counter()
    src_msg_types: dict[str, set[str]] = {}
    seq_state: dict[tuple[str, int | None], int] = {}
    unicast_dsts: set[str] = set()
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
                    src_mac = str(getattr(eth, "src", "-"))
                    dst_mac = str(getattr(eth, "dst", "-"))
                    src_macs[src_mac] += 1
                    dst_macs[dst_mac] += 1
                    try:
                        first_octet = int(dst_mac.split(":")[0], 16)
                        if (first_octet & 1) == 0:
                            unicast_dsts.add(dst_mac)
                    except Exception:
                        pass

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
                domain = _parse_ptp_domain(payload)
                if domain is not None:
                    domain_numbers[domain] += 1
                seq_id = _parse_ptp_sequence(payload)
                if seq_id is not None:
                    sequence_ids[seq_id] += 1
                    seq_key = (str(getattr(pkt, "src", "?")), domain)
                    prev_seq = seq_state.get(seq_key)
                    if prev_seq is not None and seq_id < prev_seq:
                        detections.append({
                            "severity": "warning",
                            "summary": "PTP Sequence Decrease",
                            "details": f"{seq_key[0]} domain {domain} seqId decreased {prev_seq}->{seq_id}.",
                        })
                    seq_state[seq_key] = seq_id
                src_key = str(getattr(pkt, "src", "?"))
                if src_macs:
                    src_key = next(iter(src_macs.keys()))
                if src_macs:
                    src_mac = next(iter(src_macs.keys()))
                    src_msg_types.setdefault(src_mac, set()).add(msg_type)
                else:
                    src_msg_types.setdefault(src_key, set()).add(msg_type)

    finally:
        status.finish()
        reader.close()

    if ptp_packets:
        detections.append({
            "severity": "info",
            "summary": "PTP time-sync traffic observed",
            "details": f"{ptp_packets} PTP packets detected (UDP 319/320 or L2).",
        })
    for src, types in src_msg_types.items():
        if "Management" in types and len(types) >= 4:
            detections.append({
                "severity": "warning",
                "summary": "PTP Management Activity",
                "details": f"{src} used Management messages alongside {len(types)} PTP types (potential time control).",
            })
    if unicast_dsts:
        detections.append({
            "severity": "warning",
            "summary": "PTP Unicast Destinations",
            "details": f"Unicast PTP MAC destinations observed: {', '.join(sorted(unicast_dsts)[:5])}.",
        })

    duration = (last_seen - first_seen) if first_seen is not None and last_seen is not None else None
    return PtpSummary(
        path=path,
        total_packets=total_packets,
        ptp_packets=ptp_packets,
        msg_types=msg_types,
        domain_numbers=domain_numbers,
        sequence_ids=sequence_ids,
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
