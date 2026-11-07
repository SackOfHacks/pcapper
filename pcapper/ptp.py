from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .pcap_cache import PcapMeta, iter_packets
from .utils import memoize_analysis, safe_float

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
PTP_HEADER_LENGTH = 34
VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}


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
    if len(payload) < PTP_HEADER_LENGTH:
        return None
    return int.from_bytes(payload[30:32], "big")


def _parse_ptp_header(payload: bytes) -> tuple[str, int, int, bytes] | str:
    if len(payload) < PTP_HEADER_LENGTH:
        return "truncated PTP common header"
    version = payload[1] & 0x0F
    if version != 2:
        return f"unsupported PTP version {version}"
    message_length = int.from_bytes(payload[2:4], "big")
    if message_length < PTP_HEADER_LENGTH:
        return "invalid PTP message length below common header size"
    if message_length > len(payload):
        return "truncated PTP message"
    return (
        _msg_type_name(payload[0] & 0x0F),
        payload[4],
        int.from_bytes(payload[30:32], "big"),
        payload[20:30],
    )


def _extract_ptp_payload(eth: object) -> bytes | None:
    ethertype = int(getattr(eth, "type", 0) or 0)
    layer = getattr(eth, "payload", None)
    while ethertype in VLAN_ETHERTYPES and layer is not None:
        ethertype = int(getattr(layer, "type", 0) or 0)
        layer = getattr(layer, "payload", None)
    if ethertype != PTP_ETHERTYPE or layer is None:
        return None
    return bytes(layer)


@memoize_analysis
def analyze_ptp(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> PtpSummary:
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
    seq_state: dict[tuple[bytes, int, str], int] = {}
    seq_regression_seen: set[tuple[bytes, int, str]] = set()
    unicast_dsts: set[str] = set()
    detections: list[dict[str, object]] = []
    errors: list[str] = []
    malformed_messages: Counter[str] = Counter()
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    for pkt in iter_packets(path, packets=packets, meta=meta, show_status=show_status):
        total_packets += 1
        ts = safe_float(getattr(pkt, "time", None))

        is_ptp = False
        payload = b""
        if Ether is not None and pkt.haslayer(Ether):  # type: ignore[truthy-bool]
            eth = pkt[Ether]  # type: ignore[index]
            try:
                l2_payload = _extract_ptp_payload(eth)
            except Exception as exc:
                malformed_messages[
                    f"could not decode Ethernet payload ({type(exc).__name__})"
                ] += 1
                l2_payload = None
            if l2_payload is not None:
                payload = l2_payload
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

        ip_src: str | None = None
        ip_dst: str | None = None
        source_label = str(getattr(pkt, "src", "?"))
        if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
            udp = pkt[UDP]  # type: ignore[index]
            sport = int(getattr(udp, "sport", 0) or 0)
            dport = int(getattr(udp, "dport", 0) or 0)
            if sport in {PTP_EVENT_PORT, PTP_GENERAL_PORT} or dport in {
                PTP_EVENT_PORT,
                PTP_GENERAL_PORT,
            }:
                is_ptp = True
                try:
                    payload = bytes(getattr(udp, "payload", b""))
                except Exception as exc:
                    malformed_messages[
                        f"could not decode UDP payload ({type(exc).__name__})"
                    ] += 1
                    payload = b""
                if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                    ip_src = str(pkt[IP].src)  # type: ignore[index]
                    ip_dst = str(pkt[IP].dst)  # type: ignore[index]
                    source_label = ip_src
                elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                    ip_src = str(pkt[IPv6].src)  # type: ignore[index]
                    ip_dst = str(pkt[IPv6].dst)  # type: ignore[index]
                    source_label = ip_src

        if not is_ptp:
            continue

        ptp_packets += 1
        # The report window spans this protocol's traffic, not every packet.
        if ts is not None:
            if first_seen is None or ts < first_seen:
                first_seen = ts
            if last_seen is None or ts > last_seen:
                last_seen = ts
        parsed_header = _parse_ptp_header(payload)
        if isinstance(parsed_header, str):
            malformed_messages[parsed_header] += 1
            continue
        msg_type, domain, seq_id, source_port_identity = parsed_header
        if ip_src is not None and ip_dst is not None:
            src_ips[ip_src] += 1
            dst_ips[ip_dst] += 1
            try:
                if not ipaddress.ip_address(ip_dst).is_multicast:
                    unicast_dsts.add(ip_dst)
            except ValueError:
                pass
        msg_types[msg_type] += 1
        domain_numbers[domain] += 1
        sequence_ids[seq_id] += 1
        seq_key = (source_port_identity, domain, msg_type)
        prev_seq = seq_state.get(seq_key)
        if prev_seq is not None:
            backward_step = (prev_seq - seq_id) & 0xFFFF
            if (
                0 < backward_step < 0x8000
                and seq_key not in seq_regression_seen
            ):
                seq_regression_seen.add(seq_key)
                detections.append(
                    {
                        "severity": "warning",
                        "summary": "PTP Sequence Decrease",
                        "details": (
                            f"{source_port_identity.hex()} domain {domain} "
                            f"{msg_type} seqId moved backward {prev_seq}->{seq_id}."
                        ),
                    }
                )
        seq_state[seq_key] = seq_id
        src_msg_types.setdefault(source_label, set()).add(msg_type)

    errors.extend(
        f"{count} malformed PTP message(s): {reason}."
        for reason, count in sorted(malformed_messages.items())
    )


    if ptp_packets:
        detections.append(
            {
                "severity": "info",
                "summary": "PTP time-sync traffic observed",
                "details": f"{ptp_packets} PTP packets detected (UDP 319/320 or L2).",
            }
        )
    for src, types in src_msg_types.items():
        if "Management" in types and len(types) >= 4:
            detections.append(
                {
                    "severity": "warning",
                    "summary": "PTP Management Activity",
                    "details": f"{src} used Management messages alongside {len(types)} PTP types (potential time control).",
                }
            )
    if unicast_dsts:
        detections.append(
            {
                "severity": "warning",
                "summary": "PTP Unicast Destinations",
                "details": f"PTP unicast destinations observed: {', '.join(sorted(unicast_dsts)[:5])}.",
            }
        )

    duration = (
        (last_seen - first_seen)
        if first_seen is not None and last_seen is not None
        else None
    )
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
