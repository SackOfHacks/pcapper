from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import ipaddress
from typing import Optional

from .pcap_cache import get_reader
from .utils import safe_float

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore


@dataclass(frozen=True)
class Iec101103Summary:
    path: Path
    total_packets: int
    candidate_packets: int
    client_counts: Counter[str]
    server_counts: Counter[str]
    type_counts: Counter[str]
    cause_counts: Counter[str]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


CAUSES = {
    1: "Periodic",
    2: "Background",
    3: "Spontaneous",
    4: "Initialized",
    5: "Request",
    6: "Activation",
    7: "Activation Confirmation",
    8: "Deactivation",
    9: "Deactivation Confirmation",
    10: "Activation Termination",
}


def _parse_asdu(payload: bytes) -> tuple[Optional[str], Optional[str]]:
    if len(payload) < 9:
        return None, None
    if payload[0] != 0x68:
        return None, None
    if len(payload) >= 6 and payload[3] == 0x68:
        idx = 4
        if idx + 1 >= len(payload):
            return None, None
        idx += 1
        if idx + 1 >= len(payload):
            return None, None
        idx += 1
    else:
        idx = 6
    if idx + 6 > len(payload):
        return None, None
    type_id = payload[idx]
    vsq = payload[idx + 1]
    _ = vsq
    cot_raw = int.from_bytes(payload[idx + 2:idx + 4], "little")
    cot = cot_raw & 0x3F
    cause_name = CAUSES.get(cot, f"COT {cot}")
    type_name = f"ASDU {type_id}"
    return type_name, cause_name


def _iec_apdu_candidate(payload: bytes) -> bool:
    if not payload or len(payload) < 4:
        return False
    if payload[0] != 0x68:
        return False
    length = payload[1]
    return 4 <= length <= 255


def analyze_iec101_103(path: Path, show_status: bool = True) -> Iec101103Summary:
    reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)
    total_packets = 0
    candidate_packets = 0
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    type_counts: Counter[str] = Counter()
    cause_counts: Counter[str] = Counter()
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

            payload = b""
            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                payload = bytes(getattr(pkt[TCP], "payload", b""))  # type: ignore[index]
            elif UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                payload = bytes(getattr(pkt[UDP], "payload", b""))  # type: ignore[index]
            if not _iec_apdu_candidate(payload):
                continue

            src_ip = None
            dst_ip = None
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                src_ip = str(pkt[IP].src)  # type: ignore[index]
                dst_ip = str(pkt[IP].dst)  # type: ignore[index]
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                src_ip = str(pkt[IPv6].src)  # type: ignore[index]
                dst_ip = str(pkt[IPv6].dst)  # type: ignore[index]
            if not src_ip or not dst_ip:
                continue

            candidate_packets += 1
            client_counts[src_ip] += 1
            server_counts[dst_ip] += 1

            type_name, cause_name = _parse_asdu(payload)
            if type_name:
                type_counts[type_name] += 1
            if cause_name:
                cause_counts[cause_name] += 1

    finally:
        status.finish()
        reader.close()

    if candidate_packets:
        detections.append({
            "severity": "info",
            "summary": "IEC 60870-5-101/103 candidate traffic observed",
            "details": f"{candidate_packets} packets matched IEC 101/103 APDU framing heuristics.",
        })
    unique_clients = len(client_counts)
    unique_servers = len(server_counts)
    if unique_servers >= 20 and candidate_packets >= 50:
        detections.append({
            "severity": "warning",
            "summary": "IEC 101/103 Broad Polling Pattern",
            "details": f"{unique_clients} clients contacted {unique_servers} servers (possible scanning or wide polling).",
        })
    public_endpoints = []
    for ip_value in set(client_counts) | set(server_counts):
        try:
            if ipaddress.ip_address(ip_value).is_global:
                public_endpoints.append(ip_value)
        except Exception:
            continue
    if public_endpoints:
        detections.append({
            "severity": "high",
            "summary": "IEC 101/103 Exposure to Public IP",
            "details": f"IEC 101/103 candidate traffic observed with public endpoint(s): {', '.join(sorted(public_endpoints)[:5])}.",
        })

    duration = (last_seen - first_seen) if first_seen is not None and last_seen is not None else None
    return Iec101103Summary(
        path=path,
        total_packets=total_packets,
        candidate_packets=candidate_packets,
        client_counts=client_counts,
        server_counts=server_counts,
        type_counts=type_counts,
        cause_counts=cause_counts,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
