from __future__ import annotations

import uuid
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .pcap_cache import PcapMeta, iter_packets
from .utils import extract_packet_endpoints, memoize_analysis, safe_float

try:
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    IPv6 = None  # type: ignore


OPC_UUIDS = {
    "39c13a4d-011e-11d0-9675-0020afd8adb3": "OPC DA 2.0",
    "39c13a4e-011e-11d0-9675-0020afd8adb3": "OPC DA 3.0",
    "1b1f2a21-d10d-11d1-9a8f-00c04fc9e26e": "OPC AE",
    "7ea2d5b5-2b09-11d1-bcaa-00805fc59d7c": "OPC HDA",
    "f31dfde2-07b6-11d2-b2d8-0060083ba1fb": "OPC DX",
}


def _uuid_to_le_bytes(value: str) -> bytes:
    u = uuid.UUID(value)
    data = u.bytes_le
    return data


UUID_MARKERS = {value: _uuid_to_le_bytes(value) for value in OPC_UUIDS}


@dataclass(frozen=True)
class OpcClassicSummary:
    path: Path
    total_packets: int
    opc_packets: int
    interface_counts: Counter[str]
    client_counts: Counter[str]
    server_counts: Counter[str]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


_DCERPC_SERVER_PDUS = {2, 3, 12, 13, 15}  # response, fault, bind_ack, bind_nak, alter_context_resp


def _dcerpc_from_server(payload: bytes) -> bool:
    if len(payload) < 3 or payload[0] != 5:
        return False
    return payload[2] in _DCERPC_SERVER_PDUS


@memoize_analysis
def analyze_opc_classic(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> OpcClassicSummary:
    if TCP is None:
        return OpcClassicSummary(
            path,
            0,
            0,
            Counter(),
            Counter(),
            Counter(),
            [],
            ["Scapy TCP unavailable"],
            None,
            None,
            None,
        )

    total_packets = 0
    opc_packets = 0
    interface_counts: Counter[str] = Counter()
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    detections: list[dict[str, object]] = []
    errors: list[str] = []
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    for pkt in iter_packets(path, packets=packets, meta=meta, show_status=show_status):
        total_packets += 1
        ts = safe_float(getattr(pkt, "time", None))

        if not pkt.haslayer(TCP):  # type: ignore[truthy-bool]
            continue
        tcp = pkt[TCP]  # type: ignore[index]
        payload = bytes(getattr(tcp, "payload", b""))
        if not payload:
            continue

        matched = False
        for uuid_text, marker in UUID_MARKERS.items():
            if marker in payload:
                interface_counts[OPC_UUIDS[uuid_text]] += 1
                matched = True

        if not matched:
            continue

        src_ip, dst_ip = extract_packet_endpoints(pkt)
        if src_ip and dst_ip:
            # DCE/RPC PDU type (byte 2): bind/alter-context/request come from
            # the client, bind_ack/response from the server. The UUID marker
            # appears in both directions, so counting the sender of every
            # marked PDU as the client made each OPC server its own client.
            if _dcerpc_from_server(payload):
                client_counts[dst_ip] += 1
                server_counts[src_ip] += 1
            else:
                client_counts[src_ip] += 1
                server_counts[dst_ip] += 1

        opc_packets += 1
        # The report window spans this protocol's traffic, not every packet.
        if ts is not None:
            if first_seen is None or ts < first_seen:
                first_seen = ts
            if last_seen is None or ts > last_seen:
                last_seen = ts


    if opc_packets:
        detections.append(
            {
                "severity": "info",
                "summary": "OPC Classic (DCOM) indicators observed",
                "details": f"{opc_packets} packets with OPC Classic interface UUIDs detected.",
            }
        )

    duration = (
        (last_seen - first_seen)
        if first_seen is not None and last_seen is not None
        else None
    )
    return OpcClassicSummary(
        path=path,
        total_packets=total_packets,
        opc_packets=opc_packets,
        interface_counts=interface_counts,
        client_counts=client_counts,
        server_counts=server_counts,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
