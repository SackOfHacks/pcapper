from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .pcap_cache import get_reader
from .utils import safe_float
from .device_detection import device_fingerprints_from_text

try:
    from scapy.layers.l2 import Ether  # type: ignore
except Exception:  # pragma: no cover
    Ether = None  # type: ignore


LLDP_ETHERTYPE = 0x88CC
PROFINET_ETHERTYPE = 0x8892

DCP_SERVICE_IDS = {
    0x03: "Identify",
    0x04: "Set",
    0x05: "Get",
    0x06: "Hello",
    0x07: "Get-Enum",
    0x08: "Reset",
}

DCP_SERVICE_TYPES = {
    0x00: "Request",
    0x01: "Response",
}

DCP_OPTIONS = {
    0x01: "IP",
    0x02: "Device",
    0x03: "DHCP",
    0x04: "Control",
}

DCP_SUBOPTIONS = {
    (0x01, 0x02): "IP Parameters",
    (0x02, 0x01): "Device Vendor",
    (0x02, 0x02): "Device Name",
    (0x02, 0x03): "Device ID",
    (0x04, 0x02): "Reset",
}


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
    dcp_services: Counter[str]
    dcp_device_names: Counter[str]
    dcp_ips: Counter[str]
    artifacts: list["LldpDcpArtifact"]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


@dataclass(frozen=True)
class LldpDcpArtifact:
    kind: str
    detail: str
    src: str
    dst: str


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


def _decode_dcp_blocks(payload: bytes, offset: int) -> list[tuple[int, int, bytes]]:
    blocks: list[tuple[int, int, bytes]] = []
    ptr = offset
    while ptr + 4 <= len(payload):
        option = payload[ptr]
        suboption = payload[ptr + 1]
        block_len = int.from_bytes(payload[ptr + 2:ptr + 4], "big")
        ptr += 4
        if block_len <= 0 or ptr + block_len > len(payload):
            break
        block = payload[ptr:ptr + block_len]
        ptr += block_len
        blocks.append((option, suboption, block))
    return blocks


def _parse_dcp(payload: bytes) -> tuple[list[str], list[str], list[str]]:
    services: list[str] = []
    names: list[str] = []
    ips: list[str] = []
    if len(payload) < 12:
        return services, names, ips
    service_id = payload[2]
    service_type = payload[3]
    service_name = DCP_SERVICE_IDS.get(service_id, f"Service 0x{service_id:02x}")
    type_name = DCP_SERVICE_TYPES.get(service_type, f"Type 0x{service_type:02x}")
    services.append(f"{service_name} {type_name}")

    data_len = int.from_bytes(payload[10:12], "big")
    block_start = 12
    if data_len and block_start + data_len <= len(payload):
        blocks = _decode_dcp_blocks(payload, block_start)
    else:
        blocks = _decode_dcp_blocks(payload, block_start)

    for option, suboption, block in blocks:
        data = block[2:] if len(block) >= 2 else block
        if (option, suboption) == (0x02, 0x02) and data:
            name = data.decode("utf-8", errors="ignore").strip("\x00").strip()
            if name:
                names.append(name)
        if (option, suboption) == (0x01, 0x02) and len(data) >= 12:
            ip = ".".join(str(b) for b in data[0:4])
            mask = ".".join(str(b) for b in data[4:8])
            gw = ".".join(str(b) for b in data[8:12])
            ips.append(f"{ip} mask {mask} gw {gw}")
    return services, names, ips


def analyze_lldp_dcp(path: Path, show_status: bool = True) -> LldpDcpSummary:
    if Ether is None:
        return LldpDcpSummary(
            path,
            0,
            0,
            0,
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            [],
            [],
            ["Scapy Ether unavailable"],
            None,
            None,
            None,
        )

    reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)
    total_packets = 0
    lldp_packets = 0
    dcp_packets = 0
    system_names: Counter[str] = Counter()
    chassis_ids: Counter[str] = Counter()
    port_ids: Counter[str] = Counter()
    dcp_frame_ids: Counter[str] = Counter()
    dcp_services: Counter[str] = Counter()
    dcp_device_names: Counter[str] = Counter()
    dcp_ips: Counter[str] = Counter()
    artifacts: list[LldpDcpArtifact] = []
    seen_device_artifacts: set[str] = set()
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
                    for detail in device_fingerprints_from_text(sysname, source="LLDP system name"):
                        key = f"device:{detail}"
                        if key in seen_device_artifacts:
                            continue
                        seen_device_artifacts.add(key)
                        artifacts.append(LldpDcpArtifact(kind="device", detail=detail, src=eth.src, dst=eth.dst))

            if eth_type == PROFINET_ETHERTYPE and len(payload) >= 2:
                dcp_packets += 1
                frame_id = int.from_bytes(payload[0:2], "big")
                dcp_frame_ids[f"0x{frame_id:04x}"] += 1
                if 0xFE00 <= frame_id <= 0xFEFF:
                    services, names, ips = _parse_dcp(payload)
                    for svc in services:
                        dcp_services[svc] += 1
                    for name in names:
                        dcp_device_names[name] += 1
                        for detail in device_fingerprints_from_text(name, source="DCP device name"):
                            key = f"device:{detail}"
                            if key in seen_device_artifacts:
                                continue
                            seen_device_artifacts.add(key)
                            artifacts.append(LldpDcpArtifact(kind="device", detail=detail, src=eth.src, dst=eth.dst))
                    for ip in ips:
                        dcp_ips[ip] += 1

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
    if len(system_names) >= 25 or len(chassis_ids) >= 25:
        detections.append({
            "severity": "warning",
            "summary": "LLDP Reconnaissance Pattern",
            "details": f"Large LLDP inventory footprint (systems={len(system_names)} chassis={len(chassis_ids)}).",
        })
    if dcp_packets >= 500 or len(dcp_frame_ids) >= 20:
        detections.append({
            "severity": "warning",
            "summary": "DCP Activity Spike",
            "details": f"High DCP activity (frames={dcp_packets} unique_frame_ids={len(dcp_frame_ids)}).",
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
        dcp_services=dcp_services,
        dcp_device_names=dcp_device_names,
        dcp_ips=dcp_ips,
        artifacts=artifacts,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
