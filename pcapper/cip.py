from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional
import ipaddress

try:
    from scapy.layers.inet import TCP, UDP, IP
    from scapy.packet import Raw
except ImportError:  # pragma: no cover - scapy optional at runtime
    TCP = UDP = IP = Raw = None

from .equipment import equipment_artifacts
from .industrial_helpers import IndustrialArtifact, IndustrialAnomaly
from .pcap_cache import get_reader
from .utils import safe_float

CIP_TCP_PORT = 44818
CIP_UDP_PORT = 2222
CIP_SECURITY_PORT = 2221

ENIP_COMMANDS = {
    0x0001: "NOP",
    0x0004: "ListServices",
    0x0063: "ListIdentity",
    0x0064: "ListInterfaces",
    0x0065: "RegisterSession",
    0x0066: "UnregisterSession",
    0x0067: "SendRRData",
    0x0068: "SendUnitData",
    0x0069: "IndicateStatus",
    0x006A: "Cancel",
    0x006B: "FindNextObjectInstance",
    0x006C: "ReadObjectInstanceAttributes",
    0x006D: "WriteObjectInstanceAttributes",
    0x006F: "SendRRData",
    0x0070: "SendUnitData",
}

CIP_SERVICE_NAMES = {
    0x01: "Get_Attributes_All",
    0x02: "Set_Attributes_All",
    0x03: "Get_Attribute_List",
    0x04: "Set_Attribute_List",
    0x05: "Reset",
    0x06: "Start",
    0x07: "Stop",
    0x08: "Create",
    0x09: "Delete",
    0x0A: "Multiple_Service_Packet",
    0x0E: "Get_Attribute_Single",
    0x0F: "Set_Attribute_Single",
    0x10: "Find_Next_Object_Instance",
    0x11: "Restore",
    0x12: "Save",
    0x13: "No_Operation",
    0x4B: "ReadTag",
    0x4C: "WriteTag",
    0x4D: "ReadTagFragmented",
    0x4E: "WriteTagFragmented",
    0x4F: "ReadModifyWriteTag",
    0x50: "Get_Instance_Attribute_List",
    0x51: "Forward_Close",
    0x52: "ResetService",
    0x54: "ReadData",
    0x55: "WriteData",
    0x5C: "Forward_Open",
    0x73: "ProgramUpload",
    0x74: "ProgramDownload",
    0x75: "ProgramCommand",
    0x91: "GetConnectionOwner",
}

CIP_GENERAL_STATUS = {
    0x00: "Success",
    0x01: "Connection failure",
    0x02: "Resource unavailable",
    0x03: "Invalid parameter",
    0x04: "Path segment error",
    0x05: "Path destination unknown",
    0x06: "Partial transfer",
    0x07: "Connection lost",
    0x08: "Service not supported",
    0x09: "Invalid Attribute",
    0x0B: "Device state conflict",
    0x0C: "Reply data too large",
    0x0E: "Not enough data",
    0x13: "Vendor specific error",
}

CIP_CLASS_NAMES = {
    0x01: "Identity",
    0x02: "Message Router",
    0x03: "DeviceNet",
    0x04: "Assembly",
    0x05: "Connection",
    0x06: "Connection Manager",
    0x07: "Register",
    0x08: "Discrete Input Point",
    0x09: "Discrete Output Point",
    0x0A: "Analog Input Point",
    0x0B: "Analog Output Point",
    0x0C: "Analog Input Group",
    0x0D: "Analog Output Group",
    0x0E: "Programmable Controller",
    0x0F: "Discrete Input Group",
    0x10: "Discrete Output Group",
    0x11: "Discrete Group",
}

CIP_ATTRIBUTE_NAMES = {
    0x01: {
        1: "Vendor ID",
        2: "Device Type",
        3: "Product Code",
        4: "Revision",
        5: "Status",
        6: "Serial Number",
        7: "Product Name",
    },
    0x04: {
        3: "Data",
    },
    0x05: {
        1: "State",
        2: "Instance Type",
    },
    0x06: {
        1: "Open Connections",
        2: "Max Connections",
    },
    0x0E: {
        1: "Status",
        2: "Mode",
    },
}

CIP_DATA_TYPES = {
    0xC1: "BOOL",
    0xC2: "SINT",
    0xC3: "INT",
    0xC4: "DINT",
    0xC5: "LINT",
    0xC6: "USINT",
    0xC7: "UINT",
    0xC8: "UDINT",
    0xC9: "ULINT",
    0xCA: "REAL",
    0xCB: "LREAL",
}

CIP_SAFETY_CLASS_IDS = {0x43, 0x44}
CIP_SECURITY_CLASS_IDS = {0x64}

SUSPICIOUS_SERVICE_CODES = {
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    0x4C,
    0x4E,
    0x4F,
    0x51,
    0x52,
    0x55,
    0x5C,
    0x73,
    0x74,
    0x75,
}

HIGH_RISK_SERVICE_CODES = {
    0x05,
    0x06,
    0x07,
    0x4C,
    0x4E,
    0x4F,
    0x55,
    0x74,
    0x75,
}

CONTROL_SERVICE_CODES = {
    0x05,
    0x06,
    0x07,
    0x52,
}

PROGRAM_SERVICE_CODES = {
    0x73,
    0x74,
    0x75,
}

WRITE_SERVICE_CODES = {
    0x02,
    0x04,
    0x0F,
    0x4C,
    0x4E,
    0x4F,
    0x55,
}

ENUMERATION_SERVICE_CODES = {
    0x01,
    0x03,
    0x0E,
    0x4B,
    0x4D,
    0x50,
}

SIZE_BUCKETS = [
    (0, 19, "0-19"),
    (20, 39, "20-39"),
    (40, 79, "40-79"),
    (80, 159, "80-159"),
    (160, 319, "160-319"),
    (320, 639, "320-639"),
    (640, 1279, "640-1279"),
    (1280, 2559, "1280-2559"),
    (2560, 5119, "2560-5119"),
    (5120, 65535, "5120+"),
]

WRITE_BASELINE_MIN = 10


@dataclass(frozen=True)
class SizeBucket:
    label: str
    count: int
    avg: float
    min: int
    max: int
    pct: float


@dataclass
class CIPAnalysis:
    path: Path
    duration: float = 0.0
    total_packets: int = 0
    cip_packets: int = 0
    total_bytes: int = 0
    cip_bytes: int = 0
    requests: int = 0
    responses: int = 0
    connected_packets: int = 0
    unconnected_packets: int = 0
    io_packets: int = 0
    src_ips: Counter[str] = field(default_factory=Counter)
    dst_ips: Counter[str] = field(default_factory=Counter)
    client_ips: Counter[str] = field(default_factory=Counter)
    server_ips: Counter[str] = field(default_factory=Counter)
    sessions: Counter[str] = field(default_factory=Counter)
    enip_commands: Counter[str] = field(default_factory=Counter)
    cip_services: Counter[str] = field(default_factory=Counter)
    high_risk_services: Counter[str] = field(default_factory=Counter)
    suspicious_services: Counter[str] = field(default_factory=Counter)
    source_risky_commands: Counter[str] = field(default_factory=Counter)
    source_enum_commands: Counter[str] = field(default_factory=Counter)
    server_error_responses: Counter[str] = field(default_factory=Counter)
    service_error_counts: Counter[str] = field(default_factory=Counter)
    service_endpoints: dict[str, Counter[str]] = field(default_factory=dict)
    class_ids: Counter[int] = field(default_factory=Counter)
    instance_ids: Counter[int] = field(default_factory=Counter)
    attribute_ids: Counter[int] = field(default_factory=Counter)
    status_codes: Counter[str] = field(default_factory=Counter)
    packet_size_buckets: list[SizeBucket] = field(default_factory=list)
    payload_size_buckets: list[SizeBucket] = field(default_factory=list)
    artifacts: list[IndustrialArtifact] = field(default_factory=list)
    anomalies: list[IndustrialAnomaly] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def merge_cip_summaries(summaries: list[CIPAnalysis]) -> CIPAnalysis:
    if not summaries:
        return CIPAnalysis(path=Path("ALL_PCAPS_0"))

    merged = CIPAnalysis(path=Path(f"ALL_PCAPS_{len(summaries)}"))
    error_seen: set[str] = set()

    for summary in summaries:
        merged.duration += summary.duration
        merged.total_packets += summary.total_packets
        merged.cip_packets += summary.cip_packets
        merged.total_bytes += summary.total_bytes
        merged.cip_bytes += summary.cip_bytes
        merged.requests += summary.requests
        merged.responses += summary.responses
        merged.connected_packets += summary.connected_packets
        merged.unconnected_packets += summary.unconnected_packets
        merged.io_packets += summary.io_packets

        merged.src_ips.update(summary.src_ips)
        merged.dst_ips.update(summary.dst_ips)
        merged.client_ips.update(summary.client_ips)
        merged.server_ips.update(summary.server_ips)
        merged.sessions.update(summary.sessions)
        merged.enip_commands.update(summary.enip_commands)
        merged.cip_services.update(summary.cip_services)
        merged.high_risk_services.update(summary.high_risk_services)
        merged.suspicious_services.update(summary.suspicious_services)
        merged.source_risky_commands.update(summary.source_risky_commands)
        merged.source_enum_commands.update(summary.source_enum_commands)
        merged.server_error_responses.update(summary.server_error_responses)
        merged.service_error_counts.update(summary.service_error_counts)
        merged.class_ids.update(summary.class_ids)
        merged.instance_ids.update(summary.instance_ids)
        merged.attribute_ids.update(summary.attribute_ids)
        merged.status_codes.update(summary.status_codes)

        for service, counter in summary.service_endpoints.items():
            merged.service_endpoints.setdefault(service, Counter()).update(counter)

        merged.artifacts.extend(summary.artifacts)
        merged.anomalies.extend(summary.anomalies)

        for err in summary.errors:
            if err in error_seen:
                continue
            error_seen.add(err)
            merged.errors.append(err)

    return merged


def _extract_transport(pkt) -> tuple[bool, str, str, int, int, bytes]:
    src_ip = "?"
    dst_ip = "?"
    sport = 0
    dport = 0
    payload = b""

    if TCP is not None and pkt.haslayer(TCP):
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
        payload_obj = pkt[TCP].payload
        payload = bytes(payload_obj) if payload_obj else b""
        if not payload and Raw is not None and pkt.haslayer(Raw):
            try:
                payload = bytes(pkt[Raw].load)
            except Exception:
                pass
    elif UDP is not None and pkt.haslayer(UDP):
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)
        payload_obj = pkt[UDP].payload
        payload = bytes(payload_obj) if payload_obj else b""
        if not payload and Raw is not None and pkt.haslayer(Raw):
            try:
                payload = bytes(pkt[Raw].load)
            except Exception:
                pass
    else:
        return False, src_ip, dst_ip, sport, dport, payload

    if IP is not None and pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
    else:
        src_ip = pkt[0].src if hasattr(pkt[0], "src") else "?"
        dst_ip = pkt[0].dst if hasattr(pkt[0], "dst") else "?"

    return True, src_ip, dst_ip, sport, dport, payload


def _format_ascii(payload: bytes, limit: int = 200) -> str:
    if not payload:
        return ""
    text = payload[:limit].decode("utf-8", errors="ignore")
    cleaned = "".join(ch if ch.isprintable() else " " for ch in text)
    return " ".join(cleaned.split())


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except Exception:
        return False


def _parse_cpf(data: bytes) -> tuple[Optional[bytes], bool]:
    if len(data) < 6:
        return None, False
    ptr = 0
    ptr += 4
    ptr += 2
    if ptr + 2 > len(data):
        return None, False
    item_count = int.from_bytes(data[ptr:ptr + 2], "little")
    ptr += 2
    cip_payload: Optional[bytes] = None
    is_connected = False
    for _ in range(item_count):
        if ptr + 4 > len(data):
            break
        item_type = int.from_bytes(data[ptr:ptr + 2], "little")
        item_length = int.from_bytes(data[ptr + 2:ptr + 4], "little")
        ptr += 4
        item_data = data[ptr:ptr + item_length]
        ptr += item_length
        if item_type in {0x00B1, 0x00B2, 0x00B4}:
            cip_payload = item_data
            if item_type != 0x00B1:
                is_connected = True
    return cip_payload, is_connected


def _parse_enip(payload: bytes) -> tuple[Optional[int], Optional[str], Optional[int], Optional[bytes], bool]:
    if len(payload) < 24:
        return None, None, None, payload, False
    command = int.from_bytes(payload[0:2], "little")
    length = int.from_bytes(payload[2:4], "little")
    status = int.from_bytes(payload[8:12], "little")
    encap_data = payload[24:24 + length]
    is_connected = False
    cip_payload = encap_data or None
    if command in {0x006F, 0x0070}:
        cip_payload, is_connected = _parse_cpf(encap_data)
    return command, ENIP_COMMANDS.get(command), status, cip_payload, is_connected


def _bytes_to_path_string(path_bytes: bytes) -> str:
    if not path_bytes:
        return ""
    segments = []
    idx = 0
    current_class_id: Optional[int] = None
    while idx < len(path_bytes):
        if idx + 1 >= len(path_bytes):
            break
        seg_type = path_bytes[idx]
        seg_format = path_bytes[idx + 1]
        idx += 2

        if seg_type & 0xE0 == 0x20:
            segment_type = seg_type & 0x1F
            if segment_type == 0x00:
                if seg_format & 0x80:
                    if idx + 1 >= len(path_bytes):
                        break
                    value = int.from_bytes(path_bytes[idx:idx + 2], "little")
                    idx += 2
                else:
                    value = seg_format
                current_class_id = value
                class_name = CIP_CLASS_NAMES.get(value)
                if class_name:
                    segments.append(f"Class:{value}({class_name})")
                else:
                    segments.append(f"Class:{value}")
            elif segment_type == 0x01:
                if seg_format & 0x80:
                    if idx + 1 >= len(path_bytes):
                        break
                    value = int.from_bytes(path_bytes[idx:idx + 2], "little")
                    idx += 2
                else:
                    value = seg_format
                segments.append(f"Instance:{value}")
            elif segment_type == 0x02:
                if seg_format & 0x80:
                    if idx + 1 >= len(path_bytes):
                        break
                    value = int.from_bytes(path_bytes[idx:idx + 2], "little")
                    idx += 2
                else:
                    value = seg_format
                segments.append(f"Member:{value}")
            elif segment_type == 0x03:
                if seg_format & 0x80:
                    if idx + 1 >= len(path_bytes):
                        break
                    value = int.from_bytes(path_bytes[idx:idx + 2], "little")
                    idx += 2
                else:
                    value = seg_format
                segments.append(f"ConnectionPoint:{value}")
            elif segment_type == 0x04:
                if seg_format & 0x80:
                    if idx + 1 >= len(path_bytes):
                        break
                    value = int.from_bytes(path_bytes[idx:idx + 2], "little")
                    idx += 2
                else:
                    value = seg_format
                attr_name = CIP_ATTRIBUTE_NAMES.get(current_class_id or -1, {}).get(value)
                if attr_name:
                    segments.append(f"Attribute:{value}({attr_name})")
                else:
                    segments.append(f"Attribute:{value}")
            else:
                segments.append(f"Logical{segment_type}:{seg_format}")
        elif seg_type == 0x91:
            symbol_len = seg_format
            if idx + symbol_len > len(path_bytes):
                break
            symbol = path_bytes[idx:idx + symbol_len].decode("ascii", errors="ignore")
            idx += symbol_len
            if symbol_len % 2 and idx < len(path_bytes):
                idx += 1
            segments.append(f"Symbol:{symbol}")
        elif seg_type == 0x92:
            if idx >= len(path_bytes):
                break
            symbol_len = int.from_bytes(bytes([seg_format, path_bytes[idx]]), "little")
            idx += 1
            if idx + symbol_len > len(path_bytes):
                break
            symbol = path_bytes[idx:idx + symbol_len].decode("utf-8", errors="ignore")
            idx += symbol_len
            if symbol_len % 2 and idx < len(path_bytes):
                idx += 1
            segments.append(f"Symbol:{symbol}")
        else:
            segments.append(f"0x{seg_type:02X}:{seg_format}")
    return "/".join(segments)


def _decode_cip_data_type(code: Optional[int]) -> Optional[str]:
    if code is None:
        return None
    return CIP_DATA_TYPES.get(code, f"0x{code:04x}")


def _extract_symbol(path_str: str) -> Optional[str]:
    if not path_str:
        return None
    for segment in path_str.split("/"):
        if segment.startswith("Symbol:"):
            return segment.split(":", 1)[-1]
    return None


def _parse_tag_payload(
    service_code: Optional[int],
    is_request: bool,
    payload: bytes,
) -> tuple[Optional[int], Optional[int], Optional[int]]:
    if service_code is None:
        return None, None, None
    if service_code == 0x4B:
        if is_request and len(payload) >= 2:
            elements = int.from_bytes(payload[0:2], "little")
            return None, elements, None
        if not is_request and len(payload) >= 2:
            data_type = int.from_bytes(payload[0:2], "little")
            return data_type, None, None
    if service_code == 0x4C and is_request and len(payload) >= 4:
        data_type = int.from_bytes(payload[0:2], "little")
        elements = int.from_bytes(payload[2:4], "little")
        return data_type, elements, None
    if service_code == 0x4D and is_request and len(payload) >= 6:
        elements = int.from_bytes(payload[0:2], "little")
        offset = int.from_bytes(payload[2:6], "little")
        return None, elements, offset
    if service_code == 0x4E and is_request and len(payload) >= 8:
        data_type = int.from_bytes(payload[0:2], "little")
        elements = int.from_bytes(payload[2:4], "little")
        offset = int.from_bytes(payload[4:8], "little")
        return data_type, elements, offset
    if service_code == 0x4F and is_request and len(payload) >= 2:
        data_type = int.from_bytes(payload[0:2], "little")
        return data_type, None, None
    return None, None, None


def _flatten_path_words(words: bytes) -> bytes:
    if not words:
        return b""
    result = bytearray()
    for idx in range(0, len(words), 2):
        result.extend(words[idx:idx + 2])
    return bytes(result[: len(words)])


def _parse_cip_message(payload: bytes) -> tuple[Optional[int], Optional[str], bool, Optional[int], Optional[str], Optional[int], Optional[int], Optional[int], str, bytes]:
    service = None
    service_name = None
    is_request = True
    general_status = None
    general_status_text = None
    class_id = None
    instance_id = None
    attribute_id = None
    path_str = ""

    if not payload:
        return service, service_name, is_request, general_status, general_status_text, class_id, instance_id, attribute_id, path_str, payload

    service = payload[0]
    service_name = CIP_SERVICE_NAMES.get(service & 0x7F)
    is_request = (service & 0x80) == 0

    if is_request:
        if len(payload) >= 2:
            path_size_words = payload[1]
            path_byte_len = path_size_words * 2
            if len(payload) >= 2 + path_byte_len:
                path_bytes = payload[2:2 + path_byte_len]
                flattened = _flatten_path_words(path_bytes)
                path_str = _bytes_to_path_string(flattened)
                idx = 0
                while idx + 1 < len(flattened):
                    seg_type = flattened[idx]
                    seg_format = flattened[idx + 1]
                    idx += 2
                    if seg_type & 0xE0 == 0x20:
                        segment_type = seg_type & 0x1F
                        if segment_type == 0x00:
                            if seg_format & 0x80 and idx + 1 < len(flattened):
                                class_id = int.from_bytes(flattened[idx:idx + 2], "little")
                                idx += 2
                            else:
                                class_id = seg_format
                        elif segment_type == 0x01:
                            if seg_format & 0x80 and idx + 1 < len(flattened):
                                instance_id = int.from_bytes(flattened[idx:idx + 2], "little")
                                idx += 2
                            else:
                                instance_id = seg_format
                        elif segment_type == 0x04:
                            if seg_format & 0x80 and idx + 1 < len(flattened):
                                attribute_id = int.from_bytes(flattened[idx:idx + 2], "little")
                                idx += 2
                            else:
                                attribute_id = seg_format
                payload = payload[2 + path_byte_len:] if 2 + path_byte_len < len(payload) else b""
            else:
                payload = payload[2:] if len(payload) > 2 else b""
    else:
        if len(payload) >= 4:
            general_status = payload[2]
            general_status_text = CIP_GENERAL_STATUS.get(general_status)
            additional_size = payload[3]
            offset = 4 + (additional_size * 2)
            payload = payload[offset:] if offset < len(payload) else b""
        else:
            payload = b""

    return service, service_name, is_request, general_status, general_status_text, class_id, instance_id, attribute_id, path_str, payload


def _bucketize(values: list[int]) -> list[SizeBucket]:
    buckets: list[SizeBucket] = []
    total = len(values)
    for low, high, label in SIZE_BUCKETS:
        entries = [val for val in values if low <= val <= high]
        count = len(entries)
        avg = sum(entries) / count if count else 0.0
        min_val = min(entries) if entries else 0
        max_val = max(entries) if entries else 0
        pct = (count / total) * 100 if total else 0.0
        buckets.append(SizeBucket(label=label, count=count, avg=avg, min=min_val, max=max_val, pct=pct))
    return buckets


def analyze_cip(path: Path, show_status: bool = True) -> CIPAnalysis:
    if TCP is None and UDP is None:
        return CIPAnalysis(path=path, errors=["Scapy unavailable (TCP/UDP missing)"])

    try:
        reader, status, _stream, _size_bytes, _file_type = get_reader(
            path, show_status=show_status
        )
    except Exception as exc:
        return CIPAnalysis(path=path, errors=[f"Error: {exc}"])

    analysis = CIPAnalysis(path=path)
    start_time = None
    last_time = None
    seen_artifacts: set[str] = set()
    max_anomalies = 200
    payload_sizes: list[int] = []
    packet_sizes: list[int] = []
    session_last_ts: dict[str, float] = {}
    session_intervals: dict[str, list[float]] = defaultdict(list)
    src_dst_counts: dict[str, Counter[str]] = defaultdict(Counter)
    src_requests: Counter[str] = Counter()
    src_responses: Counter[str] = Counter()
    src_commands: dict[str, Counter[str]] = defaultdict(Counter)
    failed_pairs: Counter[str] = Counter()
    nonstandard_sessions: Counter[str] = Counter()
    src_control_commands: Counter[str] = Counter()
    src_program_commands: Counter[str] = Counter()
    src_write_commands: Counter[str] = Counter()
    asset_write_targets: dict[str, set[str]] = defaultdict(set)
    asset_write_counts: Counter[str] = Counter()
    write_target_anoms_seen: set[str] = set()
    security_sessions_seen: set[str] = set()

    try:
        with status as pbar:
            try:
                total_count = len(reader)
            except Exception:
                total_count = None
            for idx, pkt in enumerate(reader):
                if total_count and idx % 10 == 0:
                    try:
                        pbar.update(int((idx / max(1, total_count)) * 100))
                    except Exception:
                        pass

                analysis.total_packets += 1
                pkt_len = int(len(pkt)) if hasattr(pkt, "__len__") else 0
                analysis.total_bytes += pkt_len
                ts = safe_float(getattr(pkt, "time", 0))
                if start_time is None:
                    start_time = ts
                last_time = ts

                has_transport, src_ip, dst_ip, sport, dport, payload = _extract_transport(pkt)
                if not has_transport:
                    continue

                matches_port = sport in {CIP_TCP_PORT, CIP_UDP_PORT, CIP_SECURITY_PORT} or dport in {CIP_TCP_PORT, CIP_UDP_PORT, CIP_SECURITY_PORT}
                matches_signature = False
                if payload and len(payload) >= 2:
                    cmd_guess = int.from_bytes(payload[0:2], "little")
                    matches_signature = cmd_guess in ENIP_COMMANDS

                if not matches_port and not matches_signature:
                    continue
                if matches_signature and not matches_port:
                    nonstandard_sessions[f"{src_ip}:{sport} -> {dst_ip}:{dport}"] += 1

                analysis.cip_packets += 1
                analysis.cip_bytes += pkt_len
                payload_sizes.append(len(payload))
                packet_sizes.append(pkt_len)

                analysis.src_ips[src_ip] += 1
                analysis.dst_ips[dst_ip] += 1
                analysis.sessions[f"{src_ip}:{sport} -> {dst_ip}:{dport}"] += 1
                src_dst_counts[src_ip][dst_ip] += 1

                if sport == CIP_SECURITY_PORT or dport == CIP_SECURITY_PORT:
                    sec_key = f"cip_security_port:{src_ip}->{dst_ip}"
                    if sec_key not in seen_artifacts and len(analysis.artifacts) < 200:
                        seen_artifacts.add(sec_key)
                        analysis.artifacts.append(
                            IndustrialArtifact(
                                kind="cip_security",
                                detail="CIP Security port 2221 traffic observed",
                                src=src_ip,
                                dst=dst_ip,
                                ts=ts or 0.0,
                            )
                        )
                    if sec_key not in security_sessions_seen and len(analysis.anomalies) < max_anomalies:
                        security_sessions_seen.add(sec_key)
                        analysis.anomalies.append(
                            IndustrialAnomaly(
                                severity="LOW",
                                title="CIP Security Session",
                                description="Traffic observed on CIP Security port 2221.",
                                src=src_ip,
                                dst=dst_ip,
                                ts=ts or 0.0,
                            )
                        )

                if dport == CIP_UDP_PORT or sport == CIP_UDP_PORT:
                    analysis.io_packets += 1

                session_key = f"{src_ip}:{sport} -> {dst_ip}:{dport}"
                if session_key in session_last_ts and ts is not None:
                    interval = ts - session_last_ts[session_key]
                    if interval >= 0:
                        session_intervals[session_key].append(interval)
                if ts is not None:
                    session_last_ts[session_key] = ts

                encap_command, encap_name, encap_status, cip_payload, is_connected = _parse_enip(payload)
                if encap_command is not None:
                    cmd_label = encap_name or f"Encap 0x{encap_command:04x}"
                    analysis.enip_commands[cmd_label] += 1
                if encap_status is not None:
                    status_label = f"0x{encap_status:08x}"
                    analysis.status_codes[status_label] += 1

                if is_connected:
                    analysis.connected_packets += 1
                else:
                    analysis.unconnected_packets += 1

                if cip_payload is None:
                    cip_payload = payload

                (
                    service,
                    service_name,
                    is_request,
                    general_status,
                    general_status_text,
                    class_id,
                    instance_id,
                    attribute_id,
                    path_str,
                    cip_payload,
                ) = _parse_cip_message(cip_payload)

                if service is not None and not service_name:
                    service_name = f"Service 0x{service & 0x7F:02x}"

                service_code = (service & 0x7F) if service is not None else None
                tag_name = _extract_symbol(path_str)
                data_type_code, element_count, tag_offset = _parse_tag_payload(service_code, is_request, cip_payload)
                data_type_name = _decode_cip_data_type(data_type_code)

                if is_request:
                    analysis.requests += 1
                    analysis.client_ips[src_ip] += 1
                    analysis.server_ips[dst_ip] += 1
                    src_requests[src_ip] += 1
                else:
                    analysis.responses += 1
                    analysis.client_ips[dst_ip] += 1
                    analysis.server_ips[src_ip] += 1
                    src_responses[src_ip] += 1

                if service_name:
                    analysis.cip_services[service_name] += 1
                    actor_ip = src_ip if is_request else dst_ip
                    src_commands[actor_ip][service_name] += 1
                    endpoints = analysis.service_endpoints.setdefault(service_name, Counter())
                    endpoints[f"{src_ip} -> {dst_ip}"] += 1

                    if is_request and service_code is not None:
                        is_write_service = service_code in WRITE_SERVICE_CODES or service_code in HIGH_RISK_SERVICE_CODES
                        if service_code in HIGH_RISK_SERVICE_CODES:
                            analysis.high_risk_services[service_name] += 1
                            analysis.source_risky_commands[src_ip] += 1
                        if is_write_service:
                            src_write_commands[src_ip] += 1
                        elif service_code in ENUMERATION_SERVICE_CODES:
                            analysis.suspicious_services[service_name] += 1
                            analysis.source_enum_commands[src_ip] += 1
                        if service_code in CONTROL_SERVICE_CODES:
                            src_control_commands[src_ip] += 1
                        if service_code in PROGRAM_SERVICE_CODES:
                            src_program_commands[src_ip] += 1

                        if is_write_service:
                            asset_key = dst_ip
                            asset_write_counts[asset_key] += 1
                            target_parts = []
                            if tag_name:
                                target_parts.append(f"tag:{tag_name}")
                            elif class_id is not None:
                                target_parts.append(f"class:{class_id}")
                                if instance_id is not None:
                                    target_parts.append(f"instance:{instance_id}")
                                if attribute_id is not None:
                                    target_parts.append(f"attribute:{attribute_id}")
                            if path_str and not target_parts:
                                target_parts.append(path_str)
                            if target_parts:
                                target_key = "|".join(target_parts)
                                if target_key not in asset_write_targets[asset_key]:
                                    asset_write_targets[asset_key].add(target_key)
                                    if asset_write_counts[asset_key] >= WRITE_BASELINE_MIN:
                                        anomaly_key = f"{asset_key}:{target_key}"
                                        if anomaly_key not in write_target_anoms_seen and len(analysis.anomalies) < max_anomalies:
                                            write_target_anoms_seen.add(anomaly_key)
                                            analysis.anomalies.append(
                                                IndustrialAnomaly(
                                                    severity="MEDIUM",
                                                    title="CIP Unexpected Write Target",
                                                    description=f"New write target for asset {asset_key}: {target_key}",
                                                    src=src_ip,
                                                    dst=dst_ip,
                                                    ts=ts or 0.0,
                                                )
                                            )

                if class_id is not None:
                    analysis.class_ids[class_id] += 1
                    class_name = CIP_CLASS_NAMES.get(class_id)
                    detail = f"Class {class_id}"
                    if class_name:
                        detail = f"{detail} ({class_name})"
                    if instance_id is not None:
                        detail = f"{detail} Instance {instance_id}"
                    if attribute_id is not None:
                        attr_name = CIP_ATTRIBUTE_NAMES.get(class_id, {}).get(attribute_id)
                        if attr_name:
                            detail = f"{detail} Attribute {attribute_id} ({attr_name})"
                        else:
                            detail = f"{detail} Attribute {attribute_id}"
                    key = f"cip_object:{detail}"
                    if key not in seen_artifacts and len(analysis.artifacts) < 200:
                        seen_artifacts.add(key)
                        analysis.artifacts.append(
                            IndustrialArtifact(
                                kind="cip_object",
                                detail=detail,
                                src=src_ip,
                                dst=dst_ip,
                                ts=ts or 0.0,
                            )
                        )
                    if class_id in CIP_SAFETY_CLASS_IDS:
                        safety_key = f"cip_safety:{class_id}"
                        if safety_key not in seen_artifacts and len(analysis.artifacts) < 200:
                            seen_artifacts.add(safety_key)
                            analysis.artifacts.append(
                                IndustrialArtifact(
                                    kind="cip_safety",
                                    detail=f"CIP Safety object class {class_id}",
                                    src=src_ip,
                                    dst=dst_ip,
                                    ts=ts or 0.0,
                                )
                            )
                    if class_id in CIP_SECURITY_CLASS_IDS:
                        security_key = f"cip_security:{class_id}"
                        if security_key not in seen_artifacts and len(analysis.artifacts) < 200:
                            seen_artifacts.add(security_key)
                            analysis.artifacts.append(
                                IndustrialArtifact(
                                    kind="cip_security",
                                    detail=f"CIP Security object class {class_id}",
                                    src=src_ip,
                                    dst=dst_ip,
                                    ts=ts or 0.0,
                                )
                            )
                if instance_id is not None:
                    analysis.instance_ids[instance_id] += 1
                if attribute_id is not None:
                    analysis.attribute_ids[attribute_id] += 1

                if general_status is not None:
                    status_text = general_status_text or f"0x{general_status:02x}"
                    analysis.status_codes[status_text] += 1

                    if general_status != 0x00:
                        if service_name:
                            analysis.service_error_counts[service_name] += 1
                        if not is_request:
                            analysis.server_error_responses[src_ip] += 1
                            failed_pairs[f"{dst_ip} -> {src_ip}"] += 1

                if tag_name:
                    key = f"tag:{tag_name}"
                    if key not in seen_artifacts and len(analysis.artifacts) < 200:
                        seen_artifacts.add(key)
                        analysis.artifacts.append(
                            IndustrialArtifact(
                                kind="tag",
                                detail=tag_name,
                                src=src_ip,
                                dst=dst_ip,
                                ts=ts or 0.0,
                            )
                        )
                    if service_code in {0x4B, 0x4C, 0x4D, 0x4E, 0x4F} and len(analysis.artifacts) < 200:
                        op_parts = [f"tag={tag_name}"]
                        if data_type_name:
                            op_parts.append(f"type={data_type_name}")
                        if element_count is not None:
                            op_parts.append(f"elements={element_count}")
                        if tag_offset is not None:
                            op_parts.append(f"offset={tag_offset}")
                        if is_request:
                            op_kind = "tag_write" if service_code in {0x4C, 0x4E, 0x4F} else "tag_read"
                        else:
                            op_kind = "tag_response"
                        detail = " ".join(op_parts)
                        op_key = f"{op_kind}:{detail}"
                        if op_key not in seen_artifacts:
                            seen_artifacts.add(op_key)
                            analysis.artifacts.append(
                                IndustrialArtifact(
                                    kind=op_kind,
                                    detail=detail,
                                    src=src_ip,
                                    dst=dst_ip,
                                    ts=ts or 0.0,
                                )
                            )

                if encap_command in {0x0004, 0x0063}:
                    ascii_text = _format_ascii(cip_payload, limit=180)
                    if ascii_text:
                        key = f"identity:{ascii_text}"
                        if key not in seen_artifacts and len(analysis.artifacts) < 200:
                            seen_artifacts.add(key)
                            analysis.artifacts.append(
                                IndustrialArtifact(
                                    kind="identity",
                                    detail=ascii_text,
                                    src=src_ip,
                                    dst=dst_ip,
                                    ts=ts or 0.0,
                                )
                            )

                equipment_payload = cip_payload or payload
                for kind, detail in equipment_artifacts(equipment_payload):
                    key = f"{kind}:{detail}"
                    if key not in seen_artifacts and len(analysis.artifacts) < 200:
                        seen_artifacts.add(key)
                        analysis.artifacts.append(
                            IndustrialArtifact(
                                kind=kind,
                                detail=detail,
                                src=src_ip,
                                dst=dst_ip,
                                ts=ts or 0.0,
                            )
                        )

                if service is not None and (service & 0x7F) in SUSPICIOUS_SERVICE_CODES:
                    severity = "HIGH" if (service & 0x7F) in {0x74, 0x75, 0x05} else "MEDIUM"
                    title = "Suspicious CIP Service"
                    description = f"{service_name or f'Service 0x{service:02x}'} observed"
                    if len(analysis.anomalies) < max_anomalies:
                        analysis.anomalies.append(
                            IndustrialAnomaly(
                                severity=severity,
                                title=title,
                                description=description,
                                src=src_ip,
                                dst=dst_ip,
                                ts=ts or 0.0,
                            )
                        )

                if general_status is not None and general_status != 0x00:
                    if len(analysis.anomalies) < max_anomalies:
                        analysis.anomalies.append(
                            IndustrialAnomaly(
                                severity="LOW",
                                title="CIP Error Response",
                                description=f"General status {general_status_text or f'0x{general_status:02x}'}",
                                src=src_ip,
                                dst=dst_ip,
                                ts=ts or 0.0,
                            )
                        )

    except Exception as exc:
        analysis.errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        try:
            reader.close()
        except Exception:
            pass

    if start_time is not None and last_time is not None:
        analysis.duration = last_time - start_time

    analysis.packet_size_buckets = _bucketize(packet_sizes)
    analysis.payload_size_buckets = _bucketize(payload_sizes)

    if nonstandard_sessions:
        for session, count in nonstandard_sessions.most_common(6):
            if len(analysis.anomalies) < max_anomalies:
                analysis.anomalies.append(
                    IndustrialAnomaly(
                        severity="MEDIUM",
                        title="CIP on Non-Standard Port",
                        description=f"{session} ({count} packets)",
                        src="*",
                        dst="*",
                        ts=0.0,
                    )
                )

    total_conn = analysis.connected_packets + analysis.unconnected_packets
    if total_conn and analysis.requests >= 50:
        unconnected_ratio = analysis.unconnected_packets / total_conn
        if unconnected_ratio >= 0.8 and len(analysis.anomalies) < max_anomalies:
            analysis.anomalies.append(
                IndustrialAnomaly(
                    severity="MEDIUM",
                    title="High Unconnected CIP Ratio",
                    description=f"Unconnected explicit messaging dominates ({unconnected_ratio:.0%} of CIP traffic).",
                    src="*",
                    dst="*",
                    ts=0.0,
                )
            )

    for src, dsts in src_dst_counts.items():
        unique_dsts = len(dsts)
        req_count = src_requests.get(src, 0)
        resp_count = src_responses.get(src, 0)
        if unique_dsts >= 20 and req_count > resp_count * 2:
            if len(analysis.anomalies) < max_anomalies:
                analysis.anomalies.append(
                    IndustrialAnomaly(
                        severity="MEDIUM",
                        title="CIP Scanning/Probing",
                        description=f"Source contacted {unique_dsts} CIP endpoints with low response rate.",
                        src=src,
                        dst="*",
                        ts=0.0,
                    )
                )

        if req_count >= 50 and any(cmd in {"RegisterSession", "ListIdentity", "ListServices"} for cmd in src_commands.get(src, {})):
            if len(analysis.anomalies) < max_anomalies:
                analysis.anomalies.append(
                    IndustrialAnomaly(
                        severity="MEDIUM",
                        title="CIP Enumeration Burst",
                        description=f"High volume of session/identity requests ({req_count}) from source.",
                        src=src,
                        dst="*",
                        ts=0.0,
                    )
                )

    for src, risky_count in analysis.source_risky_commands.items():
        req_count = src_requests.get(src, 0)
        risky_ratio = (risky_count / req_count) if req_count else 0.0
        if risky_count >= 20 and risky_ratio >= 0.25:
            if len(analysis.anomalies) < max_anomalies:
                analysis.anomalies.append(
                    IndustrialAnomaly(
                        severity="HIGH",
                        title="CIP Control Command Burst",
                        description=f"{risky_count} high-risk write/control commands from source ({risky_ratio:.0%} of requests).",
                        src=src,
                        dst="*",
                        ts=0.0,
                    )
                )

    for src, enum_count in analysis.source_enum_commands.items():
        unique_dsts = len(src_dst_counts.get(src, {}))
        if enum_count >= 30 and unique_dsts >= 8:
            if len(analysis.anomalies) < max_anomalies:
                analysis.anomalies.append(
                    IndustrialAnomaly(
                        severity="MEDIUM",
                        title="CIP Reconnaissance Campaign",
                        description=f"Enumeration-heavy behavior observed across {unique_dsts} endpoints ({enum_count} requests).",
                        src=src,
                        dst="*",
                        ts=0.0,
                    )
                )

    for server, error_count in analysis.server_error_responses.items():
        resp_count = src_responses.get(server, 0)
        error_ratio = (error_count / resp_count) if resp_count else 0.0
        if error_count >= 20 and error_ratio >= 0.4:
            if len(analysis.anomalies) < max_anomalies:
                analysis.anomalies.append(
                    IndustrialAnomaly(
                        severity="MEDIUM",
                        title="CIP Server Error Flood",
                        description=f"Server produced {error_count} failed responses ({error_ratio:.0%} failure rate).",
                        src=server,
                        dst="*",
                        ts=0.0,
                    )
                )

    for pair, error_count in failed_pairs.items():
        if error_count >= 10:
            client, server = pair.split(" -> ", 1)
            if len(analysis.anomalies) < max_anomalies:
                analysis.anomalies.append(
                    IndustrialAnomaly(
                        severity="HIGH",
                        title="Repeated Failed CIP Operations",
                        description=f"{error_count} failed responses for client/server pair (possible brute-force or unsupported command abuse).",
                        src=client,
                        dst=server,
                        ts=0.0,
                    )
                )

    for session_key, intervals in session_intervals.items():
        if len(intervals) < 6:
            continue
        avg = sum(intervals) / len(intervals)
        if avg <= 0:
            continue
        variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
        cv = (variance ** 0.5) / avg
        if cv <= 0.2 and 1.0 <= avg <= 300.0:
            src_part, dst_part = session_key.split(" -> ", 1)
            src_ip = src_part.split(":", 1)[0]
            dst_ip = dst_part.split(":", 1)[0]
            if len(analysis.anomalies) < max_anomalies:
                analysis.anomalies.append(
                    IndustrialAnomaly(
                        severity="LOW",
                        title="Possible CIP Beaconing",
                        description=f"Regular interval traffic (~{avg:.2f}s) observed for session.",
                        src=src_ip,
                        dst=dst_ip,
                        ts=0.0,
                    )
                )

    for ip_value, count in analysis.dst_ips.items():
        if _is_public_ip(ip_value) and analysis.cip_bytes > 1_000_000 and count > 10:
            if len(analysis.anomalies) < max_anomalies:
                analysis.anomalies.append(
                    IndustrialAnomaly(
                        severity="LOW",
                        title="Possible CIP Exfiltration",
                        description="CIP traffic observed toward public IP with high byte volume.",
                        src="*",
                        dst=ip_value,
                        ts=0.0,
                    )
                )

    for service_name, endpoints in analysis.service_endpoints.items():
        if service_name not in analysis.high_risk_services:
            continue
        for endpoint, count in endpoints.items():
            if count < 10:
                continue
            try:
                _src, dst = endpoint.split(" -> ", 1)
            except ValueError:
                continue
            if _is_public_ip(dst):
                if len(analysis.anomalies) < max_anomalies:
                    analysis.anomalies.append(
                        IndustrialAnomaly(
                            severity="HIGH",
                            title="High-Risk CIP Command to Public Endpoint",
                            description=f"{service_name} invoked {count} times toward public destination.",
                            src="*",
                            dst=dst,
                            ts=0.0,
                        )
                    )

    for src, control_count in src_control_commands.items():
        req_count = src_requests.get(src, 0)
        ratio = (control_count / req_count) if req_count else 0.0
        if control_count >= 5 and ratio >= 0.1 and len(analysis.anomalies) < max_anomalies:
            analysis.anomalies.append(
                IndustrialAnomaly(
                    severity="HIGH",
                    title="CIP Control Commands",
                    description=f"{control_count} control commands observed ({ratio:.0%} of requests).",
                    src=src,
                    dst="*",
                    ts=0.0,
                )
            )

    for src, program_count in src_program_commands.items():
        if program_count and len(analysis.anomalies) < max_anomalies:
            analysis.anomalies.append(
                IndustrialAnomaly(
                    severity="HIGH",
                    title="CIP Program Transfer",
                    description=f"{program_count} program upload/download commands observed.",
                    src=src,
                    dst="*",
                    ts=0.0,
                )
            )

    for src, write_count in src_write_commands.items():
        req_count = src_requests.get(src, 0)
        ratio = (write_count / req_count) if req_count else 0.0
        if write_count >= 20 and ratio >= 0.3 and len(analysis.anomalies) < max_anomalies:
            analysis.anomalies.append(
                IndustrialAnomaly(
                    severity="HIGH",
                    title="CIP Write Burst",
                    description=f"{write_count} write/configuration commands ({ratio:.0%} of requests).",
                    src=src,
                    dst="*",
                    ts=0.0,
                )
            )

    return analysis
