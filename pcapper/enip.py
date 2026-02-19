from __future__ import annotations

from collections import Counter, defaultdict
from functools import lru_cache
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import ipaddress

try:
    from scapy.layers.inet import TCP, UDP, IP
    from scapy.packet import Raw
except ImportError:  # pragma: no cover - scapy optional at runtime
    TCP = UDP = IP = Raw = None

from .cip import (
    CIP_GENERAL_STATUS,
    CIP_CLASS_NAMES,
    CIP_ATTRIBUTE_NAMES,
    CIP_SERVICE_NAMES,
    CONTROL_SERVICE_CODES,
    PROGRAM_SERVICE_CODES,
    WRITE_SERVICE_CODES,
    ENUMERATION_SERVICE_CODES,
    HIGH_RISK_SERVICE_CODES,
    CIP_SECURITY_PORT,
    CIP_SAFETY_CLASS_IDS,
    CIP_SECURITY_CLASS_IDS,
    WRITE_BASELINE_MIN,
    _parse_cip_message,
    _extract_symbol,
    _parse_tag_payload,
    _decode_cip_data_type,
)
from .equipment import equipment_artifacts
from .device_detection import device_fingerprint_from_fields
from .industrial_helpers import IndustrialArtifact, IndustrialAnomaly
from .pcap_cache import get_reader
from .utils import safe_float, safe_read_text

ENIP_TCP_PORT = 44818
ENIP_UDP_PORT = 2222
ENIP_SECURITY_PORT = CIP_SECURITY_PORT

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

SUSPICIOUS_ENIP_COMMANDS = {
    "ListServices",
    "ListIdentity",
    "ListInterfaces",
    "RegisterSession",
    "WriteObjectInstanceAttributes",
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


@dataclass(frozen=True)
class SizeBucket:
    label: str
    count: int
    avg: float
    min: int
    max: int
    pct: float


@dataclass
class IdentityInfo:
    src_ip: str
    vendor_id: Optional[int]
    device_type: Optional[int]
    product_code: Optional[int]
    revision: Optional[str]
    serial_number: Optional[int]
    product_name: Optional[str]
    vendor_name: Optional[str] = None
    device_type_name: Optional[str] = None
    product_code_name: Optional[str] = None


@dataclass
class ENIPAnalysis:
    path: Path
    duration: float = 0.0
    total_packets: int = 0
    enip_packets: int = 0
    total_bytes: int = 0
    enip_bytes: int = 0
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
    identities: list[IdentityInfo] = field(default_factory=list)


def merge_enip_summaries(summaries: list[ENIPAnalysis]) -> ENIPAnalysis:
    if not summaries:
        return ENIPAnalysis(path=Path("ALL_PCAPS_0"))

    merged = ENIPAnalysis(path=Path(f"ALL_PCAPS_{len(summaries)}"))

    def _merge_buckets(all_buckets: list[list[SizeBucket]]) -> list[SizeBucket]:
        by_label: dict[str, dict[str, float]] = {}
        for bucket_list in all_buckets:
            for bucket in bucket_list:
                entry = by_label.setdefault(
                    bucket.label,
                    {"count": 0.0, "sum": 0.0, "min": 0.0, "max": 0.0},
                )
                count = float(bucket.count)
                if count <= 0:
                    continue
                if entry["count"] == 0:
                    entry["min"] = float(bucket.min)
                    entry["max"] = float(bucket.max)
                else:
                    entry["min"] = min(entry["min"], float(bucket.min))
                    entry["max"] = max(entry["max"], float(bucket.max))
                entry["count"] += count
                entry["sum"] += float(bucket.avg) * count

        total_count = sum(entry["count"] for entry in by_label.values())
        merged_buckets: list[SizeBucket] = []
        for low, high, label in SIZE_BUCKETS:
            _ = low, high
            entry = by_label.get(label)
            if not entry or entry["count"] <= 0:
                merged_buckets.append(SizeBucket(label=label, count=0, avg=0.0, min=0, max=0, pct=0.0))
                continue
            count = int(entry["count"])
            avg = entry["sum"] / entry["count"] if entry["count"] else 0.0
            pct = (entry["count"] / total_count) * 100 if total_count else 0.0
            merged_buckets.append(
                SizeBucket(
                    label=label,
                    count=count,
                    avg=avg,
                    min=int(entry["min"]),
                    max=int(entry["max"]),
                    pct=pct,
                )
            )
        return merged_buckets

    error_seen: set[str] = set()
    identity_seen: set[tuple[object, object, object, object, object]] = set()

    packet_bucket_lists: list[list[SizeBucket]] = []
    payload_bucket_lists: list[list[SizeBucket]] = []

    for summary in summaries:
        merged.duration += summary.duration
        merged.total_packets += summary.total_packets
        merged.enip_packets += summary.enip_packets
        merged.total_bytes += summary.total_bytes
        merged.enip_bytes += summary.enip_bytes
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
        merged.class_ids.update(summary.class_ids)
        merged.instance_ids.update(summary.instance_ids)
        merged.attribute_ids.update(summary.attribute_ids)
        merged.status_codes.update(summary.status_codes)

        for service, counter in summary.service_endpoints.items():
            merged.service_endpoints.setdefault(service, Counter()).update(counter)

        packet_bucket_lists.append(summary.packet_size_buckets)
        payload_bucket_lists.append(summary.payload_size_buckets)

        merged.artifacts.extend(summary.artifacts)
        merged.anomalies.extend(summary.anomalies)

        for err in summary.errors:
            if err in error_seen:
                continue
            error_seen.add(err)
            merged.errors.append(err)

        for ident in summary.identities:
            key = (
                ident.src_ip,
                ident.vendor_id,
                ident.device_type,
                ident.product_code,
                ident.serial_number,
            )
            if key in identity_seen:
                continue
            identity_seen.add(key)
            merged.identities.append(ident)

    merged.packet_size_buckets = _merge_buckets(packet_bucket_lists)
    merged.payload_size_buckets = _merge_buckets(payload_bucket_lists)
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


def _parse_list_identity_response(data: bytes, src_ip: str) -> list[IdentityInfo]:
    if len(data) < 6:
        return []
    ptr = 0
    ptr += 2
    ptr += 2
    item_count = int.from_bytes(data[ptr:ptr + 2], "little")
    ptr += 2
    identities: list[IdentityInfo] = []
    for _ in range(item_count):
        if ptr + 4 > len(data):
            break
        item_type = int.from_bytes(data[ptr:ptr + 2], "little")
        item_len = int.from_bytes(data[ptr + 2:ptr + 4], "little")
        ptr += 4
        if ptr + item_len > len(data):
            break
        item_data = data[ptr:ptr + item_len]
        ptr += item_len
        if item_type != 0x000C:
            continue
        if len(item_data) < 28:
            continue
        vendor_id = int.from_bytes(item_data[0:2], "little")
        device_type = int.from_bytes(item_data[2:4], "little")
        product_code = int.from_bytes(item_data[4:6], "little")
        revision_major = item_data[6]
        revision_minor = item_data[7]
        serial_number = int.from_bytes(item_data[10:14], "little")
        product_name_len = item_data[14]
        name_start = 15
        name_end = min(len(item_data), name_start + product_name_len)
        try:
            product_name = item_data[name_start:name_end].decode("utf-8", errors="ignore")
        except Exception:
            product_name = None
        if product_name:
            product_name = _clean_identity_text(product_name)
        revision = f"{revision_major}.{revision_minor}"
        vendor_name, device_type_name, product_code_name = _resolve_identity_names(
            vendor_id, device_type, product_code
        )
        identities.append(
            IdentityInfo(
                src_ip=src_ip,
                vendor_id=vendor_id,
                device_type=device_type,
                product_code=product_code,
                revision=revision,
                serial_number=serial_number,
                product_name=product_name,
                vendor_name=vendor_name,
                device_type_name=device_type_name,
                product_code_name=product_code_name,
            )
        )
    return identities


def _clean_identity_text(value: str) -> str:
    cleaned = "".join(ch if ch.isprintable() else " " for ch in value)
    return " ".join(cleaned.split())


def _identity_mapping_path() -> Path:
    return Path(__file__).with_name("enip_mappings.json")


@lru_cache(maxsize=4)
def _load_identity_mappings() -> dict[str, dict[str, object]]:
    path = _identity_mapping_path()
    if not path.exists():
        return {}
    try:
        import json
        raw_text = safe_read_text(path, encoding="utf-8", errors="ignore")
        if not raw_text:
            return {}
        raw = json.loads(raw_text)
        return raw if isinstance(raw, dict) else {}
    except Exception:
        return {}


def _resolve_identity_names(
    vendor_id: Optional[int],
    device_type: Optional[int],
    product_code: Optional[int],
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    mappings = _load_identity_mappings()
    vendor_name = None
    device_type_name = None
    product_code_name = None

    vendors = mappings.get("vendors") if isinstance(mappings.get("vendors"), dict) else {}
    device_types = mappings.get("device_types") if isinstance(mappings.get("device_types"), dict) else {}
    product_codes = mappings.get("product_codes") if isinstance(mappings.get("product_codes"), dict) else {}

    matched_vendor_id = None
    if vendor_id is not None:
        vendor_name = vendors.get(str(vendor_id))
        if vendor_name:
            matched_vendor_id = str(vendor_id)
        vendor_bucket = product_codes.get(str(vendor_id)) if isinstance(product_codes, dict) else None
        if isinstance(vendor_bucket, dict) and product_code is not None:
            product_code_name = vendor_bucket.get(str(product_code))

    if product_code_name is None and product_code is not None and isinstance(product_codes, dict):
        for vendor_key, vendor_bucket in product_codes.items():
            if not isinstance(vendor_bucket, dict):
                continue
            candidate = vendor_bucket.get(str(product_code))
            if candidate:
                product_code_name = candidate
                matched_vendor_id = matched_vendor_id or str(vendor_key)
                if vendor_name is None:
                    vendor_name = vendors.get(str(vendor_key))
                break

    if device_type is not None:
        device_type_name = device_types.get(str(device_type))

    if product_code_name is None and product_code is not None:
        flat_codes = mappings.get("product_codes_flat")
        if isinstance(flat_codes, dict):
            product_code_name = flat_codes.get(str(product_code))

    return vendor_name, device_type_name, product_code_name


def _scan_identity_items(payload: bytes, src_ip: str) -> list[IdentityInfo]:
    identities: list[IdentityInfo] = []
    if len(payload) < 8:
        return identities
    idx = 0
    max_len = len(payload)
    while idx + 4 <= max_len:
        item_type = int.from_bytes(payload[idx:idx + 2], "little")
        item_len = int.from_bytes(payload[idx + 2:idx + 4], "little")
        if item_type == 0x000C and item_len >= 28 and idx + 4 + item_len <= max_len:
            item_data = payload[idx + 4:idx + 4 + item_len]
            identities.extend(_parse_list_identity_response(
                b"\x00\x00\x00\x00\x01\x00" + b"\x0c\x00" + item_len.to_bytes(2, "little") + item_data,
                src_ip,
            ))
            idx += 4 + item_len
            continue
        idx += 1
    return identities


def _parse_cip_service(payload: bytes) -> tuple[Optional[int], Optional[str], bool, Optional[int], Optional[str]]:
    if not payload:
        return None, None, True, None, None
    service = payload[0]
    service_name = CIP_SERVICE_NAMES.get(service & 0x7F)
    is_request = (service & 0x80) == 0
    if is_request:
        return service, service_name, True, None, None
    if len(payload) >= 4:
        general_status = payload[2]
        status_text = CIP_GENERAL_STATUS.get(general_status)
    else:
        general_status = None
        status_text = None
    return service, service_name, False, general_status, status_text


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


def analyze_enip(path: Path, show_status: bool = True) -> ENIPAnalysis:
    if TCP is None and UDP is None:
        return ENIPAnalysis(path=path, errors=["Scapy unavailable (TCP/UDP missing)"])

    try:
        reader, status, _stream, _size_bytes, _file_type = get_reader(
            path, show_status=show_status
        )
    except Exception as exc:
        return ENIPAnalysis(path=path, errors=[f"Error: {exc}"])

    analysis = ENIPAnalysis(path=path)
    start_time = None
    last_time = None
    max_anomalies = 200
    seen_artifacts: set[str] = set()
    payload_sizes: list[int] = []
    packet_sizes: list[int] = []
    session_last_ts: dict[str, float] = {}
    session_intervals: dict[str, list[float]] = defaultdict(list)
    src_dst_counts: dict[str, Counter[str]] = defaultdict(Counter)
    src_requests: Counter[str] = Counter()
    src_responses: Counter[str] = Counter()
    src_commands: dict[str, Counter[str]] = defaultdict(Counter)
    nonstandard_sessions: Counter[str] = Counter()
    src_control_commands: Counter[str] = Counter()
    src_program_commands: Counter[str] = Counter()
    src_write_commands: Counter[str] = Counter()
    src_enum_commands: Counter[str] = Counter()
    src_high_risk_commands: Counter[str] = Counter()
    identity_keys: set[tuple[str, int | None, int | None, int | None, str | None]] = set()
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

                matches_port = sport in {ENIP_TCP_PORT, ENIP_UDP_PORT, ENIP_SECURITY_PORT} or dport in {ENIP_TCP_PORT, ENIP_UDP_PORT, ENIP_SECURITY_PORT}
                matches_signature = False
                if payload and len(payload) >= 2:
                    cmd_guess = int.from_bytes(payload[0:2], "little")
                    matches_signature = cmd_guess in ENIP_COMMANDS

                if not matches_port and not matches_signature:
                    continue
                if matches_signature and not matches_port:
                    nonstandard_sessions[f"{src_ip}:{sport} -> {dst_ip}:{dport}"] += 1

                analysis.enip_packets += 1
                analysis.enip_bytes += pkt_len
                payload_sizes.append(len(payload))
                packet_sizes.append(pkt_len)

                analysis.src_ips[src_ip] += 1
                analysis.dst_ips[dst_ip] += 1
                analysis.sessions[f"{src_ip}:{sport} -> {dst_ip}:{dport}"] += 1
                src_dst_counts[src_ip][dst_ip] += 1

                if sport == ENIP_SECURITY_PORT or dport == ENIP_SECURITY_PORT:
                    sec_key = f"enip_security_port:{src_ip}->{dst_ip}"
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

                if dport == ENIP_UDP_PORT or sport == ENIP_UDP_PORT:
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
                    src_commands[src_ip][cmd_label] += 1

                    if cmd_label in SUSPICIOUS_ENIP_COMMANDS and len(analysis.anomalies) < max_anomalies:
                        analysis.anomalies.append(
                            IndustrialAnomaly(
                                severity="LOW",
                                title="ENIP Enumeration/Session Command",
                                description=f"{cmd_label} observed.",
                                src=src_ip,
                                dst=dst_ip,
                                ts=ts or 0.0,
                            )
                        )

                if encap_status is not None:
                    status_label = f"0x{encap_status:08x}"
                    analysis.status_codes[status_label] += 1
                    if encap_status != 0 and len(analysis.anomalies) < max_anomalies:
                        analysis.anomalies.append(
                            IndustrialAnomaly(
                                severity="LOW",
                                title="ENIP Error Status",
                                description=f"Encapsulation status {status_label}.",
                                src=src_ip,
                                dst=dst_ip,
                                ts=ts or 0.0,
                            )
                        )

                if is_connected:
                    analysis.connected_packets += 1
                else:
                    analysis.unconnected_packets += 1

                if cip_payload is None:
                    cip_payload = payload

                if cip_payload:
                    identities = []
                    if encap_command == 0x0063:
                        identities.extend(_parse_list_identity_response(cip_payload, src_ip))
                    identities.extend(_scan_identity_items(cip_payload, src_ip))
                    for ident in identities:
                        key = (
                            ident.src_ip,
                            ident.vendor_id,
                            ident.device_type,
                            ident.product_code,
                            ident.product_name,
                        )
                        if key in identity_keys:
                            continue
                        identity_keys.add(key)
                        if len(analysis.identities) < 200:
                            analysis.identities.append(ident)
                        device_fields = {
                            "vendor": ident.vendor_name or (f"Vendor {ident.vendor_id}" if ident.vendor_id is not None else None),
                            "device_type": ident.device_type_name or (f"DeviceType {ident.device_type}" if ident.device_type is not None else None),
                            "model": ident.product_code_name or (f"Product {ident.product_code}" if ident.product_code is not None else None),
                            "product": ident.product_name,
                            "revision": ident.revision,
                            "serial": ident.serial_number,
                        }
                        detail = device_fingerprint_from_fields(device_fields, source="ENIP ListIdentity")
                        if detail:
                            key = f"device:{detail}"
                            if key not in seen_artifacts and len(analysis.artifacts) < 200:
                                seen_artifacts.add(key)
                                analysis.artifacts.append(
                                    IndustrialArtifact(
                                        kind="device",
                                        detail=detail,
                                        src=src_ip,
                                        dst=dst_ip,
                                        ts=ts or 0.0,
                                    )
                                )

                (
                    service,
                    service_name,
                    is_request,
                    general_status,
                    status_text,
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
                    endpoints = analysis.service_endpoints.setdefault(service_name, Counter())
                    endpoints[f"{src_ip} -> {dst_ip}"] += 1
                    if is_request and service_code is not None:
                        is_write_service = service_code in WRITE_SERVICE_CODES or service_code in HIGH_RISK_SERVICE_CODES
                        if is_write_service:
                            src_write_commands[src_ip] += 1
                        if service_code in CONTROL_SERVICE_CODES:
                            src_control_commands[src_ip] += 1
                        if service_code in PROGRAM_SERVICE_CODES:
                            src_program_commands[src_ip] += 1
                        if service_code in ENUMERATION_SERVICE_CODES:
                            src_enum_commands[src_ip] += 1
                        if service_code in HIGH_RISK_SERVICE_CODES:
                            src_high_risk_commands[src_ip] += 1

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

                if general_status is not None and general_status != 0x00 and len(analysis.anomalies) < max_anomalies:
                    analysis.anomalies.append(
                        IndustrialAnomaly(
                            severity="LOW",
                            title="CIP Error Response",
                            description=f"General status {status_text or f'0x{general_status:02x}'}.",
                            src=src_ip,
                            dst=dst_ip,
                            ts=ts or 0.0,
                        )
                    )

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
                        op_kind = "tag_write" if is_request and service_code in {0x4C, 0x4E, 0x4F} else "tag_read"
                        if not is_request:
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
                        title="ENIP/CIP on Non-Standard Port",
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
                    title="High Unconnected ENIP/CIP Ratio",
                    description=f"Unconnected explicit messaging dominates ({unconnected_ratio:.0%} of ENIP/CIP traffic).",
                    src="*",
                    dst="*",
                    ts=0.0,
                )
            )

    for src, dsts in src_dst_counts.items():
        unique_dsts = len(dsts)
        req_count = src_requests.get(src, 0)
        resp_count = src_responses.get(src, 0)
        if unique_dsts >= 20 and req_count > resp_count * 2 and len(analysis.anomalies) < max_anomalies:
            analysis.anomalies.append(
                IndustrialAnomaly(
                    severity="MEDIUM",
                    title="ENIP Scanning/Probing",
                    description=f"Source contacted {unique_dsts} ENIP endpoints with low response rate.",
                    src=src,
                    dst="*",
                    ts=0.0,
                )
            )

        if req_count >= 50 and any(cmd in SUSPICIOUS_ENIP_COMMANDS for cmd in src_commands.get(src, {})):
            if len(analysis.anomalies) < max_anomalies:
                analysis.anomalies.append(
                    IndustrialAnomaly(
                        severity="MEDIUM",
                        title="ENIP Enumeration Burst",
                        description=f"High volume of ENIP session/identity requests ({req_count}) from source.",
                        src=src,
                        dst="*",
                        ts=0.0,
                    )
                )

    for src, enum_count in src_enum_commands.items():
        unique_dsts = len(src_dst_counts.get(src, {}))
        if enum_count >= 30 and unique_dsts >= 8:
            if len(analysis.anomalies) < max_anomalies:
                analysis.anomalies.append(
                    IndustrialAnomaly(
                        severity="MEDIUM",
                        title="CIP Enumeration Campaign",
                        description=f"Enumeration-heavy CIP usage across {unique_dsts} endpoints ({enum_count} requests).",
                        src=src,
                        dst="*",
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
                        title="Possible ENIP Beaconing",
                        description=f"Regular interval traffic (~{avg:.2f}s) observed for session.",
                        src=src_ip,
                        dst=dst_ip,
                        ts=0.0,
                    )
                )

    for ip_value, count in analysis.dst_ips.items():
        if _is_public_ip(ip_value) and analysis.enip_bytes > 1_000_000 and count > 10:
            if len(analysis.anomalies) < max_anomalies:
                analysis.anomalies.append(
                    IndustrialAnomaly(
                        severity="LOW",
                        title="Possible ENIP Exfiltration",
                        description="ENIP traffic observed toward public IP with high byte volume.",
                        src="*",
                        dst=ip_value,
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

    for src, risky_count in src_high_risk_commands.items():
        req_count = src_requests.get(src, 0)
        ratio = (risky_count / req_count) if req_count else 0.0
        if risky_count >= 10 and ratio >= 0.2 and len(analysis.anomalies) < max_anomalies:
            analysis.anomalies.append(
                IndustrialAnomaly(
                    severity="HIGH",
                    title="High-Risk CIP Services",
                    description=f"{risky_count} high-risk service invocations ({ratio:.0%} of requests).",
                    src=src,
                    dst="*",
                    ts=0.0,
                )
            )

    return analysis
