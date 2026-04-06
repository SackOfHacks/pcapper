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
    ENIP_ENUMERATION_COMMANDS,
    CPF_ITEM_TYPES,
    CIP_RECON_STATUS_CODES,
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
    _parse_multiple_service_packet,
    _match_sensitive_tag,
    _parse_enip_details as _parse_enip_details_base,
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
    high_risk_services: Counter[str] = field(default_factory=Counter)
    suspicious_services: Counter[str] = field(default_factory=Counter)
    source_risky_commands: Counter[str] = field(default_factory=Counter)
    source_enum_commands: Counter[str] = field(default_factory=Counter)
    source_enip_enum_commands: Counter[str] = field(default_factory=Counter)
    source_recon_commands: Counter[str] = field(default_factory=Counter)
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
        merged.high_risk_services.update(summary.high_risk_services)
        merged.suspicious_services.update(summary.suspicious_services)
        merged.source_risky_commands.update(summary.source_risky_commands)
        merged.source_enum_commands.update(summary.source_enum_commands)
        merged.source_enip_enum_commands.update(summary.source_enip_enum_commands)
        merged.source_recon_commands.update(summary.source_recon_commands)
        merged.server_error_responses.update(summary.server_error_responses)
        merged.service_error_counts.update(summary.service_error_counts)
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
    info = _parse_enip_details_base(
        b"\x6f\x00" + len(data).to_bytes(2, "little") + b"\x00" * 20 + data
    )
    payload = info.get("cip_payload")
    return (payload if isinstance(payload, (bytes, bytearray)) else None, bool(info.get("is_connected", False)))


def _parse_enip(payload: bytes) -> tuple[Optional[int], Optional[str], Optional[int], Optional[bytes], bool]:
    info = _parse_enip_details_base(payload)
    return (
        info.get("command"),  # type: ignore[return-value]
        info.get("command_name"),  # type: ignore[return-value]
        info.get("status"),  # type: ignore[return-value]
        info.get("cip_payload"),  # type: ignore[return-value]
        bool(info.get("is_connected", False)),
    )


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
    src_enip_commands: dict[str, Counter[str]] = defaultdict(Counter)
    failed_pairs: Counter[str] = Counter()
    nonstandard_sessions: Counter[str] = Counter()
    src_control_commands: Counter[str] = Counter()
    src_program_commands: Counter[str] = Counter()
    src_write_commands: Counter[str] = Counter()
    src_register_commands: Counter[str] = Counter()
    src_unregister_commands: Counter[str] = Counter()
    src_enum_commands: Counter[str] = Counter()
    src_high_risk_commands: Counter[str] = Counter()
    src_recon_errors: Counter[str] = Counter()
    identity_keys: set[tuple[str, int | None, int | None, int | None, str | None]] = set()
    asset_write_targets: dict[str, set[str]] = defaultdict(set)
    asset_write_counts: Counter[str] = Counter()
    write_target_anoms_seen: set[str] = set()
    security_sessions_seen: set[str] = set()
    sensitive_write_seen: set[str] = set()

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

                request_like = (dport in {ENIP_TCP_PORT, ENIP_UDP_PORT, ENIP_SECURITY_PORT}) and (
                    sport not in {ENIP_TCP_PORT, ENIP_UDP_PORT, ENIP_SECURITY_PORT}
                )
                response_like = (sport in {ENIP_TCP_PORT, ENIP_UDP_PORT, ENIP_SECURITY_PORT}) and (
                    dport not in {ENIP_TCP_PORT, ENIP_UDP_PORT, ENIP_SECURITY_PORT}
                )

                enip = _parse_enip_details_base(payload)
                encap_command = enip.get("command")
                encap_name = enip.get("command_name")
                encap_status = enip.get("status")
                cip_payload = enip.get("cip_payload")
                is_connected = bool(enip.get("is_connected", False))
                encap_data = enip.get("encap_data")
                session_handle = enip.get("session_handle")
                is_cip_carrier = bool(enip.get("is_cip_carrier", False))
                cpf_item_types = enip.get("cpf_item_types")
                cpf_malformed = bool(enip.get("cpf_malformed", False))
                length_mismatch = bool(enip.get("length_mismatch", False))

                if encap_command is not None:
                    cmd_label = str(encap_name or f"Encap 0x{int(encap_command):04x}")
                    actor_ip = src_ip if request_like else dst_ip if response_like else src_ip
                    analysis.enip_commands[cmd_label] += 1
                    src_commands[actor_ip][cmd_label] += 1
                    src_enip_commands[actor_ip][cmd_label] += 1

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
                    if cmd_label in ENIP_ENUMERATION_COMMANDS:
                        analysis.source_enip_enum_commands[actor_ip] += 1
                        analysis.source_enum_commands[actor_ip] += 1
                    if cmd_label == "RegisterSession":
                        src_register_commands[actor_ip] += 1
                    elif cmd_label == "UnregisterSession":
                        src_unregister_commands[actor_ip] += 1

                    if session_handle and len(analysis.artifacts) < 200:
                        session_key = f"enip_session:{actor_ip}:{session_handle}:{cmd_label}"
                        if session_key not in seen_artifacts:
                            seen_artifacts.add(session_key)
                            analysis.artifacts.append(
                                IndustrialArtifact(
                                    kind="enip_session",
                                    detail=f"{cmd_label} session=0x{int(session_handle):08x}",
                                    src=src_ip,
                                    dst=dst_ip,
                                    ts=ts or 0.0,
                                )
                            )

                if encap_status is not None:
                    status_text = str(enip.get("status_text") or f"0x{int(encap_status):08x}")
                    analysis.status_codes[f"ENIP:{status_text}"] += 1
                    if int(encap_status) != 0 and len(analysis.anomalies) < max_anomalies:
                        analysis.anomalies.append(
                            IndustrialAnomaly(
                                severity="LOW",
                                title="ENIP Error Status",
                                description=f"Encapsulation status {status_text}.",
                                src=src_ip,
                                dst=dst_ip,
                                ts=ts or 0.0,
                            )
                        )

                if length_mismatch and len(analysis.anomalies) < max_anomalies:
                    analysis.anomalies.append(
                        IndustrialAnomaly(
                            severity="MEDIUM",
                            title="Malformed ENIP Length",
                            description="ENIP declared payload length does not match observed payload size.",
                            src=src_ip,
                            dst=dst_ip,
                            ts=ts or 0.0,
                        )
                    )

                if is_cip_carrier and cpf_malformed and len(analysis.anomalies) < max_anomalies:
                    analysis.anomalies.append(
                        IndustrialAnomaly(
                            severity="MEDIUM",
                            title="Malformed ENIP CPF",
                            description="Common Packet Format item table appears truncated or malformed.",
                            src=src_ip,
                            dst=dst_ip,
                            ts=ts or 0.0,
                        )
                    )

                if is_cip_carrier and isinstance(cpf_item_types, list) and cpf_item_types and len(analysis.artifacts) < 200:
                    item_names = [CPF_ITEM_TYPES.get(int(code), f"0x{int(code):04x}") for code in cpf_item_types[:4]]
                    cpf_key = f"cpf_items:{','.join(str(int(code)) for code in cpf_item_types[:6])}"
                    if cpf_key not in seen_artifacts:
                        seen_artifacts.add(cpf_key)
                        analysis.artifacts.append(
                            IndustrialArtifact(
                                kind="enip_cpf",
                                detail=", ".join(item_names),
                                src=src_ip,
                                dst=dst_ip,
                                ts=ts or 0.0,
                            )
                        )

                if is_connected:
                    analysis.connected_packets += 1
                else:
                    analysis.unconnected_packets += 1

                parse_payload = b""
                if is_cip_carrier and isinstance(cip_payload, (bytes, bytearray)):
                    parse_payload = bytes(cip_payload)
                elif encap_command is None and isinstance(cip_payload, (bytes, bytearray)):
                    parse_payload = bytes(cip_payload)

                if encap_data:
                    identities = []
                    if encap_command == 0x0063:
                        identities.extend(_parse_list_identity_response(bytes(encap_data), src_ip))
                    identities.extend(_scan_identity_items(bytes(encap_data), src_ip))
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
                    cip_is_request,
                    general_status,
                    status_text,
                    class_id,
                    instance_id,
                    attribute_id,
                    path_str,
                    cip_payload,
                ) = _parse_cip_message(parse_payload)
                if service is not None and not service_name:
                    service_name = f"Service 0x{service & 0x7F:02x}"

                service_code = (service & 0x7F) if service is not None else None
                tag_name = _extract_symbol(path_str)
                is_request = bool(cip_is_request) if service is not None else (request_like or not response_like)
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
                        if service_code in ENUMERATION_SERVICE_CODES:
                            src_enum_commands[src_ip] += 1
                        if service_code in HIGH_RISK_SERVICE_CODES:
                            src_high_risk_commands[src_ip] += 1

                        if service_code == 0x0A:
                            sub_codes = _parse_multiple_service_packet(cip_payload)
                            if sub_codes:
                                sub_names = [CIP_SERVICE_NAMES.get(code, f"Service 0x{code:02x}") for code in sub_codes]
                                msp_detail = ", ".join(sub_names[:6])
                                if len(sub_names) > 6:
                                    msp_detail = f"{msp_detail} (+{len(sub_names) - 6})"
                                msp_key = f"msp:{src_ip}:{dst_ip}:{msp_detail}"
                                if msp_key not in seen_artifacts and len(analysis.artifacts) < 200:
                                    seen_artifacts.add(msp_key)
                                    analysis.artifacts.append(
                                        IndustrialArtifact(
                                            kind="cip_multi_service",
                                            detail=msp_detail,
                                            src=src_ip,
                                            dst=dst_ip,
                                            ts=ts or 0.0,
                                        )
                                    )
                                for sub_code, sub_name in zip(sub_codes, sub_names):
                                    msp_service_name = f"MSP/{sub_name}"
                                    analysis.cip_services[msp_service_name] += 1
                                    msp_eps = analysis.service_endpoints.setdefault(msp_service_name, Counter())
                                    msp_eps[f"{src_ip} -> {dst_ip}"] += 1
                                    if sub_code in HIGH_RISK_SERVICE_CODES:
                                        analysis.high_risk_services[msp_service_name] += 1
                                        analysis.source_risky_commands[src_ip] += 1
                                    if sub_code in ENUMERATION_SERVICE_CODES:
                                        analysis.suspicious_services[msp_service_name] += 1
                                        analysis.source_enum_commands[src_ip] += 1
                                    if sub_code in CONTROL_SERVICE_CODES:
                                        src_control_commands[src_ip] += 1
                                    if sub_code in PROGRAM_SERVICE_CODES:
                                        src_program_commands[src_ip] += 1
                                    if sub_code in WRITE_SERVICE_CODES or sub_code in HIGH_RISK_SERVICE_CODES:
                                        src_write_commands[src_ip] += 1

                                if any(code in HIGH_RISK_SERVICE_CODES for code in sub_codes) and len(analysis.anomalies) < max_anomalies:
                                    analysis.anomalies.append(
                                        IndustrialAnomaly(
                                            severity="HIGH",
                                            title="CIP Multi-Service High-Risk Bundle",
                                            description=f"Multiple_Service_Packet includes high-risk operation(s): {msp_detail}",
                                            src=src_ip,
                                            dst=dst_ip,
                                            ts=ts or 0.0,
                                        )
                                    )

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

                        sensitive_token = _match_sensitive_tag(tag_name if is_write_service else None)
                        if sensitive_token:
                            sensitive_key = f"{src_ip}:{dst_ip}:{tag_name}:{service_name}:{sensitive_token}"
                            if sensitive_key not in sensitive_write_seen and len(analysis.anomalies) < max_anomalies:
                                sensitive_write_seen.add(sensitive_key)
                                severity = "HIGH" if sensitive_token in {"safety", "sif", "estop", "trip", "interlock"} else "MEDIUM"
                                analysis.anomalies.append(
                                    IndustrialAnomaly(
                                        severity=severity,
                                        title="CIP Sensitive Tag Write",
                                        description=f"Write-like operation to sensitive tag '{tag_name}' (keyword: {sensitive_token}).",
                                        src=src_ip,
                                        dst=dst_ip,
                                        ts=ts or 0.0,
                                    )
                                )
                            artifact_key = f"sensitive_tag_write:{tag_name}:{sensitive_token}:{service_name}"
                            if artifact_key not in seen_artifacts and len(analysis.artifacts) < 200:
                                seen_artifacts.add(artifact_key)
                                analysis.artifacts.append(
                                    IndustrialArtifact(
                                        kind="tag_sensitive_write",
                                        detail=f"tag={tag_name} service={service_name} keyword={sensitive_token}",
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
                        if is_request and service_code in WRITE_SERVICE_CODES | CONTROL_SERVICE_CODES | HIGH_RISK_SERVICE_CODES:
                            if len(analysis.anomalies) < max_anomalies:
                                analysis.anomalies.append(
                                    IndustrialAnomaly(
                                        severity="HIGH",
                                        title="CIP Safety Object Control/Write",
                                        description=f"Write/control service {service_name or service_code} targeted safety class {class_id}.",
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
                        if is_request and service_code in WRITE_SERVICE_CODES | CONTROL_SERVICE_CODES | HIGH_RISK_SERVICE_CODES:
                            if len(analysis.anomalies) < max_anomalies:
                                analysis.anomalies.append(
                                    IndustrialAnomaly(
                                        severity="HIGH",
                                        title="CIP Security Object Modification",
                                        description=f"Write/control service {service_name or service_code} targeted CIP Security class {class_id}.",
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
                    cip_status_text = status_text or CIP_GENERAL_STATUS.get(general_status) or f"0x{general_status:02x}"
                    analysis.status_codes[f"CIP:{cip_status_text}"] += 1
                    if general_status != 0x00 and len(analysis.anomalies) < max_anomalies:
                        analysis.anomalies.append(
                            IndustrialAnomaly(
                                severity="LOW",
                                title="CIP Error Response",
                                description=f"General status {cip_status_text}.",
                                src=src_ip,
                                dst=dst_ip,
                                ts=ts or 0.0,
                            )
                        )
                        if service_name:
                            analysis.service_error_counts[service_name] += 1
                        if not is_request:
                            analysis.server_error_responses[src_ip] += 1
                            failed_pairs[f"{dst_ip} -> {src_ip}"] += 1
                            if general_status in CIP_RECON_STATUS_CODES:
                                src_recon_errors[dst_ip] += 1
                                analysis.source_recon_commands[dst_ip] += 1

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
                    identity_payload = encap_data if isinstance(encap_data, (bytes, bytearray)) else cip_payload
                    ascii_text = _format_ascii(bytes(identity_payload), limit=180) if identity_payload else ""
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

        if req_count >= 50 and any(cmd in SUSPICIOUS_ENIP_COMMANDS for cmd in src_enip_commands.get(src, {})):
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

    for src, enum_count in analysis.source_enip_enum_commands.items():
        unique_dsts = len(src_dst_counts.get(src, {}))
        if enum_count >= 20 and unique_dsts >= 4 and len(analysis.anomalies) < max_anomalies:
            analysis.anomalies.append(
                IndustrialAnomaly(
                    severity="MEDIUM",
                    title="ENIP Discovery Sweep",
                    description=f"{enum_count} ENIP discovery/session enumeration commands across {unique_dsts} endpoints.",
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

    for server, error_count in analysis.server_error_responses.items():
        resp_count = src_responses.get(server, 0)
        error_ratio = (error_count / resp_count) if resp_count else 0.0
        if error_count >= 20 and error_ratio >= 0.4 and len(analysis.anomalies) < max_anomalies:
            analysis.anomalies.append(
                IndustrialAnomaly(
                    severity="MEDIUM",
                    title="ENIP/CIP Server Error Flood",
                    description=f"Server produced {error_count} failed responses ({error_ratio:.0%} failure rate).",
                    src=server,
                    dst="*",
                    ts=0.0,
                )
            )

    for pair, error_count in failed_pairs.items():
        if error_count >= 10 and len(analysis.anomalies) < max_anomalies:
            client, server = pair.split(" -> ", 1)
            analysis.anomalies.append(
                IndustrialAnomaly(
                    severity="HIGH",
                    title="Repeated Failed ENIP/CIP Operations",
                    description=f"{error_count} failed responses for client/server pair.",
                    src=client,
                    dst=server,
                    ts=0.0,
                )
            )

    for src, register_count in src_register_commands.items():
        unregister_count = src_unregister_commands.get(src, 0)
        if register_count >= 20 and unregister_count <= max(1, register_count // 10):
            if len(analysis.anomalies) < max_anomalies:
                analysis.anomalies.append(
                    IndustrialAnomaly(
                        severity="MEDIUM",
                        title="ENIP Session Churn",
                        description=f"{register_count} RegisterSession vs {unregister_count} UnregisterSession commands.",
                        src=src,
                        dst="*",
                        ts=0.0,
                    )
                )

    for src, recon_count in src_recon_errors.items():
        unique_dsts = len(src_dst_counts.get(src, {}))
        if recon_count >= 10 and unique_dsts >= 3 and len(analysis.anomalies) < max_anomalies:
            analysis.anomalies.append(
                IndustrialAnomaly(
                    severity="MEDIUM",
                    title="CIP Reconnaissance Error Pattern",
                    description=f"{recon_count} path/service/attribute errors returned from {unique_dsts} endpoints.",
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
