from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import ipaddress

try:
    from scapy.layers.inet import TCP, UDP, IP
    from scapy.packet import Raw
except ImportError:  # pragma: no cover - scapy optional at runtime
    TCP = UDP = IP = Raw = None

from .cip import CIP_GENERAL_STATUS, CIP_SERVICE_NAMES
from .equipment import equipment_artifacts
from .industrial_helpers import IndustrialArtifact, IndustrialAnomaly
from .pcap_cache import get_reader
from .utils import safe_float

ENIP_TCP_PORT = 44818
ENIP_UDP_PORT = 2222

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
    status_codes: Counter[str] = field(default_factory=Counter)
    packet_size_buckets: list[SizeBucket] = field(default_factory=list)
    payload_size_buckets: list[SizeBucket] = field(default_factory=list)
    artifacts: list[IndustrialArtifact] = field(default_factory=list)
    anomalies: list[IndustrialAnomaly] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    identities: list[IdentityInfo] = field(default_factory=list)


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


def _load_identity_mappings() -> dict[str, dict[str, object]]:
    path = _identity_mapping_path()
    if not path.exists():
        return {}
    try:
        import json

        raw = json.loads(path.read_text(encoding="utf-8"))
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
    identity_keys: set[tuple[str, int | None, int | None, int | None, str | None]] = set()

    try:
        with status as pbar:
            total_count = len(reader)
            for idx, pkt in enumerate(reader):
                if idx % 10 == 0:
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

                matches_port = sport in {ENIP_TCP_PORT, ENIP_UDP_PORT} or dport in {ENIP_TCP_PORT, ENIP_UDP_PORT}
                matches_signature = False
                if payload and len(payload) >= 2:
                    cmd_guess = int.from_bytes(payload[0:2], "little")
                    matches_signature = cmd_guess in ENIP_COMMANDS

                if not matches_port and not matches_signature:
                    continue

                analysis.enip_packets += 1
                analysis.enip_bytes += pkt_len
                payload_sizes.append(len(payload))
                packet_sizes.append(pkt_len)

                analysis.src_ips[src_ip] += 1
                analysis.dst_ips[dst_ip] += 1
                analysis.sessions[f"{src_ip}:{sport} -> {dst_ip}:{dport}"] += 1
                src_dst_counts[src_ip][dst_ip] += 1

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

                service, service_name, is_request, general_status, status_text = _parse_cip_service(cip_payload)
                if service is not None and not service_name:
                    service_name = f"Service 0x{service & 0x7F:02x}"

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
        analysis.errors.append(str(exc))

    if start_time is not None and last_time is not None:
        analysis.duration = last_time - start_time

    analysis.packet_size_buckets = _bucketize(packet_sizes)
    analysis.payload_size_buckets = _bucketize(payload_sizes)

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

    return analysis
