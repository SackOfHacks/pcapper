from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import ipaddress
import math
import struct

try:
    from scapy.layers.inet import TCP, IP
    from scapy.packet import Raw
except ImportError:
    TCP = IP = Raw = None

from .pcap_cache import get_reader
from .equipment import equipment_artifacts
from .device_detection import device_fingerprint_from_fields
from .utils import detect_file_type, safe_float

# --- Constants ---

MODBUS_TCP_PORT = 502
PROTOCOL_ID_MODBUS = 0

FUNC_NAMES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    7: "Read Exception Status",
    8: "Diagnostics",
    11: "Get Comm Event Counter",
    12: "Get Comm Event Log",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    17: "Report Server ID",
    20: "Read File Record",
    21: "Write File Record",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
    24: "Read FIFO Queue",
    43: "Encapsulated Interface Transport (Read Device ID)"
}

WRITE_FUNCTIONS = {5, 6, 15, 16, 21, 22, 23}
DIAGNOSTIC_FUNCTIONS = {8, 43}
ENUMERATION_FUNCTIONS = {17, 43}

WRITE_BASELINE_MIN = 10

EXCEPTION_CODES = {
    1: "Illegal Function",
    2: "Illegal Data Address",
    3: "Illegal Data Value",
    4: "Server Device Failure",
    5: "Acknowledge",
    6: "Server Device Busy",
    8: "Memory Parity Error",
    10: "Gateway Path Unavailable",
    11: "Gateway Target Device Failed to Respond"
}

PACKET_BUCKETS = [
    (64, "<=64"),
    (128, "65-128"),
    (256, "129-256"),
    (512, "257-512"),
    (1024, "513-1024"),
    (1500, "1025-1500"),
    (9000, "1501-9000"),
]

FLOW_BUCKETS = [
    (0.0, 1.0, "<=1s"),
    (1.0, 10.0, "1-10s"),
    (10.0, 60.0, "10-60s"),
    (60.0, 300.0, "1-5m"),
    (300.0, 1800.0, "5-30m"),
    (1800.0, float("inf"), ">30m"),
]

# --- Dataclasses ---

@dataclass
class ModbusMessage:
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    trans_id: int
    unit_id: int
    func_code: int
    func_name: str
    is_exception: bool = False
    exception_code: Optional[int] = None
    exception_desc: Optional[str] = None
    payload_len: int = 0
    detail: Optional[str] = None
    direction: Optional[str] = None

@dataclass
class ModbusAnomaly:
    severity: str # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    src: str
    dst: str
    ts: float


@dataclass
class ModbusArtifact:
    kind: str
    detail: str
    src: str
    dst: str
    ts: float

@dataclass
class ModbusAnalysis:
    path: Path
    duration: float = 0.0
    total_packets: int = 0
    modbus_packets: int = 0
    total_bytes: int = 0
    modbus_bytes: int = 0
    modbus_payload_bytes: int = 0
    
    # Statistics
    func_counts: Counter[str] = field(default_factory=Counter)
    unit_ids: Counter[int] = field(default_factory=Counter)
    src_ips: Counter[str] = field(default_factory=Counter) # Client IPs usually
    dst_ips: Counter[str] = field(default_factory=Counter) # Server/PLC IPs
    client_bytes: Counter[str] = field(default_factory=Counter)
    server_bytes: Counter[str] = field(default_factory=Counter)
    endpoint_packets: Counter[str] = field(default_factory=Counter)
    endpoint_bytes: Counter[str] = field(default_factory=Counter)
    service_endpoints: Dict[str, Counter[str]] = field(default_factory=dict)
    packet_size_hist: Counter[str] = field(default_factory=Counter)
    payload_size_hist: Counter[str] = field(default_factory=Counter)
    packet_size_stats: Dict[str, float] = field(default_factory=dict)
    payload_size_stats: Dict[str, float] = field(default_factory=dict)
    flow_duration_buckets: Dict[str, Counter[str]] = field(default_factory=dict)
    
    # Activity
    messages: List[ModbusMessage] = field(default_factory=list)
    artifacts: List[ModbusArtifact] = field(default_factory=list)
    anomalies: List[ModbusAnomaly] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    @property
    def unique_clients(self) -> int:
        return len(self.src_ips)
    
    @property
    def unique_servers(self) -> int:
        return len(self.dst_ips)
        
    @property
    def error_rate(self) -> float:
        if not self.messages: return 0.0
        errs = sum(1 for m in self.messages if m.is_exception)
        return (errs / len(self.messages)) * 100


def _bucketize(size: int) -> str:
    for ceiling, label in PACKET_BUCKETS:
        if size <= ceiling:
            return label
    return ">9000"


def _append_sample(samples: List[int], value: int, max_len: int = 50000) -> None:
    samples.append(value)
    if len(samples) > max_len:
        del samples[::2]


def _percentile(sorted_vals: List[int], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = int(round((pct / 100.0) * (len(sorted_vals) - 1)))
    idx = max(0, min(len(sorted_vals) - 1, idx))
    return float(sorted_vals[idx])


def _stats_from_samples(samples: List[int]) -> Dict[str, float]:
    if not samples:
        return {"min": 0.0, "max": 0.0, "avg": 0.0, "p50": 0.0, "p95": 0.0}
    sorted_vals = sorted(samples)
    total = sum(sorted_vals)
    return {
        "min": float(sorted_vals[0]),
        "max": float(sorted_vals[-1]),
        "avg": total / max(len(sorted_vals), 1),
        "p50": _percentile(sorted_vals, 50.0),
        "p95": _percentile(sorted_vals, 95.0),
    }


def _bucketize_duration(duration: float) -> str:
    for low, high, label in FLOW_BUCKETS:
        if low <= duration <= high:
            return label
    return ">30m"


def _is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except Exception:
        return False


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except Exception:
        return False


def _modbus_reg_type(func_code: int) -> Optional[str]:
    if func_code in {1, 5, 15}:
        return "coil"
    if func_code == 2:
        return "discrete_input"
    if func_code in {3, 6, 16, 22, 23}:
        return "holding_register"
    if func_code == 4:
        return "input_register"
    return None


def _format_register_range(reg_type: Optional[str], addr: Optional[int], qty: Optional[int]) -> str:
    if addr is None:
        return ""
    if qty is None or qty <= 1:
        return f"{reg_type or 'register'}[{addr}]"
    return f"{reg_type or 'register'}[{addr}-{addr + max(qty - 1, 0)}]"


def _parse_modbus_request_info(func_code: int, pdu: bytes) -> tuple[Optional[str], Optional[str], Optional[int], Optional[int]]:
    if not pdu:
        return None, None, None, None
    try:
        reg_type = _modbus_reg_type(func_code)
        if func_code in {1, 2, 3, 4} and len(pdu) >= 5:
            addr = int.from_bytes(pdu[1:3], "big")
            qty = int.from_bytes(pdu[3:5], "big")
            detail = f"{_format_register_range(reg_type, addr, qty)} qty={qty}"
            return detail, reg_type, addr, qty
        if func_code in {5, 6} and len(pdu) >= 5:
            addr = int.from_bytes(pdu[1:3], "big")
            value = int.from_bytes(pdu[3:5], "big")
            detail = f"{_format_register_range(reg_type, addr, 1)} value=0x{value:04x}"
            return detail, reg_type, addr, 1
        if func_code in {15, 16} and len(pdu) >= 6:
            addr = int.from_bytes(pdu[1:3], "big")
            qty = int.from_bytes(pdu[3:5], "big")
            byte_count = pdu[5]
            detail = f"{_format_register_range(reg_type, addr, qty)} qty={qty} bytes={byte_count}"
            return detail, reg_type, addr, qty
        if func_code == 22 and len(pdu) >= 7:
            addr = int.from_bytes(pdu[1:3], "big")
            and_mask = int.from_bytes(pdu[3:5], "big")
            or_mask = int.from_bytes(pdu[5:7], "big")
            detail = f"{_format_register_range(reg_type, addr, 1)} and=0x{and_mask:04x} or=0x{or_mask:04x}"
            return detail, reg_type, addr, 1
        if func_code == 23 and len(pdu) >= 10:
            read_addr = int.from_bytes(pdu[1:3], "big")
            read_qty = int.from_bytes(pdu[3:5], "big")
            write_addr = int.from_bytes(pdu[5:7], "big")
            write_qty = int.from_bytes(pdu[7:9], "big")
            byte_count = pdu[9]
            detail = (
                f"read={_format_register_range('holding_register', read_addr, read_qty)} "
                f"write={_format_register_range('holding_register', write_addr, write_qty)} bytes={byte_count}"
            )
            return detail, "holding_register", write_addr, write_qty
        if func_code == 8 and len(pdu) >= 5:
            subfunc = int.from_bytes(pdu[1:3], "big")
            data = int.from_bytes(pdu[3:5], "big")
            detail = f"diag subfunc=0x{subfunc:04x} data=0x{data:04x}"
            return detail, None, None, None
        if func_code == 17:
            return "report_server_id", None, None, None
        if func_code == 43 and len(pdu) >= 3:
            mei_type = pdu[1]
            detail = f"mei=0x{mei_type:02x}"
            return detail, None, None, None
    except Exception:
        return None, None, None, None
    return None, None, None, None


def _parse_modbus_response_detail(func_code: int, pdu: bytes) -> Optional[str]:
    if not pdu or len(pdu) < 2:
        return None
    try:
        reg_type = _modbus_reg_type(func_code)
        if func_code in {1, 2} and len(pdu) >= 2:
            byte_count = pdu[1]
            data = pdu[2:2 + byte_count]
            set_bits = sum(bin(b).count("1") for b in data)
            total_bits = byte_count * 8
            return f"{reg_type or 'bits'} bytes={byte_count} set={set_bits}/{total_bits}"
        if func_code in {3, 4} and len(pdu) >= 2:
            byte_count = pdu[1]
            data = pdu[2:2 + byte_count]
            regs = []
            for idx in range(0, min(len(data), 16), 2):
                if idx + 2 <= len(data):
                    regs.append(int.from_bytes(data[idx:idx + 2], "big"))
            preview = ", ".join(str(r) for r in regs[:6])
            return f"{reg_type or 'registers'} count={byte_count // 2} values=[{preview}]"
        if func_code in {5, 6} and len(pdu) >= 5:
            addr = int.from_bytes(pdu[1:3], "big")
            value = int.from_bytes(pdu[3:5], "big")
            return f"write_ack {reg_type or 'register'}[{addr}] value=0x{value:04x}"
        if func_code in {15, 16} and len(pdu) >= 5:
            addr = int.from_bytes(pdu[1:3], "big")
            qty = int.from_bytes(pdu[3:5], "big")
            return f"write_ack {_format_register_range(reg_type, addr, qty)} qty={qty}"
        if func_code == 22 and len(pdu) >= 7:
            addr = int.from_bytes(pdu[1:3], "big")
            and_mask = int.from_bytes(pdu[3:5], "big")
            or_mask = int.from_bytes(pdu[5:7], "big")
            return f"mask_write_ack {_format_register_range(reg_type, addr, 1)} and=0x{and_mask:04x} or=0x{or_mask:04x}"
        if func_code == 23 and len(pdu) >= 2:
            byte_count = pdu[1]
            return f"readwrite_response bytes={byte_count}"
        if func_code == 17 and len(pdu) >= 2:
            byte_count = pdu[1]
            text = pdu[2:2 + byte_count].decode("ascii", errors="ignore").strip()
            return f"server_id={text}" if text else "server_id"
        if func_code == 43 and len(pdu) >= 3:
            mei_type = pdu[1]
            return f"device_id_response mei=0x{mei_type:02x}"
    except Exception:
        return None
    return None


def _parse_device_id_response(pdu: bytes) -> dict[str, str]:
    if len(pdu) < 7:
        return {}
    if pdu[1] != 0x0E:
        return {}
    idx = 7
    fields: dict[str, str] = {}
    object_map = {
        0x00: "vendor",
        0x01: "product_code",
        0x02: "revision",
        0x03: "vendor_url",
        0x04: "product",
        0x05: "model",
        0x06: "user_app",
    }
    while idx + 2 <= len(pdu):
        obj_id = pdu[idx]
        length = pdu[idx + 1]
        idx += 2
        if idx + length > len(pdu):
            break
        raw = pdu[idx:idx + length]
        idx += length
        value = raw.decode("latin-1", errors="ignore").strip()
        if not value:
            continue
        key = object_map.get(obj_id)
        if key and key not in fields:
            fields[key] = value
    return fields

def _parse_modbus_request_detail(func_code: int, pdu: bytes) -> str | None:
    detail, _, _, _ = _parse_modbus_request_info(func_code, pdu)
    return detail

def analyze_modbus(path: Path, show_status: bool = True) -> ModbusAnalysis:
    if TCP is None:
        return ModbusAnalysis(
            path=path,
            errors=["Scapy unavailable (TCP missing)"],
        )

    try:
        reader, status, _stream, _size_bytes, _file_type = get_reader(
            path, show_status=show_status
        )
    except Exception as e:
        return ModbusAnalysis(
            path=path,
            errors=[f"Error: {e}"],
        )
    # Attempt to find file handle for progress
    # for attr in ("fd", "f", "fh", "_fh", "_file", "file"):
    #    candidate = getattr(reader, attr, None)
    #    if candidate is not None:
    #        stream = candidate
    #        break

    total_packets = 0
    modbus_packets = 0
    total_bytes = 0
    modbus_bytes = 0
    modbus_payload_bytes = 0
    
    func_counts = Counter()
    unit_ids = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    client_bytes = Counter()
    server_bytes = Counter()
    endpoint_packets = Counter()
    endpoint_bytes = Counter()
    service_endpoints: Dict[str, Counter[str]] = defaultdict(Counter)
    packet_size_hist = Counter()
    payload_size_hist = Counter()
    packet_size_samples: List[int] = []
    payload_size_samples: List[int] = []
    
    messages: List[ModbusMessage] = []
    artifacts: List[ModbusArtifact] = []
    anomalies: List[ModbusAnomaly] = []
    errors: List[str] = []

    start_time = None
    last_time = None

    flow_map: Dict[Tuple[str, str, int, int], Dict[str, Optional[float]]] = defaultdict(lambda: {
        "first": None,
        "last": None,
    })
    session_last_ts: Dict[str, float] = {}
    session_intervals: Dict[str, List[float]] = defaultdict(list)
    src_dst_counts: Dict[str, Counter[str]] = defaultdict(Counter)
    src_requests: Counter[str] = Counter()
    src_responses: Counter[str] = Counter()
    src_unit_ids: Dict[str, Set[int]] = defaultdict(set)
    src_dst_payload_bytes: Dict[str, Counter[str]] = defaultdict(Counter)
    
    # Aggregate noisy anomalies
    write_events = Counter()
    exception_events = Counter()
    diagnostic_events = Counter()
    enumeration_events = Counter()
    reserved_events = Counter()
    write_details: Dict[Tuple[str, int, str, str], str] = {}
    src_write_requests: Counter[str] = Counter()
    nonstandard_port_counts: Counter[str] = Counter()
    seen_artifacts: Set[str] = set()
    max_anomalies = 200
    asset_write_targets: Dict[Tuple[str, int], Set[str]] = defaultdict(set)
    asset_write_counts: Counter[Tuple[str, int]] = Counter()
    write_target_anoms_seen: Set[str] = set()

    try:
        with status as pbar:
            try:
                total_count = len(reader)
            except Exception:
                total_count = None
            for i, pkt in enumerate(reader):
                if total_count and i % 10 == 0:
                    try:
                        pbar.update(int((i / max(1, total_count)) * 100))
                    except Exception:
                        pass

                total_packets += 1
                pkt_len = int(len(pkt)) if hasattr(pkt, "__len__") else 0
                total_bytes += pkt_len
                ts = safe_float(getattr(pkt, "time", 0))
                if start_time is None: start_time = ts
                last_time = ts
                
                has_tcp = False
                sport = 0
                dport = 0
                payload = b""

                if pkt.haslayer(TCP):
                    has_tcp = True
                    # Debug Check
                    # print(f"DEBUG: Pkt {total_packets} TCP Sport={pkt[TCP].sport} Dport={pkt[TCP].dport}")

                    sport = int(pkt[TCP].sport)
                    dport = int(pkt[TCP].dport)
                    
                    # Check for Payload (Using generic payload access)
                    payload_obj = pkt[TCP].payload
                    payload = bytes(payload_obj) if payload_obj else b""
                    if not payload and Raw is not None and pkt.haslayer(Raw):
                        try:
                            payload = bytes(pkt[Raw].load)
                        except Exception:
                            pass
                else:
                    # Fallback: parse TCP from raw bytes if scapy didn't dissect layers
                    try:
                        raw = bytes(pkt)
                        if len(raw) >= 34 and raw[12:14] == b"\x08\x00":  # Ethernet + IPv4
                            ihl = (raw[14] & 0x0F) * 4
                            proto = raw[23]
                            if proto == 6:  # TCP
                                ip_start = 14
                                total_len = int.from_bytes(raw[16:18], "big")
                                tcp_start = ip_start + ihl
                                if len(raw) >= tcp_start + 20:
                                    data_offset = (raw[tcp_start + 12] >> 4) * 4
                                    sport = int.from_bytes(raw[tcp_start:tcp_start + 2], "big")
                                    dport = int.from_bytes(raw[tcp_start + 2:tcp_start + 4], "big")
                                    payload_start = tcp_start + data_offset
                                    ip_end = ip_start + total_len
                                    payload = raw[payload_start:ip_end] if ip_end <= len(raw) else raw[payload_start:]
                                    has_tcp = True
                    except Exception:
                        pass

                if not has_tcp:
                    continue
                
                # Header Check (MBAP)
                is_modbus = False
                
                # 1. Port-based check
                if sport == MODBUS_TCP_PORT or dport == MODBUS_TCP_PORT:
                     is_modbus = True

                # 2. Heuristic check (if not standard port)
                if not is_modbus and payload and len(payload) >= 8:
                    try:
                        _, proto_id, length, _ = struct.unpack(">HHHB", payload[:7])
                        # Modbus Protocol ID is 0
                        # Length should be remaining bytes approx matching
                        if proto_id == 0:
                            # Verify length consistency
                            remaining = len(payload) - 6
                            if length >= remaining: 
                                is_modbus = True
                    except:
                        pass
                
                if not is_modbus:
                    continue
                if (sport != MODBUS_TCP_PORT and dport != MODBUS_TCP_PORT) and payload:
                    nonstandard_port_counts[f"{sport}->{dport}"] += 1

                modbus_packets += 1
                modbus_bytes += pkt_len

                if not payload or len(payload) < 8:
                    continue

                try:
                    offset = 0
                    parsed_any = False
                    while offset + 7 <= len(payload):
                        try:
                            trans_id, proto_id, length, unit_id = struct.unpack(">HHHB", payload[offset:offset + 7])
                        except struct.error:
                            break

                        if proto_id != PROTOCOL_ID_MODBUS:
                            offset += 1
                            continue

                        if length < 2:
                            offset += 1
                            continue

                        frame_len = 6 + length
                        if offset + frame_len > len(payload):
                            break

                        pdu_start = offset + 7
                        pdu_len = length - 1
                        pdu = payload[pdu_start:pdu_start + pdu_len]
                        offset += frame_len

                        if not pdu:
                            continue

                        parsed_any = True
                        func_code = pdu[0]

                        # Exception Check (MSB set)
                        is_exception = False
                        exception_code = None
                        exception_desc = None

                        original_func = func_code
                        if func_code & 0x80:
                            is_exception = True
                            original_func = func_code & 0x7F
                            if len(pdu) > 1:
                                exception_code = pdu[1]
                                exception_desc = EXCEPTION_CODES.get(exception_code, "Unknown Exception")

                        func_name = FUNC_NAMES.get(original_func)
                        if not func_name:
                            func_name = f"Reserved/Proprietary ({original_func})"
                        func_counts[func_name] += 1
                        unit_ids[unit_id] += 1

                        is_server_response = (sport == MODBUS_TCP_PORT)

                        if IP is not None and pkt.haslayer(IP):
                            src_ip = pkt[IP].src
                            dst_ip = pkt[IP].dst
                        else:
                            src_ip = pkt[0].src if hasattr(pkt[0], 'src') else "0.0.0.0"
                            dst_ip = pkt[0].dst if hasattr(pkt[0], 'dst') else "0.0.0.0"

                        request_detail = None
                        if not is_server_response:
                            src_ips[src_ip] += 1
                            client_bytes[src_ip] += pkt_len

                            src_requests[src_ip] += 1
                            src_dst_counts[src_ip][dst_ip] += 1
                            src_unit_ids[src_ip].add(unit_id)

                            if pdu:
                                src_dst_payload_bytes[src_ip][dst_ip] += len(pdu)

                            request_detail, reg_type, addr, qty = _parse_modbus_request_info(original_func, pdu)

                            # Check for Write Operations (Risk)
                            if original_func in WRITE_FUNCTIONS:
                                write_events[(func_name, unit_id, src_ip, dst_ip)] += 1
                                src_write_requests[src_ip] += 1
                                if request_detail:
                                    write_details[(func_name, unit_id, src_ip, dst_ip)] = request_detail
                                asset_key = (dst_ip, unit_id)
                                asset_write_counts[asset_key] += 1
                                target = _format_register_range(reg_type, addr, qty)
                                if target:
                                    if target not in asset_write_targets[asset_key]:
                                        asset_write_targets[asset_key].add(target)
                                        if asset_write_counts[asset_key] >= WRITE_BASELINE_MIN:
                                            anomaly_key = f"{asset_key}:{target}"
                                            if anomaly_key not in write_target_anoms_seen and len(anomalies) < max_anomalies:
                                                write_target_anoms_seen.add(anomaly_key)
                                                anomalies.append(
                                                    ModbusAnomaly(
                                                        severity="MEDIUM",
                                                        title="Modbus Unexpected Write Target",
                                                        description=f"New write target for asset {dst_ip} Unit {unit_id}: {target}",
                                                        src=src_ip,
                                                        dst=dst_ip,
                                                        ts=ts or 0.0,
                                                    )
                                                )

                            # Diagnostic functions can be risky
                            if original_func in DIAGNOSTIC_FUNCTIONS:
                                diagnostic_events[(func_name, src_ip, dst_ip)] += 1

                            if original_func == 43 and request_detail and request_detail.startswith("mei=0x0e"):
                                enumeration_events[(func_name, src_ip, dst_ip)] += 1
                            elif original_func in ENUMERATION_FUNCTIONS:
                                enumeration_events[(func_name, src_ip, dst_ip)] += 1

                            if func_name.startswith("Reserved/Proprietary"):
                                reserved_events[(original_func, src_ip, dst_ip)] += 1

                        else:
                            dst_ips[src_ip] += 1 # Server is source
                            server_bytes[src_ip] += pkt_len
                            src_responses[src_ip] += 1

                        endpoint_packets[src_ip] += 1
                        endpoint_packets[dst_ip] += 1
                        endpoint_bytes[src_ip] += pkt_len
                        endpoint_bytes[dst_ip] += pkt_len

                        packet_size_hist[_bucketize(pkt_len)] += 1
                        payload_len = len(pdu)
                        payload_size_hist[_bucketize(payload_len)] += 1
                        modbus_payload_bytes += payload_len
                        _append_sample(packet_size_samples, pkt_len)
                        _append_sample(payload_size_samples, payload_len)

                        if pdu:
                            endpoints = service_endpoints.setdefault(func_name, Counter())
                            endpoints[f"{src_ip} -> {dst_ip}"] += 1

                        for kind, detail in equipment_artifacts(payload):
                            key = f"{kind}:{detail}"
                            if key in seen_artifacts:
                                continue
                            seen_artifacts.add(key)
                            if len(artifacts) < 200:
                                artifacts.append(ModbusArtifact(
                                    kind=kind,
                                    detail=detail,
                                    src=src_ip,
                                    dst=dst_ip,
                                    ts=ts or 0.0,
                                ))

                        if is_server_response and original_func == 43 and pdu:
                            device_fields = _parse_device_id_response(pdu)
                            if device_fields:
                                detail = device_fingerprint_from_fields(
                                    {
                                        "vendor": device_fields.get("vendor"),
                                        "model": device_fields.get("model"),
                                        "product": device_fields.get("product") or device_fields.get("product_code"),
                                        "firmware": device_fields.get("revision"),
                                        "software": device_fields.get("user_app"),
                                    },
                                    source="Modbus Read Device ID",
                                )
                                if detail:
                                    key = f"device:{detail}"
                                    if key not in seen_artifacts and len(artifacts) < 200:
                                        seen_artifacts.add(key)
                                        artifacts.append(ModbusArtifact(
                                            kind="device",
                                            detail=detail,
                                            src=src_ip,
                                            dst=dst_ip,
                                            ts=ts or 0.0,
                                        ))

                        flow_key = (src_ip, dst_ip, sport, dport)
                        flow = flow_map[flow_key]
                        if ts is not None:
                            if flow["first"] is None or ts < float(flow["first"] or ts):
                                flow["first"] = ts
                            if flow["last"] is None or ts > float(flow["last"] or ts):
                                flow["last"] = ts

                            session_key = f"{src_ip}:{sport} -> {dst_ip}:{dport}"
                            last_ts = session_last_ts.get(session_key)
                            if last_ts is not None:
                                interval = ts - last_ts
                                if interval >= 0:
                                    session_intervals[session_key].append(interval)
                            session_last_ts[session_key] = ts

                        if is_exception:
                            exception_events[(exception_code, exception_desc, original_func, src_ip, dst_ip)] += 1

                        # Store message (limit to reasonable number if memory constraint, but user wants details)
                        response_detail = None
                        if is_server_response and not is_exception:
                            response_detail = _parse_modbus_response_detail(original_func, pdu)

                        messages.append(ModbusMessage(
                            ts=ts,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=sport,
                            dst_port=dport,
                            trans_id=trans_id,
                            unit_id=unit_id,
                            func_code=func_code,
                            func_name=func_name,
                            is_exception=is_exception,
                            exception_code=exception_code,
                            exception_desc=exception_desc,
                            payload_len=len(pdu),
                            detail=request_detail if not is_server_response else response_detail,
                            direction="response" if is_server_response else "request",
                        ))

                    if not parsed_any and sport != MODBUS_TCP_PORT and dport != MODBUS_TCP_PORT:
                        modbus_packets -= 1

                except struct.error:
                    pass
                except Exception:
                    pass

    except Exception as e:
        errors.append(f"{type(e).__name__}: {e}")
    finally:
        try:
            reader.close()
        except Exception:
            pass
    
    duration = 0.0
    if start_time is not None and last_time is not None:
        duration = last_time - start_time

    packet_size_stats = _stats_from_samples(packet_size_samples)
    payload_size_stats = _stats_from_samples(payload_size_samples)

    flow_duration_buckets: Dict[str, Counter[str]] = {
        "all": Counter(),
        "requests": Counter(),
        "responses": Counter(),
    }
    for (src_ip, dst_ip, sport, dport), info in flow_map.items():
        start = info.get("first")
        end = info.get("last")
        if start is None or end is None:
            continue
        duration_val = max(0.0, float(end) - float(start))
        bucket = _bucketize_duration(duration_val)
        flow_duration_buckets["all"][bucket] += 1
        if dport == MODBUS_TCP_PORT:
            flow_duration_buckets["requests"][bucket] += 1
        if sport == MODBUS_TCP_PORT:
            flow_duration_buckets["responses"][bucket] += 1

    for (func_name, unit_id, src_ip, dst_ip), count in write_events.items():
        if len(anomalies) >= max_anomalies:
            break
        suffix = f" (x{count})" if count > 1 else ""
        detail = write_details.get((func_name, unit_id, src_ip, dst_ip))
        detail_text = f" [{detail}]" if detail else ""
        anomalies.append(ModbusAnomaly(
            severity="HIGH",
            title="Modbus Write Operation",
            description=f"Write command ({func_name}) sent to Unit ID {unit_id}{suffix}{detail_text}",
            src=src_ip,
            dst=dst_ip,
            ts=0.0,
        ))
        if unit_id == 0:
            if len(anomalies) < max_anomalies:
                anomalies.append(ModbusAnomaly(
                    severity="CRITICAL",
                    title="Modbus Broadcast Write",
                    description=f"Broadcast write using {func_name} to Unit ID 0{suffix}{detail_text}",
                    src=src_ip,
                    dst=dst_ip,
                    ts=0.0,
                ))

    for (func_name, src_ip, dst_ip), count in diagnostic_events.items():
        suffix = f" (x{count})" if count > 1 else ""
        if len(anomalies) < max_anomalies:
            anomalies.append(ModbusAnomaly(
                severity="LOW",
                title="Modbus Diagnostic/Info",
                description=f"Diagnostic or identity request ({func_name}){suffix}",
                src=src_ip,
                dst=dst_ip,
                ts=0.0,
            ))

    for (func_name, src_ip, dst_ip), count in enumeration_events.items():
        if len(anomalies) >= max_anomalies:
            break
        suffix = f" (x{count})" if count > 1 else ""
        anomalies.append(ModbusAnomaly(
            severity="LOW",
            title="Modbus Enumeration",
            description=f"Device identity discovery ({func_name}){suffix}",
            src=src_ip,
            dst=dst_ip,
            ts=0.0,
        ))

    for (func_code, src_ip, dst_ip), count in reserved_events.items():
        if len(anomalies) >= max_anomalies:
            break
        suffix = f" (x{count})" if count > 1 else ""
        anomalies.append(ModbusAnomaly(
            severity="LOW",
            title="Modbus Proprietary Function",
            description=f"Reserved/proprietary function {func_code}{suffix}",
            src=src_ip,
            dst=dst_ip,
            ts=0.0,
        ))

    for (exc_code, exc_desc, original_func, src_ip, dst_ip), count in exception_events.items():
        if len(anomalies) >= max_anomalies:
            break
        suffix = f" (x{count})" if count > 1 else ""
        desc_text = f"Exception {exc_code} ({exc_desc}) for Function {original_func}{suffix}"
        severity = "MEDIUM"
        if exc_desc in {"Illegal Function", "Illegal Data Address"}:
            severity = "HIGH"
        anomalies.append(ModbusAnomaly(
            severity=severity,
            title="Modbus Exception",
            description=desc_text,
            src=src_ip,
            dst=dst_ip,
            ts=0.0,
        ))

    for src_ip, dsts in src_dst_counts.items():
        unique_dsts = len(dsts)
        req_count = src_requests.get(src_ip, 0)
        resp_count = src_responses.get(src_ip, 0)
        if unique_dsts >= 20 and req_count > resp_count * 2:
            if len(anomalies) < max_anomalies:
                anomalies.append(ModbusAnomaly(
                    severity="MEDIUM",
                    title="Modbus Scanning/Probing",
                    description=f"Source contacted {unique_dsts} endpoints with low response rate.",
                    src=src_ip,
                    dst="*",
                    ts=0.0,
                ))

        unit_count = len(src_unit_ids.get(src_ip, set()))
        if unit_count >= 20:
            if len(anomalies) < max_anomalies:
                anomalies.append(ModbusAnomaly(
                    severity="MEDIUM",
                    title="Modbus Unit ID Scan",
                    description=f"Source probed {unit_count} Unit IDs.",
                    src=src_ip,
                    dst="*",
                    ts=0.0,
                ))

    for src_ip, dsts in src_dst_payload_bytes.items():
        for dst_ip, byte_count in dsts.items():
            if byte_count >= 1_000_000 and _is_public_ip(dst_ip) and _is_private_ip(src_ip):
                if len(anomalies) < max_anomalies:
                    anomalies.append(ModbusAnomaly(
                        severity="HIGH",
                        title="Possible Modbus Data Exfiltration",
                        description=f"{byte_count} bytes sent to public IP.",
                        src=src_ip,
                        dst=dst_ip,
                        ts=0.0,
                    ))

    for session_key, intervals in session_intervals.items():
        if len(intervals) < 6:
            continue
        avg = sum(intervals) / len(intervals)
        if avg <= 0:
            continue
        variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
        cv = math.sqrt(variance) / avg
        if cv <= 0.2 and 0.5 <= avg <= 60.0:
            src_part, dst_part = session_key.split(" -> ", 1)
            src_ip = src_part.split(":", 1)[0]
            dst_ip = dst_part.split(":", 1)[0]
            if len(anomalies) < max_anomalies:
                anomalies.append(ModbusAnomaly(
                    severity="LOW",
                    title="Possible Modbus Beaconing",
                    description=f"Regular interval traffic (~{avg:.2f}s) observed.",
                    src=src_ip,
                    dst=dst_ip,
                    ts=0.0,
                ))

    for src_ip, count in src_write_requests.items():
        req_count = src_requests.get(src_ip, 0)
        ratio = (count / req_count) if req_count else 0.0
        if count >= 20 and ratio >= 0.3 and len(anomalies) < max_anomalies:
            anomalies.append(ModbusAnomaly(
                severity="HIGH",
                title="Modbus Write Burst",
                description=f"{count} write requests ({ratio:.0%} of client traffic).",
                src=src_ip,
                dst="*",
                ts=0.0,
            ))

    if nonstandard_port_counts:
        for session, count in nonstandard_port_counts.most_common(6):
            if len(anomalies) >= max_anomalies:
                break
            anomalies.append(ModbusAnomaly(
                severity="MEDIUM",
                title="Modbus on Non-Standard Port",
                description=f"Modbus signature observed on {session} ({count} packets).",
                src="*",
                dst="*",
                ts=0.0,
            ))

    public_endpoints = [ip for ip in set(src_ips) | set(dst_ips) if _is_public_ip(ip)]
    if public_endpoints and len(anomalies) < max_anomalies:
        anomalies.append(ModbusAnomaly(
            severity="HIGH",
            title="Modbus Exposure to Public IP",
            description=f"Modbus traffic observed with public endpoint(s): {', '.join(sorted(public_endpoints)[:5])}.",
            src="*",
            dst="*",
            ts=0.0,
        ))

    return ModbusAnalysis(
        path=path,
        duration=duration,
        total_packets=total_packets,
        modbus_packets=modbus_packets,
        total_bytes=total_bytes,
        modbus_bytes=modbus_bytes,
        modbus_payload_bytes=modbus_payload_bytes,
        func_counts=func_counts,
        unit_ids=unit_ids,
        src_ips=src_ips,
        dst_ips=dst_ips,
        client_bytes=client_bytes,
        server_bytes=server_bytes,
        endpoint_packets=endpoint_packets,
        endpoint_bytes=endpoint_bytes,
        service_endpoints=dict(service_endpoints),
        packet_size_hist=packet_size_hist,
        payload_size_hist=payload_size_hist,
        packet_size_stats=packet_size_stats,
        payload_size_stats=payload_size_stats,
        flow_duration_buckets=flow_duration_buckets,
        messages=messages,
        artifacts=artifacts,
        anomalies=anomalies,
        errors=errors
    )
