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
    seen_artifacts: Set[str] = set()

    try:
        with status as pbar:
            total_count = len(reader)
            for i, pkt in enumerate(reader):
                if i % 10 == 0:
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

                        if not is_server_response:
                            src_ips[src_ip] += 1
                            client_bytes[src_ip] += pkt_len

                            src_requests[src_ip] += 1
                            src_dst_counts[src_ip][dst_ip] += 1
                            src_unit_ids[src_ip].add(unit_id)

                            if pdu:
                                src_dst_payload_bytes[src_ip][dst_ip] += len(pdu)

                            # Check for Write Operations (Risk)
                            if original_func in (5, 6, 15, 16, 21, 22, 23):
                                write_events[(func_name, unit_id, src_ip, dst_ip)] += 1

                            # Diagnostic functions can be risky
                            if original_func in (8, 43):
                                diagnostic_events[(func_name, src_ip, dst_ip)] += 1

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
                            payload_len=len(pdu)
                        ))

                    if not parsed_any and sport != MODBUS_TCP_PORT and dport != MODBUS_TCP_PORT:
                        modbus_packets -= 1

                except struct.error:
                    pass
                except Exception:
                    pass

    except Exception as e:
        errors.append(str(e))
    # finally:
    #    reader.close()
    
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
        suffix = f" (x{count})" if count > 1 else ""
        anomalies.append(ModbusAnomaly(
            severity="HIGH",
            title="Modbus Write Operation",
            description=f"Write command ({func_name}) sent to Unit ID {unit_id}{suffix}",
            src=src_ip,
            dst=dst_ip,
            ts=0.0,
        ))
        if unit_id == 0:
            anomalies.append(ModbusAnomaly(
                severity="CRITICAL",
                title="Modbus Broadcast Write",
                description=f"Broadcast write using {func_name} to Unit ID 0{suffix}",
                src=src_ip,
                dst=dst_ip,
                ts=0.0,
            ))

    for (func_name, src_ip, dst_ip), count in diagnostic_events.items():
        suffix = f" (x{count})" if count > 1 else ""
        anomalies.append(ModbusAnomaly(
            severity="LOW",
            title="Modbus Diagnostic/Info",
            description=f"Diagnostic or Identity request ({func_name}){suffix}",
            src=src_ip,
            dst=dst_ip,
            ts=0.0,
        ))

    for (exc_code, exc_desc, original_func, src_ip, dst_ip), count in exception_events.items():
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
            anomalies.append(ModbusAnomaly(
                severity="LOW",
                title="Possible Modbus Beaconing",
                description=f"Regular interval traffic (~{avg:.2f}s) observed.",
                src=src_ip,
                dst=dst_ip,
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
