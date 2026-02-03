from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import struct

try:
    from scapy.layers.inet import TCP, IP
    from scapy.packet import Raw
except ImportError:
    TCP = IP = Raw = None

from .pcap_cache import get_reader
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
class ModbusAnalysis:
    path: Path
    duration: float = 0.0
    total_packets: int = 0
    modbus_packets: int = 0
    
    # Statistics
    func_counts: Counter[str] = field(default_factory=Counter)
    unit_ids: Counter[int] = field(default_factory=Counter)
    src_ips: Counter[str] = field(default_factory=Counter) # Client IPs usually
    dst_ips: Counter[str] = field(default_factory=Counter) # Server/PLC IPs
    
    # Activity
    messages: List[ModbusMessage] = field(default_factory=list)
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

def analyze_modbus(path: Path, show_status: bool = True) -> ModbusAnalysis:
    if TCP is None:
         return ModbusAnalysis(path, 0.0, 0, 0, Counter(), Counter(), Counter(), Counter(), [], [], ["Scapy unavailable (TCP missing)"])

    try:
        reader, status, _stream, _size_bytes, _file_type = get_reader(
            path, show_status=show_status
        )
    except Exception as e:
        return ModbusAnalysis(path, 0.0, 0, 0, Counter(), Counter(), Counter(), Counter(), [], [], [f"Error: {e}"])
    # Attempt to find file handle for progress
    # for attr in ("fd", "f", "fh", "_fh", "_file", "file"):
    #    candidate = getattr(reader, attr, None)
    #    if candidate is not None:
    #        stream = candidate
    #        break

    total_packets = 0
    modbus_packets = 0
    
    func_counts = Counter()
    unit_ids = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    
    messages: List[ModbusMessage] = []
    anomalies: List[ModbusAnomaly] = []
    errors: List[str] = []

    start_time = None
    last_time = None
    
    # Aggregate noisy anomalies
    write_events = Counter()
    exception_events = Counter()
    diagnostic_events = Counter()

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

                if not payload or len(payload) < 8:
                    continue
                    
                try:
                    trans_id, proto_id, length, unit_id = struct.unpack(">HHHB", payload[:7])
                    
                    # Double check protocol ID just in case port matched but data is garbage
                    if proto_id != PROTOCOL_ID_MODBUS:
                        # If heuristic matched, it should be 0.
                        if sport != MODBUS_TCP_PORT and dport != MODBUS_TCP_PORT:
                            modbus_packets -= 1 # Backtrack count if heuristic failed deep check
                            continue
                        # If port 502, we count it as "Modbus Packet" (likely malformed or noise) but don't parse deeper
                        continue 
                    
                    # PDU starts at offset 7
                    pdu = payload[7:]
                    if not pdu: continue
                    
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
                            
                    func_name = FUNC_NAMES.get(original_func, f"Unknown ({original_func})")
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

                        # Check for Write Operations (Risk)
                        if original_func in (5, 6, 15, 16, 21, 22, 23):
                            write_events[(func_name, unit_id, src_ip, dst_ip)] += 1

                        # Diagnostic functions can be risky
                        if original_func in (8, 43):
                            diagnostic_events[(func_name, src_ip, dst_ip)] += 1

                    else:
                        dst_ips[src_ip] += 1 # Server is source

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
                    
                except struct.error:
                    pass
                except Exception:
                    pass

    except Exception as e:
        errors.append(str(e))
    # finally:
    #    reader.close()
    
    duration = 0.0
    if start_time and last_time:
        duration = last_time - start_time

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
        anomalies.append(ModbusAnomaly(
            severity="MEDIUM",
            title="Modbus Exception",
            description=desc_text,
            src=src_ip,
            dst=dst_ip,
            ts=0.0,
        ))

    return ModbusAnalysis(
        path=path,
        duration=duration,
        total_packets=total_packets,
        modbus_packets=modbus_packets,
        func_counts=func_counts,
        unit_ids=unit_ids,
        src_ips=src_ips,
        dst_ips=dst_ips,
        messages=messages,
        anomalies=anomalies,
        errors=errors
    )
