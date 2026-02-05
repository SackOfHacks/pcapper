from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import struct

try:
    from scapy.layers.inet import TCP, UDP
    from scapy.packet import Raw
except ImportError:
    TCP = UDP = Raw = None

from .pcap_cache import get_reader
from .utils import detect_file_type, safe_float

# --- Constants ---

DNP3_PORT = 20000
DNP3_START_BYTES = b"\x05\x64"

# Application Layer Function Codes
FUNC_CODES = {
    0: "Confirm",
    1: "Read",
    2: "Write",
    3: "Select",
    4: "Operate",
    5: "Direct Operate",
    6: "Direct Operate (No Ack)",
    7: "Immediate Freeze",
    8: "Immediate Freeze (No Ack)",
    9: "Freeze and Clear",
    10: "Freeze and Clear (No Ack)",
    11: "Freeze with Time",
    12: "Freeze with Time (No Ack)",
    13: "Cold Restart",
    14: "Warm Restart",
    15: "Initialize Data",
    16: "Initialize Application",
    17: "Start Application",
    18: "Stop Application",
    19: "Save Configuration",
    20: "Enable Unsolicited",
    21: "Disable Unsolicited",
    22: "Assign Class",
    23: "Delay Measurement",
    24: "Record Current Time",
    25: "Open File",
    26: "Close File",
    27: "Delete File",
    28: "Get File Info",
    29: "Authenticate File",
    30: "Abort File",
    31: "Activate Config",
    32: "Authenticate Req",
    33: "Authenticate Err",
    129: "Response"
}

# --- Dataclasses ---

@dataclass
class Dnp3Message:
    ts: float
    src_ip: str
    dst_ip: str
    src_addr: int # Data Link Source
    dst_addr: int # Data Link Dest
    len: int
    func_code: Optional[int]
    func_name: str
    is_master: bool # True if sending requests typically (heuristically)
    app_control: Optional[int] = None
    unsolicited: bool = False

@dataclass
class Dnp3Anomaly:
    severity: str # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    src: str
    dst: str
    ts: float

@dataclass
class Dnp3Analysis:
    path: Path
    duration: float = 0.0
    total_packets: int = 0
    dnp3_packets: int = 0
    
    # Statistics
    func_counts: Counter[str] = field(default_factory=Counter)
    src_addrs: Counter[int] = field(default_factory=Counter) # DNP3 Addresses
    dst_addrs: Counter[int] = field(default_factory=Counter)
    ip_endpoints: Counter[str] = field(default_factory=Counter) # IP addresses participating
    write_ops: Counter[str] = field(default_factory=Counter)
    file_ops: Counter[str] = field(default_factory=Counter)
    auth_ops: Counter[str] = field(default_factory=Counter)
    restart_ops: Counter[str] = field(default_factory=Counter)
    unsolicited_responses: int = 0
    
    # Activity
    messages: List[Dnp3Message] = field(default_factory=list)
    anomalies: List[Dnp3Anomaly] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    @property
    def unique_dnp3_addresses(self) -> int:
        return len(set(list(self.src_addrs.keys()) + list(self.dst_addrs.keys())))


def analyze_dnp3(path: Path, show_status: bool = True) -> Dnp3Analysis:
    if TCP is None:
        return Dnp3Analysis(path, 0.0, 0, 0, Counter(), Counter(), Counter(), Counter(), [], [], ["Scapy unavailable (TCP missing)"])

    try:
        reader, status, _stream, _size_bytes, _file_type = get_reader(
            path, show_status=show_status
        )
    except Exception as e:
        return Dnp3Analysis(path, 0.0, 0, 0, Counter(), Counter(), Counter(), Counter(), [], [], [f"Error: {e}"])
    # Attempt to find file handle for progress
    # for attr in ("fd", "f", "fh", "_fh", "_file", "file"):
    #    candidate = getattr(reader, attr, None)
    #    if candidate is not None:
    #        stream = candidate
    #        break

    total_packets = 0
    dnp3_packets = 0
    
    func_counts = Counter()
    src_addrs = Counter()
    dst_addrs = Counter()
    ip_endpoints = Counter()
    write_ops = Counter()
    file_ops = Counter()
    auth_ops = Counter()
    restart_ops = Counter()
    unsolicited_responses = 0
    
    messages: List[Dnp3Message] = []
    anomalies: List[Dnp3Anomaly] = []
    errors: List[str] = []

    start_time = None
    last_time = None
    
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
                
                # Check ports
                has_transport = False
                sport, dport = 0, 0
                payload = b""
                
                if pkt.haslayer(TCP):
                    has_transport = True
                    sport = int(pkt[TCP].sport)
                    dport = int(pkt[TCP].dport)
                    # print(f"DEBUG DNP3: TCP {sport}->{dport}")
                    payload_obj = pkt[TCP].payload
                    payload = bytes(payload_obj) if payload_obj else b""
                    if not payload and Raw is not None and pkt.haslayer(Raw):
                        try:
                            payload = bytes(pkt[Raw].load)
                        except Exception:
                            pass
                elif pkt.haslayer(UDP):
                    has_transport = True
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
                    # Fallback: parse TCP/UDP from raw bytes if scapy didn't dissect layers
                    try:
                        raw = bytes(pkt)
                        if len(raw) >= 34 and raw[12:14] == b"\x08\x00":  # Ethernet + IPv4
                            ihl = (raw[14] & 0x0F) * 4
                            proto = raw[23]
                            ip_start = 14
                            total_len = int.from_bytes(raw[16:18], "big")
                            transport_start = ip_start + ihl
                            if proto == 6 and len(raw) >= transport_start + 20:
                                data_offset = (raw[transport_start + 12] >> 4) * 4
                                sport = int.from_bytes(raw[transport_start:transport_start + 2], "big")
                                dport = int.from_bytes(raw[transport_start + 2:transport_start + 4], "big")
                                payload_start = transport_start + data_offset
                                ip_end = ip_start + total_len
                                payload = raw[payload_start:ip_end] if ip_end <= len(raw) else raw[payload_start:]
                                has_transport = True
                            elif proto == 17 and len(raw) >= transport_start + 8:
                                sport = int.from_bytes(raw[transport_start:transport_start + 2], "big")
                                dport = int.from_bytes(raw[transport_start + 2:transport_start + 4], "big")
                                payload_start = transport_start + 8
                                ip_end = ip_start + total_len
                                payload = raw[payload_start:ip_end] if ip_end <= len(raw) else raw[payload_start:]
                                has_transport = True
                    except Exception:
                        pass

                if not has_transport:
                    continue
                
                # Check for DNP3 Header Start bytes (0x05 0x64)
                start_idx = payload.find(DNP3_START_BYTES) if payload else -1
                
                is_dnp3 = False
                
                # 1. Port match
                if sport == DNP3_PORT or dport == DNP3_PORT:
                    is_dnp3 = True
                    
                # 2. Heuristic: Start bytes + Length check
                if not is_dnp3 and start_idx != -1:
                    if len(payload) >= start_idx + 10:
                        is_dnp3 = True
                
                if not is_dnp3:
                    continue
                
                dnp3_packets += 1
                
                if start_idx == -1:
                    # Generic port traffic without DNP3 signature in this packet
                    continue

                # Align to potential DNP3 frame
                dnp3_data = payload[start_idx:]
                if len(dnp3_data) < 10: # Header is 10 bytes
                    continue
                
                try:
                    # Header: Start(2), Len(1), Control(1), Dest(2), Src(2), CRC(2)
                    dl_len = dnp3_data[2]
                    dl_ctrl = dnp3_data[3]
                    dl_dst = struct.unpack("<H", dnp3_data[4:6])[0]
                    dl_src = struct.unpack("<H", dnp3_data[6:8])[0]
                    
                    # dnp3_packets counted above
                    
                    src_ip = pkt[0].src if hasattr(pkt[0], 'src') else "?"
                    dst_ip = pkt[0].dst if hasattr(pkt[0], 'dst') else "?"
                    
                    ip_endpoints[src_ip] += 1
                    ip_endpoints[dst_ip] += 1
                    
                    src_addrs[dl_src] += 1
                    dst_addrs[dl_dst] += 1
                    
                    # Application Layer Parsing (Simplified)
                    # Transport header is usually 1 byte after Data Link header (offset 10)
                    # TP Header: FIN/FIR/Seq
                    # APP Header starts after TP header.
                    
                    # NOTE: DNP3 frames can be fragmented. Simple parser assumes App header follows immediately in first frame.
                    
                    func_code = None
                    func_name = "Unknown/Fragment"
                    app_control = None
                    unsolicited = False
                    
                    if len(dnp3_data) > 11: # 10 Header + 1 Transport + at least 1 App
                        # Transport Byte at offset 10
                        # App Byte at offset 11 (Request/Response Header)
                        # App Header: AC(1), FC(1)
                        
                        # Just checking if it looks like an App header
                        # This is a bit heuristic without full reassembly
                        
                        app_control = dnp3_data[11] if len(dnp3_data) > 11 else None
                        if app_control is not None:
                            unsolicited = (app_control & 0x10) != 0
                            if unsolicited:
                                unsolicited_responses += 1

                        app_fc = dnp3_data[12] if len(dnp3_data) > 12 else None
                        # Actually:
                        # Header (10)
                        # Transport (1 usually)
                        # Application Request: Control(1), FunctionCode(1)
                        # So FC is at index 10 + 1 + 1 = 12
                        
                        if app_fc is not None:
                            func_code = app_fc
                            func_name = FUNC_CODES.get(func_code, f"Unknown ({func_code})")
                            
                            func_counts[func_name] += 1
                            
                            # Anomalies
                            if func_code in (13, 14): # Restarts
                                restart_ops[func_name] += 1
                                anomalies.append(Dnp3Anomaly(
                                    "HIGH", "DNP3 Restart", f"System restart command ({func_name}) detected",
                                    src_ip, dst_ip, ts
                                ))
                            
                            if func_code == 2: # Write
                                write_ops[func_name] += 1
                                anomalies.append(Dnp3Anomaly(
                                    "MEDIUM", "DNP3 Write", f"Write command detected to {dst_ip} (Addr {dl_dst})",
                                    src_ip, dst_ip, ts
                                ))
                                
                            if func_code in (0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1F): # File operations (23-31 roughly)
                                # 25=Open, 27=Delete etc.
                                if 25 <= func_code <= 27:
                                    file_ops[func_name] += 1
                                    anomalies.append(Dnp3Anomaly(
                                        "HIGH", "DNP3 File Op", f"File operation ({func_name}) detected",
                                        src_ip, dst_ip, ts
                                    ))

                            if func_code in (32, 33):
                                auth_ops[func_name] += 1
                                anomalies.append(Dnp3Anomaly(
                                    "MEDIUM", "DNP3 Auth", f"Secure auth function ({func_name}) observed",
                                    src_ip, dst_ip, ts
                                ))
                            
                            if func_code == 129: # Response
                                # Check Internal Indications (IIN)
                                # Resp Header: AC(1), FC(1), IIN(2)
                                if len(dnp3_data) >= 15:
                                    iin = struct.unpack(">H", dnp3_data[13:15])[0] # IIN is usually Big Endian? DNP3 is Little Endian mostly
                                    # Wait, DNP3 documentation says LSB first usually.
                                    iin = struct.unpack("<H", dnp3_data[13:15])[0] 
                                    
                                    # IIN1.0 = All Stations
                                    # IIN1.4 = Trouble
                                    # IIN1.5 = Device Restart
                                    
                                    if iin & 0x0080: # Device Restart
                                        anomalies.append(Dnp3Anomaly(
                                            "MEDIUM", "IIN Device Restart", "Internal Indication: Device Restart detected",
                                            src_ip, dst_ip, ts
                                        ))
                                    if iin & 0x0040: # Trouble
                                        anomalies.append(Dnp3Anomaly(
                                            "MEDIUM", "IIN Device Trouble", "Internal Indication: Device Trouble/Error",
                                            src_ip, dst_ip, ts
                                        ))
                    
                    messages.append(Dnp3Message(
                        ts=ts,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_addr=dl_src,
                        dst_addr=dl_dst,
                        len=dl_len,
                        func_code=func_code,
                        func_name=func_name,
                        is_master=(func_code is not None and func_code != 129),
                        app_control=app_control,
                        unsolicited=unsolicited,
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

    return Dnp3Analysis(
        path=path,
        duration=duration,
        total_packets=total_packets,
        dnp3_packets=dnp3_packets,
        func_counts=func_counts,
        src_addrs=src_addrs,
        dst_addrs=dst_addrs,
        ip_endpoints=ip_endpoints,
        write_ops=write_ops,
        file_ops=file_ops,
        auth_ops=auth_ops,
        restart_ops=restart_ops,
        unsolicited_responses=unsolicited_responses,
        messages=messages,
        anomalies=anomalies,
        errors=errors
    )
