from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
import struct

try:
    from scapy.layers.inet import TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw, Packet
    from scapy.utils import PcapReader, PcapNgReader
except ImportError:
    TCP = UDP = Raw = None

from .progress import build_statusbar
from .utils import detect_file_type, safe_float

# --- Dataclasses ---

@dataclass
class NtlmSession:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    username: str = "Unknown"
    domain: str = "Unknown"
    workstation: str = "Unknown"
    version: str = "Unknown" # NTLMv1, NTLMv2
    message_type: str = "Unknown"
    ts: float = 0.0

@dataclass
class NtlmAnomaly:
    severity: str # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    packet_index: int
    src: str
    dst: str

@dataclass
class NtlmAnalysis:
    path: Path
    duration: float = 0.0
    total_packets: int = 0
    ntlm_packets: int = 0
    versions: Counter[str] = field(default_factory=Counter)
    raw_users: Counter[str] = field(default_factory=Counter) # Just names
    raw_domains: Counter[str] = field(default_factory=Counter)
    raw_workstations: Counter[str] = field(default_factory=Counter)
    sessions: List[NtlmSession] = field(default_factory=list)
    anomalies: List[NtlmAnomaly] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def total_sessions(self) -> int:
        return len(self.sessions)

    @property
    def authenticated_sessions(self) -> int:
        return sum(1 for s in self.sessions if s.message_type == "Authenticate")

    @property
    def unique_users(self) -> Set[Tuple[str, str]]:
        # Returns (domain, username) tuples
        s = set()
        for session in self.sessions:
            if session.username:
                s.add((session.domain, session.username))
        return s

    @property
    def unique_domains(self) -> Set[str]:
        return set(self.raw_domains.keys())

    @property
    def unique_workstations(self) -> Set[str]:
        return set(s.workstation for s in self.sessions if s.workstation and s.workstation != "Unknown")


# --- Constants ---

NTLM_SIG = b"NTLMSSP\x00"

MSG_TYPE_NEGOTIATE = 1
MSG_TYPE_CHALLENGE = 2
MSG_TYPE_AUTHENTICATE = 3

# Flags
NTLMSSP_NEGOTIATE_56 = 0x80000000
NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000
NTLMSSP_NEGOTIATE_128 = 0x20000000
NTLMSSP_NEGOTIATE_VERSION = 0x02000000
NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000
NTLMSSP_REQUEST_NON_NT_SESSION_KEY = 0x00400000
NTLMSSP_NEGOTIATE_IDENTIFY = 0x00100000
NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
NTLMSSP_TARGET_TYPE_SERVER = 0x00020000
NTLMSSP_TARGET_TYPE_DOMAIN = 0x00010000
NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000
NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED = 0x00001000
NTLMSSP_NEGOTIATE_ANONYMOUS = 0x00000800
NTLMSSP_NEGOTIATE_NTLM = 0x00000200 # NTLM v1
NTLMSSP_NEGOTIATE_LM_KEY = 0x00000080
NTLMSSP_NEGOTIATE_DATAGRAM = 0x00000040
NTLMSSP_NEGOTIATE_SEAL = 0x00000020
NTLMSSP_NEGOTIATE_SIGN = 0x00000010
NTLMSSP_REQUEST_TARGET = 0x00000004
NTLMSSP_NEGOTIATE_OEM = 0x00000002
NTLMSSP_NEGOTIATE_UNICODE = 0x00000001

# --- Helpers ---

def _read_sec_buffer(data: bytes, offset: int) -> Tuple[int, int, int]:
    # Length (2), Allocated (2), Offset (4)
    if offset + 8 > len(data): return 0, 0, 0
    length, alloc, val_offset = struct.unpack("<HHI", data[offset:offset+8])
    return length, alloc, val_offset

def _extract_string(data: bytes, length: int, offset: int, unicode: bool) -> str:
    if offset + length > len(data): return "Error"
    raw = data[offset:offset+length]
    try:
        if unicode:
            return raw.decode("utf-16le")
        else:
            return raw.decode("ascii")
    except:
        return raw.hex()

# --- Analysis Functions ---

def analyze_ntlm(path: Path, show_status: bool = True) -> NtlmAnalysis:
    if TCP is None:
         return NtlmAnalysis(path, 0.0, 0, 0, Counter(), Counter(), Counter(), Counter(), [], [], ["Scapy unavailable"])

    ftype = detect_file_type(path)
    try:
        reader = PcapNgReader(str(path)) if ftype == "pcapng" else PcapReader(str(path))
    except Exception as e:
        return NtlmAnalysis(path, 0.0, 0, 0, Counter(), Counter(), Counter(), Counter(), [], [], [f"Error: {e}"])

    size_bytes = 0
    try:
        size_bytes = path.stat().st_size
    except Exception:
        pass
        
    status = build_statusbar(path, enabled=show_status)
    stream = None
    for attr in ("fd", "f", "fh", "_fh", "_file", "file"):
        candidate = getattr(reader, attr, None)
        if candidate is not None:
            stream = candidate
            break

    total_packets = 0
    ntlm_packets = 0
    
    versions = Counter()
    users = Counter()
    domains = Counter()
    workstations = Counter()
    
    sessions: List[NtlmSession] = []
    anomalies: List[NtlmAnomaly] = []
    errors: List[str] = []

    start_time = None
    last_time = None

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            total_packets += 1
            ts = safe_float(getattr(pkt, "time", 0))
            if start_time is None: start_time = ts
            last_time = ts
            
            # Look for NTLM Signature in Raw payload
            # Can be in TCP or UDP
            if not pkt.haslayer(Raw): continue
            
            payload = bytes(pkt[Raw])
            idx = payload.find(NTLM_SIG)
            
            if idx == -1: continue
            
            ntlm_packets += 1
            ntlm_data = payload[idx:]
            
            if len(ntlm_data) < 12: continue
            
            # Header
            try:
                msg_type = struct.unpack("<I", ntlm_data[8:12])[0]
                
                src = pkt[0].src if hasattr(pkt[0], 'src') else "0.0.0.0"
                dst = pkt[0].dst if hasattr(pkt[0], 'dst') else "0.0.0.0"
                sport = 0
                dport = 0
                if pkt.haslayer(TCP):
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    sport = pkt[UDP].sport
                    dport = pkt[UDP].dport    

                if msg_type == MSG_TYPE_AUTHENTICATE:
                    # Message Type 3
                    # Sig(8), Type(4), LmResp(8), NtResp(8), Domain(8), User(8), Workstation(8), SessionKey(8), Flags(4)
                    
                    if len(ntlm_data) < 64: continue
                    
                    # Offsets relative to start of ntlmssp header
                    lm_len, lm_alloc, lm_off = _read_sec_buffer(ntlm_data, 12)
                    nt_len, nt_alloc, nt_off = _read_sec_buffer(ntlm_data, 20)
                    dom_len, dom_alloc, dom_off = _read_sec_buffer(ntlm_data, 28)
                    user_len, user_alloc, user_off = _read_sec_buffer(ntlm_data, 36)
                    ws_len, ws_alloc, ws_off = _read_sec_buffer(ntlm_data, 44)
                    sk_len, sk_alloc, sk_off = _read_sec_buffer(ntlm_data, 52)
                    flags = struct.unpack("<I", ntlm_data[60:64])[0]
                    
                    is_unicode = (flags & NTLMSSP_NEGOTIATE_UNICODE) != 0
                    
                    domain = _extract_string(ntlm_data, dom_len, dom_off, is_unicode)
                    user = _extract_string(ntlm_data, user_len, user_off, is_unicode)
                    workstation = _extract_string(ntlm_data, ws_len, ws_off, is_unicode)
                    
                    users[user] += 1
                    domains[domain] += 1
                    workstations[workstation] += 1
                    
                    # Version Check (Rough heuristic based on response lengths)
                    # NTLMv1: NT Resp is 24 bytes
                    # NTLMv2: NT Resp is > 24 bytes (usually contains HMAC, etc)
                    ver = "Unknown"
                    if nt_len == 24:
                        ver = "NTLMv1"
                        versions["NTLMv1"] += 1
                        anomalies.append(NtlmAnomaly("CRITICAL", "NTLMv1 Auth", f"Legacy NTLMv1 authentication used by {user}", total_packets, src, dst))
                    elif nt_len > 24:
                        ver = "NTLMv2"
                        versions["NTLMv2"] += 1
                        
                    # Check for Null Session / Anonymous
                    if flags & NTLMSSP_NEGOTIATE_ANONYMOUS:
                        anomalies.append(NtlmAnomaly("HIGH", "Anonymous NTLM", "Anonymous/Null session attempted", total_packets, src, dst))
                        user = "(Anonymous)"
                        
                    sessions.append(NtlmSession(
                        src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                        username=user, domain=domain, workstation=workstation, 
                        version=ver, message_type="Authenticate", ts=ts
                    ))
                    
                elif msg_type == MSG_TYPE_CHALLENGE:
                     # Message Type 2 (Server Challenge)
                     pass
                     
                elif msg_type == MSG_TYPE_NEGOTIATE:
                     # Message Type 1
                     pass

            except Exception:
                pass

    except Exception as e:
        errors.append(str(e))
    finally:
        status.finish()
        reader.close()
    
    duration = 0.0
    if start_time and last_time:
        duration = last_time - start_time

    return NtlmAnalysis(
        path=path,
        duration=duration,
        total_packets=total_packets,
        ntlm_packets=ntlm_packets,
        versions=versions,
        raw_users=users,
        raw_domains=domains,
        raw_workstations=workstations,
        sessions=sessions,
        anomalies=anomalies,
        errors=errors
    )
