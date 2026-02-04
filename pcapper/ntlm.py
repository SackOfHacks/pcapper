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

from .pcap_cache import get_reader
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
class NtlmConversation:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    packets: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    requests: int = 0
    responses: int = 0
    messages: Counter[str] = field(default_factory=Counter)


@dataclass
class NtlmArtifact:
    value: str
    description: str

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
    conversations: List[NtlmConversation] = field(default_factory=list)
    request_counts: Counter[str] = field(default_factory=Counter)
    response_counts: Counter[str] = field(default_factory=Counter)
    status_codes: Counter[str] = field(default_factory=Counter)
    src_counts: Counter[str] = field(default_factory=Counter)
    dst_counts: Counter[str] = field(default_factory=Counter)
    services: Counter[str] = field(default_factory=Counter)
    artifacts: List[NtlmArtifact] = field(default_factory=list)
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

NTSTATUS_MAP = {
    0x00000000: "STATUS_SUCCESS",
    0xC0000001: "STATUS_UNSUCCESSFUL",
    0xC0000002: "STATUS_NOT_IMPLEMENTED",
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    0xC0000008: "STATUS_INVALID_HANDLE",
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
    0xC0000035: "STATUS_OBJECT_NAME_COLLISION",
    0xC000003A: "STATUS_OBJECT_PATH_NOT_FOUND",
    0xC0000043: "STATUS_SHARING_VIOLATION",
    0xC0000048: "STATUS_OBJECT_NAME_INVALID",
    0xC000005E: "STATUS_NO_LOGON_SERVERS",
    0xC000006D: "STATUS_LOGON_FAILURE",
    0xC000006E: "STATUS_ACCOUNT_RESTRICTION",
    0xC000006F: "STATUS_INVALID_LOGON_HOURS",
    0xC0000070: "STATUS_INVALID_WORKSTATION",
    0xC0000071: "STATUS_PASSWORD_EXPIRED",
    0xC0000072: "STATUS_ACCOUNT_DISABLED",
    0xC0000073: "STATUS_NONE_MAPPED",
    0xC0000074: "STATUS_INVALID_ACCOUNT_NAME",
    0xC0000075: "STATUS_USER_EXISTS",
    0xC0000076: "STATUS_NO_SUCH_USER",
    0xC0000077: "STATUS_GROUP_EXISTS",
    0xC0000078: "STATUS_NO_SUCH_GROUP",
    0xC0000079: "STATUS_MEMBER_IN_GROUP",
    0xC000007A: "STATUS_MEMBER_NOT_IN_GROUP",
    0xC000007B: "STATUS_LAST_ADMIN",
    0xC000007C: "STATUS_WRONG_PASSWORD",
    0xC000007D: "STATUS_ILL_FORMED_PASSWORD",
    0xC000007E: "STATUS_PASSWORD_RESTRICTION",
    0xC000007F: "STATUS_LOGON_FAILURE",
    0xC00000A2: "STATUS_PIPE_NOT_AVAILABLE",
    0xC00000AC: "STATUS_PIPE_BUSY",
    0xC00000B0: "STATUS_PIPE_DISCONNECTED",
    0xC00000B5: "STATUS_INSUFF_SERVER_RESOURCES",
    0xC00000BA: "STATUS_FILE_IS_A_DIRECTORY",
    0xC00000BB: "STATUS_NOT_SUPPORTED",
    0xC00000CC: "STATUS_BAD_NETWORK_NAME",
    0xC00000D0: "STATUS_NOT_A_REPARSE_POINT",
    0xC00000D4: "STATUS_IO_REPARSE_TAG_NOT_HANDLED",
    0xC00000DE: "STATUS_NO_MORE_ENTRIES",
    0xC00000FB: "STATUS_NO_SUCH_FILE",
    0xC0000101: "STATUS_DIRECTORY_NOT_EMPTY",
    0xC0000120: "STATUS_CANCELLED",
    0xC0000135: "STATUS_DLL_NOT_FOUND",
    0xC0000139: "STATUS_ENTRYPOINT_NOT_FOUND",
    0xC0000142: "STATUS_DLL_INIT_FAILED",
    0xC000015B: "STATUS_LOGON_TYPE_NOT_GRANTED",
    0xC000018D: "STATUS_TRUST_FAILURE",
    0xC0000193: "STATUS_ACCOUNT_EXPIRED",
    0xC000019C: "STATUS_INVALID_ACCOUNT_NAME",
    0xC0000203: "STATUS_STACK_OVERFLOW",
    0xC0000234: "STATUS_ACCOUNT_LOCKED_OUT",
    0xC00002EF: "STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP",
    0xC00002FD: "STATUS_SMB_GUEST_LOGON_BLOCKED",
    0xC000A003: "STATUS_NETWORK_ACCESS_DENIED",
    0xC000A004: "STATUS_BAD_NETWORK_PATH",
    0xC000A005: "STATUS_NETWORK_BUSY",
    0xC000A006: "STATUS_NETWORK_ACCESS_DENIED",
    0xC000A00D: "STATUS_BAD_NETWORK_NAME",
}


def _parse_smb2_status(payload: bytes) -> Optional[str]:
    idx = payload.find(b"\xfeSMB")
    if idx == -1 or len(payload) < idx + 12:
        return None
    status = struct.unpack("<I", payload[idx + 8:idx + 12])[0]
    name = NTSTATUS_MAP.get(status)
    if name:
        return f"SMB2_{name}"
    return f"SMB2_STATUS_0x{status:08X}"


def _parse_smb1_status(payload: bytes) -> Optional[str]:
    idx = payload.find(b"\xffSMB")
    if idx == -1 or len(payload) < idx + 13:
        return None
    status = struct.unpack("<I", payload[idx + 5:idx + 9])[0]
    name = NTSTATUS_MAP.get(status)
    if name:
        return f"SMB1_{name}"
    return f"SMB1_STATUS_0x{status:08X}"


def _parse_smb2_ids(payload: bytes) -> Tuple[Optional[int], Optional[int]]:
    idx = payload.find(b"\xfeSMB")
    if idx == -1 or len(payload) < idx + 48:
        return None, None
    message_id = struct.unpack("<Q", payload[idx + 24:idx + 32])[0]
    session_id = struct.unpack("<Q", payload[idx + 40:idx + 48])[0]
    return int(message_id), int(session_id)


def _parse_smb1_ids(payload: bytes) -> Tuple[Optional[int], Optional[int]]:
    idx = payload.find(b"\xffSMB")
    if idx == -1 or len(payload) < idx + 32:
        return None, None
    uid = struct.unpack("<H", payload[idx + 28:idx + 30])[0]
    mid = struct.unpack("<H", payload[idx + 30:idx + 32])[0]
    return int(uid), int(mid)


def _parse_http_status(payload: bytes) -> Optional[str]:
    if not payload.startswith(b"HTTP/"):
        return None
    line_end = payload.find(b"\r\n")
    if line_end == -1:
        return None
    try:
        line = payload[:line_end].decode("latin-1", errors="ignore")
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            return f"HTTP_{parts[1]}"
    except Exception:
        return None
    return None

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

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path, show_status=show_status
        )
    except Exception as exc:
        return NtlmAnalysis(path, 0.0, 0, 0, Counter(), Counter(), Counter(), Counter(), [], [], [f"Error: {exc}"])

    size_bytes = size_bytes

    total_packets = 0
    ntlm_packets = 0
    
    versions = Counter()
    users = Counter()
    domains = Counter()
    workstations = Counter()
    
    sessions: List[NtlmSession] = []
    conversations: Dict[Tuple[str, str, int, int], NtlmConversation] = {}
    handshake_state: Dict[Tuple[str, str, int, int], Dict[str, Optional[float]]] = defaultdict(lambda: {
        "negotiate": None,
        "challenge": None,
        "authenticate": None,
    })
    anomalies: List[NtlmAnomaly] = []
    artifacts: List[NtlmArtifact] = []
    errors: List[str] = []
    src_counts = Counter()
    dst_counts = Counter()
    request_counts = Counter()
    response_counts = Counter()
    status_codes = Counter()
    services = Counter()

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

                src_counts[src] += 1
                dst_counts[dst] += 1

                if dport in (445, 139):
                    services["SMB"] += 1
                elif dport in (80, 8080, 8000):
                    services["HTTP"] += 1
                elif dport in (389, 636):
                    services["LDAP"] += 1
                elif dport in (5985, 5986):
                    services["WinRM"] += 1

                smb2_msg, smb2_sess = _parse_smb2_ids(payload)
                smb1_uid, smb1_mid = _parse_smb1_ids(payload)
                if smb2_msg is not None or smb2_sess is not None:
                    convo_key = (src, dst, int(sport), int(dport), smb2_sess, smb2_msg)
                elif smb1_uid is not None or smb1_mid is not None:
                    convo_key = (src, dst, int(sport), int(dport), smb1_uid, smb1_mid)
                else:
                    convo_key = (src, dst, int(sport), int(dport))
                convo = conversations.get(convo_key)
                if convo is None:
                    convo = NtlmConversation(src_ip=src, dst_ip=dst, src_port=int(sport), dst_port=int(dport))
                    conversations[convo_key] = convo
                convo.packets += 1
                if convo.first_seen is None or (ts is not None and ts < convo.first_seen):
                    convo.first_seen = ts
                if convo.last_seen is None or (ts is not None and ts > convo.last_seen):
                    convo.last_seen = ts

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

                    request_counts["Authenticate"] += 1
                    convo.requests += 1
                    convo.messages["Authenticate"] += 1
                    handshake_state[convo_key]["authenticate"] = ts
                    if handshake_state[convo_key]["negotiate"] or handshake_state[convo_key]["challenge"]:
                        artifacts.append(NtlmArtifact(
                            value=f"{src}->{dst}",
                            description="NTLM handshake completed (Type1/2/3)"
                        ))
                    status_code = _parse_smb2_status(payload) or _parse_smb1_status(payload) or _parse_http_status(payload)
                    if status_code:
                        status_codes[status_code] += 1
                    
                elif msg_type == MSG_TYPE_CHALLENGE:
                     # Message Type 2 (Server Challenge)
                     response_counts["Challenge"] += 1
                     convo.responses += 1
                     convo.messages["Challenge"] += 1
                     handshake_state[convo_key]["challenge"] = ts
                     if len(ntlm_data) >= 32:
                         target_name_len = struct.unpack("<H", ntlm_data[12:14])[0]
                         target_name_off = struct.unpack("<I", ntlm_data[16:20])[0]
                         if target_name_len and target_name_off + target_name_len <= len(ntlm_data):
                             target_name = ntlm_data[target_name_off:target_name_off + target_name_len].decode("utf-16le", errors="ignore")
                             artifacts.append(NtlmArtifact(value=target_name, description="NTLM Target Name"))
                     if len(ntlm_data) >= 20:
                         flags = struct.unpack("<I", ntlm_data[20:24])[0]
                         if flags & NTLMSSP_NEGOTIATE_NTLM:
                             versions["NTLMv1"] += 1
                         if flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                             artifacts.append(NtlmArtifact(value="Extended Session Security", description="NTLM Challenge Flag"))
                     status_code = _parse_smb2_status(payload) or _parse_smb1_status(payload) or _parse_http_status(payload)
                     if status_code:
                         status_codes[status_code] += 1
                     
                elif msg_type == MSG_TYPE_NEGOTIATE:
                     # Message Type 1
                     request_counts["Negotiate"] += 1
                     convo.requests += 1
                     convo.messages["Negotiate"] += 1
                     handshake_state[convo_key]["negotiate"] = ts
                     if len(ntlm_data) >= 16:
                         flags = struct.unpack("<I", ntlm_data[12:16])[0]
                         if flags & NTLMSSP_NEGOTIATE_NTLM:
                             versions["NTLMv1"] += 1
                         if flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                             artifacts.append(NtlmArtifact(value="Extended Session Security", description="NTLM Negotiate Flag"))

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
        conversations=list(conversations.values()),
        request_counts=request_counts,
        response_counts=response_counts,
        status_codes=status_codes,
        src_counts=src_counts,
        dst_counts=dst_counts,
        services=services,
        artifacts=artifacts,
        anomalies=anomalies,
        errors=errors
    )
