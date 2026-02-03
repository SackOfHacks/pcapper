from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import re

try:
    from scapy.layers.inet import TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw, Packet
    from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse, NBNSNodeStatusResponse
except ImportError:
    # Use raw parsing if imports fail or layers missing
    TCP = UDP = Raw = None
    NBNSQueryRequest = NBNSQueryResponse = NBNSNodeStatusResponse = None

from .pcap_cache import get_reader
from .utils import detect_file_type

# NetBIOS Suffix Types commonly seen
SUFFIX_MAP = {
    0x00: "Workstation/Service",
    0x03: "Messenger Service",
    0x06: "RAS Server Service",
    0x1B: "Domain Master Browser",
    0x1C: "Domain Controllers",
    0x1D: "Master Browser",
    0x1E: "Browser Service Elections",
    0x1F: "NetDDE Service",
    0x20: "File Server Service",
    0x21: "RAS Client Service",
    0xDC: "Domain Controller",
    0xE0: "Master Browser",
}

NBNS_RCODE_MAP = {
    0: "NoError",
    1: "FormErr",
    2: "ServFail",
    3: "NXDomain",
    4: "NotImp",
    5: "Refused",
}

SMB2_CMD_MAP = {
    0x00: "Negotiate", 0x01: "Session Setup", 0x02: "Logoff",
    0x03: "Tree Connect", 0x04: "Tree Disconnect", 0x05: "Create",
    0x06: "Close", 0x07: "Flush", 0x08: "Read", 0x09: "Write",
    0x0A: "Lock", 0x0B: "Ioctl", 0x0C: "Cancel", 0x0D: "Echo",
    0x0E: "Query Dir", 0x0F: "Change Notify", 0x10: "Query Info",
    0x11: "Set Info", 0x12: "Oplock Break",
}

SMB1_CMD_MAP = {
    0x72: "Negotiate",
    0x73: "Session Setup",
    0x75: "Tree Connect",
    0xA2: "NT Create",
    0x2D: "Open",
    0x2E: "Read",
    0x2F: "Write",
}


def _parse_ntlm_type3(payload: bytes) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    signature = b"NTLMSSP\x00"
    idx = payload.find(signature)
    if idx == -1 or len(payload) < idx + 64:
        return None, None, None
    try:
        msg_type = int.from_bytes(payload[idx + 8:idx + 12], "little")
        if msg_type != 3:
            return None, None, None
        def _read_field(offset: int) -> Tuple[int, int]:
            length = int.from_bytes(payload[offset:offset + 2], "little")
            field_offset = int.from_bytes(payload[offset + 4:offset + 8], "little")
            return length, field_offset
        domain_len, domain_off = _read_field(idx + 28)
        user_len, user_off = _read_field(idx + 36)
        workstation_len, workstation_off = _read_field(idx + 44)
        domain = payload[idx + domain_off:idx + domain_off + domain_len].decode("utf-16le", errors="ignore") if domain_len else None
        user = payload[idx + user_off:idx + user_off + user_len].decode("utf-16le", errors="ignore") if user_len else None
        workstation = payload[idx + workstation_off:idx + workstation_off + workstation_len].decode("utf-16le", errors="ignore") if workstation_len else None
        return user or None, domain or None, workstation or None
    except Exception:
        return None, None, None


def _parse_smb_command(payload: bytes) -> Optional[str]:
    if payload.startswith(b"\xfeSMB") and len(payload) >= 16:
        cmd = int.from_bytes(payload[12:14], "little")
        return f"SMB2:{SMB2_CMD_MAP.get(cmd, f'0x{cmd:02X}') }"
    if payload.startswith(b"\xffSMB") and len(payload) >= 5:
        cmd = payload[4]
        return f"SMB1:{SMB1_CMD_MAP.get(cmd, f'0x{cmd:02X}') }"
    return None

@dataclass
class NetbiosName:
    name: str
    suffix: int
    type_str: str

@dataclass
class NetbiosHost:
    ip: str
    names: List[NetbiosName] = field(default_factory=list)
    mac: Optional[str] = None
    is_master_browser: bool = False
    is_domain_controller: bool = False
    group_name: Optional[str] = None

@dataclass
class NetbiosAnomaly:
    timestamp: float
    src_ip: str
    dst_ip: str
    type: str # Conflict, Spoof, Malformed, BroadcastStorm
    details: str
    severity: str = "LOW"


@dataclass
class NetbiosConversation:
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int
    dst_port: int
    packets: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    requests: int = 0
    responses: int = 0
    response_codes: Counter[str] = field(default_factory=Counter)


@dataclass
class NetbiosSession:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    packets: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

@dataclass
class NetbiosAnalysis:
    path: Path
    duration: float = 0.0
    total_packets: int = 0
    hosts: Dict[str, NetbiosHost] = field(default_factory=dict) # Keyed by IP
    conversations: List[NetbiosConversation] = field(default_factory=list)
    sessions: List[NetbiosSession] = field(default_factory=list)
    src_counts: Counter[str] = field(default_factory=Counter)
    dst_counts: Counter[str] = field(default_factory=Counter)
    request_counts: Counter[str] = field(default_factory=Counter)
    response_counts: Counter[str] = field(default_factory=Counter)
    response_codes: Counter[str] = field(default_factory=Counter)
    service_counts: Counter[str] = field(default_factory=Counter)
    nbss_message_types: Counter[str] = field(default_factory=Counter)
    smb_versions: Counter[str] = field(default_factory=Counter)
    smb_commands: Counter[str] = field(default_factory=Counter)
    smb_users: Counter[str] = field(default_factory=Counter)
    smb_domains: Counter[str] = field(default_factory=Counter)
    smb_sources: Counter[str] = field(default_factory=Counter)
    smb_destinations: Counter[str] = field(default_factory=Counter)
    smb_clients: Counter[str] = field(default_factory=Counter)
    artifacts: List[str] = field(default_factory=list)
    files_discovered: List[str] = field(default_factory=list)
    observed_users: Counter[str] = field(default_factory=Counter)
    anomalies: List[NetbiosAnomaly] = field(default_factory=list)
    name_conflicts: int = 0
    browser_elections: int = 0
    unique_names: Set[str] = field(default_factory=set)
    errors: List[str] = field(default_factory=list)

def decode_netbios_name(encoded_name: bytes) -> str:
    """
    Decodes a standard 32-byte Level 1 encoded NetBIOS name.
    """
    if len(encoded_name) < 32:
        return "<BAD_ENCODING>"
    
    try:
        # NetBIOS Name Encoding: 2 characters for each byte
        # Simplistic decoding for now or use scapy's if available.
        # usually stored as 16 chars (padded spaces)
        # Actually scapy usually handles this, so we might extract from layer
        pass
    except Exception:
        pass
    return encoded_name.decode('utf-8', errors='replace').strip()

def get_netbios_suffix_desc(suffix: int) -> str:
    return SUFFIX_MAP.get(suffix, f"Unknown (0x{suffix:02X})")


def _scan_filenames(data: bytes) -> List[str]:
    found = set()
    pattern = r"[\w\-.()\[\] ]+\.(?:exe|dll|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|txt|bat|ps1|mkv|mp4|avi|mov|wmv|flv|webm|jpg|jpeg|png|gif|bmp|tiff|iso|img|tar|gz|7z|rar)"
    try:
        text = data.decode("utf-16-le", errors="ignore")
        found.update(re.findall(pattern, text, re.IGNORECASE))
    except Exception:
        pass
    try:
        text = data.decode("latin-1", errors="ignore")
        found.update(re.findall(pattern, text, re.IGNORECASE))
    except Exception:
        pass
    return list(found)

def analyze_netbios(pcap_path: Path, show_status: bool = True) -> NetbiosAnalysis:
    # Try importing NBNS layers from scapy
    try:
        from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse, NBNSNodeStatusResponse, NBNSRequest, NBNSResponse
    except ImportError:
        # Fallback if specific classes aren't available exactly as named, though they are standard scapy
        NBNSQueryRequest = None

    analysis = NetbiosAnalysis(path=pcap_path)
    
    if not pcap_path.exists():
        return analysis

    packets_count = 0
    start_time = None
    last_time = None

    # For storm detection
    packet_rate_tracker = defaultdict(int) # ip -> count (reset every sec)
    current_sec = 0.0

    # Tracking for name conflicts: name -> ip
    name_registry = {} 

    conversations: Dict[Tuple[str, str, str, int, int], NetbiosConversation] = {}
    sessions: Dict[Tuple[str, str, int, int], NetbiosSession] = {}
    artifacts: Set[str] = set()

    def _update_time(obj, ts_val: float) -> None:
        if obj.first_seen is None or ts_val < obj.first_seen:
            obj.first_seen = ts_val
        if obj.last_seen is None or ts_val > obj.last_seen:
            obj.last_seen = ts_val

    def _get_convo(src: str, dst: str, proto: str, sp: int, dp: int) -> NetbiosConversation:
        key = (src, dst, proto, sp, dp)
        convo = conversations.get(key)
        if convo is None:
            convo = NetbiosConversation(src_ip=src, dst_ip=dst, protocol=proto, src_port=sp, dst_port=dp)
            conversations[key] = convo
        return convo

    def _get_session(src: str, dst: str, sp: int, dp: int) -> NetbiosSession:
        key = (src, dst, sp, dp)
        sess = sessions.get(key)
        if sess is None:
            sess = NetbiosSession(src_ip=src, dst_ip=dst, src_port=sp, dst_port=dp)
            sessions[key] = sess
        return sess

    try:
        reader, status_bar, stream, _size_bytes, _file_type = get_reader(
            pcap_path, show_status=show_status
        )
        try:
            with status_bar as pbar:
                for pkt in reader:
                    if not pkt:
                        continue
                        
                    packets_count += 1
                    ts = float(pkt.time)
                    if start_time is None:
                        start_time = ts
                    last_time = ts

                    if stream is not None:
                        try:
                            pbar.update(stream.tell())
                        except Exception:
                            pass

                    # Filter for NetBIOS ports
                    # 137 UDP - Name Service
                    # 138 UDP - Datagram Service
                    # 139 TCP - Session Service
                    
                    is_nb = False
                    if pkt.haslayer(UDP):
                        sport, dport = pkt[UDP].sport, pkt[UDP].dport
                        if sport in (137, 138) or dport in (137, 138):
                            is_nb = True
                    elif pkt.haslayer(TCP):
                        sport, dport = pkt[TCP].sport, pkt[TCP].dport
                        if sport == 139 or dport == 139:
                            is_nb = True

                    if not is_nb:
                        continue

                    # IP extraction
                    src_ip = "0.0.0.0"
                    dst_ip = "0.0.0.0"
                    if pkt.haslayer("IP"):
                        src_ip = pkt["IP"].src
                        dst_ip = pkt["IP"].dst
                    elif pkt.haslayer(IPv6):
                        src_ip = pkt[IPv6].src
                        dst_ip = pkt[IPv6].dst

                    if pkt.haslayer(Ether) and src_ip in analysis.hosts and analysis.hosts[src_ip].mac is None:
                        try:
                            analysis.hosts[src_ip].mac = str(pkt[Ether].src)
                        except Exception:
                            pass
                    
                    analysis.total_packets += 1
                    analysis.src_counts[src_ip] += 1
                    analysis.dst_counts[dst_ip] += 1

                    # Host initiation
                    if src_ip not in analysis.hosts:
                        analysis.hosts[src_ip] = NetbiosHost(ip=src_ip)

                    proto_label = "UDP" if pkt.haslayer(UDP) else "TCP"
                    convo = _get_convo(src_ip, dst_ip, proto_label, sport, dport)
                    convo.packets += 1
                    _update_time(convo, ts)

                    if sport == 137 or dport == 137:
                        analysis.service_counts["NBNS (Name Service)"] += 1
                    if sport == 138 or dport == 138:
                        analysis.service_counts["Datagram Service"] += 1
                    if proto_label == "TCP" and (sport == 139 or dport == 139):
                        analysis.service_counts["Session Service"] += 1
                        analysis.smb_clients[src_ip] += 1
                        sess = _get_session(src_ip, dst_ip, sport, dport)
                        sess.packets += 1
                        _update_time(sess, ts)
                        if pkt.haslayer(Raw):
                            payload = bytes(pkt[Raw].load)
                            if len(payload) >= 4:
                                msg_type = payload[0]
                                nbss_type_map = {
                                    0x00: "Session Message",
                                    0x81: "Session Request",
                                    0x82: "Positive Session Response",
                                    0x83: "Negative Session Response",
                                    0x84: "Retarget Session Response",
                                    0x85: "Session Keepalive",
                                }
                                analysis.nbss_message_types[nbss_type_map.get(msg_type, f"Type 0x{msg_type:02X}")] += 1
                                if payload[0] == 0x00 and len(payload) > 4:
                                    nbss_payload = payload[4:]
                                    if nbss_payload.startswith(b"\xffSMB"):
                                        analysis.smb_versions["SMB1"] += 1
                                    if nbss_payload.startswith(b"\xfeSMB"):
                                        analysis.smb_versions["SMB2/3"] += 1
                                    cmd_name = _parse_smb_command(nbss_payload)
                                    if cmd_name:
                                        analysis.smb_commands[cmd_name] += 1

                                    user, domain, _ = _parse_ntlm_type3(nbss_payload)
                                    if user:
                                        analysis.smb_users[user] += 1
                                        analysis.smb_sources[src_ip] += 1
                                        analysis.smb_destinations[dst_ip] += 1
                                    if domain:
                                        analysis.smb_domains[domain] += 1

                                    for name in _scan_filenames(nbss_payload):
                                        artifacts.add(name)
                                        analysis.files_discovered.append(name)

                    # --- NBNS Analysis (UDP 137) ---
                    if pkt.haslayer("NBNSQueryRequest"):
                        # Name Registration / Query
                        # Scapy NBNSQueryRequest has QUESTION_NAME usually
                        try:
                            # Iterate questions
                            nbns = pkt["NBNSQueryRequest"]
                            qname = nbns.QUESTION_NAME
                            qtype = nbns.QUESTION_TYPE
                            
                            # Clean up name (scapy often returns b'NAME   ')
                            decoded_name = ""
                            if isinstance(qname, bytes):
                                decoded_name = qname.decode('utf-8', errors='replace').strip()
                            else:
                                decoded_name = str(qname).strip()

                            # If last char indicates suffix
                            suffix = 0x00
                            real_name = decoded_name
                            if len(decoded_name) == 16:
                                # Often the last byte is the suffix
                                # Actually scapy's NBNS layer usually manages the encoding. 
                                # But if it is the raw 16 bytes:
                                try:
                                    suffix = decoded_name[-1].encode('latin-1')[0]
                                except:
                                    pass
                                real_name = decoded_name[:-1].strip()
                            else:
                                query_layer = pkt.getlayer("NBNSQueryRequest")
                                question_name = getattr(query_layer, "question_name", None) if query_layer else None
                                if question_name:
                                    # Sometimes relying on internal encoding is tricky.
                                    # Use raw question name if present.
                                    pass

                            # Detect Name Conflicts
                            # If flag indicates Registration (Opcode=5... wait, Opcode=0 is Query, 5 is Registration)
                            # Checking flags is harder without exact bit mask, but we can look for specific behaviors.
                            # Standard NBNS header flags: 0x2800 = Refresh / Registration?
                            
                            # Simple heuristic for conflicts:
                            # Observing "Name Conflict" or "Negative Registration Response" (WACK?)
                            analysis.request_counts["NBNS Query"] += 1
                            convo.requests += 1
                            if real_name:
                                artifacts.add(real_name)
                                analysis.unique_names.add(real_name)
                                analysis.observed_users[real_name] += 1
                                if real_name in name_registry and name_registry[real_name] != src_ip:
                                    analysis.name_conflicts += 1
                                    analysis.anomalies.append(NetbiosAnomaly(
                                        timestamp=ts,
                                        src_ip=src_ip,
                                        dst_ip=dst_ip,
                                        type="NameConflict",
                                        details=f"Name {real_name} claimed by {src_ip} and {name_registry[real_name]}",
                                        severity="HIGH",
                                    ))
                                else:
                                    name_registry[real_name] = src_ip

                        except Exception as exc:
                            analysis.errors.append(str(exc))

                    if pkt.haslayer("NBNSQueryResponse"):
                        # Name Query Response, Node Status Response, etc.
                        try:
                            nbns = pkt["NBNSQueryResponse"]
                            # Check Answers
                            rr_count = nbns.ANCOUNT
                            # We'd need to iterate RRs. Scapy puts them in `an` field.
                            # layer.an could be a list or a single object linked list
                            
                            current_rr = nbns.an
                            while current_rr and rr_count > 0:
                                # TYPE 0x21 (33) is NB_STAT (Node Status)
                                if current_rr.TYPE == 33:
                                    pass # Node status parsing is complex in generic scapy loop without `NBNSNodeStatusResponse` layer match
                                
                                # TYPE 0x20 (32) is NB (Name)
                                if current_rr.TYPE == 32:
                                    # Name resolution
                                    r_name = current_rr.RR_NAME.decode('utf-8', errors='replace').strip()
                                    
                                    # Check for conflict
                                    if dst_ip == "255.255.255.255":
                                        # Broadcast response? Usually not. response is unicast.
                                        pass
                                     
                                    # Add to host
                                    if src_ip in analysis.hosts:
                                        # Extract suffix if possible.
                                        # The name in the packet is usually padded to 15 chars + suffix.
                                        suffix = 0
                                        clean_name = r_name
                                        if len(r_name) == 16:
                                            suffix_char = r_name[-1]
                                            suffix = ord(suffix_char)
                                            clean_name = r_name[:-1].strip()
                                        
                                        # Add name if new
                                        if not any(n.name == clean_name and n.suffix == suffix for n in analysis.hosts[src_ip].names):
                                            analysis.hosts[src_ip].names.append(NetbiosName(clean_name, suffix, get_netbios_suffix_desc(suffix)))
                                            analysis.unique_names.add(clean_name)
                                            artifacts.add(clean_name)
                                            analysis.observed_users[clean_name] += 1
                                            
                                            # Identify Roles
                                            if suffix == 0x1B: # Domain Master Browser
                                                analysis.hosts[src_ip].is_domain_controller = True # Likely
                                                analysis.hosts[src_ip].is_master_browser = True
                                            if suffix == 0x1C: # Domain Controller
                                                analysis.hosts[src_ip].is_domain_controller = True
                                            if suffix in (0x1D, 0x1E):
                                                analysis.hosts[src_ip].is_master_browser = True
                                            if suffix == 0x00 and not analysis.hosts[src_ip].group_name:
                                                # Sometimes Workgroup/Domain Name comes as 00
                                                pass

                                try:
                                    current_rr = current_rr.payload
                                except:
                                    current_rr = None
                                rr_count -= 1
                            analysis.response_counts["NBNS Response"] += 1
                            convo.responses += 1
                            rcode = getattr(nbns, "RCODE", None)
                            if rcode is None:
                                rcode = getattr(nbns, "rcode", None)
                            if rcode is None and hasattr(nbns, "FLAGS"):
                                try:
                                    rcode = int(nbns.FLAGS) & 0x000F
                                except Exception:
                                    rcode = None
                            if rcode is not None:
                                code_name = NBNS_RCODE_MAP.get(rcode, f"RCODE_{rcode}")
                                analysis.response_codes[code_name] += 1
                                convo.response_codes[code_name] += 1
                        except Exception:
                            pass
                    
                    # --- Browser Protocol Analysis (UDP 138) ---
                    # Often piggybacked on NetBIOS Datagram
                    # Look for Browser protocol (ID 0x11...?)
                    # Scapy might not interpret "Browser" layer automatically easily.
                    # Searching for Election packets by signature in Raw data if present.
                    # Pattern for Host Announcement or Election
                    if pkt.haslayer(UDP) and (pkt[UDP].sport == 138 or pkt[UDP].dport == 138):
                        if pkt.haslayer(Raw):
                            payload = pkt[Raw].load
                            # Browser Protocol header often starts after payload header?
                            # Not trivial without specialized parser. 
                            # However, Election byte signature: 
                            # Command: 0x08 (Election), 0x01 (Host Announcement), 0x0C (Domain Announcement)
                            # Often found at offset inside the SMB-ish container (NetBIOS Datagram)
                            
                            # Heuristic: Check for common strings or bytes
                            # Election request often contains "Elected Master"? No.
                            
                            # Simple string scan for tracking interesting data
                            try:
                                # Browser Election (0x08)
                                # Often bytes: ... \x08 ...
                                # This is weak. Let's rely on standard ports and high level counters
                                pass
                            except:
                                pass

                    # Detect Anomalies
                    # 1. NBNS Response Spoofing detection (Simple/Intra-flow)
                    # If we see multiple responses for the same transaction ID from DIFFERENT IPs...
                    # (Requires state tracking, skipping for now to keep it lightweight)

                    # 2. Broadcast storm heuristic
                    ts_sec = int(ts)
                    if ts_sec != current_sec:
                        packet_rate_tracker.clear()
                        current_sec = ts_sec
                    packet_rate_tracker[src_ip] += 1
                    if packet_rate_tracker[src_ip] > 200:
                        analysis.anomalies.append(NetbiosAnomaly(
                            timestamp=ts,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            type="BroadcastStorm",
                            details=f"High NetBIOS packet rate from {src_ip}",
                            severity="MEDIUM",
                        ))
                        
        finally:
            reader.close()
    except Exception as exc:
        analysis.errors.append(str(exc))

    if last_time and start_time:
        analysis.duration = last_time - start_time

    analysis.conversations = list(conversations.values())
    analysis.sessions = list(sessions.values())
    analysis.artifacts = sorted(artifacts)

    return analysis
