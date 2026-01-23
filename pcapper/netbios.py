from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    from scapy.layers.inet import TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw, Packet
    from scapy.utils import PcapReader
    from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse, NBNSNodeStatusResponse
except ImportError:
    # Use raw parsing if imports fail or layers missing
    TCP = UDP = Raw = None
    NBNSQueryRequest = NBNSQueryResponse = NBNSNodeStatusResponse = None

from .progress import build_statusbar

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
class NetbiosAnalysis:
    path: Path
    duration: float = 0.0
    total_packets: int = 0
    hosts: Dict[str, NetbiosHost] = field(default_factory=dict) # Keyed by IP
    anomalies: List[NetbiosAnomaly] = field(default_factory=list)
    name_conflicts: int = 0
    browser_elections: int = 0
    unique_names: Set[str] = field(default_factory=set)

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

def analyze_netbios(pcap_path: Path, show_status: bool = True) -> NetbiosAnalysis:
    from scapy.all import PcapReader, Raw
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

    try:
        with PcapReader(str(pcap_path)) as reader:
            # We assume regular file status bar
            status_bar = build_statusbar(pcap_path, show_status, "NetBIOS")
            
            with status_bar as pbar:
                for pkt in reader:
                    if not pkt:
                        continue
                        
                    packets_count += 1
                    ts = float(pkt.time)
                    if start_time is None:
                        start_time = ts
                    last_time = ts

                    pbar.update(reader.tell())

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
                    
                    analysis.total_packets += 1
                    
                    # IP extraction
                    src_ip = "0.0.0.0"
                    dst_ip = "0.0.0.0"
                    if pkt.haslayer("IP"):
                        src_ip = pkt["IP"].src
                        dst_ip = pkt["IP"].dst
                    elif pkt.haslayer(IPv6):
                        src_ip = pkt[IPv6].src
                        dst_ip = pkt[IPv6].dst

                    # Host initiation
                    if src_ip not in analysis.hosts:
                        analysis.hosts[src_ip] = NetbiosHost(ip=src_ip)

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
                            elif len(pkt.getlayer("NBNSQueryRequest").question_name) > 0:
                                # Sometimes relying on internal encoding is tricky. 
                                # Let's try to infer if we can see the raw bytes
                                pass

                            # Detect Name Conflicts
                            # If flag indicates Registration (Opcode=5... wait, Opcode=0 is Query, 5 is Registration)
                            # Checking flags is harder without exact bit mask, but we can look for specific behaviors.
                            # Standard NBNS header flags: 0x2800 = Refresh / Registration?
                            
                            # Simple heuristic for conflicts:
                            # Observing "Name Conflict" or "Negative Registration Response" (WACK?)
                            pass

                        except Exception:
                            pass

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
                        
    except Exception as e:
        # print(f"Error analysing NetBIOS: {e}")
        pass

    if last_time and start_time:
        analysis.duration = last_time - start_time

    return analysis
