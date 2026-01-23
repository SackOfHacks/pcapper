from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
import struct

try:
    from scapy.layers.inet import TCP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw, Packet
    from scapy.utils import PcapReader, PcapNgReader
except ImportError:
    TCP = Raw = None

from .progress import build_statusbar
from .utils import detect_file_type, safe_float

# --- Dataclasses ---

@dataclass
class SmbShare:
    name: str # e.g. \\192.168.1.5\IPC$
    server_ip: str
    connect_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    is_admin: bool = False

@dataclass
class SmbSession:
    client_ip: str
    server_ip: str
    username: Optional[str] = None
    domain: Optional[str] = None
    is_guest: bool = False
    smb_version: str = "Unknown" # SMBv1, SMBv2, SMBv3
    signing_required: bool = False
    start_ts: float = 0.0
    active: bool = False

@dataclass
class SmbFileOp:
    filename: str
    action: str # Read, Write, Delete, Create
    path: str
    size: int = 0
    ts: float = 0.0

@dataclass
class SmbAnomaly:
    severity: str # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    packet_index: int
    src: str
    dst: str

@dataclass
class SmbSummary:
    path: Path
    total_packets: int
    smb_packets: int
    versions: Counter[str]
    commands: Counter[str]
    error_codes: Counter[str] # NT Status codes
    sessions: List[SmbSession]
    shares: List[SmbShare]
    files: List[SmbFileOp]
    anomalies: List[SmbAnomaly]
    top_clients: Counter[str]
    top_servers: Counter[str]
    lateral_movement: List[Dict[str, object]]
    errors: List[str]

# --- Constants ---

SMB1_MAGIC = b"\xffSMB"
SMB2_MAGIC = b"\xfeSMB"

# SMB2 Commands
SMB2_COM_NEGOTIATE = 0x00
SMB2_COM_SESSION_SETUP = 0x01
SMB2_COM_LOGOFF = 0x02
SMB2_COM_TREE_CONNECT = 0x03
SMB2_COM_TREE_DISCONNECT = 0x04
SMB2_COM_CREATE = 0x05
SMB2_COM_CLOSE = 0x06
SMB2_COM_FLUSH = 0x07
SMB2_COM_READ = 0x08
SMB2_COM_WRITE = 0x09
SMB2_COM_LOCK = 0x0A
SMB2_COM_IOCTL = 0x0B
SMB2_COM_CANCEL = 0x0C
SMB2_COM_ECHO = 0x0D
SMB2_COM_QUERY_DIRECTORY = 0x0E
SMB2_COM_CHANGE_NOTIFY = 0x0F
SMB2_COM_QUERY_INFO = 0x10
SMB2_COM_SET_INFO = 0x11
SMB2_COM_OPLOCK_BREAK = 0x12

SMB2_CMD_MAP = {
    0x00: "Negotiate", 0x01: "Session Setup", 0x02: "Logoff",
    0x03: "Tree Connect", 0x04: "Tree Disconnect", 0x05: "Create",
    0x06: "Close", 0x07: "Flush", 0x08: "Read", 0x09: "Write",
    0x0A: "Lock", 0x0B: "Ioctl", 0x0C: "Cancel", 0x0D: "Echo",
    0x0E: "Query Dir", 0x0F: "Change Notify", 0x10: "Query Info",
    0x11: "Set Info", 0x12: "Oplock Break"
}

# SMB1 Commands (Selected)
SMB1_COM_NEGOTIATE = 0x72
SMB1_COM_SESSION_SETUP_ANDX = 0x73
SMB1_COM_TREE_CONNECT_ANDX = 0x75
SMB1_COM_NT_CREATE_ANDX = 0xA2
SMB1_COM_OPEN_ANDX = 0x2D
SMB1_COM_READ_ANDX = 0x2E
SMB1_COM_WRITE_ANDX = 0x2F

# Critical NT Status codes
STATUS_SUCCESS = 0x00000000
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_LOGON_FAILURE = 0xC000006D
STATUS_ACCOUNT_LOCKED_OUT = 0xC0000234
STATUS_PASSWORD_EXPIRED = 0xC0000071
STATUS_BAD_NETWORK_NAME = 0xC00000CC # Share not found
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034

NT_STATUS_MAP = {
    0xC0000022: "Access Denied",
    0xC000006D: "Logon Failure",
    0xC0000234: "Account Locked",
    0xC0000071: "Password Expired",
    0xC00000CC: "Bad Network Name",
    0xC0000034: "Object Not Found",
    0x00000000: "Success"
}

# --- Analysis Functions ---

def analyze_smb(path: Path, show_status: bool = True) -> SmbSummary:
    if TCP is None:
        return SmbSummary(path, 0, 0, Counter(), Counter(), Counter(), [], [], [], [], Counter(), Counter(), [], ["Scapy not available"])

    ftype = detect_file_type(path)
    try:
        reader = PcapNgReader(str(path)) if ftype == "pcapng" else PcapReader(str(path))
    except Exception as e:
        return SmbSummary(path, 0, 0, Counter(), Counter(), Counter(), [], [], [], [], Counter(), Counter(), [], [f"Error opening pcap: {e}"])

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
    smb_packets = 0
    versions = Counter()
    commands = Counter()
    error_codes = Counter()
    
    # Trackers
    shares: Dict[str, SmbShare] = {}
    sessions: Dict[Tuple[str, str, int], SmbSession] = {} # Key: ClientIP, ServerIP, SessionID (if determinable)
    anomalies: List[SmbAnomaly] = []
    
    # State tracking
    top_clients = Counter()
    top_servers = Counter()
    errors: List[str] = []
    client_to_servers: Dict[str, Set[str]] = defaultdict(set)
    client_admin_shares: Counter[str] = Counter()
    client_failures: Counter[str] = Counter()
    
    # Helper to parse specific packets
    def _parse_smb2_header(payload: bytes, src: str, dst: str, idx: int):
        # SMB2 Header is 64 bytes
        if len(payload) < 64: return
        
        # Structure:
        # ProtocolId (4) | StructSize (2) | CreditCharge (2)
        # Status (4) | Command (2) | CreditReq/Resp (2)
        # Flags (4) | NextCommand (4) | MessageId (8)
        # ProcessId (4) | TreeId (4) | SessionId (8)
        # Signature (16)
        
        try:
            status = struct.unpack("<I", payload[8:12])[0]
            cmd = struct.unpack("<H", payload[12:14])[0]
            flags = struct.unpack("<I", payload[16:20])[0]
            # msg_id = struct.unpack("<Q", payload[24:32])[0]
            # process_id = struct.unpack("<I", payload[32:36])[0]
            tree_id = struct.unpack("<I", payload[36:40])[0]
            session_id = struct.unpack("<Q", payload[40:48])[0]
            
            is_response = (flags & 0x00000001) != 0
            
            cmd_name = SMB2_CMD_MAP.get(cmd, f"Unknown(0x{cmd:02X})")
            commands[f"SMB2:{cmd_name}"] += 1
            
            # Error Code Tracking (only on responses)
            if is_response and status != 0:
                s_name = NT_STATUS_MAP.get(status, f"0x{status:08X}")
                error_codes[s_name] += 1
                
                if status == STATUS_LOGON_FAILURE:
                    anomalies.append(SmbAnomaly("HIGH", "SMB Logon Failure", f"Failed login attempt to {dst}", idx, src, dst))
                    client_failures[src] += 1
                elif status == STATUS_ACCESS_DENIED:
                    anomalies.append(SmbAnomaly("MEDIUM", "SMB Access Denied", f"Access denied on {dst}", idx, src, dst))

            # Payload after header
            data = payload[64:]
            
            # --- Tree Connect (Share Access) ---
            # Request: 0x03
            if cmd == SMB2_COM_TREE_CONNECT and not is_response:
                # Structure: StructSize(2), Reserved(2), PathOffset(2), PathLength(2)
                if len(data) >= 8:
                    path_off = struct.unpack("<H", data[4:6])[0]
                    path_len = struct.unpack("<H", data[6:8])[0]
                    
                    # Offset is from start of SMB2 Header
                    real_off = path_off - 64
                    if real_off >= 0 and real_off + path_len <= len(data):
                        share_path = data[real_off:real_off+path_len].decode('utf-16le', errors='ignore')
                        
                        share_key = f"{dst}|{share_path}"
                        if share_key not in shares:
                            is_admin = "IPC$" in share_path or "ADMIN$" in share_path or "C$" in share_path
                            shares[share_key] = SmbShare(share_path, dst, is_admin=is_admin)
                        
                        shares[share_key].connect_count += 1

                        if shares[share_key].is_admin:
                            anomalies.append(SmbAnomaly("HIGH", "Admin Share Access", f"Administrative share {share_path} accessed", idx, src, dst))
                            client_admin_shares[src] += 1

                        client_to_servers[src].add(dst)

            # --- Session Setup (Authentication Activity) ---
            # Request: 0x01
            if cmd == SMB2_COM_SESSION_SETUP and not is_response:
                # We can try to extract NTLM/Kerberos info but it relies on ASN.1 parsing often
                # Simple check for Null session or Guest
                # This is hard without full blob parsing of SPNEGO
                pass

        except Exception as e:
            pass

    def _parse_smb1_header(payload: bytes, src: str, dst: str, idx: int):
        # SMB1 Header is 32 bytes
        if len(payload) < 32: return
        
        # Command is at offset 4
        cmd = payload[4]
        
        cmd_name = f"0x{cmd:02X}"
        if cmd == SMB1_COM_NEGOTIATE: cmd_name = "Negotiate"
        elif cmd == SMB1_COM_SESSION_SETUP_ANDX: cmd_name = "Session Setup"
        elif cmd == SMB1_COM_TREE_CONNECT_ANDX: cmd_name = "Tree Connect"
        
        commands[f"SMB1:{cmd_name}"] += 1
        
        # Flags2 at offset 14 (2 bytes)
        # flags2 = struct.unpack("<H", payload[14:16])[0]
        
        # Error code (Status) at offset 9 (4 bytes)
        status = struct.unpack("<I", payload[9:13])[0]
        
        is_response = (payload[13] & 0x80) != 0 # Flags at offset 13, bit 7 is Reply bit
        
        if is_response and status != 0:
            s_name = NT_STATUS_MAP.get(status, f"0x{status:08X}")
            error_codes[s_name] += 1

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
            if TCP in pkt and (pkt[TCP].dport == 445 or pkt[TCP].sport == 445 or pkt[TCP].dport == 139 or pkt[TCP].sport == 139):
                smb_packets += 1
                if Raw in pkt:
                    payload = bytes(pkt[Raw])
                    
                    # NetBIOS Session Service typically adds 4 bytes Header if port 139 or even 445 sometimes
                    # Header: MsgType(1), Length(3)
                    # Often bytes[0] == 0x00 and then length.
                    
                    offset = 0
                    if len(payload) > 4 and payload[0] == 0x00:
                         # Likely NetBIOS framing
                         offset = 4
                    
                    smb_data = payload[offset:]
                    
                    if smb_data.startswith(SMB2_MAGIC):
                        versions["SMB2/3"] += 1
                        
                        src = pkt[0].src if hasattr(pkt[0], 'src') else "0.0.0.0" # IP layer
                        dst = pkt[0].dst if hasattr(pkt[0], 'dst') else "0.0.0.0"
                        
                        # Determine direction
                        if pkt[TCP].dport == 445 or pkt[TCP].dport == 139:
                            top_clients[src] += 1
                            top_servers[dst] += 1
                            _parse_smb2_header(smb_data, src, dst, total_packets)
                        else:
                            top_servers[src] += 1
                            top_clients[dst] += 1
                            _parse_smb2_header(smb_data, src, dst, total_packets)

                    elif smb_data.startswith(SMB1_MAGIC):
                        versions["SMB1"] += 1
                        if versions["SMB1"] == 1:
                            src = pkt[0].src if hasattr(pkt[0], 'src') else "?"
                            dst = pkt[0].dst if hasattr(pkt[0], 'dst') else "?"
                            anomalies.append(SmbAnomaly("CRITICAL", "SMBv1 Detected", "Legacy, insecure SMBv1 protocol in use.", total_packets, src, dst))
                            
                        src = pkt[0].src if hasattr(pkt[0], 'src') else "0.0.0.0"
                        dst = pkt[0].dst if hasattr(pkt[0], 'dst') else "0.0.0.0"
                        
                        if pkt[TCP].dport == 445 or pkt[TCP].dport == 139:
                            top_clients[src] += 1
                            top_servers[dst] += 1
                            _parse_smb1_header(smb_data, src, dst, total_packets)
                        else:
                            top_servers[src] += 1
                            top_clients[dst] += 1
                            _parse_smb1_header(smb_data, src, dst, total_packets)

    except Exception as e:
        errors.append(str(e))
    finally:
        status.finish()
        reader.close()

    lateral_movement: List[Dict[str, object]] = []
    for client, servers in client_to_servers.items():
        server_count = len(servers)
        admin_hits = client_admin_shares.get(client, 0)
        failures = client_failures.get(client, 0)
        score = (server_count / 3.0) + (admin_hits * 1.5) + (failures / 5.0)
        if score >= 2.5 or server_count >= 10:
            lateral_movement.append({
                "client": client,
                "servers": server_count,
                "admin_shares": admin_hits,
                "failures": failures,
                "score": round(score, 2),
            })
        
    return SmbSummary(
        path=path,
        total_packets=total_packets,
        smb_packets=smb_packets,
        versions=versions,
        commands=commands,
        error_codes=error_codes,
        sessions=list(sessions.values()),
        shares=list(shares.values()),
        files=[], # File op parsing requires fuller state tracking
        anomalies=anomalies,
        top_clients=top_clients,
        top_servers=top_servers,
        lateral_movement=sorted(lateral_movement, key=lambda x: x.get("score", 0), reverse=True),
        errors=errors
    )
