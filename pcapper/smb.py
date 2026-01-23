from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
import struct
import uuid

try:
    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6
    from scapy.packet import Raw, Packet
    from scapy.utils import PcapReader, PcapNgReader
except ImportError:
    IP = TCP = Raw = None

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
    session_id: Optional[int] = None
    username: Optional[str] = None
    domain: Optional[str] = None
    workstation: Optional[str] = None
    auth_type: Optional[str] = None
    is_guest: bool = False
    smb_version: str = "Unknown" # SMBv1, SMBv2, SMBv3
    signing_required: bool = False
    start_ts: float = 0.0
    last_seen: float = 0.0
    packets: int = 0
    bytes: int = 0
    active: bool = False


@dataclass
class SmbConversation:
    client_ip: str
    server_ip: str
    packets: int = 0
    bytes: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    requests: int = 0
    responses: int = 0
    commands: Counter[str] = field(default_factory=Counter)
    statuses: Counter[str] = field(default_factory=Counter)


@dataclass
class SmbServer:
    ip: str
    dialects: Set[str] = field(default_factory=set)
    signing_required: Optional[bool] = None
    capabilities: Set[str] = field(default_factory=set)
    server_guid: Optional[str] = None
    shares: Set[str] = field(default_factory=set)
    packets: int = 0
    bytes: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None


@dataclass
class SmbClient:
    ip: str
    dialects: Set[str] = field(default_factory=set)
    client_guid: Optional[str] = None
    usernames: Set[str] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    packets: int = 0
    bytes: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

@dataclass
class SmbFileOp:
    filename: str
    action: str # Read, Write, Delete, Create
    path: str
    size: int = 0
    ts: float = 0.0
    client_ip: Optional[str] = None
    server_ip: Optional[str] = None
    share: Optional[str] = None
    file_id: Optional[str] = None

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
    requests: Counter[str]
    responses: Counter[str]
    error_codes: Counter[str] # NT Status codes
    sessions: List[SmbSession]
    conversations: List[SmbConversation]
    servers: List[SmbServer]
    clients: List[SmbClient]
    shares: List[SmbShare]
    files: List[SmbFileOp]
    artifacts: List[str]
    observed_users: Counter[str]
    observed_domains: Counter[str]
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

SMB2_DIALECT_MAP = {
    0x0202: "SMB2.0.2",
    0x0210: "SMB2.1",
    0x0300: "SMB3.0",
    0x0302: "SMB3.0.2",
    0x0311: "SMB3.1.1",
}

SMB2_SIGNING_REQUIRED = 0x0002

SMB2_CAPABILITIES = {
    0x00000001: "DFS",
    0x00000002: "Leasing",
    0x00000004: "LargeMTU",
    0x00000008: "MultiChannel",
    0x00000010: "PersistentHandles",
    0x00000020: "DirectoryLeasing",
    0x00000040: "Encryption",
}

# --- Analysis Functions ---

def analyze_smb(path: Path, show_status: bool = True) -> SmbSummary:
    if TCP is None:
        return SmbSummary(path, 0, 0, Counter(), Counter(), Counter(), Counter(), [], [], [], [], [], [], [], Counter(), Counter(), [], Counter(), Counter(), [], ["Scapy not available"])

    ftype = detect_file_type(path)
    try:
        reader = PcapNgReader(str(path)) if ftype == "pcapng" else PcapReader(str(path))
    except Exception as e:
        return SmbSummary(path, 0, 0, Counter(), Counter(), Counter(), Counter(), [], [], [], [], [], [], [], Counter(), Counter(), [], Counter(), Counter(), [], [f"Error opening pcap: {e}"])

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
    requests = Counter()
    responses = Counter()
    error_codes = Counter()
    
    # Trackers
    shares: Dict[str, SmbShare] = {}
    sessions: Dict[Tuple[str, str, int], SmbSession] = {} # Key: ClientIP, ServerIP, SessionID (if determinable)
    conversations: Dict[Tuple[str, str], SmbConversation] = {}
    servers: Dict[str, SmbServer] = {}
    clients: Dict[str, SmbClient] = {}
    anomalies: List[SmbAnomaly] = []
    files: List[SmbFileOp] = []
    artifacts: Set[str] = set()
    observed_users: Counter[str] = Counter()
    observed_domains: Counter[str] = Counter()
    
    # State tracking
    top_clients = Counter()
    top_servers = Counter()
    errors: List[str] = []
    client_to_servers: Dict[str, Set[str]] = defaultdict(set)
    client_admin_shares: Counter[str] = Counter()
    client_failures: Counter[str] = Counter()
    pending_creates: Dict[Tuple[str, str, int, int], Dict[str, object]] = {}
    tree_map: Dict[Tuple[str, str, int, int], str] = {}
    file_id_map: Dict[Tuple[str, str, int, str], str] = {}

    def _get_ip_pair(pkt: Packet) -> Tuple[str, str]:
        if IP is not None and IP in pkt:
            return pkt[IP].src, pkt[IP].dst
        if IPv6 is not None and IPv6 in pkt:
            return pkt[IPv6].src, pkt[IPv6].dst
        return "0.0.0.0", "0.0.0.0"

    def _update_time(obj, ts: Optional[float]) -> None:
        if ts is None:
            return
        if obj.first_seen is None or ts < obj.first_seen:
            obj.first_seen = ts
        if obj.last_seen is None or ts > obj.last_seen:
            obj.last_seen = ts

    def _track_conversation(client: str, server: str, length: int, ts: Optional[float], is_request: bool, cmd_name: str, status_text: Optional[str]) -> None:
        key = (client, server)
        convo = conversations.get(key)
        if convo is None:
            convo = SmbConversation(client_ip=client, server_ip=server)
            conversations[key] = convo
        convo.packets += 1
        convo.bytes += length
        _update_time(convo, ts)
        if is_request:
            convo.requests += 1
        else:
            convo.responses += 1
        if cmd_name:
            convo.commands[cmd_name] += 1
        if status_text:
            convo.statuses[status_text] += 1

    def _get_server(ip: str) -> SmbServer:
        srv = servers.get(ip)
        if srv is None:
            srv = SmbServer(ip=ip)
            servers[ip] = srv
        return srv

    def _get_client(ip: str) -> SmbClient:
        cli = clients.get(ip)
        if cli is None:
            cli = SmbClient(ip=ip)
            clients[ip] = cli
        return cli

    def _hex_guid(value: bytes) -> str:
        try:
            return str(uuid.UUID(bytes_le=value))
        except Exception:
            return value.hex()

    def _dialect_name(code: int) -> str:
        return SMB2_DIALECT_MAP.get(code, f"0x{code:04x}")

    def _dialect_family(name: str) -> str:
        if name.startswith("SMB3"):
            return "SMB3"
        if name.startswith("SMB2"):
            return "SMB2"
        return "SMB2/3"

    def _extract_strings(data: bytes, min_len: int = 4) -> Set[str]:
        results: Set[str] = set()
        current = bytearray()
        for b in data:
            if 32 <= b <= 126:
                current.append(b)
            else:
                if len(current) >= min_len:
                    results.add(current.decode("latin-1", errors="ignore"))
                current = bytearray()
        if len(current) >= min_len:
            results.add(current.decode("latin-1", errors="ignore"))

        utf16 = bytearray()
        i = 0
        while i + 1 < len(data):
            ch = data[i]
            if 32 <= ch <= 126 and data[i + 1] == 0x00:
                utf16.append(ch)
                i += 2
            else:
                if len(utf16) >= min_len:
                    results.add(utf16.decode("latin-1", errors="ignore"))
                utf16 = bytearray()
                i += 2
        if len(utf16) >= min_len:
            results.add(utf16.decode("latin-1", errors="ignore"))
        return results

    def _extract_users_from_strings(strings: Set[str]) -> Tuple[Set[str], Set[str]]:
        users: Set[str] = set()
        domains: Set[str] = set()
        for value in strings:
            if "\\" in value and len(value.split("\\")) == 2:
                dom, user = value.split("\\", 1)
                if dom and user:
                    domains.add(dom)
                    users.add(user)
            if "@" in value and len(value.split("@")) == 2:
                user, dom = value.split("@", 1)
                if user and dom:
                    domains.add(dom)
                    users.add(user)
        return users, domains

    def _parse_ntlm_type3(payload: bytes) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        signature = b"NTLMSSP\x00"
        idx = payload.find(signature)
        if idx == -1 or len(payload) < idx + 64:
            return None, None, None
        try:
            msg_type = struct.unpack("<I", payload[idx + 8:idx + 12])[0]
            if msg_type != 3:
                return None, None, None
            def _read_field(offset: int) -> Tuple[int, int]:
                length = struct.unpack("<H", payload[offset:offset + 2])[0]
                field_offset = struct.unpack("<I", payload[offset + 4:offset + 8])[0]
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

    def _iter_smb_records(payload: bytes) -> List[bytes]:
        records: List[bytes] = []
        if len(payload) >= 4 and payload[0] == 0x00:
            offset = 0
            while offset + 4 <= len(payload):
                if payload[offset] != 0x00:
                    break
                length = int.from_bytes(payload[offset + 1:offset + 4], "big")
                if length <= 0:
                    break
                end = offset + 4 + length
                if end > len(payload):
                    break
                records.append(payload[offset + 4:end])
                offset = end
            if records:
                return records

        def _scan_magic(magic: bytes) -> None:
            start = 0
            while True:
                idx = payload.find(magic, start)
                if idx == -1:
                    break
                records.append(payload[idx:])
                start = idx + len(magic)

        _scan_magic(SMB2_MAGIC)
        _scan_magic(SMB1_MAGIC)
        return records
    
    # Helper to parse specific packets
    def _parse_smb2_header(payload: bytes, src: str, dst: str, idx: int, ts: Optional[float], length: int, is_request_flow: bool):
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
            msg_id = struct.unpack("<Q", payload[24:32])[0]
            # msg_id = struct.unpack("<Q", payload[24:32])[0]
            # process_id = struct.unpack("<I", payload[32:36])[0]
            tree_id = struct.unpack("<I", payload[36:40])[0]
            session_id = struct.unpack("<Q", payload[40:48])[0]
            
            is_response = (flags & 0x00000001) != 0
            
            cmd_name = SMB2_CMD_MAP.get(cmd, f"Unknown(0x{cmd:02X})")
            full_cmd = f"SMB2:{cmd_name}"
            commands[full_cmd] += 1
            if is_response:
                responses[full_cmd] += 1
            else:
                requests[full_cmd] += 1
            
            # Error Code Tracking (only on responses)
            status_text = None
            if is_response:
                status_text = NT_STATUS_MAP.get(status, f"0x{status:08X}")
                error_codes[status_text] += 1
                
                if status == STATUS_LOGON_FAILURE:
                    anomalies.append(SmbAnomaly("HIGH", "SMB Logon Failure", f"Failed login attempt to {dst}", idx, src, dst))
                    client_failures[src] += 1
                elif status == STATUS_ACCESS_DENIED:
                    anomalies.append(SmbAnomaly("MEDIUM", "SMB Access Denied", f"Access denied on {dst}", idx, src, dst))

            _track_conversation(src if is_request_flow else dst, dst if is_request_flow else src, length, ts, not is_response, full_cmd, status_text)

            session_key = (src if is_request_flow else dst, dst if is_request_flow else src, int(session_id))
            if session_id != 0:
                sess = sessions.get(session_key)
                if sess is None:
                    sess = SmbSession(client_ip=session_key[0], server_ip=session_key[1], session_id=int(session_id))
                    sessions[session_key] = sess
                server_info = servers.get(sess.server_ip)
                if server_info and server_info.signing_required is not None:
                    sess.signing_required = server_info.signing_required
                if server_info and server_info.dialects and sess.smb_version == "Unknown":
                    if any(d.startswith("SMB3") for d in server_info.dialects):
                        sess.smb_version = "SMB3"
                    elif any(d.startswith("SMB2") for d in server_info.dialects):
                        sess.smb_version = "SMB2"
                sess.packets += 1
                sess.bytes += length
                if ts is not None and (sess.start_ts == 0.0 or ts < sess.start_ts):
                    sess.start_ts = ts
                if ts is not None and ts > sess.last_seen:
                    sess.last_seen = ts
                sess.active = True

            # Payload after header
            data = payload[64:]
            
            # --- Negotiate (Capabilities, Dialects, Signing) ---
            if cmd == SMB2_COM_NEGOTIATE:
                if not is_response:
                    if len(data) >= 36:
                        dialect_count = struct.unpack("<H", data[2:4])[0]
                        client_guid = data[12:28]
                        cli = _get_client(src if is_request_flow else dst)
                        if client_guid.strip(b"\x00"):
                            cli.client_guid = _hex_guid(client_guid)
                        if len(data) >= 36 + (dialect_count * 2):
                            dialects = [struct.unpack("<H", data[36 + i:38 + i])[0] for i in range(0, dialect_count * 2, 2)]
                            for d in dialects:
                                name = _dialect_name(d)
                                cli.dialects.add(name)
                                versions[_dialect_family(name)] += 1
                else:
                    if len(data) >= 64:
                        security_mode = struct.unpack("<H", data[2:4])[0]
                        dialect = struct.unpack("<H", data[4:6])[0]
                        capabilities = struct.unpack("<I", data[12:16])[0]
                        server_guid = data[16:32]
                        srv = _get_server(dst if is_request_flow else src)
                        srv.server_guid = _hex_guid(server_guid) if server_guid.strip(b"\x00") else srv.server_guid
                        dialect_name = _dialect_name(dialect)
                        srv.dialects.add(dialect_name)
                        versions[_dialect_family(dialect_name)] += 1
                        signing_required = (security_mode & SMB2_SIGNING_REQUIRED) != 0
                        srv.signing_required = signing_required if srv.signing_required is None else srv.signing_required
                        for cap_bit, cap_name in SMB2_CAPABILITIES.items():
                            if capabilities & cap_bit:
                                srv.capabilities.add(cap_name)
                        if not signing_required:
                            anomalies.append(SmbAnomaly("MEDIUM", "SMB Signing Not Required", f"Server {srv.ip} allows unsigned SMB sessions", idx, src, dst))

            # --- Session Setup (Authentication Activity) ---
            if cmd == SMB2_COM_SESSION_SETUP and not is_response:
                user, domain, workstation = _parse_ntlm_type3(payload)
                if user or domain:
                    sess = sessions.get(session_key)
                    if sess is None and session_id != 0:
                        sess = SmbSession(client_ip=session_key[0], server_ip=session_key[1], session_id=int(session_id))
                        sessions[session_key] = sess
                    if sess:
                        sess.username = user or sess.username
                        sess.domain = domain or sess.domain
                        sess.workstation = workstation or sess.workstation
                        sess.auth_type = "NTLM"
                        if user:
                            observed_users[user] += 1
                        if domain:
                            observed_domains[domain] += 1

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
                            _get_server(dst).shares.add(share_path)
                        
                        shares[share_key].connect_count += 1

                        if shares[share_key].is_admin:
                            anomalies.append(SmbAnomaly("HIGH", "Admin Share Access", f"Administrative share {share_path} accessed", idx, src, dst))
                            client_admin_shares[src] += 1

                        client_to_servers[src].add(dst)

                        if session_id != 0 and tree_id != 0:
                            tree_map[(src, dst, int(session_id), int(tree_id))] = share_path

            # --- Create (File Access) ---
            if cmd == SMB2_COM_CREATE and not is_response:
                if len(data) >= 56:
                    name_offset = struct.unpack("<H", data[48:50])[0]
                    name_length = struct.unpack("<H", data[50:52])[0]
                    real_off = name_offset - 64
                    if name_length > 0 and real_off >= 0 and real_off + name_length <= len(data):
                        filename = data[real_off:real_off + name_length].decode("utf-16le", errors="ignore")
                        share = tree_map.get((src, dst, int(session_id), int(tree_id)))
                        files.append(SmbFileOp(filename=filename, action="Create", path=filename, ts=ts or 0.0, client_ip=src, server_ip=dst, share=share))
                        suspicious_ext = {".exe", ".dll", ".ps1", ".bat", ".vbs", ".js", ".scr", ".sys", ".lnk", ".zip", ".rar", ".7z"}
                        lower_name = filename.lower()
                        for ext in suspicious_ext:
                            if lower_name.endswith(ext):
                                anomalies.append(SmbAnomaly("MEDIUM", "Suspicious File Created", f"{filename} created over SMB", idx, src, dst))
                                break
                        if session_id != 0:
                            pending_creates[(src, dst, int(session_id), int(msg_id))] = {"filename": filename, "tree_id": int(tree_id), "share": share}

            if cmd == SMB2_COM_CREATE and is_response:
                if len(data) >= 80 and session_id != 0:
                    file_id = data[64:80]
                    pending = pending_creates.pop((dst, src, int(session_id), int(msg_id)), None)
                    if pending:
                        file_id_hex = file_id.hex()
                        share = pending.get("share")
                        filename = str(pending.get("filename", ""))
                        file_id_map[(dst, src, int(session_id), file_id_hex)] = filename
                        if filename and share:
                            artifacts.add(f"{share}{filename}")

            if cmd in (SMB2_COM_READ, SMB2_COM_WRITE) and not is_response:
                if len(data) >= 32 and session_id != 0:
                    length_bytes = struct.unpack("<I", data[4:8])[0]
                    file_id = data[16:32]
                    file_id_hex = file_id.hex()
                    filename = file_id_map.get((src, dst, int(session_id), file_id_hex))
                    share = tree_map.get((src, dst, int(session_id), int(tree_id)))
                    action = "Read" if cmd == SMB2_COM_READ else "Write"
                    files.append(SmbFileOp(filename=filename or "(unknown)", action=action, path=filename or "(unknown)", size=length_bytes, ts=ts or 0.0, client_ip=src, server_ip=dst, share=share, file_id=file_id_hex))

        except Exception:
            pass

    def _parse_smb1_header(payload: bytes, src: str, dst: str, idx: int, ts: Optional[float], length: int, is_request_flow: bool):
        # SMB1 Header is 32 bytes
        if len(payload) < 32: return
        
        # Command is at offset 4
        cmd = payload[4]
        
        cmd_name = f"0x{cmd:02X}"
        if cmd == SMB1_COM_NEGOTIATE: cmd_name = "Negotiate"
        elif cmd == SMB1_COM_SESSION_SETUP_ANDX: cmd_name = "Session Setup"
        elif cmd == SMB1_COM_TREE_CONNECT_ANDX: cmd_name = "Tree Connect"
        
        full_cmd = f"SMB1:{cmd_name}"
        commands[full_cmd] += 1
        
        # Flags2 at offset 14 (2 bytes)
        # flags2 = struct.unpack("<H", payload[14:16])[0]
        
        # Error code (Status) at offset 9 (4 bytes)
        status = struct.unpack("<I", payload[9:13])[0]
        
        is_response = (payload[13] & 0x80) != 0 # Flags at offset 13, bit 7 is Reply bit
        
        if is_response:
            responses[full_cmd] += 1
        else:
            requests[full_cmd] += 1

        status_text = None
        if is_response:
            status_text = NT_STATUS_MAP.get(status, f"0x{status:08X}")
            error_codes[status_text] += 1

        _track_conversation(src if is_request_flow else dst, dst if is_request_flow else src, length, ts, not is_response, full_cmd, status_text)

        if cmd == SMB1_COM_NEGOTIATE and not is_response and len(payload) > 36:
            dialects = []
            data = payload[32:]
            if len(data) >= 3:
                byte_count = struct.unpack("<H", data[1:3])[0]
                dialect_blob = data[3:3 + byte_count]
                parts = dialect_blob.split(b"\x00")
                for part in parts:
                    if part.startswith(b"\x02"):
                        name = part[1:].decode("latin-1", errors="ignore")
                        if name:
                            dialects.append(name)
            if dialects:
                cli = _get_client(src if is_request_flow else dst)
                for name in dialects:
                    cli.dialects.add(name)

        if cmd == SMB1_COM_TREE_CONNECT_ANDX and not is_response:
            strings = _extract_strings(payload)
            for text in strings:
                if text.startswith("\\\\") and "\\" in text[2:]:
                    share_path = text
                    share_key = f"{dst}|{share_path}"
                    if share_key not in shares:
                        is_admin = "IPC$" in share_path or "ADMIN$" in share_path or "C$" in share_path
                        shares[share_key] = SmbShare(share_path, dst, is_admin=is_admin)
                        _get_server(dst).shares.add(share_path)
                    shares[share_key].connect_count += 1
                    if shares[share_key].is_admin:
                        anomalies.append(SmbAnomaly("HIGH", "Admin Share Access", f"Administrative share {share_path} accessed", idx, src, dst))
                        client_admin_shares[src] += 1
                    client_to_servers[src].add(dst)

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
                payload = b""
                if Raw in pkt:
                    payload = bytes(pkt[Raw])
                else:
                    try:
                        payload = bytes(pkt[TCP].payload)
                    except Exception:
                        payload = b""
                if payload:
                    ts = safe_float(getattr(pkt, "time", None))
                    length = len(payload)

                    src, dst = _get_ip_pair(pkt)
                    is_request_flow = pkt[TCP].dport in (445, 139)
                    client = src if is_request_flow else dst
                    server = dst if is_request_flow else src

                    top_clients[client] += 1
                    top_servers[server] += 1

                    cli = _get_client(client)
                    srv = _get_server(server)
                    cli.packets += 1
                    cli.bytes += length
                    srv.packets += 1
                    srv.bytes += length
                    _update_time(cli, ts)
                    _update_time(srv, ts)
                    
                    # NetBIOS Session Service typically adds 4 bytes Header if port 139 or even 445 sometimes
                    # Header: MsgType(1), Length(3)
                    # Often bytes[0] == 0x00 and then length.
                    
                    offset = 0
                    if len(payload) > 4 and payload[0] == 0x00:
                         # Likely NetBIOS framing
                         offset = 4
                    
                    smb_data = payload[offset:]
                    
                    smb_records = _iter_smb_records(payload)
                    if not smb_records:
                        smb_records = [payload]

                    for smb_data in smb_records:
                        if smb_data.startswith(SMB2_MAGIC):
                            versions["SMB2/3"] += 1
                            _parse_smb2_header(smb_data, client, server, total_packets, ts, length, is_request_flow)

                        elif smb_data.startswith(SMB1_MAGIC):
                            versions["SMB1"] += 1
                            if versions["SMB1"] == 1:
                                anomalies.append(SmbAnomaly("CRITICAL", "SMBv1 Detected", "Legacy, insecure SMBv1 protocol in use.", total_packets, client, server))
                            if pkt[TCP].sport == 139 or pkt[TCP].dport == 139:
                                anomalies.append(SmbAnomaly("LOW", "SMB over NetBIOS", "SMB traffic over port 139 observed.", total_packets, client, server))
                            _parse_smb1_header(smb_data, client, server, total_packets, ts, length, is_request_flow)

                        # Artifacts and user strings
                        strings = _extract_strings(smb_data)
                        for text in strings:
                            if "\\PIPE\\" in text.upper():
                                artifacts.add(text)
                        users, domains = _extract_users_from_strings(strings)
                        for user in users:
                            observed_users[user] += 1
                            cli.usernames.add(user)
                            if user.lower() in {"guest", "anonymous", "anonymous logon"}:
                                anomalies.append(SmbAnomaly("MEDIUM", "Guest/Anonymous SMB User", f"Guest/anonymous user {user} observed", total_packets, client, server))
                        for domain in domains:
                            observed_domains[domain] += 1
                            cli.domains.add(domain)

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
        requests=requests,
        responses=responses,
        error_codes=error_codes,
        sessions=list(sessions.values()),
        conversations=list(conversations.values()),
        servers=list(servers.values()),
        clients=list(clients.values()),
        shares=list(shares.values()),
        files=files,
        artifacts=sorted(artifacts),
        observed_users=observed_users,
        observed_domains=observed_domains,
        anomalies=anomalies,
        top_clients=top_clients,
        top_servers=top_servers,
        lateral_movement=sorted(lateral_movement, key=lambda x: x.get("score", 0), reverse=True),
        errors=errors
    )
