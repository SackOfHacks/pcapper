from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
import struct
import uuid
import os

try:
    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6
    from scapy.packet import Raw, Packet
    from scapy.utils import PcapReader, PcapNgReader
except ImportError:
    IP = TCP = Raw = None

from .pcap_cache import get_reader
from .utils import detect_file_type, safe_float, decode_payload, counter_inc, set_add_cap, setdict_add

MAX_SMB_UNIQUE = int(os.getenv("PCAPPER_MAX_SMB_UNIQUE", "50000"))
MAX_SMB_CONVERSATIONS = int(os.getenv("PCAPPER_MAX_SMB_CONVERSATIONS", "50000"))
MAX_SMB_SESSIONS = int(os.getenv("PCAPPER_MAX_SMB_SESSIONS", "20000"))
MAX_SMB_SHARES = int(os.getenv("PCAPPER_MAX_SMB_SHARES", "20000"))
MAX_SMB_FILES = int(os.getenv("PCAPPER_MAX_SMB_FILES", "50000"))
MAX_SMB_ARTIFACTS = int(os.getenv("PCAPPER_MAX_SMB_ARTIFACTS", "50000"))
MAX_SMB_ANOMALIES = int(os.getenv("PCAPPER_MAX_SMB_ANOMALIES", "2000"))
MAX_SMB_PENDING = int(os.getenv("PCAPPER_MAX_SMB_PENDING", "50000"))
MAX_SMB_TREE_MAP = int(os.getenv("PCAPPER_MAX_SMB_TREES", "50000"))
MAX_SMB_FILE_IDS = int(os.getenv("PCAPPER_MAX_SMB_FILE_IDS", "100000"))

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
    encryption_required: Optional[bool] = None
    encrypted: bool = False
    signed_packets: int = 0
    unsigned_packets: int = 0
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
    workstations: Set[str] = field(default_factory=set)
    workstation_candidates: Set[str] = field(default_factory=set)
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
    smb_ports: Counter[int]
    versions: Counter[str]
    commands: Counter[str]
    requests: Counter[str]
    responses: Counter[str]
    error_codes: Counter[str] # NT Status codes
    signed_packets: int
    unsigned_packets: int
    encrypted_packets: int
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
    analysis_notes: List[str]
    errors: List[str]

# --- Constants ---

SMB1_MAGIC = b"\xffSMB"
SMB2_MAGIC = b"\xfeSMB"
SMB3_TRANSFORM_MAGIC = b"\xfdSMB"

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
SMB2_FLAGS_SIGNED = 0x00000008
SMB2_SESSION_FLAG_ENCRYPT_DATA = 0x0001
SMB1_FLAGS_RESPONSE = 0x80
SMB1_FLAGS2_SIGNED = 0x0004

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
        return SmbSummary(
            path,
            0,
            0,
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            0,
            0,
            0,
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            Counter(),
            Counter(),
            [],
            Counter(),
            Counter(),
            [],
            [],
            ["Scapy not available"],
        )

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path, show_status=show_status
        )
    except Exception as exc:
        return SmbSummary(
            path,
            0,
            0,
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            0,
            0,
            0,
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            Counter(),
            Counter(),
            [],
            Counter(),
            Counter(),
            [],
            [],
            [f"Error opening pcap: {exc}"],
        )

    size_bytes = size_bytes

    total_packets = 0
    smb_packets = 0
    smb_ports: Counter[int] = Counter()
    versions = Counter()
    commands = Counter()
    requests = Counter()
    responses = Counter()
    error_codes = Counter()
    signed_packets = 0
    unsigned_packets = 0
    encrypted_packets = 0
    
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
    analysis_notes: List[str] = []
    
    # State tracking
    top_clients = Counter()
    top_servers = Counter()
    errors: List[str] = []
    client_to_servers: Dict[str, Set[str]] = defaultdict(set)
    client_admin_shares: Counter[str] = Counter()
    client_failures: Counter[str] = Counter()
    pending_creates: Dict[Tuple[str, str, int, int], Dict[str, object]] = {}
    pending_io: Dict[Tuple[str, str, int, int, int], Dict[str, object]] = {}
    pending_auth: Dict[Tuple[str, str, int], Dict[str, object]] = {}
    tree_map: Dict[Tuple[str, str, int, int], str] = {}
    file_id_map: Dict[Tuple[str, str, int, str], str] = {}
    smb1_tree_map: Dict[Tuple[str, str, int], str] = {}
    smb1_pending_auth: Dict[Tuple[str, str, int], Dict[str, object]] = {}
    session_id_map: Dict[int, Tuple[str, str]] = {}

    cap_warnings: Set[str] = set()

    def _cap_warn(key: str, message: str) -> None:
        if key in cap_warnings:
            return
        cap_warnings.add(key)
        errors.append(message)

    def _append_capped(items: List[Any], item: Any, limit: int, key: str, message: str) -> None:
        if len(items) >= limit:
            _cap_warn(key, message)
            return
        items.append(item)

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
            if len(conversations) >= MAX_SMB_CONVERSATIONS:
                _cap_warn("conversations", f"SMB conversations capped at {MAX_SMB_CONVERSATIONS}")
                return
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
            counter_inc(convo.commands, cmd_name)
        if status_text:
            counter_inc(convo.statuses, status_text)

    def _get_server(ip: str) -> SmbServer:
        srv = servers.get(ip)
        if srv is None:
            if len(servers) >= MAX_SMB_UNIQUE:
                _cap_warn("servers", f"SMB servers capped at {MAX_SMB_UNIQUE}")
                return SmbServer(ip=ip)
            srv = SmbServer(ip=ip)
            servers[ip] = srv
        return srv

    def _get_client(ip: str) -> SmbClient:
        cli = clients.get(ip)
        if cli is None:
            if len(clients) >= MAX_SMB_UNIQUE:
                _cap_warn("clients", f"SMB clients capped at {MAX_SMB_UNIQUE}")
                return SmbClient(ip=ip)
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
                    results.add(decode_payload(bytes(current), encoding="latin-1"))
                current = bytearray()
        if len(current) >= min_len:
            results.add(decode_payload(bytes(current), encoding="latin-1"))

        utf16 = bytearray()
        i = 0
        while i + 1 < len(data):
            ch = data[i]
            if 32 <= ch <= 126 and data[i + 1] == 0x00:
                utf16.append(ch)
                i += 2
            else:
                if len(utf16) >= min_len:
                    results.add(decode_payload(bytes(utf16), encoding="latin-1"))
                utf16 = bytearray()
                i += 2
        if len(utf16) >= min_len:
            results.add(decode_payload(bytes(utf16), encoding="latin-1"))
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

    WORKSTATION_BLACKLIST = {
        "NTLMSSP", "SMB", "SMB2", "SMB3", "LANMAN", "WORKGROUP", "DOMAIN", "WINDOWS",
        "MICROSOFT", "ADMIN", "GUEST", "ANONYMOUS", "PIPE", "IPC", "SHARE", "BUILTIN",
        "SERVER", "CLIENT", "LOCALHOST",
    }

    def _extract_workstations_from_strings(strings: Set[str]) -> Tuple[Set[str], Set[str]]:
        candidates: Set[str] = set()
        refined: Set[str] = set()
        for value in strings:
            if not value:
                continue
            if value.startswith("\\\\"):
                continue
            if any(token in value for token in ("\\", "/", ":", "@", " ")):
                continue
            if "." in value:
                continue
            if len(value) < 3 or len(value) > 15:
                continue
            if value.isdigit():
                continue
            if not all(ch.isalnum() or ch in "-_" for ch in value):
                continue
            upper = value.upper()
            if upper in WORKSTATION_BLACKLIST:
                continue
            if not any(ch.isalpha() for ch in value):
                continue
            candidates.add(value)
            if len(value) >= 4 and sum(ch.isdigit() for ch in value) <= 3:
                refined.add(value)
        return refined, candidates

    KRB5_OID_DER = b"\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"

    def _detect_auth_mechs(payload: bytes) -> Set[str]:
        mechs: Set[str] = set()
        if b"NTLMSSP" in payload:
            mechs.add("NTLM")
        if KRB5_OID_DER in payload or b"Kerberos" in payload or b"kerberos" in payload:
            mechs.add("Kerberos")
        return mechs

    def _set_auth_type(sess: SmbSession, auth: str) -> None:
        if not auth:
            return
        if sess.auth_type:
            existing = {token.strip() for token in sess.auth_type.split("/") if token.strip()}
            if auth not in existing:
                sess.auth_type = "/".join(list(existing) + [auth])
        else:
            sess.auth_type = auth

    def _split_unc_share(path: str) -> tuple[Optional[str], Optional[str]]:
        if not path:
            return None, None
        normalized = path.replace("/", "\\")
        if not normalized.startswith("\\\\"):
            return None, None
        trimmed = normalized.lstrip("\\")
        parts = [part for part in trimmed.split("\\") if part]
        if len(parts) < 2:
            return None, None
        share = f"\\\\{parts[0]}\\{parts[1]}"
        remainder = "\\".join(parts[2:]) if len(parts) > 2 else ""
        return share, remainder or None

    def _apply_auth_details(sess: SmbSession, details: Dict[str, object]) -> None:
        for mech in details.get("mechs", []) if isinstance(details.get("mechs"), list) else []:
            _set_auth_type(sess, str(mech))
        user = details.get("user")
        domain = details.get("domain")
        workstation = details.get("workstation")
        if user:
            sess.username = str(user)
        if domain:
            sess.domain = str(domain)
        if workstation:
            sess.workstation = str(workstation)

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
            domain = decode_payload(payload[idx + domain_off:idx + domain_off + domain_len], encoding="utf-16le") if domain_len else None
            user = decode_payload(payload[idx + user_off:idx + user_off + user_len], encoding="utf-16le") if user_len else None
            workstation = decode_payload(payload[idx + workstation_off:idx + workstation_off + workstation_len], encoding="utf-16le") if workstation_len else None
            return user or None, domain or None, workstation or None
        except Exception:
            return None, None, None

    def _parse_smb3_transform_session_id(payload: bytes) -> Optional[int]:
        if len(payload) < 52:
            return None
        try:
            return struct.unpack("<Q", payload[44:52])[0]
        except Exception:
            return None

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
        _scan_magic(SMB3_TRANSFORM_MAGIC)
        return records

    def _iter_smb2_commands(payload: bytes) -> List[bytes]:
        commands: List[bytes] = []
        offset = 0
        max_len = len(payload)
        while offset + 64 <= max_len:
            if not payload[offset:].startswith(SMB2_MAGIC):
                break
            next_cmd = 0
            if offset + 24 <= max_len:
                try:
                    next_cmd = struct.unpack("<I", payload[offset + 20:offset + 24])[0]
                except Exception:
                    next_cmd = 0
            if next_cmd == 0:
                commands.append(payload[offset:])
                break
            if next_cmd < 64 or offset + next_cmd > max_len:
                commands.append(payload[offset:])
                break
            commands.append(payload[offset:offset + next_cmd])
            offset += next_cmd
        if not commands:
            commands.append(payload)
        return commands
    
    # Helper to parse specific packets
    def _parse_smb2_header(payload: bytes, src: str, dst: str, src_port: int, dst_port: int, idx: int, ts: Optional[float], length: int):
        nonlocal signed_packets, unsigned_packets
        # SMB2 Header is 64 bytes
        if len(payload) < 64:
            return

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
            tree_id = struct.unpack("<I", payload[36:40])[0]
            session_id = struct.unpack("<Q", payload[40:48])[0]

            is_response = (flags & 0x00000001) != 0
            client = dst if is_response else src
            server = src if is_response else dst
            server_port = src_port if is_response else dst_port

            if isinstance(server_port, int):
                counter_inc(smb_ports, int(server_port))

            signed = (flags & SMB2_FLAGS_SIGNED) != 0
            if signed:
                signed_packets += 1
            else:
                unsigned_packets += 1

            cmd_name = SMB2_CMD_MAP.get(cmd, f"Unknown(0x{cmd:02X})")
            full_cmd = f"SMB2:{cmd_name}"
            counter_inc(commands, full_cmd)
            if is_response:
                counter_inc(responses, full_cmd)
            else:
                counter_inc(requests, full_cmd)

            # Error Code Tracking (only on responses)
            status_text = None
            if is_response:
                status_text = NT_STATUS_MAP.get(status, f"0x{status:08X}")
                counter_inc(error_codes, status_text)

                if status == STATUS_LOGON_FAILURE:
                    _append_capped(
                        anomalies,
                        SmbAnomaly("HIGH", "SMB Logon Failure", f"Failed login attempt to {server}", idx, src, dst),
                        MAX_SMB_ANOMALIES,
                        "anomalies",
                        f"SMB anomalies capped at {MAX_SMB_ANOMALIES}",
                    )
                    counter_inc(client_failures, client)
                elif status == STATUS_ACCESS_DENIED:
                    _append_capped(
                        anomalies,
                        SmbAnomaly("MEDIUM", "SMB Access Denied", f"Access denied on {server}", idx, src, dst),
                        MAX_SMB_ANOMALIES,
                        "anomalies",
                        f"SMB anomalies capped at {MAX_SMB_ANOMALIES}",
                    )

            _track_conversation(client, server, length, ts, not is_response, full_cmd, status_text)

            session_key = (client, server, int(session_id))
            sess: Optional[SmbSession] = None
            if session_id != 0:
                sess = sessions.get(session_key)
                if sess is None:
                    if len(sessions) >= MAX_SMB_SESSIONS:
                        _cap_warn("sessions", f"SMB sessions capped at {MAX_SMB_SESSIONS}")
                        sess = None
                    else:
                        sess = SmbSession(client_ip=client, server_ip=server, session_id=int(session_id))
                        sessions[session_key] = sess
                if sess:
                    session_id_map.setdefault(int(session_id), (client, server))
                    server_info = servers.get(sess.server_ip)
                    if server_info and server_info.signing_required is not None:
                        sess.signing_required = server_info.signing_required
                    if server_info and server_info.dialects and sess.smb_version == "Unknown":
                        if any(d.startswith("SMB3") for d in server_info.dialects):
                            sess.smb_version = "SMB3"
                        elif any(d.startswith("SMB2") for d in server_info.dialects):
                            sess.smb_version = "SMB2"
                        else:
                            sess.smb_version = "SMB2/3"
                    elif sess.smb_version == "Unknown":
                        sess.smb_version = "SMB2/3"
                    sess.packets += 1
                    sess.bytes += length
                    if ts is not None and (sess.start_ts == 0.0 or ts < sess.start_ts):
                        sess.start_ts = ts
                    if ts is not None and ts > sess.last_seen:
                        sess.last_seen = ts
                    sess.active = True

                    if signed:
                        sess.signed_packets += 1
                    else:
                        sess.unsigned_packets += 1

            # Payload after header
            data = payload[64:]

            # --- Negotiate (Capabilities, Dialects, Signing) ---
            if cmd == SMB2_COM_NEGOTIATE:
                if not is_response:
                    if len(data) >= 36:
                        dialect_count = struct.unpack("<H", data[2:4])[0]
                        client_guid = data[12:28]
                        cli = _get_client(client)
                        if client_guid.strip(b"\x00"):
                            cli.client_guid = _hex_guid(client_guid)
                        if len(data) >= 36 + (dialect_count * 2):
                            dialects = [struct.unpack("<H", data[36 + i:38 + i])[0] for i in range(0, dialect_count * 2, 2)]
                            for d in dialects:
                                name = _dialect_name(d)
                                set_add_cap(cli.dialects, name, max_size=MAX_SMB_UNIQUE)
                                counter_inc(versions, _dialect_family(name))
                else:
                    if len(data) >= 64:
                        security_mode = struct.unpack("<H", data[2:4])[0]
                        dialect = struct.unpack("<H", data[4:6])[0]
                        capabilities = struct.unpack("<I", data[12:16])[0]
                        server_guid = data[16:32]
                        srv = _get_server(server)
                        srv.server_guid = _hex_guid(server_guid) if server_guid.strip(b"\x00") else srv.server_guid
                        dialect_name = _dialect_name(dialect)
                        set_add_cap(srv.dialects, dialect_name, max_size=MAX_SMB_UNIQUE)
                        counter_inc(versions, _dialect_family(dialect_name))
                        signing_required = (security_mode & SMB2_SIGNING_REQUIRED) != 0
                        srv.signing_required = signing_required if srv.signing_required is None else srv.signing_required
                        for cap_bit, cap_name in SMB2_CAPABILITIES.items():
                            if capabilities & cap_bit:
                                set_add_cap(srv.capabilities, cap_name, max_size=MAX_SMB_UNIQUE)
                        if not signing_required:
                            _append_capped(
                                anomalies,
                                SmbAnomaly("MEDIUM", "SMB Signing Not Required", f"Server {srv.ip} allows unsigned SMB sessions", idx, src, dst),
                                MAX_SMB_ANOMALIES,
                                "anomalies",
                                f"SMB anomalies capped at {MAX_SMB_ANOMALIES}",
                            )

            # --- Session Setup (Authentication Activity) ---
            if cmd == SMB2_COM_SESSION_SETUP:
                if not is_response:
                    mechs = _detect_auth_mechs(payload)
                    user, domain, workstation = _parse_ntlm_type3(payload)
                    if user:
                        counter_inc(observed_users, user)
                    if domain:
                        counter_inc(observed_domains, domain)
                    auth_details = {
                        "user": user,
                        "domain": domain,
                        "workstation": workstation,
                        "mechs": sorted(mechs),
                    }
                    if user or domain or mechs:
                        pending_auth[(client, server, int(msg_id))] = auth_details
                        if sess is None and session_id != 0:
                            if len(sessions) >= MAX_SMB_SESSIONS:
                                _cap_warn("sessions", f"SMB sessions capped at {MAX_SMB_SESSIONS}")
                                sess = None
                            else:
                                sess = SmbSession(client_ip=client, server_ip=server, session_id=int(session_id))
                                sessions[session_key] = sess
                        if sess:
                            _apply_auth_details(sess, auth_details)
                            if user or domain:
                                _set_auth_type(sess, "NTLM")
                else:
                    if session_id != 0:
                        if sess is None:
                            if len(sessions) >= MAX_SMB_SESSIONS:
                                _cap_warn("sessions", f"SMB sessions capped at {MAX_SMB_SESSIONS}")
                                sess = None
                            else:
                                sess = SmbSession(client_ip=client, server_ip=server, session_id=int(session_id))
                                sessions[session_key] = sess
                        if sess:
                            pending = pending_auth.pop((client, server, int(msg_id)), None)
                            if pending:
                                _apply_auth_details(sess, pending)
                                if pending.get("user") or pending.get("domain"):
                                    _set_auth_type(sess, "NTLM")
                    if len(data) >= 8 and sess:
                        session_flags = struct.unpack("<H", data[2:4])[0]
                        if session_flags & SMB2_SESSION_FLAG_ENCRYPT_DATA:
                            sess.encryption_required = True

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
                        share_path = decode_payload(data[real_off:real_off+path_len], encoding="utf-16le")

                        share_key = f"{server}|{share_path}"
                        if share_key not in shares:
                            if len(shares) >= MAX_SMB_SHARES:
                                _cap_warn("shares", f"SMB shares capped at {MAX_SMB_SHARES}")
                                share_key = ""
                            else:
                                is_admin = "IPC$" in share_path or "ADMIN$" in share_path or "C$" in share_path
                                shares[share_key] = SmbShare(share_path, server, is_admin=is_admin)
                                set_add_cap(_get_server(server).shares, share_path, max_size=MAX_SMB_UNIQUE)
                        if share_key and share_key in shares:
                            shares[share_key].connect_count += 1

                        if share_key and shares[share_key].is_admin:
                            _append_capped(
                                anomalies,
                                SmbAnomaly("HIGH", "Admin Share Access", f"Administrative share {share_path} accessed", idx, src, dst),
                                MAX_SMB_ANOMALIES,
                                "anomalies",
                                f"SMB anomalies capped at {MAX_SMB_ANOMALIES}",
                            )
                            counter_inc(client_admin_shares, client)

                        setdict_add(client_to_servers, client, server, max_keys=MAX_SMB_UNIQUE, max_values=MAX_SMB_UNIQUE)

                        if tree_id != 0:
                            tree_key = (client, server, int(session_id), int(tree_id))
                            if len(tree_map) < MAX_SMB_TREE_MAP or tree_key in tree_map:
                                tree_map[tree_key] = share_path
                            else:
                                _cap_warn("tree_map", f"SMB tree map capped at {MAX_SMB_TREE_MAP}")

            # --- Create (File Access) ---
            if cmd == SMB2_COM_CREATE and not is_response:
                if len(data) >= 56:
                    name_offset = struct.unpack("<H", data[48:50])[0]
                    name_length = struct.unpack("<H", data[50:52])[0]
                    real_off = name_offset - 64
                    if name_length > 0 and real_off >= 0 and real_off + name_length <= len(data):
                        filename = decode_payload(data[real_off:real_off + name_length], encoding="utf-16le")
                        share = tree_map.get((client, server, int(session_id), int(tree_id)))
                        if not share:
                            unc_share, unc_name = _split_unc_share(filename)
                            if unc_share:
                                share = unc_share
                                filename = unc_name or filename
                        _append_capped(
                            files,
                            SmbFileOp(filename=filename, action="Create", path=filename, ts=ts or 0.0, client_ip=client, server_ip=server, share=share),
                            MAX_SMB_FILES,
                            "files",
                            f"SMB file events capped at {MAX_SMB_FILES}",
                        )
                        suspicious_ext = {".exe", ".dll", ".ps1", ".bat", ".vbs", ".js", ".scr", ".sys", ".lnk", ".zip", ".rar", ".7z"}
                        lower_name = filename.lower()
                        for ext in suspicious_ext:
                            if lower_name.endswith(ext):
                                _append_capped(
                                    anomalies,
                                    SmbAnomaly("MEDIUM", "Suspicious File Created", f"{filename} created over SMB", idx, src, dst),
                                    MAX_SMB_ANOMALIES,
                                    "anomalies",
                                    f"SMB anomalies capped at {MAX_SMB_ANOMALIES}",
                                )
                                break
                        if len(pending_creates) < MAX_SMB_PENDING or (client, server, int(session_id), int(msg_id)) in pending_creates:
                            pending_creates[(client, server, int(session_id), int(msg_id))] = {"filename": filename, "tree_id": int(tree_id), "share": share}
                        else:
                            _cap_warn("pending_creates", f"SMB pending creates capped at {MAX_SMB_PENDING}")

            if cmd == SMB2_COM_CREATE and is_response:
                if len(data) >= 80:
                    file_id = data[64:80]
                    pending = pending_creates.pop((client, server, int(session_id), int(msg_id)), None)
                    if pending:
                        file_id_hex = file_id.hex()
                        share = pending.get("share")
                        filename = str(pending.get("filename", ""))
                        if not share:
                            unc_share, unc_name = _split_unc_share(filename)
                            if unc_share:
                                share = unc_share
                                filename = unc_name or filename
                        if len(file_id_map) < MAX_SMB_FILE_IDS or (client, server, int(session_id), file_id_hex) in file_id_map:
                            file_id_map[(client, server, int(session_id), file_id_hex)] = filename
                        else:
                            _cap_warn("file_ids", f"SMB file id map capped at {MAX_SMB_FILE_IDS}")
                        if filename and share:
                            if len(artifacts) < MAX_SMB_ARTIFACTS or f"{share}{filename}" in artifacts:
                                artifacts.add(f"{share}{filename}")
                            else:
                                _cap_warn("artifacts", f"SMB artifacts capped at {MAX_SMB_ARTIFACTS}")

            if cmd in (SMB2_COM_READ, SMB2_COM_WRITE) and not is_response:
                if len(data) >= 32:
                    length_bytes = struct.unpack("<I", data[4:8])[0]
                    file_id = data[16:32]
                    file_id_hex = file_id.hex()
                    filename = file_id_map.get((client, server, int(session_id), file_id_hex))
                    share = tree_map.get((client, server, int(session_id), int(tree_id)))
                    if filename and not share:
                        unc_share, unc_name = _split_unc_share(filename)
                        if unc_share:
                            share = unc_share
                            filename = unc_name or filename
                    action = "Read" if cmd == SMB2_COM_READ else "Write"
                    op_index = None
                    if len(files) < MAX_SMB_FILES:
                        files.append(
                            SmbFileOp(
                                filename=filename or "(unknown)",
                                action=action,
                                path=filename or "(unknown)",
                                size=length_bytes,
                                ts=ts or 0.0,
                                client_ip=client,
                                server_ip=server,
                                share=share,
                                file_id=file_id_hex,
                            )
                        )
                        op_index = len(files) - 1
                    else:
                        _cap_warn("files", f"SMB file events capped at {MAX_SMB_FILES}")

                    if op_index is not None:
                        pending_io[(client, server, int(session_id), int(msg_id), int(cmd))] = {
                            "index": op_index,
                        }

            if cmd in (SMB2_COM_READ, SMB2_COM_WRITE) and is_response:
                if len(data) >= 8:
                    resp_len = 0
                    if cmd == SMB2_COM_READ:
                        resp_len = struct.unpack("<I", data[4:8])[0]
                    else:
                        resp_len = struct.unpack("<I", data[4:8])[0]
                    pending = pending_io.pop((client, server, int(session_id), int(msg_id), int(cmd)), None)
                    if pending and resp_len:
                        idx = pending.get("index")
                        if isinstance(idx, int) and 0 <= idx < len(files):
                            files[idx].size = resp_len

        except Exception:
            pass

    def _pick_smb1_filename(strings: Set[str]) -> Optional[str]:
        candidates: List[str] = []
        for text in strings:
            if text.startswith("\\\\"):
                continue
            if "\\" in text or "." in text:
                candidates.append(text)
        if not candidates:
            return None
        return max(candidates, key=len)

    def _parse_smb1_header(payload: bytes, src: str, dst: str, src_port: int, dst_port: int, idx: int, ts: Optional[float], length: int):
        nonlocal signed_packets, unsigned_packets
        # SMB1 Header is 32 bytes
        if len(payload) < 32:
            return

        # Command is at offset 4
        cmd = payload[4]

        cmd_name = f"0x{cmd:02X}"
        if cmd == SMB1_COM_NEGOTIATE:
            cmd_name = "Negotiate"
        elif cmd == SMB1_COM_SESSION_SETUP_ANDX:
            cmd_name = "Session Setup"
        elif cmd == SMB1_COM_TREE_CONNECT_ANDX:
            cmd_name = "Tree Connect"
        elif cmd == SMB1_COM_NT_CREATE_ANDX:
            cmd_name = "NT Create"
        elif cmd == SMB1_COM_OPEN_ANDX:
            cmd_name = "Open"
        elif cmd == SMB1_COM_READ_ANDX:
            cmd_name = "Read"
        elif cmd == SMB1_COM_WRITE_ANDX:
            cmd_name = "Write"

        full_cmd = f"SMB1:{cmd_name}"
        counter_inc(commands, full_cmd)

        flags = payload[13]
        flags2 = struct.unpack("<H", payload[14:16])[0]
        status = struct.unpack("<I", payload[9:13])[0]
        tid = struct.unpack("<H", payload[24:26])[0]
        uid = struct.unpack("<H", payload[28:30])[0]
        mid = struct.unpack("<H", payload[30:32])[0]

        is_response = (flags & SMB1_FLAGS_RESPONSE) != 0
        client = dst if is_response else src
        server = src if is_response else dst
        server_port = src_port if is_response else dst_port

        if isinstance(server_port, int):
            counter_inc(smb_ports, int(server_port))

        if is_response:
            counter_inc(responses, full_cmd)
        else:
            counter_inc(requests, full_cmd)

        status_text = None
        if is_response:
            status_text = NT_STATUS_MAP.get(status, f"0x{status:08X}")
            counter_inc(error_codes, status_text)

        _track_conversation(client, server, length, ts, not is_response, full_cmd, status_text)

        signed = (flags2 & SMB1_FLAGS2_SIGNED) != 0
        if signed:
            signed_packets += 1
        else:
            unsigned_packets += 1

        if cmd == SMB1_COM_NEGOTIATE and not is_response and len(payload) > 36:
            dialects = []
            data = payload[32:]
            if len(data) >= 3:
                byte_count = struct.unpack("<H", data[1:3])[0]
                dialect_blob = data[3:3 + byte_count]
                parts = dialect_blob.split(b"\x00")
                for part in parts:
                    if part.startswith(b"\x02"):
                        name = decode_payload(part[1:], encoding="latin-1")
                        if name:
                            dialects.append(name)
            if dialects:
                cli = _get_client(client)
                for name in dialects:
                    set_add_cap(cli.dialects, name, max_size=MAX_SMB_UNIQUE)

        if cmd == SMB1_COM_SESSION_SETUP_ANDX:
            mechs = _detect_auth_mechs(payload)
            user, domain, workstation = _parse_ntlm_type3(payload)
            if user:
                counter_inc(observed_users, user)
            if domain:
                counter_inc(observed_domains, domain)
            if not is_response:
                if user or domain or mechs:
                    smb1_pending_auth[(client, server, mid)] = {
                        "user": user,
                        "domain": domain,
                        "workstation": workstation,
                        "mechs": sorted(mechs),
                    }
            else:
                pending = smb1_pending_auth.pop((client, server, mid), None)
                if pending and uid != 0:
                    session_key = (client, server, int(uid))
                    sess = sessions.get(session_key)
                    if sess is None:
                        if len(sessions) >= MAX_SMB_SESSIONS:
                            _cap_warn("sessions", f"SMB sessions capped at {MAX_SMB_SESSIONS}")
                            sess = None
                        else:
                            sess = SmbSession(client_ip=client, server_ip=server, session_id=int(uid))
                            sessions[session_key] = sess
                    if sess:
                        sess.smb_version = "SMB1"
                        if pending.get("user"):
                            sess.username = pending.get("user")
                        if pending.get("domain"):
                            sess.domain = pending.get("domain")
                        if pending.get("workstation"):
                            sess.workstation = pending.get("workstation")
                        for mech in pending.get("mechs", []):
                            _set_auth_type(sess, mech)
                        if signed:
                            sess.signed_packets += 1
                        else:
                            sess.unsigned_packets += 1
                        sess.packets += 1
                        sess.bytes += length
                        if ts is not None and (sess.start_ts == 0.0 or ts < sess.start_ts):
                            sess.start_ts = ts
                        if ts is not None and ts > sess.last_seen:
                            sess.last_seen = ts
                        sess.active = True

        if cmd == SMB1_COM_TREE_CONNECT_ANDX and not is_response:
            strings = _extract_strings(payload)
            for text in strings:
                if text.startswith("\\\\") and "\\" in text[2:]:
                    share_path = text
                    share_key = f"{server}|{share_path}"
                    if share_key not in shares:
                        if len(shares) >= MAX_SMB_SHARES:
                            _cap_warn("shares", f"SMB shares capped at {MAX_SMB_SHARES}")
                            share_key = ""
                        else:
                            is_admin = "IPC$" in share_path or "ADMIN$" in share_path or "C$" in share_path
                            shares[share_key] = SmbShare(share_path, server, is_admin=is_admin)
                            set_add_cap(_get_server(server).shares, share_path, max_size=MAX_SMB_UNIQUE)
                    if share_key and share_key in shares:
                        shares[share_key].connect_count += 1
                        if shares[share_key].is_admin:
                            _append_capped(
                                anomalies,
                                SmbAnomaly("HIGH", "Admin Share Access", f"Administrative share {share_path} accessed", idx, src, dst),
                                MAX_SMB_ANOMALIES,
                                "anomalies",
                                f"SMB anomalies capped at {MAX_SMB_ANOMALIES}",
                            )
                            counter_inc(client_admin_shares, client)
                    setdict_add(client_to_servers, client, server, max_keys=MAX_SMB_UNIQUE, max_values=MAX_SMB_UNIQUE)
                    if tid != 0:
                        smb1_tree_map[(client, server, int(tid))] = share_path

        if cmd in (SMB1_COM_NT_CREATE_ANDX, SMB1_COM_OPEN_ANDX) and not is_response:
            strings = _extract_strings(payload)
            filename = _pick_smb1_filename(strings)
            share = smb1_tree_map.get((client, server, int(tid)))
            if filename and not share:
                unc_share, unc_name = _split_unc_share(filename)
                if unc_share:
                    share = unc_share
                    filename = unc_name or filename
            if filename:
                action = "Create" if cmd == SMB1_COM_NT_CREATE_ANDX else "Open"
                _append_capped(
                    files,
                    SmbFileOp(filename=filename, action=action, path=filename, ts=ts or 0.0, client_ip=client, server_ip=server, share=share),
                    MAX_SMB_FILES,
                    "files",
                    f"SMB file events capped at {MAX_SMB_FILES}",
                )

        if cmd in (SMB1_COM_READ_ANDX, SMB1_COM_WRITE_ANDX) and not is_response:
            length_bytes = 0
            try:
                word_count = payload[32]
                param_len = int(word_count) * 2
                if cmd == SMB1_COM_READ_ANDX and word_count >= 12 and len(payload) >= 49:
                    max_count_low = struct.unpack("<H", payload[43:45])[0]
                    max_count_high = struct.unpack("<H", payload[47:49])[0]
                    length_bytes = max_count_low + (max_count_high << 16)
                elif cmd == SMB1_COM_WRITE_ANDX and word_count >= 12 and len(payload) >= 45:
                    length_bytes = struct.unpack("<H", payload[43:45])[0]
                if length_bytes == 0:
                    byte_count_offset = 33 + param_len
                    if len(payload) >= byte_count_offset + 2:
                        length_bytes = struct.unpack("<H", payload[byte_count_offset:byte_count_offset + 2])[0]
            except Exception:
                length_bytes = 0
            share = smb1_tree_map.get((client, server, int(tid)))
            filename = None
            strings = _extract_strings(payload)
            filename = _pick_smb1_filename(strings)
            if filename and not share:
                unc_share, unc_name = _split_unc_share(filename)
                if unc_share:
                    share = unc_share
                    filename = unc_name or filename
            action = "Read" if cmd == SMB1_COM_READ_ANDX else "Write"
            _append_capped(
                files,
                SmbFileOp(filename=filename or "(unknown)", action=action, path=filename or "(unknown)", size=length_bytes, ts=ts or 0.0, client_ip=client, server_ip=server, share=share),
                MAX_SMB_FILES,
                "files",
                f"SMB file events capped at {MAX_SMB_FILES}",
            )

    def _looks_like_smb(payload: bytes) -> bool:
        if not payload:
            return False
        if payload.startswith((SMB2_MAGIC, SMB1_MAGIC, SMB3_TRANSFORM_MAGIC)):
            return True
        if len(payload) >= 8 and payload[0] == 0x00 and payload[4:8] in (SMB2_MAGIC, SMB1_MAGIC, SMB3_TRANSFORM_MAGIC):
            return True
        for magic in (SMB2_MAGIC, SMB1_MAGIC, SMB3_TRANSFORM_MAGIC):
            if payload.find(magic, 0, 12) != -1:
                return True
        return False

    def _resolve_packet_roles(records: List[bytes], src: str, dst: str, src_port: int, dst_port: int) -> Tuple[str, str]:
        for record in records:
            if record.startswith(SMB2_MAGIC) and len(record) >= 20:
                try:
                    flags = struct.unpack("<I", record[16:20])[0]
                    is_response = (flags & 0x00000001) != 0
                    return (dst, src) if is_response else (src, dst)
                except Exception:
                    pass
            if record.startswith(SMB1_MAGIC) and len(record) >= 14:
                try:
                    is_response = (record[13] & SMB1_FLAGS_RESPONSE) != 0
                    return (dst, src) if is_response else (src, dst)
                except Exception:
                    pass
            if record.startswith(SMB3_TRANSFORM_MAGIC):
                session_id = _parse_smb3_transform_session_id(record)
                if session_id and session_id in session_id_map:
                    return session_id_map[session_id]
        if dst_port in (445, 139):
            return src, dst
        if src_port in (445, 139):
            return dst, src
        return src, dst

    def _update_host_stats(client: str, server: str, length: int, ts: Optional[float]) -> None:
        counter_inc(top_clients, client)
        counter_inc(top_servers, server)
        cli = _get_client(client)
        srv = _get_server(server)
        cli.packets += 1
        cli.bytes += length
        srv.packets += 1
        srv.bytes += length
        _update_time(cli, ts)
        _update_time(srv, ts)

    def _handle_smb3_transform(payload: bytes, src: str, dst: str, src_port: int, dst_port: int, idx: int, ts: Optional[float], length: int, packet_client: str, packet_server: str) -> None:
        nonlocal encrypted_packets
        encrypted_packets += 1
        session_id = _parse_smb3_transform_session_id(payload)
        client = packet_client
        server = packet_server
        if session_id and session_id in session_id_map:
            client, server = session_id_map[session_id]
        server_port = src_port if server == src else dst_port
        if isinstance(server_port, int):
            counter_inc(smb_ports, int(server_port))
        full_cmd = "SMB3:Encrypted"
        counter_inc(commands, full_cmd)
        is_request = src == client
        if is_request:
            counter_inc(requests, full_cmd)
        else:
            counter_inc(responses, full_cmd)
        _track_conversation(client, server, length, ts, is_request, full_cmd, None)
        if session_id:
            session_key = (client, server, int(session_id))
            sess = sessions.get(session_key)
            if sess is None:
                if len(sessions) >= MAX_SMB_SESSIONS:
                    _cap_warn("sessions", f"SMB sessions capped at {MAX_SMB_SESSIONS}")
                    sess = None
                else:
                    sess = SmbSession(client_ip=client, server_ip=server, session_id=int(session_id))
                    sessions[session_key] = sess
            if sess:
                sess.encrypted = True
                sess.smb_version = "SMB3"
                sess.packets += 1
                sess.bytes += length
                if ts is not None and (sess.start_ts == 0.0 or ts < sess.start_ts):
                    sess.start_ts = ts
                if ts is not None and ts > sess.last_seen:
                    sess.last_seen = ts
                sess.active = True

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
            if TCP not in pkt:
                continue
            payload = b""
            if Raw in pkt:
                payload = bytes(pkt[Raw])
            else:
                try:
                    payload = bytes(pkt[TCP].payload)
                except Exception:
                    payload = b""
            if not payload:
                continue
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            standard_port = src_port in (445, 139) or dst_port in (445, 139)
            if not standard_port and not _looks_like_smb(payload):
                continue
            smb_packets += 1
            ts = safe_float(getattr(pkt, "time", None))
            length = len(payload)

            src, dst = _get_ip_pair(pkt)

            smb_records = _iter_smb_records(payload)
            if not smb_records:
                if standard_port:
                    smb_records = [payload]
                else:
                    continue

            packet_client, packet_server = _resolve_packet_roles(smb_records, src, dst, src_port, dst_port)
            _update_host_stats(packet_client, packet_server, length, ts)
            cli = _get_client(packet_client)

            for smb_data in smb_records:
                if smb_data.startswith(SMB3_TRANSFORM_MAGIC):
                    counter_inc(versions, "SMB3")
                    _handle_smb3_transform(smb_data, src, dst, src_port, dst_port, total_packets, ts, length, packet_client, packet_server)
                    continue

                if smb_data.startswith(SMB2_MAGIC):
                    counter_inc(versions, "SMB2/3")
                    for cmd_payload in _iter_smb2_commands(smb_data):
                        _parse_smb2_header(cmd_payload, src, dst, src_port, dst_port, total_packets, ts, length)

                elif smb_data.startswith(SMB1_MAGIC):
                    counter_inc(versions, "SMB1")
                    if versions.get("SMB1", 0) == 1:
                        _append_capped(
                            anomalies,
                            SmbAnomaly("CRITICAL", "SMBv1 Detected", "Legacy, insecure SMBv1 protocol in use.", total_packets, packet_client, packet_server),
                            MAX_SMB_ANOMALIES,
                            "anomalies",
                            f"SMB anomalies capped at {MAX_SMB_ANOMALIES}",
                        )
                    if src_port == 139 or dst_port == 139:
                        _append_capped(
                            anomalies,
                            SmbAnomaly("LOW", "SMB over NetBIOS", "SMB traffic over port 139 observed.", total_packets, packet_client, packet_server),
                            MAX_SMB_ANOMALIES,
                            "anomalies",
                            f"SMB anomalies capped at {MAX_SMB_ANOMALIES}",
                        )
                    _parse_smb1_header(smb_data, src, dst, src_port, dst_port, total_packets, ts, length)

                if not smb_data.startswith((SMB2_MAGIC, SMB1_MAGIC)):
                    continue

                # Artifacts and user strings (skip encrypted SMB3 transform)
                strings = _extract_strings(smb_data)
                for text in strings:
                    if "\\PIPE\\" in text.upper():
                        if len(artifacts) < MAX_SMB_ARTIFACTS or text in artifacts:
                            artifacts.add(text)
                        else:
                            _cap_warn("artifacts", f"SMB artifacts capped at {MAX_SMB_ARTIFACTS}")
                users, domains = _extract_users_from_strings(strings)
                refined_workstations, workstation_candidates = _extract_workstations_from_strings(strings)
                for user in users:
                    counter_inc(observed_users, user)
                    set_add_cap(cli.usernames, user, max_size=MAX_SMB_UNIQUE)
                    if user.lower() in {"guest", "anonymous", "anonymous logon"}:
                        _append_capped(
                            anomalies,
                            SmbAnomaly("MEDIUM", "Guest/Anonymous SMB User", f"Guest/anonymous user {user} observed", total_packets, packet_client, packet_server),
                            MAX_SMB_ANOMALIES,
                            "anomalies",
                            f"SMB anomalies capped at {MAX_SMB_ANOMALIES}",
                        )
                for domain in domains:
                    counter_inc(observed_domains, domain)
                    set_add_cap(cli.domains, domain, max_size=MAX_SMB_UNIQUE)
                for workstation in refined_workstations:
                    set_add_cap(cli.workstations, workstation, max_size=MAX_SMB_UNIQUE)
                for workstation in workstation_candidates:
                    set_add_cap(cli.workstation_candidates, workstation, max_size=MAX_SMB_UNIQUE)

    except Exception as e:
        errors.append(str(e))
    finally:
        status.finish()
        reader.close()

    lateral_movement: List[Dict[str, object]] = []
    for client, server_set in client_to_servers.items():
        server_count = len(server_set)
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

    if encrypted_packets:
        analysis_notes.append(
            f"SMB3 encrypted transform headers observed ({encrypted_packets} packets); command/file/user parsing is limited for encrypted traffic."
        )
    non_standard_ports = [port for port in smb_ports if port not in (445, 139)]
    if non_standard_ports:
        ports_text = ", ".join(str(port) for port in sorted(non_standard_ports)[:8])
        analysis_notes.append(f"SMB traffic observed on non-standard ports: {ports_text}.")

    server_values = list(servers.values()) if isinstance(servers, dict) else list(servers)
    return SmbSummary(
        path=path,
        total_packets=total_packets,
        smb_packets=smb_packets,
        smb_ports=smb_ports,
        versions=versions,
        commands=commands,
        requests=requests,
        responses=responses,
        error_codes=error_codes,
        signed_packets=signed_packets,
        unsigned_packets=unsigned_packets,
        encrypted_packets=encrypted_packets,
        sessions=list(sessions.values()),
        conversations=list(conversations.values()),
        servers=server_values,
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
        analysis_notes=analysis_notes,
        errors=errors
    )
