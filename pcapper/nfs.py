from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import struct

try:
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.packet import Raw, Packet
    from scapy.utils import PcapReader, PcapNgReader
except Exception:  # pragma: no cover
    IP = TCP = UDP = Raw = None  # type: ignore

from .pcap_cache import get_reader
from .utils import detect_file_type, safe_float, decode_payload, counter_inc, set_add_cap


RPC_CALL = 0
RPC_REPLY = 1
RPC_MSG_ACCEPTED = 0
RPC_SUCCESS = 0

NFS_PROGRAM = 100003
NFS_PORT = 2049

NFS_V3_PROC = {
    0: "NULL",
    1: "GETATTR",
    2: "SETATTR",
    3: "LOOKUP",
    4: "ACCESS",
    5: "READLINK",
    6: "READ",
    7: "WRITE",
    8: "CREATE",
    9: "MKDIR",
    10: "SYMLINK",
    11: "MKNOD",
    12: "REMOVE",
    13: "RMDIR",
    14: "RENAME",
    15: "LINK",
    16: "READDIR",
    17: "READDIRPLUS",
    18: "FSSTAT",
    19: "FSINFO",
    20: "PATHCONF",
    21: "COMMIT",
}

NFS_V4_PROC = {
    0: "NULL",
    1: "COMPOUND",
}

NFS_STATUS = {
    0: "OK",
    1: "PERM",
    2: "NOENT",
    5: "IO",
    6: "NXIO",
    13: "ACCES",
    17: "EXIST",
    18: "XDEV",
    19: "NODEV",
    20: "NOTDIR",
    21: "ISDIR",
    22: "INVAL",
    27: "FBIG",
    28: "NOSPC",
    30: "ROFS",
    31: "MLINK",
    63: "NAMETOOLONG",
    70: "STALE",
    10001: "BADHANDLE",
    10003: "BAD_COOKIE",
    10004: "NOTSUPP",
    10005: "TOOSMALL",
    10006: "SERVERFAULT",
}

AUTH_NULL = 0
AUTH_UNIX = 1


@dataclass
class NfsConversation:
    client_ip: str
    server_ip: str
    packets: int = 0
    bytes: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    requests: int = 0
    responses: int = 0
    procedures: Counter[str] = field(default_factory=Counter)
    statuses: Counter[str] = field(default_factory=Counter)


@dataclass
class NfsServer:
    ip: str
    versions: Set[str] = field(default_factory=set)
    packets: int = 0
    bytes: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None


@dataclass
class NfsClient:
    ip: str
    versions: Set[str] = field(default_factory=set)
    uids: Set[int] = field(default_factory=set)
    gids: Set[int] = field(default_factory=set)
    usernames: Set[str] = field(default_factory=set)
    packets: int = 0
    bytes: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None


@dataclass
class NfsSession:
    client_ip: str
    server_ip: str
    xid: int
    start_ts: Optional[float]
    end_ts: Optional[float]
    procedure: Optional[str]
    status: Optional[str]


@dataclass
class NfsFileOp:
    action: str
    name: str
    client_ip: str
    server_ip: str
    ts: Optional[float]


@dataclass
class NfsAnomaly:
    severity: str
    title: str
    description: str
    packet_index: int
    src: str
    dst: str


@dataclass
class NfsSummary:
    path: Path
    total_packets: int
    nfs_packets: int
    versions: Counter[str]
    procedures: Counter[str]
    requests: Counter[str]
    responses: Counter[str]
    status_codes: Counter[str]
    conversations: List[NfsConversation]
    servers: List[NfsServer]
    clients: List[NfsClient]
    sessions: List[NfsSession]
    files: List[NfsFileOp]
    artifacts: List[str]
    observed_users: Counter[str]
    anomalies: List[NfsAnomaly]
    top_clients: Counter[str]
    top_servers: Counter[str]
    errors: List[str]


def _update_time(obj, ts: Optional[float]) -> None:
    if ts is None:
        return
    if obj.first_seen is None or ts < obj.first_seen:
        obj.first_seen = ts
    if obj.last_seen is None or ts > obj.last_seen:
        obj.last_seen = ts


def _get_ip_pair(pkt: Packet) -> Tuple[str, str]:
    if IP is not None and IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 is not None and IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    return "0.0.0.0", "0.0.0.0"


def _extract_strings(data: bytes, min_len: int = 4) -> Set[str]:
    results: Set[str] = set()
    current = bytearray()
    for b in data:
        if 32 <= b <= 126:
            current.append(b)
        else:
            if len(current) >= min_len:
                results.add(decode_payload(current, encoding="latin-1"))
            current = bytearray()
    if len(current) >= min_len:
        results.add(decode_payload(current, encoding="latin-1"))
    return results


def _strip_record_marker(payload: bytes) -> bytes:
    if len(payload) < 4:
        return payload
    marker = int.from_bytes(payload[:4], "big")
    length = marker & 0x7FFFFFFF
    if length <= len(payload) - 4:
        return payload[4:4 + length]
    return payload


def _rpc_align(length: int) -> int:
    return (length + 3) & ~3


def _parse_auth_unix(blob: bytes) -> Tuple[Optional[str], Optional[int], Optional[int]]:
    if len(blob) < 8:
        return None, None, None
    try:
        stamp = struct.unpack(">I", blob[0:4])[0]
        _ = stamp
        name_len = struct.unpack(">I", blob[4:8])[0]
        offset = 8
        name = None
        if name_len > 0 and offset + name_len <= len(blob):
            name = decode_payload(blob[offset:offset + name_len], encoding="latin-1")
        offset = _rpc_align(offset + name_len)
        if offset + 8 <= len(blob):
            uid = struct.unpack(">I", blob[offset:offset + 4])[0]
            gid = struct.unpack(">I", blob[offset + 4:offset + 8])[0]
            return name, uid, gid
    except Exception:
        pass
    return None, None, None


def analyze_nfs(path: Path, show_status: bool = True) -> NfsSummary:
    if TCP is None:
        return NfsSummary(
            path,
            0,
            0,
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            [],
            [],
            [],
            [],
            [],
            [],
            Counter(),
            [],
            Counter(),
            Counter(),
            ["Scapy not available"],
        )

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path, show_status=show_status
        )
    except Exception as exc:
        return NfsSummary(
            path,
            0,
            0,
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            [],
            [],
            [],
            [],
            [],
            [],
            Counter(),
            [],
            Counter(),
            Counter(),
            [f"Error opening pcap: {e}"],
        )

    size_bytes = size_bytes

    total_packets = 0
    nfs_packets = 0

    versions = Counter()
    procedures = Counter()
    requests = Counter()
    responses = Counter()
    status_codes = Counter()

    conversations: Dict[Tuple[str, str], NfsConversation] = {}
    servers: Dict[str, NfsServer] = {}
    clients: Dict[str, NfsClient] = {}
    sessions: Dict[int, NfsSession] = {}
    files: List[NfsFileOp] = []
    artifacts: Set[str] = set()
    observed_users: Counter[str] = Counter()
    anomalies: List[NfsAnomaly] = []
    top_clients = Counter()
    top_servers = Counter()
    errors: List[str] = []

    def _get_convo(client: str, server: str) -> NfsConversation:
        key = (client, server)
        convo = conversations.get(key)
        if convo is None:
            convo = NfsConversation(client_ip=client, server_ip=server)
            conversations[key] = convo
        return convo

    def _get_server(ip: str) -> NfsServer:
        srv = servers.get(ip)
        if srv is None:
            srv = NfsServer(ip=ip)
            servers[ip] = srv
        return srv

    def _get_client(ip: str) -> NfsClient:
        cli = clients.get(ip)
        if cli is None:
            cli = NfsClient(ip=ip)
            clients[ip] = cli
        return cli

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
            if TCP in pkt or UDP in pkt:
                sport = getattr(pkt[TCP], "sport", None) if TCP in pkt else getattr(pkt[UDP], "sport", None)
                dport = getattr(pkt[TCP], "dport", None) if TCP in pkt else getattr(pkt[UDP], "dport", None)
                if sport != NFS_PORT and dport != NFS_PORT:
                    continue
                payload = b""
                if Raw in pkt:
                    payload = bytes(pkt[Raw])
                else:
                    try:
                        payload = bytes(pkt[TCP].payload) if TCP in pkt else bytes(pkt[UDP].payload)
                    except Exception:
                        payload = b""
                if not payload:
                    continue

                nfs_packets += 1
                ts = safe_float(getattr(pkt, "time", None))
                src, dst = _get_ip_pair(pkt)
                is_request = dport == NFS_PORT
                client = src if is_request else dst
                server = dst if is_request else src
                length = len(payload)

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

                convo = _get_convo(client, server)
                convo.packets += 1
                convo.bytes += length
                _update_time(convo, ts)

                rpc_payload = _strip_record_marker(payload)
                if len(rpc_payload) < 8:
                    continue

                xid = struct.unpack(">I", rpc_payload[0:4])[0]
                msg_type = struct.unpack(">I", rpc_payload[4:8])[0]

                if msg_type == RPC_CALL and len(rpc_payload) >= 40:
                    rpcvers = struct.unpack(">I", rpc_payload[8:12])[0]
                    prog = struct.unpack(">I", rpc_payload[12:16])[0]
                    vers = struct.unpack(">I", rpc_payload[16:20])[0]
                    proc = struct.unpack(">I", rpc_payload[20:24])[0]

                    if prog != NFS_PROGRAM or rpcvers != 2:
                        continue

                    if vers == 3:
                        proc_name = NFS_V3_PROC.get(proc, f"PROC_{proc}")
                        counter_inc(versions, "NFSv3")
                        set_add_cap(cli.versions, "NFSv3")
                        set_add_cap(srv.versions, "NFSv3")
                    elif vers == 4:
                        proc_name = NFS_V4_PROC.get(proc, f"PROC_{proc}")
                        counter_inc(versions, "NFSv4")
                        set_add_cap(cli.versions, "NFSv4")
                        set_add_cap(srv.versions, "NFSv4")
                    else:
                        proc_name = f"PROC_{proc}"
                        counter_inc(versions, f"NFSv{vers}")
                        set_add_cap(cli.versions, f"NFSv{vers}")
                        set_add_cap(srv.versions, f"NFSv{vers}")

                    counter_inc(procedures, proc_name)
                    counter_inc(requests, proc_name)
                    convo.requests += 1
                    counter_inc(convo.procedures, proc_name)

                    cred_flavor = struct.unpack(">I", rpc_payload[24:28])[0]
                    cred_len = struct.unpack(">I", rpc_payload[28:32])[0]
                    cred_blob = rpc_payload[32:32 + cred_len] if cred_len <= len(rpc_payload) else b""

                    if cred_flavor == AUTH_UNIX:
                        name, uid, gid = _parse_auth_unix(cred_blob)
                        if name:
                            set_add_cap(cli.usernames, name)
                            counter_inc(observed_users, name)
                        if uid is not None:
                            set_add_cap(cli.uids, uid)
                            if uid == 0:
                                anomalies.append(NfsAnomaly("HIGH", "NFS Root UID", f"Root UID used by {client}", total_packets, client, server))
                        if gid is not None:
                            set_add_cap(cli.gids, gid)
                    elif cred_flavor == AUTH_NULL:
                        anomalies.append(NfsAnomaly("MEDIUM", "NFS NULL Auth", f"Null authentication from {client}", total_packets, client, server))

                    sess = NfsSession(client_ip=client, server_ip=server, xid=xid, start_ts=ts, end_ts=None, procedure=proc_name, status=None)
                    sessions[xid] = sess

                    strings = _extract_strings(rpc_payload[32 + _rpc_align(cred_len):])
                    for text in strings:
                        if "/" in text or "." in text:
                            set_add_cap(artifacts, text)
                            if proc_name in {"LOOKUP", "CREATE", "REMOVE", "MKDIR", "RMDIR", "RENAME", "READ", "WRITE"}:
                                files.append(NfsFileOp(action=proc_name, name=text, client_ip=client, server_ip=server, ts=ts))

                elif msg_type == RPC_REPLY and len(rpc_payload) >= 12:
                    reply_stat = struct.unpack(">I", rpc_payload[8:12])[0]
                    if reply_stat == RPC_MSG_ACCEPTED and len(rpc_payload) >= 24:
                        verifier_flavor = struct.unpack(">I", rpc_payload[12:16])[0]
                        verifier_len = struct.unpack(">I", rpc_payload[16:20])[0]
                        offset = 20 + _rpc_align(verifier_len)
                        if offset + 4 <= len(rpc_payload):
                            accept_stat = struct.unpack(">I", rpc_payload[offset:offset + 4])[0]
                            status_text = NFS_STATUS.get(accept_stat, f"{accept_stat}")
                            counter_inc(status_codes, status_text)
                            counter_inc(responses, "REPLY")
                            convo.responses += 1
                            counter_inc(convo.statuses, status_text)

                            sess = sessions.get(xid)
                            if sess:
                                sess.end_ts = ts
                                sess.status = status_text

                            if accept_stat == 13:
                                anomalies.append(NfsAnomaly("MEDIUM", "NFS Access Denied", f"Access denied from {server}", total_packets, server, client))
                            if accept_stat == 30:
                                anomalies.append(NfsAnomaly("LOW", "NFS Read-only", f"ROFS from {server}", total_packets, server, client))

    except Exception as e:
        errors.append(str(e))
    finally:
        status.finish()
        reader.close()

    return NfsSummary(
        path=path,
        total_packets=total_packets,
        nfs_packets=nfs_packets,
        versions=versions,
        procedures=procedures,
        requests=requests,
        responses=responses,
        status_codes=status_codes,
        conversations=list(conversations.values()),
        servers=list(servers.values()),
        clients=list(clients.values()),
        sessions=list(sessions.values()),
        files=files,
        artifacts=sorted(artifacts),
        observed_users=observed_users,
        anomalies=anomalies,
        top_clients=top_clients,
        top_servers=top_servers,
        errors=errors,
    )
