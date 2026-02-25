from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Iterable
import ipaddress
import re
import struct

from .pcap_cache import get_reader
from .utils import safe_float

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.layers.l2 import Ether  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore
    Ether = None  # type: ignore


RPC_PORTS = {135, 445, 593}

RESPONSE_PDU_TYPES = {"response", "bind_ack", "bind_nak", "alter_context_resp"}

PDU_TYPE_MAP = {
    0x00: "request",
    0x02: "response",
    0x0B: "bind",
    0x0C: "bind_ack",
    0x0D: "bind_nak",
    0x0E: "alter_context",
    0x0F: "alter_context_resp",
    0x10: "auth3",
    0x11: "shutdown",
    0x12: "co_cancel",
    0x13: "orphaned",
}

RPC_INTERFACES = {
    "e1af8308-5d1f-11c9-91a4-08002b14a0fa": "EPM (Endpoint Mapper)",
    "4b324fc8-1670-01d3-1278-5a47bf6ee188": "SRVSVC (Server Service)",
    "12345778-1234-abcd-ef00-0123456789ab": "LSARPC (LSA)",
    "12345778-1234-abcd-ef00-0123456789ac": "SAMR (SAM)",
    "367abb81-9844-35f1-ad32-98f038001003": "SVCCTL (Service Control)",
    "6bffd098-a112-3610-9833-46c3f87e345a": "WKSSVC (Workstation)",
    "12345678-1234-abcd-ef00-01234567cffb": "NETLOGON",
    "1ff70682-0a51-30e8-076d-740be8cee98b": "ATSVC (AT Scheduler)",
    "338cd001-2244-31f1-aaaa-900038001003": "WINREG (Remote Registry)",
}

SAMR_UUID = "12345778-1234-abcd-ef00-0123456789ac"
# MS-SAMR: SamrQueryInformationUser (opnum 36), SamrQueryInformationUser2 (opnum 47)
SAMR_QUERY_USER_OPNUMS = {36, 47}

RPC_OPNUM_MAP: dict[str, dict[int, str]] = {
    # Basic/common mappings; keep conservative to avoid false attribution.
    # UUIDs are lower-case, without version suffix.
    "e1af8308-5d1f-11c9-91a4-08002b14a0fa": {
        3: "ept_map",
        5: "ept_map_auth",
    },
}

HOST_RE = re.compile(r"\b([A-Za-z0-9_.-]{2,64})\b")
DOMAIN_USER_RE = re.compile(r"\b([A-Za-z0-9_.-]{1,64})\\([A-Za-z0-9_.-]{1,64})\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b")
MAC_RE = re.compile(r"\b([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})\b")
UNC_SHARE_RE = re.compile(r"\\\\([A-Za-z0-9_.-]{1,64})\\\\([A-Za-z0-9.$_-]{1,64})")
PIPE_REMOTE_RE = re.compile(r"\\\\([A-Za-z0-9_.-]{1,64})\\\\pipe\\\\([A-Za-z0-9._$-]{1,64})", re.IGNORECASE)
PIPE_LOCAL_RE = re.compile(r"\\\\\\.\\\\pipe\\\\([A-Za-z0-9._$-]{1,64})", re.IGNORECASE)
PIPE_GENERIC_RE = re.compile(r"\\pipe\\([A-Za-z0-9._$-]{1,64})", re.IGNORECASE)

SAMR_FULLNAME_STOPWORDS = {
    "administrator",
    "administrators",
    "admin",
    "domain admins",
    "domain users",
    "enterprise admins",
    "authenticated users",
    "anonymous",
    "guest",
    "guests",
    "default",
    "unknown",
}
SAMR_NAME_TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z.'-]{0,40}$")

SUSPICIOUS_STRINGS = [
    (re.compile(r"powershell|cmd\.exe|wmic|winrs", re.IGNORECASE), "Command execution tooling"),
    (re.compile(r"mimikatz|cobalt|beacon|meterpreter", re.IGNORECASE), "Malware tooling"),
    (re.compile(r"rundll32|regsvr32|schtasks|at\s+", re.IGNORECASE), "Execution/persistence tooling"),
    (re.compile(r"nmap|masscan|sqlmap", re.IGNORECASE), "Recon tooling"),
]


@dataclass(frozen=True)
class RpcConversation:
    client_ip: str
    server_ip: str
    protocol: str
    server_port: int
    packets: int
    bytes: int
    first_seen: Optional[float]
    last_seen: Optional[float]


@dataclass(frozen=True)
class RpcArtifact:
    kind: str
    detail: str
    src: str
    dst: str


@dataclass(frozen=True)
class RpcSummary:
    path: Path
    total_packets: int
    rpc_packets: int
    total_bytes: int
    total_messages: int
    unique_clients: int
    unique_servers: int
    client_counts: Counter[str]
    server_counts: Counter[str]
    server_ports: Counter[int]
    protocol_counts: Counter[str]
    pdu_counts: Counter[str]
    interface_counts: Counter[str]
    command_counts: Counter[str]
    share_counts: Counter[str]
    pipe_counts: Counter[str]
    hostname_counts: Counter[str]
    domain_user_counts: Counter[str]
    ip_strings: Counter[str]
    mac_strings: Counter[str]
    plaintext_strings: Counter[str]
    samr_fullnames: list[dict[str, object]]
    conversations: list[RpcConversation]
    detections: list[dict[str, object]]
    anomalies: list[dict[str, object]]
    artifacts: list[RpcArtifact]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "total_packets": self.total_packets,
            "rpc_packets": self.rpc_packets,
            "total_bytes": self.total_bytes,
            "total_messages": self.total_messages,
            "unique_clients": self.unique_clients,
            "unique_servers": self.unique_servers,
            "client_counts": dict(self.client_counts),
            "server_counts": dict(self.server_counts),
            "server_ports": dict(self.server_ports),
            "protocol_counts": dict(self.protocol_counts),
            "pdu_counts": dict(self.pdu_counts),
            "interface_counts": dict(self.interface_counts),
            "command_counts": dict(self.command_counts),
            "share_counts": dict(self.share_counts),
            "pipe_counts": dict(self.pipe_counts),
            "hostname_counts": dict(self.hostname_counts),
            "domain_user_counts": dict(self.domain_user_counts),
            "ip_strings": dict(self.ip_strings),
            "mac_strings": dict(self.mac_strings),
            "plaintext_strings": dict(self.plaintext_strings),
            "samr_fullnames": list(self.samr_fullnames),
            "conversations": [
                {
                    "client_ip": conv.client_ip,
                    "server_ip": conv.server_ip,
                    "protocol": conv.protocol,
                    "server_port": conv.server_port,
                    "packets": conv.packets,
                    "bytes": conv.bytes,
                    "first_seen": conv.first_seen,
                    "last_seen": conv.last_seen,
                }
                for conv in self.conversations
            ],
            "detections": list(self.detections),
            "anomalies": list(self.anomalies),
            "artifacts": [
                {"kind": item.kind, "detail": item.detail, "src": item.src, "dst": item.dst}
                for item in self.artifacts
            ],
            "errors": list(self.errors),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": self.duration_seconds,
        }


def _rpc_pdu_type(payload: bytes | None) -> Optional[str]:
    if not payload or len(payload) < 16:
        return None
    if payload[0] != 0x05:
        return None
    ptype = payload[2]
    return PDU_TYPE_MAP.get(ptype, f"0x{ptype:02x}")


def _find_rpc_pdu(payload: bytes | None) -> tuple[Optional[str], int]:
    if not payload or len(payload) < 16:
        return None, 0
    direct = _rpc_pdu_type(payload)
    if direct:
        return direct, 0

    idx = payload.find(b"\x05")
    while idx != -1 and idx + 16 <= len(payload):
        minor = payload[idx + 1]
        if minor in (0x00, 0x01):
            ptype = payload[idx + 2]
            if ptype in PDU_TYPE_MAP:
                data_rep = payload[idx + 4:idx + 8]
                if data_rep in {b"\x10\x00\x00\x00", b"\x00\x00\x00\x10"}:
                    return PDU_TYPE_MAP.get(ptype, f"0x{ptype:02x}"), idx
        idx = payload.find(b"\x05", idx + 1)
    return None, 0


def _decode_uuid_le(data: bytes) -> Optional[str]:
    if len(data) < 16:
        return None
    try:
        d1, d2, d3 = struct.unpack("<IHH", data[:8])
        d4 = data[8:10]
        d5 = data[10:16]
        return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4.hex()}-{d5.hex()}"
    except Exception:
        return None


def _parse_bind_contexts(payload: bytes | None) -> list[tuple[int, str]]:
    if not payload or len(payload) < 32:
        return []
    if payload[0] != 0x05 or payload[2] != 0x0B:
        return []
    contexts: list[tuple[int, str]] = []
    try:
        idx = 16
        if idx + 10 > len(payload):
            return []
        idx += 2  # max_xmit
        idx += 2  # max_recv
        idx += 4  # assoc_group
        num_ctx = payload[idx]
        idx += 4  # num_ctx + reserved
        for _ in range(num_ctx):
            if idx + 4 > len(payload):
                break
            context_id = struct.unpack_from("<H", payload, idx)[0]
            idx += 2  # context_id
            num_trans = payload[idx]
            idx += 2  # num_trans + reserved
            if idx + 20 > len(payload):
                break
            uuid = _decode_uuid_le(payload[idx:idx + 16])
            idx += 16
            vers = struct.unpack("<HH", payload[idx:idx + 4])
            idx += 4
            if uuid:
                iface = f"{uuid} v{vers[0]}.{vers[1]}"
                contexts.append((context_id, iface))
            for _t in range(num_trans):
                if idx + 20 > len(payload):
                    break
                idx += 16 + 4
    except Exception:
        return contexts
    return contexts


def _extract_utf16le_strings(payload: bytes, limit: int = 200) -> list[str]:
    if not payload:
        return []
    out: list[str] = []
    current = bytearray()
    i = 0
    while i + 1 < len(payload):
        b1 = payload[i]
        b2 = payload[i + 1]
        if 32 <= b1 <= 126 and b2 == 0x00:
            current.append(b1)
            i += 2
            continue
        if len(current) >= 4:
            out.append(current.decode("latin-1", errors="ignore")[:limit])
        current = bytearray()
        i += 1
    if len(current) >= 4:
        out.append(current.decode("latin-1", errors="ignore")[:limit])
    return out


def _extract_strings(payload: bytes, limit: int = 200) -> list[str]:
    if not payload:
        return []
    out: list[str] = []
    seen: set[str] = set()
    current = bytearray()
    for b in payload:
        if 32 <= b <= 126:
            current.append(b)
        else:
            if len(current) >= 4:
                value = current.decode("latin-1", errors="ignore")[:limit]
                if value not in seen:
                    out.append(value)
                    seen.add(value)
            current = bytearray()
    if len(current) >= 4:
        value = current.decode("latin-1", errors="ignore")[:limit]
        if value not in seen:
            out.append(value)
            seen.add(value)

    for value in _extract_utf16le_strings(payload, limit=limit):
        if value not in seen:
            out.append(value)
            seen.add(value)
    return out


def _rpc_is_little_endian(rpc_payload: bytes) -> bool:
    if len(rpc_payload) < 8:
        return True
    data_rep = rpc_payload[4:8]
    if data_rep == b"\x10\x00\x00\x00":
        return True
    if data_rep == b"\x00\x00\x00\x10":
        return False
    return True


def _rpc_read_u16(payload: bytes, offset: int, le: bool) -> Optional[int]:
    if offset + 2 > len(payload):
        return None
    return struct.unpack_from("<H" if le else ">H", payload, offset)[0]


def _rpc_read_u32(payload: bytes, offset: int, le: bool) -> Optional[int]:
    if offset + 4 > len(payload):
        return None
    return struct.unpack_from("<I" if le else ">I", payload, offset)[0]


def _rpc_stub_data(rpc_payload: bytes, le: bool) -> bytes:
    if len(rpc_payload) < 24:
        return b""
    frag_len = _rpc_read_u16(rpc_payload, 8, le) or len(rpc_payload)
    auth_len = _rpc_read_u16(rpc_payload, 10, le) or 0
    stub_end = min(len(rpc_payload), frag_len)
    if auth_len and stub_end >= auth_len + 24:
        stub_end = max(24, stub_end - auth_len)
    return rpc_payload[24:stub_end]


def _looks_like_samr_fullname(value: str) -> bool:
    cleaned = " ".join(value.strip().split())
    if len(cleaned) < 3 or len(cleaned) > 80:
        return False
    lowered = cleaned.lower()
    if lowered in SAMR_FULLNAME_STOPWORDS:
        return False
    if "\\" in cleaned or "@" in cleaned:
        return False
    if "," in cleaned:
        parts = [part.strip() for part in cleaned.split(",") if part.strip()]
        if len(parts) >= 2 and all(SAMR_NAME_TOKEN_RE.match(part) for part in parts[:2]):
            return True
    parts = [part for part in cleaned.split() if part]
    if len(parts) < 2:
        return False
    if not all(SAMR_NAME_TOKEN_RE.match(part) for part in parts[:2]):
        return False
    return True


def _extract_samr_fullnames(payload: bytes) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for value in _extract_utf16le_strings(payload, limit=120):
        cleaned = " ".join(value.strip().split())
        if not cleaned or cleaned in seen:
            continue
        if _looks_like_samr_fullname(cleaned):
            names.append(cleaned)
            seen.add(cleaned)
    return names


def _beacon_score(times: list[float]) -> Optional[dict[str, float]]:
    if len(times) < 5:
        return None
    times_sorted = sorted(times)
    deltas = [b - a for a, b in zip(times_sorted, times_sorted[1:]) if b > a]
    if len(deltas) < 4:
        return None
    avg = sum(deltas) / len(deltas)
    if avg <= 0:
        return None
    variance = sum((d - avg) ** 2 for d in deltas) / len(deltas)
    stddev = variance ** 0.5
    if avg < 1 or avg > 3600:
        return None
    if stddev / avg > 0.15:
        return None
    return {"avg": avg, "stddev": stddev}


def analyze_rpc(path: Path, show_status: bool = True, packets: list[object] | None = None, meta: object | None = None) -> RpcSummary:
    errors: list[str] = []
    if TCP is None and UDP is None:
        errors.append("Scapy IP layers unavailable; install scapy for RPC analysis.")
        return RpcSummary(
            path=path,
            total_packets=0,
            rpc_packets=0,
            total_bytes=0,
            total_messages=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            server_ports=Counter(),
            protocol_counts=Counter(),
            pdu_counts=Counter(),
            interface_counts=Counter(),
            command_counts=Counter(),
            share_counts=Counter(),
            pipe_counts=Counter(),
            hostname_counts=Counter(),
            domain_user_counts=Counter(),
            ip_strings=Counter(),
            mac_strings=Counter(),
            plaintext_strings=Counter(),
            samr_fullnames=[],
            conversations=[],
            detections=[],
            anomalies=[],
            artifacts=[],
            errors=errors,
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, packets=packets, meta=meta, show_status=show_status
    )

    total_packets = 0
    rpc_packets = 0
    total_bytes = 0
    total_messages = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    server_ports: Counter[int] = Counter()
    protocol_counts: Counter[str] = Counter()
    pdu_counts: Counter[str] = Counter()
    interface_counts: Counter[str] = Counter()
    command_counts: Counter[str] = Counter()
    share_counts: Counter[str] = Counter()
    pipe_counts: Counter[str] = Counter()
    hostname_counts: Counter[str] = Counter()
    domain_user_counts: Counter[str] = Counter()
    ip_strings: Counter[str] = Counter()
    mac_strings: Counter[str] = Counter()
    plaintext_strings: Counter[str] = Counter()
    samr_fullnames: list[dict[str, object]] = []
    samr_seen: set[tuple[str, str, str, int, str]] = set()

    conv_map: dict[tuple[str, str, str, int], dict[str, object]] = {}
    flow_contexts: dict[tuple[str, str, str, int], dict[int, str]] = {}
    artifacts: list[RpcArtifact] = []
    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []
    pending_calls: dict[tuple[str, str, str, int, int], dict[str, object]] = {}

    dst_by_src: dict[str, set[str]] = defaultdict(set)
    request_times: dict[tuple[str, str], list[float]] = defaultdict(list)
    response_bytes: Counter[tuple[str, str]] = Counter()
    request_bytes: Counter[tuple[str, str]] = Counter()
    bind_failures: Counter[str] = Counter()

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
            pkt_len = int(len(pkt)) if hasattr(pkt, "__len__") else 0
            total_bytes += pkt_len
            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            src_ip = None
            dst_ip = None
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                ip_layer = pkt[IP]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                ip_layer = pkt[IPv6]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))

            if not src_ip or not dst_ip:
                continue

            proto = None
            sport = None
            dport = None
            payload = None

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp_layer = pkt[TCP]  # type: ignore[index]
                proto = "TCP"
                sport = int(getattr(tcp_layer, "sport", 0) or 0)
                dport = int(getattr(tcp_layer, "dport", 0) or 0)
                try:
                    payload = bytes(tcp_layer.payload)
                except Exception:
                    payload = None
            elif UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp_layer = pkt[UDP]  # type: ignore[index]
                proto = "UDP"
                sport = int(getattr(udp_layer, "sport", 0) or 0)
                dport = int(getattr(udp_layer, "dport", 0) or 0)
                try:
                    payload = bytes(udp_layer.payload)
                except Exception:
                    payload = None

            if not proto or not payload:
                continue

            pdu_type, pdu_offset = _find_rpc_pdu(payload)
            if not pdu_type and sport not in RPC_PORTS and dport not in RPC_PORTS:
                continue
            if not pdu_type:
                continue

            rpc_payload = payload[pdu_offset:] if pdu_offset < len(payload) else payload
            rpc_packets += 1
            total_messages += 1
            protocol_counts[proto] += 1
            pdu_counts[pdu_type] += 1
            le = _rpc_is_little_endian(rpc_payload)
            call_id = _rpc_read_u32(rpc_payload, 12, le) if len(rpc_payload) >= 16 else None
            is_response = pdu_type in RESPONSE_PDU_TYPES
            if is_response:
                client_ip = dst_ip
                server_ip = src_ip
                client_port = dport
                server_port = sport
            else:
                client_ip = src_ip
                server_ip = dst_ip
                client_port = sport
                server_port = dport
            server_port = int(server_port or 0)

            server_ports[server_port] += 1
            client_counts[client_ip] += 1
            server_counts[server_ip] += 1
            if not is_response:
                dst_by_src[client_ip].add(server_ip)
                if ts is not None:
                    request_times[(client_ip, server_ip)].append(ts)

            flow_key = (client_ip, server_ip)
            if is_response:
                response_bytes[flow_key] += pkt_len
            else:
                request_bytes[flow_key] += pkt_len
            if pdu_type == "bind_nak":
                bind_failures[client_ip] += 1

            conv_key = (client_ip, server_ip, proto, int(server_port))
            conv = conv_map.get(conv_key)
            if conv is None:
                conv = {"packets": 0, "bytes": 0, "first_seen": ts, "last_seen": ts}
                conv_map[conv_key] = conv
            conv["packets"] = int(conv["packets"]) + 1
            conv["bytes"] = int(conv["bytes"]) + pkt_len
            if ts is not None:
                if conv["first_seen"] is None or ts < conv["first_seen"]:
                    conv["first_seen"] = ts
                if conv["last_seen"] is None or ts > conv["last_seen"]:
                    conv["last_seen"] = ts

            if pdu_type == "bind":
                contexts = _parse_bind_contexts(rpc_payload)
                if contexts:
                    context_map = flow_contexts.setdefault(conv_key, {})
                    for context_id, iface in contexts:
                        context_map[context_id] = iface
                        uuid = iface.split(" ", 1)[0]
                        label = RPC_INTERFACES.get(uuid)
                        display = f"{label} ({iface})" if label else iface
                        interface_counts[display] += 1
                        if label:
                            artifacts.append(RpcArtifact(kind="interface", detail=f"{label} ({iface})", src=client_ip, dst=server_ip))

            if pdu_type == "request" and len(rpc_payload) >= 24:
                context_id = _rpc_read_u16(rpc_payload, 20, le) or 0
                opnum = _rpc_read_u16(rpc_payload, 22, le) or 0
                iface = flow_contexts.get(conv_key, {}).get(context_id)
                iface_uuid = iface.split(" ", 1)[0] if iface else None
                label = RPC_INTERFACES.get(iface_uuid or "", None)
                op_map = RPC_OPNUM_MAP.get(iface_uuid or "", {})
                op_name = op_map.get(opnum)
                if op_name:
                    command = f"{label or iface_uuid or 'RPC'}::{op_name}"
                elif iface:
                    command = f"{label or iface} opnum {opnum}"
                else:
                    command = f"opnum {opnum}"
                command_counts[command] += 1
                if call_id is not None and iface_uuid == SAMR_UUID and opnum in SAMR_QUERY_USER_OPNUMS:
                    key = (client_ip, server_ip, proto, int(server_port), call_id)
                    pending_calls[key] = {"opnum": opnum}
                    if len(pending_calls) > 2048:
                        pending_calls.clear()

            if pdu_type == "response" and call_id is not None:
                key = (client_ip, server_ip, proto, int(server_port), call_id)
                pending = pending_calls.pop(key, None)
                if pending and int(pending.get("opnum", -1)) in SAMR_QUERY_USER_OPNUMS:
                    stub_data = _rpc_stub_data(rpc_payload, le)
                    for full_name in _extract_samr_fullnames(stub_data):
                        samr_key = (full_name.lower(), server_ip, client_ip, int(server_port), proto)
                        if samr_key in samr_seen:
                            continue
                        samr_seen.add(samr_key)
                        samr_fullnames.append({
                            "full_name": full_name,
                            "src_ip": server_ip,
                            "dst_ip": client_ip,
                            "protocol": proto,
                            "server_port": int(server_port),
                            "opnum": int(pending.get("opnum", -1)),
                        })

            if pdu_offset > 0 and (sport == 445 or dport == 445):
                artifacts.append(RpcArtifact(
                    kind="rpc_over_smb",
                    detail=f"DCE/RPC header at offset {pdu_offset} ({pdu_type})",
                    src=client_ip,
                    dst=server_ip,
                ))

            for item in _extract_strings(payload, limit=200):
                plaintext_strings[item] += 1
                if HOST_RE.fullmatch(item) and len(item) <= 64:
                    hostname_counts[item] += 1
                for match in DOMAIN_USER_RE.findall(item):
                    domain_user_counts[f"{match[0]}\\{match[1]}"] += 1
                for match in IP_RE.findall(item):
                    ip_strings[match] += 1
                for match in IPV6_RE.findall(item):
                    try:
                        ipaddress.ip_address(match)
                    except Exception:
                        continue
                    ip_strings[match] += 1
                for match in MAC_RE.findall(item):
                    mac_strings[match] += 1
                pipe_names: set[str] = set()
                pipe_paths: set[str] = set()
                for match in UNC_SHARE_RE.finditer(item):
                    server = match.group(1)
                    share = match.group(2)
                    if share.lower() == "pipe":
                        continue
                    share_path = f"\\\\{server}\\{share}"
                    share_counts[share_path] += 1
                    artifacts.append(RpcArtifact(kind="share", detail=share_path, src=src_ip, dst=dst_ip))
                for match in PIPE_REMOTE_RE.finditer(item):
                    pipe_path = f"\\\\{match.group(1)}\\pipe\\{match.group(2)}"
                    if pipe_path not in pipe_paths:
                        pipe_counts[pipe_path] += 1
                        artifacts.append(RpcArtifact(kind="pipe", detail=pipe_path, src=src_ip, dst=dst_ip))
                        pipe_paths.add(pipe_path)
                        pipe_names.add(match.group(2).lower())
                for match in PIPE_LOCAL_RE.finditer(item):
                    pipe_path = f"\\\\.\\pipe\\{match.group(1)}"
                    if pipe_path not in pipe_paths:
                        pipe_counts[pipe_path] += 1
                        artifacts.append(RpcArtifact(kind="pipe", detail=pipe_path, src=src_ip, dst=dst_ip))
                        pipe_paths.add(pipe_path)
                        pipe_names.add(match.group(1).lower())
                for match in PIPE_GENERIC_RE.finditer(item):
                    if match.group(1).lower() in pipe_names:
                        continue
                    pipe_path = f"\\pipe\\{match.group(1)}"
                    if pipe_path not in pipe_paths:
                        pipe_counts[pipe_path] += 1
                        artifacts.append(RpcArtifact(kind="pipe", detail=pipe_path, src=src_ip, dst=dst_ip))
                        pipe_paths.add(pipe_path)
                for pattern, reason in SUSPICIOUS_STRINGS:
                    if pattern.search(item):
                        detections.append({
                            "severity": "warning",
                            "summary": f"Suspicious RPC content: {reason}",
                            "details": f"{src_ip}->{dst_ip} {item[:120]}",
                            "source": "RPC",
                        })
    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        try:
            reader.close()
        except Exception:
            pass

    for src, dsts in dst_by_src.items():
        if len(dsts) >= 20:
            detections.append({
                "severity": "warning",
                "summary": "RPC scanning/probing detected",
                "details": f"{src} contacted {len(dsts)} RPC endpoints.",
                "source": "RPC",
            })

    for src, count in bind_failures.items():
        if count >= 10:
            detections.append({
                "severity": "warning",
                "summary": "RPC bind failures spike",
                "details": f"{src} saw {count} bind_nak responses.",
                "source": "RPC",
            })

    for flow, times in request_times.items():
        score = _beacon_score(times)
        if score:
            detections.append({
                "severity": "warning",
                "summary": "RPC beaconing suspected",
                "details": f"{flow[0]}->{flow[1]} avg {score['avg']:.1f}s interval.",
                "source": "RPC",
            })

    for flow, resp_bytes in response_bytes.items():
        req_bytes = request_bytes.get(flow, 1)
        if resp_bytes > 50_000 and resp_bytes > req_bytes * 5:
            detections.append({
                "severity": "warning",
                "summary": "RPC data exfiltration suspected",
                "details": f"{flow[0]}->{flow[1]} response bytes {resp_bytes}.",
                "source": "RPC",
            })

    conversations: list[RpcConversation] = []
    for (src, dst, proto, port), data in conv_map.items():
        conversations.append(RpcConversation(
            client_ip=src,
            server_ip=dst,
            protocol=proto,
            server_port=port,
            packets=int(data["packets"]),
            bytes=int(data["bytes"]),
            first_seen=data.get("first_seen"),
            last_seen=data.get("last_seen"),
        ))
    conversations.sort(key=lambda c: c.packets, reverse=True)

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    return RpcSummary(
        path=path,
        total_packets=total_packets,
        rpc_packets=rpc_packets,
        total_bytes=total_bytes,
        total_messages=total_messages,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        server_ports=server_ports,
        protocol_counts=protocol_counts,
        pdu_counts=pdu_counts,
        interface_counts=interface_counts,
        command_counts=command_counts,
        share_counts=share_counts,
        pipe_counts=pipe_counts,
        hostname_counts=hostname_counts,
        domain_user_counts=domain_user_counts,
        ip_strings=ip_strings,
        mac_strings=mac_strings,
        plaintext_strings=plaintext_strings,
        samr_fullnames=samr_fullnames,
        conversations=conversations,
        detections=detections,
        anomalies=anomalies,
        artifacts=artifacts,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )


def merge_rpc_summaries(summaries: Iterable[RpcSummary]) -> RpcSummary:
    summary_list = list(summaries)
    if not summary_list:
        return RpcSummary(
            path=Path("ALL_PCAPS_0"),
            total_packets=0,
            rpc_packets=0,
            total_bytes=0,
            total_messages=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            server_ports=Counter(),
            protocol_counts=Counter(),
            pdu_counts=Counter(),
            interface_counts=Counter(),
            command_counts=Counter(),
            share_counts=Counter(),
            pipe_counts=Counter(),
            hostname_counts=Counter(),
            domain_user_counts=Counter(),
            ip_strings=Counter(),
            mac_strings=Counter(),
            plaintext_strings=Counter(),
            samr_fullnames=[],
            conversations=[],
            detections=[],
            anomalies=[],
            artifacts=[],
            errors=[],
            first_seen=None,
            last_seen=None,
            duration_seconds=0.0,
        )

    total_packets = 0
    rpc_packets = 0
    total_bytes = 0
    total_messages = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    duration_seconds = 0.0

    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    server_ports: Counter[int] = Counter()
    protocol_counts: Counter[str] = Counter()
    pdu_counts: Counter[str] = Counter()
    interface_counts: Counter[str] = Counter()
    command_counts: Counter[str] = Counter()
    share_counts: Counter[str] = Counter()
    pipe_counts: Counter[str] = Counter()
    hostname_counts: Counter[str] = Counter()
    domain_user_counts: Counter[str] = Counter()
    ip_strings: Counter[str] = Counter()
    mac_strings: Counter[str] = Counter()
    plaintext_strings: Counter[str] = Counter()
    samr_fullnames: list[dict[str, object]] = []
    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []
    artifacts: list[RpcArtifact] = []
    errors: list[str] = []

    conv_map: dict[tuple[str, str, str, int], dict[str, object]] = {}
    det_seen: set[tuple[str, str, str]] = set()
    err_seen: set[str] = set()

    for summary in summary_list:
        total_packets += summary.total_packets
        rpc_packets += summary.rpc_packets
        total_bytes += summary.total_bytes
        total_messages += summary.total_messages
        if summary.first_seen is not None:
            if first_seen is None or summary.first_seen < first_seen:
                first_seen = summary.first_seen
        if summary.last_seen is not None:
            if last_seen is None or summary.last_seen > last_seen:
                last_seen = summary.last_seen
        if summary.duration_seconds is not None:
            duration_seconds += summary.duration_seconds

        client_counts.update(summary.client_counts)
        server_counts.update(summary.server_counts)
        server_ports.update(summary.server_ports)
        protocol_counts.update(summary.protocol_counts)
        pdu_counts.update(summary.pdu_counts)
        interface_counts.update(summary.interface_counts)
        command_counts.update(summary.command_counts)
        share_counts.update(summary.share_counts)
        pipe_counts.update(summary.pipe_counts)
        hostname_counts.update(summary.hostname_counts)
        domain_user_counts.update(summary.domain_user_counts)
        ip_strings.update(summary.ip_strings)
        mac_strings.update(summary.mac_strings)
        plaintext_strings.update(summary.plaintext_strings)
        samr_fullnames.extend(getattr(summary, "samr_fullnames", []) or [])

        for item in summary.detections:
            key = (str(item.get("severity", "")), str(item.get("summary", "")), str(item.get("details", "")))
            if key in det_seen:
                continue
            det_seen.add(key)
            detections.append(item)
        anomalies.extend(summary.anomalies)
        artifacts.extend(summary.artifacts)
        for err in summary.errors:
            if err in err_seen:
                continue
            err_seen.add(err)
            errors.append(err)

        for conv in summary.conversations:
            key = (conv.client_ip, conv.server_ip, conv.protocol, conv.server_port)
            current = conv_map.get(key)
            if current is None:
                conv_map[key] = {
                    "packets": conv.packets,
                    "bytes": conv.bytes,
                    "first_seen": conv.first_seen,
                    "last_seen": conv.last_seen,
                }
                continue
            current["packets"] = int(current["packets"]) + conv.packets
            current["bytes"] = int(current["bytes"]) + conv.bytes
            if conv.first_seen is not None and (current["first_seen"] is None or conv.first_seen < current["first_seen"]):
                current["first_seen"] = conv.first_seen
            if conv.last_seen is not None and (current["last_seen"] is None or conv.last_seen > current["last_seen"]):
                current["last_seen"] = conv.last_seen

    conversations = [
        RpcConversation(
            client_ip=key[0],
            server_ip=key[1],
            protocol=key[2],
            server_port=key[3],
            packets=int(val["packets"]),
            bytes=int(val["bytes"]),
            first_seen=val.get("first_seen"),
            last_seen=val.get("last_seen"),
        )
        for key, val in conv_map.items()
    ]
    conversations.sort(key=lambda c: c.packets, reverse=True)

    return RpcSummary(
        path=Path(f"ALL_PCAPS_{len(summary_list)}"),
        total_packets=total_packets,
        rpc_packets=rpc_packets,
        total_bytes=total_bytes,
        total_messages=total_messages,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        server_ports=server_ports,
        protocol_counts=protocol_counts,
        pdu_counts=pdu_counts,
        interface_counts=interface_counts,
        command_counts=command_counts,
        share_counts=share_counts,
        pipe_counts=pipe_counts,
        hostname_counts=hostname_counts,
        domain_user_counts=domain_user_counts,
        ip_strings=ip_strings,
        mac_strings=mac_strings,
        plaintext_strings=plaintext_strings,
        samr_fullnames=samr_fullnames,
        conversations=conversations,
        detections=detections,
        anomalies=anomalies,
        artifacts=artifacts,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )
