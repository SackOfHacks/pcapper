from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import re
import base64
import hashlib

from .pcap_cache import get_reader
from .utils import safe_float

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.layers.l2 import Ether  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore
    Ether = None  # type: ignore
    Raw = None  # type: ignore


RDP_TCP_PORTS = {3389, 3390, 3388}
RDP_UDP_PORTS = {3389, 3390, 3391, 3392}
MSTSHASH_RE = re.compile(r"Cookie:\s*mstshash=([^\r\n;]+)", re.IGNORECASE)
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

SUSPICIOUS_PLAINTEXT = [
    (re.compile(r"password\s*[:=]", re.IGNORECASE), "Credential indicator"),
    (re.compile(r"user(name)?\s*[:=]", re.IGNORECASE), "User indicator"),
    (re.compile(r"cmd\.exe|powershell|psexec|wmic", re.IGNORECASE), "Administrative tooling"),
    (re.compile(r"mimikatz|cobalt|beacon|meterpreter", re.IGNORECASE), "Offensive tooling"),
]

FILE_NAME_RE = re.compile(
    r"[\w\-.()\[\]/ ]+\.(?:exe|dll|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|rar|7z|tar|gz|tgz|txt|csv|log|ps1|sh|bat|py|js|jar|apk|iso|img)",
    re.IGNORECASE,
)

_TLS_PREFIXES = (b"\x16\x03",)
_DTLS_PREFIXES = (b"\x16\xfe",)


@dataclass(frozen=True)
class RdpConversation:
    client_ip: str
    server_ip: str
    server_port: int
    client_port: int
    client_mac: Optional[str]
    server_mac: Optional[str]
    packets: int
    bytes: int
    client_packets: int
    server_packets: int
    client_bytes: int
    server_bytes: int
    first_seen: Optional[float]
    last_seen: Optional[float]
    client_name: Optional[str]
    tls_detected: bool
    udp_detected: bool


@dataclass(frozen=True)
class RdpSummary:
    path: Path
    total_packets: int
    rdp_packets: int
    total_bytes: int
    client_packets: int
    server_packets: int
    client_bytes: int
    server_bytes: int
    total_sessions: int
    tcp_sessions: int
    udp_sessions: int
    unique_clients: int
    unique_servers: int
    client_counts: Counter[str]
    server_counts: Counter[str]
    client_macs: Counter[str]
    server_macs: Counter[str]
    ip_to_macs: dict[str, list[str]]
    server_tcp_ports: Counter[int]
    server_udp_ports: Counter[int]
    client_names: Counter[str]
    tls_handshakes: int
    dtls_handshakes: int
    requested_protocols: Counter[str]
    selected_protocols: Counter[str]
    client_builds: Counter[str]
    certificates: Counter[str]
    decrypted_username: Counter[str]
    decrypted_domain: Counter[str]
    decrypted_client_name: Counter[str]
    auth_evidence: list[dict[str, object]]
    plaintext_strings: Counter[str]
    suspicious_plaintext: Counter[str]
    file_artifacts: Counter[str]
    conversations: list[RdpConversation]
    detections: list[dict[str, object]]
    anomalies: list[dict[str, object]]
    artifacts: list[str]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]
    analysis_notes: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "total_packets": self.total_packets,
            "rdp_packets": self.rdp_packets,
            "total_bytes": self.total_bytes,
            "client_packets": self.client_packets,
            "server_packets": self.server_packets,
            "client_bytes": self.client_bytes,
            "server_bytes": self.server_bytes,
            "total_sessions": self.total_sessions,
            "tcp_sessions": self.tcp_sessions,
            "udp_sessions": self.udp_sessions,
            "unique_clients": self.unique_clients,
            "unique_servers": self.unique_servers,
            "client_counts": dict(self.client_counts),
            "server_counts": dict(self.server_counts),
            "client_macs": dict(self.client_macs),
            "server_macs": dict(self.server_macs),
            "ip_to_macs": {key: list(value) for key, value in self.ip_to_macs.items()},
            "server_tcp_ports": dict(self.server_tcp_ports),
            "server_udp_ports": dict(self.server_udp_ports),
            "client_names": dict(self.client_names),
            "tls_handshakes": self.tls_handshakes,
            "dtls_handshakes": self.dtls_handshakes,
            "requested_protocols": dict(self.requested_protocols),
            "selected_protocols": dict(self.selected_protocols),
            "client_builds": dict(self.client_builds),
            "certificates": dict(self.certificates),
            "decrypted_username": dict(self.decrypted_username),
            "decrypted_domain": dict(self.decrypted_domain),
            "decrypted_client_name": dict(self.decrypted_client_name),
            "auth_evidence": list(self.auth_evidence),
            "plaintext_strings": dict(self.plaintext_strings),
            "suspicious_plaintext": dict(self.suspicious_plaintext),
            "file_artifacts": dict(self.file_artifacts),
            "conversations": [
                {
                    "client_ip": conv.client_ip,
                    "server_ip": conv.server_ip,
                    "server_port": conv.server_port,
                    "client_port": conv.client_port,
                    "client_mac": conv.client_mac,
                    "server_mac": conv.server_mac,
                    "packets": conv.packets,
                    "bytes": conv.bytes,
                    "client_packets": conv.client_packets,
                    "server_packets": conv.server_packets,
                    "client_bytes": conv.client_bytes,
                    "server_bytes": conv.server_bytes,
                    "first_seen": conv.first_seen,
                    "last_seen": conv.last_seen,
                    "client_name": conv.client_name,
                    "tls_detected": conv.tls_detected,
                    "udp_detected": conv.udp_detected,
                }
                for conv in self.conversations
            ],
            "detections": list(self.detections),
            "anomalies": list(self.anomalies),
            "artifacts": list(self.artifacts),
            "errors": list(self.errors),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": self.duration_seconds,
            "analysis_notes": list(self.analysis_notes),
        }


def merge_rdp_summaries(summaries: list[RdpSummary] | tuple[RdpSummary, ...] | set[RdpSummary]) -> RdpSummary:
    summary_list = list(summaries)
    if not summary_list:
        return RdpSummary(
            path=Path("ALL_PCAPS_0"),
            total_packets=0,
            rdp_packets=0,
            total_bytes=0,
            client_packets=0,
            server_packets=0,
            client_bytes=0,
            server_bytes=0,
            total_sessions=0,
            tcp_sessions=0,
            udp_sessions=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            client_macs=Counter(),
            server_macs=Counter(),
            ip_to_macs={},
            server_tcp_ports=Counter(),
            server_udp_ports=Counter(),
            client_names=Counter(),
            tls_handshakes=0,
            dtls_handshakes=0,
            requested_protocols=Counter(),
            selected_protocols=Counter(),
            client_builds=Counter(),
            certificates=Counter(),
            decrypted_username=Counter(),
            decrypted_domain=Counter(),
            decrypted_client_name=Counter(),
            auth_evidence=[],
            plaintext_strings=Counter(),
            suspicious_plaintext=Counter(),
            file_artifacts=Counter(),
            conversations=[],
            detections=[],
            anomalies=[],
            artifacts=[],
            errors=[],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
            analysis_notes=[],
        )

    total_packets = 0
    rdp_packets = 0
    total_bytes = 0
    client_packets = 0
    server_packets = 0
    client_bytes = 0
    server_bytes = 0
    total_sessions = 0
    tcp_sessions = 0
    udp_sessions = 0
    tls_handshakes = 0
    dtls_handshakes = 0

    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    client_macs: Counter[str] = Counter()
    server_macs: Counter[str] = Counter()
    ip_to_macs: dict[str, set[str]] = defaultdict(set)
    server_tcp_ports: Counter[int] = Counter()
    server_udp_ports: Counter[int] = Counter()
    client_names: Counter[str] = Counter()
    requested_protocols: Counter[str] = Counter()
    selected_protocols: Counter[str] = Counter()
    client_builds: Counter[str] = Counter()
    certificates: Counter[str] = Counter()
    decrypted_username: Counter[str] = Counter()
    decrypted_domain: Counter[str] = Counter()
    decrypted_client_name: Counter[str] = Counter()
    auth_evidence: list[dict[str, object]] = []
    auth_evidence_seen: set[tuple[str, str, int, int, str, str, str]] = set()
    plaintext_strings: Counter[str] = Counter()
    suspicious_plaintext: Counter[str] = Counter()
    file_artifacts: Counter[str] = Counter()
    conversations: list[RdpConversation] = []
    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []
    artifacts: list[str] = []
    errors: list[str] = []

    for summary in summary_list:
        total_packets += summary.total_packets
        rdp_packets += summary.rdp_packets
        total_bytes += summary.total_bytes
        client_packets += summary.client_packets
        server_packets += summary.server_packets
        client_bytes += summary.client_bytes
        server_bytes += summary.server_bytes
        total_sessions += summary.total_sessions
        tcp_sessions += summary.tcp_sessions
        udp_sessions += summary.udp_sessions
        tls_handshakes += summary.tls_handshakes

        if summary.first_seen is not None:
            first_seen = summary.first_seen if first_seen is None else min(first_seen, summary.first_seen)
        if summary.last_seen is not None:
            last_seen = summary.last_seen if last_seen is None else max(last_seen, summary.last_seen)

        client_counts.update(summary.client_counts)
        server_counts.update(summary.server_counts)
        client_macs.update(summary.client_macs)
        server_macs.update(summary.server_macs)
        for ip_value, macs in summary.ip_to_macs.items():
            ip_to_macs[ip_value].update(macs)
        server_tcp_ports.update(summary.server_tcp_ports)
        server_udp_ports.update(summary.server_udp_ports)
        client_names.update(summary.client_names)
        requested_protocols.update(summary.requested_protocols)
        selected_protocols.update(summary.selected_protocols)
        client_builds.update(summary.client_builds)
        certificates.update(summary.certificates)
        decrypted_username.update(summary.decrypted_username)
        decrypted_domain.update(summary.decrypted_domain)
        decrypted_client_name.update(summary.decrypted_client_name)
        for item in summary.auth_evidence:
            key = (
                str(item.get("client_ip", "")),
                str(item.get("server_ip", "")),
                int(item.get("client_port", 0) or 0),
                int(item.get("server_port", 0) or 0),
                str(item.get("username", "")),
                str(item.get("domain", "")),
                str(item.get("client_name", "")),
            )
            if key in auth_evidence_seen:
                continue
            auth_evidence_seen.add(key)
            auth_evidence.append(dict(item))
        plaintext_strings.update(summary.plaintext_strings)
        suspicious_plaintext.update(summary.suspicious_plaintext)
        file_artifacts.update(summary.file_artifacts)
        conversations.extend(summary.conversations)
        detections.extend(summary.detections)
        anomalies.extend(summary.anomalies)
        artifacts.extend(summary.artifacts)
        errors.extend(summary.errors)
        for note in summary.analysis_notes:
            if note not in analysis_notes:
                analysis_notes.append(note)

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    return RdpSummary(
        path=Path("ALL_PCAPS"),
        total_packets=total_packets,
        rdp_packets=rdp_packets,
        total_bytes=total_bytes,
        client_packets=client_packets,
        server_packets=server_packets,
        client_bytes=client_bytes,
        server_bytes=server_bytes,
        total_sessions=total_sessions,
        tcp_sessions=tcp_sessions,
        udp_sessions=udp_sessions,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        client_macs=client_macs,
        server_macs=server_macs,
        ip_to_macs={key: sorted(value) for key, value in ip_to_macs.items()},
        server_tcp_ports=server_tcp_ports,
        server_udp_ports=server_udp_ports,
        client_names=client_names,
        tls_handshakes=tls_handshakes,
        dtls_handshakes=dtls_handshakes,
        requested_protocols=requested_protocols,
        selected_protocols=selected_protocols,
        client_builds=client_builds,
        certificates=certificates,
        decrypted_username=decrypted_username,
        decrypted_domain=decrypted_domain,
        decrypted_client_name=decrypted_client_name,
        auth_evidence=auth_evidence,
        plaintext_strings=plaintext_strings,
        suspicious_plaintext=suspicious_plaintext,
        file_artifacts=file_artifacts,
        conversations=conversations,
        detections=detections,
        anomalies=anomalies,
        artifacts=artifacts,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
        analysis_notes=analysis_notes,
    )


@dataclass
class _SessionState:
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    is_udp: bool
    client_mac: Optional[str] = None
    server_mac: Optional[str] = None
    packets: int = 0
    bytes: int = 0
    client_packets: int = 0
    server_packets: int = 0
    client_bytes: int = 0
    server_bytes: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    client_name: Optional[str] = None
    tls_detected: bool = False


def _extract_ascii_strings(data: bytes, min_len: int = 4, max_len: int = 200) -> list[str]:
    results: list[str] = []
    if not data:
        return results
    current = bytearray()
    for b in data:
        if 32 <= b <= 126:
            current.append(b)
        else:
            if len(current) >= min_len:
                value = current.decode("latin-1", errors="ignore")
                results.append(value[:max_len])
            current = bytearray()
    if len(current) >= min_len:
        value = current.decode("latin-1", errors="ignore")
        results.append(value[:max_len])
    return results


def _scan_plaintext(
    payload: bytes,
    plaintext_counter: Counter[str],
    suspicious_counter: Counter[str],
    file_counter: Counter[str],
    artifacts: list[str],
    max_unique: int = 2000,
) -> None:
    for item in _extract_ascii_strings(payload):
        if not item:
            continue
        if len(plaintext_counter) < max_unique or item in plaintext_counter:
            plaintext_counter[item] += 1
        for pattern, reason in SUSPICIOUS_PLAINTEXT:
            if pattern.search(item):
                suspicious_counter[f"{reason}: {item}"] += 1
        for match in FILE_NAME_RE.findall(item):
            file_counter[match] += 1
        if "mstshash=" in item.lower():
            artifacts.append(item)
        if "credssp" in item.lower():
            artifacts.append(item)
        if "ntlmssp" in item.lower():
            artifacts.append(item)


def _read_uint16(data: bytes, offset: int) -> tuple[Optional[int], int]:
    if offset + 2 > len(data):
        return None, offset
    value = int.from_bytes(data[offset:offset + 2], "little")
    return value, offset + 2


def _read_uint32_le(data: bytes, offset: int) -> tuple[Optional[int], int]:
    if offset + 4 > len(data):
        return None, offset
    value = int.from_bytes(data[offset:offset + 4], "little")
    return value, offset + 4


def _parse_rdp_negotiation(payload: bytes) -> tuple[Optional[int], Optional[int]]:
    if not payload or payload[0] != 0x03:
        return None, None
    if len(payload) < 7:
        return None, None
    if payload[1] != 0x00:
        return None, None
    total_len = int.from_bytes(payload[2:4], "big")
    if total_len <= 0 or total_len > len(payload):
        total_len = len(payload)
    offset = 4
    if payload[offset] != 0x02:
        return None, None
    offset += 1
    tpdu_len = payload[offset]
    offset += 1
    if tpdu_len < 6:
        return None, None
    if offset + (tpdu_len - 1) > len(payload):
        return None, None
    offset += (tpdu_len - 1)
    if offset >= len(payload) or payload[offset] != 0xE0:
        return None, None
    offset += 1
    offset += 6
    if offset > total_len:
        return None, None
    requested = None
    selected = None
    while offset + 4 <= total_len:
        if payload[offset:offset + 4] == b"\x00\x00\x00\x00":
            break
        if offset + 4 > total_len:
            break
        typ = payload[offset]
        length = payload[offset + 1]
        if length < 4:
            break
        if offset + length > total_len:
            break
        if typ == 0x01 and length >= 8:
            requested = int.from_bytes(payload[offset + 4:offset + 8], "little")
        if typ == 0x02 and length >= 8:
            selected = int.from_bytes(payload[offset + 4:offset + 8], "little")
        offset += length
    return requested, selected


def _rdp_protocol_names(mask: int | None) -> list[str]:
    if mask is None:
        return []
    names: list[str] = []
    if mask & 0x00000001:
        names.append("TLS")
    if mask & 0x00000002:
        names.append("NLA")
    if mask & 0x00000004:
        names.append("RDP")
    if mask & 0x00000008:
        names.append("RDSTLS")
    return names


def _parse_rdp_client_core_data(payload: bytes) -> tuple[Optional[str], Optional[str], Optional[str]]:
    if not payload:
        return None, None, None
    marker = b"\x01\xc0\xd8\x00"
    idx = payload.find(marker)
    if idx == -1:
        return None, None, None
    offset = idx + 4
    if offset + 4 > len(payload):
        return None, None, None
    offset += 4  # total length
    core_type, offset = _read_uint16(payload, offset)
    core_len, offset = _read_uint16(payload, offset)
    if core_type != 0xC001 or core_len is None:
        return None, None, None
    if offset + core_len - 4 > len(payload):
        return None, None, None
    data = payload[offset:offset + core_len - 4]
    if len(data) < 4:
        return None, None, None
    version = int.from_bytes(data[:4], "little")
    offset2 = 4
    if offset2 + 8 > len(data):
        return None, None, str(version)
    offset2 += 8  # skip desktop width/height
    if offset2 + 2 > len(data):
        return None, None, str(version)
    offset2 += 2  # color depth
    if offset2 + 2 > len(data):
        return None, None, str(version)
    offset2 += 2  # SAS
    if offset2 + 4 > len(data):
        return None, None, str(version)
    keyboard_layout = int.from_bytes(data[offset2:offset2 + 4], "little")
    offset2 += 4
    if offset2 + 4 > len(data):
        return None, None, str(version)
    client_build = int.from_bytes(data[offset2:offset2 + 4], "little")
    offset2 += 4
    if offset2 + 32 > len(data):
        return None, str(client_build), str(version)
    client_name_raw = data[offset2:offset2 + 32]
    try:
        client_name = client_name_raw.decode("utf-16-le", errors="ignore").rstrip("\x00")
    except Exception:
        client_name = None
    return client_name or None, str(client_build), str(version)


def _coerce_decrypted_payload(value: object | None) -> Optional[bytes]:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        candidate = value.strip()
        if candidate and len(candidate) % 4 == 0 and _BASE64_RE.match(candidate):
            try:
                return base64.b64decode(candidate)
            except Exception:
                pass
        return candidate.encode("latin-1", errors="ignore")
    return None


def _find_decrypted_payload(
    pkt: object,
    meta: object | None,
    pkt_index: int,
    decrypted_payloads: dict[int, bytes] | None,
) -> tuple[Optional[bytes], Optional[str]]:
    if decrypted_payloads:
        payload = _coerce_decrypted_payload(decrypted_payloads.get(pkt_index))
        if payload:
            return payload, "parameter"
    if hasattr(pkt, "pcapper_rdp_decrypted"):
        payload = _coerce_decrypted_payload(getattr(pkt, "pcapper_rdp_decrypted", None))
        if payload:
            return payload, "packet"
    if meta is None:
        return None, None
    candidate = None
    if isinstance(meta, dict):
        candidate = meta.get("rdp_decrypted") or meta.get("rdp_decrypted_packets")
    else:
        candidate = getattr(meta, "rdp_decrypted", None) or getattr(meta, "rdp_decrypted_packets", None)
    if isinstance(candidate, dict):
        payload = _coerce_decrypted_payload(candidate.get(pkt_index))
        if payload:
            return payload, "meta"
    if isinstance(candidate, list):
        if 0 <= pkt_index - 1 < len(candidate):
            payload = _coerce_decrypted_payload(candidate[pkt_index - 1])
            if payload:
                return payload, "meta"
    return None, None


def _parse_rdp_decrypted_identity(payload: bytes) -> tuple[Optional[str], Optional[str], Optional[str]]:
    if not payload:
        return None, None, None
    text = payload.decode("latin-1", errors="ignore")
    user = None
    domain = None
    host = None
    match = re.search(r"(?:username|user)\s*[:=]\s*([\\w\\-\\.@]{1,64})", text, re.IGNORECASE)
    if match:
        user = match.group(1)
    match = re.search(r"(?:domain)\\s*[:=]\\s*([\\w\\-\\.]{1,64})", text, re.IGNORECASE)
    if match:
        domain = match.group(1)
    match = re.search(r"(?:clientname|client_name|hostname)\\s*[:=]\\s*([\\w\\-\\.]{1,64})", text, re.IGNORECASE)
    if match:
        host = match.group(1)
    return user, domain, host


def _direction(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    is_udp: bool,
) -> tuple[str, str, int, int]:
    ports = RDP_UDP_PORTS if is_udp else RDP_TCP_PORTS
    if dport in ports:
        return src_ip, dst_ip, sport, dport
    if sport in ports:
        return dst_ip, src_ip, dport, sport
    if dport < 1024 and sport >= 1024:
        return src_ip, dst_ip, sport, dport
    if sport < 1024 and dport >= 1024:
        return dst_ip, src_ip, dport, sport
    return src_ip, dst_ip, sport, dport


def _beaconing_score(times: list[float]) -> Optional[dict[str, float]]:
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
    if avg < 5 or avg > 86400:
        return None
    if stddev > max(5.0, avg * 0.25):
        return None
    return {"avg": avg, "stddev": stddev}


def analyze_rdp(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
    decrypted_payloads: dict[int, bytes] | None = None,
) -> RdpSummary:
    errors: list[str] = []
    if (TCP is None and UDP is None) or (IP is None and IPv6 is None):
        errors.append("Scapy IP/TCP/UDP layers unavailable; install scapy for RDP analysis.")
        return RdpSummary(
            path=path,
            total_packets=0,
            rdp_packets=0,
            total_bytes=0,
            client_packets=0,
            server_packets=0,
            client_bytes=0,
            server_bytes=0,
            total_sessions=0,
            tcp_sessions=0,
            udp_sessions=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            client_macs=Counter(),
            server_macs=Counter(),
            ip_to_macs={},
            server_tcp_ports=Counter(),
            server_udp_ports=Counter(),
            client_names=Counter(),
            tls_handshakes=0,
            dtls_handshakes=0,
            requested_protocols=Counter(),
            selected_protocols=Counter(),
            client_builds=Counter(),
            certificates=Counter(),
            decrypted_username=Counter(),
            decrypted_domain=Counter(),
            decrypted_client_name=Counter(),
            auth_evidence=[],
            plaintext_strings=Counter(),
            suspicious_plaintext=Counter(),
            file_artifacts=Counter(),
            conversations=[],
            detections=[],
            anomalies=[],
            artifacts=[],
            errors=errors,
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
            analysis_notes=[],
        )

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, packets=packets, meta=meta, show_status=show_status
    )

    total_packets = 0
    rdp_packets = 0
    total_bytes = 0
    client_packets = 0
    server_packets = 0
    client_bytes = 0
    server_bytes = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    sessions: dict[tuple[str, int, str, int, bool], _SessionState] = {}
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    client_macs: Counter[str] = Counter()
    server_macs: Counter[str] = Counter()
    ip_to_macs: dict[str, set[str]] = defaultdict(set)
    server_tcp_ports: Counter[int] = Counter()
    server_udp_ports: Counter[int] = Counter()
    client_names: Counter[str] = Counter()
    tls_handshakes = 0
    dtls_handshakes = 0
    requested_protocols: Counter[str] = Counter()
    selected_protocols: Counter[str] = Counter()
    client_builds: Counter[str] = Counter()
    certificates: Counter[str] = Counter()
    decrypted_username: Counter[str] = Counter()
    decrypted_domain: Counter[str] = Counter()
    decrypted_client_name: Counter[str] = Counter()
    auth_evidence: list[dict[str, object]] = []
    auth_evidence_seen: set[tuple[str, str, int, int, str, str, str]] = set()

    plaintext_strings: Counter[str] = Counter()
    suspicious_plaintext: Counter[str] = Counter()
    file_artifacts: Counter[str] = Counter()
    artifacts: list[str] = []
    analysis_notes: list[str] = [
        "Plaintext indicators are limited to pre-encryption or decrypted payloads.",
        "RDP negotiation parsing is best-effort and may not decode all variants.",
    ]

    short_session_counts: Counter[tuple[str, str]] = Counter()
    short_session_by_client: Counter[str] = Counter()
    short_session_targets: dict[str, set[str]] = defaultdict(set)
    pair_first_seen: dict[tuple[str, str], list[float]] = defaultdict(list)

    pkt_index = 0
    decrypted_sources: set[str] = set()

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            pkt_index += 1
            total_packets += 1
            pkt_len = int(len(pkt)) if hasattr(pkt, "__len__") else 0
            total_bytes += pkt_len

            ip_layer = None
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                ip_layer = pkt[IP]  # type: ignore[index]
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                ip_layer = pkt[IPv6]  # type: ignore[index]
            if ip_layer is None:
                continue

            src_ip = str(getattr(ip_layer, "src", ""))
            dst_ip = str(getattr(ip_layer, "dst", ""))
            if not src_ip or not dst_ip:
                continue

            is_udp = UDP is not None and pkt.haslayer(UDP)  # type: ignore[truthy-bool]
            is_tcp = TCP is not None and pkt.haslayer(TCP)  # type: ignore[truthy-bool]
            if not (is_tcp or is_udp):
                continue

            if is_tcp:
                tcp = pkt[TCP]  # type: ignore[index]
                sport = int(getattr(tcp, "sport", 0) or 0)
                dport = int(getattr(tcp, "dport", 0) or 0)
            else:
                udp = pkt[UDP]  # type: ignore[index]
                sport = int(getattr(udp, "sport", 0) or 0)
                dport = int(getattr(udp, "dport", 0) or 0)

            payload = b""
            if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                try:
                    payload = bytes(pkt[Raw])  # type: ignore[index]
                except Exception:
                    payload = b""
            else:
                try:
                    if is_tcp:
                        payload = bytes(tcp.payload)
                    else:
                        payload = bytes(udp.payload)
                except Exception:
                    payload = b""

            payload_prefix = payload[:128] if payload else b""
            decrypted_payload, decrypt_source = _find_decrypted_payload(
                pkt, meta, pkt_index, decrypted_payloads
            )
            if decrypt_source:
                decrypted_sources.add(decrypt_source)
            is_rdp = (
                (is_tcp and (sport in RDP_TCP_PORTS or dport in RDP_TCP_PORTS))
                or (is_udp and (sport in RDP_UDP_PORTS or dport in RDP_UDP_PORTS))
                or (payload_prefix and (b"Cookie: mstshash=" in payload_prefix or b"RDPUDP" in payload_prefix))
            )
            if not is_rdp and not decrypted_payload:
                continue

            rdp_packets += 1
            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            eth_src = None
            eth_dst = None
            if Ether is not None and pkt.haslayer(Ether):  # type: ignore[truthy-bool]
                try:
                    eth_layer = pkt[Ether]  # type: ignore[index]
                    eth_src = str(getattr(eth_layer, "src", "")) or None
                    eth_dst = str(getattr(eth_layer, "dst", "")) or None
                except Exception:
                    eth_src = None
                    eth_dst = None

            client_ip, server_ip, client_port, server_port = _direction(
                src_ip, dst_ip, sport, dport, is_udp
            )

            client_counts[client_ip] += 1
            server_counts[server_ip] += 1
            if is_udp:
                server_udp_ports[server_port] += 1
            else:
                server_tcp_ports[server_port] += 1

            if eth_src and src_ip:
                ip_to_macs[src_ip].add(eth_src.lower())
            if eth_dst and dst_ip:
                ip_to_macs[dst_ip].add(eth_dst.lower())
            if eth_src and src_ip == client_ip:
                client_macs[eth_src.lower()] += 1
            if eth_dst and dst_ip == server_ip:
                server_macs[eth_dst.lower()] += 1

            session_key = (client_ip, client_port, server_ip, server_port, is_udp)
            session = sessions.get(session_key)
            if session is None:
                session = _SessionState(
                    client_ip=client_ip,
                    server_ip=server_ip,
                    client_port=client_port,
                    server_port=server_port,
                    is_udp=is_udp,
                    first_seen=ts,
                    last_seen=ts,
                )
                sessions[session_key] = session
            if session.client_mac is None and eth_src and src_ip == client_ip:
                session.client_mac = eth_src.lower()
            if session.server_mac is None and eth_dst and dst_ip == server_ip:
                session.server_mac = eth_dst.lower()

            session.packets += 1
            session.bytes += pkt_len
            if src_ip == client_ip:
                session.client_packets += 1
                session.client_bytes += pkt_len
                client_packets += 1
                client_bytes += pkt_len
            else:
                session.server_packets += 1
                session.server_bytes += pkt_len
                server_packets += 1
                server_bytes += pkt_len

            if ts is not None:
                if session.first_seen is None or ts < session.first_seen:
                    session.first_seen = ts
                if session.last_seen is None or ts > session.last_seen:
                    session.last_seen = ts

            text = ""
            if payload:
                try:
                    text = payload.decode("latin-1", errors="ignore")
                except Exception:
                    text = ""

            if text:
                match = MSTSHASH_RE.search(text)
                if match:
                    client_name = match.group(1).strip()
                    if client_name:
                        session.client_name = session.client_name or client_name
                        client_names[client_name] += 1
                if "Cookie: mstshash=" in text:
                    artifacts.append(text.strip())
                if "CredSSP" in text or "NTLMSSP" in text:
                    artifacts.append(text.strip())
                requested_mask, selected_mask = _parse_rdp_negotiation(payload_prefix)
                for item in _rdp_protocol_names(requested_mask):
                    requested_protocols[item] += 1
                for item in _rdp_protocol_names(selected_mask):
                    selected_protocols[item] += 1
                core_client, client_build, _version = _parse_rdp_client_core_data(payload_prefix)
                if core_client:
                    decrypted_client_name[core_client] += 1
                if client_build:
                    client_builds[client_build] += 1
                if (not payload_prefix.startswith(_TLS_PREFIXES) and not payload_prefix.startswith(_DTLS_PREFIXES)):
                    _scan_plaintext(payload, plaintext_strings, suspicious_plaintext, file_artifacts, artifacts)

            if payload_prefix.startswith(_TLS_PREFIXES):
                tls_handshakes += 1
                session.tls_detected = True
            if payload_prefix.startswith(_DTLS_PREFIXES):
                dtls_handshakes += 1
                session.tls_detected = True

            if decrypted_payload:
                _scan_plaintext(decrypted_payload, plaintext_strings, suspicious_plaintext, file_artifacts, artifacts)
                user, domain, host = _parse_rdp_decrypted_identity(decrypted_payload)
                if user:
                    decrypted_username[user] += 1
                if domain:
                    decrypted_domain[domain] += 1
                if host:
                    decrypted_client_name[host] += 1
                if user:
                    key = (
                        session.client_ip,
                        session.server_ip,
                        session.client_port,
                        session.server_port,
                        user,
                        domain or "-",
                        host or "-",
                    )
                    if key not in auth_evidence_seen:
                        auth_evidence_seen.add(key)
                        auth_evidence.append({
                            "client_ip": session.client_ip,
                            "server_ip": session.server_ip,
                            "client_port": session.client_port,
                            "server_port": session.server_port,
                            "username": user,
                            "domain": domain or "-",
                            "client_name": host or "-",
                        })

    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        reader.close()

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    conversations: list[RdpConversation] = []
    tcp_sessions = 0
    udp_sessions = 0
    for session in sessions.values():
        conversations.append(
            RdpConversation(
                client_ip=session.client_ip,
                server_ip=session.server_ip,
                server_port=session.server_port,
                client_port=session.client_port,
                client_mac=session.client_mac,
                server_mac=session.server_mac,
                packets=session.packets,
                bytes=session.bytes,
                client_packets=session.client_packets,
                server_packets=session.server_packets,
                client_bytes=session.client_bytes,
                server_bytes=session.server_bytes,
                first_seen=session.first_seen,
                last_seen=session.last_seen,
                client_name=session.client_name,
                tls_detected=session.tls_detected,
                udp_detected=session.is_udp,
            )
        )
        if session.is_udp:
            udp_sessions += 1
        else:
            tcp_sessions += 1
        if session.packets <= 6 and session.bytes < 2000:
            short_session_counts[(session.client_ip, session.server_ip)] += 1
            short_session_by_client[session.client_ip] += 1
            short_session_targets[session.client_ip].add(session.server_ip)
        if session.first_seen is not None:
            pair_first_seen[(session.client_ip, session.server_ip)].append(session.first_seen)

    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []

    non_standard_ports = [port for port in server_tcp_ports if port not in RDP_TCP_PORTS]
    non_standard_ports += [port for port in server_udp_ports if port not in RDP_UDP_PORTS]
    if non_standard_ports:
        detections.append({
            "severity": "info",
            "summary": "RDP observed on non-standard ports",
            "details": ", ".join(str(port) for port in sorted(set(non_standard_ports))),
        })

    if server_udp_ports:
        detections.append({
            "severity": "info",
            "summary": "RDP UDP transport observed",
            "details": ", ".join(str(port) for port in sorted(server_udp_ports.keys())),
        })

    if suspicious_plaintext and (plaintext_strings or decrypted_sources):
        detections.append({
            "severity": "warning",
            "summary": "Suspicious plaintext strings observed in RDP payloads",
            "details": "Potential credentials, tooling, or sensitive strings in cleartext.",
        })

    if decrypted_sources:
        analysis_notes.append(f"Decrypted RDP payloads provided via: {', '.join(sorted(decrypted_sources))}.")

    for (client_ip, server_ip), count in short_session_counts.items():
        if count >= 20:
            anomalies.append({
                "title": "Potential brute force or probing",
                "details": f"{client_ip} -> {server_ip} short sessions: {count}",
            })

    for client_ip, count in short_session_by_client.items():
        targets = short_session_targets.get(client_ip, set())
        if count >= 30 and len(targets) >= 10:
            anomalies.append({
                "title": "Potential RDP scanning",
                "details": f"{client_ip} short sessions: {count} across {len(targets)} servers",
            })

    for (client_ip, server_ip), times in pair_first_seen.items():
        score = _beaconing_score(times)
        if score:
            detections.append({
                "severity": "info",
                "summary": "Potential RDP beaconing",
                "details": f"{client_ip} -> {server_ip} avg interval {score['avg']:.1f}s, stddev {score['stddev']:.1f}s",
            })

    for session in sessions.values():
        if session.client_bytes >= 50 * 1024 * 1024 and session.client_bytes > session.server_bytes * 3:
            detections.append({
                "severity": "warning",
                "summary": "Potential RDP data upload/exfiltration",
                "details": (
                    f"{session.client_ip} -> {session.server_ip} "
                    f"client->server {session.client_bytes / (1024 * 1024):.1f} MB"
                ),
            })
        if session.server_bytes >= 200 * 1024 * 1024 and session.server_bytes > session.client_bytes * 3:
            detections.append({
                "severity": "info",
                "summary": "High server->client RDP data volume",
                "details": (
                    f"{session.server_ip} -> {session.client_ip} "
                    f"server->client {session.server_bytes / (1024 * 1024):.1f} MB"
                ),
            })
        if session.last_seen is not None and session.first_seen is not None:
            duration = session.last_seen - session.first_seen
            if duration >= 4 * 3600:
                anomalies.append({
                    "title": "Long-lived RDP session",
                    "details": f"{session.client_ip} -> {session.server_ip} duration {duration:.0f}s",
                })

    total_sessions = len(conversations)

    return RdpSummary(
        path=path,
        total_packets=total_packets,
        rdp_packets=rdp_packets,
        total_bytes=total_bytes,
        client_packets=client_packets,
        server_packets=server_packets,
        client_bytes=client_bytes,
        server_bytes=server_bytes,
        total_sessions=total_sessions,
        tcp_sessions=tcp_sessions,
        udp_sessions=udp_sessions,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        client_macs=client_macs,
        server_macs=server_macs,
        ip_to_macs={key: sorted(value) for key, value in ip_to_macs.items()},
        server_tcp_ports=server_tcp_ports,
        server_udp_ports=server_udp_ports,
        client_names=client_names,
        tls_handshakes=tls_handshakes,
        dtls_handshakes=dtls_handshakes,
        requested_protocols=requested_protocols,
        selected_protocols=selected_protocols,
        client_builds=client_builds,
        certificates=certificates,
        decrypted_username=decrypted_username,
        decrypted_domain=decrypted_domain,
        decrypted_client_name=decrypted_client_name,
        auth_evidence=auth_evidence,
        plaintext_strings=plaintext_strings,
        suspicious_plaintext=suspicious_plaintext,
        file_artifacts=file_artifacts,
        conversations=conversations,
        detections=detections,
        anomalies=anomalies,
        artifacts=artifacts,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
        analysis_notes=analysis_notes,
    )
