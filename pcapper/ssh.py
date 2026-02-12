from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import re

from .pcap_cache import get_reader
from .utils import safe_float

try:
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    IPv6 = None  # type: ignore
    Raw = None  # type: ignore


SSH_PORTS = {22, 2222, 2200}
SSH_BANNER_RE = re.compile(r"(SSH-[0-9.]+-[^\s\r\n]+)")

SSH_MESSAGE_TYPES = {
    1: "SSH_MSG_DISCONNECT",
    2: "SSH_MSG_IGNORE",
    3: "SSH_MSG_UNIMPLEMENTED",
    4: "SSH_MSG_DEBUG",
    5: "SSH_MSG_SERVICE_REQUEST",
    6: "SSH_MSG_SERVICE_ACCEPT",
    20: "SSH_MSG_KEXINIT",
    21: "SSH_MSG_NEWKEYS",
    30: "SSH_MSG_KEXDH_INIT",
    31: "SSH_MSG_KEXDH_REPLY",
    50: "SSH_MSG_USERAUTH_REQUEST",
    51: "SSH_MSG_USERAUTH_FAILURE",
    52: "SSH_MSG_USERAUTH_SUCCESS",
    53: "SSH_MSG_USERAUTH_BANNER",
    60: "SSH_MSG_USERAUTH_PK_OK",
    80: "SSH_MSG_GLOBAL_REQUEST",
    81: "SSH_MSG_REQUEST_SUCCESS",
    82: "SSH_MSG_REQUEST_FAILURE",
    90: "SSH_MSG_CHANNEL_OPEN",
    91: "SSH_MSG_CHANNEL_OPEN_CONFIRMATION",
    92: "SSH_MSG_CHANNEL_OPEN_FAILURE",
    93: "SSH_MSG_CHANNEL_WINDOW_ADJUST",
    94: "SSH_MSG_CHANNEL_DATA",
    95: "SSH_MSG_CHANNEL_EXTENDED_DATA",
    96: "SSH_MSG_CHANNEL_EOF",
    97: "SSH_MSG_CHANNEL_CLOSE",
    98: "SSH_MSG_CHANNEL_REQUEST",
    99: "SSH_MSG_CHANNEL_SUCCESS",
    100: "SSH_MSG_CHANNEL_FAILURE",
}

SSH_DISCONNECT_REASONS = {
    1: "Host not allowed",
    2: "Protocol error",
    3: "Key exchange failed",
    4: "Reserved",
    5: "MAC error",
    6: "Compression error",
    7: "Service not available",
    8: "Protocol version not supported",
    9: "Host key not verifiable",
    10: "Connection lost",
    11: "By application",
    12: "Too many connections",
    13: "Auth cancelled by user",
    14: "No more auth methods",
    15: "Illegal user name",
}

REQUEST_TYPES = {
    "SSH_MSG_SERVICE_REQUEST",
    "SSH_MSG_USERAUTH_REQUEST",
    "SSH_MSG_GLOBAL_REQUEST",
    "SSH_MSG_CHANNEL_OPEN",
    "SSH_MSG_CHANNEL_REQUEST",
}

RESPONSE_TYPES = {
    "SSH_MSG_SERVICE_ACCEPT",
    "SSH_MSG_USERAUTH_SUCCESS",
    "SSH_MSG_USERAUTH_FAILURE",
    "SSH_MSG_REQUEST_SUCCESS",
    "SSH_MSG_REQUEST_FAILURE",
    "SSH_MSG_CHANNEL_OPEN_CONFIRMATION",
    "SSH_MSG_CHANNEL_OPEN_FAILURE",
    "SSH_MSG_CHANNEL_SUCCESS",
    "SSH_MSG_CHANNEL_FAILURE",
}

KEX_ALGOS = {
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group1-sha1",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "sntrup761x25519-sha512@openssh.com",
}

HOSTKEY_ALGOS = {
    "ssh-ed25519",
    "ssh-ed25519-cert-v01@openssh.com",
    "ssh-rsa",
    "rsa-sha2-256",
    "rsa-sha2-512",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
}

CIPHER_ALGOS = {
    "chacha20-poly1305@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
    "3des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "arcfour",
}

MAC_ALGOS = {
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1",
    "hmac-md5",
    "umac-64@openssh.com",
    "umac-128@openssh.com",
}

COMP_ALGOS = {
    "none",
    "zlib",
    "zlib@openssh.com",
}

AUTH_METHODS = {
    "publickey",
    "password",
    "keyboard-interactive",
    "gssapi-with-mic",
    "hostbased",
    "none",
}

WEAK_ALGOS = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "ssh-rsa",
    "3des-cbc",
    "arcfour",
    "hmac-sha1",
    "hmac-md5",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
}

SUSPICIOUS_PLAINTEXT = [
    (re.compile(r"password\s*[:=]", re.IGNORECASE), "Credential indicator"),
    (re.compile(r"user(name)?\s*[:=]", re.IGNORECASE), "User indicator"),
    (re.compile(r"ssh-rsa|ssh-ed25519", re.IGNORECASE), "SSH key material"),
    (re.compile(r"BEGIN OPENSSH PRIVATE KEY", re.IGNORECASE), "Private key material"),
    (re.compile(r"scp\s+|sftp\s+", re.IGNORECASE), "File transfer tooling"),
]

FILE_NAME_RE = re.compile(
    r"[\w\-.()\[\]/ ]+\.(?:exe|dll|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|rar|7z|tar|gz|tgz|txt|csv|log|ps1|sh|bat|py|js|jar|apk|iso|img)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SshConversation:
    client_ip: str
    server_ip: str
    server_port: int
    client_port: int
    packets: int
    bytes: int
    first_seen: Optional[float]
    last_seen: Optional[float]
    client_version: Optional[str]
    server_version: Optional[str]


@dataclass(frozen=True)
class SshSummary:
    path: Path
    total_packets: int
    ssh_packets: int
    total_bytes: int
    total_sessions: int
    unique_clients: int
    unique_servers: int
    client_counts: Counter[str]
    server_counts: Counter[str]
    server_ports: Counter[int]
    client_versions: Counter[str]
    server_versions: Counter[str]
    client_software: Counter[str]
    server_software: Counter[str]
    auth_methods: Counter[str]
    kex_algorithms: Counter[str]
    host_key_algorithms: Counter[str]
    cipher_algorithms: Counter[str]
    mac_algorithms: Counter[str]
    compression_algorithms: Counter[str]
    message_types: Counter[str]
    client_message_types: Counter[str]
    server_message_types: Counter[str]
    request_counts: Counter[str]
    response_counts: Counter[str]
    disconnect_reasons: Counter[str]
    plaintext_strings: Counter[str]
    suspicious_plaintext: Counter[str]
    file_artifacts: Counter[str]
    conversations: list[SshConversation]
    detections: list[dict[str, object]]
    anomalies: list[dict[str, object]]
    artifacts: list[str]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "total_packets": self.total_packets,
            "ssh_packets": self.ssh_packets,
            "total_bytes": self.total_bytes,
            "total_sessions": self.total_sessions,
            "unique_clients": self.unique_clients,
            "unique_servers": self.unique_servers,
            "client_counts": dict(self.client_counts),
            "server_counts": dict(self.server_counts),
            "server_ports": dict(self.server_ports),
            "client_versions": dict(self.client_versions),
            "server_versions": dict(self.server_versions),
            "client_software": dict(self.client_software),
            "server_software": dict(self.server_software),
            "auth_methods": dict(self.auth_methods),
            "kex_algorithms": dict(self.kex_algorithms),
            "host_key_algorithms": dict(self.host_key_algorithms),
            "cipher_algorithms": dict(self.cipher_algorithms),
            "mac_algorithms": dict(self.mac_algorithms),
            "compression_algorithms": dict(self.compression_algorithms),
            "message_types": dict(self.message_types),
            "client_message_types": dict(self.client_message_types),
            "server_message_types": dict(self.server_message_types),
            "request_counts": dict(self.request_counts),
            "response_counts": dict(self.response_counts),
            "disconnect_reasons": dict(self.disconnect_reasons),
            "plaintext_strings": dict(self.plaintext_strings),
            "suspicious_plaintext": dict(self.suspicious_plaintext),
            "file_artifacts": dict(self.file_artifacts),
            "conversations": [
                {
                    "client_ip": conv.client_ip,
                    "server_ip": conv.server_ip,
                    "server_port": conv.server_port,
                    "client_port": conv.client_port,
                    "packets": conv.packets,
                    "bytes": conv.bytes,
                    "first_seen": conv.first_seen,
                    "last_seen": conv.last_seen,
                    "client_version": conv.client_version,
                    "server_version": conv.server_version,
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
        }


@dataclass
class _SessionState:
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    packets: int = 0
    bytes: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    client_version: Optional[str] = None
    server_version: Optional[str] = None


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


def _extract_version(text: str) -> Optional[str]:
    match = SSH_BANNER_RE.search(text)
    if not match:
        return None
    return match.group(1)


def _software_from_version(version: str | None) -> Optional[str]:
    if not version:
        return None
    parts = version.split("-", 2)
    if len(parts) < 3:
        return None
    return parts[2]


def _direction(src_ip: str, dst_ip: str, sport: int, dport: int) -> tuple[str, str, int, int]:
    if dport in SSH_PORTS:
        return src_ip, dst_ip, sport, dport
    if sport in SSH_PORTS:
        return dst_ip, src_ip, dport, sport
    if dport < 1024 and sport >= 1024:
        return src_ip, dst_ip, sport, dport
    if sport < 1024 and dport >= 1024:
        return dst_ip, src_ip, dport, sport
    return src_ip, dst_ip, sport, dport


def _parse_ssh_messages(payload: bytes) -> list[tuple[int, Optional[int]]]:
    messages: list[tuple[int, Optional[int]]] = []
    if not payload or payload.startswith(b"SSH-"):
        return messages
    idx = 0
    max_len = len(payload)
    while idx + 6 <= max_len:
        pkt_len = int.from_bytes(payload[idx:idx + 4], "big")
        if pkt_len < 1 or pkt_len > 35000:
            break
        if idx + 4 + pkt_len > max_len:
            break
        padding = payload[idx + 4]
        if padding + 1 > pkt_len:
            break
        msg_offset = idx + 5
        msg_type = payload[msg_offset]
        reason: Optional[int] = None
        if msg_type == 1 and msg_offset + 5 <= max_len:
            reason = int.from_bytes(payload[msg_offset + 1:msg_offset + 5], "big")
        messages.append((msg_type, reason))
        idx += 4 + pkt_len
    return messages


def _scan_algorithms(text: str, counters: dict[str, Counter[str]]) -> None:
    if not text:
        return
    tokens = re.split(r"[\s,\0]+", text)
    for token in tokens:
        if not token:
            continue
        if token in KEX_ALGOS:
            counters["kex"][token] += 1
        if token in HOSTKEY_ALGOS:
            counters["hostkey"][token] += 1
        if token in CIPHER_ALGOS:
            counters["cipher"][token] += 1
        if token in MAC_ALGOS:
            counters["mac"][token] += 1
        if token in COMP_ALGOS:
            counters["comp"][token] += 1
        if token in AUTH_METHODS:
            counters["auth"][token] += 1


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
        if "ssh-rsa" in item or "ssh-ed25519" in item:
            artifacts.append(item)
        if "OPENSSH PRIVATE KEY" in item.upper():
            artifacts.append(item)


def analyze_ssh(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
) -> SshSummary:
    errors: list[str] = []
    if TCP is None or (IP is None and IPv6 is None):
        errors.append("Scapy IP/TCP layers unavailable; install scapy for SSH analysis.")
        return SshSummary(
            path=path,
            total_packets=0,
            ssh_packets=0,
            total_bytes=0,
            total_sessions=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            server_ports=Counter(),
            client_versions=Counter(),
            server_versions=Counter(),
            client_software=Counter(),
            server_software=Counter(),
            auth_methods=Counter(),
            kex_algorithms=Counter(),
            host_key_algorithms=Counter(),
            cipher_algorithms=Counter(),
            mac_algorithms=Counter(),
            compression_algorithms=Counter(),
            message_types=Counter(),
            client_message_types=Counter(),
            server_message_types=Counter(),
            request_counts=Counter(),
            response_counts=Counter(),
            disconnect_reasons=Counter(),
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
        )

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, packets=packets, meta=meta, show_status=show_status
    )

    total_packets = 0
    ssh_packets = 0
    total_bytes = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    sessions: dict[tuple[str, int, str, int], _SessionState] = {}
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    server_ports: Counter[int] = Counter()

    client_versions: Counter[str] = Counter()
    server_versions: Counter[str] = Counter()
    client_software: Counter[str] = Counter()
    server_software: Counter[str] = Counter()

    message_types: Counter[str] = Counter()
    client_message_types: Counter[str] = Counter()
    server_message_types: Counter[str] = Counter()
    request_counts: Counter[str] = Counter()
    response_counts: Counter[str] = Counter()
    disconnect_reasons: Counter[str] = Counter()

    plaintext_strings: Counter[str] = Counter()
    suspicious_plaintext: Counter[str] = Counter()
    file_artifacts: Counter[str] = Counter()
    artifacts: list[str] = []

    algo_counters: dict[str, Counter[str]] = {
        "kex": Counter(),
        "hostkey": Counter(),
        "cipher": Counter(),
        "mac": Counter(),
        "comp": Counter(),
        "auth": Counter(),
    }

    short_session_counts: Counter[tuple[str, str]] = Counter()

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

            if TCP is None or not pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                continue

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

            tcp = pkt[TCP]  # type: ignore[index]
            sport = int(getattr(tcp, "sport", 0) or 0)
            dport = int(getattr(tcp, "dport", 0) or 0)

            payload = b""
            if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                try:
                    payload = bytes(pkt[Raw])  # type: ignore[index]
                except Exception:
                    payload = b""
            else:
                try:
                    payload = bytes(tcp.payload)
                except Exception:
                    payload = b""

            is_ssh = sport in SSH_PORTS or dport in SSH_PORTS or b"SSH-" in payload[:32]
            if not is_ssh:
                continue

            ssh_packets += 1
            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            client_ip, server_ip, client_port, server_port = _direction(
                src_ip, dst_ip, sport, dport
            )

            server_ports[server_port] += 1
            client_counts[client_ip] += 1
            server_counts[server_ip] += 1

            session_key = (client_ip, client_port, server_ip, server_port)
            session = sessions.get(session_key)
            if session is None:
                session = _SessionState(
                    client_ip=client_ip,
                    server_ip=server_ip,
                    client_port=client_port,
                    server_port=server_port,
                    packets=0,
                    bytes=0,
                    first_seen=ts,
                    last_seen=ts,
                )
                sessions[session_key] = session
            session.packets += 1
            session.bytes += pkt_len
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
                version = _extract_version(text)
                if version:
                    if src_ip == client_ip:
                        if session.client_version is None:
                            session.client_version = version
                        client_versions[version] += 1
                        software = _software_from_version(version)
                        if software:
                            client_software[software] += 1
                    else:
                        if session.server_version is None:
                            session.server_version = version
                        server_versions[version] += 1
                        software = _software_from_version(version)
                        if software:
                            server_software[software] += 1
                _scan_algorithms(text, algo_counters)
                _scan_plaintext(payload, plaintext_strings, suspicious_plaintext, file_artifacts, artifacts)

            for msg_type, reason in _parse_ssh_messages(payload):
                name = SSH_MESSAGE_TYPES.get(msg_type, f"SSH_MSG_{msg_type}")
                message_types[name] += 1
                if src_ip == client_ip:
                    client_message_types[name] += 1
                    if name in REQUEST_TYPES:
                        request_counts[name] += 1
                else:
                    server_message_types[name] += 1
                    if name in RESPONSE_TYPES:
                        response_counts[name] += 1
                if msg_type == 1 and reason is not None:
                    disconnect_reasons[SSH_DISCONNECT_REASONS.get(reason, f"Reason {reason}")] += 1

    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        reader.close()

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    conversations: list[SshConversation] = []
    for session in sessions.values():
        conversations.append(
            SshConversation(
                client_ip=session.client_ip,
                server_ip=session.server_ip,
                server_port=session.server_port,
                client_port=session.client_port,
                packets=session.packets,
                bytes=session.bytes,
                first_seen=session.first_seen,
                last_seen=session.last_seen,
                client_version=session.client_version,
                server_version=session.server_version,
            )
        )
        if session.packets <= 6 and session.bytes < 2000:
            short_session_counts[(session.client_ip, session.server_ip)] += 1

    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []

    non_standard_ports = [port for port in server_ports if port not in {22, 2222}]
    if non_standard_ports:
        detections.append({
            "severity": "info",
            "summary": "SSH observed on non-standard ports",
            "details": ", ".join(str(port) for port in sorted(non_standard_ports)),
        })

    legacy_versions = [
        v for v in list(client_versions.keys()) + list(server_versions.keys())
        if v.startswith("SSH-1.") or v.startswith("SSH-1.99")
    ]
    if legacy_versions:
        detections.append({
            "severity": "warning",
            "summary": "Legacy SSH protocol versions observed",
            "details": ", ".join(sorted(set(legacy_versions))),
        })

    weak_algos = [algo for algo in algo_counters["kex"] if algo in WEAK_ALGOS]
    weak_algos += [algo for algo in algo_counters["cipher"] if algo in WEAK_ALGOS]
    weak_algos += [algo for algo in algo_counters["mac"] if algo in WEAK_ALGOS]
    weak_algos += [algo for algo in algo_counters["hostkey"] if algo in WEAK_ALGOS]
    if weak_algos:
        detections.append({
            "severity": "warning",
            "summary": "Weak SSH algorithms observed",
            "details": ", ".join(sorted(set(weak_algos))),
        })

    if suspicious_plaintext:
        detections.append({
            "severity": "warning",
            "summary": "Suspicious plaintext strings observed in SSH payloads",
            "details": "Potential credentials, keys, or tooling references in cleartext.",
        })

    for (client_ip, server_ip), count in short_session_counts.items():
        if count >= 20:
            anomalies.append({
                "title": "Potential brute force or scanning",
                "details": f"{client_ip} -> {server_ip} short sessions: {count}",
            })

    if disconnect_reasons:
        anomalies.append({
            "title": "SSH disconnects observed",
            "details": ", ".join(f"{reason}({count})" for reason, count in disconnect_reasons.most_common(5)),
        })

    total_sessions = len(conversations)

    return SshSummary(
        path=path,
        total_packets=total_packets,
        ssh_packets=ssh_packets,
        total_bytes=total_bytes,
        total_sessions=total_sessions,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        server_ports=server_ports,
        client_versions=client_versions,
        server_versions=server_versions,
        client_software=client_software,
        server_software=server_software,
        auth_methods=algo_counters["auth"],
        kex_algorithms=algo_counters["kex"],
        host_key_algorithms=algo_counters["hostkey"],
        cipher_algorithms=algo_counters["cipher"],
        mac_algorithms=algo_counters["mac"],
        compression_algorithms=algo_counters["comp"],
        message_types=message_types,
        client_message_types=client_message_types,
        server_message_types=server_message_types,
        request_counts=request_counts,
        response_counts=response_counts,
        disconnect_reasons=disconnect_reasons,
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
    )
