from __future__ import annotations

import base64
import hashlib
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .device_detection import device_fingerprints_from_text
from .pcap_cache import get_reader
from .utils import extract_packet_endpoints, memoize_analysis, safe_float, packet_length, extract_ascii_strings as _extract_ascii_strings
from .utils import beacon_score as _beaconing_score
from .utils import is_private_ip, is_public_ip

try:
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.layers.l2 import Ether  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    IPv6 = None  # type: ignore
    Ether = None  # type: ignore
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

# Only genuinely obsolete/broken algorithms that a current, securely-configured
# endpoint does NOT offer. The detection matches against the *offered* KEXINIT
# name-lists, and modern OpenSSH still offers diffie-hellman-group14-sha1,
# aes*-cbc, hmac-sha1 and ssh-rsa for backward compatibility — flagging those
# fired "Weak SSH algorithms" on essentially every OpenSSH handshake. (Assessing
# the actually-negotiated algorithm would be stronger; that needs per-direction
# KEXINIT tracking and is noted for a future pass.)
WEAK_ALGOS = {
    "diffie-hellman-group1-sha1",
    "3des-cbc",
    "des-cbc",
    "blowfish-cbc",
    "cast128-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "hmac-md5",
    "hmac-md5-96",
    "none",
    "ssh-dss",
}

# SSH client banners that indicate a scripted/library client rather than an
# interactive human admin. Legitimate automation uses these too, so this is a
# context signal (info/warning), but malware, C2 frameworks, brute-forcers and
# automated lateral-movement tooling overwhelmingly ride non-OpenSSH libraries.
SSH_AUTOMATION_CLIENTS = {
    "paramiko": "Python paramiko (scripted)",
    "asyncssh": "Python AsyncSSH (scripted)",
    "libssh": "libssh (library/tooling)",
    "libssh2": "libssh2 (library/tooling)",
    "go": "Go x/crypto/ssh (tooling — common in offensive tools)",
    "russh": "Rust russh (tooling)",
    "thrussh": "Rust thrussh (tooling)",
    "renci.sshnet": "SSH.NET (.NET scripted)",
    "ssh.net": "SSH.NET (.NET scripted)",
    "jsch": "JSch (Java scripted)",
    "phpseclib": "phpseclib (PHP scripted)",
    "node": "Node ssh2 (scripted)",
    "warp": "WarpSSH",
}

SUSPICIOUS_PLAINTEXT = [
    (re.compile(r"password\s*[:=]", re.IGNORECASE), "Credential indicator"),
    (re.compile(r"(?<![\w-])user(name)?\s*[:=]\s*\S", re.IGNORECASE), "User indicator"),
    # Match actual public-key *material* (base64 key blob), not the bare
    # "ssh-rsa"/"ssh-ed25519" algorithm names that appear in every KEXINIT
    # host-key name-list (those produced false "SSH key material" hits).
    (re.compile(r"AAAAB3NzaC1yc2E|AAAAC3NzaC1lZDI1NTE5|AAAAE2VjZHNhLXNoYTI"), "SSH public key material"),
    (re.compile(r"BEGIN (?:OPENSSH|RSA|EC|DSA|PRIVATE) .*PRIVATE KEY", re.IGNORECASE), "Private key material"),
    (re.compile(r"\bscp\b|\bsftp\b|sftp-server", re.IGNORECASE), "File transfer tooling"),
]

# Terrapin prefix-truncation attack (CVE-2023-48795). A handshake is vulnerable
# when a "vulnerable" cipher mode is negotiated AND strict key-exchange is not
# offered by BOTH peers. Strict KEX is advertised by a pseudo-algorithm token in
# the KEXINIT kex_algorithms name-list (added in OpenSSH 9.6 / Dec 2023).
TERRAPIN_STRICT_KEX_CLIENT = "kex-strict-c-v00@openssh.com"
TERRAPIN_STRICT_KEX_SERVER = "kex-strict-s-v00@openssh.com"
# ChaCha20-Poly1305 is always affected; CBC ciphers are affected only in
# Encrypt-then-MAC mode (a *-etm@openssh.com MAC negotiated alongside *-cbc).
TERRAPIN_VULN_CIPHERS = {"chacha20-poly1305@openssh.com"}
CBC_CIPHERS = {
    "3des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "blowfish-cbc",
    "cast128-cbc",
    "rijndael-cbc@lysator.liu.se",
}
ETM_MAC_SUFFIX = "-etm@openssh.com"

FILE_NAME_RE = re.compile(
    r"[\w\-.()\[\]/ ]+\.(?:exe|dll|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|rar|7z|tar|gz|tgz|txt|csv|log|ps1|sh|bat|py|js|jar|apk|iso|img)",
    re.IGNORECASE,
)

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


@dataclass(frozen=True)
class SshConversation:
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
    client_version: Optional[str]
    server_version: Optional[str]
    auth_failures: int
    auth_successes: int


@dataclass(frozen=True)
class SshSummary:
    path: Path
    total_packets: int
    ssh_packets: int
    total_bytes: int
    client_packets: int
    server_packets: int
    client_bytes: int
    server_bytes: int
    total_sessions: int
    unique_clients: int
    unique_servers: int
    client_counts: Counter[str]
    server_counts: Counter[str]
    client_macs: Counter[str]
    server_macs: Counter[str]
    ip_to_macs: dict[str, list[str]]
    server_ports: Counter[int]
    client_versions: Counter[str]
    server_versions: Counter[str]
    client_software: Counter[str]
    server_software: Counter[str]
    auth_methods: Counter[str]
    auth_usernames: Counter[str]
    auth_evidence: list[dict[str, object]]
    kex_algorithms: Counter[str]
    host_key_algorithms: Counter[str]
    cipher_algorithms: Counter[str]
    mac_algorithms: Counter[str]
    compression_algorithms: Counter[str]
    client_hassh: Counter[str]
    server_hassh: Counter[str]
    client_hassh_strings: dict[str, str]
    server_hassh_strings: dict[str, str]
    host_key_fingerprints: Counter[str]
    host_key_types: Counter[str]
    message_types: Counter[str]
    client_message_types: Counter[str]
    server_message_types: Counter[str]
    request_counts: Counter[str]
    response_counts: Counter[str]
    disconnect_reasons: Counter[str]
    plaintext_strings: Counter[str]
    suspicious_plaintext: Counter[str]
    file_artifacts: Counter[str]
    device_fingerprints: Counter[str]
    conversations: list[SshConversation]
    auth_attempts_by_client: Counter[str]
    auth_failures_by_client: Counter[str]
    auth_successes_by_client: Counter[str]
    detections: list[dict[str, object]]
    anomalies: list[dict[str, object]]
    artifacts: list[str]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]
    analysis_notes: list[str]
    auth_inference: list[dict[str, object]]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "total_packets": self.total_packets,
            "ssh_packets": self.ssh_packets,
            "total_bytes": self.total_bytes,
            "client_packets": self.client_packets,
            "server_packets": self.server_packets,
            "client_bytes": self.client_bytes,
            "server_bytes": self.server_bytes,
            "total_sessions": self.total_sessions,
            "unique_clients": self.unique_clients,
            "unique_servers": self.unique_servers,
            "client_counts": dict(self.client_counts),
            "server_counts": dict(self.server_counts),
            "client_macs": dict(self.client_macs),
            "server_macs": dict(self.server_macs),
            "ip_to_macs": {key: list(value) for key, value in self.ip_to_macs.items()},
            "server_ports": dict(self.server_ports),
            "client_versions": dict(self.client_versions),
            "server_versions": dict(self.server_versions),
            "client_software": dict(self.client_software),
            "server_software": dict(self.server_software),
            "auth_methods": dict(self.auth_methods),
            "auth_usernames": dict(self.auth_usernames),
            "auth_evidence": list(self.auth_evidence),
            "kex_algorithms": dict(self.kex_algorithms),
            "host_key_algorithms": dict(self.host_key_algorithms),
            "cipher_algorithms": dict(self.cipher_algorithms),
            "mac_algorithms": dict(self.mac_algorithms),
            "compression_algorithms": dict(self.compression_algorithms),
            "client_hassh": dict(self.client_hassh),
            "server_hassh": dict(self.server_hassh),
            "client_hassh_strings": dict(self.client_hassh_strings),
            "server_hassh_strings": dict(self.server_hassh_strings),
            "host_key_fingerprints": dict(self.host_key_fingerprints),
            "host_key_types": dict(self.host_key_types),
            "message_types": dict(self.message_types),
            "client_message_types": dict(self.client_message_types),
            "server_message_types": dict(self.server_message_types),
            "request_counts": dict(self.request_counts),
            "response_counts": dict(self.response_counts),
            "disconnect_reasons": dict(self.disconnect_reasons),
            "plaintext_strings": dict(self.plaintext_strings),
            "suspicious_plaintext": dict(self.suspicious_plaintext),
            "file_artifacts": dict(self.file_artifacts),
            "device_fingerprints": dict(self.device_fingerprints),
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
                    "client_version": conv.client_version,
                    "server_version": conv.server_version,
                    "auth_failures": conv.auth_failures,
                    "auth_successes": conv.auth_successes,
                }
                for conv in self.conversations
            ],
            "auth_attempts_by_client": dict(self.auth_attempts_by_client),
            "auth_failures_by_client": dict(self.auth_failures_by_client),
            "auth_successes_by_client": dict(self.auth_successes_by_client),
            "detections": list(self.detections),
            "anomalies": list(self.anomalies),
            "artifacts": list(self.artifacts),
            "errors": list(self.errors),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": self.duration_seconds,
            "analysis_notes": list(self.analysis_notes),
            "auth_inference": list(self.auth_inference),
        }


def merge_ssh_summaries(
    summaries: list[SshSummary] | tuple[SshSummary, ...] | set[SshSummary],
) -> SshSummary:
    summary_list = list(summaries)
    if not summary_list:
        return SshSummary(
            path=Path("ALL_PCAPS_0"),
            total_packets=0,
            ssh_packets=0,
            total_bytes=0,
            client_packets=0,
            server_packets=0,
            client_bytes=0,
            server_bytes=0,
            total_sessions=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            client_macs=Counter(),
            server_macs=Counter(),
            ip_to_macs={},
            server_ports=Counter(),
            client_versions=Counter(),
            server_versions=Counter(),
            client_software=Counter(),
            server_software=Counter(),
            auth_methods=Counter(),
            auth_usernames=Counter(),
            auth_evidence=[],
            kex_algorithms=Counter(),
            host_key_algorithms=Counter(),
            cipher_algorithms=Counter(),
            mac_algorithms=Counter(),
            compression_algorithms=Counter(),
            client_hassh=Counter(),
            server_hassh=Counter(),
            client_hassh_strings={},
            server_hassh_strings={},
            host_key_fingerprints=Counter(),
            host_key_types=Counter(),
            message_types=Counter(),
            client_message_types=Counter(),
            server_message_types=Counter(),
            request_counts=Counter(),
            response_counts=Counter(),
            disconnect_reasons=Counter(),
            plaintext_strings=Counter(),
            suspicious_plaintext=Counter(),
            file_artifacts=Counter(),
            device_fingerprints=Counter(),
            conversations=[],
            auth_attempts_by_client=Counter(),
            auth_failures_by_client=Counter(),
            auth_successes_by_client=Counter(),
            detections=[],
            anomalies=[],
            artifacts=[],
            errors=[],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
            analysis_notes=[],
            auth_inference=[],
        )

    total_packets = 0
    ssh_packets = 0
    total_bytes = 0
    client_packets = 0
    server_packets = 0
    client_bytes = 0
    server_bytes = 0
    total_sessions = 0

    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    client_macs: Counter[str] = Counter()
    server_macs: Counter[str] = Counter()
    ip_to_macs: dict[str, set[str]] = defaultdict(set)
    server_ports: Counter[int] = Counter()
    client_versions: Counter[str] = Counter()
    server_versions: Counter[str] = Counter()
    client_software: Counter[str] = Counter()
    server_software: Counter[str] = Counter()
    auth_methods: Counter[str] = Counter()
    auth_usernames: Counter[str] = Counter()
    auth_evidence: list[dict[str, object]] = []
    auth_evidence_seen: set[tuple[str, str, int, int, str, str]] = set()
    kex_algorithms: Counter[str] = Counter()
    host_key_algorithms: Counter[str] = Counter()
    cipher_algorithms: Counter[str] = Counter()
    mac_algorithms: Counter[str] = Counter()
    compression_algorithms: Counter[str] = Counter()
    client_hassh: Counter[str] = Counter()
    server_hassh: Counter[str] = Counter()
    client_hassh_strings: dict[str, str] = {}
    server_hassh_strings: dict[str, str] = {}
    host_key_fingerprints: Counter[str] = Counter()
    host_key_types: Counter[str] = Counter()
    message_types: Counter[str] = Counter()
    client_message_types: Counter[str] = Counter()
    server_message_types: Counter[str] = Counter()
    request_counts: Counter[str] = Counter()
    response_counts: Counter[str] = Counter()
    disconnect_reasons: Counter[str] = Counter()
    plaintext_strings: Counter[str] = Counter()
    suspicious_plaintext: Counter[str] = Counter()
    file_artifacts: Counter[str] = Counter()
    device_fingerprints: Counter[str] = Counter()
    auth_attempts_by_client: Counter[str] = Counter()
    auth_failures_by_client: Counter[str] = Counter()
    auth_successes_by_client: Counter[str] = Counter()

    conversations: list[SshConversation] = []
    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []
    artifacts: list[str] = []
    errors: list[str] = []
    analysis_notes: list[str] = []
    auth_inference: list[dict[str, object]] = []

    for summary in summary_list:
        total_packets += summary.total_packets
        ssh_packets += summary.ssh_packets
        total_bytes += summary.total_bytes
        client_packets += summary.client_packets
        server_packets += summary.server_packets
        client_bytes += summary.client_bytes
        server_bytes += summary.server_bytes
        total_sessions += summary.total_sessions

        if summary.first_seen is not None:
            first_seen = (
                summary.first_seen
                if first_seen is None
                else min(first_seen, summary.first_seen)
            )
        if summary.last_seen is not None:
            last_seen = (
                summary.last_seen
                if last_seen is None
                else max(last_seen, summary.last_seen)
            )

        client_counts.update(summary.client_counts)
        server_counts.update(summary.server_counts)
        client_macs.update(summary.client_macs)
        server_macs.update(summary.server_macs)
        for ip_value, macs in summary.ip_to_macs.items():
            ip_to_macs[ip_value].update(macs)
        server_ports.update(summary.server_ports)
        client_versions.update(summary.client_versions)
        server_versions.update(summary.server_versions)
        client_software.update(summary.client_software)
        server_software.update(summary.server_software)
        auth_methods.update(summary.auth_methods)
        auth_usernames.update(summary.auth_usernames)
        for item in summary.auth_evidence:
            key = (
                str(item.get("client_ip", "")),
                str(item.get("server_ip", "")),
                int(item.get("client_port", 0) or 0),
                int(item.get("server_port", 0) or 0),
                str(item.get("username", "")),
                str(item.get("method", "")),
            )
            if key in auth_evidence_seen:
                continue
            auth_evidence_seen.add(key)
            auth_evidence.append(dict(item))
        kex_algorithms.update(summary.kex_algorithms)
        host_key_algorithms.update(summary.host_key_algorithms)
        cipher_algorithms.update(summary.cipher_algorithms)
        mac_algorithms.update(summary.mac_algorithms)
        compression_algorithms.update(summary.compression_algorithms)
        client_hassh.update(summary.client_hassh)
        server_hassh.update(summary.server_hassh)
        for key, value in summary.client_hassh_strings.items():
            client_hassh_strings.setdefault(key, value)
        for key, value in summary.server_hassh_strings.items():
            server_hassh_strings.setdefault(key, value)
        host_key_fingerprints.update(summary.host_key_fingerprints)
        host_key_types.update(summary.host_key_types)
        message_types.update(summary.message_types)
        client_message_types.update(summary.client_message_types)
        server_message_types.update(summary.server_message_types)
        request_counts.update(summary.request_counts)
        response_counts.update(summary.response_counts)
        disconnect_reasons.update(summary.disconnect_reasons)
        plaintext_strings.update(summary.plaintext_strings)
        suspicious_plaintext.update(summary.suspicious_plaintext)
        file_artifacts.update(summary.file_artifacts)
        device_fingerprints.update(summary.device_fingerprints)
        auth_attempts_by_client.update(summary.auth_attempts_by_client)
        auth_failures_by_client.update(summary.auth_failures_by_client)
        auth_successes_by_client.update(summary.auth_successes_by_client)

        conversations.extend(summary.conversations)
        detections.extend(summary.detections)
        anomalies.extend(summary.anomalies)
        artifacts.extend(summary.artifacts)
        errors.extend(summary.errors)
        auth_inference.extend(getattr(summary, "auth_inference", []) or [])
        for note in summary.analysis_notes:
            if note not in analysis_notes:
                analysis_notes.append(note)

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    return SshSummary(
        path=Path("ALL_PCAPS"),
        total_packets=total_packets,
        ssh_packets=ssh_packets,
        total_bytes=total_bytes,
        client_packets=client_packets,
        server_packets=server_packets,
        client_bytes=client_bytes,
        server_bytes=server_bytes,
        total_sessions=total_sessions,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        client_macs=client_macs,
        server_macs=server_macs,
        ip_to_macs={key: sorted(value) for key, value in ip_to_macs.items()},
        server_ports=server_ports,
        client_versions=client_versions,
        server_versions=server_versions,
        client_software=client_software,
        server_software=server_software,
        auth_methods=auth_methods,
        auth_usernames=auth_usernames,
        auth_evidence=auth_evidence,
        kex_algorithms=kex_algorithms,
        host_key_algorithms=host_key_algorithms,
        cipher_algorithms=cipher_algorithms,
        mac_algorithms=mac_algorithms,
        compression_algorithms=compression_algorithms,
        client_hassh=client_hassh,
        server_hassh=server_hassh,
        client_hassh_strings=client_hassh_strings,
        server_hassh_strings=server_hassh_strings,
        host_key_fingerprints=host_key_fingerprints,
        host_key_types=host_key_types,
        message_types=message_types,
        client_message_types=client_message_types,
        server_message_types=server_message_types,
        request_counts=request_counts,
        response_counts=response_counts,
        disconnect_reasons=disconnect_reasons,
        plaintext_strings=plaintext_strings,
        suspicious_plaintext=suspicious_plaintext,
        file_artifacts=file_artifacts,
        device_fingerprints=device_fingerprints,
        conversations=conversations,
        auth_attempts_by_client=auth_attempts_by_client,
        auth_failures_by_client=auth_failures_by_client,
        auth_successes_by_client=auth_successes_by_client,
        detections=detections,
        anomalies=anomalies,
        artifacts=artifacts,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
        analysis_notes=analysis_notes,
        auth_inference=auth_inference,
    )


@dataclass
class _SessionState:
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
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
    client_version: Optional[str] = None
    server_version: Optional[str] = None
    auth_failures: int = 0
    auth_successes: int = 0
    saw_newkeys: bool = False
    saw_banner: bool = False
    saw_kexinit: bool = False
    # Bytes/packets exchanged AFTER key exchange completed (the encrypted
    # auth + channel phase). Used to infer auth outcome without decryption.
    post_kex_client_bytes: int = 0
    post_kex_server_bytes: int = 0
    post_kex_client_pkts: int = 0
    post_kex_server_pkts: int = 0
    # Parsed KEXINIT name-lists per direction (for Terrapin / negotiation).
    client_kex: Optional[dict] = None
    server_kex: Optional[dict] = None


def _extract_version(text: str) -> Optional[str]:
    match = SSH_BANNER_RE.search(text)
    if not match:
        return None
    return match.group(1)


def _truncate_plain(text: str, max_len: int = 80) -> str:
    text = text.replace("\n", " ").replace("\r", " ").strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


def _software_from_version(version: str | None) -> Optional[str]:
    if not version:
        return None
    parts = version.split("-", 2)
    if len(parts) < 3:
        return None
    return parts[2]


def _direction(
    src_ip: str, dst_ip: str, sport: int, dport: int
) -> tuple[str, str, int, int]:
    if dport in SSH_PORTS:
        return src_ip, dst_ip, sport, dport
    if sport in SSH_PORTS:
        return dst_ip, src_ip, dport, sport
    if dport < 1024 and sport >= 1024:
        return src_ip, dst_ip, sport, dport
    if sport < 1024 and dport >= 1024:
        return dst_ip, src_ip, dport, sport
    return src_ip, dst_ip, sport, dport


def _negotiate(client_list: list[str], server_list: list[str]) -> Optional[str]:
    """SSH algorithm negotiation (RFC 4253 §7.1): the first algorithm on the
    client's preference list that the server also supports."""
    if not client_list or not server_list:
        return None
    server_set = set(server_list)
    for algo in client_list:
        if algo in server_set:
            return algo
    return None


def _terrapin_assessment(
    client_kex: Optional[dict], server_kex: Optional[dict]
) -> Optional[list[str]]:
    """Return the vulnerable negotiated cipher mode(s) if this handshake is
    exposed to the Terrapin attack (CVE-2023-48795), else None.

    Vulnerable iff a vulnerable cipher mode is negotiated in either direction
    AND strict KEX is not advertised by BOTH peers.
    """
    if not client_kex or not server_kex:
        return None
    c_kex = client_kex.get("kex", []) or []
    s_kex = server_kex.get("kex", []) or []
    strict = (
        TERRAPIN_STRICT_KEX_CLIENT in c_kex and TERRAPIN_STRICT_KEX_SERVER in s_kex
    )
    if strict:
        return None  # both peers enforce strict KEX -> protected
    findings: list[str] = []
    for direction, enc_key, mac_key in (
        ("c->s", "enc_c2s", "mac_c2s"),
        ("s->c", "enc_s2c", "mac_s2c"),
    ):
        cipher = _negotiate(
            client_kex.get(enc_key, []) or [], server_kex.get(enc_key, []) or []
        )
        if not cipher:
            continue
        if cipher in TERRAPIN_VULN_CIPHERS:
            findings.append(f"{direction} {cipher}")
        elif cipher in CBC_CIPHERS:
            mac = _negotiate(
                client_kex.get(mac_key, []) or [], server_kex.get(mac_key, []) or []
            )
            if mac and mac.endswith(ETM_MAC_SUFFIX):
                findings.append(f"{direction} {cipher}/{mac}")
    return findings or None


def _classify_session_auth(session: "_SessionState") -> str:
    """Infer the authentication outcome of an ENCRYPTED SSH session from traffic
    volume after key exchange (SSH user-auth is encrypted, so this is a
    heuristic, mirroring Zeek's size-based auth inference).

    Returns: 'no-kex' (never finished KEX), 'failed-or-short' (reached the
    encrypted auth phase but ended quickly with little data -> likely a failed
    or aborted login), or 'established' (sustained data -> likely a successful,
    interactive/exec/forwarding session).
    """
    if not session.saw_newkeys:
        return "no-kex"
    post = session.post_kex_client_bytes + session.post_kex_server_bytes
    duration = 0.0
    if session.first_seen is not None and session.last_seen is not None:
        duration = max(0.0, session.last_seen - session.first_seen)
    if post >= 6000 or duration >= 30.0 or session.post_kex_server_pkts >= 12:
        return "established"
    return "failed-or-short"


def _parse_ssh_messages(payload: bytes) -> list[tuple[int, Optional[int], bytes]]:
    messages: list[tuple[int, Optional[int], bytes]] = []
    if not payload or payload.startswith(b"SSH-"):
        return messages
    idx = 0
    max_len = len(payload)
    while idx + 6 <= max_len:
        pkt_len = int.from_bytes(payload[idx : idx + 4], "big")
        if pkt_len < 1 or pkt_len > 35000:
            break
        if idx + 4 + pkt_len > max_len:
            break
        padding = payload[idx + 4]
        if padding + 1 > pkt_len:
            break
        msg_offset = idx + 5
        msg_len = pkt_len - padding - 1
        if msg_len < 1 or msg_offset + msg_len > max_len:
            break
        msg_type = payload[msg_offset]
        reason: Optional[int] = None
        if msg_type == 1 and msg_offset + 5 <= max_len:
            reason = int.from_bytes(payload[msg_offset + 1 : msg_offset + 5], "big")
        msg_payload = payload[msg_offset : msg_offset + msg_len]
        messages.append((msg_type, reason, msg_payload))
        idx += 4 + pkt_len
    return messages


def _read_uint32(data: bytes, offset: int) -> tuple[Optional[int], int]:
    if offset + 4 > len(data):
        return None, offset
    value = int.from_bytes(data[offset : offset + 4], "big")
    return value, offset + 4


def _read_string(data: bytes, offset: int) -> tuple[Optional[bytes], int]:
    length, offset = _read_uint32(data, offset)
    if length is None:
        return None, offset
    if length < 0 or offset + length > len(data):
        return None, offset
    return data[offset : offset + length], offset + length


def _parse_kexinit(msg_payload: bytes) -> Optional[dict[str, list[str]]]:
    if not msg_payload or msg_payload[0] != 20:
        return None
    offset = 1 + 16  # skip message type + cookie
    fields: list[list[str]] = []
    for _ in range(10):
        raw, offset = _read_string(msg_payload, offset)
        if raw is None:
            return None
        text = raw.decode("utf-8", errors="ignore")
        fields.append([item for item in text.split(",") if item])
    return {
        "kex": fields[0],
        "hostkey": fields[1],
        "enc_c2s": fields[2],
        "enc_s2c": fields[3],
        "mac_c2s": fields[4],
        "mac_s2c": fields[5],
        "comp_c2s": fields[6],
        "comp_s2c": fields[7],
        "lang_c2s": fields[8],
        "lang_s2c": fields[9],
    }


def _hassh_from_kex(kex: dict[str, list[str]], *, server: bool) -> tuple[str, str]:
    if server:
        parts = [
            ",".join(kex.get("kex", [])),
            ",".join(kex.get("hostkey", [])),
            ",".join(kex.get("enc_s2c", [])),
            ",".join(kex.get("mac_s2c", [])),
            ",".join(kex.get("comp_s2c", [])),
        ]
    else:
        parts = [
            ",".join(kex.get("kex", [])),
            ",".join(kex.get("hostkey", [])),
            ",".join(kex.get("enc_c2s", [])),
            ",".join(kex.get("mac_c2s", [])),
            ",".join(kex.get("comp_c2s", [])),
        ]
    hassh_str = ";".join(parts)
    hassh = hashlib.md5(hassh_str.encode("utf-8", errors="ignore")).hexdigest()
    return hassh, hassh_str


# Valid host-key algorithm name prefixes. A real host-key blob begins with one
# of these; used to validate that we parsed an actual host key and not, e.g.,
# the DH group-exchange prime carried by the same message number.
_HOSTKEY_TYPE_PREFIXES = (
    "ssh-rsa",
    "ssh-ed25519",
    "ssh-dss",
    "rsa-sha2-",
    "ecdsa-sha2-",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-",
)


def _parse_hostkey_fingerprint(
    msg_payload: bytes,
) -> tuple[Optional[str], Optional[str]]:
    # The host key (K_S) is the first field of KEXDH_REPLY / KEX_ECDH_REPLY
    # (msg 31) and KEX_DH_GEX_REPLY (msg 33). Message number 31 is overloaded:
    # under diffie-hellman-group-exchange it is KEX_DH_GEX_GROUP and carries the
    # prime p (which sshd randomizes per connection), NOT a host key -- so the
    # blob is only accepted when its first string is a known host-key algorithm.
    if not msg_payload or msg_payload[0] not in (31, 33):
        return None, None
    offset = 1
    hostkey_blob, offset = _read_string(msg_payload, offset)
    if not hostkey_blob:
        return None, None
    key_type_blob, _ = _read_string(hostkey_blob, 0)
    if not key_type_blob:
        return None, None
    key_type = key_type_blob.decode("utf-8", errors="ignore")
    if not any(
        key_type == prefix or key_type.startswith(prefix)
        for prefix in _HOSTKEY_TYPE_PREFIXES
    ):
        return None, None
    digest = hashlib.sha256(hostkey_blob).digest()
    fingerprint = "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
    return key_type, fingerprint


def _parse_userauth_request(msg_payload: bytes) -> tuple[Optional[str], Optional[str]]:
    if not msg_payload or msg_payload[0] != 50:
        return None, None
    offset = 1
    user_raw, offset = _read_string(msg_payload, offset)
    if user_raw is None:
        return None, None
    _service_raw, offset = _read_string(msg_payload, offset)
    method_raw, _offset = _read_string(msg_payload, offset)
    username = user_raw.decode("utf-8", errors="ignore") if user_raw else None
    method = method_raw.decode("utf-8", errors="ignore") if method_raw else None
    return username or None, method or None


def _parse_channel_data(msg_payload: bytes) -> Optional[bytes]:
    if not msg_payload:
        return None
    msg_type = msg_payload[0]
    offset = 1
    if msg_type == 94:
        # SSH_MSG_CHANNEL_DATA
        _recipient, offset = _read_uint32(msg_payload, offset)
        data, _offset = _read_string(msg_payload, offset)
        return data
    if msg_type == 95:
        # SSH_MSG_CHANNEL_EXTENDED_DATA
        _recipient, offset = _read_uint32(msg_payload, offset)
        _dtype, offset = _read_uint32(msg_payload, offset)
        data, _offset = _read_string(msg_payload, offset)
        return data
    return None


def _parse_decrypted_ssh_messages(
    payload: bytes,
) -> list[tuple[int, Optional[int], bytes]]:
    messages = _parse_ssh_messages(payload)
    if messages:
        return messages
    if not payload:
        return []
    msg_type = payload[0]
    if msg_type not in SSH_MESSAGE_TYPES:
        return []
    reason: Optional[int] = None
    if msg_type == 1 and len(payload) >= 5:
        reason = int.from_bytes(payload[1:5], "big")
    return [(msg_type, reason, payload)]


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
        payload = decrypted_payloads.get(pkt_index)
        payload = _coerce_decrypted_payload(payload)
        if payload:
            return payload, "parameter"
    if hasattr(pkt, "pcapper_ssh_decrypted"):
        payload = _coerce_decrypted_payload(getattr(pkt, "pcapper_ssh_decrypted", None))
        if payload:
            return payload, "packet"
    if meta is None:
        return None, None
    candidate = None
    if isinstance(meta, dict):
        candidate = meta.get("ssh_decrypted") or meta.get("ssh_decrypted_packets")
    else:
        candidate = getattr(meta, "ssh_decrypted", None) or getattr(
            meta, "ssh_decrypted_packets", None
        )
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


@memoize_analysis
def analyze_ssh(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
    decrypted_payloads: dict[int, bytes] | None = None,
) -> SshSummary:
    errors: list[str] = []
    if TCP is None or (IP is None and IPv6 is None):
        errors.append(
            "Scapy IP/TCP layers unavailable; install scapy for SSH analysis."
        )
        return SshSummary(
            path=path,
            total_packets=0,
            ssh_packets=0,
            total_bytes=0,
            client_packets=0,
            server_packets=0,
            client_bytes=0,
            server_bytes=0,
            total_sessions=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            client_macs=Counter(),
            server_macs=Counter(),
            ip_to_macs={},
            server_ports=Counter(),
            client_versions=Counter(),
            server_versions=Counter(),
            client_software=Counter(),
            server_software=Counter(),
            auth_methods=Counter(),
            auth_usernames=Counter(),
            auth_evidence=[],
            kex_algorithms=Counter(),
            host_key_algorithms=Counter(),
            cipher_algorithms=Counter(),
            mac_algorithms=Counter(),
            compression_algorithms=Counter(),
            client_hassh=Counter(),
            server_hassh=Counter(),
            client_hassh_strings={},
            server_hassh_strings={},
            host_key_fingerprints=Counter(),
            host_key_types=Counter(),
            message_types=Counter(),
            client_message_types=Counter(),
            server_message_types=Counter(),
            request_counts=Counter(),
            response_counts=Counter(),
            disconnect_reasons=Counter(),
            plaintext_strings=Counter(),
            suspicious_plaintext=Counter(),
            file_artifacts=Counter(),
            device_fingerprints=Counter(),
            conversations=[],
            auth_attempts_by_client=Counter(),
            auth_failures_by_client=Counter(),
            auth_successes_by_client=Counter(),
            detections=[],
            anomalies=[],
            artifacts=[],
            errors=errors,
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
            analysis_notes=[],
            auth_inference=[],
        )

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, packets=packets, meta=meta, show_status=show_status
    )

    total_packets = 0
    ssh_packets = 0
    total_bytes = 0
    client_packets = 0
    server_packets = 0
    client_bytes = 0
    server_bytes = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    sessions: dict[tuple[str, int, str, int], _SessionState] = {}
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    client_macs: Counter[str] = Counter()
    server_macs: Counter[str] = Counter()
    ip_to_macs: dict[str, set[str]] = defaultdict(set)
    server_ports: Counter[int] = Counter()

    client_versions: Counter[str] = Counter()
    server_versions: Counter[str] = Counter()
    client_software: Counter[str] = Counter()
    server_software: Counter[str] = Counter()
    auth_usernames: Counter[str] = Counter()
    auth_evidence: list[dict[str, object]] = []
    auth_evidence_seen: set[tuple[str, str, int, int, str, str]] = set()

    message_types: Counter[str] = Counter()
    client_message_types: Counter[str] = Counter()
    server_message_types: Counter[str] = Counter()
    request_counts: Counter[str] = Counter()
    response_counts: Counter[str] = Counter()
    disconnect_reasons: Counter[str] = Counter()
    client_hassh: Counter[str] = Counter()
    server_hassh: Counter[str] = Counter()
    client_hassh_strings: dict[str, str] = {}
    server_hassh_strings: dict[str, str] = {}
    host_key_fingerprints: Counter[str] = Counter()
    host_key_types: Counter[str] = Counter()

    plaintext_strings: Counter[str] = Counter()
    suspicious_plaintext: Counter[str] = Counter()
    file_artifacts: Counter[str] = Counter()
    device_fingerprints: Counter[str] = Counter()
    artifacts: list[str] = []
    analysis_notes: list[str] = [
        "SSH handshake (banner/KEXINIT/host key) is parsed in the clear; user-auth and channel data are encrypted.",
        "Auth outcomes are INFERRED from post-handshake traffic volume (Zeek-style); exact usernames/methods need decrypted traffic.",
    ]

    algo_counters: dict[str, Counter[str]] = {
        "kex": Counter(),
        "hostkey": Counter(),
        "cipher": Counter(),
        "mac": Counter(),
        "comp": Counter(),
        "auth": Counter(),
    }

    short_session_counts: Counter[tuple[str, str]] = Counter()
    short_session_by_client: Counter[str] = Counter()
    short_session_targets: dict[str, set[str]] = defaultdict(set)
    pair_first_seen: dict[tuple[str, str], list[float]] = defaultdict(list)
    auth_attempts_by_client: Counter[str] = Counter()
    auth_failures_by_client: Counter[str] = Counter()
    auth_successes_by_client: Counter[str] = Counter()

    # Per (client, server) auth-outcome inference from encrypted sessions.
    auth_pairs: dict[tuple[str, str], dict[str, object]] = {}
    # Terrapin (CVE-2023-48795) per (client, server) -> vulnerable cipher modes.
    terrapin_pairs: dict[tuple[str, str], list[str]] = {}
    # (server_ip, server_port) -> {key_type -> {fingerprints}} for host-key-change
    # detection. Keyed by port too so two distinct SSH services on one host are
    # not mistaken for a single server changing its key.
    server_host_keys: dict[tuple[str, int], dict[str, set[str]]] = defaultdict(
        lambda: defaultdict(set)
    )

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
            pkt_len = packet_length(pkt)
            total_bytes += pkt_len

            if TCP is None or not pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                continue

            src_ip, dst_ip = extract_packet_endpoints(pkt)
            if not src_ip or not dst_ip:
                continue

            tcp = pkt[TCP]  # type: ignore[index]
            sport = int(getattr(tcp, "sport", 0) or 0)
            dport = int(getattr(tcp, "dport", 0) or 0)

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

            decrypted_payload, decrypt_source = _find_decrypted_payload(
                pkt, meta, pkt_index, decrypted_payloads
            )
            if decrypt_source:
                decrypted_sources.add(decrypt_source)

            is_ssh = sport in SSH_PORTS or dport in SSH_PORTS or b"SSH-" in payload[:32]
            if not is_ssh and not decrypted_payload:
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
            if eth_src and src_ip:
                ip_to_macs[src_ip].add(eth_src.lower())
            if eth_dst and dst_ip:
                ip_to_macs[dst_ip].add(eth_dst.lower())
            if eth_src and src_ip == client_ip:
                client_macs[eth_src.lower()] += 1
            if eth_dst and dst_ip == server_ip:
                server_macs[eth_dst.lower()] += 1

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
            if session.client_mac is None and eth_src and src_ip == client_ip:
                session.client_mac = eth_src.lower()
            if session.server_mac is None and eth_dst and dst_ip == server_ip:
                session.server_mac = eth_dst.lower()
            session.packets += 1
            session.bytes += pkt_len
            # Length of the TCP application payload (0 for pure ACKs). Used to
            # measure the encrypted post-KEX data volume for auth inference.
            app_len = len(payload) if payload else 0
            if src_ip == client_ip:
                session.client_packets += 1
                session.client_bytes += pkt_len
                client_packets += 1
                client_bytes += pkt_len
                if session.saw_newkeys and app_len:
                    session.post_kex_client_bytes += app_len
                    session.post_kex_client_pkts += 1
            else:
                session.server_packets += 1
                session.server_bytes += pkt_len
                server_packets += 1
                server_bytes += pkt_len
                if session.saw_newkeys and app_len:
                    session.post_kex_server_bytes += app_len
                    session.post_kex_server_pkts += 1
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
                    session.saw_banner = True
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

            parsed_messages: list[tuple[int, Optional[int], bytes]] = []
            decrypted_active = False
            if decrypted_payload:
                parsed_messages = _parse_decrypted_ssh_messages(decrypted_payload)
                if parsed_messages:
                    decrypted_active = True
            if not parsed_messages and payload and not session.saw_newkeys:
                candidates = _parse_ssh_messages(payload)
                if candidates:
                    trusted = session.saw_banner
                    if not trusted:
                        for msg_type, _reason, _msg_payload in candidates:
                            if msg_type in {5, 6, 20, 21, 30, 31}:
                                trusted = True
                                break
                    if trusted:
                        parsed_messages = candidates

            kex_parsed = False
            if parsed_messages:
                for msg_type, reason, msg_payload in parsed_messages:
                    name = SSH_MESSAGE_TYPES.get(msg_type, f"SSH_MSG_{msg_type}")
                    message_types[name] += 1
                    if msg_type == 20:
                        session.saw_kexinit = True
                        kex = _parse_kexinit(msg_payload)
                        if kex:
                            kex_parsed = True
                            if src_ip == client_ip:
                                session.client_kex = kex
                                hassh, hassh_str = _hassh_from_kex(kex, server=False)
                                client_hassh[hassh] += 1
                                client_hassh_strings.setdefault(hassh, hassh_str)
                            else:
                                session.server_kex = kex
                                hassh, hassh_str = _hassh_from_kex(kex, server=True)
                                server_hassh[hassh] += 1
                                server_hassh_strings.setdefault(hassh, hassh_str)
                            for item in kex.get("kex", []):
                                algo_counters["kex"][item] += 1
                            for item in kex.get("hostkey", []):
                                algo_counters["hostkey"][item] += 1
                            for item in kex.get("enc_c2s", []):
                                algo_counters["cipher"][item] += 1
                            for item in kex.get("enc_s2c", []):
                                algo_counters["cipher"][item] += 1
                            for item in kex.get("mac_c2s", []):
                                algo_counters["mac"][item] += 1
                            for item in kex.get("mac_s2c", []):
                                algo_counters["mac"][item] += 1
                            for item in kex.get("comp_c2s", []):
                                algo_counters["comp"][item] += 1
                            for item in kex.get("comp_s2c", []):
                                algo_counters["comp"][item] += 1
                    if msg_type in (31, 33):
                        key_type, fingerprint = _parse_hostkey_fingerprint(msg_payload)
                        if fingerprint:
                            host_key_fingerprints[fingerprint] += 1
                            if key_type:
                                host_key_types[key_type] += 1
                            # KEXDH_REPLY comes from the server; record which host
                            # key(s) this server presented, keyed by key type, so a
                            # changed key (same type, different fingerprint) flags a
                            # possible MITM / host-key rotation.
                            server_host_keys[(server_ip, session.server_port)][
                                key_type or "?"
                            ].add(fingerprint)
                    if msg_type == 50 and decrypted_active:
                        username, method = _parse_userauth_request(msg_payload)
                        if method:
                            algo_counters["auth"][method] += 1
                        if username:
                            auth_usernames[username] += 1
                            key = (
                                client_ip,
                                server_ip,
                                session.client_port,
                                session.server_port,
                                username,
                                method or "-",
                            )
                            if key not in auth_evidence_seen:
                                auth_evidence_seen.add(key)
                                auth_evidence.append(
                                    {
                                        "client_ip": client_ip,
                                        "server_ip": server_ip,
                                        "client_port": session.client_port,
                                        "server_port": session.server_port,
                                        "username": username,
                                        "method": method or "-",
                                    }
                                )
                    if src_ip == client_ip:
                        client_message_types[name] += 1
                        if name in REQUEST_TYPES:
                            request_counts[name] += 1
                    else:
                        server_message_types[name] += 1
                        if name in RESPONSE_TYPES:
                            response_counts[name] += 1
                        if msg_type == 51 and decrypted_active:
                            session.auth_failures += 1
                            auth_failures_by_client[client_ip] += 1
                        if msg_type == 52 and decrypted_active:
                            session.auth_successes += 1
                            auth_successes_by_client[client_ip] += 1
                    if msg_type == 50 and src_ip == client_ip and decrypted_active:
                        auth_attempts_by_client[client_ip] += 1
                    if msg_type == 1 and reason is not None:
                        disconnect_reasons[
                            SSH_DISCONNECT_REASONS.get(reason, f"Reason {reason}")
                        ] += 1
                    if msg_type == 21:
                        session.saw_newkeys = True
                        break

            if (
                text
                and not session.saw_newkeys
                and (session.saw_banner or session.saw_kexinit)
                and not kex_parsed
            ):
                _scan_algorithms(text, algo_counters)
            # NOTE: SSHv2 carries NO application data before encryption -- the
            # only pre-NEWKEYS traffic is the version banner and the binary
            # key-exchange (KEXINIT/KEXDH). Scanning that for "plaintext
            # indicators" only ever surfaced the algorithm name-lists (and their
            # length-prefix bytes) as noise, and matched host-key *algorithm*
            # names as fake "key material". Real credentials/keys/commands appear
            # only in DECRYPTED channel data, so plaintext scanning runs there.
            if decrypted_active:
                for msg_type, _reason, msg_payload in parsed_messages:
                    data = _parse_channel_data(msg_payload)
                    if data:
                        _scan_plaintext(
                            data,
                            plaintext_strings,
                            suspicious_plaintext,
                            file_artifacts,
                            artifacts,
                        )

    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        reader.close()

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    for version, count in client_versions.items():
        for detail in device_fingerprints_from_text(
            version, source="SSH client banner"
        ):
            device_fingerprints[detail] += count
    for version, count in server_versions.items():
        for detail in device_fingerprints_from_text(
            version, source="SSH server banner"
        ):
            device_fingerprints[detail] += count
    for software, count in client_software.items():
        for detail in device_fingerprints_from_text(
            software, source="SSH client software"
        ):
            device_fingerprints[detail] += count
    for software, count in server_software.items():
        for detail in device_fingerprints_from_text(
            software, source="SSH server software"
        ):
            device_fingerprints[detail] += count

    conversations: list[SshConversation] = []
    for session in sessions.values():
        conversations.append(
            SshConversation(
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
                client_version=session.client_version,
                server_version=session.server_version,
                auth_failures=session.auth_failures,
                auth_successes=session.auth_successes,
            )
        )
        if session.packets <= 6 and session.bytes < 2000:
            short_session_counts[(session.client_ip, session.server_ip)] += 1
            short_session_by_client[session.client_ip] += 1
            short_session_targets[session.client_ip].add(session.server_ip)
        if session.first_seen is not None:
            pair_first_seen[(session.client_ip, session.server_ip)].append(
                session.first_seen
            )

        pair = (session.client_ip, session.server_ip)
        # Auth-outcome inference (encrypted): tally per client->server pair.
        outcome = _classify_session_auth(session)
        stats = auth_pairs.get(pair)
        if stats is None:
            stats = {
                "sessions": 0,
                "reached_kex": 0,
                "failed": 0,
                "established": 0,
                "no_kex": 0,
                "client_software": Counter(),
                "first_seen": session.first_seen,
                "last_seen": session.last_seen,
                "server_port": session.server_port,
            }
            auth_pairs[pair] = stats
        stats["sessions"] = int(stats["sessions"]) + 1  # type: ignore[arg-type]
        if outcome == "no-kex":
            stats["no_kex"] = int(stats["no_kex"]) + 1  # type: ignore[arg-type]
        else:
            stats["reached_kex"] = int(stats["reached_kex"]) + 1  # type: ignore[arg-type]
        if outcome == "failed-or-short":
            stats["failed"] = int(stats["failed"]) + 1  # type: ignore[arg-type]
        elif outcome == "established":
            stats["established"] = int(stats["established"]) + 1  # type: ignore[arg-type]
        software = _software_from_version(session.client_version)
        if software:
            stats["client_software"][software] += 1  # type: ignore[index]
        if session.first_seen is not None:
            if stats["first_seen"] is None or session.first_seen < float(stats["first_seen"]):  # type: ignore[arg-type]
                stats["first_seen"] = session.first_seen
        if session.last_seen is not None:
            if stats["last_seen"] is None or session.last_seen > float(stats["last_seen"]):  # type: ignore[arg-type]
                stats["last_seen"] = session.last_seen

        # Terrapin assessment per session; keep the worst (any vulnerable) hit.
        terrapin = _terrapin_assessment(session.client_kex, session.server_kex)
        if terrapin and pair not in terrapin_pairs:
            terrapin_pairs[pair] = terrapin

    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []
    auth_inference: list[dict[str, object]] = []

    def _span(first: object, last: object) -> Optional[float]:
        if first is None or last is None:
            return None
        return max(0.0, float(last) - float(first))  # type: ignore[arg-type]

    # --- Authentication outcome inference (encrypted, Zeek-style) --------------
    # SSH user-auth is encrypted, so brute force is inferred from many sessions
    # that complete key exchange and then end immediately (failed/aborted login)
    # vs. sessions that sustain data (successful, interactive/exec session).
    sweep_by_client: dict[str, dict[str, object]] = {}
    for (client_ip, server_ip), st in auth_pairs.items():
        sessions_n = int(st["sessions"])  # type: ignore[arg-type]
        reached = int(st["reached_kex"])  # type: ignore[arg-type]
        failed = int(st["failed"])  # type: ignore[arg-type]
        established = int(st["established"])  # type: ignore[arg-type]
        port = int(st["server_port"])  # type: ignore[arg-type]
        sw_counter = st["client_software"]  # type: ignore[assignment]
        top_sw = sw_counter.most_common(1)[0][0] if sw_counter else None  # type: ignore[union-attr]
        span = _span(st["first_seen"], st["last_seen"])

        if sessions_n >= 3 or established or failed >= 2:
            auth_inference.append(
                {
                    "client": client_ip,
                    "server": server_ip,
                    "port": port,
                    "sessions": sessions_n,
                    "likely_failed": failed,
                    "likely_success": established,
                    "client_software": top_sw or "-",
                    "verdict": (
                        "brute-force+success"
                        if (failed >= 5 and established)
                        else "brute-force"
                        if failed >= 5
                        else "established"
                        if established
                        else "attempts"
                    ),
                }
            )

        sc = sweep_by_client.setdefault(
            client_ip,
            {"servers": set(), "failed_servers": set(), "sessions": 0},
        )
        sc["servers"].add(server_ip)  # type: ignore[union-attr]
        sc["sessions"] = int(sc["sessions"]) + sessions_n  # type: ignore[arg-type]
        if failed >= 1 and established == 0:
            sc["failed_servers"].add(server_ip)  # type: ignore[union-attr]

        # Per-target brute force: many auth sessions ending right after KEX.
        if reached >= 5 and failed >= 5:
            evidence = [
                f"{sessions_n} SSH sessions {client_ip} -> {server_ip}:{port}",
                f"{failed} ended immediately after key exchange (likely failed/aborted auth)",
            ]
            if established:
                evidence.append(
                    f"{established} session(s) then sustained data (LIKELY SUCCESSFUL login)"
                )
            if top_sw:
                evidence.append(f"client software: {top_sw}")
            if span:
                evidence.append(f"window: {span:.0f}s")
            if established >= 1:
                detections.append(
                    {
                        "severity": "high",
                        "summary": "Likely successful SSH brute force / credential compromise",
                        "details": (
                            f"{client_ip} -> {server_ip}:{port}: {failed} failed-looking "
                            f"auth sessions followed by {established} established session(s)."
                        ),
                        "confidence": "medium",
                        "mitre": "T1110 Brute Force; T1021.004 Remote Services: SSH",
                        "evidence": evidence,
                        "client_ip": client_ip,
                        "server_ip": server_ip,
                    }
                )
            else:
                detections.append(
                    {
                        "severity": "warning",
                        "summary": "Possible SSH brute force (inferred from encrypted sessions)",
                        "details": (
                            f"{client_ip} -> {server_ip}:{port}: {failed} of {sessions_n} "
                            "sessions ended right after key exchange with no established session."
                        ),
                        "confidence": "medium",
                        "mitre": "T1110 Brute Force",
                        "evidence": evidence,
                        "client_ip": client_ip,
                        "server_ip": server_ip,
                    }
                )

    # Horizontal sweep: one source attempting auth against many SSH servers.
    for client_ip, sc in sweep_by_client.items():
        failed_servers = sc["failed_servers"]  # type: ignore[assignment]
        if len(failed_servers) >= 10:  # type: ignore[arg-type]
            sample = ", ".join(sorted(failed_servers)[:8])  # type: ignore[arg-type]
            detections.append(
                {
                    "severity": "warning",
                    "summary": "SSH authentication sweep across many hosts",
                    "details": (
                        f"{client_ip} attempted SSH auth against {len(failed_servers)} "  # type: ignore[arg-type]
                        "servers with no established session."
                    ),
                    "confidence": "medium",
                    "mitre": "T1110 Brute Force; T1021.004 Remote Services: SSH; T1046 Network Service Discovery",
                    "evidence": [
                        f"source: {client_ip}",
                        f"{len(failed_servers)} target servers (no successful session)",  # type: ignore[arg-type]
                        f"targets: {sample}",
                    ],
                    "client_ip": client_ip,
                }
            )

    # --- Terrapin (CVE-2023-48795) --------------------------------------------
    if terrapin_pairs:
        modes: set[str] = set()
        for vuln in terrapin_pairs.values():
            modes.update(vuln)
        pair_list = [
            f"{c} -> {s} ({', '.join(v)})" for (c, s), v in list(terrapin_pairs.items())[:8]
        ]
        detections.append(
            {
                "severity": "warning",
                "summary": "Terrapin-vulnerable SSH handshake (CVE-2023-48795)",
                "details": (
                    "Vulnerable cipher mode negotiated without strict key exchange "
                    "(kex-strict-*-v00@openssh.com absent) — exposed to prefix-truncation/downgrade."
                ),
                "confidence": "high",
                "mitre": "T1557 Adversary-in-the-Middle (CVE-2023-48795)",
                "evidence": [f"{len(terrapin_pairs)} handshake(s) affected"]
                + [f"modes: {', '.join(sorted(modes))}"]
                + pair_list,
            }
        )

    # --- Host key change (possible MITM / key rotation) -----------------------
    for (server_ip, server_port), by_type in server_host_keys.items():
        for ktype, fps in by_type.items():
            if len(fps) > 1:
                detections.append(
                    {
                        "severity": "high",
                        "summary": "SSH host key changed during capture (possible MITM)",
                        "details": (
                            f"Server {server_ip}:{server_port} presented {len(fps)} "
                            f"different {ktype} host keys for the same service."
                        ),
                        "confidence": "medium",
                        "mitre": "T1557 Adversary-in-the-Middle",
                        "evidence": [
                            f"server: {server_ip}:{server_port}",
                            f"key type: {ktype}",
                        ]
                        + sorted(fps),
                        "server_ip": server_ip,
                    }
                )

    # --- Egress / internal->external SSH (tunneling / exfil / C2) --------------
    egress: dict[str, dict[str, object]] = {}
    for conv in conversations:
        if is_private_ip(conv.client_ip) and is_public_ip(conv.server_ip):
            row = egress.setdefault(
                conv.server_ip,
                {"sessions": 0, "bytes_out": 0, "ports": set(), "clients": set()},
            )
            row["sessions"] = int(row["sessions"]) + 1  # type: ignore[arg-type]
            row["bytes_out"] = int(row["bytes_out"]) + conv.client_bytes  # type: ignore[arg-type]
            row["ports"].add(conv.server_port)  # type: ignore[union-attr]
            row["clients"].add(conv.client_ip)  # type: ignore[union-attr]
    if egress:
        ev = []
        for server_ip, row in sorted(
            egress.items(), key=lambda kv: int(kv[1]["bytes_out"]), reverse=True  # type: ignore[arg-type]
        )[:8]:
            ports = ",".join(str(p) for p in sorted(row["ports"]))  # type: ignore[union-attr]
            ev.append(
                f"{server_ip}:{ports} <- {len(row['clients'])} host(s), "  # type: ignore[union-attr]
                f"{int(row['sessions'])} session(s), "
                f"{int(row['bytes_out']) / 1024:.1f} KB out"
            )
        detections.append(
            {
                "severity": "warning",
                "summary": "Outbound SSH from internal host to external server",
                "details": (
                    f"{len(egress)} external SSH destination(s) reached from internal "
                    "hosts — review for tunneling, exfiltration, or unsanctioned remote access."
                ),
                "confidence": "medium",
                "mitre": "T1048 Exfiltration Over Alternative Protocol; T1572 Protocol Tunneling; T1021.004 Remote Services: SSH",
                "evidence": ev,
            }
        )

    # --- Non-standard port ----------------------------------------------------
    non_standard_ports = [port for port in server_ports if port not in SSH_PORTS]
    if non_standard_ports:
        port_ev = [
            f"port {port}: {server_ports[port]} packet(s)"
            for port in sorted(non_standard_ports)
        ]
        detections.append(
            {
                "severity": "warning",
                "summary": "SSH on non-standard port (possible evasion/tunnel)",
                "details": (
                    "SSH handshake observed on "
                    + ", ".join(str(port) for port in sorted(non_standard_ports))
                    + " — non-standard SSH ports are used to evade egress filtering and IDS."
                ),
                "confidence": "high",
                "mitre": "T1571 Non-Standard Port; T1572 Protocol Tunneling",
                "evidence": port_ev,
            }
        )

    legacy_versions = [
        v
        for v in list(client_versions.keys()) + list(server_versions.keys())
        if v.startswith("SSH-1.") or v.startswith("SSH-1.99")
    ]
    if legacy_versions:
        detections.append(
            {
                "severity": "warning",
                "summary": "Legacy/insecure SSH protocol version offered",
                "details": (
                    "SSH-1.x / 1.99 is cryptographically broken (MITM, key recovery). "
                    "A 1.99 banner means the endpoint still accepts SSHv1."
                ),
                "confidence": "high",
                "mitre": "T1040 Network Sniffing; T1557 Adversary-in-the-Middle",
                "evidence": sorted(set(legacy_versions)),
            }
        )

    weak_algos = [algo for algo in algo_counters["kex"] if algo in WEAK_ALGOS]
    weak_algos += [algo for algo in algo_counters["cipher"] if algo in WEAK_ALGOS]
    weak_algos += [algo for algo in algo_counters["mac"] if algo in WEAK_ALGOS]
    weak_algos += [algo for algo in algo_counters["hostkey"] if algo in WEAK_ALGOS]
    if weak_algos:
        detections.append(
            {
                "severity": "info",
                "summary": "Weak SSH algorithms offered",
                "details": (
                    "Obsolete/broken algorithms present in a KEXINIT name-list "
                    "(offered, not necessarily negotiated)."
                ),
                "confidence": "low",
                "mitre": "T1040 Network Sniffing",
                "evidence": sorted(set(weak_algos)),
            }
        )

    if suspicious_plaintext and (
        algo_counters["auth"] or auth_usernames or decrypted_sources
    ):
        detections.append(
            {
                "severity": "warning",
                "summary": "Suspicious plaintext strings observed in SSH payloads",
                "details": "Potential credentials, keys, or tooling references in cleartext.",
                "confidence": "medium",
                "mitre": "T1552 Unsecured Credentials",
                "evidence": [
                    _truncate_plain(text)
                    for text, _c in suspicious_plaintext.most_common(6)
                ],
            }
        )

    # --- Auth outcomes from DECRYPTED traffic (when keys provided) -------------
    for client_ip, failures in auth_failures_by_client.items():
        successes = auth_successes_by_client.get(client_ip, 0)
        if failures >= 25 and successes == 0:
            detections.append(
                {
                    "severity": "warning",
                    "summary": "SSH brute force (decrypted auth failures)",
                    "details": f"{client_ip} auth failures: {failures}",
                    "confidence": "high",
                    "mitre": "T1110 Brute Force",
                    "evidence": [f"{client_ip}: {failures} USERAUTH_FAILURE, 0 success"],
                    "client_ip": client_ip,
                }
            )
        elif failures >= 50 and successes > 0:
            detections.append(
                {
                    "severity": "high",
                    "summary": "SSH password spraying / brute force with success",
                    "details": f"{client_ip} auth failures: {failures}, successes: {successes}",
                    "confidence": "high",
                    "mitre": "T1110 Brute Force; T1021.004 Remote Services: SSH",
                    "evidence": [
                        f"{client_ip}: {failures} USERAUTH_FAILURE, {successes} USERAUTH_SUCCESS"
                    ],
                    "client_ip": client_ip,
                }
            )

    for (client_ip, server_ip), count in short_session_counts.items():
        if count >= 20:
            anomalies.append(
                {
                    "title": "Repeated short SSH sessions (brute force / scan)",
                    "details": f"{client_ip} -> {server_ip} short sessions: {count}",
                    "mitre": "T1110 Brute Force",
                }
            )

    for client_ip, count in short_session_by_client.items():
        targets = short_session_targets.get(client_ip, set())
        if count >= 30 and len(targets) >= 10:
            anomalies.append(
                {
                    "title": "Potential SSH scanning",
                    "details": f"{client_ip} short sessions: {count} across {len(targets)} servers",
                    "mitre": "T1046 Network Service Discovery",
                }
            )

    if disconnect_reasons:
        anomalies.append(
            {
                "title": "SSH disconnects observed",
                "details": ", ".join(
                    f"{reason}({count})"
                    for reason, count in disconnect_reasons.most_common(5)
                ),
            }
        )

    if decrypted_sources:
        source_text = ", ".join(sorted(decrypted_sources))
        analysis_notes.append(f"Decrypted SSH payloads provided via: {source_text}.")

    for (client_ip, server_ip), times in pair_first_seen.items():
        score = _beaconing_score(times)
        if score:
            # Beaconing to an EXTERNAL host is a strong C2 signal; periodic SSH to
            # an internal host is frequently benign automation (cron/monitoring/
            # backup), so down-rank it to informational.
            external = is_public_ip(server_ip)
            detections.append(
                {
                    "severity": "warning" if external else "info",
                    "summary": "Potential SSH beaconing (regular connection interval)",
                    "details": (
                        f"{client_ip} -> {server_ip} avg interval {score['avg']:.1f}s, "
                        f"stddev {score['stddev']:.1f}s"
                        + (" (external host)" if external else " (internal host)")
                    ),
                    "confidence": "medium" if external else "low",
                    "mitre": "T1071 Application Layer Protocol; T1572 Protocol Tunneling",
                    "evidence": [
                        f"{client_ip} -> {server_ip}"
                        + (" [external]" if external else " [internal]"),
                        f"{len(times)} connections",
                        f"avg interval {score['avg']:.1f}s (+/- {score['stddev']:.1f}s)",
                    ],
                    "client_ip": client_ip,
                    "server_ip": server_ip,
                }
            )

    for session in sessions.values():
        if (
            session.client_bytes >= 50 * 1024 * 1024
            and session.client_bytes > session.server_bytes * 3
        ):
            detections.append(
                {
                    "severity": "warning",
                    "summary": "Potential SSH data exfiltration (large outbound transfer)",
                    "details": (
                        f"{session.client_ip} -> {session.server_ip} "
                        f"outbound {session.client_bytes / (1024 * 1024):.1f} MB"
                    ),
                    "confidence": "medium",
                    "mitre": "T1048 Exfiltration Over Alternative Protocol; T1029 Scheduled Transfer",
                    "evidence": [
                        f"{session.client_ip}:{session.client_port} -> "
                        f"{session.server_ip}:{session.server_port}",
                        f"{session.client_bytes / (1024 * 1024):.1f} MB out / "
                        f"{session.server_bytes / (1024 * 1024):.1f} MB in",
                    ],
                    "client_ip": session.client_ip,
                    "server_ip": session.server_ip,
                }
            )
        if session.last_seen is not None and session.first_seen is not None:
            duration = session.last_seen - session.first_seen
            if duration >= 4 * 3600:
                anomalies.append(
                    {
                        "title": "Long-lived SSH session",
                        "details": (
                            f"{session.client_ip} -> {session.server_ip} "
                            f"duration {duration / 3600:.1f}h — review for persistent "
                            "tunnel / interactive C2"
                        ),
                        "mitre": "T1572 Protocol Tunneling",
                    }
                )

    # Flag scripted/library SSH clients (paramiko, Go, libssh, ...). One match
    # is logged per software string with the connection count so an analyst can
    # tell scripted automation/C2 from interactive OpenSSH/PuTTY admin sessions.
    for software, count in client_software.items():
        software_l = software.lower()
        label = next(
            (
                desc
                for marker, desc in SSH_AUTOMATION_CLIENTS.items()
                if marker in software_l
            ),
            None,
        )
        if label:
            detections.append(
                {
                    "severity": "info",
                    "summary": "Scripted/library SSH client",
                    "details": (
                        f"{software} — {label}; {count} connection(s). "
                        "Non-interactive SSH clients are common in automation but "
                        "also in brute-forcers, C2 and lateral-movement tooling."
                    ),
                    "confidence": "low",
                    "mitre": "T1021.004 Remote Services: SSH",
                    "evidence": [f"client banner software: {software}", f"{count} connection(s)"],
                }
            )

    # A scripted/library SSH *server* is a stronger signal — production SSH
    # daemons are OpenSSH/dropbear/Cisco, so a paramiko/AsyncSSH/Go/libssh
    # server banner points to a reverse-shell implant, honeypot, or custom tool.
    for software, count in server_software.items():
        software_l = software.lower()
        label = next(
            (
                desc
                for marker, desc in SSH_AUTOMATION_CLIENTS.items()
                if marker in software_l
            ),
            None,
        )
        if label:
            detections.append(
                {
                    "severity": "warning",
                    "summary": "Scripted/library SSH server (possible reverse shell/implant)",
                    "details": (
                        f"{software} — {label} acting as an SSH server; "
                        f"{count} connection(s). Production SSH servers are "
                        "OpenSSH/dropbear — a library server suggests a reverse "
                        "shell, custom implant, or honeypot."
                    ),
                    "confidence": "medium",
                    "mitre": "T1021.004 Remote Services: SSH; T1572 Protocol Tunneling",
                    "evidence": [
                        f"server banner software: {software}",
                        f"{count} connection(s)",
                    ],
                }
            )

    total_sessions = len(conversations)

    return SshSummary(
        path=path,
        total_packets=total_packets,
        ssh_packets=ssh_packets,
        total_bytes=total_bytes,
        client_packets=client_packets,
        server_packets=server_packets,
        client_bytes=client_bytes,
        server_bytes=server_bytes,
        total_sessions=total_sessions,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        client_macs=client_macs,
        server_macs=server_macs,
        ip_to_macs={key: sorted(value) for key, value in ip_to_macs.items()},
        server_ports=server_ports,
        client_versions=client_versions,
        server_versions=server_versions,
        client_software=client_software,
        server_software=server_software,
        auth_methods=algo_counters["auth"],
        auth_usernames=auth_usernames,
        auth_evidence=auth_evidence,
        kex_algorithms=algo_counters["kex"],
        host_key_algorithms=algo_counters["hostkey"],
        cipher_algorithms=algo_counters["cipher"],
        mac_algorithms=algo_counters["mac"],
        compression_algorithms=algo_counters["comp"],
        client_hassh=client_hassh,
        server_hassh=server_hassh,
        client_hassh_strings=client_hassh_strings,
        server_hassh_strings=server_hassh_strings,
        host_key_fingerprints=host_key_fingerprints,
        host_key_types=host_key_types,
        message_types=message_types,
        client_message_types=client_message_types,
        server_message_types=server_message_types,
        request_counts=request_counts,
        response_counts=response_counts,
        disconnect_reasons=disconnect_reasons,
        plaintext_strings=plaintext_strings,
        suspicious_plaintext=suspicious_plaintext,
        file_artifacts=file_artifacts,
        device_fingerprints=device_fingerprints,
        conversations=conversations,
        auth_attempts_by_client=auth_attempts_by_client,
        auth_failures_by_client=auth_failures_by_client,
        auth_successes_by_client=auth_successes_by_client,
        detections=detections,
        anomalies=anomalies,
        artifacts=artifacts,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
        analysis_notes=analysis_notes,
        auth_inference=auth_inference,
    )
