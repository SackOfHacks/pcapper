from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import re

from .pcap_cache import get_reader
from .utils import safe_float
from .device_detection import device_fingerprints_from_text

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


TELNET_PORTS = {23, 2323, 9923}

USERNAME_RE = re.compile(r"(?:login|user(name)?|username)\s*[:=]\s*(\S+)", re.IGNORECASE)
PASSWORD_RE = re.compile(r"(?:password|passwd|pass)\s*[:=]\s*(\S+)", re.IGNORECASE)

SUSPICIOUS_PLAINTEXT = [
    (re.compile(r"password\s*[:=]", re.IGNORECASE), "Credential indicator"),
    (re.compile(r"user(name)?\s*[:=]", re.IGNORECASE), "User indicator"),
    (re.compile(r"enable\s*$", re.IGNORECASE), "Privilege escalation prompt"),
    (re.compile(r"conf t|configure terminal", re.IGNORECASE), "Config mode entry"),
    (re.compile(r"wget\s+|curl\s+|tftp\s+", re.IGNORECASE), "File transfer tooling"),
    (re.compile(r"busybox|dropbear|mirai", re.IGNORECASE), "IoT malware marker"),
]

FILE_NAME_RE = re.compile(
    r"[\w\-.()\[\]/ ]+\.(?:exe|bin|elf|dll|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|rar|7z|tar|gz|tgz|txt|csv|log|ps1|sh|bat|py|js|jar|apk|iso|img)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class TelnetConversation:
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
    usernames: list[str]
    passwords: int


@dataclass(frozen=True)
class TelnetSummary:
    path: Path
    total_packets: int
    telnet_packets: int
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
    usernames: Counter[str]
    passwords: Counter[str]
    commands: Counter[str]
    plaintext_strings: Counter[str]
    suspicious_plaintext: Counter[str]
    file_artifacts: Counter[str]
    device_fingerprints: Counter[str]
    conversations: list[TelnetConversation]
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
            "telnet_packets": self.telnet_packets,
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
            "usernames": dict(self.usernames),
            "passwords": dict(self.passwords),
            "commands": dict(self.commands),
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
                    "usernames": list(conv.usernames),
                    "passwords": conv.passwords,
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
    usernames: Counter[str] = None  # type: ignore[assignment]
    passwords: Counter[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.usernames is None:
            self.usernames = Counter()
        if self.passwords is None:
            self.passwords = Counter()


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


def _strip_telnet_iac(payload: bytes) -> bytes:
    if not payload:
        return payload
    out = bytearray()
    i = 0
    length = len(payload)
    while i < length:
        b = payload[i]
        if b == 255:  # IAC
            if i + 1 >= length:
                break
            cmd = payload[i + 1]
            if cmd in {251, 252, 253, 254}:  # WILL/WONT/DO/DONT
                i += 3
                continue
            if cmd == 250:  # SB
                i += 2
                while i + 1 < length:
                    if payload[i] == 255 and payload[i + 1] == 240:
                        i += 2
                        break
                    i += 1
                continue
            i += 2
            continue
        out.append(b)
        i += 1
    return bytes(out)


def _scan_plaintext(
    payload: bytes,
    plaintext_counter: Counter[str],
    suspicious_counter: Counter[str],
    file_counter: Counter[str],
    artifacts: list[str],
    commands: Counter[str],
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
        if item.strip().startswith(("$", "#", ">")) or "whoami" in item.lower():
            commands[item.strip()] += 1
        if "login:" in item.lower() or "password:" in item.lower():
            artifacts.append(item)


def _direction(src_ip: str, dst_ip: str, sport: int, dport: int) -> tuple[str, str, int, int]:
    if dport in TELNET_PORTS:
        return src_ip, dst_ip, sport, dport
    if sport in TELNET_PORTS:
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


def analyze_telnet(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
) -> TelnetSummary:
    errors: list[str] = []
    if TCP is None or (IP is None and IPv6 is None):
        errors.append("Scapy IP/TCP layers unavailable; install scapy for Telnet analysis.")
        return TelnetSummary(
            path=path,
            total_packets=0,
            telnet_packets=0,
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
            usernames=Counter(),
            passwords=Counter(),
            commands=Counter(),
            plaintext_strings=Counter(),
            suspicious_plaintext=Counter(),
            file_artifacts=Counter(),
            device_fingerprints=Counter(),
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
    telnet_packets = 0
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
    usernames: Counter[str] = Counter()
    passwords: Counter[str] = Counter()
    commands: Counter[str] = Counter()

    plaintext_strings: Counter[str] = Counter()
    suspicious_plaintext: Counter[str] = Counter()
    file_artifacts: Counter[str] = Counter()
    device_fingerprints: Counter[str] = Counter()
    artifacts: list[str] = []

    short_session_counts: Counter[tuple[str, str]] = Counter()
    short_session_by_client: Counter[str] = Counter()
    short_session_targets: dict[str, set[str]] = defaultdict(set)
    pair_first_seen: dict[tuple[str, str], list[float]] = defaultdict(list)

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

            payload_prefix = payload[:16] if payload else b""
            is_telnet = (
                sport in TELNET_PORTS
                or dport in TELNET_PORTS
                or payload_prefix.startswith(b"\xff\xfb")
                or payload_prefix.startswith(b"\xff\xfd")
            )
            if not is_telnet:
                continue

            telnet_packets += 1
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

            clean_payload = _strip_telnet_iac(payload)
            text = ""
            if clean_payload:
                try:
                    text = clean_payload.decode("latin-1", errors="ignore")
                except Exception:
                    text = ""

            if text:
                user_match = USERNAME_RE.search(text)
                if user_match:
                    value = user_match.group(2)
                    session.usernames[value] += 1
                    usernames[value] += 1
                pass_match = PASSWORD_RE.search(text)
                if pass_match:
                    value = pass_match.group(1)
                    session.passwords[value] += 1
                    passwords[value] += 1
                _scan_plaintext(clean_payload, plaintext_strings, suspicious_plaintext, file_artifacts, artifacts, commands)

    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        reader.close()

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    for text, count in plaintext_strings.most_common(50):
        for detail in device_fingerprints_from_text(text, source="Telnet plaintext"):
            device_fingerprints[detail] += count

    conversations: list[TelnetConversation] = []
    for session in sessions.values():
        conversations.append(
            TelnetConversation(
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
                usernames=list(session.usernames.keys()),
                passwords=sum(session.passwords.values()),
            )
        )
        if session.packets <= 6 and session.bytes < 2000:
            short_session_counts[(session.client_ip, session.server_ip)] += 1
            short_session_by_client[session.client_ip] += 1
            short_session_targets[session.client_ip].add(session.server_ip)
        if session.first_seen is not None:
            pair_first_seen[(session.client_ip, session.server_ip)].append(session.first_seen)

    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []

    non_standard_ports = [port for port in server_ports if port not in {23, 2323}]
    if non_standard_ports:
        detections.append({
            "severity": "info",
            "summary": "Telnet observed on non-standard ports",
            "details": ", ".join(str(port) for port in sorted(non_standard_ports)),
        })

    if usernames or passwords:
        detections.append({
            "severity": "warning",
            "summary": "Cleartext Telnet credentials observed",
            "details": "Usernames and/or passwords were extracted from Telnet sessions.",
        })

    if suspicious_plaintext:
        detections.append({
            "severity": "warning",
            "summary": "Suspicious plaintext strings observed in Telnet payloads",
            "details": "Potential credentials, tooling, or sensitive strings in cleartext.",
        })

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
                "title": "Potential Telnet scanning",
                "details": f"{client_ip} short sessions: {count} across {len(targets)} servers",
            })

    for (client_ip, server_ip), times in pair_first_seen.items():
        score = _beaconing_score(times)
        if score:
            detections.append({
                "severity": "info",
                "summary": "Potential Telnet beaconing",
                "details": f"{client_ip} -> {server_ip} avg interval {score['avg']:.1f}s, stddev {score['stddev']:.1f}s",
            })

    for session in sessions.values():
        if session.client_bytes >= 50 * 1024 * 1024 and session.client_bytes > session.server_bytes * 3:
            detections.append({
                "severity": "warning",
                "summary": "Potential Telnet data upload/exfiltration",
                "details": (
                    f"{session.client_ip} -> {session.server_ip} "
                    f"client->server {session.client_bytes / (1024 * 1024):.1f} MB"
                ),
            })
        if session.last_seen is not None and session.first_seen is not None:
            duration = session.last_seen - session.first_seen
            if duration >= 4 * 3600:
                anomalies.append({
                    "title": "Long-lived Telnet session",
                    "details": f"{session.client_ip} -> {session.server_ip} duration {duration:.0f}s",
                })

    total_sessions = len(conversations)

    return TelnetSummary(
        path=path,
        total_packets=total_packets,
        telnet_packets=telnet_packets,
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
        usernames=usernames,
        passwords=passwords,
        commands=commands,
        plaintext_strings=plaintext_strings,
        suspicious_plaintext=suspicious_plaintext,
        file_artifacts=file_artifacts,
        device_fingerprints=device_fingerprints,
        conversations=conversations,
        detections=detections,
        anomalies=anomalies,
        artifacts=artifacts,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )


def merge_telnet_summaries(
    summaries: list[TelnetSummary] | tuple[TelnetSummary, ...] | set[TelnetSummary],
) -> TelnetSummary:
    summary_list = list(summaries)
    if not summary_list:
        return TelnetSummary(
            path=Path("ALL_PCAPS_0"),
            total_packets=0,
            telnet_packets=0,
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
            usernames=Counter(),
            passwords=Counter(),
            commands=Counter(),
            plaintext_strings=Counter(),
            suspicious_plaintext=Counter(),
            file_artifacts=Counter(),
            device_fingerprints=Counter(),
            conversations=[],
            detections=[],
            anomalies=[],
            artifacts=[],
            errors=[],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    total_packets = 0
    telnet_packets = 0
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
    usernames: Counter[str] = Counter()
    passwords: Counter[str] = Counter()
    commands: Counter[str] = Counter()
    plaintext_strings: Counter[str] = Counter()
    suspicious_plaintext: Counter[str] = Counter()
    file_artifacts: Counter[str] = Counter()
    device_fingerprints: Counter[str] = Counter()
    conversations: list[TelnetConversation] = []
    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []
    artifacts: list[str] = []
    errors: list[str] = []

    for summary in summary_list:
        total_packets += summary.total_packets
        telnet_packets += summary.telnet_packets
        total_bytes += summary.total_bytes
        client_packets += summary.client_packets
        server_packets += summary.server_packets
        client_bytes += summary.client_bytes
        server_bytes += summary.server_bytes
        total_sessions += summary.total_sessions

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
        server_ports.update(summary.server_ports)
        usernames.update(summary.usernames)
        passwords.update(summary.passwords)
        commands.update(summary.commands)
        plaintext_strings.update(summary.plaintext_strings)
        suspicious_plaintext.update(summary.suspicious_plaintext)
        file_artifacts.update(summary.file_artifacts)
        device_fingerprints.update(summary.device_fingerprints)
        conversations.extend(summary.conversations)
        detections.extend(summary.detections)
        anomalies.extend(summary.anomalies)
        artifacts.extend(summary.artifacts)
        errors.extend(summary.errors)

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    return TelnetSummary(
        path=Path("ALL_PCAPS"),
        total_packets=total_packets,
        telnet_packets=telnet_packets,
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
        usernames=usernames,
        passwords=passwords,
        commands=commands,
        plaintext_strings=plaintext_strings,
        suspicious_plaintext=suspicious_plaintext,
        file_artifacts=file_artifacts,
        device_fingerprints=device_fingerprints,
        conversations=conversations,
        detections=detections,
        anomalies=anomalies,
        artifacts=artifacts,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )
