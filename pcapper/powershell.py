from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import ipaddress
import re

from .pcap_cache import get_reader
from .utils import safe_float

try:
    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    IPv6 = None  # type: ignore
    Ether = None  # type: ignore
    Raw = None  # type: ignore


POWERSHELL_PORTS = {5985, 5986, 47001}

POWERSHELL_HINT_RE = re.compile(
    r"(powershell|pwsh|system\.management\.automation|windows\s*power\s*shell)",
    re.IGNORECASE,
)

PS_COMMAND_RE = re.compile(r"\b(?:powershell|pwsh)\b[^\r\n]{0,300}", re.IGNORECASE)
PS_ENCODED_RE = re.compile(r"(?:-enc(?:odedcommand)?|frombase64string)\b", re.IGNORECASE)
PS_IEX_RE = re.compile(r"\binvoke-expression\b|\biex\b", re.IGNORECASE)
PS_DOWNLOAD_RE = re.compile(r"(downloadstring|invoke-webrequest|invoke-restmethod|new-object\s+net\.webclient)", re.IGNORECASE)
PS_AMSI_RE = re.compile(r"amsi(?:utils)?|amsiInitFailed|amsiScanBuffer", re.IGNORECASE)
PS_BYPASS_RE = re.compile(r"-executionpolicy\s+bypass|bypass\s+\w+\s+policy", re.IGNORECASE)
PS_LM_RE = re.compile(r"(psexec|wmic|winrs|schtasks|at\s+|rundll32|regsvr32)", re.IGNORECASE)
PS_CRED_RE = re.compile(r"(get-credential|convertto-securestring|asplaintext)", re.IGNORECASE)
PS_EXFIL_RE = re.compile(r"(compress-archive|convertto-json|invoke-webrequest|out-file|set-content|add-content)", re.IGNORECASE)
PS_AD_RE = re.compile(r"(get-aduser|get-adcomputer|get-addomain|get-adgroup)", re.IGNORECASE)
PS_NETDISC_RE = re.compile(r"(test-connection|get-nettcpconnection|get-netipconfiguration|get-netneighbor|get-netroute)", re.IGNORECASE)

URL_RE = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC_RE = re.compile(r"\b([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})\b")
HOST_VALUE_RE = re.compile(r"(?:hostname|computername|name)\s*[:=]\s*([A-Za-z0-9_.-]{2,64})", re.IGNORECASE)
DOMAIN_USER_RE = re.compile(r"\b([A-Za-z0-9_.-]{1,64})\\([A-Za-z0-9_.-]{1,64})\b")


SUSPICIOUS_PATTERNS = [
    (PS_ENCODED_RE, "Encoded command"),
    (PS_IEX_RE, "Invoke-Expression"),
    (PS_DOWNLOAD_RE, "Download tooling"),
    (PS_AMSI_RE, "AMSI bypass"),
    (PS_BYPASS_RE, "Execution policy bypass"),
    (PS_LM_RE, "Lateral movement tooling"),
    (PS_CRED_RE, "Credential handling"),
    (PS_EXFIL_RE, "Potential staging/exfil"),
]


@dataclass(frozen=True)
class PowershellConversation:
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
    hints: list[str]


@dataclass(frozen=True)
class PowershellSummary:
    path: Path
    total_packets: int
    powershell_packets: int
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
    hostnames: Counter[str]
    ip_strings: Counter[str]
    mac_strings: Counter[str]
    domains: Counter[str]
    usernames: Counter[str]
    commands: Counter[str]
    suspicious_indicators: Counter[str]
    urls: Counter[str]
    ad_queries: Counter[str]
    network_discovery: Counter[str]
    plaintext_strings: Counter[str]
    detections: list[dict[str, object]]
    anomalies: list[dict[str, object]]
    artifacts: list[str]
    conversations: list[PowershellConversation]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "total_packets": self.total_packets,
            "powershell_packets": self.powershell_packets,
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
            "hostnames": dict(self.hostnames),
            "ip_strings": dict(self.ip_strings),
            "mac_strings": dict(self.mac_strings),
            "domains": dict(self.domains),
            "usernames": dict(self.usernames),
            "commands": dict(self.commands),
            "suspicious_indicators": dict(self.suspicious_indicators),
            "urls": dict(self.urls),
            "ad_queries": dict(self.ad_queries),
            "network_discovery": dict(self.network_discovery),
            "plaintext_strings": dict(self.plaintext_strings),
            "detections": list(self.detections),
            "anomalies": list(self.anomalies),
            "artifacts": list(self.artifacts),
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
                    "hints": list(conv.hints),
                }
                for conv in self.conversations
            ],
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
    hints: Counter[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.hints is None:
            self.hints = Counter()


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


def _extract_utf16le_strings(data: bytes, min_len: int = 4, max_len: int = 200) -> list[str]:
    results: list[str] = []
    if not data:
        return results
    current = bytearray()
    i = 0
    while i + 1 < len(data):
        ch = data[i]
        if 32 <= ch <= 126 and data[i + 1] == 0x00:
            current.append(ch)
            i += 2
        else:
            if len(current) >= min_len:
                value = current.decode("latin-1", errors="ignore")
                results.append(value[:max_len])
            current = bytearray()
            i += 2
    if len(current) >= min_len:
        value = current.decode("latin-1", errors="ignore")
        results.append(value[:max_len])
    return results


def _direction(src_ip: str, dst_ip: str, sport: int, dport: int) -> tuple[str, str, int, int]:
    if dport in POWERSHELL_PORTS:
        return src_ip, dst_ip, sport, dport
    if sport in POWERSHELL_PORTS:
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


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def analyze_powershell(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
) -> PowershellSummary:
    errors: list[str] = []
    if TCP is None or (IP is None and IPv6 is None):
        errors.append("Scapy IP/TCP layers unavailable; install scapy for PowerShell analysis.")
        return PowershellSummary(
            path=path,
            total_packets=0,
            powershell_packets=0,
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
            hostnames=Counter(),
            ip_strings=Counter(),
            mac_strings=Counter(),
            domains=Counter(),
            usernames=Counter(),
            commands=Counter(),
            suspicious_indicators=Counter(),
            urls=Counter(),
            ad_queries=Counter(),
            network_discovery=Counter(),
            plaintext_strings=Counter(),
            detections=[],
            anomalies=[],
            artifacts=[],
            conversations=[],
            errors=errors,
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path, packets=packets, meta=meta, show_status=show_status
        )
    except Exception as exc:
        return PowershellSummary(
            path=path,
            total_packets=0,
            powershell_packets=0,
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
            hostnames=Counter(),
            ip_strings=Counter(),
            mac_strings=Counter(),
            domains=Counter(),
            usernames=Counter(),
            commands=Counter(),
            suspicious_indicators=Counter(),
            urls=Counter(),
            ad_queries=Counter(),
            network_discovery=Counter(),
            plaintext_strings=Counter(),
            detections=[],
            anomalies=[],
            artifacts=[],
            conversations=[],
            errors=[f"Error opening pcap: {exc}"],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    total_packets = 0
    powershell_packets = 0
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

    hostnames: Counter[str] = Counter()
    ip_strings: Counter[str] = Counter()
    mac_strings: Counter[str] = Counter()
    domains: Counter[str] = Counter()
    usernames: Counter[str] = Counter()
    commands: Counter[str] = Counter()
    suspicious_indicators: Counter[str] = Counter()
    urls: Counter[str] = Counter()
    ad_queries: Counter[str] = Counter()
    network_discovery: Counter[str] = Counter()
    plaintext_strings: Counter[str] = Counter()

    artifacts: list[str] = []
    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []
    errors = []

    client_times: dict[str, list[float]] = defaultdict(list)
    client_targets: dict[str, set[str]] = defaultdict(set)

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

            if not payload:
                continue

            strings = _extract_ascii_strings(payload) + _extract_utf16le_strings(payload)
            if not strings:
                continue

            matched = any(POWERSHELL_HINT_RE.search(value) for value in strings)
            if not matched:
                continue

            powershell_packets += 1
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
                    client_mac=eth_src if src_ip == client_ip else None,
                    server_mac=eth_dst if dst_ip == server_ip else None,
                )
                sessions[session_key] = session

            session.packets += 1
            session.bytes += pkt_len
            if ts is not None:
                if session.first_seen is None or ts < session.first_seen:
                    session.first_seen = ts
                if session.last_seen is None or ts > session.last_seen:
                    session.last_seen = ts
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
                client_times[client_ip].append(ts)
            client_targets[client_ip].add(server_ip)

            for value in strings:
                if not value:
                    continue

                if POWERSHELL_HINT_RE.search(value):
                    if len(plaintext_strings) < 2000 or value in plaintext_strings:
                        plaintext_strings[value] += 1

                cmd_match = PS_COMMAND_RE.search(value)
                if cmd_match:
                    cmd = cmd_match.group(0).strip()
                    commands[cmd] += 1

                host_match = HOST_VALUE_RE.search(value)
                if host_match:
                    hostnames[host_match.group(1).lower()] += 1

                for dom, user in DOMAIN_USER_RE.findall(value):
                    domains[dom.lower()] += 1
                    usernames[user.lower()] += 1

                for ip_value in IP_RE.findall(value):
                    if _valid_ip(ip_value):
                        ip_strings[ip_value] += 1

                for mac_value in MAC_RE.findall(value):
                    mac_strings[mac_value.lower()] += 1

                for url in URL_RE.findall(value):
                    urls[url] += 1

                if PS_AD_RE.search(value):
                    ad_queries[PS_AD_RE.search(value).group(0)] += 1

                if PS_NETDISC_RE.search(value):
                    network_discovery[PS_NETDISC_RE.search(value).group(0)] += 1

                for pattern, label in SUSPICIOUS_PATTERNS:
                    if pattern.search(value):
                        suspicious_indicators[f"{label}: {value}"] += 1
                        session.hints[label] += 1

    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        reader.close()

    conversations: list[PowershellConversation] = []
    for session in sessions.values():
        conversations.append(
            PowershellConversation(
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
                hints=[hint for hint, _count in session.hints.most_common(5)],
            )
        )

    total_sessions = len(conversations)

    for client, targets in client_targets.items():
        if len(targets) >= 12:
            detections.append(
                {
                    "severity": "warning",
                    "summary": "PowerShell fan-out",
                    "details": f"{client} contacted {len(targets)} unique targets",
                }
            )

    for client, times in client_times.items():
        score = _beaconing_score(times)
        if score:
            detections.append(
                {
                    "severity": "warning",
                    "summary": "Possible PowerShell beaconing",
                    "details": f"{client} interval avg={score['avg']:.1f}s stddev={score['stddev']:.1f}s",
                }
            )

    if any(PS_AMSI_RE.search(key) for key in suspicious_indicators.keys()):
        detections.append(
            {
                "severity": "high",
                "summary": "PowerShell AMSI bypass indicators",
                "details": "AMSI-related bypass strings observed",
            }
        )

    if any(PS_ENCODED_RE.search(key) for key in suspicious_indicators.keys()):
        detections.append(
            {
                "severity": "warning",
                "summary": "Encoded PowerShell command",
                "details": "EncodedCommand/FromBase64String observed",
            }
        )

    if urls and any(PS_DOWNLOAD_RE.search(key) for key in suspicious_indicators.keys()):
        detections.append(
            {
                "severity": "warning",
                "summary": "PowerShell download activity",
                "details": f"{len(urls)} URLs observed with download tooling",
            }
        )

    if server_bytes > 5 * max(1, client_bytes) and server_bytes > 1024 * 1024:
        detections.append(
            {
                "severity": "warning",
                "summary": "Data-heavy PowerShell responses",
                "details": f"Server bytes {server_bytes} greatly exceed client bytes {client_bytes}",
            }
        )

    if suspicious_indicators:
        anomalies.append(
            {
                "title": "Suspicious PowerShell indicators",
                "details": ", ".join(
                    f"{name}({count})" for name, count in suspicious_indicators.most_common(6)
                ),
            }
        )

    if commands:
        for cmd, count in commands.most_common(12):
            artifacts.append(f"Command: {cmd} ({count})")

    if urls:
        artifacts.append("URLs: " + ", ".join(list(urls.keys())[:10]))

    if hostnames:
        artifacts.append("Hosts: " + ", ".join(list(hostnames.keys())[:10]))

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    return PowershellSummary(
        path=path,
        total_packets=total_packets,
        powershell_packets=powershell_packets,
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
        hostnames=hostnames,
        ip_strings=ip_strings,
        mac_strings=mac_strings,
        domains=domains,
        usernames=usernames,
        commands=commands,
        suspicious_indicators=suspicious_indicators,
        urls=urls,
        ad_queries=ad_queries,
        network_discovery=network_discovery,
        plaintext_strings=plaintext_strings,
        detections=detections,
        anomalies=anomalies,
        artifacts=artifacts,
        conversations=conversations,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )


def merge_powershell_summaries(
    summaries: list[PowershellSummary] | tuple[PowershellSummary, ...] | set[PowershellSummary],
) -> PowershellSummary:
    summary_list = list(summaries)
    if not summary_list:
        return PowershellSummary(
            path=Path("ALL_PCAPS_0"),
            total_packets=0,
            powershell_packets=0,
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
            hostnames=Counter(),
            ip_strings=Counter(),
            mac_strings=Counter(),
            domains=Counter(),
            usernames=Counter(),
            commands=Counter(),
            suspicious_indicators=Counter(),
            urls=Counter(),
            ad_queries=Counter(),
            network_discovery=Counter(),
            plaintext_strings=Counter(),
            detections=[],
            anomalies=[],
            artifacts=[],
            conversations=[],
            errors=[],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    total_packets = 0
    powershell_packets = 0
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

    hostnames: Counter[str] = Counter()
    ip_strings: Counter[str] = Counter()
    mac_strings: Counter[str] = Counter()
    domains: Counter[str] = Counter()
    usernames: Counter[str] = Counter()
    commands: Counter[str] = Counter()
    suspicious_indicators: Counter[str] = Counter()
    urls: Counter[str] = Counter()
    ad_queries: Counter[str] = Counter()
    network_discovery: Counter[str] = Counter()
    plaintext_strings: Counter[str] = Counter()
    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []
    artifacts: list[str] = []
    conversations: list[PowershellConversation] = []
    errors: list[str] = []

    for summary in summary_list:
        total_packets += summary.total_packets
        powershell_packets += summary.powershell_packets
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

        hostnames.update(summary.hostnames)
        ip_strings.update(summary.ip_strings)
        mac_strings.update(summary.mac_strings)
        domains.update(summary.domains)
        usernames.update(summary.usernames)
        commands.update(summary.commands)
        suspicious_indicators.update(summary.suspicious_indicators)
        urls.update(summary.urls)
        ad_queries.update(summary.ad_queries)
        network_discovery.update(summary.network_discovery)
        plaintext_strings.update(summary.plaintext_strings)
        detections.extend(summary.detections)
        anomalies.extend(summary.anomalies)
        artifacts.extend(summary.artifacts)
        conversations.extend(summary.conversations)
        errors.extend(summary.errors)

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    return PowershellSummary(
        path=Path("ALL_PCAPS"),
        total_packets=total_packets,
        powershell_packets=powershell_packets,
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
        hostnames=hostnames,
        ip_strings=ip_strings,
        mac_strings=mac_strings,
        domains=domains,
        usernames=usernames,
        commands=commands,
        suspicious_indicators=suspicious_indicators,
        urls=urls,
        ad_queries=ad_queries,
        network_discovery=network_discovery,
        plaintext_strings=plaintext_strings,
        detections=detections,
        anomalies=anomalies,
        artifacts=artifacts,
        conversations=conversations,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )
