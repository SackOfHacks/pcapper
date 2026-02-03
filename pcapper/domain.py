from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .pcap_cache import PcapMeta, get_reader

from .utils import detect_file_type, safe_float
from .dns import analyze_dns
from .netbios import analyze_netbios
from .ntlm import analyze_ntlm
from .files import analyze_files

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore


DOMAIN_PORTS = {53, 88, 135, 139, 389, 445, 464, 593, 3268, 3269, 636}
KERBEROS_PORTS = {88, 464}
LDAP_PORTS = {389, 636, 3268, 3269}
SMB_PORTS = {445, 139}
RPC_PORTS = {135, 593}
DNS_PORTS = {53}


@dataclass(frozen=True)
class DomainConversation:
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str
    packets: int


@dataclass(frozen=True)
class DomainAnalysis:
    path: Path
    duration: float
    total_packets: int
    domains: Counter[str]
    dc_hosts: Counter[str]
    servers: Counter[str]
    clients: Counter[str]
    service_counts: Counter[str]
    response_codes: Counter[str]
    request_counts: Counter[str]
    urls: Counter[str]
    user_agents: Counter[str]
    users: Counter[str]
    credentials: Counter[str]
    computer_names: Counter[str]
    files: List[str]
    conversations: List[DomainConversation]
    anomalies: List[str]
    detections: List[Dict[str, object]]
    errors: List[str]


_DOMAIN_SKIP_SUFFIXES = (".in-addr.arpa", ".ip6.arpa")
_CRED_USER_PATTERNS = [
    re.compile(r"(?i)\b(user(name)?|login|uid|cn|samaccountname|userprincipalname)\b\s*[:=]\s*([^\s'\";]{2,})"),
]
_CRED_PASS_PATTERNS = [
    re.compile(r"(?i)\b(pass(word)?|passwd|pwd)\b\s*[:=]\s*([^\s'\";]{4,})"),
]


def _base_domain(name: str) -> str:
    name = name.strip(".")
    if not name:
        return name
    parts = [part for part in name.split(".") if part]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return name


def _extract_ascii_strings(data: bytes, min_len: int = 4, max_len: int = 200) -> List[str]:
    results: List[str] = []
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


def _extract_utf16le_strings(data: bytes, min_len: int = 4, max_len: int = 200) -> List[str]:
    results: List[str] = []
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


def _parse_http_request(payload: bytes) -> Tuple[Optional[str], Optional[str]]:
    try:
        header, _ = payload.split(b"\r\n\r\n", 1)
    except Exception:
        return None, None
    try:
        lines = header.split(b"\r\n")
        if not lines:
            return None, None
        req_line = lines[0].decode("latin-1", errors="ignore")
        parts = req_line.split(" ")
        if len(parts) < 2:
            return None, None
        path = parts[1]
        host = None
        ua = None
        for line in lines[1:]:
            if line.lower().startswith(b"host:"):
                host = line.split(b":", 1)[1].strip().decode("latin-1", errors="ignore")
            if line.lower().startswith(b"user-agent:"):
                ua = line.split(b":", 1)[1].strip().decode("latin-1", errors="ignore")
        if host:
            url = f"{host}{path}"
        else:
            url = path
        return url, ua
    except Exception:
        return None, None


def analyze_domain(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> DomainAnalysis:
    errors: List[str] = []
    detections: List[Dict[str, object]] = []
    anomalies: List[str] = []

    dns_summary = analyze_dns(path, show_status=False, packets=packets, meta=meta)
    netbios_summary = analyze_netbios(path, show_status=False)
    ntlm_summary = analyze_ntlm(path, show_status=False)
    files_summary = analyze_files(path, show_status=False)

    domains = Counter()
    for qname, count in dns_summary.qname_counts.items():
        qname_lower = qname.lower().strip(".")
        if any(qname_lower.endswith(suffix) for suffix in _DOMAIN_SKIP_SUFFIXES):
            continue
        base = _base_domain(qname_lower)
        if base:
            domains[base] += count

    dc_hosts = Counter()
    for ip, host in netbios_summary.hosts.items():
        if host.is_domain_controller:
            dc_hosts[ip] += 1

    users = Counter(ntlm_summary.raw_users)
    computer_names = Counter(ntlm_summary.raw_workstations)

    for name in netbios_summary.unique_names:
        if name:
            computer_names[name] += 1

    response_codes = Counter()
    response_codes.update(netbios_summary.response_codes)
    response_codes.update(ntlm_summary.status_codes)

    request_counts = Counter()
    request_counts.update(netbios_summary.request_counts)
    request_counts.update(ntlm_summary.request_counts)

    files = [art.filename for art in files_summary.artifacts]

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, packets=packets, meta=meta, show_status=show_status
    )

    total_packets = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    servers = Counter()
    clients = Counter()
    service_counts = Counter()
    urls = Counter()
    user_agents = Counter()
    convos: Dict[Tuple[str, str, int, str], int] = defaultdict(int)
    credentials = Counter()

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

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp_layer = pkt[TCP]  # type: ignore[index]
                sport = int(getattr(tcp_layer, "sport", 0) or 0)
                dport = int(getattr(tcp_layer, "dport", 0) or 0)
                if dport in DOMAIN_PORTS or sport in DOMAIN_PORTS:
                    servers[dst_ip] += 1
                    clients[src_ip] += 1
                    service_counts[f"TCP/{dport or sport}"] += 1
                    convos[(src_ip, dst_ip, dport or sport, "TCP")] += 1

                payload = bytes(getattr(tcp_layer, "payload", b""))
                if payload and payload.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ")):
                    url, ua = _parse_http_request(payload)
                    if url:
                        urls[url] += 1
                    if ua:
                        user_agents[ua] += 1

                if payload:
                    for value in _extract_ascii_strings(payload) + _extract_utf16le_strings(payload):
                        if not value:
                            continue
                        for pattern in _CRED_USER_PATTERNS:
                            match = pattern.search(value)
                            if match:
                                user_val = match.group(3)
                                users[user_val] += 1
                        for pattern in _CRED_PASS_PATTERNS:
                            match = pattern.search(value)
                            if match:
                                credentials[match.group(0)] += 1

            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp_layer = pkt[UDP]  # type: ignore[index]
                sport = int(getattr(udp_layer, "sport", 0) or 0)
                dport = int(getattr(udp_layer, "dport", 0) or 0)
                if dport in DOMAIN_PORTS or sport in DOMAIN_PORTS:
                    servers[dst_ip] += 1
                    clients[src_ip] += 1
                    service_counts[f"UDP/{dport or sport}"] += 1
                    convos[(src_ip, dst_ip, dport or sport, "UDP")] += 1
    finally:
        status.finish()
        reader.close()

    duration = 0.0
    if first_seen is not None and last_seen is not None:
        duration = max(0.0, last_seen - first_seen)

    conversations = [
        DomainConversation(src, dst, port, proto, count)
        for (src, dst, port, proto), count in convos.items()
    ]
    conversations.sort(key=lambda c: c.packets, reverse=True)

    if ntlm_summary.anomalies:
        anomalies.extend([a.title for a in ntlm_summary.anomalies])
    if netbios_summary.anomalies:
        anomalies.extend([a.type for a in netbios_summary.anomalies])

    if dc_hosts:
        detections.append({
            "severity": "info",
            "summary": "Domain Controllers observed",
            "details": ", ".join(dc_hosts.keys()),
            "source": "Domain",
        })
    if users:
        detections.append({
            "severity": "info",
            "summary": "Domain users observed",
            "details": ", ".join([u for u, _ in users.most_common(10)]),
            "source": "Domain",
        })
    if credentials:
        detections.append({
            "severity": "warning",
            "summary": "Potential credentials observed",
            "details": ", ".join([c for c, _ in credentials.most_common(5)]),
            "source": "Domain",
        })

    return DomainAnalysis(
        path=path,
        duration=duration,
        total_packets=total_packets,
        domains=domains,
        dc_hosts=dc_hosts,
        servers=servers,
        clients=clients,
        service_counts=service_counts,
        response_codes=response_codes,
        request_counts=request_counts,
        urls=urls,
        user_agents=user_agents,
        users=users,
        credentials=credentials,
        computer_names=computer_names,
        files=files,
        conversations=conversations,
        anomalies=anomalies,
        detections=detections,
        errors=errors,
    )
