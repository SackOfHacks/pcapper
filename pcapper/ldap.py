from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import ipaddress
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from scapy.utils import PcapReader, PcapNgReader

from .progress import build_statusbar
from .utils import detect_file_type, safe_float
from .dns import analyze_dns
from .files import analyze_files

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore
    Raw = None  # type: ignore


LDAP_PORTS = {389, 636, 3268, 3269}
LDAP_CLEAR_PORTS = {389, 3268}

LDAP_DNS_HINTS = ("_ldap._tcp", "_gc._tcp", "_msdcs")

LDAP_RESULT_CODES = {
    0: "success",
    1: "operationsError",
    2: "protocolError",
    3: "timeLimitExceeded",
    4: "sizeLimitExceeded",
    5: "compareFalse",
    6: "compareTrue",
    7: "authMethodNotSupported",
    8: "strongerAuthRequired",
    10: "referral",
    11: "adminLimitExceeded",
    12: "unavailableCriticalExtension",
    13: "confidentialityRequired",
    14: "saslBindInProgress",
    16: "noSuchAttribute",
    17: "undefinedAttributeType",
    18: "inappropriateMatching",
    19: "constraintViolation",
    20: "attributeOrValueExists",
    21: "invalidAttributeSyntax",
    32: "noSuchObject",
    34: "invalidDN",
    49: "invalidCredentials",
    50: "insufficientAccessRights",
    53: "unwillingToPerform",
    54: "loopDetect",
    64: "namingViolation",
    65: "objectClassViolation",
    66: "notAllowedOnNonLeaf",
    67: "notAllowedOnRDN",
    68: "entryAlreadyExists",
    69: "objectClassModsProhibited",
    71: "affectsMultipleDSAs",
    80: "other",
}

LDAP_RESULT_NAMES = {name.lower(): name for name in LDAP_RESULT_CODES.values()}

DN_TOKEN_RE = re.compile(
    r"(?i)\b(?:cn|ou|dc|uid|sn|o|c|l|st|samaccountname|userprincipalname|mail|member|memberof|dnshostname|serviceprincipalname)\s*=\s*[^,;]+"
)
FILTER_HINTS = (
    "(objectclass=",
    "(objectcategory=",
    "(samaccountname=",
    "(userprincipalname=",
    "(member=",
    "(memberof=",
    "givenname",
    "sn=",
    "mail=",
)

LDAP_USER_ATTRS = {"cn", "uid", "samaccountname", "userprincipalname", "givenname", "sn", "mail"}

SECRET_PATTERNS = [
    re.compile(r"(?i)\b(password|passwd|pwd|unicodepwd|userpassword)\b\s*[:=]\s*([^\s'\";]{4,})"),
    re.compile(r"(?i)\b(token|api[_-]?key|secret)\b\s*[:=]\s*([^\s'\";]{6,})"),
]


@dataclass(frozen=True)
class LdapConversation:
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str
    packets: int


@dataclass(frozen=True)
class LdapAnalysis:
    path: Path
    duration: float
    total_packets: int
    ldap_domains: Counter[str]
    servers: Counter[str]
    clients: Counter[str]
    service_counts: Counter[str]
    response_codes: Counter[str]
    request_counts: Counter[str]
    http_methods: Counter[str]
    http_clients: Counter[str]
    urls: Counter[str]
    user_agents: Counter[str]
    ldap_queries: Counter[str]
    ldap_users: Counter[str]
    ldap_systems: Counter[str]
    secrets: Counter[str]
    files: List[str]
    conversations: List[LdapConversation]
    session_stats: Dict[str, int]
    artifacts: List[str]
    anomalies: List[str]
    detections: List[Dict[str, object]]
    errors: List[str]


def _parse_http_request(payload: bytes) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    try:
        header, _ = payload.split(b"\r\n\r\n", 1)
    except Exception:
        return None, None, None
    try:
        lines = header.split(b"\r\n")
        if not lines:
            return None, None, None
        req_line = lines[0].decode("latin-1", errors="ignore")
        parts = req_line.split(" ")
        if len(parts) < 2:
            return None, None, None
        method = parts[0]
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
        return url, ua, method
    except Exception:
        return None, None, None


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


def _extract_ldap_strings(payload: bytes) -> List[str]:
    try:
        text = payload.decode("utf-8", errors="ignore")
    except Exception:
        return []
    tokens: List[str] = []
    for token in text.split("\x00"):
        if "=" in token or token.lower().startswith("cn=") or token.lower().startswith("dc="):
            if len(token) > 3:
                tokens.append(token)
    return tokens


def _is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
        return addr.is_global
    except Exception:
        return False


def analyze_ldap(path: Path, show_status: bool = True) -> LdapAnalysis:
    errors: List[str] = []
    detections: List[Dict[str, object]] = []
    anomalies: List[str] = []

    dns_summary = analyze_dns(path, show_status=False)
    files_summary = analyze_files(path, show_status=False)

    ldap_domains = Counter()
    for qname, count in dns_summary.qname_counts.items():
        qname_lower = qname.lower()
        if any(token in qname_lower for token in LDAP_DNS_HINTS):
            ldap_domains[qname_lower] += count

    files = [art.filename for art in files_summary.artifacts]

    file_type = detect_file_type(path)
    reader = PcapNgReader(str(path)) if file_type == "pcapng" else PcapReader(str(path))

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
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    servers = Counter()
    clients = Counter()
    service_counts = Counter()
    response_codes = Counter()
    request_counts = Counter()
    http_methods = Counter()
    http_clients = Counter()
    urls = Counter()
    user_agents = Counter()
    ldap_queries = Counter()
    ldap_users = Counter()
    ldap_systems = Counter()
    secrets = Counter()
    convos: Dict[Tuple[str, str, int, str], int] = defaultdict(int)
    artifacts: set[str] = set()
    cleartext_ldap_seen = False
    udp_ldap_seen = False

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
                if dport in LDAP_PORTS or sport in LDAP_PORTS:
                    servers[dst_ip] += 1
                    clients[src_ip] += 1
                    request_counts["LDAP Traffic"] += 1
                    service_counts[f"TCP/{dport or sport}"] += 1
                    convos[(src_ip, dst_ip, dport or sport, "TCP")] += 1
                    if dport in LDAP_CLEAR_PORTS or sport in LDAP_CLEAR_PORTS:
                        cleartext_ldap_seen = True

                payload = bytes(getattr(tcp_layer, "payload", b""))
                if payload and payload.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ")):
                    url, ua, method = _parse_http_request(payload)
                    if url:
                        urls[url] += 1
                    if ua:
                        user_agents[ua] += 1
                    if method:
                        http_methods[method] += 1
                    http_clients[src_ip] += 1

                if payload and (sport in LDAP_PORTS or dport in LDAP_PORTS):
                    for token in _extract_ldap_strings(payload):
                        if token:
                            ldap_queries[token] += 1
                            if token.lower().startswith("cn="):
                                ldap_users[token] += 1
                                artifacts.add(token)

                    for value in _extract_ascii_strings(payload) + _extract_utf16le_strings(payload):
                        if not value:
                            continue
                        lower = value.lower()

                        if any(hint in lower for hint in FILTER_HINTS) or "(objectclass" in lower:
                            ldap_queries[value] += 1
                            artifacts.add(value)

                        for match in DN_TOKEN_RE.findall(value):
                            ldap_queries[match] += 1
                            artifacts.add(match)
                            key, _, val = match.partition("=")
                            key_lower = key.strip().lower()
                            val = val.strip()
                            if key_lower in LDAP_USER_ATTRS:
                                ldap_users[val] += 1
                            elif key_lower == "cn":
                                if val.endswith("$"):
                                    ldap_systems[val] += 1
                                else:
                                    ldap_users[val] += 1
                            if key_lower in {"dnshostname", "serviceprincipalname"}:
                                ldap_systems[val] += 1

                        if any(word in lower for word in ("bind", "search", "modify", "add", "delete", "compare", "extended", "unbind")):
                            if "bind" in lower:
                                request_counts["Bind"] += 1
                            if "search" in lower:
                                request_counts["Search"] += 1
                            if "modify" in lower:
                                request_counts["Modify"] += 1
                            if "add" in lower:
                                request_counts["Add"] += 1
                            if "delete" in lower:
                                request_counts["Delete"] += 1
                            if "compare" in lower:
                                request_counts["Compare"] += 1
                            if "extended" in lower:
                                request_counts["Extended"] += 1
                            if "unbind" in lower:
                                request_counts["Unbind"] += 1

                        for pattern in SECRET_PATTERNS:
                            match = pattern.search(value)
                            if match:
                                secrets[match.group(0)] += 1
                                artifacts.add(match.group(0))

                        if "resultcode" in lower or "invalidcredentials" in lower or "insufficientaccessrights" in lower:
                            for name_lower, name in LDAP_RESULT_NAMES.items():
                                if name_lower in lower:
                                    response_codes[name] += 1
                            numeric_match = re.search(r"resultcode\s*[:=]\s*(\d+)", lower)
                            if numeric_match:
                                code = int(numeric_match.group(1))
                                name = LDAP_RESULT_CODES.get(code, str(code))
                                response_codes[f"{code} ({name})"] += 1

            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp_layer = pkt[UDP]  # type: ignore[index]
                sport = int(getattr(udp_layer, "sport", 0) or 0)
                dport = int(getattr(udp_layer, "dport", 0) or 0)
                if dport in LDAP_PORTS or sport in LDAP_PORTS:
                    servers[dst_ip] += 1
                    clients[src_ip] += 1
                    request_counts["LDAP Traffic"] += 1
                    service_counts[f"UDP/{dport or sport}"] += 1
                    convos[(src_ip, dst_ip, dport or sport, "UDP")] += 1
                    udp_ldap_seen = True

    finally:
        status.finish()
        reader.close()

    duration = 0.0
    if first_seen is not None and last_seen is not None:
        duration = max(0.0, last_seen - first_seen)

    conversations = [
        LdapConversation(src, dst, port, proto, count)
        for (src, dst, port, proto), count in convos.items()
    ]
    conversations.sort(key=lambda c: c.packets, reverse=True)

    session_stats = {
        "total_sessions": len(conversations),
        "unique_clients": len(clients),
        "unique_servers": len(servers),
        "tcp_sessions": sum(1 for convo in conversations if convo.proto == "TCP"),
        "udp_sessions": sum(1 for convo in conversations if convo.proto == "UDP"),
    }

    if cleartext_ldap_seen:
        anomalies.append("Cleartext LDAP observed on TCP/389 or TCP/3268.")
    if udp_ldap_seen:
        anomalies.append("LDAP over UDP observed (uncommon).")

    public_servers = [ip for ip in servers.keys() if _is_public_ip(ip)]
    if public_servers:
        anomalies.append("LDAP traffic to public IPs detected.")
        detections.append({
            "severity": "warning",
            "summary": "LDAP traffic to public IPs",
            "details": ", ".join(public_servers[:10]),
            "source": "LDAP",
        })

    if ldap_users:
        detections.append({
            "severity": "info",
            "summary": "LDAP users observed",
            "details": ", ".join([u for u, _ in ldap_users.most_common(10)]),
            "source": "LDAP",
        })

    if secrets:
        detections.append({
            "severity": "warning",
            "summary": "Potential secrets/passwords in LDAP payloads",
            "details": ", ".join([s for s, _ in secrets.most_common(5)]),
            "source": "LDAP",
        })

    if any("invalidCredentials" in code for code in response_codes.keys()):
        detections.append({
            "severity": "warning",
            "summary": "LDAP invalid credentials observed",
            "details": ", ".join([c for c, _ in response_codes.most_common(5)]),
            "source": "LDAP",
        })

    if any("ms-mcs-admpwd" in query.lower() or "unicodepwd" in query.lower() for query in ldap_queries.keys()):
        detections.append({
            "severity": "critical",
            "summary": "LDAP queries for password attributes",
            "details": "Queries include ms-Mcs-AdmPwd or unicodePwd.",
            "source": "LDAP",
        })

    return LdapAnalysis(
        path=path,
        duration=duration,
        total_packets=total_packets,
        ldap_domains=ldap_domains,
        servers=servers,
        clients=clients,
        service_counts=service_counts,
        response_codes=response_codes,
        request_counts=request_counts,
        http_methods=http_methods,
        http_clients=http_clients,
        urls=urls,
        user_agents=user_agents,
        ldap_queries=ldap_queries,
        ldap_users=ldap_users,
        ldap_systems=ldap_systems,
        secrets=secrets,
        files=files,
        conversations=conversations,
        session_stats=session_stats,
        artifacts=sorted(artifacts),
        anomalies=anomalies,
        detections=detections,
        errors=errors,
    )
