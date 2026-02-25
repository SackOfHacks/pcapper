from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import ipaddress
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .pcap_cache import PcapMeta, get_reader

from .utils import detect_file_type, safe_float, decode_payload, counter_inc, set_add_cap
from .dns import analyze_dns
from .files import analyze_files
from .progress import run_with_busy_status

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
    r"(?i)\b(?:cn|ou|dc|uid|sn|givenname|displayname|o|c|l|st|samaccountname|userprincipalname|mail|member|memberof|dnshostname|serviceprincipalname)\s*=\s*[^,;]+"
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

LDAP_USER_ATTRS = {"cn", "uid", "samaccountname", "userprincipalname", "givenname", "sn", "mail", "displayname"}

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
    ldap_error_codes: Counter[str]
    request_counts: Counter[str]
    http_methods: Counter[str]
    http_clients: Counter[str]
    urls: Counter[str]
    user_agents: Counter[str]
    ldap_queries: Counter[str]
    ldap_filter_types: Counter[str]
    ldap_users: Counter[str]
    ldap_systems: Counter[str]
    ldap_binds: Counter[str]
    suspicious_attributes: Counter[str]
    secrets: Counter[str]
    files: List[str]
    conversations: List[LdapConversation]
    session_stats: Dict[str, int]
    cleartext_packets: int
    ldaps_packets: int
    public_endpoints: Counter[str]
    bind_bursts: Counter[str]
    bind_identities: List[Dict[str, object]]
    user_evidence: List[Dict[str, object]]
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
        req_line = decode_payload(lines[0], encoding="latin-1")
        parts = req_line.split(" ")
        if len(parts) < 2:
            return None, None, None
        method = parts[0]
        path = parts[1]
        host = None
        ua = None
        for line in lines[1:]:
            if line.lower().startswith(b"host:"):
                host = decode_payload(line.split(b":", 1)[1].strip(), encoding="latin-1")
            if line.lower().startswith(b"user-agent:"):
                ua = decode_payload(line.split(b":", 1)[1].strip(), encoding="latin-1")
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
                value = decode_payload(current, encoding="latin-1")
                results.append(value[:max_len])
            current = bytearray()
    if len(current) >= min_len:
        value = decode_payload(current, encoding="latin-1")
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
                value = decode_payload(current, encoding="latin-1")
                results.append(value[:max_len])
            current = bytearray()
            i += 2
    if len(current) >= min_len:
        value = decode_payload(current, encoding="latin-1")
        results.append(value[:max_len])
    return results


def _extract_ldap_strings(payload: bytes) -> List[str]:
    try:
        text = decode_payload(payload, encoding="utf-8")
    except Exception:
        return []
    tokens: List[str] = []
    for token in text.split("\x00"):
        if "=" in token or token.lower().startswith("cn=") or token.lower().startswith("dc="):
            if len(token) > 3:
                tokens.append(token)
    return tokens


def _ldap_filter_type(query: str) -> Optional[str]:
    q = query.lower()
    if "(objectclass=" in q:
        return "objectClass"
    if "(objectcategory=" in q:
        return "objectCategory"
    if "(samaccountname=" in q or "samaccountname=" in q:
        return "sAMAccountName"
    if "(userprincipalname=" in q or "userprincipalname=" in q:
        return "userPrincipalName"
    if "(member=" in q or "member=" in q:
        return "member"
    if "(memberof=" in q or "memberof=" in q:
        return "memberOf"
    if "mail=" in q:
        return "mail"
    if "dnshostname=" in q:
        return "dNSHostName"
    if "serviceprincipalname=" in q:
        return "servicePrincipalName"
    if "(cn=" in q or "cn=" in q:
        return "cn"
    if "(uid=" in q or "uid=" in q:
        return "uid"
    return None


def _extract_bind_identities(text: str) -> list[str]:
    identities: list[str] = []
    for match in DN_TOKEN_RE.findall(text):
        identities.append(match)
    if not identities:
        lower = text.lower()
        if lower.startswith("cn=") or lower.startswith("uid=") or lower.startswith("dn="):
            identities.append(text)
    return identities


def _is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
        return addr.is_global
    except Exception:
        return False


def analyze_ldap(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> LdapAnalysis:
    errors: List[str] = []
    detections: List[Dict[str, object]] = []
    anomalies: List[str] = []

    def _busy(desc: str, func, *args, **kwargs):
        return run_with_busy_status(path, show_status, f"LDAP: {desc}", func, *args, **kwargs)

    dns_summary = _busy("DNS", analyze_dns, path, show_status=False, packets=packets, meta=meta)
    files_summary = _busy("Files", analyze_files, path, show_status=False)

    ldap_domains = Counter()
    for qname, count in dns_summary.qname_counts.items():
        qname_lower = qname.lower()
        if any(token in qname_lower for token in LDAP_DNS_HINTS):
            ldap_domains[qname_lower] += count

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
    response_codes = Counter()
    ldap_error_codes = Counter()
    request_counts = Counter()
    http_methods = Counter()
    http_clients = Counter()
    urls = Counter()
    user_agents = Counter()
    ldap_queries = Counter()
    ldap_filter_types = Counter()
    ldap_users = Counter()
    ldap_systems = Counter()
    secrets = Counter()
    ldap_binds = Counter()
    suspicious_attributes = Counter()
    public_endpoints = Counter()
    bind_buckets: dict[tuple[str, int], int] = defaultdict(int)
    bind_identities: list[dict[str, object]] = []
    bind_identity_seen: set[tuple[str, str, int, str]] = set()
    user_evidence: list[dict[str, object]] = []
    user_evidence_seen: set[tuple[str, str, int, str, str, str]] = set()
    cleartext_packets = 0
    ldaps_packets = 0
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

            proto = None
            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp_layer = pkt[TCP]  # type: ignore[index]
                sport = int(getattr(tcp_layer, "sport", 0) or 0)
                dport = int(getattr(tcp_layer, "dport", 0) or 0)
                proto = "TCP"
                if dport in LDAP_PORTS or sport in LDAP_PORTS:
                    counter_inc(servers, dst_ip)
                    counter_inc(clients, src_ip)
                    counter_inc(request_counts, "LDAP Traffic")
                    counter_inc(service_counts, f"TCP/{dport or sport}")
                    counter_inc(convos, (src_ip, dst_ip, dport or sport, "TCP"))
                    if dport in LDAP_CLEAR_PORTS or sport in LDAP_CLEAR_PORTS:
                        cleartext_ldap_seen = True
                        cleartext_packets += 1
                    if dport in {636, 3269} or sport in {636, 3269}:
                        ldaps_packets += 1
                    if _is_public_ip(src_ip):
                        counter_inc(public_endpoints, src_ip)
                    if _is_public_ip(dst_ip):
                        counter_inc(public_endpoints, dst_ip)

                payload = bytes(getattr(tcp_layer, "payload", b""))
                if payload and payload.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ")):
                    url, ua, method = _parse_http_request(payload)
                    if url:
                        counter_inc(urls, url)
                    if ua:
                        counter_inc(user_agents, ua)
                    if method:
                        counter_inc(http_methods, method)
                    counter_inc(http_clients, src_ip)

                if payload and (sport in LDAP_PORTS or dport in LDAP_PORTS):
                    for token in _extract_ldap_strings(payload):
                        if token:
                            counter_inc(ldap_queries, token)
                            filter_type = _ldap_filter_type(token)
                            if filter_type:
                                counter_inc(ldap_filter_types, filter_type)
                            lower_token = token.lower()
                            if "unicodepwd" in lower_token:
                                counter_inc(suspicious_attributes, "unicodePwd")
                            if "ms-mcs-admpwd" in lower_token:
                                counter_inc(suspicious_attributes, "ms-Mcs-AdmPwd")
                            if "userpassword" in lower_token:
                                counter_inc(suspicious_attributes, "userPassword")
                            if token.lower().startswith("cn="):
                                counter_inc(ldap_users, token)
                                set_add_cap(artifacts, token)
                                key = (src_ip, dst_ip, dport or sport, proto or "TCP", "cn", token)
                                if key not in user_evidence_seen:
                                    user_evidence_seen.add(key)
                                    user_evidence.append({
                                        "src_ip": src_ip,
                                        "dst_ip": dst_ip,
                                        "dst_port": dport or sport,
                                        "protocol": proto or "TCP",
                                        "attr": "cn",
                                        "value": token.partition("=")[2].strip() if "=" in token else token,
                                    })

                    for value in _extract_ascii_strings(payload) + _extract_utf16le_strings(payload):
                        if not value:
                            continue
                        lower = value.lower()

                        if any(hint in lower for hint in FILTER_HINTS) or "(objectclass" in lower:
                            counter_inc(ldap_queries, value)
                            set_add_cap(artifacts, value)
                            filter_type = _ldap_filter_type(value)
                            if filter_type:
                                counter_inc(ldap_filter_types, filter_type)
                            if "unicodepwd" in lower:
                                counter_inc(suspicious_attributes, "unicodePwd")
                            if "ms-mcs-admpwd" in lower:
                                counter_inc(suspicious_attributes, "ms-Mcs-AdmPwd")
                            if "userpassword" in lower:
                                counter_inc(suspicious_attributes, "userPassword")

                        for match in DN_TOKEN_RE.findall(value):
                            counter_inc(ldap_queries, match)
                            set_add_cap(artifacts, match)
                            key, _, val = match.partition("=")
                            key_lower = key.strip().lower()
                            val = val.strip()
                            if key_lower in LDAP_USER_ATTRS or key_lower in {"cn", "sn"}:
                                ev_key = (src_ip, dst_ip, dport or sport, proto or "TCP", key_lower, val)
                                if ev_key not in user_evidence_seen:
                                    user_evidence_seen.add(ev_key)
                                    user_evidence.append({
                                        "src_ip": src_ip,
                                        "dst_ip": dst_ip,
                                        "dst_port": dport or sport,
                                        "protocol": proto or "TCP",
                                        "attr": key_lower,
                                        "value": val,
                                    })
                            if key_lower in LDAP_USER_ATTRS:
                                counter_inc(ldap_users, val)
                            elif key_lower == "cn":
                                if val.endswith("$"):
                                    counter_inc(ldap_systems, val)
                                else:
                                    counter_inc(ldap_users, val)
                            if key_lower in {"dnshostname", "serviceprincipalname"}:
                                counter_inc(ldap_systems, val)

                        if any(word in lower for word in ("bind", "search", "modify", "add", "delete", "compare", "extended", "unbind")):
                            if "bind" in lower:
                                counter_inc(request_counts, "Bind")
                                for identity in _extract_bind_identities(value):
                                    if identity:
                                        counter_inc(ldap_binds, identity)
                                        key = (src_ip, dst_ip, dport or sport, identity)
                                        if key not in bind_identity_seen:
                                            bind_identity_seen.add(key)
                                            bind_identities.append({
                                                "src_ip": src_ip,
                                                "dst_ip": dst_ip,
                                                "dst_port": dport or sport,
                                                "protocol": "TCP",
                                                "identity": identity,
                                            })
                                if ts is not None:
                                    minute_bucket = int(ts // 60)
                                    counter_inc(bind_buckets, (src_ip, minute_bucket))
                            if "search" in lower:
                                counter_inc(request_counts, "Search")
                            if "modify" in lower:
                                counter_inc(request_counts, "Modify")
                            if "add" in lower:
                                counter_inc(request_counts, "Add")
                            if "delete" in lower:
                                counter_inc(request_counts, "Delete")
                            if "compare" in lower:
                                counter_inc(request_counts, "Compare")
                            if "extended" in lower:
                                counter_inc(request_counts, "Extended")
                            if "unbind" in lower:
                                counter_inc(request_counts, "Unbind")

                        for pattern in SECRET_PATTERNS:
                            match = pattern.search(value)
                            if match:
                                counter_inc(secrets, match.group(0))
                                set_add_cap(artifacts, match.group(0))

                        if "resultcode" in lower or "invalidcredentials" in lower or "insufficientaccessrights" in lower:
                            for name_lower, name in LDAP_RESULT_NAMES.items():
                                if name_lower in lower:
                                    counter_inc(response_codes, name)
                                    if name_lower in {"invalidcredentials", "insufficientaccessrights"}:
                                        counter_inc(ldap_error_codes, name)
                            numeric_match = re.search(r"resultcode\s*[:=]\s*(\d+)", lower)
                            if numeric_match:
                                code = int(numeric_match.group(1))
                                name = LDAP_RESULT_CODES.get(code, str(code))
                                counter_inc(response_codes, f"{code} ({name})")
                                if code != 0:
                                    counter_inc(ldap_error_codes, f"{code} ({name})")

            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp_layer = pkt[UDP]  # type: ignore[index]
                sport = int(getattr(udp_layer, "sport", 0) or 0)
                dport = int(getattr(udp_layer, "dport", 0) or 0)
                if dport in LDAP_PORTS or sport in LDAP_PORTS:
                    counter_inc(servers, dst_ip)
                    counter_inc(clients, src_ip)
                    counter_inc(request_counts, "LDAP Traffic")
                    counter_inc(service_counts, f"UDP/{dport or sport}")
                    counter_inc(convos, (src_ip, dst_ip, dport or sport, "UDP"))
                    udp_ldap_seen = True
                    cleartext_packets += 1
                    if _is_public_ip(src_ip):
                        counter_inc(public_endpoints, src_ip)
                    if _is_public_ip(dst_ip):
                        counter_inc(public_endpoints, dst_ip)

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

    if ldap_binds:
        anonymous_binds = [name for name in ldap_binds.keys() if "anonymous" in name.lower() or "guest" in name.lower()]
        if anonymous_binds:
            detections.append({
                "severity": "warning",
                "summary": "Anonymous/guest LDAP binds observed",
                "details": ", ".join(anonymous_binds[:10]),
                "source": "LDAP",
            })

    search_count = request_counts.get("Search", 0)
    if search_count >= 50 or len(ldap_queries) >= 50:
        detections.append({
            "severity": "warning",
            "summary": "LDAP enumeration indicators",
            "details": f"Search requests: {search_count}, unique queries: {len(ldap_queries)}.",
            "source": "LDAP",
        })

    invalid_creds = ldap_error_codes.get("invalidcredentials", 0) or ldap_error_codes.get("49 (invalidCredentials)", 0)
    if invalid_creds and len(ldap_binds) >= 10:
        detections.append({
            "severity": "warning",
            "summary": "Potential LDAP password spraying",
            "details": f"Invalid credentials: {invalid_creds}, unique bind identities: {len(ldap_binds)}.",
            "source": "LDAP",
        })

    bind_bursts = Counter()
    for (client_ip, _minute), count in bind_buckets.items():
        if count > bind_bursts.get(client_ip, 0):
            bind_bursts[client_ip] = count
    if bind_bursts:
        top_burst = max(bind_bursts.values())
        if top_burst >= 20:
            detections.append({
                "severity": "warning",
                "summary": "Potential LDAP brute-force (high bind rate)",
                "details": f"Peak binds/min observed: {top_burst}",
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
        ldap_error_codes=ldap_error_codes,
        request_counts=request_counts,
        http_methods=http_methods,
        http_clients=http_clients,
        urls=urls,
        user_agents=user_agents,
        ldap_queries=ldap_queries,
        ldap_filter_types=ldap_filter_types,
        ldap_users=ldap_users,
        ldap_systems=ldap_systems,
        ldap_binds=ldap_binds,
        suspicious_attributes=suspicious_attributes,
        secrets=secrets,
        files=files,
        conversations=conversations,
        session_stats=session_stats,
        cleartext_packets=cleartext_packets,
        ldaps_packets=ldaps_packets,
        public_endpoints=public_endpoints,
        bind_bursts=bind_bursts,
        bind_identities=bind_identities,
        user_evidence=user_evidence,
        artifacts=sorted(artifacts),
        anomalies=anomalies,
        detections=detections,
        errors=errors,
    )
