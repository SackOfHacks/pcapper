from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .dns import analyze_dns
from .files import analyze_files
from .netbios import analyze_netbios
from .ntlm import analyze_ntlm
from .pcap_cache import PcapMeta, get_reader
from .progress import run_with_busy_status
from .utils import safe_float

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


def _port_to_domain_service(port: int) -> str:
    if port in KERBEROS_PORTS:
        return "Kerberos"
    if port in LDAP_PORTS:
        return "LDAP"
    if port in SMB_PORTS:
        return "SMB"
    if port in RPC_PORTS:
        return "RPC"
    if port in DNS_PORTS:
        return "DNS"
    return f"Port {port}"


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
    deterministic_checks: Dict[str, List[str]] = field(default_factory=dict)
    dc_role_drift: List[Dict[str, object]] = field(default_factory=list)
    kerberos_abuse_profiles: List[Dict[str, object]] = field(default_factory=list)
    dcsync_signals: List[Dict[str, object]] = field(default_factory=list)
    ldap_bind_risks: List[Dict[str, object]] = field(default_factory=list)
    ntlm_relay_signals: List[str] = field(default_factory=list)
    sequence_violations: List[Dict[str, object]] = field(default_factory=list)
    host_attack_paths: List[Dict[str, object]] = field(default_factory=list)
    incident_clusters: List[Dict[str, object]] = field(default_factory=list)
    campaign_indicators: List[Dict[str, object]] = field(default_factory=list)
    baseline_anomalies: List[Dict[str, object]] = field(default_factory=list)
    benign_context: List[str] = field(default_factory=list)


_DOMAIN_SKIP_SUFFIXES = (".in-addr.arpa", ".ip6.arpa")
_CRED_USER_PATTERNS = [
    re.compile(
        r"(?i)\b(user(name)?|login|uid|cn|samaccountname|userprincipalname)\b\s*[:=]\s*([^\s'\";]{2,})"
    ),
]
_CRED_PASS_PATTERNS = [
    re.compile(r"(?i)\b(pass(word)?|passwd|pwd)\b\s*[:=]\s*([^\s'\";<>]{4,})"),
]
_DOMAIN_USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._$@-]{2,63}$")
_DOMAIN_COMPUTER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
_KERBEROS_MSG_TYPES = {
    10: "AS-REQ",
    11: "AS-REP",
    12: "TGS-REQ",
    13: "TGS-REP",
    14: "AP-REQ",
    15: "AP-REP",
    30: "KRB-ERROR",
}
_KERBEROS_ETYPE_MAP = {
    23: "RC4-HMAC",
    17: "AES128",
    18: "AES256",
    3: "DES-CBC-MD5",
    1: "DES-CBC-CRC",
}
_LDAP_RISKY_TOKENS = {
    "admincount=1": "Admin-protected object enumeration",
    "samaccountname=*": "Broad account enumeration wildcard",
    "msds-allowedtoactonbehalfofotheridentity": "RBCD delegation abuse surface",
    "serviceprincipalname=": "SPN discovery / kerberoast prep",
    "useraccountcontrol": "Account control flag manipulation/enumeration",
    "unicodepwd": "Password attribute reference",
    "trusteddomain": "Domain trust reconnaissance",
    "ms-pki-certificate-name-flag": "AD CS template abuse context",
    "pkicertificatetemplate": "AD CS template enumeration",
    "ntsecuritydescriptor": "ACL / security descriptor access",
}
_RELAY_COERCION_HINTS = ("wpad", "llmnr", "nbns", "responder", "mitm", "poison")


def _clean_identity_token(value: str) -> str:
    text = str(value or "").replace("\x00", "").strip()
    text = text.strip(" \t\r\n\"'`[]{}()<>,;:!|&*?^%")
    return text


def _looks_like_hex_noise(value: str) -> bool:
    text = str(value or "")
    if len(text) < 8 or len(text) % 2 != 0:
        return False
    return bool(re.fullmatch(r"[0-9A-Fa-f]+", text))


def _is_plausible_domain_user(value: str) -> bool:
    user = _clean_identity_token(value)
    if not user or user.lower() == "unknown":
        return False
    if not _DOMAIN_USER_RE.fullmatch(user):
        return False
    if _looks_like_hex_noise(user):
        return False
    if user.isdigit():
        return False
    if sum(1 for ch in user if ch.isalpha()) < 2:
        return False
    return True


def _is_plausible_computer_name(value: str) -> bool:
    name = _clean_identity_token(value)
    if not name or name.lower() == "unknown":
        return False
    if not _DOMAIN_COMPUTER_RE.fullmatch(name):
        return False
    if _looks_like_hex_noise(name):
        return False
    if sum(1 for ch in name if ch.isalpha()) < 2:
        return False
    return True


def _is_plausible_credential_string(value: str) -> bool:
    text = _clean_identity_token(value)
    if len(text) < 8 or len(text) > 140:
        return False
    if not any(ch.isalpha() for ch in text):
        return False
    if "=" not in text and ":" not in text:
        return False
    lower = text.lower()
    if any(
        token in lower
        for token in ("</", "<", ">", "&nbsp", "form", "submit", "button", "enter")
    ):
        return False
    return True


def _base_domain(name: str) -> str:
    name = name.strip(".")
    if not name:
        return name
    parts = [part for part in name.split(".") if part]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return name


def _extract_ascii_strings(
    data: bytes, min_len: int = 4, max_len: int = 200
) -> List[str]:
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


def _extract_utf16le_strings(
    data: bytes, min_len: int = 4, max_len: int = 200
) -> List[str]:
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


def _extract_kerberos_message_types(payload: bytes) -> List[str]:
    found: List[str] = []
    if not payload:
        return found
    try:
        for match in re.finditer(rb"[\xa0-\xbf]\x03\x02\x01(.)", payload):
            msg_code = int(match.group(1)[0])
            name = _KERBEROS_MSG_TYPES.get(msg_code)
            if name and name not in found:
                found.append(name)
    except Exception:
        return found
    return found


def _extract_kerberos_etypes(payload: bytes) -> List[str]:
    etypes: List[str] = []
    if not payload:
        return etypes
    try:
        for code, name in _KERBEROS_ETYPE_MAP.items():
            marker = bytes((0x02, 0x01, code & 0xFF))
            if marker in payload and name not in etypes:
                etypes.append(name)
    except Exception:
        return etypes
    return etypes


def _extract_primary_host_label(host_obj: object) -> str:
    names = getattr(host_obj, "names", []) or []
    for item in names:
        name = _clean_identity_token(str(getattr(item, "name", "") or ""))
        if name:
            return name
    group_name = _clean_identity_token(str(getattr(host_obj, "group_name", "") or ""))
    return group_name


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

    def _busy(desc: str, func, *args, **kwargs):
        return run_with_busy_status(
            path, show_status, f"Domain: {desc}", func, *args, **kwargs
        )

    dns_summary = _busy(
        "DNS", analyze_dns, path, show_status=False, packets=packets, meta=meta
    )
    netbios_summary = _busy("NetBIOS", analyze_netbios, path, show_status=False)
    ntlm_summary = _busy("NTLM", analyze_ntlm, path, show_status=False)
    files_summary = _busy("Files", analyze_files, path, show_status=False)

    domains = Counter()
    for qname, count in dns_summary.qname_counts.items():
        qname_lower = qname.lower().strip(".")
        if any(qname_lower.endswith(suffix) for suffix in _DOMAIN_SKIP_SUFFIXES):
            continue
        base = _base_domain(qname_lower)
        if base:
            domains[base] += count

    dc_hosts = Counter()
    host_labels_by_ip: Dict[str, str] = {}
    for ip, host in netbios_summary.hosts.items():
        if host.is_domain_controller:
            dc_hosts[ip] += 1
        primary = _extract_primary_host_label(host)
        if primary:
            host_labels_by_ip[str(ip)] = primary

    users = Counter(
        {
            name: int(count)
            for name, count in Counter(ntlm_summary.raw_users).items()
            if _is_plausible_domain_user(name)
        }
    )
    computer_names = Counter(
        {
            name: int(count)
            for name, count in Counter(ntlm_summary.raw_workstations).items()
            if _is_plausible_computer_name(name)
        }
    )

    for name in netbios_summary.unique_names:
        if _is_plausible_computer_name(name):
            computer_names[_clean_identity_token(name)] += 1

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
    server_service_hits: Dict[str, Counter[str]] = defaultdict(Counter)
    src_service_hits: Dict[str, Counter[str]] = defaultdict(Counter)
    pair_ports: Dict[Tuple[str, str], set[int]] = defaultdict(set)
    pair_packets: Counter[Tuple[str, str]] = Counter()
    ldap_simple_bind_hits: Counter[Tuple[str, str]] = Counter()
    ldap_anonymous_bind_hits: Counter[Tuple[str, str]] = Counter()
    kerberos_targets_by_src: Dict[str, set[str]] = defaultdict(set)
    adcs_hits: Counter[str] = Counter()
    ot_identity_overlap_hits: Counter[str] = Counter()
    dcsync_fingerprint_hits: Dict[Tuple[str, str], Counter[str]] = defaultdict(Counter)
    dcsync_fingerprint_packets: Dict[Tuple[str, str], List[int]] = defaultdict(list)
    kerberos_msgtype_by_src: Dict[str, Counter[str]] = defaultdict(Counter)
    kerberos_etypes_by_src: Dict[str, Counter[str]] = defaultdict(Counter)
    kerberos_spn_targets: Counter[Tuple[str, str]] = Counter()
    ldap_risky_query_hits: Counter[Tuple[str, str, str]] = Counter()
    relay_chain_hints_by_src: Counter[str] = Counter()
    src_first_packet: Dict[str, int] = {}

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

            src_first_packet.setdefault(src_ip, total_packets)

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp_layer = pkt[TCP]  # type: ignore[index]
                sport = int(getattr(tcp_layer, "sport", 0) or 0)
                dport = int(getattr(tcp_layer, "dport", 0) or 0)
                if dport in DOMAIN_PORTS or sport in DOMAIN_PORTS:
                    if dport in DOMAIN_PORTS:
                        server_ip = dst_ip
                        client_ip = src_ip
                        server_port = dport
                    else:
                        server_ip = src_ip
                        client_ip = dst_ip
                        server_port = sport

                    service_name = _port_to_domain_service(server_port)
                    servers[server_ip] += 1
                    clients[client_ip] += 1
                    service_counts[f"TCP/{server_port}"] += 1
                    convos[(client_ip, server_ip, server_port, "TCP")] += 1
                    server_service_hits[server_ip][service_name] += 1
                    src_service_hits[client_ip][service_name] += 1
                    pair_ports[(client_ip, server_ip)].add(server_port)
                    pair_packets[(client_ip, server_ip)] += 1
                    if server_port in KERBEROS_PORTS:
                        kerberos_targets_by_src[client_ip].add(server_ip)

                payload = bytes(getattr(tcp_layer, "payload", b""))
                if payload and ((dport in KERBEROS_PORTS) or (sport in KERBEROS_PORTS)):
                    kerb_src = src_ip if dport in KERBEROS_PORTS else dst_ip
                    kerb_dst = dst_ip if dport in KERBEROS_PORTS else src_ip
                    for msg_type in _extract_kerberos_message_types(payload):
                        kerberos_msgtype_by_src[kerb_src][msg_type] += 1
                    for etype in _extract_kerberos_etypes(payload):
                        kerberos_etypes_by_src[kerb_src][etype] += 1
                    payload_lower = payload.lower()
                    if b"krbtgt/" in payload_lower:
                        kerberos_spn_targets[(kerb_src, "krbtgt")] += 1
                    if (
                        b"serviceprincipalname" in payload_lower
                        or b"cifs/" in payload_lower
                        or b"http/" in payload_lower
                    ):
                        kerberos_spn_targets[(kerb_src, kerb_dst)] += 1

                if payload and (
                    (dport in RPC_PORTS)
                    or (sport in RPC_PORTS)
                    or dport == 445
                    or sport == 445
                ):
                    pair_key = (
                        (src_ip, dst_ip)
                        if dport in {135, 593, 445}
                        else (dst_ip, src_ip)
                    )
                    payload_lower = payload.lower()
                    if b"drsuapi" in payload_lower:
                        dcsync_fingerprint_hits[pair_key]["drsuapi_string"] += 1
                        dcsync_fingerprint_packets[pair_key].append(total_packets)
                    if b"idl_drsgetncchanges" in payload_lower:
                        dcsync_fingerprint_hits[pair_key]["drsgetncchanges"] += 1
                        dcsync_fingerprint_packets[pair_key].append(total_packets)
                    if (
                        b"\x35\x42\x51\xe3\x06\x4b\xd1\x11\xab\x04\x00\xc0\x4f\xc2\xdc\xd2"
                        in payload
                    ):
                        dcsync_fingerprint_hits[pair_key]["drsuapi_uuid"] += 1
                        dcsync_fingerprint_packets[pair_key].append(total_packets)

                if payload and payload.startswith(
                    (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ")
                ):
                    url, ua = _parse_http_request(payload)
                    if url:
                        urls[url] += 1
                    if ua:
                        user_agents[ua] += 1

                if payload:
                    extracted = _extract_ascii_strings(
                        payload
                    ) + _extract_utf16le_strings(payload)
                    values: set[str] = set()
                    for value in extracted:
                        cleaned = _clean_identity_token(value)
                        if cleaned:
                            values.add(cleaned)
                    for value in values:
                        value_lower = value.lower()
                        if any(token in value_lower for token in _RELAY_COERCION_HINTS):
                            relay_chain_hints_by_src[src_ip] += 1
                        if any(
                            token in value_lower
                            for token in (
                                "certsrv",
                                "pkinit",
                                "certipy",
                                "adcs",
                                "enrollment",
                                "enrollcert",
                            )
                        ):
                            adcs_hits[src_ip] += 1
                        if any(
                            token in value_lower
                            for token in (
                                "plc",
                                "scada",
                                "hmi",
                                "modbus",
                                "dnp3",
                                "iec104",
                                "profinet",
                                "s7",
                                "opc",
                            )
                        ):
                            ot_identity_overlap_hits[src_ip] += 1
                        if dport in LDAP_PORTS or sport in LDAP_PORTS:
                            pair_key = (
                                (src_ip, dst_ip)
                                if dport in LDAP_PORTS
                                else (dst_ip, src_ip)
                            )
                            for token, reason in _LDAP_RISKY_TOKENS.items():
                                if token in value_lower:
                                    ldap_risky_query_hits[
                                        (pair_key[0], pair_key[1], reason)
                                    ] += 1
                            if "simple" in value_lower and "bind" in value_lower:
                                ldap_simple_bind_hits[pair_key] += 1
                            if "anonymous" in value_lower and "bind" in value_lower:
                                ldap_anonymous_bind_hits[pair_key] += 1
                        for pattern in _CRED_USER_PATTERNS:
                            match = pattern.search(value)
                            if match:
                                user_val = _clean_identity_token(match.group(3))
                                if _is_plausible_domain_user(user_val):
                                    users[user_val] += 1
                        for pattern in _CRED_PASS_PATTERNS:
                            match = pattern.search(value)
                            if match:
                                field_name = _clean_identity_token(
                                    match.group(1) or "password"
                                ).lower()
                                raw_value = _clean_identity_token(match.group(3))
                                if not raw_value:
                                    continue
                                credential_value = f"{field_name}={raw_value}"
                                if _is_plausible_credential_string(credential_value):
                                    credentials[credential_value] += 1

            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp_layer = pkt[UDP]  # type: ignore[index]
                sport = int(getattr(udp_layer, "sport", 0) or 0)
                dport = int(getattr(udp_layer, "dport", 0) or 0)
                payload = bytes(getattr(udp_layer, "payload", b""))
                if dport in DOMAIN_PORTS or sport in DOMAIN_PORTS:
                    if dport in DOMAIN_PORTS:
                        server_ip = dst_ip
                        client_ip = src_ip
                        server_port = dport
                    else:
                        server_ip = src_ip
                        client_ip = dst_ip
                        server_port = sport

                    service_name = _port_to_domain_service(server_port)
                    servers[server_ip] += 1
                    clients[client_ip] += 1
                    service_counts[f"UDP/{server_port}"] += 1
                    convos[(client_ip, server_ip, server_port, "UDP")] += 1
                    server_service_hits[server_ip][service_name] += 1
                    src_service_hits[client_ip][service_name] += 1
                    pair_ports[(client_ip, server_ip)].add(server_port)
                    pair_packets[(client_ip, server_ip)] += 1
                    if server_port in KERBEROS_PORTS:
                        kerberos_targets_by_src[client_ip].add(server_ip)
                        for msg_type in _extract_kerberos_message_types(payload):
                            kerberos_msgtype_by_src[client_ip][msg_type] += 1
                        for etype in _extract_kerberos_etypes(payload):
                            kerberos_etypes_by_src[client_ip][etype] += 1
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
        detections.append(
            {
                "severity": "info",
                "summary": "Domain Controllers observed",
                "details": ", ".join(dc_hosts.keys()),
                "source": "Domain",
            }
        )
    if users:
        detections.append(
            {
                "severity": "info",
                "summary": "Domain users observed",
                "details": ", ".join([u for u, _ in users.most_common(10)]),
                "source": "Domain",
            }
        )
    if credentials:
        detections.append(
            {
                "severity": "warning",
                "summary": "Potential credentials observed",
                "details": ", ".join([c for c, _ in credentials.most_common(5)]),
                "source": "Domain",
            }
        )

    deterministic_checks: Dict[str, List[str]] = {
        "dc_role_consistency": [],
        "kerberos_ticket_abuse": [],
        "dcsync_replication_activity": [],
        "ldap_bind_risk": [],
        "ntlm_downgrade_or_relay_exposure": [],
        "auth_sequence_plausibility": [],
        "name_resolution_poisoning_context": [],
        "privileged_account_spread": [],
        "public_domain_service_exposure": [],
        "adcs_or_certificate_abuse_context": [],
        "credential_material_in_domain_flows": [],
        "ot_identity_attack_surface_overlap": [],
        "dcsync_fingerprint_evidence": [],
        "kerberos_roast_or_cipher_risk": [],
        "ldap_directory_abuse_context": [],
        "relay_coercion_chain_context": [],
        "identity_attack_path_correlation": [],
        "baseline_service_deviation": [],
    }
    dc_role_drift: List[Dict[str, object]] = []
    kerberos_abuse_profiles: List[Dict[str, object]] = []
    dcsync_signals: List[Dict[str, object]] = []
    ldap_bind_risks: List[Dict[str, object]] = []
    ntlm_relay_signals: List[str] = []
    sequence_violations: List[Dict[str, object]] = []
    host_attack_paths: List[Dict[str, object]] = []
    incident_clusters: List[Dict[str, object]] = []
    campaign_indicators: List[Dict[str, object]] = []
    benign_context: List[str] = []
    baseline_anomalies: List[Dict[str, object]] = []

    dc_set = set(dc_hosts.keys())

    for server_ip, svc_counter in server_service_hits.items():
        infra_services = [
            name
            for name in ("Kerberos", "LDAP", "SMB", "RPC")
            if int(svc_counter.get(name, 0)) > 0
        ]
        if len(infra_services) >= 2 and int(servers.get(server_ip, 0)) >= 20:
            if server_ip not in dc_set:
                item = {
                    "server": server_ip,
                    "services": infra_services,
                    "packets": int(servers.get(server_ip, 0)),
                    "observed_as_dc": False,
                }
                dc_role_drift.append(item)
                deterministic_checks["dc_role_consistency"].append(
                    f"{server_ip} exposes multi-role domain services ({', '.join(infra_services)}) but is not flagged as a DC"
                )

    for src_ip, svc_counter in src_service_hits.items():
        kerberos_hits = int(svc_counter.get("Kerberos", 0))
        target_count = len(kerberos_targets_by_src.get(src_ip, set()))
        if kerberos_hits >= 20 and target_count >= 3:
            profile = {
                "src": src_ip,
                "kerberos_requests": kerberos_hits,
                "target_dcs": target_count,
                "targets": sorted(kerberos_targets_by_src.get(src_ip, set())),
            }
            kerberos_abuse_profiles.append(profile)
            deterministic_checks["kerberos_ticket_abuse"].append(
                f"{src_ip} generated {kerberos_hits} Kerberos requests across {target_count} targets"
            )

    for (src_ip, dst_ip), ports in pair_ports.items():
        if dst_ip not in dc_set or src_ip in dc_set:
            continue
        if (
            (135 in ports or 593 in ports)
            and 445 in ports
            and bool(set(ports).intersection(LDAP_PORTS))
        ):
            signal = {
                "src": src_ip,
                "dc": dst_ip,
                "ports": sorted(ports),
                "packets": int(pair_packets.get((src_ip, dst_ip), 0)),
            }
            dcsync_signals.append(signal)
            deterministic_checks["dcsync_replication_activity"].append(
                f"{src_ip} contacted DC {dst_ip} over RPC+SMB+LDAP (ports={','.join(str(p) for p in sorted(ports))})"
            )

    for (src_ip, dst_ip), token_counts in dcsync_fingerprint_hits.items():
        if dst_ip not in dc_set:
            continue
        if src_ip in dc_set:
            continue
        evidence = [
            f"{name}={int(count)}"
            for name, count in token_counts.items()
            if int(count) > 0
        ]
        if not evidence:
            continue
        packet_refs = sorted(set(dcsync_fingerprint_packets.get((src_ip, dst_ip), [])))[
            :5
        ]
        deterministic_checks["dcsync_fingerprint_evidence"].append(
            f"{src_ip}->{dst_ip} fingerprints [{', '.join(evidence)}] packets={','.join(str(v) for v in packet_refs) or '-'}"
        )

    cleartext_ldap_pairs = []
    for (src_ip, dst_ip), ports in pair_ports.items():
        if 389 in ports:
            cleartext_ldap_pairs.append(
                (src_ip, dst_ip, int(pair_packets.get((src_ip, dst_ip), 0)))
            )
    cleartext_ldap_pairs.sort(key=lambda item: item[2], reverse=True)
    for src_ip, dst_ip, pkt_count in cleartext_ldap_pairs[:8]:
        item = {
            "src": src_ip,
            "dst": dst_ip,
            "type": "cleartext_ldap",
            "packets": pkt_count,
        }
        ldap_bind_risks.append(item)
        deterministic_checks["ldap_bind_risk"].append(
            f"Cleartext LDAP observed: {src_ip}->{dst_ip} packets={pkt_count}"
        )

    for (src_ip, dst_ip), count in ldap_simple_bind_hits.most_common(8):
        ldap_bind_risks.append(
            {
                "src": src_ip,
                "dst": dst_ip,
                "type": "simple_bind",
                "hits": int(count),
            }
        )
        deterministic_checks["ldap_bind_risk"].append(
            f"Possible LDAP simple bind strings on {src_ip}->{dst_ip} hits={int(count)}"
        )
    for (src_ip, dst_ip), count in ldap_anonymous_bind_hits.most_common(8):
        ldap_bind_risks.append(
            {
                "src": src_ip,
                "dst": dst_ip,
                "type": "anonymous_bind",
                "hits": int(count),
            }
        )
        deterministic_checks["ldap_bind_risk"].append(
            f"Possible LDAP anonymous bind strings on {src_ip}->{dst_ip} hits={int(count)}"
        )
    for (src_ip, dst_ip, reason), count in ldap_risky_query_hits.most_common(12):
        deterministic_checks["ldap_directory_abuse_context"].append(
            f"{src_ip}->{dst_ip} {reason} hits={int(count)}"
        )

    ntlm_versions = getattr(ntlm_summary, "versions", Counter())
    ntlm_v1_hits = int(ntlm_versions.get("NTLMv1", 0)) + int(ntlm_versions.get("v1", 0))
    if ntlm_v1_hits > 0:
        msg = f"NTLMv1 authentication observed ({ntlm_v1_hits})"
        ntlm_relay_signals.append(msg)
        deterministic_checks["ntlm_downgrade_or_relay_exposure"].append(msg)
    for item in getattr(ntlm_summary, "anomalies", []):
        title = str(getattr(item, "title", "") or "")
        if "Anonymous NTLM" in title or "NTLMv1" in title:
            evidence = f"{title}: {str(getattr(item, 'description', '') or '')}"
            ntlm_relay_signals.append(evidence)
            deterministic_checks["ntlm_downgrade_or_relay_exposure"].append(evidence)

    for src_ip, msg_counter in kerberos_msgtype_by_src.items():
        as_req = int(msg_counter.get("AS-REQ", 0))
        tgs_req = int(msg_counter.get("TGS-REQ", 0))
        tgs_rep = int(msg_counter.get("TGS-REP", 0))
        if as_req >= 10 and tgs_req >= 25 and tgs_req >= max(1, (as_req * 2)):
            deterministic_checks["kerberos_roast_or_cipher_risk"].append(
                f"{src_ip} produced elevated Kerberos ticket-request ratio AS-REQ={as_req} TGS-REQ={tgs_req}"
            )
        if tgs_req >= 20 and tgs_rep == 0:
            deterministic_checks["kerberos_roast_or_cipher_risk"].append(
                f"{src_ip} generated many TGS-REQ without visible TGS-REP responses (req={tgs_req})"
            )
    for src_ip, et_counter in kerberos_etypes_by_src.items():
        rc4 = int(et_counter.get("RC4-HMAC", 0))
        aes = int(et_counter.get("AES128", 0)) + int(et_counter.get("AES256", 0))
        if rc4 >= 5 and rc4 > aes:
            deterministic_checks["kerberos_roast_or_cipher_risk"].append(
                f"{src_ip} Kerberos encryption skew favors RC4 (RC4={rc4}, AES={aes})"
            )
        if (
            int(et_counter.get("DES-CBC-MD5", 0)) > 0
            or int(et_counter.get("DES-CBC-CRC", 0)) > 0
        ):
            deterministic_checks["kerberos_roast_or_cipher_risk"].append(
                f"{src_ip} legacy DES Kerberos etype observed ({', '.join(k for k, v in et_counter.items() if v and k.startswith('DES'))})"
            )
    for (src_ip, spn_target), count in kerberos_spn_targets.items():
        if count >= 8:
            deterministic_checks["kerberos_roast_or_cipher_risk"].append(
                f"{src_ip} repeated Kerberos SPN targeting toward {spn_target} hits={int(count)}"
            )

    ntlm_src_counts = getattr(ntlm_summary, "src_counts", Counter())
    for src_ip, svc_counter in src_service_hits.items():
        lateral_hits = int(svc_counter.get("SMB", 0)) + int(svc_counter.get("RPC", 0))
        auth_signal = int(svc_counter.get("Kerberos", 0)) + int(
            ntlm_src_counts.get(src_ip, 0)
        )
        if lateral_hits >= 15 and auth_signal == 0:
            violation = {
                "src": src_ip,
                "lateral_hits": lateral_hits,
                "auth_signals": auth_signal,
                "reason": "SMB/RPC activity without clear auth precursor",
            }
            sequence_violations.append(violation)
            deterministic_checks["auth_sequence_plausibility"].append(
                f"{src_ip} produced SMB/RPC activity ({lateral_hits}) without visible auth precursor"
            )

    high_risk_nbns = [
        a
        for a in getattr(netbios_summary, "anomalies", [])
        if str(getattr(a, "severity", "")).upper() in {"HIGH", "CRITICAL"}
    ]
    if high_risk_nbns:
        for item in high_risk_nbns[:8]:
            deterministic_checks["name_resolution_poisoning_context"].append(
                f"{item.type} {item.src_ip}->{item.dst_ip}: {item.details}"
            )

    nbns_sources = {
        str(getattr(a, "src_ip", "") or "")
        for a in high_risk_nbns
        if str(getattr(a, "src_ip", "") or "")
    }
    for src_ip in sorted(nbns_sources):
        svc_counter = src_service_hits.get(src_ip, Counter())
        ntlm_hits = int(ntlm_src_counts.get(src_ip, 0))
        smb_rpc_hits = int(svc_counter.get("SMB", 0)) + int(svc_counter.get("RPC", 0))
        relay_hints = int(relay_chain_hints_by_src.get(src_ip, 0))
        if ntlm_hits > 0 and smb_rpc_hits > 0:
            deterministic_checks["relay_coercion_chain_context"].append(
                f"{src_ip} poisoning context + NTLM({ntlm_hits}) + SMB/RPC({smb_rpc_hits}) suggests relay/coercion chain"
            )
        if relay_hints > 0:
            deterministic_checks["relay_coercion_chain_context"].append(
                f"{src_ip} contains relay/coercion lexical hints in payload strings hits={relay_hints}"
            )

    user_to_hosts: Dict[str, set[str]] = defaultdict(set)
    for sess in getattr(ntlm_summary, "sessions", []):
        username = str(getattr(sess, "username", "") or "").strip()
        src_ip = str(getattr(sess, "src_ip", "") or "").strip()
        if username and src_ip and _is_plausible_domain_user(username):
            user_to_hosts[username].add(src_ip)
    for username, hosts in user_to_hosts.items():
        if len(hosts) >= 3:
            deterministic_checks["privileged_account_spread"].append(
                f"Account {username} used from {len(hosts)} hosts ({', '.join(sorted(hosts)[:6])})"
            )

    for service_name in ("Kerberos", "LDAP", "SMB", "RPC", "DNS"):
        sample = [
            int(counter.get(service_name, 0))
            for counter in src_service_hits.values()
            if int(counter.get(service_name, 0)) > 0
        ]
        if len(sample) < 3:
            continue
        avg = float(sum(sample) / len(sample))
        variance = float(sum((value - avg) ** 2 for value in sample) / len(sample))
        stdev = math.sqrt(variance)
        if stdev <= 0:
            continue
        for src_ip, counter in src_service_hits.items():
            value = int(counter.get(service_name, 0))
            if value <= 0:
                continue
            zscore = (value - avg) / stdev
            if zscore >= 2.5:
                baseline_anomalies.append(
                    {
                        "src": src_ip,
                        "service": service_name,
                        "count": value,
                        "avg": avg,
                        "stdev": stdev,
                        "zscore": zscore,
                    }
                )
                deterministic_checks["baseline_service_deviation"].append(
                    f"{src_ip} {service_name} volume={value} deviates from peer baseline (avg={avg:.1f}, z={zscore:.2f})"
                )

    for server_ip, count in servers.items():
        server_text = str(server_ip)
        if "." not in server_text and ":" not in server_text:
            continue
        try:
            if ipaddress.ip_address(server_text).is_global:
                deterministic_checks["public_domain_service_exposure"].append(
                    f"Public domain-service endpoint observed server={server_text} packets={int(count)}"
                )
        except Exception:
            continue

    for src_ip, count in adcs_hits.most_common(10):
        deterministic_checks["adcs_or_certificate_abuse_context"].append(
            f"AD CS / certificate enrollment context from {src_ip} hits={int(count)}"
        )
    for src_ip, count in ot_identity_overlap_hits.most_common(10):
        deterministic_checks["ot_identity_attack_surface_overlap"].append(
            f"OT/ICS context mixed with identity/domain strings from {src_ip} hits={int(count)}"
        )
    for cred, count in credentials.most_common(12):
        deterministic_checks["credential_material_in_domain_flows"].append(
            f"Credential-like material observed count={int(count)} sample={cred[:96]}"
        )

    host_accounts: Dict[str, set[str]] = defaultdict(set)
    for account, hosts in user_to_hosts.items():
        for host in hosts:
            host_accounts[host].add(account)

    indicators_by_src: Dict[str, List[str]] = defaultdict(list)
    targets_by_src: Dict[str, set[str]] = defaultdict(set)
    for item in kerberos_abuse_profiles:
        src_ip = str(item.get("src", ""))
        indicators_by_src[src_ip].append(
            "Kerberos ticketing burst across multiple targets"
        )
        for target in item.get("targets", []):
            targets_by_src[src_ip].add(str(target))
    for item in dcsync_signals:
        src_ip = str(item.get("src", ""))
        indicators_by_src[src_ip].append("Replication-like RPC+SMB+LDAP sequence to DC")
        targets_by_src[src_ip].add(str(item.get("dc", "")))
    for item in sequence_violations:
        src_ip = str(item.get("src", ""))
        indicators_by_src[src_ip].append(
            str(item.get("reason", "Sequence plausibility issue"))
        )

    for src_ip, indicators in indicators_by_src.items():
        unique_indicators = list(dict.fromkeys([v for v in indicators if v]))
        if not unique_indicators:
            continue
        confidence = "high" if len(unique_indicators) >= 2 else "medium"
        services = src_service_hits.get(src_ip, Counter())
        service_path = [
            name
            for name in ("Kerberos", "LDAP", "SMB", "RPC", "DNS")
            if int(services.get(name, 0)) > 0
        ]
        account_values = sorted(host_accounts.get(src_ip, set()))
        first_pkt = int(src_first_packet.get(src_ip, 0))
        target_rows = sorted(targets_by_src.get(src_ip, set()))
        labeled_targets = []
        for target in target_rows:
            label_value = host_labels_by_ip.get(str(target), "")
            if label_value:
                labeled_targets.append(f"{target}({label_value})")
            else:
                labeled_targets.append(str(target))
        host_attack_paths.append(
            {
                "host": src_ip,
                "steps": unique_indicators,
                "targets": labeled_targets,
                "accounts": account_values,
                "service_path": service_path,
                "first_packet": first_pkt,
                "confidence": confidence,
            }
        )
        deterministic_checks["identity_attack_path_correlation"].append(
            f"{src_ip} path services={','.join(service_path) or '-'} accounts={','.join(account_values[:3]) or '-'} "
            f"targets={','.join(target_rows[:3]) or '-'} first_packet={first_pkt}"
        )
        incident_clusters.append(
            {
                "cluster": f"cluster-{src_ip}",
                "host": src_ip,
                "indicators": unique_indicators,
                "target_count": len(targets_by_src.get(src_ip, set())),
                "confidence": confidence,
            }
        )

    shared_dc_sources: Dict[str, set[str]] = defaultdict(set)
    for signal in dcsync_signals:
        shared_dc_sources[str(signal.get("dc", ""))].add(str(signal.get("src", "")))
    for dc_ip, source_hosts in shared_dc_sources.items():
        if len(source_hosts) >= 2:
            campaign_indicators.append(
                {
                    "indicator": "Shared DC target for replication-like behavior",
                    "value": dc_ip,
                    "hosts": sorted(source_hosts),
                }
            )

    for username, hosts in user_to_hosts.items():
        if len(hosts) >= 2:
            campaign_indicators.append(
                {
                    "indicator": "Shared account across hosts",
                    "value": username,
                    "hosts": sorted(hosts),
                }
            )

    relay_sources: Dict[str, set[str]] = defaultdict(set)
    for evidence in deterministic_checks["relay_coercion_chain_context"]:
        match = re.match(r"^(\S+)", str(evidence))
        if not match:
            continue
        src_ip = match.group(1)
        for target in targets_by_src.get(src_ip, set()):
            relay_sources[src_ip].add(str(target))
    for src_ip, targets in relay_sources.items():
        campaign_indicators.append(
            {
                "indicator": "Potential relay/coercion campaign path",
                "value": src_ip,
                "hosts": sorted(targets),
            }
        )

    if baseline_anomalies:
        for item in baseline_anomalies[:10]:
            campaign_indicators.append(
                {
                    "indicator": "Service baseline outlier",
                    "value": f"{item.get('src', '-')}/{item.get('service', '-')}",
                    "hosts": [str(item.get("src", "-"))],
                }
            )

    if not deterministic_checks["dc_role_consistency"]:
        benign_context.append(
            "No strong DC role drift signal based on observed service mix"
        )
    if not deterministic_checks["auth_sequence_plausibility"]:
        benign_context.append(
            "No major domain auth sequence plausibility violations detected"
        )
    if not deterministic_checks["baseline_service_deviation"]:
        benign_context.append(
            "No material per-service baseline deviation detected among active domain clients"
        )

    if deterministic_checks["kerberos_ticket_abuse"]:
        detections.append(
            {
                "severity": "warning",
                "summary": "Kerberos ticket abuse indicators",
                "details": "; ".join(deterministic_checks["kerberos_ticket_abuse"][:3]),
                "source": "Domain",
            }
        )
    if deterministic_checks["dcsync_replication_activity"]:
        detections.append(
            {
                "severity": "high",
                "summary": "Replication-like access pattern to Domain Controllers",
                "details": "; ".join(
                    deterministic_checks["dcsync_replication_activity"][:3]
                ),
                "source": "Domain",
            }
        )
    if deterministic_checks["ntlm_downgrade_or_relay_exposure"]:
        detections.append(
            {
                "severity": "warning",
                "summary": "NTLM downgrade/relay exposure",
                "details": "; ".join(
                    deterministic_checks["ntlm_downgrade_or_relay_exposure"][:3]
                ),
                "source": "Domain",
            }
        )
    if deterministic_checks["public_domain_service_exposure"]:
        detections.append(
            {
                "severity": "high",
                "summary": "Public exposure of domain-control protocol surface",
                "details": "; ".join(
                    deterministic_checks["public_domain_service_exposure"][:3]
                ),
                "source": "Domain",
            }
        )
    if deterministic_checks["adcs_or_certificate_abuse_context"]:
        detections.append(
            {
                "severity": "warning",
                "summary": "AD CS / certificate abuse context indicators",
                "details": "; ".join(
                    deterministic_checks["adcs_or_certificate_abuse_context"][:3]
                ),
                "source": "Domain",
            }
        )
    if deterministic_checks["credential_material_in_domain_flows"]:
        detections.append(
            {
                "severity": "warning",
                "summary": "Credential material observed in domain traffic flows",
                "details": "; ".join(
                    deterministic_checks["credential_material_in_domain_flows"][:3]
                ),
                "source": "Domain",
            }
        )
    if deterministic_checks["dcsync_fingerprint_evidence"]:
        detections.append(
            {
                "severity": "high",
                "summary": "DCSync RPC fingerprint evidence observed",
                "details": "; ".join(
                    deterministic_checks["dcsync_fingerprint_evidence"][:3]
                ),
                "source": "Domain",
            }
        )
    if deterministic_checks["kerberos_roast_or_cipher_risk"]:
        detections.append(
            {
                "severity": "warning",
                "summary": "Kerberos roast/cipher-risk context observed",
                "details": "; ".join(
                    deterministic_checks["kerberos_roast_or_cipher_risk"][:3]
                ),
                "source": "Domain",
            }
        )
    if deterministic_checks["relay_coercion_chain_context"]:
        detections.append(
            {
                "severity": "high",
                "summary": "Relay/coercion chain context observed",
                "details": "; ".join(
                    deterministic_checks["relay_coercion_chain_context"][:3]
                ),
                "source": "Domain",
            }
        )
    if deterministic_checks["baseline_service_deviation"]:
        detections.append(
            {
                "severity": "warning",
                "summary": "Domain client baseline deviation observed",
                "details": "; ".join(
                    deterministic_checks["baseline_service_deviation"][:3]
                ),
                "source": "Domain",
            }
        )

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
        deterministic_checks=deterministic_checks,
        dc_role_drift=dc_role_drift,
        kerberos_abuse_profiles=kerberos_abuse_profiles,
        dcsync_signals=dcsync_signals,
        ldap_bind_risks=ldap_bind_risks,
        ntlm_relay_signals=ntlm_relay_signals,
        sequence_violations=sequence_violations,
        host_attack_paths=host_attack_paths,
        incident_clusters=incident_clusters,
        campaign_indicators=campaign_indicators,
        baseline_anomalies=baseline_anomalies,
        benign_context=benign_context,
    )
