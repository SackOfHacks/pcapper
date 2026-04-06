from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
import ipaddress
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .pcap_cache import PcapMeta, get_reader
from .utils import safe_float

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore


KERBEROS_PORTS = {88, 464}

UPN_RE = re.compile(r"\b([A-Za-z0-9._$-]{3,})@([A-Za-z0-9.-]{3,})\b")
SPN_RE = re.compile(r"\b([A-Za-z0-9._-]{3,}/[A-Za-z0-9._:-]{3,})(?:@([A-Za-z0-9.-]{3,}))?\b")
ERR_RE = re.compile(r"\bKDC_ERR_[A-Z0-9_]+\b")
REQ_RE = re.compile(r"\b(AS-REQ|AS-REP|TGS-REQ|TGS-REP|KRB_ERROR|S4U2SELF|S4U2PROXY|PA-ENC-TIMESTAMP)\b", re.IGNORECASE)

CNAME_SUFFIXES = (
    ".local",
    ".lan",
    ".corp",
    ".internal",
    ".intra",
    ".private",
    ".home",
    ".lab",
    ".test",
    ".example",
    ".com",
    ".net",
    ".org",
    ".edu",
    ".gov",
    ".mil",
    ".int",
    ".co.uk",
    ".org.uk",
    ".gov.uk",
    ".ac.uk",
)
CNAME_USER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._$-]{2,63}$")
_ARTIFACT_TOKEN_RE = re.compile(r"^[A-Za-z0-9@._:/$-]{4,200}$")
_REALM_TOKEN_RE = re.compile(r"^[A-Za-z0-9.-]{3,128}$")
_PRINCIPAL_LOCAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._$-]{2,63}$")
_SPN_SERVICE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{2,31}$")
_SPN_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
_KNOWN_SPN_SERVICES = {
    "HOST",
    "CIFS",
    "HTTP",
    "LDAP",
    "MSSQLSVC",
    "RPCSS",
    "WSMAN",
    "TERMSRV",
    "DNS",
    "NFS",
    "FTP",
    "SMTP",
    "IMAP",
    "POP",
    "RPC",
    "GC",
    "KADMIN",
    "KPASSWD",
    "RESTRICTEDKRBHOST",
    "KRBTGT",
}
_KERBEROS_TEXT_MARKERS = (
    "krb",
    "kdc_err_",
    "as-req",
    "as-rep",
    "tgs-req",
    "tgs-rep",
    "s4u2self",
    "s4u2proxy",
    "pa-enc-timestamp",
    "krbtgt",
)


def _clean_identity_token(value: str) -> str:
    text = str(value or "").strip()
    text = text.strip(" \t\r\n\"'`[]{}()<>,;:!|&*?^%")
    return text


def _normalize_realm(value: str) -> str:
    return _clean_identity_token(value).upper()


def _is_plausible_realm(value: str) -> bool:
    realm = _normalize_realm(value)
    if not realm or not _REALM_TOKEN_RE.fullmatch(realm):
        return False
    if not realm[0].isalnum() or not realm[-1].isalnum():
        return False
    if sum(1 for ch in realm if ch.isalpha()) < 3:
        return False
    if ".." in realm or "--" in realm:
        return False
    if "." in realm:
        labels = realm.split(".")
        if len(labels) < 2:
            return False
        for label in labels:
            if len(label) < 2 or not re.fullmatch(r"[A-Z0-9-]+", label):
                return False
            if label[0] == "-" or label[-1] == "-":
                return False
            if label.isdigit():
                return False
        return True
    if len(realm) < 5:
        return False
    return realm == realm.upper() and re.fullmatch(r"[A-Z0-9-]+", realm) is not None


def _normalize_principal_local(value: str) -> str:
    return _clean_identity_token(value)


def _is_plausible_principal_local(value: str) -> bool:
    local = _normalize_principal_local(value)
    if not local or not _PRINCIPAL_LOCAL_RE.fullmatch(local):
        return False
    if local.isdigit():
        return False
    if sum(1 for ch in local if ch.isalpha()) < 2:
        return False
    if local.count(".") > 3:
        return False
    return True


def _normalize_spn(value: str) -> str:
    return _clean_identity_token(value)


def _is_plausible_spn(value: str) -> bool:
    spn = _normalize_spn(value)
    if "/" not in spn:
        return False
    service, host_part = spn.split("/", 1)
    host_only = host_part.split("@", 1)[0].split(":", 1)[0]
    if not _SPN_SERVICE_RE.fullmatch(service):
        return False
    if not _SPN_HOST_RE.fullmatch(host_only):
        return False
    if host_only.count(".") > 6:
        return False
    if sum(1 for ch in host_only if ch.isalpha()) < 2:
        return False
    service_upper = service.upper()
    if "." not in host_only and "-" not in host_only and service_upper not in _KNOWN_SPN_SERVICES:
        if len(host_only) < 8:
            return False
    return True


def _is_useful_kerberos_artifact(value: str) -> bool:
    text = _clean_identity_token(value)
    if len(text) < 4:
        return False
    if not _ARTIFACT_TOKEN_RE.fullmatch(text):
        return False
    lower = text.lower()
    if any(marker in lower for marker in _KERBEROS_TEXT_MARKERS):
        return True
    if UPN_RE.search(text):
        return True
    if SPN_RE.search(text):
        return True
    if "." in text and sum(1 for ch in text if ch.isalpha()) >= 4:
        return True
    return False


def _artifact_sort_key(value: str) -> tuple[int, int, int, str]:
    text = str(value)
    lower = text.lower()
    marker_rank = 0 if any(marker in lower for marker in _KERBEROS_TEXT_MARKERS) else 1
    identity_rank = 0 if ("@" in text or "/" in text or "." in text) else 1
    return (marker_rank, identity_rank, -len(text), text)


def _split_cname_concat(value: str) -> Optional[tuple[str, str]]:
    text = _clean_identity_token(value)
    if len(text) < 6 or "@" in text or "\\" in text:
        return None
    lower = text.lower()
    best: tuple[int, str, str] | None = None
    for suffix in CNAME_SUFFIXES:
        start = 0
        while True:
            idx = lower.find(suffix, start)
            if idx == -1:
                break
            end = idx + len(suffix)
            if end >= len(text):
                start = idx + 1
                continue
            realm = text[:end]
            user = text[end:]
            user = _normalize_principal_local(user)
            realm = _normalize_realm(realm)
            if not CNAME_USER_RE.fullmatch(user):
                start = idx + 1
                continue
            if realm.count(".") < 1:
                start = idx + 1
                continue
            if not _is_plausible_realm(realm):
                start = idx + 1
                continue
            if not _is_plausible_principal_local(user):
                start = idx + 1
                continue
            score = 0
            if user.islower():
                score += 3
            if user.isalpha():
                score += 1
            if "." not in user:
                score += 2
            if realm.isupper():
                score += 2
            if any(ch.isdigit() for ch in user):
                score -= 1
            if best is None or score > best[0] or (score == best[0] and len(realm) > len(best[1])):
                best = (score, realm, user)
            start = idx + 1
    if not best:
        return None
    return best[2], best[1]


@dataclass(frozen=True)
class KerberosConversation:
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str
    packets: int


@dataclass(frozen=True)
class KerberosAnalysis:
    path: Path
    duration: float
    first_seen: Optional[float]
    last_seen: Optional[float]
    total_packets: int
    servers: Counter[str]
    clients: Counter[str]
    service_counts: Counter[str]
    request_types: Counter[str]
    error_codes: Counter[str]
    realms: Counter[str]
    principals: Counter[str]
    spns: Counter[str]
    conversations: List[KerberosConversation]
    session_stats: Dict[str, int]
    tcp_packets: int
    udp_packets: int
    public_endpoints: Counter[str]
    suspicious_attributes: Counter[str]
    bind_bursts: Counter[str]
    principal_evidence: List[Dict[str, object]]
    artifacts: List[str]
    anomalies: List[str]
    detections: List[Dict[str, object]]
    errors: List[str]
    deterministic_checks: Dict[str, List[str]] = field(default_factory=dict)
    attack_matrix: List[Dict[str, str]] = field(default_factory=list)


def _build_kerberos_attack_overview(
    *,
    request_types: Counter[str],
    error_codes: Counter[str],
    spns: Counter[str],
    public_endpoints: Counter[str],
    bind_bursts: Counter[str],
    request_types_by_client: dict[str, Counter[str]],
    spns_by_client: dict[str, set[str]],
    realms_by_client: dict[str, set[str]],
    error_by_client: dict[str, Counter[str]],
) -> tuple[Dict[str, List[str]], List[Dict[str, str]]]:
    checks: Dict[str, List[str]] = {
        "kerberoasting": [],
        "asrep_roasting": [],
        "password_spray_bruteforce": [],
        "delegation_abuse": [],
        "ticket_forgery_ptt": [],
        "user_enumeration": [],
        "public_kdc_exposure": [],
        "cross_realm_or_realm_spray": [],
    }
    matrix: List[Dict[str, str]] = []

    def _status_row(attack: str, status: str, severity: str, evidence: str) -> None:
        matrix.append({
            "attack": attack,
            "status": status,
            "severity": severity,
            "evidence": evidence,
        })

    tgs_req = int(request_types.get("TGS-REQ", 0))
    unique_spn = len(spns)
    kerberoast_clients: list[str] = []
    for client_ip, reqs in request_types_by_client.items():
        client_tgs = int(reqs.get("TGS-REQ", 0))
        client_spns = len(spns_by_client.get(client_ip, set()))
        if client_tgs >= 20 and client_spns >= 8:
            kerberoast_clients.append(f"{client_ip}(tgs={client_tgs},spn={client_spns})")
    if (tgs_req >= 50 and unique_spn >= 15) or kerberoast_clients:
        checks["kerberoasting"].append(f"TGS-REQ={tgs_req}, unique SPNs={unique_spn}")
        if kerberoast_clients:
            checks["kerberoasting"].append(f"Top clients: {', '.join(kerberoast_clients[:5])}")
        _status_row(
            "Kerberoasting (TGS ticket harvesting)",
            "suspicious",
            "high",
            "; ".join(checks["kerberoasting"]) or f"TGS-REQ={tgs_req}, unique SPNs={unique_spn}",
        )
    elif tgs_req >= 15 and unique_spn >= 8:
        checks["kerberoasting"].append(f"TGS-REQ={tgs_req}, unique SPNs={unique_spn}")
        _status_row(
            "Kerberoasting (TGS ticket harvesting)",
            "watch",
            "warning",
            checks["kerberoasting"][0],
        )
    else:
        _status_row(
            "Kerberoasting (TGS ticket harvesting)",
            "not observed",
            "info",
            f"TGS-REQ={tgs_req}, unique SPNs={unique_spn}",
        )

    as_rep = int(request_types.get("AS-REP", 0))
    preauth_required = int(error_codes.get("KDC_ERR_PREAUTH_REQUIRED", 0))
    if as_rep >= 5 and preauth_required == 0:
        checks["asrep_roasting"].append(f"AS-REP={as_rep} with no KDC_ERR_PREAUTH_REQUIRED")
        _status_row("AS-REP roasting", "suspicious", "high", checks["asrep_roasting"][0])
    elif as_rep >= 10 and as_rep > preauth_required:
        checks["asrep_roasting"].append(
            f"AS-REP={as_rep} exceeds preauth-required errors={preauth_required}"
        )
        _status_row("AS-REP roasting", "watch", "warning", checks["asrep_roasting"][0])
    else:
        _status_row(
            "AS-REP roasting",
            "not observed",
            "info",
            f"AS-REP={as_rep}, KDC_ERR_PREAUTH_REQUIRED={preauth_required}",
        )

    preauth_failed = int(error_codes.get("KDC_ERR_PREAUTH_FAILED", 0))
    peak_burst = int(max(bind_bursts.values()) if bind_bursts else 0)
    spray_clients = [
        f"{client_ip}({int(codes.get('KDC_ERR_PREAUTH_FAILED', 0))})"
        for client_ip, codes in error_by_client.items()
        if int(codes.get("KDC_ERR_PREAUTH_FAILED", 0)) >= 10
    ]
    if peak_burst >= 20 or preauth_failed >= 30 or len(spray_clients) >= 2:
        checks["password_spray_bruteforce"].append(
            f"Preauth failures={preauth_failed}, peak AS/TGS req/min={peak_burst}"
        )
        if spray_clients:
            checks["password_spray_bruteforce"].append(f"Top clients: {', '.join(spray_clients[:5])}")
        _status_row(
            "Password spray / brute-force",
            "suspicious",
            "high",
            "; ".join(checks["password_spray_bruteforce"]),
        )
    elif preauth_failed >= 10:
        checks["password_spray_bruteforce"].append(
            f"Preauth failures elevated ({preauth_failed})"
        )
        _status_row(
            "Password spray / brute-force",
            "watch",
            "warning",
            checks["password_spray_bruteforce"][0],
        )
    else:
        _status_row(
            "Password spray / brute-force",
            "not observed",
            "info",
            f"KDC_ERR_PREAUTH_FAILED={preauth_failed}, peak/min={peak_burst}",
        )

    s4u2self = int(request_types.get("S4U2SELF", 0))
    s4u2proxy = int(request_types.get("S4U2PROXY", 0))
    s4u_total = s4u2self + s4u2proxy
    if s4u_total >= 10:
        checks["delegation_abuse"].append(f"S4U2SELF={s4u2self}, S4U2PROXY={s4u2proxy}")
        _status_row("Delegation abuse (S4U)", "suspicious", "high", checks["delegation_abuse"][0])
    elif s4u_total > 0:
        checks["delegation_abuse"].append(f"S4U2SELF={s4u2self}, S4U2PROXY={s4u2proxy}")
        _status_row("Delegation abuse (S4U)", "watch", "warning", checks["delegation_abuse"][0])
    else:
        _status_row(
            "Delegation abuse (S4U)",
            "not observed",
            "info",
            "No S4U2Self/S4U2Proxy observed",
        )

    krbtgt_hits = int(spns.get("krbtgt", 0))
    tgs_rep = int(request_types.get("TGS-REP", 0))
    as_req = int(request_types.get("AS-REQ", 0))
    ptt_like_clients: list[str] = []
    for client_ip, reqs in request_types_by_client.items():
        client_tgs = int(reqs.get("TGS-REQ", 0))
        client_as = int(reqs.get("AS-REQ", 0))
        if client_tgs >= 20 and client_as <= 2:
            ptt_like_clients.append(f"{client_ip}(tgs={client_tgs},as={client_as})")
    if krbtgt_hits > 0 and tgs_rep >= 20 and as_req <= max(2, tgs_rep // 20):
        checks["ticket_forgery_ptt"].append(f"krbtgt={krbtgt_hits}, TGS-REP={tgs_rep}, AS-REQ={as_req}")
    if ptt_like_clients:
        checks["ticket_forgery_ptt"].append(f"TGS-heavy clients: {', '.join(ptt_like_clients[:5])}")
    if checks["ticket_forgery_ptt"]:
        severity = "high" if krbtgt_hits > 0 else "warning"
        _status_row(
            "Ticket forgery / pass-the-ticket",
            "suspicious" if severity == "high" else "watch",
            severity,
            "; ".join(checks["ticket_forgery_ptt"]),
        )
    else:
        _status_row(
            "Ticket forgery / pass-the-ticket",
            "not observed",
            "info",
            f"krbtgt={krbtgt_hits}, TGS-REP={tgs_rep}, AS-REQ={as_req}",
        )

    unknown_user_errors = int(error_codes.get("KDC_ERR_C_PRINCIPAL_UNKNOWN", 0))
    unknown_service_errors = int(error_codes.get("KDC_ERR_S_PRINCIPAL_UNKNOWN", 0))
    enum_total = unknown_user_errors + unknown_service_errors
    enum_clients = [
        f"{client_ip}({int(codes.get('KDC_ERR_C_PRINCIPAL_UNKNOWN', 0) + codes.get('KDC_ERR_S_PRINCIPAL_UNKNOWN', 0))})"
        for client_ip, codes in error_by_client.items()
        if int(codes.get("KDC_ERR_C_PRINCIPAL_UNKNOWN", 0) + codes.get("KDC_ERR_S_PRINCIPAL_UNKNOWN", 0)) >= 10
    ]
    if enum_total >= 20:
        checks["user_enumeration"].append(
            f"Unknown principal errors user={unknown_user_errors}, service={unknown_service_errors}"
        )
        if enum_clients:
            checks["user_enumeration"].append(f"Top clients: {', '.join(enum_clients[:5])}")
        _status_row(
            "User/service enumeration via KDC errors",
            "suspicious",
            "warning",
            "; ".join(checks["user_enumeration"]),
        )
    else:
        _status_row(
            "User/service enumeration via KDC errors",
            "not observed",
            "info",
            f"KDC_ERR_C_PRINCIPAL_UNKNOWN={unknown_user_errors}, KDC_ERR_S_PRINCIPAL_UNKNOWN={unknown_service_errors}",
        )

    if public_endpoints:
        checks["public_kdc_exposure"].append(
            f"Public Kerberos endpoints: {', '.join(ip for ip, _ in public_endpoints.most_common(5))}"
        )
        _status_row(
            "Kerberos over public network exposure",
            "suspicious",
            "high",
            checks["public_kdc_exposure"][0],
        )
    else:
        _status_row(
            "Kerberos over public network exposure",
            "not observed",
            "info",
            "No public Kerberos endpoints observed",
        )

    realm_spray_clients: list[str] = []
    for client_ip, realms_seen in realms_by_client.items():
        as_req_client = int(request_types_by_client.get(client_ip, Counter()).get("AS-REQ", 0))
        if as_req_client >= 20 and len(realms_seen) >= 4:
            realm_spray_clients.append(f"{client_ip}(as-req={as_req_client},realms={len(realms_seen)})")
    if realm_spray_clients:
        checks["cross_realm_or_realm_spray"].append(f"Clients spanning many realms: {', '.join(realm_spray_clients[:5])}")
        _status_row(
            "Cross-realm spray/anomalous realm targeting",
            "watch",
            "warning",
            checks["cross_realm_or_realm_spray"][0],
        )
    else:
        _status_row(
            "Cross-realm spray/anomalous realm targeting",
            "not observed",
            "info",
            "No high-volume multi-realm spray pattern observed",
        )

    return checks, matrix


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


def _is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
        return addr.is_global
    except Exception:
        return False


def analyze_kerberos(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> KerberosAnalysis:
    errors: List[str] = []
    detections: List[Dict[str, object]] = []
    anomalies: List[str] = []

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, packets=packets, meta=meta, show_status=show_status
    )

    total_packets = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    servers = Counter()
    clients = Counter()
    service_counts = Counter()
    request_types = Counter()
    error_codes = Counter()
    realms = Counter()
    principals = Counter()
    spns = Counter()
    artifacts: set[str] = set()
    public_endpoints = Counter()
    convos: Dict[Tuple[str, str, int, str], int] = defaultdict(int)
    tcp_packets = 0
    udp_packets = 0
    bind_buckets: Dict[Tuple[str, int], int] = defaultdict(int)
    suspicious_attributes = Counter()
    principal_evidence: List[Dict[str, object]] = []
    principal_seen: set[tuple[str, str, int, str, str]] = set()
    request_types_by_client: dict[str, Counter[str]] = defaultdict(Counter)
    spns_by_client: dict[str, set[str]] = defaultdict(set)
    realms_by_client: dict[str, set[str]] = defaultdict(set)
    error_by_client: dict[str, Counter[str]] = defaultdict(Counter)

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

            payload = b""
            sport = 0
            dport = 0
            proto = None
            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp_layer = pkt[TCP]  # type: ignore[index]
                sport = int(getattr(tcp_layer, "sport", 0) or 0)
                dport = int(getattr(tcp_layer, "dport", 0) or 0)
                if dport in KERBEROS_PORTS or sport in KERBEROS_PORTS:
                    proto = "TCP"
                    tcp_packets += 1
                    payload = bytes(getattr(tcp_layer, "payload", b""))
            elif UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp_layer = pkt[UDP]  # type: ignore[index]
                sport = int(getattr(udp_layer, "sport", 0) or 0)
                dport = int(getattr(udp_layer, "dport", 0) or 0)
                if dport in KERBEROS_PORTS or sport in KERBEROS_PORTS:
                    proto = "UDP"
                    udp_packets += 1
                    payload = bytes(getattr(udp_layer, "payload", b""))

            if proto is None:
                continue

            servers[dst_ip] += 1
            clients[src_ip] += 1
            service_counts[f"{proto}/{dport or sport}"] += 1
            convos[(src_ip, dst_ip, dport or sport, proto)] += 1

            if _is_public_ip(src_ip):
                public_endpoints[src_ip] += 1
            if _is_public_ip(dst_ip):
                public_endpoints[dst_ip] += 1

            if not payload:
                continue

            extracted = _extract_ascii_strings(payload) + _extract_utf16le_strings(payload)
            candidate_strings: set[str] = set()
            for text in extracted:
                normalized = _clean_identity_token(text)
                if normalized:
                    candidate_strings.add(normalized)
            packet_req_tokens: set[str] = set()
            packet_err_tokens: set[str] = set()
            packet_krbtgt = False
            saw_asrep_preauth = False
            saw_pa_enc_timestamp = False

            for value in candidate_strings:
                if _is_useful_kerberos_artifact(value):
                    artifacts.add(value)

                for match in UPN_RE.finditer(value):
                    user = _normalize_principal_local(match.group(1))
                    realm = _normalize_realm(match.group(2))
                    if not _is_plausible_principal_local(user) or not _is_plausible_realm(realm):
                        continue
                    principal = f"{user}@{realm}"
                    principals[principal] += 1
                    realms[realm] += 1
                    realms_by_client[src_ip].add(realm)
                    key = (src_ip, dst_ip, dport or sport, proto, principal)
                    if key not in principal_seen:
                        principal_seen.add(key)
                        principal_evidence.append({
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "dst_port": dport or sport,
                            "protocol": proto,
                            "principal": principal,
                            "kind": "UPN",
                        })

                cname = _split_cname_concat(value)
                if cname:
                    user, realm = cname
                    user = _normalize_principal_local(user)
                    realm = _normalize_realm(realm)
                    if _is_plausible_principal_local(user) and _is_plausible_realm(realm):
                        principal = f"{user}@{realm}"
                        principals[principal] += 1
                        realms[realm] += 1
                        realms_by_client[src_ip].add(realm)
                        key = (src_ip, dst_ip, dport or sport, proto, principal)
                        if key not in principal_seen:
                            principal_seen.add(key)
                            principal_evidence.append({
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "dst_port": dport or sport,
                                "protocol": proto,
                                "principal": principal,
                                "kind": "CNameString",
                            })

                for match in SPN_RE.finditer(value):
                    spn = _normalize_spn(match.group(1))
                    if not _is_plausible_spn(spn):
                        continue
                    spns[spn] += 1
                    spns_by_client[src_ip].add(spn)
                    realm = match.group(2)
                    if realm:
                        normalized_realm = _normalize_realm(realm)
                        if _is_plausible_realm(normalized_realm):
                            realms[normalized_realm] += 1
                            realms_by_client[src_ip].add(normalized_realm)

                lower = value.lower()
                if "krbtgt" in lower:
                    packet_krbtgt = True
                for req in REQ_RE.findall(value):
                    packet_req_tokens.add(req.upper())
                for err in ERR_RE.findall(value):
                    packet_err_tokens.add(err)
                if "as-rep" in lower and "preauth" in lower:
                    saw_asrep_preauth = True
                if "pa-enc-timestamp" in lower:
                    saw_pa_enc_timestamp = True

            if packet_krbtgt:
                spns["krbtgt"] += 1
                spns_by_client[src_ip].add("krbtgt")

            for req_name in packet_req_tokens:
                request_types[req_name] += 1
                request_types_by_client[src_ip][req_name] += 1
                if ts is not None and req_name in {"AS-REQ", "TGS-REQ"}:
                    bind_buckets[(src_ip, int(ts // 60))] += 1

            for err in packet_err_tokens:
                error_codes[err] += 1
                error_by_client[src_ip][err] += 1

            if saw_asrep_preauth:
                suspicious_attributes["AS-REP (preauth)"] += 1
            if saw_pa_enc_timestamp:
                suspicious_attributes["PA-ENC-TIMESTAMP"] += 1

    finally:
        status.finish()
        reader.close()

    duration = 0.0
    if first_seen is not None and last_seen is not None:
        duration = max(0.0, last_seen - first_seen)

    conversations = [
        KerberosConversation(src, dst, port, proto, count)
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

    if public_endpoints:
        anomalies.append("Kerberos traffic to public IPs detected.")
        detections.append({
            "severity": "warning",
            "summary": "Kerberos traffic to public IPs",
            "details": ", ".join([ip for ip, _ in public_endpoints.most_common(10)]),
            "source": "Kerberos",
        })

    tgs_req = request_types.get("TGS-REQ", 0)
    if tgs_req and len(spns) >= 10:
        detections.append({
            "severity": "warning",
            "summary": "Possible Kerberoasting indicators",
            "details": f"TGS-REQ observed ({tgs_req}) with {len(spns)} unique SPNs.",
            "source": "Kerberos",
        })

    as_rep = request_types.get("AS-REP", 0)
    if as_rep and "KDC_ERR_PREAUTH_REQUIRED" not in error_codes:
        detections.append({
            "severity": "warning",
            "summary": "Possible AS-REP roasting indicators",
            "details": f"AS-REP observed ({as_rep}) without preauth requirement errors.",
            "source": "Kerberos",
        })

    if spns.get("krbtgt"):
        detections.append({
            "severity": "info",
            "summary": "krbtgt service activity observed",
            "details": "TGT-related service principal observed (heuristic for ticket activity).",
            "source": "Kerberos",
        })

    if spns.get("krbtgt") and request_types.get("TGS-REP", 0) > 0 and tgs_req > 0:
        detections.append({
            "severity": "warning",
            "summary": "Potential golden/silver ticket indicators (heuristic)",
            "details": "krbtgt SPN activity observed alongside TGS traffic.",
            "source": "Kerberos",
        })

    if request_types.get("S4U2SELF", 0) or request_types.get("S4U2PROXY", 0):
        detections.append({
            "severity": "warning",
            "summary": "Kerberos delegation activity observed",
            "details": "S4U2Self/S4U2Proxy usage can indicate delegation abuse.",
            "source": "Kerberos",
        })

    if error_codes.get("KDC_ERR_PREAUTH_FAILED"):
        detections.append({
            "severity": "warning",
            "summary": "Kerberos pre-authentication failures",
            "details": f"KDC_ERR_PREAUTH_FAILED seen {error_codes['KDC_ERR_PREAUTH_FAILED']} times.",
            "source": "Kerberos",
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
                "summary": "Potential Kerberos brute-force (high AS/TGS request rate)",
                "details": f"Peak AS/TGS requests per minute: {top_burst}",
                "source": "Kerberos",
            })

    deterministic_checks, attack_matrix = _build_kerberos_attack_overview(
        request_types=request_types,
        error_codes=error_codes,
        spns=spns,
        public_endpoints=public_endpoints,
        bind_bursts=bind_bursts,
        request_types_by_client=request_types_by_client,
        spns_by_client=spns_by_client,
        realms_by_client=realms_by_client,
        error_by_client=error_by_client,
    )

    attack_detection_map = {
        "Kerberoasting (TGS ticket harvesting)": "Potential Kerberoasting activity",
        "AS-REP roasting": "Potential AS-REP roasting activity",
        "Password spray / brute-force": "Potential Kerberos password spray/brute-force",
        "Delegation abuse (S4U)": "Potential Kerberos delegation abuse",
        "Ticket forgery / pass-the-ticket": "Potential Kerberos ticket abuse",
        "User/service enumeration via KDC errors": "Potential Kerberos principal enumeration",
        "Kerberos over public network exposure": "Kerberos exposure to public endpoints",
        "Cross-realm spray/anomalous realm targeting": "Potential cross-realm Kerberos spray",
    }
    for item in attack_matrix:
        status = str(item.get("status", ""))
        if status not in {"suspicious", "watch"}:
            continue
        summary_text = attack_detection_map.get(str(item.get("attack", "")), str(item.get("attack", "Kerberos attack indicator")))
        details = str(item.get("evidence", ""))
        severity = str(item.get("severity", "warning"))
        if status == "watch" and severity == "high":
            severity = "warning"
        detections.append({
            "severity": severity,
            "summary": summary_text,
            "details": details,
            "source": "Kerberos",
        })

    return KerberosAnalysis(
        path=path,
        duration=duration,
        first_seen=first_seen,
        last_seen=last_seen,
        total_packets=total_packets,
        servers=servers,
        clients=clients,
        service_counts=service_counts,
        request_types=request_types,
        error_codes=error_codes,
        realms=realms,
        principals=principals,
        spns=spns,
        conversations=conversations,
        session_stats=session_stats,
        tcp_packets=tcp_packets,
        udp_packets=udp_packets,
        public_endpoints=public_endpoints,
        suspicious_attributes=suspicious_attributes,
        bind_bursts=bind_bursts,
        principal_evidence=principal_evidence,
        artifacts=sorted(artifacts, key=_artifact_sort_key),
        anomalies=anomalies,
        detections=detections,
        errors=errors,
        deterministic_checks=deterministic_checks,
        attack_matrix=attack_matrix,
    )
