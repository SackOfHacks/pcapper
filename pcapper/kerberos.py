from __future__ import annotations

from .utils import is_public_ip as _is_public_ip, extract_ascii_strings as _extract_ascii_strings
from .utils import extract_utf16le_strings as _extract_utf16le_strings
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .pcap_cache import PcapMeta, get_reader
from .utils import extract_packet_endpoints, memoize_analysis, safe_float

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
SPN_RE = re.compile(
    r"\b([A-Za-z0-9._-]{3,}/[A-Za-z0-9._:-]{3,})(?:@([A-Za-z0-9.-]{3,}))?\b"
)
ERR_RE = re.compile(r"\bKDC_ERR_[A-Z0-9_]+\b")
REQ_RE = re.compile(
    r"\b(AS-REQ|AS-REP|TGS-REQ|TGS-REP|KRB_ERROR|S4U2SELF|S4U2PROXY|PA-ENC-TIMESTAMP)\b",
    re.IGNORECASE,
)

# Kerberos message types and error codes are ASN.1 *integers*, not ASCII text,
# so the string regexes above never match real binary Kerberos. The msg-type is
# the outer [APPLICATION n] tag (RFC 4120 §5.4) and KRB-ERROR carries the error
# as an INTEGER. These helpers recover both from the raw payload so the attack
# heuristics (kerberoasting, AS-REP roasting, password spray, pass-the-ticket)
# actually have data to work with.
_KRB_APP_TAGS = {
    0x6A: "AS-REQ",     # [APPLICATION 10]
    0x6B: "AS-REP",     # [APPLICATION 11]
    0x6C: "TGS-REQ",    # [APPLICATION 12]
    0x6D: "TGS-REP",    # [APPLICATION 13]
    0x6E: "AP-REQ",     # [APPLICATION 14]
    0x6F: "AP-REP",     # [APPLICATION 15]
    0x7E: "KRB-ERROR",  # [APPLICATION 30]
}
_KRB_ERROR_CODE_NAMES = {
    6: "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    7: "KDC_ERR_S_PRINCIPAL_UNKNOWN",
    18: "KDC_ERR_CLIENT_REVOKED",
    23: "KDC_ERR_KEY_EXPIRED",
    24: "KDC_ERR_PREAUTH_FAILED",
    25: "KDC_ERR_PREAUTH_REQUIRED",
}


def _krb_der_len_ok(payload: bytes, off: int) -> bool:
    if off + 1 >= len(payload):
        return False
    length_byte = payload[off + 1]
    return length_byte < 0x80 or length_byte in (0x81, 0x82, 0x83, 0x84)


def _krb_msgtype_from_payload(payload: bytes) -> Optional[str]:
    """Kerberos message name from the outer APPLICATION tag, or None.

    On UDP/88 the tag is at offset 0; on TCP/88 a 4-byte length prefix precedes
    it. A plausible DER length byte must follow the tag to avoid false matches.
    """
    if len(payload) < 2:
        return None
    for off in (0, 4):
        if (
            len(payload) > off + 1
            and payload[off] in _KRB_APP_TAGS
            and _krb_der_len_ok(payload, off)
        ):
            return _KRB_APP_TAGS[payload[off]]
    return None


def _krb_error_code_from_payload(payload: bytes) -> Optional[str]:
    """Error name from a KRB-ERROR's error-code field ([6] INTEGER -> A6 03 02 01 cc)."""
    idx = payload.find(b"\xa6\x03\x02\x01")
    if idx >= 0 and idx + 4 < len(payload):
        return _KRB_ERROR_CODE_NAMES.get(payload[idx + 4])
    return None


# RFC 3961/4120 + Microsoft etype numbers. AES (17/18) is the modern default;
# RC4-HMAC (23/24) and the single-DES types (1/2/3) are crackable offline and a
# client that requests *only* those is downgrading — the kerberoast / AS-REP
# roast signature (Rubeus, Impacket, etc. force RC4 to harvest crackable tickets).
_KRB_ETYPE_NAMES = {
    1: "des-cbc-crc",
    2: "des-cbc-md4",
    3: "des-cbc-md5",
    16: "des3-cbc-sha1",
    17: "aes128-cts-hmac-sha1",
    18: "aes256-cts-hmac-sha1",
    19: "aes128-cts-hmac-sha256",
    20: "aes256-cts-hmac-sha384",
    23: "rc4-hmac",
    24: "rc4-hmac-exp",
    25: "camellia128-cts-cmac",
    26: "camellia256-cts-cmac",
}
_KRB_WEAK_ETYPES = {1, 2, 3, 23, 24}  # single-DES + RC4: crackable offline
_KRB_STRONG_ETYPES = {16, 17, 18, 19, 20, 25, 26}  # AES / 3DES / Camellia


def _krb_reqbody_etypes(payload: bytes) -> list[int]:
    """Encryption types a KDC-REQ offers, from the req-body [8] etype list.

    DER for the field is ``A8 ll 30 ll (02 ll ee...)+`` ([8] SEQUENCE OF Int32).
    Each element is a DER INTEGER of variable length — Windows lists the AES/RC4
    etypes as one-byte values but also Microsoft-proprietary negative etypes as
    two-byte values (e.g. ``02 02 FF 7B`` = -133), so a fixed 1-byte assumption
    drops the whole list. The whole SEQUENCE is parsed as INTEGER TLVs that must
    exactly fill it, which keeps the ``A8`` anchor unambiguous against unrelated
    context tags. Returns the (signed) etypes in request/preference order, or
    ``[]`` if no valid etype SEQUENCE is found.
    """
    n = len(payload)
    for idx in range(n - 5):
        if (
            payload[idx] == 0xA8
            and payload[idx + 2] == 0x30
            and payload[idx + 4] == 0x02
        ):
            seq_len = payload[idx + 3]
            seq_start = idx + 4
            seq_end = seq_start + seq_len
            if seq_len == 0 or seq_end > n:
                continue
            etypes: list[int] = []
            ok = True
            pos = seq_start
            while pos < seq_end:
                if payload[pos] != 0x02:  # every element must be an INTEGER
                    ok = False
                    break
                int_len = payload[pos + 1]
                val_start = pos + 2
                val_end = val_start + int_len
                if int_len == 0 or int_len > 4 or val_end > seq_end:
                    ok = False
                    break
                etypes.append(
                    int.from_bytes(payload[val_start:val_end], "big", signed=True)
                )
                pos = val_end
            if ok and pos == seq_end and etypes:
                return etypes
    return []

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
    if (
        "." not in host_only
        and "-" not in host_only
        and service_upper not in _KNOWN_SPN_SERVICES
    ):
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
            if (
                best is None
                or score > best[0]
                or (score == best[0] and len(realm) > len(best[1]))
            ):
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
    etype_counts: Counter[int] = field(default_factory=Counter)


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
        "kdc_error_saturation": [],
    }
    matrix: List[Dict[str, str]] = []

    def _status_row(attack: str, status: str, severity: str, evidence: str) -> None:
        matrix.append(
            {
                "attack": attack,
                "status": status,
                "severity": severity,
                "evidence": evidence,
            }
        )

    tgs_req = int(request_types.get("TGS-REQ", 0))
    unique_spn = len(spns)
    kerberoast_clients: list[str] = []
    for client_ip, reqs in request_types_by_client.items():
        client_tgs = int(reqs.get("TGS-REQ", 0))
        client_spns = len(spns_by_client.get(client_ip, set()))
        if client_tgs >= 20 and client_spns >= 8:
            kerberoast_clients.append(
                f"{client_ip}(tgs={client_tgs},spn={client_spns})"
            )
    if (tgs_req >= 50 and unique_spn >= 15) or kerberoast_clients:
        checks["kerberoasting"].append(f"TGS-REQ={tgs_req}, unique SPNs={unique_spn}")
        if kerberoast_clients:
            checks["kerberoasting"].append(
                f"Top clients: {', '.join(kerberoast_clients[:5])}"
            )
        _status_row(
            "Kerberoasting (TGS ticket harvesting)",
            "suspicious",
            "high",
            "; ".join(checks["kerberoasting"])
            or f"TGS-REQ={tgs_req}, unique SPNs={unique_spn}",
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
        checks["asrep_roasting"].append(
            f"AS-REP={as_rep} with no KDC_ERR_PREAUTH_REQUIRED"
        )
        _status_row(
            "AS-REP roasting", "suspicious", "high", checks["asrep_roasting"][0]
        )
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
            checks["password_spray_bruteforce"].append(
                f"Top clients: {', '.join(spray_clients[:5])}"
            )
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
        _status_row(
            "Delegation abuse (S4U)",
            "suspicious",
            "high",
            checks["delegation_abuse"][0],
        )
    elif s4u_total > 0:
        checks["delegation_abuse"].append(f"S4U2SELF={s4u2self}, S4U2PROXY={s4u2proxy}")
        _status_row(
            "Delegation abuse (S4U)", "watch", "warning", checks["delegation_abuse"][0]
        )
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
        checks["ticket_forgery_ptt"].append(
            f"krbtgt={krbtgt_hits}, TGS-REP={tgs_rep}, AS-REQ={as_req}"
        )
    if ptt_like_clients:
        checks["ticket_forgery_ptt"].append(
            f"TGS-heavy clients: {', '.join(ptt_like_clients[:5])}"
        )
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
        if int(
            codes.get("KDC_ERR_C_PRINCIPAL_UNKNOWN", 0)
            + codes.get("KDC_ERR_S_PRINCIPAL_UNKNOWN", 0)
        )
        >= 10
    ]
    if enum_total >= 20:
        checks["user_enumeration"].append(
            f"Unknown principal errors user={unknown_user_errors}, service={unknown_service_errors}"
        )
        if enum_clients:
            checks["user_enumeration"].append(
                f"Top clients: {', '.join(enum_clients[:5])}"
            )
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
        as_req_client = int(
            request_types_by_client.get(client_ip, Counter()).get("AS-REQ", 0)
        )
        if as_req_client >= 20 and len(realms_seen) >= 4:
            realm_spray_clients.append(
                f"{client_ip}(as-req={as_req_client},realms={len(realms_seen)})"
            )
    if realm_spray_clients:
        checks["cross_realm_or_realm_spray"].append(
            f"Clients spanning many realms: {', '.join(realm_spray_clients[:5])}"
        )
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

    kdc_error_total = sum(int(v) for v in error_codes.values())
    auth_req_total = int(request_types.get("AS-REQ", 0)) + int(
        request_types.get("TGS-REQ", 0)
    )
    ratio = (
        (float(kdc_error_total) / float(auth_req_total)) if auth_req_total > 0 else 0.0
    )
    if kdc_error_total >= 40 and ratio >= 0.35:
        checks["kdc_error_saturation"].append(
            f"KDC error saturation errors={kdc_error_total} auth_requests={auth_req_total} ratio={ratio:.2f}"
        )
        _status_row(
            "KDC error saturation",
            "suspicious",
            "warning",
            checks["kdc_error_saturation"][0],
        )
    elif kdc_error_total >= 20 and ratio >= 0.20:
        checks["kdc_error_saturation"].append(
            f"Elevated KDC error ratio errors={kdc_error_total} auth_requests={auth_req_total} ratio={ratio:.2f}"
        )
        _status_row(
            "KDC error saturation",
            "watch",
            "warning",
            checks["kdc_error_saturation"][0],
        )
    else:
        _status_row(
            "KDC error saturation",
            "not observed",
            "info",
            f"errors={kdc_error_total}, auth_requests={auth_req_total}, ratio={ratio:.2f}",
        )

    return checks, matrix


@memoize_analysis
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
    etype_counts: Counter[int] = Counter()  # encryption types offered across all KDC-REQs
    weak_only_etype_clients: Dict[str, list[int]] = {}  # client -> RC4/DES-only request list

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

            src_ip, dst_ip = extract_packet_endpoints(pkt)

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

            extracted = _extract_ascii_strings(payload) + _extract_utf16le_strings(
                payload
            )
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

            # Recover msg-type / error-code from the binary ASN.1 (the ASCII
            # regexes never match real Kerberos). This is what feeds the attack
            # heuristics below.
            binary_msgtype = _krb_msgtype_from_payload(payload)
            if binary_msgtype:
                packet_req_tokens.add(
                    "KRB_ERROR" if binary_msgtype == "KRB-ERROR" else binary_msgtype
                )
                if binary_msgtype == "KRB-ERROR":
                    err_name = _krb_error_code_from_payload(payload)
                    if err_name:
                        packet_err_tokens.add(err_name)
                elif binary_msgtype in ("AS-REQ", "TGS-REQ"):
                    req_etypes = _krb_reqbody_etypes(payload)
                    if req_etypes:
                        # Only count recognized cryptographic etypes; Windows
                        # also lists Microsoft-proprietary negative markers that
                        # are not session-crypto choices.
                        crypto_etypes = [
                            e for e in req_etypes if e in _KRB_ETYPE_NAMES
                        ]
                        etype_counts.update(crypto_etypes)
                        # A request offering ONLY single-DES/RC4 (no AES) is an
                        # encryption downgrade — the kerberoast / AS-REP-roast
                        # signature. Normal Windows clients list AES first and
                        # only fall back to RC4, so a mixed list is benign.
                        if crypto_etypes and all(
                            e in _KRB_WEAK_ETYPES for e in crypto_etypes
                        ):
                            weak_only_etype_clients.setdefault(
                                src_ip, crypto_etypes
                            )

            for value in candidate_strings:
                if _is_useful_kerberos_artifact(value):
                    artifacts.add(value)

                for match in UPN_RE.finditer(value):
                    user = _normalize_principal_local(match.group(1))
                    realm = _normalize_realm(match.group(2))
                    if not _is_plausible_principal_local(
                        user
                    ) or not _is_plausible_realm(realm):
                        continue
                    principal = f"{user}@{realm}"
                    principals[principal] += 1
                    realms[realm] += 1
                    realms_by_client[src_ip].add(realm)
                    key = (src_ip, dst_ip, dport or sport, proto, principal)
                    if key not in principal_seen:
                        principal_seen.add(key)
                        principal_evidence.append(
                            {
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "dst_port": dport or sport,
                                "protocol": proto,
                                "principal": principal,
                                "kind": "UPN",
                            }
                        )

                cname = _split_cname_concat(value)
                if cname:
                    user, realm = cname
                    user = _normalize_principal_local(user)
                    realm = _normalize_realm(realm)
                    if _is_plausible_principal_local(user) and _is_plausible_realm(
                        realm
                    ):
                        principal = f"{user}@{realm}"
                        principals[principal] += 1
                        realms[realm] += 1
                        realms_by_client[src_ip].add(realm)
                        key = (src_ip, dst_ip, dport or sport, proto, principal)
                        if key not in principal_seen:
                            principal_seen.add(key)
                            principal_evidence.append(
                                {
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "dst_port": dport or sport,
                                    "protocol": proto,
                                    "principal": principal,
                                    "kind": "CNameString",
                                }
                            )

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
        detections.append(
            {
                "severity": "warning",
                "summary": "Kerberos traffic to public IPs",
                "details": ", ".join(
                    [ip for ip, _ in public_endpoints.most_common(10)]
                ),
                "source": "Kerberos",
            }
        )

    tgs_req = request_types.get("TGS-REQ", 0)
    if tgs_req and len(spns) >= 10:
        detections.append(
            {
                "severity": "warning",
                "summary": "Possible Kerberoasting indicators",
                "details": f"TGS-REQ observed ({tgs_req}) with {len(spns)} unique SPNs.",
                "source": "Kerberos",
            }
        )

    if weak_only_etype_clients:
        sample_client = next(iter(weak_only_etype_clients))
        sample_etypes = weak_only_etype_clients[sample_client]
        etype_label = ", ".join(
            _KRB_ETYPE_NAMES.get(e, str(e)) for e in sample_etypes
        )
        detections.append(
            {
                "severity": "high",
                "summary": "Kerberos encryption downgrade (weak-only etype request)",
                "details": (
                    f"{len(weak_only_etype_clients)} client(s) requested only "
                    f"crackable encryption (no AES) — e.g. {sample_client} offered "
                    f"[{etype_label}]. RC4/DES-only requests are the kerberoast / "
                    f"AS-REP-roast downgrade signature (Rubeus, Impacket)."
                ),
                "source": "Kerberos",
            }
        )

    as_rep = request_types.get("AS-REP", 0)
    if as_rep and "KDC_ERR_PREAUTH_REQUIRED" not in error_codes:
        detections.append(
            {
                "severity": "warning",
                "summary": "Possible AS-REP roasting indicators",
                "details": f"AS-REP observed ({as_rep}) without preauth requirement errors.",
                "source": "Kerberos",
            }
        )

    if spns.get("krbtgt"):
        detections.append(
            {
                "severity": "info",
                "summary": "krbtgt service activity observed",
                "details": "TGT-related service principal observed (heuristic for ticket activity).",
                "source": "Kerberos",
            }
        )

    # Golden/silver tickets are forged tickets *used* without a preceding AS
    # exchange, so the signal is TGS activity disproportionate to AS-REQ — not
    # the mere presence of krbtgt+TGS traffic, which is every normal session.
    tgs_rep_total = int(request_types.get("TGS-REP", 0))
    as_req_total = int(request_types.get("AS-REQ", 0))
    if (
        spns.get("krbtgt")
        and tgs_rep_total >= 20
        and as_req_total <= max(2, tgs_rep_total // 10)
    ):
        detections.append(
            {
                "severity": "warning",
                "summary": "Potential golden/silver ticket indicators (heuristic)",
                "details": (
                    f"TGS traffic (TGS-REP={tgs_rep_total}) with disproportionately "
                    f"few AS-REQ ({as_req_total}); tickets used without AS exchange."
                ),
                "source": "Kerberos",
            }
        )

    if request_types.get("S4U2SELF", 0) or request_types.get("S4U2PROXY", 0):
        detections.append(
            {
                "severity": "warning",
                "summary": "Kerberos delegation activity observed",
                "details": "S4U2Self/S4U2Proxy usage can indicate delegation abuse.",
                "source": "Kerberos",
            }
        )

    if error_codes.get("KDC_ERR_PREAUTH_FAILED"):
        detections.append(
            {
                "severity": "warning",
                "summary": "Kerberos pre-authentication failures",
                "details": f"KDC_ERR_PREAUTH_FAILED seen {error_codes['KDC_ERR_PREAUTH_FAILED']} times.",
                "source": "Kerberos",
            }
        )

    bind_bursts = Counter()
    for (client_ip, _minute), count in bind_buckets.items():
        if count > bind_bursts.get(client_ip, 0):
            bind_bursts[client_ip] = count
    if bind_bursts:
        top_burst = max(bind_bursts.values())
        if top_burst >= 20:
            detections.append(
                {
                    "severity": "warning",
                    "summary": "Potential Kerberos brute-force (high AS/TGS request rate)",
                    "details": f"Peak AS/TGS requests per minute: {top_burst}",
                    "source": "Kerberos",
                }
            )

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
        summary_text = attack_detection_map.get(
            str(item.get("attack", "")),
            str(item.get("attack", "Kerberos attack indicator")),
        )
        details = str(item.get("evidence", ""))
        severity = str(item.get("severity", "warning"))
        if status == "watch" and severity == "high":
            severity = "warning"
        detections.append(
            {
                "severity": severity,
                "summary": summary_text,
                "details": details,
                "source": "Kerberos",
            }
        )

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
        etype_counts=etype_counts,
    )
