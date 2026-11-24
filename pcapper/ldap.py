from __future__ import annotations

from .utils import is_public_ip as _is_public_ip, extract_ascii_strings as _extract_ascii_strings
from .utils import extract_utf16le_strings
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .dns import analyze_dns
from .ldap_ber import iter_ldap_messages
from .files import analyze_files
from .lite import UNSUPPORTED, LitePacket
from .pcap_cache import PcapMeta, iter_packets
from .progress import run_with_busy_status
from .utils import counter_inc, decode_payload, extract_packet_endpoints, memoize_analysis, safe_float, set_add_cap

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
# A source port equal to an LDAP port identifies the directory server only
# when the other end is an ephemeral port; otherwise a flow whose ephemeral
# source happens to be 389 is reported as a directory server.
_EPHEMERAL_MIN = 1024


def _ldap_roles(
    src_ip: str, dst_ip: str, sport: int, dport: int
) -> tuple[str, str, int] | None:
    """(client_ip, server_ip, server_port), or None when not LDAP.

    Roles come from the LDAP port, not from packet direction: the server's
    reply is still the server's traffic. Counting ``dst_ip`` as the server on
    every packet made each directory server also its own busiest "client".
    """
    if dport in LDAP_PORTS:
        return src_ip, dst_ip, dport
    if sport in LDAP_PORTS and dport >= _EPHEMERAL_MIN:
        return dst_ip, src_ip, sport
    return None


# A TCP payload opening like one of these is read as an HTTP request, on any port.
_HTTP_REQUEST_STARTS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ")


def _lite_not_ldap(record: LitePacket, src_ip: str, dst_ip: str) -> bool:
    """True when the packet loop certainly does nothing with the record, read
    from its bytes: no TCP/UDP layer, or one off the LDAP ports -- UDP, or
    TCP whose payload (``bytes(tcp.payload)``: from the start of the payload
    scapy leaves as Raw on into any Ethernet padding) does not open an HTTP
    request. Anything else is decided by the scapy path."""
    l4 = record.lite_l4()
    if l4 is None:
        return True
    if l4 is UNSUPPORTED or _ldap_roles(src_ip, dst_ip, l4[1], l4[2]) is not None:
        return False
    if not l4[0]:
        return True
    if l4[5] < 0:
        return False  # scapy dissects the payload further: let it decide
    return not record.original.startswith(_HTTP_REQUEST_STARTS, l4[7])


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

# LDAP result codes live in the BER bytes as an ENUMERATED integer, not as the
# ASCII text "invalidCredentials"/"resultCode" — so the string heuristics never
# match real binary LDAP and bind-failure/brute-force detection was dead. Each
# response protocolOp (bindResponse [APPLICATION 1]=0x61, searchResultDone=0x65,
# modifyResponse=0x67, addResponse=0x69, delResponse=0x6b, modDNResponse=0x6d,
# compareResponse=0x6f, extendedResponse=0x78) begins with resultCode as the
# first ENUMERATED field (0x0a 0x01 <code>).
_LDAP_RESP_RE = re.compile(
    rb"[\x61\x65\x67\x69\x6b\x6d\x6f\x78](?:[\x00-\x7f]|\x81.|\x82..)\x0a\x01(.)",
    re.DOTALL,
)


def _ldap_result_codes_from_payload(payload: bytes) -> list[int]:
    """Decode LDAP response result codes from raw BER bytes."""
    return [m.group(1)[0] for m in _LDAP_RESP_RE.finditer(payload)]


SECRET_PATTERNS = [
    re.compile(
        r"(?i)\b(password|passwd|pwd|unicodepwd|userpassword)\b\s*[:=]\s*([^\s'\";]{4,})"
    ),
    re.compile(r"(?i)\b(token|api[_-]?key|secret)\b\s*[:=]\s*([^\s'\";]{6,})"),
]


# Decoded request operations, under the names the checks below count.
REQUEST_KEYS = {
    "BindRequest": "Bind", "SearchRequest": "Search", "ModifyRequest": "Modify", "AddRequest": "Add",
    "DelRequest": "Delete", "CompareRequest": "Compare", "ExtendedRequest": "Extended",
    "UnbindRequest": "Unbind", "ModifyDNRequest": "ModifyDN", "AbandonRequest": "Abandon",
}
# Attributes whose request (or use in a filter) is credential access or the
# recon that precedes it.
SENSITIVE_ATTRS = {
    "unicodepwd": "unicodePwd", "userpassword": "userPassword", "ms-mcs-admpwd": "ms-Mcs-AdmPwd",
    "mslaps-password": "msLAPS-Password", "mslaps-encryptedpassword": "msLAPS-EncryptedPassword",
    "msds-managedpassword": "msDS-ManagedPassword", "supplementalcredentials": "supplementalCredentials",
    "msds-keycredentiallink": "msDS-KeyCredentialLink", "serviceprincipalname": "servicePrincipalName",
    "msds-allowedtodelegateto": "msDS-AllowedToDelegateTo",
    "msds-allowedtoactonbehalfofotheridentity": "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "sidhistory": "sIDHistory",
}
PASSWORD_ATTRS = {"unicodePwd", "userPassword", "ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword",
                  "msDS-ManagedPassword", "supplementalCredentials"}
MAX_LDAP_RECORDS = 1000  # search requests / writes kept for the report

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
    deterministic_checks: Dict[str, List[str]]
    threat_hypotheses: List[Dict[str, object]]
    benign_context: List[str]
    # Decoded from the BER messages (cleartext LDAP only).
    operations: Counter[str] = field(default_factory=Counter)
    search_requests: List[Dict[str, object]] = field(default_factory=list)
    writes: List[Dict[str, object]] = field(default_factory=list)
    entries_returned: int = 0
    spns: Counter[str] = field(default_factory=Counter)
    diagnostics: Counter[str] = field(default_factory=Counter)


def _parse_http_request(
    payload: bytes,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
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
                host = decode_payload(
                    line.split(b":", 1)[1].strip(), encoding="latin-1"
                )
            if line.lower().startswith(b"user-agent:"):
                ua = decode_payload(line.split(b":", 1)[1].strip(), encoding="latin-1")
        if host:
            url = f"{host}{path}"
        else:
            url = path
        return url, ua, method
    except Exception:
        return None, None, None


def _extract_utf16le_strings(
    data: bytes, min_len: int = 4, max_len: int = 200
) -> List[str]:
    return extract_utf16le_strings(data, min_len, max_len)


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


@memoize_analysis
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
        return run_with_busy_status(
            path, show_status, f"LDAP: {desc}", func, *args, **kwargs
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
    operations: Counter[str] = Counter()
    search_requests: List[Dict[str, object]] = []
    writes: List[Dict[str, object]] = []
    entries_returned = 0
    spns: Counter[str] = Counter()
    diagnostics: Counter[str] = Counter()
    convos: Dict[Tuple[str, str, int, str], int] = defaultdict(int)
    artifacts: set[str] = set()
    cleartext_ldap_seen = False
    udp_ldap_seen = False

    def _mark_window(ts: Optional[float]) -> None:
        # The report window spans LDAP traffic, not every packet in scope.
        nonlocal first_seen, last_seen
        if ts is None:
            return
        if first_seen is None or ts < first_seen:
            first_seen = ts
        if last_seen is None or ts > last_seen:
            last_seen = ts

    for pkt in iter_packets(path, packets=packets, meta=meta, show_status=show_status, lite=True):
        total_packets += 1
        ts = safe_float(getattr(pkt, "time", None))
        src_ip, dst_ip = extract_packet_endpoints(pkt)

        if not src_ip or not dst_ip:
            continue

        if type(pkt) is LitePacket:
            if _lite_not_ldap(pkt, src_ip, dst_ip):
                continue
            pkt = pkt.materialize()

        if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
            tcp_layer = pkt[TCP]  # type: ignore[index]
            sport = int(getattr(tcp_layer, "sport", 0) or 0)
            dport = int(getattr(tcp_layer, "dport", 0) or 0)
            ldap_roles = _ldap_roles(src_ip, dst_ip, sport, dport)
            if ldap_roles is not None:
                client_ip, server_ip, server_port = ldap_roles
                _mark_window(ts)
                counter_inc(servers, server_ip)
                counter_inc(clients, client_ip)
                counter_inc(request_counts, "LDAP Traffic")
                counter_inc(service_counts, f"TCP/{server_port}")
                counter_inc(convos, (client_ip, server_ip, server_port, "TCP"))
                if server_port in LDAP_CLEAR_PORTS:
                    cleartext_ldap_seen = True
                    cleartext_packets += 1
                if server_port in {636, 3269}:
                    ldaps_packets += 1
                if _is_public_ip(src_ip):
                    counter_inc(public_endpoints, src_ip)
                if _is_public_ip(dst_ip):
                    counter_inc(public_endpoints, dst_ip)

            payload = bytes(getattr(tcp_layer, "payload", b""))
            if payload and payload.startswith(_HTTP_REQUEST_STARTS):
                url, ua, method = _parse_http_request(payload)
                if url:
                    counter_inc(urls, url)
                if ua:
                    counter_inc(user_agents, ua)
                if method:
                    counter_inc(http_methods, method)
                counter_inc(http_clients, src_ip)

            if payload and ldap_roles is not None:
                decoded = False
                for msg in iter_ldap_messages(payload):
                    decoded = True
                    counter_inc(operations, f"{msg.op} ({msg.name})" if msg.name else msg.op)
                    key = REQUEST_KEYS.get(msg.op)
                    if key:
                        counter_inc(request_counts, key)
                    where = {"ts": ts, "client": client_ip, "server": server_ip, "port": server_port}
                    if msg.op == "BindRequest":
                        # An empty name is anonymous only for a simple bind; a SASL
                        # bind (GSS-SPNEGO, Windows' default) carries the account
                        # inside its token, not in the bind name.
                        identity = msg.dn or ("(anonymous)" if msg.auth == "simple" else "(in SASL token)")
                        counter_inc(ldap_binds, f"{identity} [{msg.auth}]" if msg.auth else identity)
                        bind_key = (client_ip, server_ip, server_port, identity, msg.auth)
                        if bind_key not in bind_identity_seen:
                            bind_identity_seen.add(bind_key)
                            bind_identities.append({
                                "src_ip": client_ip, "dst_ip": server_ip, "dst_port": server_port,
                                "protocol": "TCP", "identity": identity, "auth": msg.auth, "ts": ts,
                            })
                        if msg.password:
                            counter_inc(secrets, f"simple bind {identity}: {msg.password}")
                        if ts is not None:
                            counter_inc(bind_buckets, (client_ip, int(ts // 60)))
                    elif msg.op == "SearchRequest":
                        query = msg.filter or "(objectClass=*)"
                        counter_inc(ldap_queries, query)
                        filter_type = _ldap_filter_type(query)
                        if filter_type:
                            counter_inc(ldap_filter_types, filter_type)
                        if len(search_requests) < MAX_LDAP_RECORDS:
                            search_requests.append({**where, "base": msg.dn, "scope": msg.scope,
                                                    "filter": query, "attributes": list(msg.attributes)})
                        named = {a.lower() for a in msg.attributes} | {
                            a for a in SENSITIVE_ATTRS if a in query.lower()}
                        for attr in sorted(named):
                            if attr in SENSITIVE_ATTRS:
                                counter_inc(suspicious_attributes, SENSITIVE_ATTRS[attr])
                    elif msg.op in ("ModifyRequest", "AddRequest", "DelRequest", "ModifyDNRequest"):
                        if len(writes) < MAX_LDAP_RECORDS:
                            writes.append({**where, "op": msg.op, "dn": msg.dn,
                                           "changes": list(msg.changes or msg.attributes)})
                        for attr, values in msg.values.items():
                            if SENSITIVE_ATTRS.get(attr.lower()) in PASSWORD_ATTRS:
                                for value in values:
                                    counter_inc(secrets, f"{msg.op} {msg.dn} {attr}: {value}")
                    elif msg.op == "SearchResultEntry":
                        entries_returned += 1
                        lowered = {k.lower(): v for k, v in msg.values.items()}
                        classes = {c.lower() for c in lowered.get("objectclass", [])}
                        for value in lowered.get("samaccountname", []):
                            if "computer" in classes or value.endswith("$"):
                                counter_inc(ldap_systems, value)
                            elif "group" not in classes:  # groups carry a sAMAccountName too
                                counter_inc(ldap_users, value)
                        for value in lowered.get("dnshostname", []):
                            counter_inc(ldap_systems, value)
                        for value in lowered.get("serviceprincipalname", []):
                            counter_inc(spns, value)
                        for attr in ("samaccountname", "userprincipalname", "mail"):
                            for value in lowered.get(attr, []):
                                ev_key = (client_ip, server_ip, server_port, "TCP", attr, value)
                                if ev_key not in user_evidence_seen and len(user_evidence) < MAX_LDAP_RECORDS:
                                    user_evidence_seen.add(ev_key)
                                    user_evidence.append({"src_ip": server_ip, "dst_ip": client_ip,
                                                          "dst_port": server_port, "protocol": "TCP",
                                                          "attr": attr, "value": value})
                        if msg.dn:
                            set_add_cap(artifacts, msg.dn)
                    if msg.result_code is not None:
                        name = LDAP_RESULT_CODES.get(msg.result_code, str(msg.result_code))
                        counter_inc(response_codes, f"{msg.result_code} ({name})")
                        # 0=success, 5/6=compareFalse/True, 14=saslBindInProgress
                        # are normal results, not errors.
                        if msg.result_code not in (0, 5, 6, 14):
                            counter_inc(ldap_error_codes, f"{msg.result_code} ({name})")
                            if msg.diagnostic:
                                counter_inc(diagnostics, msg.diagnostic.strip("\x00 ")[:200])

                if not decoded:
                    # SASL-sealed or mid-message segments: only the result-code
                    # byte scan and the string scans below apply.
                    for code in _ldap_result_codes_from_payload(payload):
                        name = LDAP_RESULT_CODES.get(code, str(code))
                        counter_inc(response_codes, f"{code} ({name})")
                        if code not in (0, 5, 6, 14):
                            counter_inc(ldap_error_codes, f"{code} ({name})")

                for value in _extract_ascii_strings(
                    payload
                ) + _extract_utf16le_strings(payload):
                    if not value:
                        continue
                    lower = value.lower()
                    if not decoded:
                        for attr, label_name in SENSITIVE_ATTRS.items():
                            if attr in lower and label_name in PASSWORD_ATTRS:
                                counter_inc(suspicious_attributes, label_name)
                    for pattern in SECRET_PATTERNS:
                        match = pattern.search(value)
                        if match:
                            counter_inc(secrets, match.group(0))
                            set_add_cap(artifacts, match.group(0))

                    if (
                        "resultcode" in lower
                        or "invalidcredentials" in lower
                        or "insufficientaccessrights" in lower
                    ):
                        for name_lower, name in LDAP_RESULT_NAMES.items():
                            if name_lower in lower:
                                counter_inc(response_codes, name)
                                if name_lower in {
                                    "invalidcredentials",
                                    "insufficientaccessrights",
                                }:
                                    counter_inc(ldap_error_codes, name)
                        numeric_match = re.search(
                            r"resultcode\s*[:=]\s*(\d+)", lower
                        )
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
            ldap_roles = _ldap_roles(src_ip, dst_ip, sport, dport)
            if ldap_roles is not None:
                client_ip, server_ip, server_port = ldap_roles
                _mark_window(ts)
                counter_inc(servers, server_ip)
                counter_inc(clients, client_ip)
                counter_inc(request_counts, "LDAP Traffic")
                counter_inc(service_counts, f"UDP/{server_port}")
                counter_inc(convos, (client_ip, server_ip, server_port, "UDP"))
                udp_ldap_seen = True
                cleartext_packets += 1
                if _is_public_ip(src_ip):
                    counter_inc(public_endpoints, src_ip)
                if _is_public_ip(dst_ip):
                    counter_inc(public_endpoints, dst_ip)

    # DNS and file results are only read after the packet loop: computing
    # them first made LDAP wait for both before it could read the capture
    # (one more full read in a shared --threats pass).
    dns_summary = _busy(
        "DNS", analyze_dns, path, show_status=False, packets=packets, meta=meta
    )
    files_summary = _busy(
        "Files", analyze_files, path, show_status=False, packets=packets, meta=meta
    )
    errors.extend(getattr(dns_summary, "errors", []) or [])
    errors.extend(getattr(files_summary, "errors", []) or [])

    ldap_domains = Counter()
    for qname, count in dns_summary.qname_counts.items():
        qname_lower = qname.lower()
        if any(token in qname_lower for token in LDAP_DNS_HINTS):
            ldap_domains[qname_lower] += count

    files = [art.filename for art in files_summary.artifacts]

    duration = 0.0
    if first_seen is not None and last_seen is not None:
        duration = max(0.0, last_seen - first_seen)

    conversations = [
        LdapConversation(src, dst, port, proto, count)
        for (src, dst, port, proto), count in convos.items()
    ]
    conversations.sort(key=lambda c: (-c.packets, c.src_ip, c.dst_ip, c.dst_port, c.proto))

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
        detections.append(
            {
                "severity": "warning",
                "summary": "LDAP traffic to public IPs",
                "details": ", ".join(public_servers[:10]),
                "source": "LDAP",
            }
        )

    if ldap_users:
        detections.append(
            {
                "severity": "info",
                "summary": "LDAP users observed",
                "details": ", ".join([u for u, _ in ldap_users.most_common(10)]),
                "source": "LDAP",
            }
        )

    cleartext_binds = [k for k in secrets if k.startswith("simple bind ")]
    if cleartext_binds:
        identities = sorted({k[len("simple bind "):].rsplit(": ", 1)[0] for k in cleartext_binds})
        detections.append(
            {
                "severity": "high",
                "summary": "Cleartext LDAP simple-bind credentials",
                "details": (
                    f"{len(identities)} account(s) bound with a password in the clear: {', '.join(identities[:10])} "
                    "(ATT&CK T1040 Network Sniffing)."
                ),
                "source": "LDAP",
            }
        )
    if secrets:
        detections.append(
            {
                "severity": "warning",
                "summary": "Potential secrets/passwords in LDAP payloads",
                "details": ", ".join([s for s, _ in secrets.most_common(5)]),
                "source": "LDAP",
            }
        )

    if any("invalidCredentials" in code for code in response_codes.keys()):
        # Report only the failure codes, not every result code — listing benign
        # results (0 success, 14 saslBindInProgress) made it look as if those
        # were credential failures.
        failure_detail = ", ".join(
            c for c, _ in ldap_error_codes.most_common(5)
        ) or ", ".join(
            c for c in response_codes if "invalidCredentials" in c
        )
        detections.append(
            {
                "severity": "warning",
                "summary": "LDAP invalid credentials observed",
                "details": failure_detail,
                "source": "LDAP",
            }
        )

    password_attrs = sorted(a for a in suspicious_attributes if a in PASSWORD_ATTRS)
    if password_attrs:
        detections.append(
            {
                "severity": "critical",
                "summary": "LDAP queries for password attributes",
                "details": f"Requested or filtered: {', '.join(password_attrs)} (LAPS / gMSA / password material).",
                "source": "LDAP",
            }
        )
    writes_by_attr = Counter(
        change.split(":", 1)[-1] for item in writes for change in item.get("changes", []) or []
    )
    risky_writes = sorted(a for a in writes_by_attr if a.lower() in {
        "msds-allowedtoactonbehalfofotheridentity", "msds-keycredentiallink", "serviceprincipalname",
        "member", "useraccountcontrol", "scriptpath", "msds-allowedtodelegateto", "ntsecuritydescriptor",
        "gpcfilesyspath", "sidhistory", "unicodepwd", "userpassword"})
    if risky_writes:
        detections.append(
            {
                "severity": "high",
                "summary": "LDAP writes to security-sensitive attributes",
                "details": (
                    f"Modified: {', '.join(risky_writes)} (RBCD, shadow credentials, targeted kerberoast, "
                    "group membership or logon-script abuse)."
                ),
                "source": "LDAP",
            }
        )

    # A query that filters on servicePrincipalName is how attackers enumerate
    # kerberoastable accounts (PowerView Get-NetUser -SPN, BloodHound, Rubeus
    # /stats) before requesting the crackable TGS tickets — the recon step that
    # precedes Kerberos kerberoasting. Correlate with --kerberos etype downgrade.
    spn_queries = int(ldap_filter_types.get("servicePrincipalName", 0))
    if spn_queries:
        detections.append(
            {
                "severity": "warning",
                "summary": "LDAP servicePrincipalName enumeration (kerberoast recon)",
                "details": (
                    f"{spn_queries} query(ies) filtered on servicePrincipalName — "
                    "enumeration of kerberoastable service accounts. Correlate with "
                    "--kerberos for TGS harvesting / RC4 downgrade."
                ),
                "source": "LDAP",
            }
        )

    if ldap_binds:
        anonymous_binds = [
            name
            for name in ldap_binds.keys()
            if "anonymous" in name.lower() or "guest" in name.lower()
        ]
        if anonymous_binds:
            detections.append(
                {
                    "severity": "warning",
                    "summary": "Anonymous/guest LDAP binds observed",
                    "details": ", ".join(anonymous_binds[:10]),
                    "source": "LDAP",
                }
            )

    search_count = request_counts.get("Search", 0)
    if search_count >= 50 or len(ldap_queries) >= 50 or entries_returned >= 200:
        detections.append(
            {
                "severity": "warning",
                "summary": "LDAP enumeration indicators",
                "details": (
                    f"Search requests: {search_count}, distinct filters: {len(ldap_queries)}, "
                    f"entries returned: {entries_returned}."
                ),
                "source": "LDAP",
            }
        )

    invalid_creds = ldap_error_codes.get(
        "invalidcredentials", 0
    ) or ldap_error_codes.get("49 (invalidCredentials)", 0)
    if invalid_creds and len(ldap_binds) >= 10:
        detections.append(
            {
                "severity": "warning",
                "summary": "Potential LDAP password spraying",
                "details": f"Invalid credentials: {invalid_creds}, unique bind identities: {len(ldap_binds)}.",
                "source": "LDAP",
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
                    "summary": "Potential LDAP brute-force (high bind rate)",
                    "details": f"Peak binds/min observed: {top_burst}",
                    "source": "LDAP",
                }
            )

    deterministic_checks: Dict[str, List[str]] = {
        "cleartext_ldap_exposure": [],
        "public_ldap_endpoint_exposure": [],
        "bind_auth_risk": [],
        "anonymous_or_guest_bind_activity": [],
        "enumeration_burst_activity": [],
        "credential_error_burst": [],
        "sensitive_attribute_access": [],
        "directory_write_activity": [],
        "secret_material_exposure": [],
    }
    threat_hypotheses: List[Dict[str, object]] = []
    benign_context: List[str] = []

    total_ldap_packets = max(1, int(cleartext_packets + ldaps_packets))
    clear_pct = (float(cleartext_packets) / float(total_ldap_packets)) * 100.0
    if cleartext_packets > 0:
        deterministic_checks["cleartext_ldap_exposure"].append(
            f"Cleartext LDAP packets={cleartext_packets}/{total_ldap_packets} ({clear_pct:.1f}%) on TCP/389, TCP/3268, or UDP/389"
        )
    for ip, count in public_endpoints.most_common(10):
        deterministic_checks["public_ldap_endpoint_exposure"].append(
            f"Public LDAP endpoint {_is_public_ip(ip) and ip or ip} observed count={int(count)}"
        )

    invalid_creds_total = sum(
        int(count)
        for name, count in ldap_error_codes.items()
        if "invalidcredentials" in str(name).lower()
        or str(name).strip().startswith("49 ")
    )
    insufficient_access_total = sum(
        int(count)
        for name, count in ldap_error_codes.items()
        if "insufficientaccessrights" in str(name).lower()
        or str(name).strip().startswith("50 ")
    )
    if invalid_creds_total > 0:
        deterministic_checks["credential_error_burst"].append(
            f"LDAP invalidCredentials responses observed count={invalid_creds_total}"
        )
    if insufficient_access_total > 0:
        deterministic_checks["credential_error_burst"].append(
            f"LDAP insufficientAccessRights responses observed count={insufficient_access_total}"
        )

    simple_bind_total = int(request_counts.get("Bind", 0))
    top_bind_rate = max(bind_bursts.values()) if bind_bursts else 0
    anonymous_bind_identities = [
        name
        for name in ldap_binds.keys()
        if "anonymous" in name.lower() or "guest" in name.lower()
    ]
    if simple_bind_total > 0:
        deterministic_checks["bind_auth_risk"].append(
            f"Bind operations observed count={simple_bind_total}; peak binds/min={top_bind_rate}"
        )
    if top_bind_rate >= 20:
        deterministic_checks["bind_auth_risk"].append(
            f"High bind rate suggests brute force/spray behavior peak_binds_per_min={top_bind_rate}"
        )
    if anonymous_bind_identities:
        deterministic_checks["anonymous_or_guest_bind_activity"].append(
            f"Anonymous/guest LDAP bind identities observed count={len(anonymous_bind_identities)}"
        )

    search_count = int(request_counts.get("Search", 0))
    unique_queries = len(ldap_queries)
    if search_count >= 50 or unique_queries >= 50 or entries_returned >= 200:
        deterministic_checks["enumeration_burst_activity"].append(
            f"LDAP search burst search_ops={search_count} unique_queries={unique_queries} entries={entries_returned}"
        )
    for attr, count in suspicious_attributes.most_common(8):
        deterministic_checks["sensitive_attribute_access"].append(
            f"Sensitive attribute queried attr={attr} count={int(count)}"
        )

    write_ops = (
        int(request_counts.get("Modify", 0))
        + int(request_counts.get("Add", 0))
        + int(request_counts.get("Delete", 0))
    )
    if write_ops > 0:
        deterministic_checks["directory_write_activity"].append(
            f"Directory write-like operations observed modify/add/delete={write_ops}"
        )
    if int(request_counts.get("Extended", 0)) > 0:
        deterministic_checks["directory_write_activity"].append(
            f"Extended LDAP operations observed count={int(request_counts.get('Extended', 0))}"
        )

    for value, count in secrets.most_common(8):
        deterministic_checks["secret_material_exposure"].append(
            f"Potential secret/token material observed count={int(count)} sample={value[:80]}"
        )

    if (
        deterministic_checks["enumeration_burst_activity"]
        and deterministic_checks["credential_error_burst"]
    ):
        threat_hypotheses.append(
            {
                "hypothesis": "LDAP password spraying or auth brute-force with directory enumeration",
                "confidence": "high",
                "evidence": len(deterministic_checks["enumeration_burst_activity"])
                + len(deterministic_checks["credential_error_burst"]),
            }
        )
    if (
        deterministic_checks["sensitive_attribute_access"]
        and deterministic_checks["directory_write_activity"]
    ):
        threat_hypotheses.append(
            {
                "hypothesis": "Privileged directory discovery followed by potential LDAP object modification",
                "confidence": "high",
                "evidence": len(deterministic_checks["sensitive_attribute_access"])
                + len(deterministic_checks["directory_write_activity"]),
            }
        )
    if (
        deterministic_checks["public_ldap_endpoint_exposure"]
        and deterministic_checks["cleartext_ldap_exposure"]
    ):
        threat_hypotheses.append(
            {
                "hypothesis": "Potential credential interception or exposed identity perimeter due to public cleartext LDAP",
                "confidence": "medium",
                "evidence": len(deterministic_checks["public_ldap_endpoint_exposure"])
                + len(deterministic_checks["cleartext_ldap_exposure"]),
            }
        )
    if (
        deterministic_checks["anonymous_or_guest_bind_activity"]
        and deterministic_checks["sensitive_attribute_access"]
    ):
        threat_hypotheses.append(
            {
                "hypothesis": "Anonymous/guest LDAP bind activity with sensitive attribute discovery",
                "confidence": "high",
                "evidence": len(
                    deterministic_checks["anonymous_or_guest_bind_activity"]
                )
                + len(deterministic_checks["sensitive_attribute_access"]),
            }
        )
    if deterministic_checks["secret_material_exposure"]:
        threat_hypotheses.append(
            {
                "hypothesis": "Credential/secret material potentially exposed in LDAP payload telemetry",
                "confidence": "medium",
                "evidence": len(deterministic_checks["secret_material_exposure"]),
            }
        )

    if not deterministic_checks["credential_error_burst"]:
        benign_context.append("No strong LDAP credential-error burst pattern observed")
    if not deterministic_checks["directory_write_activity"]:
        benign_context.append(
            "No clear LDAP modify/add/delete operation burst detected"
        )
    if not deterministic_checks["sensitive_attribute_access"]:
        benign_context.append("No repeated sensitive-attribute query pattern observed")

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
        deterministic_checks=deterministic_checks,
        threat_hypotheses=threat_hypotheses,
        benign_context=benign_context[:20],
        operations=operations,
        search_requests=search_requests,
        writes=writes,
        entries_returned=entries_returned,
        spns=spns,
        diagnostics=diagnostics,
    )
