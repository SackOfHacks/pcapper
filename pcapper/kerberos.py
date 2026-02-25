from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
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

UPN_RE = re.compile(r"\b([A-Za-z0-9._-]{2,})@([A-Za-z0-9.-]{2,})\b")
SPN_RE = re.compile(r"\b([A-Za-z0-9._-]{2,}/[A-Za-z0-9._-]{2,})(?:@([A-Za-z0-9.-]{2,}))?\b")
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
CNAME_USER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{2,32}$")


def _split_cname_concat(value: str) -> Optional[tuple[str, str]]:
    text = str(value or "").strip()
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
            if not CNAME_USER_RE.fullmatch(user):
                start = idx + 1
                continue
            if realm.count(".") < 1:
                start = idx + 1
                continue
            if not any(ch.isalpha() for ch in realm):
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

            for value in _extract_ascii_strings(payload) + _extract_utf16le_strings(payload):
                if not value:
                    continue
                artifacts.add(value)

                for match in UPN_RE.finditer(value):
                    user = match.group(1)
                    realm = match.group(2)
                    principal = f"{user}@{realm}"
                    principals[principal] += 1
                    realms[realm] += 1
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
                    principal = f"{user}@{realm}"
                    principals[principal] += 1
                    realms[realm] += 1
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
                    spn = match.group(1)
                    spns[spn] += 1
                    realm = match.group(2)
                    if realm:
                        realms[realm] += 1

                if "krbtgt" in value.lower():
                    spns["krbtgt"] += 1

                for req in REQ_RE.findall(value):
                    request_types[req.upper()] += 1
                    if ts is not None and req.upper() in {"AS-REQ", "TGS-REQ"}:
                        bind_buckets[(src_ip, int(ts // 60))] += 1

                for err in ERR_RE.findall(value):
                    error_codes[err] += 1

                lower = value.lower()
                if "as-rep" in lower and "preauth" in lower:
                    suspicious_attributes["AS-REP (preauth)"] += 1
                if "pa-enc-timestamp" in lower:
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
        artifacts=sorted(artifacts),
        anomalies=anomalies,
        detections=detections,
        errors=errors,
    )
