from __future__ import annotations


from .utils import shannon_entropy as _shannon_entropy
from .utils import is_public_ip as _is_public_ip
import ipaddress
import re
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from .pcap_cache import get_reader
from .utils import memoize_analysis, safe_float

try:
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.dns import DNS
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, Ether
    from scapy.packet import Raw
except Exception:
    IP = TCP = UDP = IPv6 = DHCP = BOOTP = DNS = ARP = Ether = Raw = None

try:
    from scapy.layers.dhcp6 import DHCP6OptClientFQDN  # type: ignore
except Exception:
    DHCP6OptClientFQDN = None

try:
    from scapy.layers.tls.handshake import (  # type: ignore
        TLSCertificate,
        TLSClientHello,
    )
except Exception:
    TLSClientHello = TLSCertificate = None


MAIL_SERVER_PORTS = {25, 110, 143, 465, 587, 993, 995, 2525}
FTP_PORTS = {20, 21, 989, 990}
SSH_PORTS = {22}
SNMP_PORTS = {161, 162}
SMB_PORTS = {139, 445}
SSDP_PORTS = {1900}
KERBEROS_PORTS = {88, 464}
LDAP_PORTS = {389, 636, 3268, 3269}
SIP_PORTS = {5060, 5061}
RDP_PORTS = {3389}
LLDP_ETHERTYPE = 0x88CC
CDP_SNAP_HEADER = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00"
CDP_MULTICAST_MAC = "01:00:0c:cc:cc:cc"
# Canonical OT port map shared with timeline.py (closes the prior coverage gap
# where this map silently omitted MELSEC/CODESYS/FINS/HART/etc.).
from .ot_ports import OT_PORT_PROTOCOLS

HOSTNAME_TOKEN_RE = re.compile(
    r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){0,6}\b",
    re.IGNORECASE,
)
HOSTNAME_LABELED_RE = re.compile(
    r"(?i)\b(?:host(?:name)?|server|client|station|node|device|controller|endpoint|ied|plc|rtu|hmi|scada)"
    r"(?:[_\s\-]*(?:name|id|uri|url))?\s*[:=]\s*([A-Za-z0-9._-]{2,253})"
)
LDAP_DNSHOST_RE = re.compile(r"(?i)\bdnshostname\s*[:=]\s*([A-Za-z0-9._-]{2,253})")
KERBEROS_SPN_RE = re.compile(
    r"(?i)\b(?:host|cifs|ldap|http|termsrv|mssqlsvc)/([A-Za-z0-9._-]{2,253})"
)
SIP_URI_HOST_RE = re.compile(r"(?i)\bsips?:[^@\s;>]+@([A-Za-z0-9._-]{2,253})")
RDP_COOKIE_RE = re.compile(r"(?i)\bcookie:\s*mstshash=([^\r\n\x00]{1,256})")
HTTP_REQUEST_LINE_RE = re.compile(
    r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)(?:\s+HTTP/[\d.]+)?[ \t]*(?:\r?\n|$)",
    re.IGNORECASE,
)


@dataclass
class HostnameFinding:
    hostname: str
    mapped_ip: str
    protocol: str
    method: str
    confidence: str
    details: str
    src_ip: str
    dst_ip: str
    first_seen: Optional[float]
    last_seen: Optional[float]
    first_packet: Optional[int]
    last_packet: Optional[int]
    count: int = 1


@dataclass
class HostnameSummary:
    path: Path
    target_ip: str | None
    hostname_query: str | None = None
    port_filter: int | None = None
    search_query: str | None = None
    total_packets: int = 0
    relevant_packets: int = 0
    findings: list[HostnameFinding] = field(default_factory=list)
    protocol_counts: Counter[str] = field(default_factory=Counter)
    method_counts: Counter[str] = field(default_factory=Counter)
    ip_to_macs: dict[str, list[str]] = field(default_factory=dict)
    analyst_verdict: str = ""
    analyst_confidence: str = "low"
    analyst_reasons: list[str] = field(default_factory=list)
    conflict_profiles: list[dict[str, object]] = field(default_factory=list)
    drift_profiles: list[dict[str, object]] = field(default_factory=list)
    suspicious_name_profiles: list[dict[str, object]] = field(default_factory=list)
    cross_protocol_corroboration: list[dict[str, object]] = field(default_factory=list)
    false_positive_context: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _build_hostname_enrichment(
    findings: list[HostnameFinding],
) -> dict[str, object]:
    checks: dict[str, list[str]] = defaultdict(list)

    def _is_priv(addr: str) -> bool:
        try:
            return ipaddress.ip_address(addr).is_private
        except Exception:
            return False

    name_to_ips: dict[str, set[str]] = defaultdict(set)
    ip_to_names: dict[str, set[str]] = defaultdict(set)
    for f in findings or []:
        name = _normalize_hostname(str(getattr(f, "hostname", "")))
        ip = str(getattr(f, "mapped_ip", "") or "")
        if not name or not ip or _is_ip_literal(name):
            continue
        name_to_ips[name].add(ip)
        ip_to_names[ip].add(name)

    # Hostname collision/spoofing: one INTERNAL hostname mapped to multiple
    # distinct IPs (name conflict / spoofing). For public names this is normal
    # load balancing / CDN, so only flag when an internal (private) IP is
    # involved.
    for name, ips in name_to_ips.items():
        if len(ips) < 2:
            continue
        if any(_is_priv(ip) for ip in ips):
            checks["hostname_collision_or_spoofing"].append(
                f"{name} -> {len(ips)} IPs ({', '.join(sorted(ips)[:4])})"
            )

    # IP alias / fronting: a single PRIVATE IP presenting many distinct
    # hostnames (identity ambiguity). Public IPs hosting many names = shared
    # hosting/CDN (benign), so restrict to internal IPs and a high count.
    for ip, names in ip_to_names.items():
        if _is_priv(ip) and len(names) >= 5:
            checks["ip_alias_or_fronting_anomaly"].append(
                f"{ip} presents {len(names)} hostnames ({', '.join(sorted(names)[:4])}...)"
            )

    score = 0
    reasons: list[str] = []
    if checks.get("hostname_collision_or_spoofing"):
        score += 2
        reasons.append("Internal hostname resolves to multiple IPs (possible conflict/spoofing)")
    if checks.get("ip_alias_or_fronting_anomaly"):
        score += 1
        reasons.append("An internal IP presents an unusually large set of hostnames")

    if score >= 4:
        verdict = "LIKELY - hostname identity anomaly with spoofing/conflict indicators is present."
        confidence = "medium"
    elif score >= 2:
        verdict = "POSSIBLE - hostname identity anomaly observed; verify against DHCP/DNS/ARP."
        confidence = "low"
    elif score >= 1:
        verdict = "LOW SIGNAL - minor hostname identity ambiguity present."
        confidence = "low"
    else:
        verdict = ""
        confidence = "low"
    if not reasons and verdict:
        reasons.append("Hostname identity heuristics crossed threshold")

    return {
        "analyst_verdict": verdict,
        "analyst_confidence": confidence,
        "analyst_reasons": reasons,
    }

def _normalize_hostname(value: str) -> str:
    hostname = value.strip().strip(".")
    hostname = re.sub(r"\s+", "", hostname)
    return hostname.lower()


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


def _is_valid_hostname(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    if " " in value or value.startswith("."):
        return False
    labels = value.split(".")
    if len(labels) < 1:
        return False
    # Underscore is invalid in DNS but common in real machine names
    # (NetBIOS, SNI values like "nat_hydra"); this is a discovery tool,
    # so accept it rather than drop genuine host identifiers.
    allowed = re.compile(r"^[a-z0-9_-]{1,63}$", re.IGNORECASE)
    for label in labels:
        if not label or not allowed.match(label):
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
    return True


def _decode_name(value: object) -> str:
    if isinstance(value, (bytes, bytearray)):
        text = value.decode("utf-8", errors="ignore")
    else:
        text = str(value)
    text = text.replace("\x00", "").strip(".")
    return text


def _decode_nbns_level1_name(value: object) -> Optional[str]:
    raw_text = ""
    if isinstance(value, (bytes, bytearray)):
        raw_bytes = bytes(value)
        if len(raw_bytes) >= 33 and raw_bytes[0] == 0x20:
            try:
                raw_text = raw_bytes[1:33].decode("ascii", errors="ignore")
            except Exception:
                raw_text = ""
        else:
            try:
                raw_text = raw_bytes.decode("ascii", errors="ignore")
            except Exception:
                raw_text = ""
    else:
        raw_text = str(value)

    raw_text = raw_text.strip().strip(".")
    if not raw_text:
        return None

    match = re.search(r"[A-Pa-p]{32}", raw_text)
    if not match:
        return None
    encoded = match.group(0).upper()

    decoded_bytes = bytearray()
    for idx in range(0, 32, 2):
        hi = ord(encoded[idx]) - ord("A")
        lo = ord(encoded[idx + 1]) - ord("A")
        if not (0 <= hi <= 15 and 0 <= lo <= 15):
            return None
        decoded_bytes.append((hi << 4) | lo)

    if len(decoded_bytes) != 16:
        return None

    try:
        host = (
            bytes(decoded_bytes[:15]).decode("latin-1", errors="ignore").rstrip(" \x00")
        )
    except Exception:
        return None
    if not host:
        return None
    return host


def _target_reverse_ptr(target_ip: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(target_ip)
    except ValueError:
        return ""
    if ip_obj.version == 4:
        return ".".join(reversed(target_ip.split("."))) + ".in-addr.arpa"
    return ip_obj.reverse_pointer


def _ptr_name_to_ip(ptr_name: str) -> str:
    name = ptr_name.strip().strip(".").lower()
    suffix_v4 = ".in-addr.arpa"
    if name.endswith(suffix_v4):
        body = name[: -len(suffix_v4)]
        octets = body.split(".")
        if len(octets) == 4 and all(
            part.isdigit() and 0 <= int(part) <= 255 for part in octets
        ):
            return ".".join(reversed(octets))
    return ""


def _extract_ip_pair(ip_layer, ipv6_layer, arp_layer) -> tuple[str, str]:
    if ip_layer is not None:
        return str(ip_layer.src), str(ip_layer.dst)
    if ipv6_layer is not None:
        return str(ipv6_layer.src), str(ipv6_layer.dst)
    if arp_layer is not None:
        try:
            return str(getattr(arp_layer, "psrc", "0.0.0.0") or "0.0.0.0"), str(
                getattr(arp_layer, "pdst", "0.0.0.0") or "0.0.0.0"
            )
        except Exception:
            return "0.0.0.0", "0.0.0.0"
    return "0.0.0.0", "0.0.0.0"


def _extract_payload(raw_layer, tcp_layer, udp_layer) -> bytes:
    if raw_layer is not None:
        try:
            return bytes(raw_layer.load)
        except Exception:
            return b""
    if tcp_layer is not None:
        try:
            return bytes(tcp_layer.payload)
        except Exception:
            return b""
    if udp_layer is not None:
        try:
            return bytes(udp_layer.payload)
        except Exception:
            return b""
    return b""


def _extract_ports(tcp_layer, udp_layer) -> tuple[Optional[int], Optional[int]]:
    if tcp_layer is not None:
        try:
            return int(tcp_layer.sport), int(tcp_layer.dport)
        except Exception:
            return None, None
    if udp_layer is not None:
        try:
            return int(udp_layer.sport), int(udp_layer.dport)
        except Exception:
            return None, None
    return None, None


def _normalize_mac(value: object) -> str:
    text = str(value or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", text):
        return text
    return ""


def _remember_ip_mac(
    ip_to_macs: dict[str, set[str]], ip_value: str, mac_value: object
) -> None:
    mac = _normalize_mac(mac_value)
    if not mac:
        return
    try:
        ip_obj = ipaddress.ip_address(ip_value)
    except Exception:
        return
    if ip_obj.is_unspecified:
        return
    ip_to_macs[str(ip_obj)].add(mac)


def _remember_mac_ip(
    mac_to_ips: dict[str, set[str]], mac_value: object, ip_value: str
) -> None:
    mac = _normalize_mac(mac_value)
    if not mac:
        return
    try:
        ip_obj = ipaddress.ip_address(ip_value)
    except Exception:
        return
    if ip_obj.is_unspecified or ip_obj.is_multicast:
        return
    mac_to_ips[mac].add(str(ip_obj))


def _safe_dns_attr(dns_layer, attr: str, default=None):
    try:
        return getattr(dns_layer, attr)
    except Exception:
        return default


def _iter_dns_rrs(dns_layer) -> list[tuple[object, str]]:
    rows: list[tuple[object, str]] = []
    for section_attr, count_attr in (
        ("an", "ancount"),
        ("ns", "nscount"),
        ("ar", "arcount"),
    ):
        current = _safe_dns_attr(dns_layer, section_attr, None)
        rr_count = int(_safe_dns_attr(dns_layer, count_attr, 0) or 0)
        for _ in range(rr_count):
            if current is None:
                break
            rows.append((current, section_attr))
            current = getattr(current, "payload", None)
    return rows


def _extract_nbns_hostnames(pkt, payload: bytes) -> list[str]:
    results: list[str] = []
    seen: set[str] = set()

    # A NetBIOS name-QUERY request (opcode 0, QR=0) asks about ANOTHER host, so
    # its QUESTION_NAME must not be attributed to the sender (caller maps these
    # to src_ip). Registrations (opcode 5+) and responses name the sender/owner
    # and are kept. Determine the message type from the dissected NBNS header,
    # falling back to the raw header flags byte (NBNS byte 2: bit 0x80 = QR,
    # bits 0x78 = opcode).
    is_name_query_request = False
    try:
        hdr = pkt.getlayer("NBNSHeader") if hasattr(pkt, "getlayer") else None
    except Exception:
        hdr = None
    if hdr is not None:
        if (
            int(getattr(hdr, "RESPONSE", 0) or 0) == 0
            and int(getattr(hdr, "OPCODE", 0) or 0) == 0
        ):
            is_name_query_request = True
    elif payload and len(payload) >= 3:
        flags = payload[2]
        if (flags & 0x80) == 0 and ((flags >> 3) & 0x0F) == 0:
            is_name_query_request = True
    if is_name_query_request:
        return results

    def _append(name: Optional[str]) -> None:
        if not name:
            return
        normalized = _normalize_hostname(name)
        if not normalized:
            return
        if normalized in seen:
            return
        seen.add(normalized)
        results.append(name)

    try:
        if hasattr(pkt, "getlayer"):
            layer = pkt.getlayer("NBNSQueryRequest")
            if layer is not None:
                for attr in ("QUESTION_NAME", "qname", "RR_NAME", "rrname"):
                    decoded = _decode_nbns_level1_name(getattr(layer, attr, None))
                    _append(decoded)
        if hasattr(pkt, "getlayer"):
            layer = pkt.getlayer("NBNSQueryResponse")
            if layer is not None:
                for attr in ("QUESTION_NAME", "qname", "RR_NAME", "rrname"):
                    decoded = _decode_nbns_level1_name(getattr(layer, attr, None))
                    _append(decoded)
    except Exception:
        pass

    if payload:
        try:
            text = payload.decode("latin-1", errors="ignore")
        except Exception:
            text = ""
        for token in re.findall(r"[A-Pa-p]{32}", text):
            decoded = _decode_nbns_level1_name(token)
            _append(decoded)

    return results


def _clean_authority_host(value: str) -> str:
    host = value.split("@", 1)[-1].strip()
    if host.startswith("["):
        host = host[1:].split("]", 1)[0]
    else:
        host = host.split(":", 1)[0]
    host = _normalize_hostname(host.strip().strip("."))
    return host if _is_valid_hostname(host) else ""


def _parse_http_request(payload: bytes) -> Optional[dict]:
    """Parse an HTTP/1.x request start-line + Host header.

    Returns {'form', 'authority_host', 'host_header'} where form is:
    - 'origin'   - "GET /path" sent to the origin server (Host names dst)
    - 'absolute' - "GET http://host/path" sent to a forward proxy
    - 'connect'  - "CONNECT host:port" sent to a forward proxy
    For absolute/connect forms the packet's dst IP is the PROXY, so the
    named host must not be mapped to dst_ip.
    """
    if not payload:
        return None
    try:
        text = payload[:2048].decode("latin-1", errors="ignore")
    except Exception:
        return None
    match = HTTP_REQUEST_LINE_RE.match(text)
    if not match:
        return None
    method = match.group(1).upper()
    target = match.group(2)

    form = "origin"
    authority = ""
    if method == "CONNECT":
        form = "connect"
        authority = target
    elif target.startswith(("http://", "https://")):
        form = "absolute"
        authority = target.split("//", 1)[1].split("/", 1)[0]

    host_header = ""
    for line in text.splitlines()[1:64]:
        if not line.strip():
            break
        if line.lower().startswith("host:"):
            host_header = line.split(":", 1)[1].strip()
            break

    return {
        "form": form,
        "authority_host": _clean_authority_host(authority) if authority else "",
        "host_header": _clean_authority_host(host_header) if host_header else "",
    }


def _parse_http2_authority_host(payload: bytes) -> Optional[str]:
    if not payload:
        return None
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return None
    if ":authority" not in text.lower():
        return None

    match = re.search(r"(?i):authority\s*[:=]\s*([A-Za-z0-9._-]{2,253})", text)
    if not match:
        return None
    host = _normalize_hostname(match.group(1))
    return host if _is_valid_hostname(host) else None


def _extract_mail_hostnames(payload: bytes) -> list[tuple[str, str, str]]:
    if not payload:
        return []
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return []

    findings: list[tuple[str, str, str]] = []
    seen: set[str] = set()

    def _add(host: str, method: str, confidence: str) -> None:
        normalized = _normalize_hostname(host)
        if not _is_valid_hostname(normalized):
            return
        key = f"{normalized}|{method}|{confidence}"
        if key in seen:
            return
        seen.add(key)
        findings.append((host, method, confidence))

    for line in text.splitlines()[:32]:
        line_text = line.strip()
        if not line_text:
            continue

        match = re.match(
            r"^(?:EHLO|HELO|LHLO)\s+([A-Za-z0-9._-]{1,253})", line_text, re.IGNORECASE
        )
        if match:
            _add(match.group(1), "SMTP HELO/EHLO", "MEDIUM")

        match = re.match(
            r"^220(?:[\s-]+)([A-Za-z0-9._-]{1,253})", line_text, re.IGNORECASE
        )
        if match:
            _add(match.group(1), "SMTP server banner", "MEDIUM")

        match = re.match(
            r"^\*\s+OK\s+([A-Za-z0-9._-]{1,253})", line_text, re.IGNORECASE
        )
        if match:
            _add(match.group(1), "IMAP server banner", "LOW")

        match = re.match(r"^\+OK\s+([A-Za-z0-9._-]{1,253})", line_text, re.IGNORECASE)
        if match:
            _add(match.group(1), "POP server banner", "LOW")

    return findings


def _looks_hostname_like(value: str, *, require_hint: bool = False) -> bool:
    normalized = _normalize_hostname(value)
    if not _is_valid_hostname(normalized):
        return False

    label0 = normalized.split(".", 1)[0]
    if len(label0) < 2:
        return False

    reserved = {
        "www",
        "http",
        "https",
        "ftp",
        "smtp",
        "imap",
        "pop3",
        "ssh",
        "dns",
        "tcp",
        "udp",
        "data",
        "guest",
        "admin",
        "root",
        "none",
        "null",
        "ok",
        "mail",
    }
    if normalized in reserved:
        return False

    if "." in normalized or normalized.endswith(".local"):
        return True

    has_alpha = any(ch.isalpha() for ch in label0)
    has_digit = any(ch.isdigit() for ch in label0)
    if has_alpha and has_digit:
        return True

    prefixes = (
        "plc",
        "rtu",
        "hmi",
        "scada",
        "ied",
        "srv",
        "host",
        "node",
        "ws",
        "pc",
        "dc",
        "eng",
        "opc",
        "io",
        "station",
        "client",
        "server",
    )
    if label0.startswith(prefixes):
        return True

    return not require_hint


def _extract_textual_hostname_tokens(
    text: str, *, require_hint: bool = False
) -> list[str]:
    if not text:
        return []
    candidates: list[str] = []
    seen: set[str] = set()
    for token in HOSTNAME_TOKEN_RE.findall(text):
        normalized = _normalize_hostname(token)
        if not _looks_hostname_like(normalized, require_hint=require_hint):
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        candidates.append(normalized)
    return candidates


def _extract_ftp_hostnames(payload: bytes) -> list[tuple[str, str, str, str]]:
    if not payload:
        return []
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return []

    findings: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()

    def _add(host: str, method: str, confidence: str, details: str) -> None:
        normalized = _normalize_hostname(host)
        if not _looks_hostname_like(normalized, require_hint=True):
            return
        key = f"{normalized}|{method}"
        if key in seen:
            return
        seen.add(key)
        findings.append((normalized, method, confidence, details))

    for line in text.splitlines()[:40]:
        line_text = line.strip()
        if not line_text:
            continue

        match = re.match(
            r"^220(?:[\s-]+)([A-Za-z0-9._-]{2,253})", line_text, re.IGNORECASE
        )
        if match:
            _add(
                match.group(1),
                "FTP server banner",
                "MEDIUM",
                f"FTP control greeting: {line_text[:120]}",
            )

        match = re.search(
            r"(?i)\b(?:ftp(?:\s+server)?|server)\s+(?:at|on)\s+([A-Za-z0-9._-]{2,253})",
            line_text,
        )
        if match:
            _add(
                match.group(1),
                "FTP hostname token",
                "LOW",
                f"FTP control line: {line_text[:120]}",
            )

    return findings


def _extract_ssh_hostnames(payload: bytes) -> list[tuple[str, str, str, str]]:
    if not payload:
        return []
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return []

    # RFC 4253: only the identification string ("SSH-2.0-software comments")
    # can carry a hostname, in its optional comment field. Binary KEX packets
    # are full of algorithm names ("3des-cbc", "ssh-ed25519", ...) that look
    # hostname-like to the tokenizer, so anything past the first line —
    # or a payload that doesn't START with the identification string — is noise.
    first_line = text.splitlines()[0].strip() if text else ""
    if not first_line.startswith("SSH-") or " " not in first_line:
        return []
    comment = first_line.split(" ", 1)[1]

    findings: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()
    for token in _extract_textual_hostname_tokens(comment, require_hint=True):
        if "." not in token:
            continue
        if token in seen:
            continue
        seen.add(token)
        findings.append(
            (
                token,
                "SSH banner hostname token",
                "LOW",
                f"SSH identification string: {first_line[:120]}",
            )
        )
    return findings


def _extract_snmp_hostnames(
    payload: bytes,
    sport: int | None,
    dport: int | None,
    src_ip: str,
    dst_ip: str,
) -> list[tuple[str, str, str, str, str]]:
    if not payload:
        return []
    if sport not in SNMP_PORTS and dport not in SNMP_PORTS:
        return []

    try:
        from .snmp import OID_LABELS as _SNMP_OID_LABELS
        from .snmp import _parse_snmp_message
    except Exception:
        return []

    msg = _parse_snmp_message(payload)
    if not isinstance(msg, dict):
        return []

    findings: list[tuple[str, str, str, str, str]] = []
    seen: set[str] = set()
    pdu = str(msg.get("pdu", "-") or "-")
    server_ip = src_ip if sport in SNMP_PORTS else dst_ip

    def _add(host: str, method: str, confidence: str, details: str) -> None:
        normalized = _normalize_hostname(host)
        if not _looks_hostname_like(normalized, require_hint=False):
            return
        key = f"{normalized}|{method}|{server_ip}"
        if key in seen:
            return
        seen.add(key)
        findings.append((normalized, method, confidence, server_ip, details))

    for oid, value in list(msg.get("varbinds", []) or []):
        oid_text = str(oid or "")
        value_text = _decode_name(value)
        if not value_text:
            continue
        label_text = str(_SNMP_OID_LABELS.get(oid_text, ""))

        if label_text == "sysName":
            _add(
                value_text, "SNMP sysName OID", "HIGH", f"SNMP {pdu} {oid_text}=sysName"
            )
            continue

        if label_text in {
            "sysDescr",
            "hrDeviceDescr",
            "hrSWRunName",
            "hrSWInstalledName",
            "sysContact",
            "sysLocation",
        }:
            for token in _extract_textual_hostname_tokens(
                value_text, require_hint=True
            ):
                _add(
                    token,
                    f"SNMP {label_text} hostname token",
                    "LOW",
                    f"SNMP {pdu} {oid_text} {label_text}",
                )

    return findings


def _extract_directory_auth_hostnames(
    payload: bytes,
) -> list[tuple[str, str, str, str]]:
    if not payload:
        return []
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return []

    findings: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()

    def _add(host: str, method: str, confidence: str, details: str) -> None:
        normalized = _normalize_hostname(host)
        if not _looks_hostname_like(normalized, require_hint=False):
            return
        key = f"{normalized}|{method}"
        if key in seen:
            return
        seen.add(key)
        findings.append((normalized, method, confidence, details))

    for match in LDAP_DNSHOST_RE.findall(text):
        _add(
            match,
            "LDAP dNSHostName attribute",
            "MEDIUM",
            "LDAP payload contains dNSHostName",
        )

    for match in KERBEROS_SPN_RE.findall(text):
        _add(
            match,
            "Kerberos SPN host component",
            "MEDIUM",
            "Kerberos host-based service principal",
        )

    return findings


def _extract_sip_hostnames(payload: bytes) -> list[tuple[str, str, str, str]]:
    if not payload:
        return []
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return []

    findings: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()

    def _add(host: str, method: str, confidence: str, details: str) -> None:
        normalized = _normalize_hostname(host)
        if not _looks_hostname_like(normalized, require_hint=False):
            return
        key = f"{normalized}|{method}"
        if key in seen:
            return
        seen.add(key)
        findings.append((normalized, method, confidence, details))

    for host in SIP_URI_HOST_RE.findall(text):
        _add(host, "SIP URI host", "MEDIUM", "SIP URI contains host component")

    for line in text.splitlines()[:40]:
        line_text = line.strip()
        if not line_text:
            continue
        if not re.match(
            r"(?i)^(via|contact|from|to|route|record-route)\s*:", line_text
        ):
            continue
        for token in _extract_textual_hostname_tokens(line_text, require_hint=True):
            _add(
                token, "SIP header host token", "LOW", f"SIP header: {line_text[:120]}"
            )

    return findings


def _extract_rdp_hostnames(payload: bytes) -> list[tuple[str, str, str, str]]:
    if not payload:
        return []
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return []
    findings: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()
    for raw_value in RDP_COOKIE_RE.findall(text):
        value = raw_value.strip()
        if not value:
            continue
        # MS-RDPBCGR: mstshash carries the client's login identity --
        # typically "username" or "DOMAIN\username", NOT a hostname.
        if "\\" in value:
            token, _, user = value.partition("\\")
            method = "RDP mstshash cookie domain"
            detail = (
                f"RDP negotiation cookie mstshash={value[:64]} "
                f"(DOMAIN\\username form; domain token of the connecting client)"
            )
        else:
            token = value
            method = "RDP mstshash cookie"
            detail = (
                f"RDP negotiation cookie mstshash={value[:64]} "
                "(client login identity; typically the username, sometimes the client hostname)"
            )
        normalized = _normalize_hostname(token)
        if not _looks_hostname_like(normalized, require_hint=False):
            continue
        dedupe_key = f"{normalized}|{method}"
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        findings.append((normalized, method, "LOW", detail))
    return findings


def _extract_opcua_hostnames(payload: bytes) -> list[tuple[str, str, str, str]]:
    if not payload:
        return []
    findings: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()

    def _add(host: str, method: str, confidence: str, details: str) -> None:
        normalized = _normalize_hostname(host)
        if not _looks_hostname_like(normalized, require_hint=False):
            return
        key = f"{normalized}|{method}"
        if key in seen:
            return
        seen.add(key)
        findings.append((normalized, method, confidence, details))

    def _from_url(url_value: str, method: str) -> None:
        try:
            parsed = urlsplit(url_value.strip())
            host = parsed.hostname or ""
        except Exception:
            host = ""
        if host:
            _add(host, method, "HIGH", f"OPC UA URL/URI: {url_value[:140]}")

    try:
        from .opc import _parse_opcua

        _commands, artifacts = _parse_opcua(payload)
        for kind, detail in artifacts:
            kind_text = str(kind or "")
            detail_text = str(detail or "")
            if kind_text == "opcua_endpoint":
                _from_url(detail_text, "OPC UA endpoint URL")
            elif kind_text in {
                "opcua_app_uri",
                "opcua_server_uri",
                "opcua_product_uri",
            }:
                if detail_text.lower().startswith("urn:"):
                    urn_host = (
                        detail_text.split(":", 2)[1]
                        if detail_text.count(":") >= 2
                        else ""
                    )
                    if urn_host:
                        _add(
                            urn_host,
                            "OPC UA application/server URI",
                            "MEDIUM",
                            f"{kind_text}={detail_text[:140]}",
                        )
                for token in _extract_textual_hostname_tokens(
                    detail_text, require_hint=True
                ):
                    _add(
                        token,
                        "OPC UA URI hostname token",
                        "LOW",
                        f"{kind_text}={detail_text[:140]}",
                    )
    except Exception:
        pass

    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        text = ""
    for match in re.findall(r"(?i)\bopc\.tcp://[^\s\"'<>]+", text):
        _from_url(match, "OPC UA endpoint URL")
    for match in re.findall(r"(?i)\burn:[A-Za-z0-9._-]+:[^\s\"'<>]+", text):
        urn_host = match.split(":", 2)[1] if match.count(":") >= 2 else ""
        if urn_host:
            _add(
                urn_host,
                "OPC UA application/server URI",
                "MEDIUM",
                f"URI token: {match[:140]}",
            )

    return findings


def _extract_profinet_hostnames(payload: bytes) -> list[tuple[str, str, str, str]]:
    if not payload:
        return []
    findings: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()

    def _add(host: str, method: str, confidence: str, details: str) -> None:
        normalized = _normalize_hostname(host)
        if not _looks_hostname_like(normalized, require_hint=False):
            return
        key = f"{normalized}|{method}"
        if key in seen:
            return
        seen.add(key)
        findings.append((normalized, method, confidence, details))

    try:
        from .profinet import _parse_dcp

        commands, artifacts, _anomalies = _parse_dcp(payload)
        command_text = ",".join(str(cmd) for cmd in commands[:3])
        for kind, detail in artifacts:
            if kind in {"dcp_device_name", "dcp_alias_name"}:
                _add(
                    str(detail),
                    "PROFINET DCP NameOfStation",
                    "HIGH",
                    f"{kind} {command_text}",
                )
    except Exception:
        pass

    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        text = ""
    for match in re.findall(
        r"(?i)\b(?:nameofstation|dcp_device_name|dcp_alias_name|station[_\s-]?name)\s*[:=]\s*([A-Za-z0-9._-]{2,253})",
        text,
    ):
        _add(
            match, "PROFINET station name token", "MEDIUM", "PROFINET DCP payload token"
        )

    return findings


def _extract_ot_keyword_hostnames(
    payload: bytes, protocol_name: str
) -> list[tuple[str, str, str, str]]:
    if not payload:
        return []
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return []

    findings: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()

    def _add(host: str, method: str, confidence: str, details: str) -> None:
        normalized = _normalize_hostname(host)
        if not _looks_hostname_like(normalized, require_hint=True):
            return
        key = f"{normalized}|{method}"
        if key in seen:
            return
        seen.add(key)
        findings.append((normalized, method, confidence, details))

    for host in HOSTNAME_LABELED_RE.findall(text):
        _add(
            host,
            f"{protocol_name} labeled hostname token",
            "LOW",
            f"{protocol_name} payload labeled host identifier",
        )

    return findings


def _extract_modbus_device_id_hostnames(
    payload: bytes,
) -> list[tuple[str, str, str, str]]:
    if not payload or len(payload) < 8:
        return []
    try:
        from .modbus import _parse_device_id_response
    except Exception:
        return []

    findings: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()
    idx = 0
    while idx + 8 <= len(payload):
        try:
            _tx_id, proto_id, length = struct.unpack(">HHH", payload[idx : idx + 6])
        except Exception:
            break
        if proto_id != 0:
            break
        pdu_len = int(length) - 1
        if pdu_len <= 0:
            break
        start = idx + 7
        end = start + pdu_len
        if end > len(payload):
            break
        pdu = payload[start:end]
        fields = _parse_device_id_response(pdu)
        if fields:
            for key in ("product", "model", "user_app", "vendor", "product_code"):
                value = str(fields.get(key, "") or "").strip()
                if not value:
                    continue
                for token in _extract_textual_hostname_tokens(value, require_hint=True):
                    dedupe_key = f"{token}|{key}"
                    if dedupe_key in seen:
                        continue
                    seen.add(dedupe_key)
                    findings.append(
                        (
                            token,
                            "Modbus device identity field",
                            "LOW",
                            f"Read Device ID field {key}={value[:120]}",
                        )
                    )
        idx = end
    return findings


def _extract_unc_hostnames(payload: bytes) -> list[str]:
    if not payload:
        return []
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return []
    hosts: list[str] = []
    seen: set[str] = set()
    for match in re.findall(r"\\\\([A-Za-z0-9._-]{1,253})\\", text):
        normalized = _normalize_hostname(match)
        if not _is_valid_hostname(normalized):
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        hosts.append(match)
    return hosts


def _extract_smb_hostnames(payload: bytes) -> list[tuple[str, str, str, str]]:
    if not payload:
        return []
    texts: list[str] = []
    try:
        texts.append(payload.decode("latin-1", errors="ignore"))
    except Exception:
        pass
    try:
        texts.append(payload.decode("utf-16le", errors="ignore"))
    except Exception:
        pass
    blob = "\n".join(text for text in texts if text)
    if not blob:
        return []

    findings: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()

    def _add(host: str, method: str, confidence: str, details: str) -> None:
        normalized = _normalize_hostname(host)
        if not _looks_hostname_like(normalized, require_hint=True):
            return
        key = f"{normalized}|{method}"
        if key in seen:
            return
        seen.add(key)
        findings.append((normalized, method, confidence, details))

    patterns = [
        (
            r"(?i)\b(?:workstation|computer|client(?:_name)?|host(?:name)?)\s*[:=]\s*([A-Za-z0-9._-]{2,253})",
            "SMB workstation token",
        ),
        (
            r"(?i)\b(?:primarydomain|domain)\s*[:=]\s*([A-Za-z0-9._-]{2,253})",
            "SMB domain token",
        ),
    ]
    for pattern, method in patterns:
        for match in re.findall(pattern, blob):
            _add(match, method, "LOW", "SMB payload field token")

    return findings


def _extract_dhcp_hostnames(
    pkt, src_ip: str, dst_ip: str
) -> list[tuple[str, str, str, str, str]]:
    results: list[tuple[str, str, str, str, str]] = []
    seen: set[str] = set()

    dhcp_layer = None
    for layer_key in (DHCP, "DHCP"):
        if layer_key is None:
            continue
        try:
            dhcp_layer = pkt.getlayer(layer_key)
            if dhcp_layer is not None:
                break
        except Exception:
            continue
    if dhcp_layer is None:
        return results

    bootp_layer = None
    for layer_key in (BOOTP, "BOOTP"):
        if layer_key is None:
            continue
        try:
            bootp_layer = pkt.getlayer(layer_key)
            if bootp_layer is not None:
                break
        except Exception:
            continue

    options = getattr(dhcp_layer, "options", None)
    if not isinstance(options, (list, tuple)):
        return results

    option_map: dict[str, object] = {}
    for option in options:
        if not isinstance(option, tuple) or len(option) < 2:
            continue
        key = str(option[0]).strip().lower()
        if key and key not in {"end", "pad"}:
            option_map[key] = option[1]

    requested_ip = _decode_name(
        option_map.get("requested_addr", option_map.get("requested-address", ""))
    )

    mapped_candidates: list[str] = []
    if bootp_layer is not None:
        mapped_candidates.extend(
            [
                str(getattr(bootp_layer, "ciaddr", "") or ""),
                str(getattr(bootp_layer, "yiaddr", "") or ""),
            ]
        )
    if requested_ip:
        mapped_candidates.append(requested_ip)
    mapped_candidates.extend([src_ip, dst_ip])

    # No usable candidate (e.g. a DISCOVER from 0.0.0.0 to broadcast) leaves
    # the finding unmapped rather than pinned to 0.0.0.0.
    mapped_ip = ""
    for candidate in mapped_candidates:
        try:
            ip_obj = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if ip_obj.is_unspecified:
            continue
        if str(ip_obj) == "255.255.255.255":
            continue
        mapped_ip = str(ip_obj)
        break

    option_meta = {
        "hostname": ("DHCP hostname option", "MEDIUM"),
        "host_name": ("DHCP hostname option", "MEDIUM"),
        "client_fqdn": ("DHCP FQDN option", "MEDIUM"),
        "fqdn": ("DHCP FQDN option", "MEDIUM"),
        "domain": ("DHCP domain option", "LOW"),
        "domain_name": ("DHCP domain option", "LOW"),
    }

    for option in options:
        if not isinstance(option, tuple) or len(option) < 2:
            continue
        key = str(option[0]).strip().lower()
        if key not in option_meta:
            continue

        method, confidence = option_meta[key]
        raw_value = option[1]
        value = _decode_name(raw_value)
        if not value:
            continue

        for token in re.split(r"[,\s]+", value):
            candidate = _normalize_hostname(token.lstrip("*.").strip())
            if not _is_valid_hostname(candidate):
                continue
            dedupe_key = f"{candidate}|{method}|{mapped_ip}"
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            results.append(
                (
                    candidate,
                    method,
                    confidence,
                    mapped_ip,
                    f"DHCP option '{key}' value observed",
                )
            )

    return results


def _extract_dhcpv6_hostnames(
    pkt, src_ip: str, dst_ip: str
) -> list[tuple[str, str, str, str, str]]:
    if DHCP6OptClientFQDN is None:
        return []

    def _pick_mapped_ip() -> str:
        for candidate in (src_ip, dst_ip):
            try:
                ip_obj = ipaddress.ip_address(candidate)
            except Exception:
                continue
            if ip_obj.is_unspecified or ip_obj.is_multicast:
                continue
            return str(ip_obj)
        return src_ip

    mapped_ip = _pick_mapped_ip()
    results: list[tuple[str, str, str, str, str]] = []
    seen: set[str] = set()

    idx = 1
    while True:
        try:
            opt = pkt.getlayer(DHCP6OptClientFQDN, nb=idx)
        except Exception:
            opt = None
        if opt is None:
            break
        idx += 1

        value = _decode_name(getattr(opt, "fqdn", ""))
        if not value:
            continue

        for token in re.split(r"[,\s]+", value):
            candidate = _normalize_hostname(token.lstrip("*.").strip())
            if not _is_valid_hostname(candidate):
                continue
            dedupe_key = f"{candidate}|{mapped_ip}"
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            results.append(
                (
                    candidate,
                    "DHCPv6 Client FQDN option (39)",
                    "MEDIUM",
                    mapped_ip,
                    "DHCPv6 client FQDN option value observed",
                )
            )

    return results


def _extract_ssdp_hostnames(payload: bytes) -> list[tuple[str, str, str, str]]:
    if not payload:
        return []
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return []
    upper = text.upper()
    if (
        "M-SEARCH" not in upper
        and "NOTIFY" not in upper
        and "HTTP/1.1 200 OK" not in upper
    ):
        return []

    findings: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()

    def _add(host: str, method: str, confidence: str, details: str) -> None:
        normalized = _normalize_hostname(host)
        if not _looks_hostname_like(normalized, require_hint=False):
            return
        key = f"{normalized}|{method}"
        if key in seen:
            return
        seen.add(key)
        findings.append((normalized, method, confidence, details))

    for line in text.splitlines()[:80]:
        line_text = line.strip()
        if not line_text:
            continue
        if not re.match(r"(?i)^(location|al)\s*:", line_text):
            continue
        url_value = line_text.split(":", 1)[1].strip().strip("<>").strip()
        if not url_value:
            continue
        try:
            parsed = urlsplit(url_value)
            host = parsed.hostname or ""
        except Exception:
            host = ""
        if host:
            _add(
                host,
                "SSDP location URL host",
                "MEDIUM",
                f"SSDP header: {line_text[:120]}",
            )

    for url_value in re.findall(r"(?i)\bhttps?://[^\s\"'<>]+", text):
        try:
            parsed = urlsplit(url_value)
            host = parsed.hostname or ""
        except Exception:
            host = ""
        if host:
            _add(
                host,
                "SSDP payload URL host",
                "LOW",
                f"SSDP payload URL: {url_value[:120]}",
            )

    return findings


def _extract_lldp_hostnames(
    eth_layer,
    payload: bytes,
    mac_to_ips: dict[str, set[str]],
) -> list[tuple[str, str, str, str, str]]:
    if eth_layer is None:
        return []

    eth_type = int(getattr(eth_layer, "type", 0) or 0)
    if eth_type != LLDP_ETHERTYPE:
        return []

    raw_payload = payload
    if not raw_payload:
        try:
            raw_payload = bytes(eth_layer.payload)
        except Exception:
            raw_payload = b""

    try:
        from .lldp_dcp import _parse_lldp_tlvs

        chassis, _port, sysname = _parse_lldp_tlvs(raw_payload)
    except Exception:
        return []

    src_mac = _normalize_mac(getattr(eth_layer, "src", ""))
    mapped_candidates = sorted(mac_to_ips.get(src_mac, set())) if src_mac else []
    mapped_ip = mapped_candidates[0] if mapped_candidates else ""

    findings: list[tuple[str, str, str, str, str]] = []
    seen: set[str] = set()

    def _add(host: str, method: str, confidence: str, detail: str) -> None:
        normalized = _normalize_hostname(host)
        if not _looks_hostname_like(normalized, require_hint=False):
            return
        key = f"{normalized}|{method}|{mapped_ip}"
        if key in seen:
            return
        seen.add(key)
        findings.append((normalized, method, confidence, mapped_ip, detail))

    if sysname:
        _add(
            str(sysname),
            "LLDP system name TLV",
            "HIGH",
            f"LLDP System Name observed from MAC {src_mac or '-'}",
        )
    if chassis:
        _add(
            str(chassis),
            "LLDP chassis ID token",
            "LOW",
            f"LLDP Chassis ID observed from MAC {src_mac or '-'}",
        )

    return findings


def _extract_cdp_hostnames(
    eth_layer,
    payload: bytes,
    mac_to_ips: dict[str, set[str]],
) -> list[tuple[str, str, str, str, str]]:
    if eth_layer is None:
        return []

    src_mac = _normalize_mac(getattr(eth_layer, "src", ""))
    dst_mac = _normalize_mac(getattr(eth_layer, "dst", ""))
    raw_payload = payload
    if not raw_payload:
        try:
            raw_payload = bytes(eth_layer.payload)
        except Exception:
            raw_payload = b""
    if len(raw_payload) < 12:
        return []

    idx = 0
    if raw_payload.startswith(CDP_SNAP_HEADER):
        idx = len(CDP_SNAP_HEADER)
    elif dst_mac != CDP_MULTICAST_MAC:
        return []

    if len(raw_payload) < idx + 4:
        return []

    # CDP header: version(1), ttl(1), checksum(2)
    version = int(raw_payload[idx])
    ttl = int(raw_payload[idx + 1])
    idx += 4

    mapped_candidates = sorted(mac_to_ips.get(src_mac, set())) if src_mac else []
    mapped_ip = mapped_candidates[0] if mapped_candidates else ""
    findings: list[tuple[str, str, str, str, str]] = []
    seen: set[str] = set()

    def _add(host: str, method: str, confidence: str, detail: str) -> None:
        normalized = _normalize_hostname(host)
        if not _looks_hostname_like(normalized, require_hint=False):
            return
        key = f"{normalized}|{method}|{mapped_ip}"
        if key in seen:
            return
        seen.add(key)
        findings.append((normalized, method, confidence, mapped_ip, detail))

    while idx + 4 <= len(raw_payload):
        tlv_type = int.from_bytes(raw_payload[idx : idx + 2], "big")
        tlv_len = int.from_bytes(raw_payload[idx + 2 : idx + 4], "big")
        if tlv_len < 4 or idx + tlv_len > len(raw_payload):
            break
        value = raw_payload[idx + 4 : idx + tlv_len]
        idx += tlv_len

        if tlv_type == 0x0001 and value:
            device_id = value.decode("latin-1", errors="ignore").strip("\x00").strip()
            if device_id:
                _add(
                    device_id,
                    "CDP device ID TLV",
                    "HIGH",
                    f"CDP v{version} ttl={ttl} device identifier observed from MAC {src_mac or '-'}",
                )

    return findings


def _extract_tls_certificate_hostnames(
    pkt, payload: bytes
) -> list[tuple[str, str, str]]:
    results: list[tuple[str, str, str]] = []
    seen: set[str] = set()

    cert_layer = None
    for layer_key in (TLSCertificate, "TLSCertificate"):
        if layer_key is None:
            continue
        try:
            cert_layer = pkt.getlayer(layer_key)
            if cert_layer is not None:
                break
        except Exception:
            continue
    if cert_layer is None:
        return results

    blobs: list[str] = []
    try:
        blobs.append(str(cert_layer))
    except Exception:
        pass
    if payload:
        try:
            blobs.append(payload.decode("latin-1", errors="ignore"))
        except Exception:
            pass
    text = "\n".join(blob for blob in blobs if blob)
    if not text:
        return results

    def _append(raw_name: str, method: str, confidence: str) -> None:
        candidate = _normalize_hostname(raw_name.lstrip("*.").strip())
        if not _is_valid_hostname(candidate):
            return
        dedupe_key = f"{candidate}|{method}"
        if dedupe_key in seen:
            return
        seen.add(dedupe_key)
        results.append((candidate, method, confidence))

    for san in re.findall(
        r"(?:DNS:|dNSName\s*=\s*)([A-Za-z0-9*._-]{1,253})", text, flags=re.IGNORECASE
    ):
        _append(san, "TLS certificate SAN", "HIGH")

    for cn in re.findall(
        r"(?:CN\s*=\s*|commonName\s*=\s*)([A-Za-z0-9*._-]{1,253})",
        text,
        flags=re.IGNORECASE,
    ):
        _append(cn, "TLS certificate subject CN", "MEDIUM")

    return results


def _extract_arp_hostnames(
    arp_layer, payload: bytes, src_ip: str, dst_ip: str
) -> list[tuple[str, str, str, str, str]]:
    results: list[tuple[str, str, str, str, str]] = []
    if arp_layer is None:
        return results

    arp_psrc = src_ip
    arp_pdst = dst_ip
    try:
        arp_psrc = str(getattr(arp_layer, "psrc", src_ip) or src_ip)
        arp_pdst = str(getattr(arp_layer, "pdst", dst_ip) or dst_ip)
    except Exception:
        pass

    mapped_candidates = [arp_psrc, src_ip, arp_pdst, dst_ip]
    mapped_ip = "0.0.0.0"
    for candidate in mapped_candidates:
        try:
            ip_obj = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if ip_obj.is_unspecified:
            continue
        if str(ip_obj) == "255.255.255.255":
            continue
        mapped_ip = str(ip_obj)
        break

    if not payload:
        return results
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return results

    seen: set[str] = set()
    for token in re.findall(r"[A-Za-z0-9*._-]{3,253}", text):
        candidate = _normalize_hostname(token.lstrip("*.").strip())
        if not _is_valid_hostname(candidate):
            continue
        key = f"{candidate}|{mapped_ip}"
        if key in seen:
            continue
        seen.add(key)
        results.append(
            (
                candidate,
                "ARP payload hostname token",
                "LOW",
                mapped_ip,
                f"ARP payload token observed psrc={arp_psrc} pdst={arp_pdst}",
            )
        )

    return results


def _extract_sni(pkt) -> Optional[str]:
    if TLSClientHello is None:
        return None
    hello = pkt.getlayer(TLSClientHello)
    if hello is None:
        return None
    try:
        exts = getattr(hello, "ext", None) or []
        for ext in exts:
            names = getattr(ext, "servernames", None) or getattr(
                ext, "server_names", None
            )
            if not names:
                continue
            for item in names:
                name = (
                    getattr(item, "servername", None)
                    or getattr(item, "name", None)
                    or item
                )
                decoded = _normalize_hostname(_decode_name(name))
                if _is_valid_hostname(decoded) and not _is_ip_literal(decoded):
                    return decoded
    except Exception:
        return None
    return None


def _parse_raw_tls_client_hello_sni(payload: bytes) -> Optional[str]:
    """Extract SNI from a raw TLS ClientHello on ANY port.

    Scapy only dissects TLS on port 443, so SNI inside RDP-on-3389 TLS,
    8443, or CONNECT-tunneled handshakes is invisible to _extract_sni().
    """
    if len(payload) < 46 or payload[0] != 0x16 or payload[1] != 0x03:
        return None
    if payload[5] != 0x01:
        return None
    try:
        idx = 9  # record header (5) + handshake type (1) + handshake len (3)
        idx += 2 + 32  # client_version + random
        if idx >= len(payload):
            return None
        idx += 1 + payload[idx]  # session id
        if idx + 2 > len(payload):
            return None
        idx += 2 + int.from_bytes(payload[idx : idx + 2], "big")  # cipher suites
        if idx + 1 > len(payload):
            return None
        idx += 1 + payload[idx]  # compression methods
        if idx + 2 > len(payload):
            return None
        ext_total = int.from_bytes(payload[idx : idx + 2], "big")
        idx += 2
        end = min(len(payload), idx + ext_total)
        while idx + 4 <= end:
            ext_type = int.from_bytes(payload[idx : idx + 2], "big")
            ext_len = int.from_bytes(payload[idx + 2 : idx + 4], "big")
            idx += 4
            if ext_type == 0 and idx + 5 <= end:
                # server_name_list: list_len(2) + type(1)=host_name + len(2)
                name_len = int.from_bytes(payload[idx + 3 : idx + 5], "big")
                name = payload[idx + 5 : idx + 5 + name_len].decode(
                    "latin-1", errors="ignore"
                )
                decoded = _normalize_hostname(name)
                if _is_valid_hostname(decoded) and not _is_ip_literal(decoded):
                    return decoded
                return None
            idx += ext_len
    except Exception:
        return None
    return None


_DER_SAN_OID = b"\x06\x03\x55\x1d\x11"  # id-ce-subjectAltName (2.5.29.17)
_DER_CN_OID = b"\x06\x03\x55\x04\x03"  # id-at-commonName (2.5.4.3)
_DER_HOST_CHARS_RE = re.compile(rb"[A-Za-z0-9*._-]+")


def _extract_der_cert_hostnames(payload: bytes) -> list[tuple[str, str, str]]:
    """Pull SAN dNSName / subject CN host values out of raw DER certificates.

    Complements the scapy TLSCertificate path, which only fires on port 443
    (and never inside CONNECT tunnels or RDP-on-3389 TLS). Searches the raw
    bytes for the SAN/CN OIDs, so it also works when the certificate record
    starts mid-stream.
    """
    if not payload:
        return []
    has_san = _DER_SAN_OID in payload
    has_cn = _DER_CN_OID in payload
    if not has_san and not has_cn:
        return []

    results: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _emit(raw: bytes, method: str, confidence: str, require_dot: bool) -> None:
        try:
            text = raw.decode("ascii")
        except Exception:
            return
        candidate = _normalize_hostname(text.lstrip("*.").strip())
        if not _is_valid_hostname(candidate) or _is_ip_literal(candidate):
            return
        if require_dot and "." not in candidate:
            return
        # Dotless CNs (issuer shorthands like "R3") are too noisy below 4 chars.
        if "." not in candidate and len(candidate) < 4:
            return
        key = (candidate, method)
        if key in seen:
            return
        seen.add(key)
        results.append((candidate, method, confidence))

    if has_san:
        idx = 0
        while len(results) < 24:
            pos = payload.find(_DER_SAN_OID, idx)
            if pos == -1:
                break
            window = payload[pos + 5 : pos + 5 + 512]
            j = 0
            while j + 2 <= len(window):
                # GeneralName dNSName = context tag [2] + short length + IA5
                if window[j] == 0x82:
                    length = window[j + 1]
                    if 1 <= length <= 64 and j + 2 + length <= len(window):
                        chunk = window[j + 2 : j + 2 + length]
                        if _DER_HOST_CHARS_RE.fullmatch(chunk) and b"." in chunk:
                            _emit(chunk, "TLS certificate SAN", "HIGH", True)
                            j += 2 + length
                            continue
                j += 1
            idx = pos + 5

    if has_cn:
        idx = 0
        while len(results) < 32:
            pos = payload.find(_DER_CN_OID, idx)
            if pos == -1:
                break
            tag_pos = pos + 5
            if tag_pos + 2 <= len(payload) and payload[tag_pos] in (0x0C, 0x13, 0x16):
                length = payload[tag_pos + 1]
                if 1 <= length <= 64 and tag_pos + 2 + length <= len(payload):
                    chunk = payload[tag_pos + 2 : tag_pos + 2 + length]
                    if _DER_HOST_CHARS_RE.fullmatch(chunk):
                        _emit(chunk, "TLS certificate subject CN", "MEDIUM", False)
            idx = pos + 5

    return results


def _parse_ntlm_type2_targets(payload: bytes) -> list[tuple[str, str, str]]:
    """Extract server self-identification from an NTLM CHALLENGE (Type 2).

    The TargetInfo AV pairs name the SERVER (NetBIOS/DNS computer name) —
    the counterpart to the Type 3 workstation field, which names the client.
    """
    signature = b"NTLMSSP\x00"
    idx = payload.find(signature)
    if idx == -1 or len(payload) < idx + 48:
        return []
    try:
        if int.from_bytes(payload[idx + 8 : idx + 12], "little") != 2:
            return []
        ti_len = int.from_bytes(payload[idx + 40 : idx + 42], "little")
        ti_off = int.from_bytes(payload[idx + 44 : idx + 48], "little")
        data = payload[idx + ti_off : idx + ti_off + ti_len]
    except Exception:
        return []

    av_labels = {
        1: ("NTLM challenge NetBIOS computer name", "MEDIUM"),
        3: ("NTLM challenge DNS computer name", "HIGH"),
    }
    results: list[tuple[str, str, str]] = []
    seen: set[tuple[str, int]] = set()
    j = 0
    while j + 4 <= len(data):
        av_id = int.from_bytes(data[j : j + 2], "little")
        av_len = int.from_bytes(data[j + 2 : j + 4], "little")
        if av_id == 0:
            break
        if av_id in av_labels and av_len and j + 4 + av_len <= len(data):
            try:
                value = (
                    data[j + 4 : j + 4 + av_len]
                    .decode("utf-16le", errors="ignore")
                    .strip()
                )
            except Exception:
                value = ""
            normalized = _normalize_hostname(value)
            key = (normalized, av_id)
            if normalized and _is_valid_hostname(normalized) and key not in seen:
                seen.add(key)
                method, confidence = av_labels[av_id]
                results.append((normalized, method, confidence))
        j += 4 + av_len
    return results


def _parse_ntlm_type3(
    payload: bytes,
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    signature = b"NTLMSSP\x00"
    idx = payload.find(signature)
    if idx == -1 or len(payload) < idx + 56:
        return None, None, None
    try:
        msg_type = int.from_bytes(payload[idx + 8 : idx + 12], "little")
        if msg_type != 3:
            return None, None, None

        def _read(offset: int) -> tuple[int, int]:
            length = int.from_bytes(payload[offset : offset + 2], "little")
            field_offset = int.from_bytes(payload[offset + 4 : offset + 8], "little")
            return length, field_offset

        domain_len, domain_off = _read(idx + 28)
        user_len, user_off = _read(idx + 36)
        workstation_len, workstation_off = _read(idx + 44)

        domain = (
            payload[idx + domain_off : idx + domain_off + domain_len].decode(
                "utf-16le", errors="ignore"
            )
            if domain_len
            else None
        )
        user = (
            payload[idx + user_off : idx + user_off + user_len].decode(
                "utf-16le", errors="ignore"
            )
            if user_len
            else None
        )
        workstation = (
            payload[
                idx + workstation_off : idx + workstation_off + workstation_len
            ].decode("utf-16le", errors="ignore")
            if workstation_len
            else None
        )
        return user or None, domain or None, workstation or None
    except Exception:
        return None, None, None


def _record_finding(
    findings_map: dict[tuple[str, str, str, str, str, str, str], HostnameFinding],
    *,
    hostname: str,
    mapped_ip: str,
    protocol: str,
    method: str,
    confidence: str,
    details: str,
    src_ip: str,
    dst_ip: str,
    ts: Optional[float],
    packet_index: Optional[int],
) -> bool:
    normalized = _normalize_hostname(hostname)
    if not _is_valid_hostname(normalized):
        return False

    key = (normalized, mapped_ip, protocol, method, src_ip, dst_ip, details)
    existing = findings_map.get(key)
    if existing is None:
        findings_map[key] = HostnameFinding(
            hostname=normalized,
            mapped_ip=mapped_ip,
            protocol=protocol,
            method=method,
            confidence=confidence,
            details=details,
            src_ip=src_ip,
            dst_ip=dst_ip,
            first_seen=ts,
            last_seen=ts,
            first_packet=packet_index,
            last_packet=packet_index,
            count=1,
        )
        return True

    existing.count += 1
    if ts is not None:
        if existing.first_seen is None or ts < existing.first_seen:
            existing.first_seen = ts
        if existing.last_seen is None or ts > existing.last_seen:
            existing.last_seen = ts
    if packet_index is not None:
        if existing.first_packet is None or packet_index < existing.first_packet:
            existing.first_packet = packet_index
        if existing.last_packet is None or packet_index > existing.last_packet:
            existing.last_packet = packet_index
    return True


def _matches_target_mapping(
    mapped_ip: str,
    target_ip: str | None,
    target_filter_enabled: bool,
    allow_related: bool = False,
    packet_relevant: bool = False,
) -> bool:
    if not target_filter_enabled:
        return True
    if not target_ip:
        return False
    if mapped_ip == target_ip:
        return True
    if allow_related and packet_relevant and mapped_ip:
        return True
    return False


def _hostname_matches_query(hostname: str, query: str | None) -> bool:
    query_text = str(query or "").strip().lower()
    if not query_text:
        return True
    return query_text in str(hostname or "").strip().lower()


def _finding_matches_search(finding: HostnameFinding, query: str | None) -> bool:
    token = str(query or "").strip().lower()
    if not token:
        return True
    haystack = " ".join(
        [
            str(finding.hostname or ""),
            str(finding.mapped_ip or ""),
            str(finding.protocol or ""),
            str(finding.method or ""),
            str(finding.details or ""),
            str(finding.src_ip or ""),
            str(finding.dst_ip or ""),
        ]
    ).lower()
    return token in haystack


def merge_hostname_summaries(summaries: list[HostnameSummary]) -> HostnameSummary:
    if not summaries:
        return HostnameSummary(path=Path("ALL_PCAPS_0"), target_ip=None)

    merged = HostnameSummary(
        path=Path(f"ALL_PCAPS_{len(summaries)}"),
        target_ip=summaries[0].target_ip,
        hostname_query=getattr(summaries[0], "hostname_query", None),
        port_filter=getattr(summaries[0], "port_filter", None),
        search_query=getattr(summaries[0], "search_query", None),
    )
    merged_map: dict[tuple[str, str, str, str, str, str, str], HostnameFinding] = {}
    merged_ip_to_macs: dict[str, set[str]] = defaultdict(set)
    seen_errors: set[str] = set()

    for summary in summaries:
        merged.total_packets += summary.total_packets
        merged.relevant_packets += summary.relevant_packets
        merged.protocol_counts.update(summary.protocol_counts)
        merged.method_counts.update(summary.method_counts)
        for ip_value, macs in (summary.ip_to_macs or {}).items():
            if not macs:
                continue
            merged_ip_to_macs[str(ip_value)].update(
                str(mac).lower() for mac in macs if str(mac).strip()
            )

        for finding in summary.findings:
            key = (
                finding.hostname,
                finding.mapped_ip,
                finding.protocol,
                finding.method,
                finding.src_ip,
                finding.dst_ip,
                finding.details,
            )
            existing = merged_map.get(key)
            if existing is None:
                merged_map[key] = HostnameFinding(
                    hostname=finding.hostname,
                    mapped_ip=finding.mapped_ip,
                    protocol=finding.protocol,
                    method=finding.method,
                    confidence=finding.confidence,
                    details=finding.details,
                    src_ip=finding.src_ip,
                    dst_ip=finding.dst_ip,
                    first_seen=finding.first_seen,
                    last_seen=finding.last_seen,
                    first_packet=finding.first_packet,
                    last_packet=finding.last_packet,
                    count=finding.count,
                )
            else:
                existing.count += finding.count
                if finding.first_seen is not None and (
                    existing.first_seen is None
                    or finding.first_seen < existing.first_seen
                ):
                    existing.first_seen = finding.first_seen
                if finding.last_seen is not None and (
                    existing.last_seen is None or finding.last_seen > existing.last_seen
                ):
                    existing.last_seen = finding.last_seen
                if finding.first_packet is not None and (
                    existing.first_packet is None
                    or finding.first_packet < existing.first_packet
                ):
                    existing.first_packet = finding.first_packet
                if finding.last_packet is not None and (
                    existing.last_packet is None
                    or finding.last_packet > existing.last_packet
                ):
                    existing.last_packet = finding.last_packet

        for err in summary.errors:
            if err in seen_errors:
                continue
            seen_errors.add(err)
            merged.errors.append(err)

    merged.findings = sorted(
        merged_map.values(),
        key=lambda item: (-item.count, item.hostname, item.method),
    )
    merged.ip_to_macs = {
        ip_value: sorted(macs) for ip_value, macs in merged_ip_to_macs.items() if macs
    }
    merged_context = _build_hostname_enrichment(merged.findings)
    merged.analyst_verdict = str(merged_context.get("analyst_verdict", ""))
    merged.analyst_confidence = str(merged_context.get("analyst_confidence", "low"))
    merged.analyst_reasons = [
        str(v) for v in list(merged_context.get("analyst_reasons", []) or [])
    ]
    merged.conflict_profiles = list(merged_context.get("conflict_profiles", []) or [])
    merged.drift_profiles = list(merged_context.get("drift_profiles", []) or [])
    merged.suspicious_name_profiles = list(
        merged_context.get("suspicious_name_profiles", []) or []
    )
    merged.cross_protocol_corroboration = list(
        merged_context.get("cross_protocol_corroboration", []) or []
    )
    merged.false_positive_context = [
        str(v) for v in list(merged_context.get("false_positive_context", []) or [])
    ]
    return merged


@memoize_analysis
def analyze_hostname(
    path: Path,
    target_ip: str | None,
    show_status: bool = True,
    include_related: bool = False,
    hostname_query: str | None = None,
    port_filter: int | None = None,
    search_query: str | None = None,
    apply_filters: bool = True,
) -> HostnameSummary:
    query_text = str(hostname_query or "").strip()
    search_text = str(search_query or "").strip()
    summary = HostnameSummary(
        path=path,
        target_ip=target_ip,
        hostname_query=query_text or None,
        port_filter=port_filter,
        search_query=search_text or None,
    )
    target_filter_enabled = bool(target_ip) and apply_filters
    port_filter_enabled = (
        bool(apply_filters)
        and isinstance(port_filter, int)
        and port_filter > 0
    )
    if target_filter_enabled:
        try:
            ipaddress.ip_address(target_ip)
        except ValueError:
            summary.errors.append(f"Invalid target IP: {target_ip}")
            return summary

    findings_map: dict[tuple[str, str, str, str, str, str, str], HostnameFinding] = {}
    ip_to_macs: dict[str, set[str]] = defaultdict(set)
    mac_to_ips: dict[str, set[str]] = defaultdict(set)
    # Flows where a CONNECT request was seen: everything after it on that
    # flow is tunneled THROUGH a proxy, so hostnames observed inside (SNI,
    # certificates) must not be mapped to the proxy's IP. Both orientations
    # are stored so server->client tunnel bytes are recognized too.
    proxy_flows: set[tuple[str, int, str, int]] = set()
    reverse_ptr = (
        _target_reverse_ptr(target_ip).lower() if target_filter_enabled else ""
    )

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path, show_status=show_status
        )
    except Exception as exc:
        summary.errors.append(f"Error opening pcap: {exc}")
        return summary

    try:
        for pkt in reader:
            summary.total_packets += 1
            packet_index = summary.total_packets
            if stream is not None and size_bytes:
                try:
                    status.update(int(min(100, (stream.tell() / size_bytes) * 100)))
                except Exception:
                    pass

            ts = safe_float(getattr(pkt, "time", None))
            # Dissect each commonly needed layer once per packet and share
            # the result; every getlayer()/haslayer() call walks the chain.
            ether_layer = pkt.getlayer(Ether) if Ether is not None else None
            ip_layer = pkt.getlayer(IP) if IP is not None else None
            ipv6_layer = (
                pkt.getlayer(IPv6) if (ip_layer is None and IPv6 is not None) else None
            )
            arp_layer = pkt.getlayer(ARP) if ARP is not None else None
            tcp_layer = pkt.getlayer(TCP) if TCP is not None else None
            udp_layer = pkt.getlayer(UDP) if UDP is not None else None
            raw_layer = pkt.getlayer(Raw) if Raw is not None else None
            src_ip, dst_ip = _extract_ip_pair(ip_layer, ipv6_layer, arp_layer)
            sport, dport = _extract_ports(tcp_layer, udp_layer)
            if ether_layer is not None:
                try:
                    src_mac = getattr(ether_layer, "src", "")
                    dst_mac = getattr(ether_layer, "dst", "")
                    _remember_ip_mac(ip_to_macs, src_ip, src_mac)
                    _remember_ip_mac(ip_to_macs, dst_ip, dst_mac)
                    _remember_mac_ip(mac_to_ips, src_mac, src_ip)
                    _remember_mac_ip(mac_to_ips, dst_mac, dst_ip)
                except Exception:
                    pass
            if arp_layer is not None:
                try:
                    psrc = str(getattr(arp_layer, "psrc", "") or "")
                    pdst = str(getattr(arp_layer, "pdst", "") or "")
                    hwsrc = getattr(arp_layer, "hwsrc", "")
                    hwdst = getattr(arp_layer, "hwdst", "")
                    _remember_ip_mac(ip_to_macs, psrc, hwsrc)
                    _remember_ip_mac(ip_to_macs, pdst, hwdst)
                    _remember_mac_ip(mac_to_ips, hwsrc, psrc)
                    _remember_mac_ip(mac_to_ips, hwdst, pdst)
                except Exception:
                    pass

            flow_relevant = target_filter_enabled and (
                src_ip == target_ip or dst_ip == target_ip
            )
            if port_filter_enabled and sport != port_filter and dport != port_filter:
                continue
            packet_relevant = flow_relevant
            found_evidence = False

            def _match(mapped_ip: str) -> bool:
                return _matches_target_mapping(
                    mapped_ip,
                    target_ip,
                    target_filter_enabled,
                    allow_related=include_related,
                    packet_relevant=flow_relevant,
                )

            # DHCP/DHCPv6 layers only ever dissect under UDP, so skip the
            # helpers entirely (and their layer-chain walks) otherwise.
            dhcp_results = (
                _extract_dhcp_hostnames(pkt, src_ip, dst_ip)
                if udp_layer is not None
                else []
            )
            for (
                host_value,
                method,
                confidence,
                mapped_ip,
                details,
            ) in dhcp_results:
                if _match(mapped_ip) and _record_finding(
                    findings_map,
                    hostname=host_value,
                    mapped_ip=mapped_ip,
                    protocol="DHCP",
                    method=method,
                    confidence=confidence,
                    details=details,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    ts=ts,
                    packet_index=packet_index,
                ):
                    found_evidence = True
                    packet_relevant = True
                    summary.protocol_counts["DHCP"] += 1
                    summary.method_counts[method] += 1

            dhcpv6_results = (
                _extract_dhcpv6_hostnames(pkt, src_ip, dst_ip)
                if udp_layer is not None
                else []
            )
            for (
                host_value,
                method,
                confidence,
                mapped_ip,
                details,
            ) in dhcpv6_results:
                if _match(mapped_ip) and _record_finding(
                    findings_map,
                    hostname=host_value,
                    mapped_ip=mapped_ip,
                    protocol="DHCPv6",
                    method=method,
                    confidence=confidence,
                    details=details,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    ts=ts,
                    packet_index=packet_index,
                ):
                    found_evidence = True
                    packet_relevant = True
                    summary.protocol_counts["DHCPv6"] += 1
                    summary.method_counts[method] += 1

            # DNS only ever dissects under UDP/TCP, so skip the chain walk
            # for other packets.
            if DNS is not None and (udp_layer is not None or tcp_layer is not None):
                try:
                    dns_layer = pkt.getlayer(DNS)
                except Exception:
                    dns_layer = None
                if dns_layer is not None:
                    port_pair = {sport, dport}
                    if 5353 in port_pair:
                        dns_protocol = "mDNS"
                    elif 5355 in port_pair:
                        dns_protocol = "LLMNR"
                    else:
                        dns_protocol = "DNS"

                    qd = _safe_dns_attr(dns_layer, "qd", None)
                    qname = ""
                    qtype = 0
                    if qd is not None:
                        qname = _decode_name(_safe_dns_attr(qd, "qname", "")).lower()
                        qtype = int(_safe_dns_attr(qd, "qtype", 0) or 0)
                        if reverse_ptr and reverse_ptr in qname and qtype == 12:
                            packet_relevant = True

                    is_response = int(_safe_dns_attr(dns_layer, "qr", 0) or 0) == 1
                    # A query name describes the host being LOOKED UP, not the
                    # querier — attributing it to src_ip would mislabel a client
                    # as the name it asked about (e.g. a host querying mDNS/LLMNR
                    # for "printer.local" is not itself printer.local). The
                    # legitimate self-identifying case (mDNS/LLMNR announcements)
                    # is captured from the *responses* below, where the answer
                    # record maps the name to the responder's own address.
                    #
                    # Query names are still hostname evidence, though — vital in
                    # one-directional captures that contain no responses at all —
                    # so record A/AAAA query names WITHOUT an IP mapping.
                    if not is_response and qname and qtype in {1, 28}:
                        query_host = _normalize_hostname(qname)
                        first_label = query_host.split(".", 1)[0]
                        if (
                            _is_valid_hostname(query_host)
                            and not query_host.endswith(".arpa")
                            and not first_label.startswith("_")
                            and not _is_ip_literal(query_host)
                        ):
                            method = f"{dns_protocol} query name (unresolved)"
                            if (
                                not target_filter_enabled or flow_relevant
                            ) and _record_finding(
                                findings_map,
                                hostname=query_host,
                                mapped_ip="",
                                protocol=dns_protocol,
                                method=method,
                                confidence="LOW",
                                details=(
                                    f"{dns_protocol} A/AAAA query observed; no answer "
                                    "in capture, so no IP mapping (name describes the "
                                    "lookup target, not the querier)"
                                ),
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                ts=ts,
                                packet_index=packet_index,
                            ):
                                found_evidence = True
                                summary.protocol_counts[dns_protocol] += 1
                                summary.method_counts[method] += 1

                    if is_response:
                        for rr, _section in _iter_dns_rrs(dns_layer):
                            rr_name = _decode_name(getattr(rr, "rrname", ""))
                            rr_type = int(getattr(rr, "type", 0) or 0)
                            rr_data = getattr(rr, "rdata", None)
                            rr_data_text = _decode_name(rr_data)

                            if rr_type in {1, 28} and (
                                not target_filter_enabled or rr_data_text == target_ip
                            ):
                                packet_relevant = True
                                method = "DNS A/AAAA mapping"
                                protocol = dns_protocol
                                if _match(rr_data_text) and _record_finding(
                                    findings_map,
                                    hostname=rr_name,
                                    mapped_ip=rr_data_text,
                                    protocol=protocol,
                                    method=method,
                                    confidence="HIGH",
                                    details=f"{rr_name} resolved to {rr_data_text}",
                                    src_ip=src_ip,
                                    dst_ip=dst_ip,
                                    ts=ts,
                                    packet_index=packet_index,
                                ):
                                    found_evidence = True
                                    summary.protocol_counts[protocol] += 1
                                    summary.method_counts[method] += 1

                            ptr_ip = _ptr_name_to_ip(rr_name)
                            if rr_type == 12 and (
                                (
                                    target_filter_enabled
                                    and reverse_ptr
                                    and reverse_ptr in rr_name.lower()
                                )
                                or (not target_filter_enabled and bool(ptr_ip))
                            ):
                                packet_relevant = True
                                method = "DNS PTR reverse lookup"
                                protocol = (
                                    dns_protocol
                                    if dns_protocol in {"mDNS", "LLMNR"}
                                    else "DNS"
                                )
                                mapped_ip = (
                                    target_ip if target_filter_enabled else ptr_ip
                                )
                                if _match(str(mapped_ip)) and _record_finding(
                                    findings_map,
                                    hostname=rr_data_text,
                                    mapped_ip=str(mapped_ip),
                                    protocol=protocol,
                                    method=method,
                                    confidence="HIGH",
                                    details=f"PTR {rr_name} -> {rr_data_text}",
                                    src_ip=src_ip,
                                    dst_ip=dst_ip,
                                    ts=ts,
                                    packet_index=packet_index,
                                ):
                                    found_evidence = True
                                    summary.protocol_counts[protocol] += 1
                                    summary.method_counts[method] += 1

                            if rr_type == 33 and dns_protocol in {"mDNS", "LLMNR"}:
                                srv_target = _decode_name(
                                    getattr(rr_data, "target", rr_data_text)
                                )
                                srv_host = _normalize_hostname(srv_target)
                                if _looks_hostname_like(srv_host, require_hint=False):
                                    method = f"{dns_protocol} SRV target"
                                    mapped_ip = src_ip
                                    if _match(mapped_ip) and _record_finding(
                                        findings_map,
                                        hostname=srv_host,
                                        mapped_ip=mapped_ip,
                                        protocol=dns_protocol,
                                        method=method,
                                        confidence="MEDIUM",
                                        details=f"{dns_protocol} SRV target {srv_host} from {src_ip}",
                                        src_ip=src_ip,
                                        dst_ip=dst_ip,
                                        ts=ts,
                                        packet_index=packet_index,
                                    ):
                                        found_evidence = True
                                        summary.protocol_counts[dns_protocol] += 1
                                        summary.method_counts[method] += 1

                            if rr_type in {5, 2} and dns_protocol in {"mDNS", "LLMNR"}:
                                alias_host = _normalize_hostname(rr_data_text)
                                if _looks_hostname_like(alias_host, require_hint=False):
                                    method = f"{dns_protocol} alias record"
                                    mapped_ip = src_ip
                                    if _match(mapped_ip) and _record_finding(
                                        findings_map,
                                        hostname=alias_host,
                                        mapped_ip=mapped_ip,
                                        protocol=dns_protocol,
                                        method=method,
                                        confidence="LOW",
                                        details=f"{dns_protocol} alias {rr_name} -> {alias_host}",
                                        src_ip=src_ip,
                                        dst_ip=dst_ip,
                                        ts=ts,
                                        packet_index=packet_index,
                                    ):
                                        found_evidence = True
                                        summary.protocol_counts[dns_protocol] += 1
                                        summary.method_counts[method] += 1

            payload = _extract_payload(raw_layer, tcp_layer, udp_layer)
            for (
                host_value,
                method,
                confidence,
                mapped_ip,
                details,
            ) in _extract_lldp_hostnames(ether_layer, payload, mac_to_ips):
                if _match(mapped_ip) and _record_finding(
                    findings_map,
                    hostname=host_value,
                    mapped_ip=mapped_ip,
                    protocol="LLDP",
                    method=method,
                    confidence=confidence,
                    details=details,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    ts=ts,
                    packet_index=packet_index,
                ):
                    found_evidence = True
                    packet_relevant = True
                    summary.protocol_counts["LLDP"] += 1
                    summary.method_counts[method] += 1

            for (
                host_value,
                method,
                confidence,
                mapped_ip,
                details,
            ) in _extract_cdp_hostnames(ether_layer, payload, mac_to_ips):
                if _match(mapped_ip) and _record_finding(
                    findings_map,
                    hostname=host_value,
                    mapped_ip=mapped_ip,
                    protocol="CDP",
                    method=method,
                    confidence=confidence,
                    details=details,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    ts=ts,
                    packet_index=packet_index,
                ):
                    found_evidence = True
                    packet_relevant = True
                    summary.protocol_counts["CDP"] += 1
                    summary.method_counts[method] += 1

            for (
                host_value,
                method,
                confidence,
                mapped_ip,
                details,
            ) in _extract_arp_hostnames(arp_layer, payload, src_ip, dst_ip):
                if _match(mapped_ip) and _record_finding(
                    findings_map,
                    hostname=host_value,
                    mapped_ip=mapped_ip,
                    protocol="ARP",
                    method=method,
                    confidence=confidence,
                    details=details,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    ts=ts,
                    packet_index=packet_index,
                ):
                    found_evidence = True
                    packet_relevant = True
                    summary.protocol_counts["ARP"] += 1
                    summary.method_counts[method] += 1

            if payload and (packet_relevant or not target_filter_enabled):
                http_request = _parse_http_request(payload)
                if http_request:
                    form = http_request["form"]
                    authority_host = http_request["authority_host"]
                    host_header = http_request["host_header"]
                    if form == "connect":
                        proxy_flows.add((src_ip, sport or 0, dst_ip, dport or 0))
                        proxy_flows.add((dst_ip, dport or 0, src_ip, sport or 0))

                    if form == "origin":
                        # Origin-form request: dst IS the named server.
                        if host_header:
                            method = "HTTP Host header"
                            protocol = "HTTP"
                            if _match(dst_ip) and _record_finding(
                                findings_map,
                                hostname=host_header,
                                mapped_ip=dst_ip,
                                protocol=protocol,
                                method=method,
                                confidence="MEDIUM",
                                details=f"Host header observed for destination {dst_ip}",
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                ts=ts,
                                packet_index=packet_index,
                            ):
                                found_evidence = True
                                summary.protocol_counts[protocol] += 1
                                summary.method_counts[method] += 1
                    else:
                        # CONNECT / absolute-URI request: dst is a forward
                        # PROXY; the authority names a remote origin whose
                        # IP is not present in this packet, so no IP mapping.
                        protocol = "HTTP"
                        if authority_host:
                            method = (
                                "HTTP CONNECT tunnel target"
                                if form == "connect"
                                else "HTTP absolute-URI authority"
                            )
                            if (not target_filter_enabled or flow_relevant) and _record_finding(
                                findings_map,
                                hostname=authority_host,
                                mapped_ip="",
                                protocol=protocol,
                                method=method,
                                confidence="MEDIUM",
                                details=(
                                    f"Proxy-form request via proxy {dst_ip}:{dport}; "
                                    "target IP not visible in this packet"
                                ),
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                ts=ts,
                                packet_index=packet_index,
                            ):
                                found_evidence = True
                                summary.protocol_counts[protocol] += 1
                                summary.method_counts[method] += 1
                        if host_header and host_header != authority_host:
                            # Host header disagreeing with the authority on a
                            # proxy-form request is itself noteworthy.
                            method = "HTTP Host header (proxy request mismatch)"
                            if (not target_filter_enabled or flow_relevant) and _record_finding(
                                findings_map,
                                hostname=host_header,
                                mapped_ip="",
                                protocol=protocol,
                                method=method,
                                confidence="LOW",
                                details=(
                                    f"Host header differs from request authority "
                                    f"{authority_host or '-'} on proxy-form request via {dst_ip}"
                                ),
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                ts=ts,
                                packet_index=packet_index,
                            ):
                                found_evidence = True
                                summary.protocol_counts[protocol] += 1
                                summary.method_counts[method] += 1

                http2_authority = _parse_http2_authority_host(payload)
                if http2_authority:
                    method = "HTTP/2 :authority pseudo-header"
                    protocol = "HTTP/2"
                    if _match(dst_ip) and _record_finding(
                        findings_map,
                        hostname=http2_authority,
                        mapped_ip=dst_ip,
                        protocol=protocol,
                        method=method,
                        confidence="MEDIUM",
                        details=f"HTTP/2 authority references destination {dst_ip}",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        ts=ts,
                        packet_index=packet_index,
                    ):
                        found_evidence = True
                        summary.protocol_counts[protocol] += 1
                        summary.method_counts[method] += 1

                if b"NTLMSSP\x00" in payload:
                    user, domain, workstation = _parse_ntlm_type3(payload)
                    if workstation:
                        # Type 3 AUTHENTICATE is sent BY the client, naming itself.
                        method = "NTLM workstation field"
                        protocol = "SMB/NTLM"
                        detail = (
                            f"NTLM auth context user={user or '-'} domain={domain or '-'}"
                        )
                        if _match(src_ip) and _record_finding(
                            findings_map,
                            hostname=workstation,
                            mapped_ip=src_ip,
                            protocol=protocol,
                            method=method,
                            confidence="LOW",
                            details=detail,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            ts=ts,
                            packet_index=packet_index,
                        ):
                            found_evidence = True
                            summary.protocol_counts[protocol] += 1
                            summary.method_counts[method] += 1

                    # Type 2 CHALLENGE is sent BY the server; its TargetInfo
                    # AV pairs carry the server's own NetBIOS/DNS computer name.
                    for (
                        host_value,
                        method,
                        confidence,
                    ) in _parse_ntlm_type2_targets(payload):
                        protocol = "SMB/NTLM"
                        if _match(src_ip) and _record_finding(
                            findings_map,
                            hostname=host_value,
                            mapped_ip=src_ip,
                            protocol=protocol,
                            method=method,
                            confidence=confidence,
                            details=(
                                f"NTLM challenge TargetInfo sent by {src_ip} "
                                f"on ports {sport}->{dport}"
                            ),
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            ts=ts,
                            packet_index=packet_index,
                        ):
                            found_evidence = True
                            summary.protocol_counts[protocol] += 1
                            summary.method_counts[method] += 1

                if (sport in MAIL_SERVER_PORTS) or (dport in MAIL_SERVER_PORTS):
                    for host_value, method, confidence in _extract_mail_hostnames(
                        payload
                    ):
                        mapped_ip = src_ip
                        if method == "SMTP HELO/EHLO":
                            # HELO/EHLO is sent by the CLIENT naming itself;
                            # the client is the side NOT on the mail port.
                            mapped_ip = src_ip if dport in MAIL_SERVER_PORTS else dst_ip
                        elif method in {
                            "SMTP server banner",
                            "IMAP server banner",
                            "POP server banner",
                        }:
                            mapped_ip = src_ip if sport in MAIL_SERVER_PORTS else dst_ip

                        if _match(mapped_ip) and _record_finding(
                            findings_map,
                            hostname=host_value,
                            mapped_ip=mapped_ip,
                            protocol="SMTP/IMAP/POP",
                            method=method,
                            confidence=confidence,
                            details=f"Application banner/command observed on ports {sport}->{dport}",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            ts=ts,
                            packet_index=packet_index,
                        ):
                            found_evidence = True
                            summary.protocol_counts["SMTP/IMAP/POP"] += 1
                            summary.method_counts[method] += 1

                if (sport in SSDP_PORTS) or (dport in SSDP_PORTS):
                    mapped_ip = src_ip if sport in SSDP_PORTS else dst_ip
                    for (
                        host_value,
                        method,
                        confidence,
                        detail,
                    ) in _extract_ssdp_hostnames(payload):
                        if _match(mapped_ip) and _record_finding(
                            findings_map,
                            hostname=host_value,
                            mapped_ip=mapped_ip,
                            protocol="SSDP/UPnP",
                            method=method,
                            confidence=confidence,
                            details=f"{detail} on ports {sport}->{dport}",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            ts=ts,
                            packet_index=packet_index,
                        ):
                            found_evidence = True
                            summary.protocol_counts["SSDP/UPnP"] += 1
                            summary.method_counts[method] += 1

                if (sport in FTP_PORTS) or (dport in FTP_PORTS):
                    ftp_mapped_ip = src_ip if sport in FTP_PORTS else dst_ip
                    for (
                        host_value,
                        method,
                        confidence,
                        detail,
                    ) in _extract_ftp_hostnames(payload):
                        if _match(ftp_mapped_ip) and _record_finding(
                            findings_map,
                            hostname=host_value,
                            mapped_ip=ftp_mapped_ip,
                            protocol="FTP",
                            method=method,
                            confidence=confidence,
                            details=f"{detail} on ports {sport}->{dport}",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            ts=ts,
                            packet_index=packet_index,
                        ):
                            found_evidence = True
                            summary.protocol_counts["FTP"] += 1
                            summary.method_counts[method] += 1

                if (sport in SSH_PORTS) or (dport in SSH_PORTS):
                    # Both peers send an identification string; it names
                    # its SENDER, not whichever side sits on port 22.
                    ssh_mapped_ip = src_ip
                    for (
                        host_value,
                        method,
                        confidence,
                        detail,
                    ) in _extract_ssh_hostnames(payload):
                        if _match(ssh_mapped_ip) and _record_finding(
                            findings_map,
                            hostname=host_value,
                            mapped_ip=ssh_mapped_ip,
                            protocol="SSH",
                            method=method,
                            confidence=confidence,
                            details=f"{detail} on ports {sport}->{dport}",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            ts=ts,
                            packet_index=packet_index,
                        ):
                            found_evidence = True
                            summary.protocol_counts["SSH"] += 1
                            summary.method_counts[method] += 1

                if (sport in SNMP_PORTS) or (dport in SNMP_PORTS):
                    for (
                        host_value,
                        method,
                        confidence,
                        mapped_ip,
                        details,
                    ) in _extract_snmp_hostnames(
                        payload,
                        sport,
                        dport,
                        src_ip,
                        dst_ip,
                    ):
                        if _match(mapped_ip) and _record_finding(
                            findings_map,
                            hostname=host_value,
                            mapped_ip=mapped_ip,
                            protocol="SNMP",
                            method=method,
                            confidence=confidence,
                            details=details,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            ts=ts,
                            packet_index=packet_index,
                        ):
                            found_evidence = True
                            summary.protocol_counts["SNMP"] += 1
                            summary.method_counts[method] += 1

                if (
                    (sport in LDAP_PORTS)
                    or (dport in LDAP_PORTS)
                    or (sport in KERBEROS_PORTS)
                    or (dport in KERBEROS_PORTS)
                ):
                    server_ip = (
                        src_ip
                        if ((sport in LDAP_PORTS) or (sport in KERBEROS_PORTS))
                        else dst_ip
                    )
                    protocol = "LDAP/Kerberos"
                    for (
                        host_value,
                        method,
                        confidence,
                        detail,
                    ) in _extract_directory_auth_hostnames(payload):
                        # An SPN host component or a dNSHostName attribute
                        # names a directory OBJECT (often a third host), not
                        # the KDC/LDAP server on this flow — leave unmapped
                        # rather than pin it to the wrong IP.
                        if (
                            not target_filter_enabled or flow_relevant
                        ) and _record_finding(
                            findings_map,
                            hostname=host_value,
                            mapped_ip="",
                            protocol=protocol,
                            method=method,
                            confidence=confidence,
                            details=(
                                f"{detail} on ports {sport}->{dport} "
                                f"(directory server {server_ip}; named host may be a third party)"
                            ),
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            ts=ts,
                            packet_index=packet_index,
                        ):
                            found_evidence = True
                            summary.protocol_counts[protocol] += 1
                            summary.method_counts[method] += 1

                if (sport in SIP_PORTS) or (dport in SIP_PORTS):
                    mapped_ip = src_ip
                    for (
                        host_value,
                        method,
                        confidence,
                        detail,
                    ) in _extract_sip_hostnames(payload):
                        if _match(mapped_ip) and _record_finding(
                            findings_map,
                            hostname=host_value,
                            mapped_ip=mapped_ip,
                            protocol="SIP",
                            method=method,
                            confidence=confidence,
                            details=f"{detail} on ports {sport}->{dport}",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            ts=ts,
                            packet_index=packet_index,
                        ):
                            found_evidence = True
                            summary.protocol_counts["SIP"] += 1
                            summary.method_counts[method] += 1

                if (sport in RDP_PORTS) or (dport in RDP_PORTS):
                    # The mstshash cookie is only ever sent client->server in
                    # the X.224 Connection Request, so attribute it to the
                    # side that is NOT on the RDP service port.
                    mapped_ip = src_ip if dport in RDP_PORTS else dst_ip
                    for (
                        host_value,
                        method,
                        confidence,
                        detail,
                    ) in _extract_rdp_hostnames(payload):
                        if _match(mapped_ip) and _record_finding(
                            findings_map,
                            hostname=host_value,
                            mapped_ip=mapped_ip,
                            protocol="RDP",
                            method=method,
                            confidence=confidence,
                            details=f"{detail} on ports {sport}->{dport}",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            ts=ts,
                            packet_index=packet_index,
                        ):
                            found_evidence = True
                            summary.protocol_counts["RDP"] += 1
                            summary.method_counts[method] += 1

                if sport in {4840} or dport in {4840}:
                    mapped_ip = dst_ip if dport == 4840 else src_ip
                    for (
                        host_value,
                        method,
                        confidence,
                        detail,
                    ) in _extract_opcua_hostnames(payload):
                        if _match(mapped_ip) and _record_finding(
                            findings_map,
                            hostname=host_value,
                            mapped_ip=mapped_ip,
                            protocol="OPC UA",
                            method=method,
                            confidence=confidence,
                            details=f"{detail} on ports {sport}->{dport}",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            ts=ts,
                            packet_index=packet_index,
                        ):
                            found_evidence = True
                            summary.protocol_counts["OPC UA"] += 1
                            summary.method_counts[method] += 1

                if sport in {34962, 34963, 34964} or dport in {34962, 34963, 34964}:
                    mapped_ip = dst_ip if dport in {34962, 34963, 34964} else src_ip
                    for (
                        host_value,
                        method,
                        confidence,
                        detail,
                    ) in _extract_profinet_hostnames(payload):
                        if _match(mapped_ip) and _record_finding(
                            findings_map,
                            hostname=host_value,
                            mapped_ip=mapped_ip,
                            protocol="PROFINET",
                            method=method,
                            confidence=confidence,
                            details=f"{detail} on ports {sport}->{dport}",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            ts=ts,
                            packet_index=packet_index,
                        ):
                            found_evidence = True
                            summary.protocol_counts["PROFINET"] += 1
                            summary.method_counts[method] += 1

                if sport == 502 or dport == 502:
                    mapped_ip = src_ip if sport == 502 else dst_ip
                    for (
                        host_value,
                        method,
                        confidence,
                        detail,
                    ) in _extract_modbus_device_id_hostnames(payload):
                        if _match(mapped_ip) and _record_finding(
                            findings_map,
                            hostname=host_value,
                            mapped_ip=mapped_ip,
                            protocol="Modbus",
                            method=method,
                            confidence=confidence,
                            details=f"{detail} on ports {sport}->{dport}",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            ts=ts,
                            packet_index=packet_index,
                        ):
                            found_evidence = True
                            summary.protocol_counts["Modbus"] += 1
                            summary.method_counts[method] += 1

                if sport in OT_PORT_PROTOCOLS or dport in OT_PORT_PROTOCOLS:
                    proto_name = (
                        OT_PORT_PROTOCOLS.get(dport)
                        or OT_PORT_PROTOCOLS.get(sport)
                        or "OT/ICS"
                    )
                    mapped_ip = dst_ip if dport in OT_PORT_PROTOCOLS else src_ip
                    for (
                        host_value,
                        method,
                        confidence,
                        detail,
                    ) in _extract_ot_keyword_hostnames(payload, proto_name):
                        if _match(mapped_ip) and _record_finding(
                            findings_map,
                            hostname=host_value,
                            mapped_ip=mapped_ip,
                            protocol=proto_name,
                            method=method,
                            confidence=confidence,
                            details=f"{detail} on ports {sport}->{dport}",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            ts=ts,
                            packet_index=packet_index,
                        ):
                            found_evidence = True
                            summary.protocol_counts[proto_name] += 1
                            summary.method_counts[method] += 1

                if (sport in SMB_PORTS) or (dport in SMB_PORTS):
                    for unc_host in _extract_unc_hostnames(payload):
                        mapped_ip = dst_ip if dport in SMB_PORTS else src_ip
                        if _match(mapped_ip) and _record_finding(
                            findings_map,
                            hostname=unc_host,
                            mapped_ip=mapped_ip,
                            protocol="SMB",
                            method="SMB UNC host reference",
                            confidence="LOW",
                            details=f"UNC path host reference on SMB flow {sport}->{dport}",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            ts=ts,
                            packet_index=packet_index,
                        ):
                            found_evidence = True
                            summary.protocol_counts["SMB"] += 1
                            summary.method_counts["SMB UNC host reference"] += 1

                    mapped_ip = dst_ip if dport in SMB_PORTS else src_ip
                    for (
                        host_value,
                        method,
                        confidence,
                        detail,
                    ) in _extract_smb_hostnames(payload):
                        if _match(mapped_ip) and _record_finding(
                            findings_map,
                            hostname=host_value,
                            mapped_ip=mapped_ip,
                            protocol="SMB",
                            method=method,
                            confidence=confidence,
                            details=f"{detail} on SMB flow {sport}->{dport}",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            ts=ts,
                            packet_index=packet_index,
                        ):
                            found_evidence = True
                            summary.protocol_counts["SMB"] += 1
                            summary.method_counts[method] += 1

            if packet_relevant or not target_filter_enabled:
                # TLS layers only ever dissect over TCP, so skip the chain
                # walk for non-TCP packets.
                sni = _extract_sni(pkt) if tcp_layer is not None else None
                if not sni and tcp_layer is not None and payload:
                    # Scapy only dissects TLS on 443; the raw parser covers
                    # RDP-on-3389 TLS, 8443, and CONNECT-tunneled handshakes.
                    sni = _parse_raw_tls_client_hello_sni(payload)
                if sni:
                    method = "TLS SNI"
                    protocol = "HTTPS/TLS"
                    in_proxy_tunnel = (
                        src_ip,
                        sport or 0,
                        dst_ip,
                        dport or 0,
                    ) in proxy_flows
                    # Inside a CONNECT tunnel dst is the PROXY, not the
                    # server the SNI names — leave the IP mapping empty.
                    sni_mapped_ip = "" if in_proxy_tunnel else dst_ip
                    sni_details = (
                        f"ClientHello SNI inside CONNECT tunnel via proxy {dst_ip}"
                        if in_proxy_tunnel
                        else f"ClientHello SNI seen for destination {dst_ip}"
                    )
                    sni_allowed = (
                        (not target_filter_enabled or flow_relevant)
                        if in_proxy_tunnel
                        else _match(dst_ip)
                    )
                    if sni_allowed and _record_finding(
                        findings_map,
                        hostname=sni,
                        mapped_ip=sni_mapped_ip,
                        protocol=protocol,
                        method=method,
                        confidence="MEDIUM",
                        details=sni_details,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        ts=ts,
                        packet_index=packet_index,
                    ):
                        found_evidence = True
                        summary.protocol_counts[protocol] += 1
                        summary.method_counts[method] += 1

            cert_results = (
                _extract_tls_certificate_hostnames(pkt, payload)
                if tcp_layer is not None
                else []
            )
            if not cert_results and tcp_layer is not None and payload:
                # Raw DER fallback for certificates scapy did not dissect
                # (non-443 ports, CONNECT tunnels, mid-stream records).
                cert_results = _extract_der_cert_hostnames(payload)
            for cert_hostname, method, confidence in cert_results:
                in_proxy_tunnel = (
                    src_ip,
                    sport or 0,
                    dst_ip,
                    dport or 0,
                ) in proxy_flows
                # The certificate is sent BY the server (src) — except inside
                # a CONNECT tunnel, where the flow endpoints are the proxy.
                mapped_ip = "" if in_proxy_tunnel else src_ip
                cert_details = (
                    f"{method} observed in certificate inside CONNECT tunnel via {dst_ip}"
                    if in_proxy_tunnel
                    else f"{method} observed in certificate sent by {src_ip}"
                )
                cert_allowed = (
                    (not target_filter_enabled or flow_relevant)
                    if in_proxy_tunnel
                    else _match(mapped_ip)
                )
                if cert_allowed and _record_finding(
                    findings_map,
                    hostname=cert_hostname,
                    mapped_ip=mapped_ip,
                    protocol="HTTPS/TLS",
                    method=method,
                    confidence=confidence,
                    details=cert_details,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    ts=ts,
                    packet_index=packet_index,
                ):
                    found_evidence = True
                    packet_relevant = True
                    summary.protocol_counts["HTTPS/TLS"] += 1
                    summary.method_counts[method] += 1

            if udp_layer is not None:
                port_pair = {int(udp_layer.sport), int(udp_layer.dport)}
                if 137 in port_pair and payload:
                    for token in _extract_nbns_hostnames(pkt, payload):
                        if _match(src_ip) and _record_finding(
                            findings_map,
                            hostname=token,
                            mapped_ip=src_ip,
                            protocol="NETBIOS",
                            method="NBNS payload token",
                            confidence="LOW",
                            details=f"NBNS packet source {src_ip}",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            ts=ts,
                            packet_index=packet_index,
                        ):
                            found_evidence = True
                            summary.protocol_counts["NETBIOS"] += 1
                            summary.method_counts["NBNS payload token"] += 1

            if target_filter_enabled and (packet_relevant or found_evidence):
                summary.relevant_packets += 1
            if not target_filter_enabled and found_evidence:
                summary.relevant_packets += 1

    except Exception as exc:
        summary.errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        status.finish()
        try:
            reader.close()
        except Exception:
            pass

    final_findings = list(findings_map.values())
    if target_filter_enabled and target_ip:
        # A hostname belongs to the target only when the per-method, session-aware
        # mapping attributed it to the target's own IP (a DNS A-record that
        # resolves to it, a Host header/SNI where it is the server, its own
        # NetBIOS/DHCP/mDNS announcement, etc.). Findings that map to a peer (a
        # server the target merely contacted) or to no IP at all (a name the
        # target only looked up) are the target's *activity*, not its *identity*,
        # so they are excluded from an -ip scoped view.
        final_findings = [
            item for item in final_findings if item.mapped_ip == target_ip
        ]

    if apply_filters and query_text:
        final_findings = [
            item
            for item in final_findings
            if _hostname_matches_query(item.hostname, query_text)
        ]
    if apply_filters and search_text:
        final_findings = [
            item for item in final_findings if _finding_matches_search(item, search_text)
        ]

    summary.findings = sorted(
        final_findings,
        key=lambda item: (-item.count, item.hostname, item.method),
    )
    summary.ip_to_macs = {
        ip_value: sorted(macs) for ip_value, macs in ip_to_macs.items() if macs
    }
    context = _build_hostname_enrichment(summary.findings)
    summary.analyst_verdict = str(context.get("analyst_verdict", ""))
    summary.analyst_confidence = str(context.get("analyst_confidence", "low"))
    summary.analyst_reasons = [
        str(v) for v in list(context.get("analyst_reasons", []) or [])
    ]
    summary.conflict_profiles = list(context.get("conflict_profiles", []) or [])
    summary.drift_profiles = list(context.get("drift_profiles", []) or [])
    summary.suspicious_name_profiles = list(
        context.get("suspicious_name_profiles", []) or []
    )
    summary.cross_protocol_corroboration = list(
        context.get("cross_protocol_corroboration", []) or []
    )
    summary.false_positive_context = [
        str(v) for v in list(context.get("false_positive_context", []) or [])
    ]
    return summary
