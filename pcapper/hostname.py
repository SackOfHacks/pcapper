from __future__ import annotations

import ipaddress
import math
import re
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from .pcap_cache import get_reader
from .utils import safe_float

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
OT_PORT_PROTOCOLS: dict[int, str] = {
    502: "Modbus",
    20000: "DNP3",
    102: "S7/MMS",
    47808: "BACnet",
    34962: "PROFINET",
    34963: "PROFINET",
    34964: "PROFINET",
    44818: "EtherNet/IP",
    2222: "CIP/ENIP",
    2221: "CIP Security",
    4840: "OPC UA",
}

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
RDP_COOKIE_RE = re.compile(r"(?i)\bcookie:\s*mstshash=([A-Za-z0-9._-]{2,253})")


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
    deterministic_checks: dict[str, list[str]] = field(default_factory=dict)
    conflict_profiles: list[dict[str, object]] = field(default_factory=list)
    drift_profiles: list[dict[str, object]] = field(default_factory=list)
    suspicious_name_profiles: list[dict[str, object]] = field(default_factory=list)
    cross_protocol_corroboration: list[dict[str, object]] = field(default_factory=list)
    risk_matrix: list[dict[str, str]] = field(default_factory=list)
    false_positive_context: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


def _is_public_ip(value: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(value)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_multicast
            or ip_obj.is_link_local
            or ip_obj.is_unspecified
        )
    except Exception:
        return False


def _build_hostname_enrichment(
    findings: list[HostnameFinding],
) -> dict[str, object]:
    _ = findings
    return {}

def _normalize_hostname(value: str) -> str:
    hostname = value.strip().strip(".")
    hostname = re.sub(r"\s+", "", hostname)
    return hostname.lower()


def _is_valid_hostname(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    if " " in value or value.startswith("."):
        return False
    labels = value.split(".")
    if len(labels) < 1:
        return False
    allowed = re.compile(r"^[a-z0-9-]{1,63}$", re.IGNORECASE)
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


def _extract_ip_pair(pkt) -> tuple[str, str]:
    if IP is not None and pkt.haslayer(IP):
        return str(pkt[IP].src), str(pkt[IP].dst)
    if IPv6 is not None and pkt.haslayer(IPv6):
        return str(pkt[IPv6].src), str(pkt[IPv6].dst)
    if ARP is not None and pkt.haslayer(ARP):
        try:
            return str(getattr(pkt[ARP], "psrc", "0.0.0.0") or "0.0.0.0"), str(
                getattr(pkt[ARP], "pdst", "0.0.0.0") or "0.0.0.0"
            )
        except Exception:
            return "0.0.0.0", "0.0.0.0"
    return "0.0.0.0", "0.0.0.0"


def _extract_payload(pkt) -> bytes:
    if Raw is not None and pkt.haslayer(Raw):
        try:
            return bytes(pkt[Raw].load)
        except Exception:
            return b""
    if TCP is not None and pkt.haslayer(TCP):
        try:
            return bytes(pkt[TCP].payload)
        except Exception:
            return b""
    if UDP is not None and pkt.haslayer(UDP):
        try:
            return bytes(pkt[UDP].payload)
        except Exception:
            return b""
    return b""


def _extract_ports(pkt) -> tuple[Optional[int], Optional[int]]:
    if TCP is not None and pkt.haslayer(TCP):
        try:
            return int(pkt[TCP].sport), int(pkt[TCP].dport)
        except Exception:
            return None, None
    if UDP is not None and pkt.haslayer(UDP):
        try:
            return int(pkt[UDP].sport), int(pkt[UDP].dport)
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
        if hasattr(pkt, "haslayer") and pkt.haslayer("NBNSQueryRequest"):
            layer = pkt["NBNSQueryRequest"]
            for attr in ("QUESTION_NAME", "qname", "RR_NAME", "rrname"):
                decoded = _decode_nbns_level1_name(getattr(layer, attr, None))
                _append(decoded)
        if hasattr(pkt, "haslayer") and pkt.haslayer("NBNSQueryResponse"):
            layer = pkt["NBNSQueryResponse"]
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


def _parse_http_host(payload: bytes) -> Optional[str]:
    if not payload:
        return None
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return None
    if not re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s", text):
        return None
    for line in text.splitlines():
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            host = host.split(":", 1)[0].strip()
            host = _normalize_hostname(host)
            return host if _is_valid_hostname(host) else None
    return None


def _parse_http_authority_host(payload: bytes) -> Optional[str]:
    if not payload:
        return None
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return None
    first_line = text.splitlines()[0].strip() if text.splitlines() else ""
    if not first_line:
        return None

    parts = first_line.split()
    if len(parts) < 2:
        return None
    method = parts[0].upper()
    target = parts[1]

    if method == "CONNECT":
        authority = target
    elif target.startswith(("http://", "https://")):
        authority = target.split("//", 1)[1].split("/", 1)[0]
    else:
        return None

    host = authority.split("@", 1)[-1].split(":", 1)[0].strip().strip(".")
    host = _normalize_hostname(host)
    return host if _is_valid_hostname(host) else None


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
    if "SSH-" not in text and "ssh" not in text.lower():
        return []

    findings: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()
    lines = text.splitlines()[:8]

    for line in lines:
        line_text = line.strip()
        if not line_text:
            continue
        for token in _extract_textual_hostname_tokens(line_text, require_hint=True):
            key = f"{token}|{line_text}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                (
                    token,
                    "SSH banner hostname token",
                    "LOW",
                    f"SSH line: {line_text[:120]}",
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
    for host in RDP_COOKIE_RE.findall(text):
        normalized = _normalize_hostname(host)
        if not _looks_hostname_like(normalized, require_hint=False):
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        findings.append(
            (
                normalized,
                "RDP mstshash cookie",
                "LOW",
                "RDP negotiation cookie contains client host token",
            )
        )
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
            if pkt.haslayer(layer_key):
                dhcp_layer = pkt[layer_key]
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
            if pkt.haslayer(layer_key):
                bootp_layer = pkt[layer_key]
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

    mapped_ip = src_ip
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
    pkt,
    payload: bytes,
    mac_to_ips: dict[str, set[str]],
) -> list[tuple[str, str, str, str, str]]:
    if Ether is None:
        return []
    try:
        if not pkt.haslayer(Ether):
            return []
        eth_layer = pkt[Ether]
    except Exception:
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
    pkt,
    payload: bytes,
    mac_to_ips: dict[str, set[str]],
) -> list[tuple[str, str, str, str, str]]:
    if Ether is None:
        return []
    try:
        if not pkt.haslayer(Ether):
            return []
        eth_layer = pkt[Ether]
    except Exception:
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
            if pkt.haslayer(layer_key):
                cert_layer = pkt[layer_key]
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
    pkt, payload: bytes, src_ip: str, dst_ip: str
) -> list[tuple[str, str, str, str, str]]:
    results: list[tuple[str, str, str, str, str]] = []
    if ARP is None:
        return results

    try:
        if not pkt.haslayer(ARP):
            return results
    except Exception:
        return results

    arp_psrc = src_ip
    arp_pdst = dst_ip
    try:
        arp_layer = pkt[ARP]
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
    if not pkt.haslayer(TLSClientHello):
        return None
    try:
        hello = pkt[TLSClientHello]
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
                if _is_valid_hostname(decoded):
                    return decoded
    except Exception:
        return None
    return None


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


def _scope_findings_to_target(
    findings: list[HostnameFinding],
    target_ip: str,
) -> list[HostnameFinding]:
    scoped_map: dict[tuple[str, str, str, str, str, str, str], HostnameFinding] = {}
    for finding in findings:
        mapped_ip = finding.mapped_ip
        if finding.src_ip == target_ip or finding.dst_ip == target_ip:
            mapped_ip = target_ip
        key = (
            finding.hostname,
            mapped_ip,
            finding.protocol,
            finding.method,
            finding.src_ip,
            finding.dst_ip,
            finding.details,
        )
        existing = scoped_map.get(key)
        if existing is None:
            scoped_map[key] = HostnameFinding(
                hostname=finding.hostname,
                mapped_ip=mapped_ip,
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
            continue

        existing.count += finding.count
        if finding.first_seen is not None and (
            existing.first_seen is None or finding.first_seen < existing.first_seen
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
            existing.last_packet is None or finding.last_packet > existing.last_packet
        ):
            existing.last_packet = finding.last_packet

    return list(scoped_map.values())


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
    merged.deterministic_checks = {
        str(key): [str(v) for v in list(values or [])]
        for key, values in dict(
            merged_context.get("deterministic_checks", {}) or {}
        ).items()
    }
    merged.conflict_profiles = list(merged_context.get("conflict_profiles", []) or [])
    merged.drift_profiles = list(merged_context.get("drift_profiles", []) or [])
    merged.suspicious_name_profiles = list(
        merged_context.get("suspicious_name_profiles", []) or []
    )
    merged.cross_protocol_corroboration = list(
        merged_context.get("cross_protocol_corroboration", []) or []
    )
    merged.risk_matrix = [
        dict(item)
        for item in list(merged_context.get("risk_matrix", []) or [])
        if isinstance(item, dict)
    ]
    merged.false_positive_context = [
        str(v) for v in list(merged_context.get("false_positive_context", []) or [])
    ]
    return merged


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
            src_ip, dst_ip = _extract_ip_pair(pkt)
            sport, dport = _extract_ports(pkt)
            if Ether is not None and pkt.haslayer(Ether):
                try:
                    src_mac = getattr(pkt[Ether], "src", "")
                    dst_mac = getattr(pkt[Ether], "dst", "")
                    _remember_ip_mac(ip_to_macs, src_ip, src_mac)
                    _remember_ip_mac(ip_to_macs, dst_ip, dst_mac)
                    _remember_mac_ip(mac_to_ips, src_mac, src_ip)
                    _remember_mac_ip(mac_to_ips, dst_mac, dst_ip)
                except Exception:
                    pass
            if ARP is not None and pkt.haslayer(ARP):
                try:
                    arp_layer = pkt[ARP]
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

            for (
                host_value,
                method,
                confidence,
                mapped_ip,
                details,
            ) in _extract_dhcp_hostnames(pkt, src_ip, dst_ip):
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

            for (
                host_value,
                method,
                confidence,
                mapped_ip,
                details,
            ) in _extract_dhcpv6_hostnames(pkt, src_ip, dst_ip):
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

            if DNS is not None and pkt.haslayer(DNS):
                try:
                    dns_layer = pkt[DNS]
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
                    if dns_protocol in {"mDNS", "LLMNR"} and not is_response and qname:
                        qname_host = _normalize_hostname(qname)
                        if _looks_hostname_like(qname_host, require_hint=False):
                            method = f"{dns_protocol} query name"
                            if _match(src_ip) and _record_finding(
                                findings_map,
                                hostname=qname_host,
                                mapped_ip=src_ip,
                                protocol=dns_protocol,
                                method=method,
                                confidence="LOW",
                                details=f"{dns_protocol} query type={qtype} for {qname_host}",
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                ts=ts,
                                packet_index=packet_index,
                            ):
                                found_evidence = True
                                packet_relevant = True
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

            payload = _extract_payload(pkt)
            for (
                host_value,
                method,
                confidence,
                mapped_ip,
                details,
            ) in _extract_lldp_hostnames(pkt, payload, mac_to_ips):
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
            ) in _extract_cdp_hostnames(pkt, payload, mac_to_ips):
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
            ) in _extract_arp_hostnames(pkt, payload, src_ip, dst_ip):
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
                host_header = _parse_http_host(payload)
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

                authority_host = _parse_http_authority_host(payload)
                if authority_host:
                    method = "HTTP absolute/CONNECT authority"
                    protocol = "HTTP"
                    if _match(dst_ip) and _record_finding(
                        findings_map,
                        hostname=authority_host,
                        mapped_ip=dst_ip,
                        protocol=protocol,
                        method=method,
                        confidence="MEDIUM",
                        details=f"HTTP request authority references destination {dst_ip}",
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

                user, domain, workstation = _parse_ntlm_type3(payload)
                if workstation:
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

                if (sport in MAIL_SERVER_PORTS) or (dport in MAIL_SERVER_PORTS):
                    for host_value, method, confidence in _extract_mail_hostnames(
                        payload
                    ):
                        mapped_ip = src_ip
                        if method == "SMTP HELO/EHLO":
                            mapped_ip = src_ip
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
                    ssh_mapped_ip = src_ip if sport in SSH_PORTS else dst_ip
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
                    mapped_ip = (
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
                        if _match(mapped_ip) and _record_finding(
                            findings_map,
                            hostname=host_value,
                            mapped_ip=mapped_ip,
                            protocol=protocol,
                            method=method,
                            confidence=confidence,
                            details=f"{detail} on ports {sport}->{dport}",
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
                    mapped_ip = src_ip
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
                sni = _extract_sni(pkt)
                if sni:
                    method = "TLS SNI"
                    protocol = "HTTPS/TLS"
                    if _match(dst_ip) and _record_finding(
                        findings_map,
                        hostname=sni,
                        mapped_ip=dst_ip,
                        protocol=protocol,
                        method=method,
                        confidence="MEDIUM",
                        details=f"ClientHello SNI seen for destination {dst_ip}",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        ts=ts,
                        packet_index=packet_index,
                    ):
                        found_evidence = True
                        summary.protocol_counts[protocol] += 1
                        summary.method_counts[method] += 1

            for cert_hostname, method, confidence in _extract_tls_certificate_hostnames(
                pkt, payload
            ):
                mapped_ip = src_ip
                if _match(mapped_ip) and _record_finding(
                    findings_map,
                    hostname=cert_hostname,
                    mapped_ip=mapped_ip,
                    protocol="HTTPS/TLS",
                    method=method,
                    confidence=confidence,
                    details=f"{method} observed in certificate sent by {src_ip}",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    ts=ts,
                    packet_index=packet_index,
                ):
                    found_evidence = True
                    packet_relevant = True
                    summary.protocol_counts["HTTPS/TLS"] += 1
                    summary.method_counts[method] += 1

            if UDP is not None and pkt.haslayer(UDP):
                port_pair = {int(pkt[UDP].sport), int(pkt[UDP].dport)}
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
    if target_filter_enabled and include_related and target_ip:
        final_findings = _scope_findings_to_target(final_findings, target_ip)

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
    summary.deterministic_checks = {
        str(key): [str(v) for v in list(values or [])]
        for key, values in dict(context.get("deterministic_checks", {}) or {}).items()
    }
    summary.conflict_profiles = list(context.get("conflict_profiles", []) or [])
    summary.drift_profiles = list(context.get("drift_profiles", []) or [])
    summary.suspicious_name_profiles = list(
        context.get("suspicious_name_profiles", []) or []
    )
    summary.cross_protocol_corroboration = list(
        context.get("cross_protocol_corroboration", []) or []
    )
    summary.risk_matrix = [
        dict(item)
        for item in list(context.get("risk_matrix", []) or [])
        if isinstance(item, dict)
    ]
    summary.false_positive_context = [
        str(v) for v in list(context.get("false_positive_context", []) or [])
    ]
    return summary
