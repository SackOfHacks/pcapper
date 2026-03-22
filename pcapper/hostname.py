from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from collections import Counter, defaultdict
import ipaddress
import math
import re

from .pcap_cache import get_reader
from .utils import safe_float

try:
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.dhcp import DHCP, BOOTP
    from scapy.layers.dns import DNS
    from scapy.layers.l2 import ARP
    from scapy.packet import Raw
except Exception:
    IP = TCP = UDP = IPv6 = DHCP = BOOTP = DNS = ARP = Raw = None

try:
    from scapy.layers.tls.handshake import TLSClientHello, TLSCertificate  # type: ignore
except Exception:
    TLSClientHello = TLSCertificate = None


MAIL_SERVER_PORTS = {21, 25, 110, 143, 465, 587, 993, 995, 2525}
SMB_PORTS = {139, 445}


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
    total_packets: int = 0
    relevant_packets: int = 0
    findings: list[HostnameFinding] = field(default_factory=list)
    protocol_counts: Counter[str] = field(default_factory=Counter)
    method_counts: Counter[str] = field(default_factory=Counter)
    analyst_verdict: str = ""
    analyst_confidence: str = "low"
    analyst_reasons: list[str] = field(default_factory=list)
    deterministic_checks: dict[str, list[str]] = field(default_factory=dict)
    conflict_profiles: list[dict[str, object]] = field(default_factory=list)
    drift_profiles: list[dict[str, object]] = field(default_factory=list)
    suspicious_name_profiles: list[dict[str, object]] = field(default_factory=list)
    cross_protocol_corroboration: list[dict[str, object]] = field(default_factory=list)
    risk_matrix: list[dict[str, str]] = field(default_factory=list)
    investigation_pivots: list[dict[str, object]] = field(default_factory=list)
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


def _build_hostname_hunting_context(findings: list[HostnameFinding]) -> dict[str, object]:
    checks: dict[str, list[str]] = {
        "hostname_collision_or_spoofing": [],
        "ip_alias_or_fronting_anomaly": [],
        "cross_protocol_corroboration": [],
        "hostname_temporal_drift": [],
        "protocol_identity_mismatch": [],
        "ad_naming_privilege_abuse": [],
        "suspicious_naming_pattern": [],
        "boundary_leak_or_cross_zone": [],
        "evidence_provenance": [],
    }

    by_host: dict[str, list[HostnameFinding]] = defaultdict(list)
    by_ip: dict[str, list[HostnameFinding]] = defaultdict(list)
    for finding in findings:
        by_host[finding.hostname].append(finding)
        by_ip[finding.mapped_ip].append(finding)

    conflict_profiles: list[dict[str, object]] = []
    drift_profiles: list[dict[str, object]] = []
    suspicious_name_profiles: list[dict[str, object]] = []
    corroboration_profiles: list[dict[str, object]] = []
    pivots: list[dict[str, object]] = []

    for hostname, rows in by_host.items():
        unique_ips = sorted({item.mapped_ip for item in rows if item.mapped_ip})
        unique_methods = sorted({item.method for item in rows if item.method})
        unique_protocols = sorted({item.protocol for item in rows if item.protocol})
        evidence_count = sum(int(item.count or 0) for item in rows)
        first_seen_vals = [item.first_seen for item in rows if isinstance(item.first_seen, (int, float))]
        last_seen_vals = [item.last_seen for item in rows if isinstance(item.last_seen, (int, float))]
        first_pkt_vals = [item.first_packet for item in rows if isinstance(item.first_packet, int)]
        last_pkt_vals = [item.last_packet for item in rows if isinstance(item.last_packet, int)]

        if len(unique_ips) >= 2:
            conflict_profiles.append(
                {
                    "type": "hostname_to_many_ips",
                    "hostname": hostname,
                    "ip_count": len(unique_ips),
                    "ips": unique_ips,
                    "methods": unique_methods,
                    "protocols": unique_protocols,
                    "evidence": evidence_count,
                }
            )
            checks["hostname_collision_or_spoofing"].append(
                f"{hostname} observed on {len(unique_ips)} IPs: {', '.join(unique_ips[:5])}"
            )

            if first_seen_vals and last_seen_vals and min(first_seen_vals) < max(last_seen_vals):
                drift_profiles.append(
                    {
                        "hostname": hostname,
                        "first_seen": min(first_seen_vals),
                        "last_seen": max(last_seen_vals),
                        "ip_count": len(unique_ips),
                        "ips": unique_ips,
                        "methods": unique_methods,
                    }
                )
                checks["hostname_temporal_drift"].append(
                    f"{hostname} reassigned/drifted across {len(unique_ips)} IPs over capture timeline"
                )

        if len(unique_protocols) >= 2:
            corroboration_profiles.append(
                {
                    "hostname": hostname,
                    "ip_count": len(unique_ips),
                    "protocols": unique_protocols,
                    "methods": unique_methods,
                    "evidence": evidence_count,
                    "confidence": "high" if len(unique_protocols) >= 3 else "medium",
                }
            )
            checks["cross_protocol_corroboration"].append(
                f"{hostname} corroborated by protocols={','.join(unique_protocols[:4])}"
            )

        text = hostname.lower()
        dot_parts = [part for part in text.split(".") if part]
        label0 = dot_parts[0] if dot_parts else text
        entropy = _shannon_entropy(label0)
        reasons: list[str] = []
        if text.startswith("xn--"):
            reasons.append("punycode")
        if any(token in text for token in ("dc", "ldap", "krbtgt", "admin", "backup", "svc", "domain")):
            reasons.append("privileged_or_domain_pattern")
        if len(label0) >= 18 and entropy >= 3.6:
            reasons.append(f"high_entropy_label={entropy:.2f}")
        if dot_parts and dot_parts[-1] in {"top", "gq", "tk", "ml", "ga", "xyz"}:
            reasons.append("suspicious_tld")

        if reasons:
            suspicious_name_profiles.append(
                {
                    "hostname": hostname,
                    "reasons": reasons,
                    "entropy": round(entropy, 2),
                    "ips": unique_ips[:8],
                    "evidence": evidence_count,
                }
            )
            if "privileged_or_domain_pattern" in reasons:
                checks["ad_naming_privilege_abuse"].append(
                    f"{hostname} appears privileged/domain-like; mapped to {', '.join(unique_ips[:3]) or '-'}"
                )
            checks["suspicious_naming_pattern"].append(
                f"{hostname} flags={','.join(reasons)}"
            )

        if any(_is_public_ip(item.dst_ip) or _is_public_ip(item.mapped_ip) for item in rows):
            checks["boundary_leak_or_cross_zone"].append(
                f"{hostname} observed with public boundary context"
            )

        if first_pkt_vals or last_pkt_vals:
            pivots.append(
                {
                    "hostname": hostname,
                    "mapped_ips": unique_ips[:6],
                    "methods": unique_methods[:4],
                    "protocols": unique_protocols[:4],
                    "first_packet": min(first_pkt_vals) if first_pkt_vals else None,
                    "last_packet": max(last_pkt_vals) if last_pkt_vals else None,
                }
            )

    for mapped_ip, rows in by_ip.items():
        if not mapped_ip:
            continue
        hostnames = sorted({item.hostname for item in rows if item.hostname})
        if len(hostnames) >= 4:
            checks["ip_alias_or_fronting_anomaly"].append(
                f"{mapped_ip} mapped to many hostnames ({len(hostnames)})"
            )
            conflict_profiles.append(
                {
                    "type": "ip_to_many_hostnames",
                    "ip": mapped_ip,
                    "host_count": len(hostnames),
                    "hostnames": hostnames,
                    "methods": sorted({item.method for item in rows if item.method}),
                    "protocols": sorted({item.protocol for item in rows if item.protocol}),
                    "evidence": sum(int(item.count or 0) for item in rows),
                }
            )

        method_set = {item.method for item in rows if item.method}
        if "DNS PTR reverse lookup" in method_set and not any(
            value in method_set
            for value in ("DNS A/AAAA mapping", "TLS SNI", "TLS certificate SAN", "HTTP Host header")
        ):
            checks["protocol_identity_mismatch"].append(
                f"{mapped_ip} has reverse-name evidence but weak forward corroboration"
            )

    checks["evidence_provenance"].append(
        f"{sum(int(item.count or 0) for item in findings)} evidence row observation(s) with flow attribution"
    )

    score = 0
    score += 2 if checks["hostname_collision_or_spoofing"] else 0
    score += 1 if checks["ip_alias_or_fronting_anomaly"] else 0
    score += 1 if checks["protocol_identity_mismatch"] else 0
    score += 1 if checks["hostname_temporal_drift"] else 0
    score += 1 if checks["ad_naming_privilege_abuse"] else 0
    score += 1 if checks["suspicious_naming_pattern"] else 0
    score += 1 if checks["boundary_leak_or_cross_zone"] else 0
    score += 1 if checks["cross_protocol_corroboration"] else 0

    reasons: list[str] = []
    if checks["hostname_collision_or_spoofing"]:
        reasons.append("Hostname collisions suggest spoofing/poisoning risk")
    if checks["protocol_identity_mismatch"]:
        reasons.append("Protocol identity mismatch observed")
    if checks["hostname_temporal_drift"]:
        reasons.append("Temporal hostname-to-IP drift observed")
    if checks["ad_naming_privilege_abuse"]:
        reasons.append("Privileged/domain naming abuse indicators observed")
    if checks["boundary_leak_or_cross_zone"]:
        reasons.append("Internal naming appears on boundary/public context")
    if checks["cross_protocol_corroboration"]:
        reasons.append("Multi-protocol corroboration available for key names")

    if score >= 7:
        verdict = "YES - HIGH-CONFIDENCE HOSTNAME SPOOFING/ABUSE SIGNALS DETECTED"
        confidence = "high"
    elif score >= 4:
        verdict = "LIKELY - MULTIPLE CORROBORATING HOSTNAME RISK INDICATORS DETECTED"
        confidence = "medium"
    elif score >= 2:
        verdict = "POSSIBLE - SUSPICIOUS HOSTNAME SIGNALS REQUIRE VALIDATION"
        confidence = "medium"
    else:
        verdict = "NO STRONG SIGNAL - NO CONVINCING HOSTNAME ABUSE PATTERN FROM CURRENT HEURISTICS"
        confidence = "low"

    false_positive_context: list[str] = []
    if not checks["hostname_collision_or_spoofing"]:
        false_positive_context.append("No strong same-hostname multi-IP collision pattern crossed threshold")
    if not checks["ip_alias_or_fronting_anomaly"]:
        false_positive_context.append("No high-volume many-hostnames-per-IP fronting pattern crossed threshold")
    if checks["cross_protocol_corroboration"] and not checks["protocol_identity_mismatch"]:
        false_positive_context.append("Multi-protocol naming evidence appears internally consistent")

    matrix: list[dict[str, str]] = [
        {
            "category": "Hostname Collision/Spoofing",
            "risk": "High" if checks["hostname_collision_or_spoofing"] else "None",
            "confidence": "High" if checks["hostname_collision_or_spoofing"] else "Low",
            "evidence": str(len(checks["hostname_collision_or_spoofing"])) if checks["hostname_collision_or_spoofing"] else "No matching detections",
        },
        {
            "category": "Temporal Drift",
            "risk": "Medium" if checks["hostname_temporal_drift"] else "None",
            "confidence": "Medium" if checks["hostname_temporal_drift"] else "Low",
            "evidence": str(len(checks["hostname_temporal_drift"])) if checks["hostname_temporal_drift"] else "No matching detections",
        },
        {
            "category": "Protocol Identity Mismatch",
            "risk": "Medium" if checks["protocol_identity_mismatch"] else "None",
            "confidence": "Medium" if checks["protocol_identity_mismatch"] else "Low",
            "evidence": str(len(checks["protocol_identity_mismatch"])) if checks["protocol_identity_mismatch"] else "No matching detections",
        },
        {
            "category": "AD/Privileged Naming Abuse",
            "risk": "Medium" if checks["ad_naming_privilege_abuse"] else "None",
            "confidence": "Medium" if checks["ad_naming_privilege_abuse"] else "Low",
            "evidence": str(len(checks["ad_naming_privilege_abuse"])) if checks["ad_naming_privilege_abuse"] else "No matching detections",
        },
        {
            "category": "Suspicious Naming Pattern",
            "risk": "Low" if checks["suspicious_naming_pattern"] else "None",
            "confidence": "Low" if checks["suspicious_naming_pattern"] else "Low",
            "evidence": str(len(checks["suspicious_naming_pattern"])) if checks["suspicious_naming_pattern"] else "No matching detections",
        },
        {
            "category": "Boundary Leakage/Cross-Zone",
            "risk": "Medium" if checks["boundary_leak_or_cross_zone"] else "None",
            "confidence": "Medium" if checks["boundary_leak_or_cross_zone"] else "Low",
            "evidence": str(len(checks["boundary_leak_or_cross_zone"])) if checks["boundary_leak_or_cross_zone"] else "No matching detections",
        },
    ]

    return {
        "analyst_verdict": verdict,
        "analyst_confidence": confidence,
        "analyst_reasons": reasons if reasons else ["No high-confidence hostname threat heuristic crossed threshold"],
        "deterministic_checks": checks,
        "conflict_profiles": conflict_profiles[:40],
        "drift_profiles": drift_profiles[:30],
        "suspicious_name_profiles": suspicious_name_profiles[:40],
        "cross_protocol_corroboration": corroboration_profiles[:40],
        "risk_matrix": matrix,
        "investigation_pivots": pivots[:40],
        "false_positive_context": false_positive_context[:8],
    }


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
        host = bytes(decoded_bytes[:15]).decode("latin-1", errors="ignore").rstrip(" \x00")
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
        if len(octets) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in octets):
            return ".".join(reversed(octets))
    return ""


def _extract_ip_pair(pkt) -> tuple[str, str]:
    if IP is not None and pkt.haslayer(IP):
        return str(pkt[IP].src), str(pkt[IP].dst)
    if IPv6 is not None and pkt.haslayer(IPv6):
        return str(pkt[IPv6].src), str(pkt[IPv6].dst)
    if ARP is not None and pkt.haslayer(ARP):
        try:
            return str(getattr(pkt[ARP], "psrc", "0.0.0.0") or "0.0.0.0"), str(getattr(pkt[ARP], "pdst", "0.0.0.0") or "0.0.0.0")
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


def _safe_dns_attr(dns_layer, attr: str, default=None):
    try:
        return getattr(dns_layer, attr)
    except Exception:
        return default


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

        match = re.match(r"^(?:EHLO|HELO|LHLO)\s+([A-Za-z0-9._-]{1,253})", line_text, re.IGNORECASE)
        if match:
            _add(match.group(1), "SMTP HELO/EHLO", "MEDIUM")

        match = re.match(r"^220(?:[\s-]+)([A-Za-z0-9._-]{1,253})", line_text, re.IGNORECASE)
        if match:
            _add(match.group(1), "SMTP server banner", "MEDIUM")

        match = re.match(r"^\*\s+OK\s+([A-Za-z0-9._-]{1,253})", line_text, re.IGNORECASE)
        if match:
            _add(match.group(1), "IMAP server banner", "LOW")

        match = re.match(r"^\+OK\s+([A-Za-z0-9._-]{1,253})", line_text, re.IGNORECASE)
        if match:
            _add(match.group(1), "POP server banner", "LOW")

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


def _extract_dhcp_hostnames(pkt, src_ip: str, dst_ip: str) -> list[tuple[str, str, str, str, str]]:
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

    requested_ip = _decode_name(option_map.get("requested_addr", option_map.get("requested-address", "")))

    mapped_candidates: list[str] = []
    if bootp_layer is not None:
        mapped_candidates.extend([
            str(getattr(bootp_layer, "ciaddr", "") or ""),
            str(getattr(bootp_layer, "yiaddr", "") or ""),
        ])
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
            results.append((candidate, method, confidence, mapped_ip, f"DHCP option '{key}' value observed"))

    return results


def _extract_tls_certificate_hostnames(pkt, payload: bytes) -> list[tuple[str, str, str]]:
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

    for san in re.findall(r"(?:DNS:|dNSName\s*=\s*)([A-Za-z0-9*._-]{1,253})", text, flags=re.IGNORECASE):
        _append(san, "TLS certificate SAN", "HIGH")

    for cn in re.findall(r"(?:CN\s*=\s*|commonName\s*=\s*)([A-Za-z0-9*._-]{1,253})", text, flags=re.IGNORECASE):
        _append(cn, "TLS certificate subject CN", "MEDIUM")

    return results


def _extract_arp_hostnames(pkt, payload: bytes, src_ip: str, dst_ip: str) -> list[tuple[str, str, str, str, str]]:
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
        results.append((
            candidate,
            "ARP payload hostname token",
            "LOW",
            mapped_ip,
            f"ARP payload token observed psrc={arp_psrc} pdst={arp_pdst}",
        ))

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
            names = getattr(ext, "servernames", None) or getattr(ext, "server_names", None)
            if not names:
                continue
            for item in names:
                name = getattr(item, "servername", None) or getattr(item, "name", None) or item
                decoded = _normalize_hostname(_decode_name(name))
                if _is_valid_hostname(decoded):
                    return decoded
    except Exception:
        return None
    return None


def _parse_ntlm_type3(payload: bytes) -> tuple[Optional[str], Optional[str], Optional[str]]:
    signature = b"NTLMSSP\x00"
    idx = payload.find(signature)
    if idx == -1 or len(payload) < idx + 56:
        return None, None, None
    try:
        msg_type = int.from_bytes(payload[idx + 8:idx + 12], "little")
        if msg_type != 3:
            return None, None, None

        def _read(offset: int) -> tuple[int, int]:
            length = int.from_bytes(payload[offset:offset + 2], "little")
            field_offset = int.from_bytes(payload[offset + 4:offset + 8], "little")
            return length, field_offset

        domain_len, domain_off = _read(idx + 28)
        user_len, user_off = _read(idx + 36)
        workstation_len, workstation_off = _read(idx + 44)

        domain = payload[idx + domain_off:idx + domain_off + domain_len].decode("utf-16le", errors="ignore") if domain_len else None
        user = payload[idx + user_off:idx + user_off + user_len].decode("utf-16le", errors="ignore") if user_len else None
        workstation = payload[idx + workstation_off:idx + workstation_off + workstation_len].decode("utf-16le", errors="ignore") if workstation_len else None
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


def merge_hostname_summaries(summaries: list[HostnameSummary]) -> HostnameSummary:
    if not summaries:
        return HostnameSummary(path=Path("ALL_PCAPS_0"), target_ip=None)

    merged = HostnameSummary(path=Path(f"ALL_PCAPS_{len(summaries)}"), target_ip=summaries[0].target_ip)
    merged_map: dict[tuple[str, str, str, str, str, str, str], HostnameFinding] = {}
    seen_errors: set[str] = set()

    for summary in summaries:
        merged.total_packets += summary.total_packets
        merged.relevant_packets += summary.relevant_packets
        merged.protocol_counts.update(summary.protocol_counts)
        merged.method_counts.update(summary.method_counts)

        for finding in summary.findings:
            key = (finding.hostname, finding.mapped_ip, finding.protocol, finding.method, finding.src_ip, finding.dst_ip, finding.details)
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
                if finding.first_seen is not None and (existing.first_seen is None or finding.first_seen < existing.first_seen):
                    existing.first_seen = finding.first_seen
                if finding.last_seen is not None and (existing.last_seen is None or finding.last_seen > existing.last_seen):
                    existing.last_seen = finding.last_seen
                if finding.first_packet is not None and (existing.first_packet is None or finding.first_packet < existing.first_packet):
                    existing.first_packet = finding.first_packet
                if finding.last_packet is not None and (existing.last_packet is None or finding.last_packet > existing.last_packet):
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
    merged_context = _build_hostname_hunting_context(merged.findings)
    merged.analyst_verdict = str(merged_context.get("analyst_verdict", ""))
    merged.analyst_confidence = str(merged_context.get("analyst_confidence", "low"))
    merged.analyst_reasons = [str(v) for v in list(merged_context.get("analyst_reasons", []) or [])]
    merged.deterministic_checks = {
        str(key): [str(v) for v in list(values or [])]
        for key, values in dict(merged_context.get("deterministic_checks", {}) or {}).items()
    }
    merged.conflict_profiles = list(merged_context.get("conflict_profiles", []) or [])
    merged.drift_profiles = list(merged_context.get("drift_profiles", []) or [])
    merged.suspicious_name_profiles = list(merged_context.get("suspicious_name_profiles", []) or [])
    merged.cross_protocol_corroboration = list(merged_context.get("cross_protocol_corroboration", []) or [])
    merged.risk_matrix = [dict(item) for item in list(merged_context.get("risk_matrix", []) or []) if isinstance(item, dict)]
    merged.investigation_pivots = list(merged_context.get("investigation_pivots", []) or [])
    merged.false_positive_context = [str(v) for v in list(merged_context.get("false_positive_context", []) or [])]
    return merged


def analyze_hostname(
    path: Path,
    target_ip: str | None,
    show_status: bool = True,
    include_related: bool = False,
) -> HostnameSummary:
    summary = HostnameSummary(path=path, target_ip=target_ip)
    target_filter_enabled = bool(target_ip)
    if target_filter_enabled:
        try:
            ipaddress.ip_address(target_ip)
        except ValueError:
            summary.errors.append(f"Invalid target IP: {target_ip}")
            return summary

    findings_map: dict[tuple[str, str, str, str, str, str, str], HostnameFinding] = {}
    reverse_ptr = _target_reverse_ptr(target_ip).lower() if target_filter_enabled else ""

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)
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

            flow_relevant = target_filter_enabled and (src_ip == target_ip or dst_ip == target_ip)
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

            for host_value, method, confidence, mapped_ip, details in _extract_dhcp_hostnames(pkt, src_ip, dst_ip):
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

            if DNS is not None and pkt.haslayer(DNS):
                try:
                    dns_layer = pkt[DNS]
                except Exception:
                    dns_layer = None
                if dns_layer is not None:
                    qd = _safe_dns_attr(dns_layer, "qd", None)
                    if qd is not None:
                        qname = _decode_name(_safe_dns_attr(qd, "qname", "")).lower()
                        qtype = int(_safe_dns_attr(qd, "qtype", 0) or 0)
                        if reverse_ptr and reverse_ptr in qname and qtype == 12:
                            packet_relevant = True

                    if int(_safe_dns_attr(dns_layer, "qr", 0) or 0) == 1:
                        an = _safe_dns_attr(dns_layer, "an", None)
                        rr_count = int(_safe_dns_attr(dns_layer, "ancount", 0) or 0)
                        current = an
                        for _ in range(rr_count):
                            if current is None:
                                break
                            rr_name = _decode_name(getattr(current, "rrname", ""))
                            rr_type = int(getattr(current, "type", 0) or 0)
                            rr_data = getattr(current, "rdata", None)
                            rr_data_text = _decode_name(rr_data)

                            if rr_type in {1, 28} and (not target_filter_enabled or rr_data_text == target_ip):
                                packet_relevant = True
                                method = "DNS A/AAAA mapping"
                                port_pair = {sport, dport}
                                if 5353 in port_pair:
                                    protocol = "mDNS"
                                elif 5355 in port_pair:
                                    protocol = "LLMNR"
                                else:
                                    protocol = "DNS"
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
                            if rr_type == 12 and ((target_filter_enabled and reverse_ptr and reverse_ptr in rr_name.lower()) or (not target_filter_enabled and bool(ptr_ip))):
                                packet_relevant = True
                                method = "DNS PTR reverse lookup"
                                protocol = "DNS"
                                mapped_ip = target_ip if target_filter_enabled else ptr_ip
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

                            current = getattr(current, "payload", None)

            payload = _extract_payload(pkt)
            for host_value, method, confidence, mapped_ip, details in _extract_arp_hostnames(pkt, payload, src_ip, dst_ip):
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

                user, domain, workstation = _parse_ntlm_type3(payload)
                if workstation:
                    method = "NTLM workstation field"
                    protocol = "SMB/NTLM"
                    detail = f"NTLM auth context user={user or '-'} domain={domain or '-'}"
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
                    for host_value, method, confidence in _extract_mail_hostnames(payload):
                        mapped_ip = src_ip
                        if method == "SMTP HELO/EHLO":
                            mapped_ip = src_ip
                        elif method in {"SMTP server banner", "IMAP server banner", "POP server banner"}:
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

            for cert_hostname, method, confidence in _extract_tls_certificate_hostnames(pkt, payload):
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

    summary.findings = sorted(
        findings_map.values(),
        key=lambda item: (-item.count, item.hostname, item.method),
    )
    context = _build_hostname_hunting_context(summary.findings)
    summary.analyst_verdict = str(context.get("analyst_verdict", ""))
    summary.analyst_confidence = str(context.get("analyst_confidence", "low"))
    summary.analyst_reasons = [str(v) for v in list(context.get("analyst_reasons", []) or [])]
    summary.deterministic_checks = {
        str(key): [str(v) for v in list(values or [])]
        for key, values in dict(context.get("deterministic_checks", {}) or {}).items()
    }
    summary.conflict_profiles = list(context.get("conflict_profiles", []) or [])
    summary.drift_profiles = list(context.get("drift_profiles", []) or [])
    summary.suspicious_name_profiles = list(context.get("suspicious_name_profiles", []) or [])
    summary.cross_protocol_corroboration = list(context.get("cross_protocol_corroboration", []) or [])
    summary.risk_matrix = [dict(item) for item in list(context.get("risk_matrix", []) or []) if isinstance(item, dict)]
    summary.investigation_pivots = list(context.get("investigation_pivots", []) or [])
    summary.false_positive_context = [str(v) for v in list(context.get("false_positive_context", []) or [])]
    return summary
