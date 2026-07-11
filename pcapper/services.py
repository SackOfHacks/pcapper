from __future__ import annotations


from .utils import is_public_ip as _is_public_ip, tcp_flags_int as _tcp_flags_int
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    from scapy.layers.dns import DNS
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, Ether
    from scapy.packet import Raw
except ImportError:
    IP = TCP = UDP = Ether = IPv6 = ARP = ICMP = DNS = Raw = None

from .pcap_cache import PcapMeta, get_reader
from .utils import extract_packet_endpoints, memoize_analysis, packet_length, safe_float

import ipaddress as _ipaddress


def _is_group_address(ip: str) -> bool:
    """True for multicast / broadcast / unspecified addresses (not real hosts)."""
    if not ip:
        return True
    if ip == "255.255.255.255":
        return True
    try:
        addr = _ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(addr.is_multicast or addr.is_unspecified)


# --- Dataclasses ---


@dataclass
class ServiceAsset:
    ip: str
    port: int
    protocol: str  # TCP/UDP
    service_name: str  # e.g. "HTTP", "SSH"
    software: Optional[str] = None  # e.g. "Apache/2.4", "OpenSSH 8.2"
    packets: int = 0
    bytes: int = 0
    clients: Set[str] = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0
    handshake_confirmed: bool = False
    discovery_method: str = "observed"


@dataclass
class ServiceRisk:
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    affected_asset: str  # IP:Port


@dataclass
class ServiceSummary:
    path: Path
    total_services: int
    assets: List[ServiceAsset]
    risks: List[ServiceRisk]
    hierarchy: Dict[str, int]  # Service Name -> Count
    analyst_verdict: str = ""
    analyst_confidence: str = "low"
    analyst_reasons: List[str] = field(default_factory=list)
    deterministic_checks: Dict[str, List[str]] = field(default_factory=dict)
    service_mismatch_profiles: List[Dict[str, object]] = field(default_factory=list)
    service_drift_profiles: List[Dict[str, object]] = field(default_factory=list)
    lateral_surface_profiles: List[Dict[str, object]] = field(default_factory=list)
    boundary_exposure_profiles: List[Dict[str, object]] = field(default_factory=list)
    ot_it_crossing_profiles: List[Dict[str, object]] = field(default_factory=list)
    false_positive_context: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


_OT_SERVICE_PORTS = {
    102,    # S7 / ISO-TSAP
    502,    # Modbus
    2404,   # IEC 60870-5-104
    4000,   # OPC / various
    4840,   # OPC UA
    9600,   # OMRON FINS
    18245,  # GE-SRTP
    20000,  # DNP3
    44818,  # EtherNet/IP
    47808,  # BACnet
    34962,  # PROFINET
    34963,  # PROFINET
    34964,  # PROFINET
    5006,   # MELSEC
    5007,   # MELSEC
    1962,   # PCWorx
    2222,   # EtherNet/IP I/O (also SSH-alt; OT context)
}
_ADMIN_SERVICE_NAMES = {"SSH", "RDP", "SMB", "VNC", "Telnet", "WinRM"}

# Database / datastore services. Exposure of these is a primary IR finding:
# they hold the crown-jewel data and several ship with NO authentication by
# default (Redis, MongoDB, Elasticsearch, Memcached, CouchDB, Cassandra), so a
# reachable instance is frequently an unauthenticated, internet-leaked breach.
_DATASTORE_SERVICES = {
    "MSSQL", "MySQL", "PostgreSQL", "Oracle", "Redis", "MongoDB",
    "Elasticsearch", "Memcached", "CouchDB", "Cassandra", "Redis",
}
_UNAUTH_DEFAULT_DATASTORES = {
    "Redis", "MongoDB", "Elasticsearch", "Memcached", "CouchDB", "Cassandra",
}

# Curated banner -> (severity, reason) map for end-of-life / known-vulnerable
# server software. Deliberately conservative: each entry is software that is
# clearly EOL or carries a well-known RCE/backdoor, to avoid false positives on
# merely-not-latest versions.
_EOL_SOFTWARE_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"vsftpd\s*2\.3\.4", re.I), "CRITICAL",
     "vsftpd 2.3.4 contains a well-known backdoor (CVE-2011-2523)"),
    (re.compile(r"ProFTPD\s*1\.3\.3", re.I), "HIGH",
     "ProFTPD 1.3.3 is affected by known RCEs (e.g. CVE-2010-4221)"),
    (re.compile(r"OpenSSH[_/ ]([0-5]\.\d+|6\.\d+)", re.I), "MEDIUM",
     "Legacy OpenSSH (<7.x) — multiple known vulnerabilities, end-of-life"),
    (re.compile(r"Apache/(1\.|2\.0\.|2\.2\.)", re.I), "HIGH",
     "End-of-life Apache httpd (1.x/2.0/2.2) — no security updates"),
    (re.compile(r"Microsoft-IIS/([0-6]\.)", re.I), "HIGH",
     "End-of-life Microsoft IIS (<=6.0) — no security updates"),
    (re.compile(r"nginx/(0\.|1\.[0-9]\.)", re.I), "MEDIUM",
     "Legacy nginx (<1.10) — end-of-life branch"),
    (re.compile(r"\bPHP/[45]\.", re.I), "HIGH",
     "End-of-life PHP (4.x/5.x) exposed in Server header"),
    (re.compile(r"Exim\s*4\.[0-8]\d?\b", re.I), "MEDIUM",
     "Legacy Exim (<4.90) — multiple known RCEs"),
    (re.compile(r"(?:OpenSSL/)(0\.|1\.0\.)", re.I), "MEDIUM",
     "End-of-life OpenSSL (<1.1) advertised in banner"),
]


def _assess_software_risk(software: str) -> Optional[tuple[str, str]]:
    """Return (severity, reason) when a service banner advertises EOL or
    known-vulnerable software, else None."""
    text = str(software or "")
    if not text:
        return None
    for pattern, severity, reason in _EOL_SOFTWARE_PATTERNS:
        if pattern.search(text):
            return severity, f"{reason}. Banner: {text[:120]}"
    return None


def _build_services_enrichment(
    assets: List[ServiceAsset], risks: List[ServiceRisk]
) -> Dict[str, object]:
    checks: Dict[str, List[str]] = defaultdict(list)

    # Map the analyzer's curated ServiceRisk findings to triage check buckets.
    for risk in risks or []:
        title = str(getattr(risk, "title", ""))
        sev = str(getattr(risk, "severity", "")).upper()
        ev = f"{getattr(risk, 'affected_asset', '?')}: {title} — {getattr(risk, 'description', '')}"
        if title == "Public Admin Service":
            checks["public_edge_admin_exposure"].append(ev)
        elif title in ("Internet-Exposed Database", "Exposed Datastore (no-auth-by-default)"):
            checks["exposed_datastores"].append(ev)
        elif title == "Potential UDP Amplification":
            checks["udp_amplification_readiness"].append(ev)
        elif title == "Non-Standard Port":
            checks["service_identity_mismatch"].append(ev)
        else:
            checks["legacy_or_weak_service_hygiene"].append(ev)

    # Asset-derived context (not scored on its own — surfaces attack surface).
    ot_assets: List[str] = []
    it_admin_assets: List[str] = []
    admin_ports_by_host: Dict[str, Set[int]] = defaultdict(set)
    ot_ports_by_host: Dict[str, Set[int]] = defaultdict(set)
    boundary_exposure_profiles: List[Dict[str, object]] = []
    for asset in assets or []:
        name = str(getattr(asset, "service_name", ""))
        port = int(getattr(asset, "port", 0) or 0)
        ip = str(getattr(asset, "ip", "?"))
        clients = len(getattr(asset, "clients", []) or [])
        if port in _OT_SERVICE_PORTS:
            ot_assets.append(f"{ip}:{port} ({name})")
            ot_ports_by_host[ip].add(port)
        if any(a in name for a in _ADMIN_SERVICE_NAMES):
            it_admin_assets.append(f"{ip}:{port} ({name})")
            admin_ports_by_host[ip].add(port)
            checks["lateral_admin_surface"].append(
                f"{ip}:{port} {name} — {clients} client(s)"
            )
        # Internet-facing attack surface: any service bound to a public IP.
        if _is_public_ip(ip):
            boundary_exposure_profiles.append(
                {
                    "asset": f"{ip}:{port}",
                    "service": name,
                    "clients": clients,
                    "packets": int(getattr(asset, "packets", 0) or 0),
                }
            )
            checks["internet_exposed_surface"].append(f"{ip}:{port} ({name})")

    # OT/IT boundary mix: an IT admin service and an OT service observed in the
    # same capture is a segmentation red flag (engineering access reachable from
    # the IT side). Only fires when BOTH are genuinely present.
    if ot_assets and it_admin_assets:
        for a in ot_assets[:5]:
            checks["ot_it_boundary_mix"].append(f"OT service: {a}")
        for a in it_admin_assets[:5]:
            checks["ot_it_boundary_mix"].append(f"IT admin service: {a}")

    provenance = []
    if assets:
        provenance.append(f"discovered services ({len(assets)})")
    if risks:
        provenance.append(f"service risks ({len(risks)})")
    if provenance:
        checks["evidence_provenance"].append("; ".join(provenance))

    crit_count = sum(1 for r in (risks or []) if str(r.severity).upper() == "CRITICAL")
    high_count = sum(1 for r in (risks or []) if str(r.severity).upper() == "HIGH")

    score = 0
    reasons: List[str] = []
    if checks.get("exposed_datastores"):
        score += 3
        reasons.append(
            f"Database/datastore exposure ({len(checks['exposed_datastores'])}) "
            "— crown-jewel data reachable"
        )
    if checks.get("public_edge_admin_exposure"):
        score += 3
        reasons.append("Administrative service exposed on a public IP")
    if crit_count:
        score += 3
        reasons.append(f"Critical service risk(s): {crit_count} (e.g. internet-exposed DB / backdoored software)")
    # Cleartext credential protocols (Telnet/FTP/TFTP) are rated HIGH by the
    # analyzer; cleartext HTTP and other MEDIUM items stay context-only so an
    # ordinary web/SNMP capture does not produce a verdict.
    if high_count:
        score += 2
        reasons.append(f"High-severity service risk(s): {high_count} (e.g. cleartext credential services / EOL software)")
    if checks.get("ot_it_boundary_mix"):
        score += 2
        reasons.append("OT and IT administrative services observed together (segmentation risk)")

    if score >= 6:
        verdict = "YES - high-confidence service-exposure risk (public admin access / critical exposure) is present."
        confidence = "high"
    elif score >= 4:
        verdict = "LIKELY - significant service-exposure risk is present."
        confidence = "medium"
    elif score >= 2:
        verdict = "POSSIBLE - notable service-exposure risk observed; review the affected assets."
        confidence = "low"
    elif score >= 1:
        verdict = "LOW SIGNAL - minor service-hygiene findings present."
        confidence = "low"
    else:
        verdict = ""
        confidence = "low"
    if not reasons and verdict:
        reasons.append("Service-risk heuristics crossed threshold")

    # Lateral-movement surface: hosts presenting >=2 admin/remote-access ports.
    lateral_surface_profiles: List[Dict[str, object]] = []
    for host, ports in sorted(admin_ports_by_host.items()):
        if len(ports) >= 2:
            lateral_surface_profiles.append(
                {
                    "host": host,
                    "admin_ports": sorted(ports),
                    "admin_port_count": len(ports),
                    "confidence": "high" if len(ports) >= 3 else "medium",
                }
            )

    # OT/IT crossing: a single host presenting BOTH an OT service and an IT
    # admin service is a dual-homed engineering-access red flag.
    ot_it_crossing_profiles: List[Dict[str, object]] = []
    for host in sorted(set(admin_ports_by_host) & set(ot_ports_by_host)):
        ot_it_crossing_profiles.append(
            {
                "host": host,
                "ot_ports": sorted(ot_ports_by_host[host]),
                "admin_ports": sorted(admin_ports_by_host[host]),
                "confidence": "high",
            }
        )

    # Service identity mismatch: protocols seen on non-standard ports.
    service_mismatch_profiles: List[Dict[str, object]] = []
    for risk in risks or []:
        if str(getattr(risk, "title", "")) == "Non-Standard Port":
            service_mismatch_profiles.append(
                {
                    "asset": str(getattr(risk, "affected_asset", "-")),
                    "service": str(getattr(risk, "description", "-")),
                    "software": "-",
                    "reasons": ["service observed on non-standard port"],
                }
            )

    return {
        "analyst_verdict": verdict,
        "analyst_confidence": confidence,
        "analyst_reasons": reasons,
        "deterministic_checks": {k: list(dict.fromkeys(v)) for k, v in checks.items()},
        "boundary_exposure_profiles": boundary_exposure_profiles,
        "lateral_surface_profiles": lateral_surface_profiles,
        "ot_it_crossing_profiles": ot_it_crossing_profiles,
        "service_mismatch_profiles": service_mismatch_profiles,
    }

def merge_services_summaries(
    summaries: List[ServiceSummary] | Tuple[ServiceSummary, ...] | Set[ServiceSummary],
) -> ServiceSummary:
    summary_list = list(summaries)
    if not summary_list:
        return ServiceSummary(
            path=Path("ALL_PCAPS_0"),
            total_services=0,
            assets=[],
            risks=[],
            hierarchy={},
            analyst_verdict="",
            analyst_confidence="low",
            analyst_reasons=[],
            deterministic_checks={},
            service_mismatch_profiles=[],
            service_drift_profiles=[],
            lateral_surface_profiles=[],
            boundary_exposure_profiles=[],
            ot_it_crossing_profiles=[],
            false_positive_context=[],
            errors=[],
        )

    assets_map: Dict[Tuple[str, int, str], ServiceAsset] = {}
    risks: List[ServiceRisk] = []
    hierarchy: Counter[str] = Counter()
    errors: List[str] = []

    for summary in summary_list:
        risks.extend(summary.risks)
        hierarchy.update(summary.hierarchy)
        errors.extend(summary.errors)
        for asset in summary.assets:
            key = (asset.ip, asset.port, asset.protocol)
            existing = assets_map.get(key)
            if existing is None:
                assets_map[key] = ServiceAsset(
                    ip=asset.ip,
                    port=asset.port,
                    protocol=asset.protocol,
                    service_name=asset.service_name,
                    software=asset.software,
                    packets=asset.packets,
                    bytes=asset.bytes,
                    clients=set(asset.clients),
                    first_seen=asset.first_seen,
                    last_seen=asset.last_seen,
                    handshake_confirmed=bool(asset.handshake_confirmed),
                    discovery_method=str(asset.discovery_method or "observed"),
                )
            else:
                existing.packets += asset.packets
                existing.bytes += asset.bytes
                existing.clients.update(asset.clients)
                existing.first_seen = min(existing.first_seen, asset.first_seen)
                existing.last_seen = max(existing.last_seen, asset.last_seen)
                if not existing.software and asset.software:
                    existing.software = asset.software
                existing.handshake_confirmed = (
                    existing.handshake_confirmed or bool(asset.handshake_confirmed)
                )
                if (
                    str(existing.discovery_method or "").lower() != "handshake_confirmed"
                    and str(asset.discovery_method or "").lower()
                    == "handshake_confirmed"
                ):
                    existing.discovery_method = "handshake_confirmed"

    assets = sorted(
        assets_map.values(),
        key=lambda item: (item.ip, item.port, item.protocol),
    )

    context = _build_services_enrichment(assets, risks)

    return ServiceSummary(
        path=Path("ALL_PCAPS"),
        total_services=len(assets),
        assets=assets,
        risks=risks,
        hierarchy=dict(hierarchy),
        analyst_verdict=str(context.get("analyst_verdict", "")),
        analyst_confidence=str(context.get("analyst_confidence", "low")),
        analyst_reasons=[
            str(v) for v in list(context.get("analyst_reasons", []) or [])
        ],
        deterministic_checks={
            str(key): [str(v) for v in list(values or [])]
            for key, values in dict(
                context.get("deterministic_checks", {}) or {}
            ).items()
        },
        service_mismatch_profiles=list(
            context.get("service_mismatch_profiles", []) or []
        ),
        service_drift_profiles=list(context.get("service_drift_profiles", []) or []),
        lateral_surface_profiles=list(
            context.get("lateral_surface_profiles", []) or []
        ),
        boundary_exposure_profiles=list(
            context.get("boundary_exposure_profiles", []) or []
        ),
        ot_it_crossing_profiles=list(context.get("ot_it_crossing_profiles", []) or []),
        false_positive_context=[
            str(v) for v in list(context.get("false_positive_context", []) or [])
        ],
        errors=errors,
    )


# --- Constants ---

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    69: "TFTP",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    123: "NTP",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    514: "Syslog",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    27017: "MongoDB",
    27018: "MongoDB",
    11211: "Memcached",
    5984: "CouchDB",
    9042: "Cassandra",
    500: "IKE",
    4500: "IPsec NAT-T",
    1194: "OpenVPN",
    51820: "WireGuard",
    1701: "L2TP",
    1723: "PPTP",
    853: "DoT",
    784: "QUIC",
    4433: "QUIC",
    102: "S7/MMS/ICCP",
    319: "PTP Event",
    320: "PTP General",
    502: "Modbus/TCP",
    9600: "FINS",
    20000: "DNP3",
    2404: "IEC-104",
    47808: "BACnet/IP",
    44818: "EtherNet/IP",
    2222: "ENIP-IO",
    2221: "CIP Security",
    34962: "PROFINET",
    34963: "PROFINET",
    34964: "PROFINET",
    4840: "OPC UA",
    789: "Crimson",
    1911: "Niagara Fox",
    4911: "Niagara Fox",
    5094: "HART-IP",
    18245: "GE SRTP",
    18246: "GE SRTP",
    20547: "ProConOS",
    1962: "PCWorx",
    5006: "MELSEC",
    5007: "MELSEC",
    5683: "CoAP",
    5684: "CoAP",
    2455: "ODESYS",
    1217: "ODESYS",
    1883: "MQTT",
    8883: "MQTT-TLS",
    34378: "Yokogawa Vnet/IP",
    34379: "Yokogawa Vnet/IP",
    34380: "Yokogawa Vnet/IP",
}

# --- Logic ---


def _get_banner(payload: bytes, port: int) -> Optional[str]:
    # Try different decode
    try:
        text = payload.decode("utf-8", errors="ignore")
    except UnicodeDecodeError:
        return None

    if not text:
        return None

    # SSH
    if port == 22 or text.startswith("SSH-"):
        m = re.match(r"(SSH-[\d.]+-[\w_.]+)", text)
        if m:
            return m.group(1)

    # HTTP Server
    if port in (80, 8080, 8000) or "HTTP/" in text:
        # Response header?
        m = re.search(r"Server:\s*([^\r\n]+)", text, re.IGNORECASE)
        if m:
            return m.group(1).strip()

    # FTP / SMTP
    if port in (21, 25) or text.startswith("220 "):
        if text.startswith("220 "):
            return text[4:].strip()

    return None


def _guess_service(payload: bytes, port: int) -> tuple[Optional[str], Optional[str]]:
    try:
        text = payload.decode("utf-8", errors="ignore")
    except Exception:
        return None, None

    if not text:
        return None, None

    if text.startswith("SSH-"):
        banner = _get_banner(payload, port)
        return "SSH", banner

    if text.startswith("HTTP/") or "HTTP/" in text[:16] or "Server:" in text:
        banner = _get_banner(payload, port)
        return "HTTP", banner

    if text.startswith("220 "):
        banner = _get_banner(payload, port)
        if "SMTP" in text.upper() or port == 25:
            return "SMTP", banner
        return "FTP", banner

    return None, None


def _tcp_is_syn(flags: object) -> bool:
    value = _tcp_flags_int(flags)
    return bool(value & 0x02) and not bool(value & 0x10)


def _tcp_is_synack(flags: object) -> bool:
    value = _tcp_flags_int(flags)
    return bool(value & 0x02) and bool(value & 0x10)


def _tcp_is_rst(flags: object) -> bool:
    value = _tcp_flags_int(flags)
    return bool(value & 0x04)


def _tcp_is_final_handshake_ack(flags: object) -> bool:
    value = _tcp_flags_int(flags)
    # Final handshake ACK must include ACK and exclude SYN/RST/FIN.
    return (
        bool(value & 0x10)
        and not bool(value & 0x02)
        and not bool(value & 0x04)
        and not bool(value & 0x01)
    )


def _tcp_payload_length(ip_layer: object, tcp_layer: object) -> int:
    try:
        tcp_hlen = int(getattr(tcp_layer, "dataofs", 0) or 0) * 4
        if tcp_hlen <= 0:
            tcp_hlen = 20

        if hasattr(ip_layer, "ihl") and hasattr(ip_layer, "len"):
            ip_hlen = int(getattr(ip_layer, "ihl", 0) or 0) * 4
            total = int(getattr(ip_layer, "len", 0) or 0)
            if ip_hlen > 0 and total > 0:
                return max(0, total - ip_hlen - tcp_hlen)

        if hasattr(ip_layer, "plen"):
            plen = int(getattr(ip_layer, "plen", 0) or 0)
            if plen > 0:
                return max(0, plen - tcp_hlen)
    except Exception:
        pass
    try:
        return len(bytes(getattr(tcp_layer, "payload", b"") or b""))
    except Exception:
        return 0


def _tcp_payload_bytes(ip_layer: object, tcp_layer: object) -> bytes:
    length = _tcp_payload_length(ip_layer, tcp_layer)
    if length <= 0:
        return b""
    try:
        payload = bytes(getattr(tcp_layer, "payload", b"") or b"")
    except Exception:
        return b""
    if not payload:
        return b""
    return payload[:length]


def _canonical_tcp_pair(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
) -> tuple[tuple[str, int, str, int], bool]:
    left = (src_ip, src_port)
    right = (dst_ip, dst_port)
    if left <= right:
        return (src_ip, src_port, dst_ip, dst_port), True
    return (dst_ip, dst_port, src_ip, src_port), False


def _infer_server_from_seen_traffic(
    a_ip: str,
    a_port: int,
    b_ip: str,
    b_port: int,
    syn_ab: int,
    syn_ba: int,
) -> Optional[tuple[str, int, str]]:
    # Prefer direct SYN direction when available: SYN sender is client.
    if syn_ab > 0 and syn_ba == 0:
        return b_ip, b_port, a_ip
    if syn_ba > 0 and syn_ab == 0:
        return a_ip, a_port, b_ip

    a_known = a_port in COMMON_PORTS
    b_known = b_port in COMMON_PORTS
    if a_known and not b_known:
        return a_ip, a_port, b_ip
    if b_known and not a_known:
        return b_ip, b_port, a_ip

    if a_port <= 1024 and b_port >= 49152:
        return a_ip, a_port, b_ip
    if b_port <= 1024 and a_port >= 49152:
        return b_ip, b_port, a_ip

    return None


def _seen_traffic_supports_service_presence(
    flow_stats: Dict[str, object],
    server_is_left: bool,
) -> bool:
    packets_server = int(
        flow_stats.get("packets_ab" if server_is_left else "packets_ba", 0) or 0
    )
    packets_client = int(
        flow_stats.get("packets_ba" if server_is_left else "packets_ab", 0) or 0
    )
    payload_server = int(
        flow_stats.get("payload_bytes_ab" if server_is_left else "payload_bytes_ba", 0)
        or 0
    )

    # Must be genuinely bidirectional and not just scanner-only probing noise.
    if packets_server <= 0 or packets_client <= 0:
        return False

    # Strong signal: server actually sent payload/application bytes.
    if payload_server > 0:
        return True

    return False


@memoize_analysis
def analyze_services(
    path: Path,
    show_status: bool = True,
    filter_ip: Optional[str] = None,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> ServiceSummary:
    if IP is None and IPv6 is None:
        return ServiceSummary(path, 0, [], [], {}, errors=["Scapy unavailable"])

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path, packets=packets, meta=meta, show_status=show_status
        )
    except Exception as exc:
        return ServiceSummary(path, 0, [], [], {}, errors=[f"Error: {exc}"])
    size_bytes = size_bytes

    # Map: (IP, Port, Proto) -> ServiceAsset
    services: Dict[Tuple[str, int, str], ServiceAsset] = {}
    risks: List[ServiceRisk] = []
    errors: List[str] = []
    cleartext_hits: Dict[Tuple[str, str], Set[int]] = defaultdict(set)
    nonstandard_hits: Dict[Tuple[str, str], Set[int]] = defaultdict(set)

    # Track full 3-way handshakes so only confirmed open TCP services are reported.
    syn_seen: Set[Tuple[str, str, int, int]] = set()
    syn_ack_seen: Set[Tuple[str, str, int, int]] = set()
    handshake_complete: Set[Tuple[str, str, int, int]] = set()
    seen_tcp_flows: Dict[Tuple[str, int, str, int], Dict[str, object]] = {}

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            ts = safe_float(getattr(pkt, "time", 0))
            src, dst = extract_packet_endpoints(pkt, include_arp=False)
            if not src or not dst:
                continue
            if IP in pkt:
                ip_layer = pkt[IP]
            elif IPv6 in pkt:
                ip_layer = pkt[IPv6]
            else:
                continue

            pkt_len = packet_length(pkt)

            # TCP
            if TCP in pkt:
                tcp = pkt[TCP]
                sport = int(getattr(tcp, "sport", 0) or 0)
                dport = int(getattr(tcp, "dport", 0) or 0)
                flags = tcp.flags

                flow_key = (src, dst, sport, dport)
                reverse_key = (dst, src, dport, sport)
                pair_key, src_is_left = _canonical_tcp_pair(src, sport, dst, dport)
                flow_stats = seen_tcp_flows.get(pair_key)
                if flow_stats is None:
                    flow_stats = {
                        "packets_ab": 0,
                        "packets_ba": 0,
                        "bytes_ab": 0,
                        "bytes_ba": 0,
                        "syn_ab": 0,
                        "syn_ba": 0,
                        "payload_samples_ab": [],
                        "payload_samples_ba": [],
                        "first_seen": ts,
                        "last_seen": ts,
                    }
                    seen_tcp_flows[pair_key] = flow_stats
                if src_is_left:
                    flow_stats["packets_ab"] = int(flow_stats["packets_ab"]) + 1
                    flow_stats["bytes_ab"] = int(flow_stats["bytes_ab"]) + pkt_len
                else:
                    flow_stats["packets_ba"] = int(flow_stats["packets_ba"]) + 1
                    flow_stats["bytes_ba"] = int(flow_stats["bytes_ba"]) + pkt_len
                payload = _tcp_payload_bytes(ip_layer, tcp)
                payload_len = len(payload)
                if src_is_left:
                    flow_stats["payload_bytes_ab"] = (
                        int(flow_stats.get("payload_bytes_ab", 0) or 0) + payload_len
                    )
                else:
                    flow_stats["payload_bytes_ba"] = (
                        int(flow_stats.get("payload_bytes_ba", 0) or 0) + payload_len
                    )
                if _tcp_is_rst(flags):
                    if src_is_left:
                        flow_stats["rst_ab"] = int(flow_stats.get("rst_ab", 0) or 0) + 1
                    else:
                        flow_stats["rst_ba"] = int(flow_stats.get("rst_ba", 0) or 0) + 1
                flow_stats["last_seen"] = ts

                if _tcp_is_syn(flags):
                    syn_seen.add(flow_key)
                    if src_is_left:
                        flow_stats["syn_ab"] = int(flow_stats["syn_ab"]) + 1
                    else:
                        flow_stats["syn_ba"] = int(flow_stats["syn_ba"]) + 1
                elif _tcp_is_synack(flags):
                    if reverse_key in syn_seen:
                        syn_ack_seen.add(reverse_key)
                elif _tcp_is_final_handshake_ack(flags):
                    if flow_key in syn_seen and flow_key in syn_ack_seen:
                        handshake_complete.add(flow_key)

                server_ip: Optional[str] = None
                server_port: Optional[int] = None
                client_ip: Optional[str] = None
                is_established = False
                if flow_key in handshake_complete:
                    is_established = True
                    server_ip, server_port, client_ip = dst, dport, src
                elif reverse_key in handshake_complete:
                    is_established = True
                    server_ip, server_port, client_ip = src, sport, dst

                if (
                    not is_established
                    or server_ip is None
                    or server_port is None
                    or client_ip is None
                ):
                    continue
                if filter_ip and server_ip != filter_ip:
                    continue

                k = (server_ip, server_port, "TCP")
                if k not in services:
                    s_name = COMMON_PORTS.get(server_port, f"TCP/{server_port}")
                    services[k] = ServiceAsset(
                        server_ip,
                        server_port,
                        "TCP",
                        s_name,
                        first_seen=ts,
                        last_seen=ts,
                        handshake_confirmed=True,
                        discovery_method="handshake_confirmed",
                    )
                s = services[k]
                s.clients.add(client_ip)
                s.packets += 1
                s.bytes += pkt_len
                s.last_seen = ts

                # Check payloads for banners only on handshake-confirmed TCP services.
                if payload:
                    sample_key = (
                        "payload_samples_ab" if src_is_left else "payload_samples_ba"
                    )
                    sample_list = flow_stats.get(sample_key)
                    if isinstance(sample_list, list) and len(sample_list) < 2:
                        sample_list.append(payload[:512])
                    guessed_service, banner = _guess_service(payload, server_port)
                    if not guessed_service:
                        continue
                    if guessed_service and s.service_name.startswith("TCP/"):
                        s.service_name = guessed_service
                    if banner and not s.software:
                        s.software = banner

            # UDP (stateless): the service is the side bound to the well-known
            # port. When BOTH ports are well-known the port number alone cannot
            # tell client from server -- the classic case is NTP, where the
            # client also sources from 123, so "traffic FROM a well-known port
            # is a service" misclassifies the querying client as an NTP server.
            # Use the protocol payload to recover direction: NTP's mode field is
            # 3 for a client request and 4/5 for a server/broadcast response.
            elif UDP in pkt:
                udp = pkt[UDP]
                sport = udp.sport
                dport = udp.dport

                ntp_mode: Optional[int] = None
                if sport == 123 or dport == 123:
                    try:
                        udp_payload = bytes(udp.payload)
                    except Exception:
                        udp_payload = b""
                    if udp_payload:
                        ntp_mode = udp_payload[0] & 0x07

                server_ip: Optional[str] = None
                server_port: Optional[int] = None
                client_ip: Optional[str] = None
                if ntp_mode == 3:
                    # NTP client request -> the destination is the NTP server.
                    server_ip, server_port, client_ip = dst, dport, src
                elif ntp_mode in (4, 5):
                    # NTP server/broadcast response -> the source is the server.
                    server_ip, server_port, client_ip = src, sport, dst
                elif sport in COMMON_PORTS and dport in COMMON_PORTS:
                    # Both well-known and no protocol disambiguation available:
                    # treat the destination (the side being queried) as the
                    # server rather than assuming the sender hosts the service.
                    server_ip, server_port, client_ip = dst, dport, src
                elif sport in COMMON_PORTS:
                    server_ip, server_port, client_ip = src, sport, dst
                elif dport in COMMON_PORTS:
                    server_ip, server_port, client_ip = dst, dport, src
                else:
                    continue

                if filter_ip and server_ip != filter_ip:
                    continue
                # Multicast / broadcast destinations (SSDP 239.255.255.250,
                # mDNS 224.0.0.251, LLMNR, NetBIOS/LLMNR broadcast, 255.255.255.255)
                # are group addresses, not hosts -- never record them as servers.
                if _is_group_address(server_ip):
                    continue
                k = (server_ip, server_port, "UDP")
                if k not in services:
                    s_name = COMMON_PORTS.get(server_port, f"UDP/{server_port}")
                    services[k] = ServiceAsset(
                        server_ip,
                        server_port,
                        "UDP",
                        s_name,
                        first_seen=ts,
                        last_seen=ts,
                        handshake_confirmed=False,
                        discovery_method="udp_observed",
                    )
                s = services[k]
                s.clients.add(client_ip)
                s.packets += 1
                s.bytes += pkt_len
                s.last_seen = ts

    except Exception as e:
        errors.append(str(e))
    finally:
        status.finish()
        reader.close()

    # Fallback for capture-gapped TCP sessions:
    # if handshake wasn't observed but traffic is bidirectional, infer likely service role.
    for pair_key, flow_stats in seen_tcp_flows.items():
        a_ip, a_port, b_ip, b_port = pair_key
        flow_key = (a_ip, b_ip, a_port, b_port)
        reverse_key = (b_ip, a_ip, b_port, a_port)
        if flow_key in handshake_complete or reverse_key in handshake_complete:
            continue

        packets_ab = int(flow_stats.get("packets_ab", 0) or 0)
        packets_ba = int(flow_stats.get("packets_ba", 0) or 0)
        if packets_ab <= 0 or packets_ba <= 0:
            continue

        inferred = _infer_server_from_seen_traffic(
            a_ip=a_ip,
            a_port=a_port,
            b_ip=b_ip,
            b_port=b_port,
            syn_ab=int(flow_stats.get("syn_ab", 0) or 0),
            syn_ba=int(flow_stats.get("syn_ba", 0) or 0),
        )
        if inferred is None:
            continue

        server_ip, server_port, client_ip = inferred
        server_is_left = server_ip == a_ip and server_port == a_port
        if not _seen_traffic_supports_service_presence(
            flow_stats, server_is_left=server_is_left
        ):
            continue
        if filter_ip and server_ip != filter_ip:
            continue

        k = (server_ip, server_port, "TCP")
        first_seen = float(flow_stats.get("first_seen", 0.0) or 0.0)
        last_seen = float(flow_stats.get("last_seen", 0.0) or 0.0)
        if k not in services:
            s_name = COMMON_PORTS.get(server_port, f"TCP/{server_port}")
            services[k] = ServiceAsset(
                server_ip,
                server_port,
                "TCP",
                s_name,
                first_seen=first_seen,
                last_seen=last_seen,
                handshake_confirmed=False,
                discovery_method="inferred_bidirectional",
            )
        s = services[k]
        s.clients.add(client_ip)
        s.packets += packets_ab + packets_ba
        s.bytes += int(flow_stats.get("bytes_ab", 0) or 0) + int(
            flow_stats.get("bytes_ba", 0) or 0
        )
        s.first_seen = min(float(s.first_seen or first_seen), first_seen)
        s.last_seen = max(float(s.last_seen or last_seen), last_seen)

        payload_samples = []
        for key_name in ("payload_samples_ab", "payload_samples_ba"):
            data = flow_stats.get(key_name, [])
            if isinstance(data, list):
                payload_samples.extend(
                    item for item in data if isinstance(item, (bytes, bytearray))
                )
        for sample in payload_samples:
            guessed_service, banner = _guess_service(bytes(sample), server_port)
            if guessed_service and s.service_name.startswith("TCP/"):
                s.service_name = guessed_service
            if banner and not s.software:
                s.software = banner

    # Risk Assessment
    risky_cleartext = {
        "Telnet": "HIGH",
        "FTP": "HIGH",
        "TFTP": "HIGH",
        "HTTP": "MEDIUM",
        "POP3": "MEDIUM",
        "IMAP": "MEDIUM",
        "LDAP": "MEDIUM",
        "SNMP": "MEDIUM",
        "VNC": "MEDIUM",
    }
    admin_services = {"SSH", "RDP", "SMB", "VNC", "Telnet", "WinRM"}
    udp_amplifiers = {"DNS", "NTP", "SNMP"}
    for k, asset in services.items():
        # Cleartext protocols
        if asset.service_name in risky_cleartext:
            cleartext_hits[(asset.ip, asset.service_name)].add(asset.port)

        client_count = len(asset.clients or [])

        # End-of-life / known-vulnerable server software (banner-driven).
        if asset.software:
            eol = _assess_software_risk(asset.software)
            if eol:
                severity, reason = eol
                risks.append(
                    ServiceRisk(
                        severity,
                        "Obsolete/Vulnerable Software",
                        reason,
                        f"{asset.ip}:{asset.port}",
                    )
                )

        # Database / datastore exposure. Internet-reachable datastores are a
        # top breach vector; unauthenticated-by-default stores (Redis/Mongo/
        # ES/Memcached/CouchDB/Cassandra) are high-risk even on internal IPs.
        if asset.service_name in _DATASTORE_SERVICES:
            unauth_default = asset.service_name in _UNAUTH_DEFAULT_DATASTORES
            public = _is_public_ip(asset.ip)
            if public:
                sev = "CRITICAL"
                detail = (
                    f"{asset.service_name} datastore reachable on a PUBLIC IP "
                    f"({client_count} client(s)). Internet-exposed databases are a "
                    "primary breach/ransomware vector"
                )
                if unauth_default:
                    detail += "; this engine ships with NO authentication by default"
                risks.append(
                    ServiceRisk(
                        sev,
                        "Internet-Exposed Database",
                        detail + ".",
                        f"{asset.ip}:{asset.port}",
                    )
                )
            elif unauth_default:
                risks.append(
                    ServiceRisk(
                        "HIGH",
                        "Exposed Datastore (no-auth-by-default)",
                        (
                            f"{asset.service_name} reachable from {client_count} "
                            "client(s). This engine has no authentication by default "
                            "— verify access controls and network segmentation."
                        ),
                        f"{asset.ip}:{asset.port}",
                    )
                )

        nonstandard_ports = {
            "HTTP": {80, 8080, 8000, 8443},
            "HTTPS": {443, 8443},
            "SSH": {22, 2222},
            "RDP": {3389},
            "SMB": {445, 139},
            "FTP": {21},
            "SMTP": {25},
        }
        for svc, ports in nonstandard_ports.items():
            if svc in asset.service_name and asset.port not in ports:
                nonstandard_hits[(asset.ip, svc)].add(asset.port)

        if _is_public_ip(asset.ip) and any(
            svc in asset.service_name for svc in admin_services
        ):
            risks.append(
                ServiceRisk(
                    "HIGH",
                    "Public Admin Service",
                    f"Administrative service {asset.service_name} exposed on a public IP.",
                    f"{asset.ip}:{asset.port}",
                )
            )

        if (
            asset.protocol == "UDP"
            and _is_public_ip(asset.ip)
            and asset.service_name in udp_amplifiers
        ):
            risks.append(
                ServiceRisk(
                    "MEDIUM",
                    "Potential UDP Amplification",
                    f"Public {asset.service_name} over UDP can be abused for amplification if open.",
                    f"{asset.ip}:{asset.port}",
                )
            )

    for (ip_value, svc), ports in cleartext_hits.items():
        port_list = ", ".join(str(port) for port in sorted(ports))
        details = f"Unencrypted {svc} service detected. Credentials/Data at risk."
        if port_list:
            details = f"{details} Ports: {port_list}."
        risks.append(
            ServiceRisk(
                risky_cleartext.get(svc, "MEDIUM"),
                "Cleartext Service",
                details,
                f"{ip_value}:{sorted(ports)[0]}",
            )
        )

    for (ip_value, svc), ports in nonstandard_hits.items():
        port_list = ", ".join(str(port) for port in sorted(ports))
        details = f"{svc} detected on non-standard ports: {port_list}."
        risks.append(
            ServiceRisk(
                "LOW",
                "Non-Standard Port",
                details,
                f"{ip_value}:{sorted(ports)[0]}",
            )
        )

    # Hierarchy
    hier = Counter()
    for s in services.values():
        hier[s.service_name] += 1

    assets_sorted = sorted(list(services.values()), key=lambda x: x.ip)
    context = _build_services_enrichment(assets_sorted, risks)

    return ServiceSummary(
        path=path,
        total_services=len(services),
        assets=assets_sorted,
        risks=risks,
        hierarchy=dict(hier),
        analyst_verdict=str(context.get("analyst_verdict", "")),
        analyst_confidence=str(context.get("analyst_confidence", "low")),
        analyst_reasons=[
            str(v) for v in list(context.get("analyst_reasons", []) or [])
        ],
        deterministic_checks={
            str(key): [str(v) for v in list(values or [])]
            for key, values in dict(
                context.get("deterministic_checks", {}) or {}
            ).items()
        },
        service_mismatch_profiles=list(
            context.get("service_mismatch_profiles", []) or []
        ),
        service_drift_profiles=list(context.get("service_drift_profiles", []) or []),
        lateral_surface_profiles=list(
            context.get("lateral_surface_profiles", []) or []
        ),
        boundary_exposure_profiles=list(
            context.get("boundary_exposure_profiles", []) or []
        ),
        ot_it_crossing_profiles=list(context.get("ot_it_crossing_profiles", []) or []),
        false_positive_context=[
            str(v) for v in list(context.get("false_positive_context", []) or [])
        ],
        errors=errors,
    )
