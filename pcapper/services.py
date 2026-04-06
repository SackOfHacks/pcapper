from __future__ import annotations

from collections import defaultdict, Counter
from dataclasses import dataclass, field
import ipaddress
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import re

try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.dns import DNS
    from scapy.packet import Raw
except ImportError:
    IP = TCP = UDP = Ether = IPv6 = ARP = ICMP = DNS = Raw = None

from .pcap_cache import PcapMeta, get_reader
from .utils import safe_float

# --- Dataclasses ---

@dataclass
class ServiceAsset:
    ip: str
    port: int
    protocol: str # TCP/UDP
    service_name: str # e.g. "HTTP", "SSH"
    software: Optional[str] = None # e.g. "Apache/2.4", "OpenSSH 8.2"
    packets: int = 0
    bytes: int = 0
    clients: Set[str] = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0

@dataclass
class ServiceRisk:
    severity: str # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    affected_asset: str # IP:Port

@dataclass
class ServiceSummary:
    path: Path
    total_services: int
    assets: List[ServiceAsset]
    risks: List[ServiceRisk]
    hierarchy: Dict[str, int] # Service Name -> Count
    analyst_verdict: str = ""
    analyst_confidence: str = "low"
    analyst_reasons: List[str] = field(default_factory=list)
    deterministic_checks: Dict[str, List[str]] = field(default_factory=dict)
    service_mismatch_profiles: List[Dict[str, object]] = field(default_factory=list)
    service_drift_profiles: List[Dict[str, object]] = field(default_factory=list)
    lateral_surface_profiles: List[Dict[str, object]] = field(default_factory=list)
    boundary_exposure_profiles: List[Dict[str, object]] = field(default_factory=list)
    ot_it_crossing_profiles: List[Dict[str, object]] = field(default_factory=list)
    investigation_pivots: List[Dict[str, object]] = field(default_factory=list)
    risk_matrix: List[Dict[str, str]] = field(default_factory=list)
    false_positive_context: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def _is_public_ip(value: str) -> bool:
    try:
        ip_addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip_addr.is_global


def _build_services_hunting_context(assets: List[ServiceAsset], risks: List[ServiceRisk]) -> Dict[str, object]:
    checks: Dict[str, List[str]] = {
        "service_identity_mismatch": [],
        "rare_or_newly_exposed_service": [],
        "lateral_admin_surface": [],
        "public_edge_admin_exposure": [],
        "service_drift_or_churn": [],
        "beacon_or_periodic_service_profile": [],
        "ot_it_boundary_mix": [],
        "udp_amplification_readiness": [],
        "legacy_or_weak_service_hygiene": [],
        "evidence_provenance": [],
    }

    mismatch_profiles: List[Dict[str, object]] = []
    drift_profiles: List[Dict[str, object]] = []
    lateral_profiles: List[Dict[str, object]] = []
    boundary_profiles: List[Dict[str, object]] = []
    ot_it_profiles: List[Dict[str, object]] = []
    pivots: List[Dict[str, object]] = []

    by_ip: Dict[str, List[ServiceAsset]] = defaultdict(list)
    by_ip_service: Dict[Tuple[str, str], List[ServiceAsset]] = defaultdict(list)
    for asset in assets:
        by_ip[str(asset.ip)].append(asset)
        by_ip_service[(str(asset.ip), str(asset.service_name).lower())].append(asset)

    admin_names = {"ssh", "rdp", "smb", "vnc", "telnet", "winrm"}
    udp_amplifiers = {"dns", "ntp", "snmp"}
    ot_ports = {102, 502, 20000, 2404, 44818, 2222, 34962, 34963, 34964, 47808, 4840}

    for ip_value, host_assets in by_ip.items():
        admin_ports: List[int] = []
        ot_seen: List[int] = []
        for asset in host_assets:
            svc_name = str(asset.service_name or "").lower()
            software = str(asset.software or "")
            if svc_name in admin_names:
                admin_ports.append(int(asset.port))
            if int(asset.port) in ot_ports:
                ot_seen.append(int(asset.port))

            software_l = software.lower()
            mismatch = False
            reasons: List[str] = []
            if software:
                if "ssh" in software_l and "ssh" not in svc_name:
                    mismatch = True
                    reasons.append("banner_ssh_vs_service")
                if "http" in software_l and "http" not in svc_name and "https" not in svc_name:
                    mismatch = True
                    reasons.append("banner_http_vs_service")
                if "smtp" in software_l and "smtp" not in svc_name:
                    mismatch = True
                    reasons.append("banner_smtp_vs_service")
            if mismatch:
                checks["service_identity_mismatch"].append(
                    f"{asset.ip}:{asset.port}/{asset.protocol} service={asset.service_name} banner={software}"
                )
                mismatch_profiles.append(
                    {
                        "asset": f"{asset.ip}:{asset.port}/{asset.protocol}",
                        "service": asset.service_name,
                        "software": software,
                        "reasons": reasons,
                    }
                )

            if asset.service_name.startswith("TCP/") or asset.service_name.startswith("UDP/"):
                checks["rare_or_newly_exposed_service"].append(
                    f"{asset.ip}:{asset.port}/{asset.protocol} unclassified service label={asset.service_name}"
                )

            duration = max(0.0, float(asset.last_seen or 0.0) - float(asset.first_seen or 0.0))
            pps = (float(asset.packets) / duration) if duration > 0 else 0.0
            if duration >= 900 and asset.packets >= 30 and pps <= 0.2:
                checks["beacon_or_periodic_service_profile"].append(
                    f"{asset.ip}:{asset.port}/{asset.protocol} packets={asset.packets} duration={duration:.1f}s pps={pps:.3f}"
                )

            if _is_public_ip(asset.ip) and svc_name in admin_names:
                checks["public_edge_admin_exposure"].append(
                    f"public {asset.ip}:{asset.port}/{asset.protocol} exposes {asset.service_name}"
                )
                boundary_profiles.append(
                    {
                        "asset": f"{asset.ip}:{asset.port}/{asset.protocol}",
                        "service": asset.service_name,
                        "clients": len(asset.clients),
                        "packets": asset.packets,
                    }
                )

            if asset.protocol.upper() == "UDP" and _is_public_ip(asset.ip) and svc_name in udp_amplifiers:
                checks["udp_amplification_readiness"].append(
                    f"public UDP amplifier candidate {asset.ip}:{asset.port} service={asset.service_name} clients={len(asset.clients)}"
                )

            checks["evidence_provenance"].append(
                f"asset={asset.ip}:{asset.port}/{asset.protocol} first={asset.first_seen:.3f} last={asset.last_seen:.3f} packets={asset.packets} bytes={asset.bytes}"
            )

        unique_admin_ports = sorted(set(admin_ports))
        if len(unique_admin_ports) >= 3:
            checks["lateral_admin_surface"].append(
                f"{ip_value} exposes admin ports {','.join(str(v) for v in unique_admin_ports)}"
            )
            lateral_profiles.append(
                {
                    "host": ip_value,
                    "admin_port_count": len(unique_admin_ports),
                    "admin_ports": unique_admin_ports,
                    "confidence": "high" if len(unique_admin_ports) >= 5 else "medium",
                }
            )

        if ot_seen and unique_admin_ports:
            checks["ot_it_boundary_mix"].append(
                f"{ip_value} mixes OT ports {','.join(str(v) for v in sorted(set(ot_seen))[:6])} with admin ports"
            )
            ot_it_profiles.append(
                {
                    "host": ip_value,
                    "ot_ports": sorted(set(ot_seen)),
                    "admin_ports": unique_admin_ports,
                    "confidence": "high" if len(ot_seen) >= 2 and len(unique_admin_ports) >= 2 else "medium",
                }
            )

    for (ip_value, svc_name), svc_assets in by_ip_service.items():
        if len(svc_assets) < 2:
            continue
        unique_ports = sorted({int(item.port) for item in svc_assets})
        unique_banners = sorted({str(item.software or "").strip() for item in svc_assets if str(item.software or "").strip()})
        if len(unique_ports) >= 2 or len(unique_banners) >= 2:
            checks["service_drift_or_churn"].append(
                f"{ip_value} service={svc_name} ports={','.join(str(v) for v in unique_ports)} banners={len(unique_banners)}"
            )
            drift_profiles.append(
                {
                    "host": ip_value,
                    "service": svc_name,
                    "port_count": len(unique_ports),
                    "ports": unique_ports,
                    "banner_count": len(unique_banners),
                    "banners": unique_banners[:5],
                }
            )

    for risk in risks:
        sev = str(risk.severity or "").upper()
        if sev in {"CRITICAL", "HIGH"}:
            checks["legacy_or_weak_service_hygiene"].append(
                f"{risk.title} on {risk.affected_asset}: {risk.description}"
            )

    scores: Dict[str, int] = defaultdict(int)
    reasons_by_host: Dict[str, List[str]] = defaultdict(list)

    def _extract_host(asset_text: str) -> str:
        return str(asset_text).split(":", 1)[0].strip()

    for item in checks["lateral_admin_surface"]:
        host = _extract_host(item)
        scores[host] += 2
        reasons_by_host[host].append("Lateral admin surface exposure")
    for item in checks["public_edge_admin_exposure"]:
        host = _extract_host(item.replace("public ", ""))
        scores[host] += 2
        reasons_by_host[host].append("Public edge admin exposure")
    for item in checks["ot_it_boundary_mix"]:
        host = _extract_host(item)
        scores[host] += 2
        reasons_by_host[host].append("OT/IT boundary mix")
    for item in checks["service_identity_mismatch"]:
        host = _extract_host(item)
        scores[host] += 1
        reasons_by_host[host].append("Service identity mismatch")
    for item in checks["service_drift_or_churn"]:
        host = _extract_host(item)
        scores[host] += 1
        reasons_by_host[host].append("Service drift/churn")

    for asset in assets:
        host = str(asset.ip)
        pivot_reasons = reasons_by_host.get(host, [])
        if not pivot_reasons:
            continue
        pivots.append(
            {
                "asset": f"{asset.ip}:{asset.port}/{asset.protocol}",
                "service": asset.service_name,
                "software": asset.software or "-",
                "clients": len(asset.clients),
                "packets": asset.packets,
                "bytes": asset.bytes,
                "first_seen": asset.first_seen,
                "last_seen": asset.last_seen,
                "reasons": list(dict.fromkeys(pivot_reasons))[:3],
            }
        )

    verdict_score = 0
    verdict_score += 2 if checks["public_edge_admin_exposure"] else 0
    verdict_score += 2 if checks["lateral_admin_surface"] else 0
    verdict_score += 2 if checks["ot_it_boundary_mix"] else 0
    verdict_score += 1 if checks["service_identity_mismatch"] else 0
    verdict_score += 1 if checks["service_drift_or_churn"] else 0
    verdict_score += 1 if checks["udp_amplification_readiness"] else 0
    verdict_score += 1 if checks["legacy_or_weak_service_hygiene"] else 0
    verdict_score += 1 if checks["beacon_or_periodic_service_profile"] else 0

    analyst_reasons: List[str] = []
    if checks["public_edge_admin_exposure"]:
        analyst_reasons.append("Public edge administrative service exposure detected")
    if checks["lateral_admin_surface"]:
        analyst_reasons.append("Hosts with broad lateral/admin service surface detected")
    if checks["ot_it_boundary_mix"]:
        analyst_reasons.append("OT and IT administrative service surfaces overlap")
    if checks["service_identity_mismatch"]:
        analyst_reasons.append("Service identity mismatch indicators detected")
    if checks["service_drift_or_churn"]:
        analyst_reasons.append("Service drift/churn indicators detected")
    if checks["legacy_or_weak_service_hygiene"]:
        analyst_reasons.append("High-severity service hygiene risks detected")

    if verdict_score >= 8:
        verdict = "YES - HIGH-CONFIDENCE SERVICE EXPOSURE/ABUSE RISK PATTERN DETECTED"
        confidence = "high"
    elif verdict_score >= 5:
        verdict = "LIKELY - MULTIPLE CORROBORATING SERVICE RISK INDICATORS DETECTED"
        confidence = "medium"
    elif verdict_score >= 2:
        verdict = "POSSIBLE - SERVICE RISK SIGNALS REQUIRE VALIDATION"
        confidence = "medium"
    else:
        verdict = "NO STRONG SIGNAL - NO CONVINCING HIGH-CONFIDENCE SERVICE ABUSE PATTERN"
        confidence = "low"

    risk_matrix: List[Dict[str, str]] = [
        {
            "category": "Service Identity Mismatch",
            "risk": "Medium" if checks["service_identity_mismatch"] else "None",
            "confidence": "Medium" if checks["service_identity_mismatch"] else "Low",
            "evidence": str(len(checks["service_identity_mismatch"])) if checks["service_identity_mismatch"] else "No matching detections",
        },
        {
            "category": "Lateral Admin Surface",
            "risk": "High" if checks["lateral_admin_surface"] else "None",
            "confidence": "High" if checks["lateral_admin_surface"] else "Low",
            "evidence": str(len(checks["lateral_admin_surface"])) if checks["lateral_admin_surface"] else "No matching detections",
        },
        {
            "category": "Public Edge Admin Exposure",
            "risk": "High" if checks["public_edge_admin_exposure"] else "None",
            "confidence": "High" if checks["public_edge_admin_exposure"] else "Low",
            "evidence": str(len(checks["public_edge_admin_exposure"])) if checks["public_edge_admin_exposure"] else "No matching detections",
        },
        {
            "category": "Service Drift/Churn",
            "risk": "Medium" if checks["service_drift_or_churn"] else "None",
            "confidence": "Medium" if checks["service_drift_or_churn"] else "Low",
            "evidence": str(len(checks["service_drift_or_churn"])) if checks["service_drift_or_churn"] else "No matching detections",
        },
        {
            "category": "OT/IT Boundary Mix",
            "risk": "Medium" if checks["ot_it_boundary_mix"] else "None",
            "confidence": "Medium" if checks["ot_it_boundary_mix"] else "Low",
            "evidence": str(len(checks["ot_it_boundary_mix"])) if checks["ot_it_boundary_mix"] else "No matching detections",
        },
        {
            "category": "UDP Amplification Readiness",
            "risk": "Medium" if checks["udp_amplification_readiness"] else "None",
            "confidence": "Medium" if checks["udp_amplification_readiness"] else "Low",
            "evidence": str(len(checks["udp_amplification_readiness"])) if checks["udp_amplification_readiness"] else "No matching detections",
        },
    ]

    false_positive_context: List[str] = []
    if not checks["service_identity_mismatch"]:
        false_positive_context.append("No strong service/banner identity mismatch crossed thresholds")
    if not checks["service_drift_or_churn"]:
        false_positive_context.append("No significant service drift/churn pattern was observed")
    if checks["lateral_admin_surface"] and not checks["public_edge_admin_exposure"]:
        false_positive_context.append("Admin surface may be expected for internal management segments")

    return {
        "analyst_verdict": verdict,
        "analyst_confidence": confidence,
        "analyst_reasons": analyst_reasons if analyst_reasons else ["No high-confidence service threat heuristic crossed threshold"],
        "deterministic_checks": checks,
        "service_mismatch_profiles": mismatch_profiles[:40],
        "service_drift_profiles": drift_profiles[:40],
        "lateral_surface_profiles": lateral_profiles[:40],
        "boundary_exposure_profiles": boundary_profiles[:40],
        "ot_it_crossing_profiles": ot_it_profiles[:40],
        "investigation_pivots": pivots[:40],
        "risk_matrix": risk_matrix,
        "false_positive_context": false_positive_context[:8],
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
            investigation_pivots=[],
            risk_matrix=[],
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
                )
            else:
                existing.packets += asset.packets
                existing.bytes += asset.bytes
                existing.clients.update(asset.clients)
                existing.first_seen = min(existing.first_seen, asset.first_seen)
                existing.last_seen = max(existing.last_seen, asset.last_seen)
                if not existing.software and asset.software:
                    existing.software = asset.software

    assets = sorted(
        assets_map.values(),
        key=lambda item: (item.ip, item.port, item.protocol),
    )

    context = _build_services_hunting_context(assets, risks)

    return ServiceSummary(
        path=Path("ALL_PCAPS"),
        total_services=len(assets),
        assets=assets,
        risks=risks,
        hierarchy=dict(hierarchy),
        analyst_verdict=str(context.get("analyst_verdict", "")),
        analyst_confidence=str(context.get("analyst_confidence", "low")),
        analyst_reasons=[str(v) for v in list(context.get("analyst_reasons", []) or [])],
        deterministic_checks={
            str(key): [str(v) for v in list(values or [])]
            for key, values in dict(context.get("deterministic_checks", {}) or {}).items()
        },
        service_mismatch_profiles=list(context.get("service_mismatch_profiles", []) or []),
        service_drift_profiles=list(context.get("service_drift_profiles", []) or []),
        lateral_surface_profiles=list(context.get("lateral_surface_profiles", []) or []),
        boundary_exposure_profiles=list(context.get("boundary_exposure_profiles", []) or []),
        ot_it_crossing_profiles=list(context.get("ot_it_crossing_profiles", []) or []),
        investigation_pivots=list(context.get("investigation_pivots", []) or []),
        risk_matrix=[dict(item) for item in list(context.get("risk_matrix", []) or []) if isinstance(item, dict)],
        false_positive_context=[str(v) for v in list(context.get("false_positive_context", []) or [])],
        errors=errors,
    )

# --- Constants ---

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 
    53: "DNS", 69: "TFTP", 80: "HTTP", 88: "Kerberos",
    110: "POP3", 123: "NTP", 135: "RPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 
    445: "SMB", 514: "Syslog", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP", 
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt", 
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
    500: "IKE", 4500: "IPsec NAT-T", 1194: "OpenVPN", 51820: "WireGuard",
    1701: "L2TP", 1723: "PPTP", 853: "DoT", 784: "QUIC", 4433: "QUIC",
    102: "S7/MMS/ICCP", 319: "PTP Event", 320: "PTP General", 502: "Modbus/TCP", 9600: "FINS", 20000: "DNP3",
    2404: "IEC-104", 47808: "BACnet/IP", 44818: "EtherNet/IP", 2222: "ENIP-IO", 2221: "CIP Security",
    34962: "PROFINET", 34963: "PROFINET", 34964: "PROFINET", 4840: "OPC UA",
    789: "Crimson", 1911: "Niagara Fox", 4911: "Niagara Fox", 5094: "HART-IP",
    18245: "GE SRTP", 18246: "GE SRTP", 20547: "ProConOS", 1962: "PCWorx",
    5006: "MELSEC", 5007: "MELSEC", 5683: "CoAP", 5684: "CoAP",
    2455: "ODESYS", 1217: "ODESYS", 1883: "MQTT", 8883: "MQTT-TLS",
    34378: "Yokogawa Vnet/IP",
    34379: "Yokogawa Vnet/IP", 34380: "Yokogawa Vnet/IP"
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

def analyze_services(
    path: Path,
    show_status: bool = True,
    filter_ip: Optional[str] = None,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> ServiceSummary:
    if IP is None:
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
    
    # To identify servers in TCP, we look for SYN-ACK (Flags=0x12) from them
    # OR we look for well-known ports responding
    # OR we look for banners
    
    # We will track provisional services if we see traffic *to* a well known port
    # But confirmed services are better.
    
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
            if IP in pkt:
                ip_layer = pkt[IP]
            elif IPv6 in pkt:
                ip_layer = pkt[IPv6]
            else:
                continue
                
            src = ip_layer.src
            dst = ip_layer.dst
            pkt_len = len(pkt)
            
            # TCP
            if TCP in pkt:
                tcp = pkt[TCP]
                sport = tcp.sport
                dport = tcp.dport
                flags = tcp.flags
                
                # Check for SYN-ACK (Agreement that Sport is a Service)
                # S=0x02, A=0x10. SA=0x12
                # Scapy flags are sometimes str, sometimes int.
                is_syn_ack = False
                if isinstance(flags, str):
                    is_syn_ack = 'S' in flags and 'A' in flags
                else:
                    is_syn_ack = (flags & 0x12) == 0x12
                
                if is_syn_ack:
                    # src is the Server
                    k = (src, sport, "TCP")
                    if filter_ip and src != filter_ip:
                        continue
                    if k not in services:
                        s_name = COMMON_PORTS.get(sport, f"TCP/{sport}")
                        services[k] = ServiceAsset(src, sport, "TCP", s_name, first_seen=ts, last_seen=ts)
                    s = services[k]
                    s.clients.add(dst)
                    s.packets += 1
                    s.bytes += pkt_len
                    s.last_seen = ts
                    continue

                # Provisional service: client traffic to a well-known port
                if dport in COMMON_PORTS:
                    k = (dst, dport, "TCP")
                    if filter_ip and dst != filter_ip:
                        continue
                    if k not in services:
                        s_name = COMMON_PORTS.get(dport, f"TCP/{dport}")
                        services[k] = ServiceAsset(dst, dport, "TCP", s_name, first_seen=ts, last_seen=ts)
                    s = services[k]
                    s.clients.add(src)
                    s.packets += 1
                    s.bytes += pkt_len
                    s.last_seen = ts
                
                # Check payloads for banners (from src)
                if Raw in pkt:
                    payload = bytes(pkt[Raw])
                    if payload:
                        guessed_service, banner = _guess_service(payload, sport)
                        if not guessed_service:
                            continue
                        if sport in COMMON_PORTS or sport <= 1024:
                            s_name = COMMON_PORTS.get(sport, guessed_service or f"TCP/{sport}")
                            k = (src, sport, "TCP")
                        elif dport in COMMON_PORTS:
                            s_name = COMMON_PORTS.get(dport, guessed_service or f"TCP/{dport}")
                            k = (dst, dport, "TCP")
                        else:
                            continue

                        if filter_ip and k[0] != filter_ip:
                            continue
                        if k not in services:
                            services[k] = ServiceAsset(k[0], k[1], "TCP", s_name, first_seen=ts, last_seen=ts)
                        s = services[k]
                        if guessed_service and s.service_name.startswith("TCP/"):
                            s.service_name = guessed_service
                        s.packets += 1
                        s.bytes += pkt_len
                        s.last_seen = ts
                        if k[0] == src:
                            s.clients.add(dst)
                        else:
                            s.clients.add(src)

                        if banner and not s.software:
                            s.software = banner
            
            # UDP
            elif UDP in pkt:
                udp = pkt[UDP]
                sport = udp.sport
                dport = udp.dport
                
                # UDP is stateless. Logic: Traffic FROM a well known port (DNS, NTP) is a service
                if sport in COMMON_PORTS:
                    k = (src, sport, "UDP")
                    if filter_ip and src != filter_ip:
                        continue
                    if k not in services:
                        s_name = COMMON_PORTS.get(sport, f"UDP/{sport}")
                        services[k] = ServiceAsset(src, sport, "UDP", s_name, first_seen=ts, last_seen=ts)
                    
                    s = services[k]
                    s.clients.add(dst)
                    s.packets += 1
                    s.bytes += pkt_len
                    s.last_seen = ts
                    
                    # DNS Answer?
                    if sport == 53 and DNS in pkt and pkt[DNS].qr == 1:
                        # It's a DNS Server
                        pass
                elif dport in COMMON_PORTS:
                    # Provisional UDP service (one-way client -> server)
                    k = (dst, dport, "UDP")
                    if filter_ip and dst != filter_ip:
                        continue
                    if k not in services:
                        s_name = COMMON_PORTS.get(dport, f"UDP/{dport}")
                        services[k] = ServiceAsset(dst, dport, "UDP", s_name, first_seen=ts, last_seen=ts)
                    s = services[k]
                    s.clients.add(src)
                    s.packets += 1
                    s.bytes += pkt_len
                    s.last_seen = ts

    except Exception as e:
        errors.append(str(e))
    finally:
        status.finish()
        reader.close()

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
        
        # Old versions (Simple check)
        if asset.software:
            sw = asset.software.lower()
            if "apache/1." in sw or "php/4." in sw:
                risks.append(ServiceRisk(
                    "CRITICAL", "Obsolete Software", 
                    f"Legacy software detected: {asset.software}", 
                    f"{asset.ip}:{asset.port}"
                ))
                
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

        if _is_public_ip(asset.ip) and any(svc in asset.service_name for svc in admin_services):
            risks.append(ServiceRisk(
                "HIGH",
                "Public Admin Service",
                f"Administrative service {asset.service_name} exposed on a public IP.",
                f"{asset.ip}:{asset.port}",
            ))

        if asset.protocol == "UDP" and _is_public_ip(asset.ip) and asset.service_name in udp_amplifiers:
            risks.append(ServiceRisk(
                "MEDIUM",
                "Potential UDP Amplification",
                f"Public {asset.service_name} over UDP can be abused for amplification if open.",
                f"{asset.ip}:{asset.port}",
            ))

    for (ip_value, svc), ports in cleartext_hits.items():
        port_list = ", ".join(str(port) for port in sorted(ports))
        details = f"Unencrypted {svc} service detected. Credentials/Data at risk."
        if port_list:
            details = f"{details} Ports: {port_list}."
        risks.append(ServiceRisk(
            risky_cleartext.get(svc, "MEDIUM"),
            "Cleartext Service",
            details,
            f"{ip_value}:{sorted(ports)[0]}",
        ))

    for (ip_value, svc), ports in nonstandard_hits.items():
        port_list = ", ".join(str(port) for port in sorted(ports))
        details = f"{svc} detected on non-standard ports: {port_list}."
        risks.append(ServiceRisk(
            "LOW",
            "Non-Standard Port",
            details,
            f"{ip_value}:{sorted(ports)[0]}",
        ))

    # Hierarchy
    hier = Counter()
    for s in services.values():
        hier[s.service_name] += 1

    assets_sorted = sorted(list(services.values()), key=lambda x: x.ip)
    context = _build_services_hunting_context(assets_sorted, risks)

    return ServiceSummary(
        path=path,
        total_services=len(services),
        assets=assets_sorted,
        risks=risks,
        hierarchy=dict(hier),
        analyst_verdict=str(context.get("analyst_verdict", "")),
        analyst_confidence=str(context.get("analyst_confidence", "low")),
        analyst_reasons=[str(v) for v in list(context.get("analyst_reasons", []) or [])],
        deterministic_checks={
            str(key): [str(v) for v in list(values or [])]
            for key, values in dict(context.get("deterministic_checks", {}) or {}).items()
        },
        service_mismatch_profiles=list(context.get("service_mismatch_profiles", []) or []),
        service_drift_profiles=list(context.get("service_drift_profiles", []) or []),
        lateral_surface_profiles=list(context.get("lateral_surface_profiles", []) or []),
        boundary_exposure_profiles=list(context.get("boundary_exposure_profiles", []) or []),
        ot_it_crossing_profiles=list(context.get("ot_it_crossing_profiles", []) or []),
        investigation_pivots=list(context.get("investigation_pivots", []) or []),
        risk_matrix=[dict(item) for item in list(context.get("risk_matrix", []) or []) if isinstance(item, dict)],
        false_positive_context=[str(v) for v in list(context.get("false_positive_context", []) or [])],
        errors=errors
    )
