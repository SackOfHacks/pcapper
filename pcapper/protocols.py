from __future__ import annotations

from collections import defaultdict, Counter
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.dns import DNS
    from scapy.packet import Raw, Packet
except ImportError:
    IP = TCP = UDP = Ether = IPv6 = ARP = ICMP = DNS = Raw = None

from .pcap_cache import get_reader
from .utils import safe_float
# from .services import get_service_name - Removed

# --- Dataclasses ---

@dataclass
class ProtocolStat:
    name: str
    packets: int = 0
    bytes: int = 0
    sub_protocols: Dict[str, 'ProtocolStat'] = field(default_factory=dict)
    
@dataclass
class Conversation:
    src: str
    dst: str
    protocol: str
    packets: int
    bytes: int
    start_ts: float
    end_ts: float
    ports: Set[int]

@dataclass
class Endpoint:
    address: str
    packets_sent: int = 0
    packets_recv: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    protocols: Set[str] = field(default_factory=set)

@dataclass
class Anomaly:
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    type: str
    description: str
    packet_index: int
    src: Optional[str] = None
    dst: Optional[str] = None

@dataclass
class ProtocolSummary:
    path: Path
    total_packets: int
    duration: float
    hierarchy: ProtocolStat
    conversations: List[Conversation]
    endpoints: List[Endpoint]
    anomalies: List[Anomaly]
    top_protocols: List[Tuple[str, int]]
    port_protocols: List[Tuple[str, int]]
    ethertype_protocols: List[Tuple[str, int]]
    errors: List[str]
    analyst_verdict: str = ""
    analyst_confidence: str = "low"
    analyst_reasons: List[str] = field(default_factory=list)
    deterministic_checks: Dict[str, List[str]] = field(default_factory=dict)
    corroborated_findings: List[Dict[str, object]] = field(default_factory=list)
    sequence_profiles: List[Dict[str, object]] = field(default_factory=list)
    zone_protocol_profiles: List[Dict[str, object]] = field(default_factory=list)
    baseline_drift_profiles: List[Dict[str, object]] = field(default_factory=list)
    tunneling_profiles: List[Dict[str, object]] = field(default_factory=list)
    beacon_profiles: List[Dict[str, object]] = field(default_factory=list)
    role_inversion_profiles: List[Dict[str, object]] = field(default_factory=list)
    investigation_pivots: List[Dict[str, object]] = field(default_factory=list)
    risk_matrix: List[Dict[str, str]] = field(default_factory=list)
    false_positive_context: List[str] = field(default_factory=list)


def _ip_zone(value: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(value)
    except ValueError:
        return "unknown"
    if ip_obj.is_loopback:
        return "loopback"
    if ip_obj.is_private:
        return "internal"
    if ip_obj.is_global:
        return "public"
    return "other"


def _build_protocol_hunting_context(
    *,
    total_packets: int,
    duration: float,
    conversations: List[Conversation],
    endpoints: List[Endpoint],
    anomalies: List[Anomaly],
    top_protocols: List[Tuple[str, int]],
    port_protocols: List[Tuple[str, int]],
    ethertype_protocols: List[Tuple[str, int]],
) -> Dict[str, object]:
    checks: Dict[str, List[str]] = {
        "protocol_identity_mismatch": [],
        "anomalous_protocol_sequence": [],
        "boundary_cross_zone_protocol": [],
        "tunneling_or_encapsulation_signal": [],
        "periodic_beacon_profile": [],
        "role_inversion_signal": [],
        "ot_protocol_boundary_crossing": [],
        "rare_or_low_prevalence_protocol": [],
        "cross_protocol_corroboration": [],
        "evidence_provenance": [],
    }

    corroborated_findings: List[Dict[str, object]] = []
    sequence_profiles: List[Dict[str, object]] = []
    zone_profiles: List[Dict[str, object]] = []
    baseline_drift_profiles: List[Dict[str, object]] = []
    tunneling_profiles: List[Dict[str, object]] = []
    beacon_profiles: List[Dict[str, object]] = []
    role_inversion_profiles: List[Dict[str, object]] = []
    pivots: List[Dict[str, object]] = []

    suspicious_proto_names = {"DNS", "ICMP", "QUIC", "HTTPS", "HTTP", "SMB", "RDP", "WinRM", "SSH", "Telnet"}
    admin_protos = {"SMB", "RDP", "WinRM", "SSH", "Telnet", "RPC", "LDAP", "Kerberos"}
    ot_markers = {"Modbus", "DNP3", "IEC", "CIP", "ENIP", "BACnet", "OPC", "S7", "PROFINET", "EtherCAT", "GOOSE", "SV", "MMS", "ICCP", "PTP", "MQTT", "CoAP", "HART"}

    for name, count in top_protocols:
        pct = (float(count) / float(total_packets) * 100.0) if total_packets > 0 else 0.0
        if count <= 5 or pct <= 0.2:
            checks["rare_or_low_prevalence_protocol"].append(
                f"{name} packets={count} prevalence={pct:.2f}%"
            )
            baseline_drift_profiles.append(
                {
                    "protocol": str(name),
                    "baseline_prevalence": "unknown(single-capture)",
                    "current_prevalence_pct": f"{pct:.2f}",
                    "status": "rare-or-first-seen-candidate",
                }
            )

    anomaly_by_src: Dict[str, List[Anomaly]] = defaultdict(list)
    for anomaly in anomalies:
        if anomaly.src:
            anomaly_by_src[str(anomaly.src)].append(anomaly)

    for src, events in anomaly_by_src.items():
        event_types = {str(event.type) for event in events}
        event_severities = {str(event.severity).upper() for event in events}
        scan_signal = any("Scan" in t for t in event_types)
        cred_signal = any(t in {"Cleartext Creds", "Credential Leakage", "Basic Auth", "Cleartext Auth"} for t in event_types)
        frag_signal = any(t == "IP Fragmentation" for t in event_types)
        if scan_signal and cred_signal:
            checks["anomalous_protocol_sequence"].append(
                f"{src} shows scan-like then credential-exposure indicators"
            )
            sequence_profiles.append(
                {
                    "entity": src,
                    "sequence": ["scan-signal", "credential-exposure"],
                    "confidence": "high",
                    "evidence_count": len(events),
                }
            )
        elif scan_signal and frag_signal:
            checks["anomalous_protocol_sequence"].append(
                f"{src} shows scan-like plus fragmentation indicators"
            )
            sequence_profiles.append(
                {
                    "entity": src,
                    "sequence": ["scan-signal", "fragmentation"],
                    "confidence": "medium",
                    "evidence_count": len(events),
                }
            )
        if len(event_types) >= 3 and ("HIGH" in event_severities or "CRITICAL" in event_severities):
            checks["cross_protocol_corroboration"].append(
                f"{src} has multi-signal anomaly stack types={','.join(sorted(event_types))}"
            )

    endpoint_map = {str(ep.address): ep for ep in endpoints}
    host_scores: Dict[str, int] = defaultdict(int)
    host_reasons: Dict[str, List[str]] = defaultdict(list)

    for conv in conversations:
        src_zone = _ip_zone(str(conv.src))
        dst_zone = _ip_zone(str(conv.dst))
        zone_pair = f"{src_zone}->{dst_zone}"
        proto_name = str(conv.protocol)
        duration_s = max(0.0, float(conv.end_ts or 0.0) - float(conv.start_ts or 0.0))
        pps = (float(conv.packets) / duration_s) if duration_s > 0 else 0.0
        avg_payload = (float(conv.bytes) / float(conv.packets)) if conv.packets > 0 else 0.0
        ports = sorted(int(p) for p in list(conv.ports))

        checks["evidence_provenance"].append(
            f"{conv.src}->{conv.dst} proto={proto_name} packets={conv.packets} bytes={conv.bytes} duration={duration_s:.1f}s ports={','.join(str(p) for p in ports[:8]) or '-'}"
        )

        is_cross_zone = {src_zone, dst_zone} == {"internal", "public"}
        if is_cross_zone and proto_name in admin_protos:
            checks["boundary_cross_zone_protocol"].append(
                f"{conv.src}->{conv.dst} {proto_name} across {zone_pair}"
            )
            zone_profiles.append(
                {
                    "src": conv.src,
                    "dst": conv.dst,
                    "protocol": proto_name,
                    "zone_pair": zone_pair,
                    "packets": conv.packets,
                    "bytes": conv.bytes,
                    "confidence": "high",
                }
            )
            host_scores[str(conv.src)] += 2
            host_reasons[str(conv.src)].append("Cross-zone admin protocol exposure")

        ot_hit = any(marker.lower() in proto_name.lower() for marker in ot_markers)
        if ot_hit and is_cross_zone:
            checks["ot_protocol_boundary_crossing"].append(
                f"{conv.src}->{conv.dst} OT protocol {proto_name} across {zone_pair}"
            )
            host_scores[str(conv.src)] += 2
            host_reasons[str(conv.src)].append("OT protocol crossing network boundary")

        if duration_s >= 900 and conv.packets >= 30 and pps <= 0.2:
            checks["periodic_beacon_profile"].append(
                f"{conv.src}->{conv.dst} proto={proto_name} packets={conv.packets} duration={duration_s:.1f}s pps={pps:.3f}"
            )
            beacon_profiles.append(
                {
                    "src": conv.src,
                    "dst": conv.dst,
                    "protocol": proto_name,
                    "packets": conv.packets,
                    "duration_s": f"{duration_s:.1f}",
                    "pps": f"{pps:.3f}",
                }
            )
            host_scores[str(conv.src)] += 1
            host_reasons[str(conv.src)].append("Low-and-slow periodic protocol cadence")

        if proto_name in {"DNS", "ICMP"} and avg_payload >= 200 and conv.packets >= 15:
            checks["tunneling_or_encapsulation_signal"].append(
                f"{conv.src}->{conv.dst} proto={proto_name} avg_payload={avg_payload:.1f} bytes packets={conv.packets}"
            )
            tunneling_profiles.append(
                {
                    "src": conv.src,
                    "dst": conv.dst,
                    "protocol": proto_name,
                    "avg_payload": f"{avg_payload:.1f}",
                    "packets": conv.packets,
                    "confidence": "medium",
                }
            )
            host_scores[str(conv.src)] += 1
            host_reasons[str(conv.src)].append("Potential protocol tunneling signal")

        src_ep = endpoint_map.get(str(conv.src))
        if src_ep is not None:
            src_protocols = {str(p) for p in src_ep.protocols}
            if proto_name in admin_protos and src_zone == "internal" and len(src_protocols) <= 2:
                checks["role_inversion_signal"].append(
                    f"{conv.src} appears narrowly exposed on admin protocol {proto_name}"
                )
                role_inversion_profiles.append(
                    {
                        "host": conv.src,
                        "protocol": proto_name,
                        "protocol_count": len(src_protocols),
                        "zone": src_zone,
                        "confidence": "medium",
                    }
                )
                host_scores[str(conv.src)] += 1
                host_reasons[str(conv.src)].append("Possible protocol role inversion")

            if len(src_protocols.intersection(suspicious_proto_names)) >= 4:
                checks["protocol_identity_mismatch"].append(
                    f"{conv.src} speaks broad risky protocol mix: {','.join(sorted(src_protocols.intersection(suspicious_proto_names)))}"
                )
                host_scores[str(conv.src)] += 1
                host_reasons[str(conv.src)].append("Broad risky cross-protocol service mix")

    for host, score in sorted(host_scores.items(), key=lambda item: item[1], reverse=True):
        reasons = list(dict.fromkeys(host_reasons.get(host, [])))
        confidence = "high" if score >= 5 else "medium" if score >= 3 else "low"
        corroborated_findings.append(
            {
                "host": host,
                "score": score,
                "confidence": confidence,
                "reasons": reasons[:4],
            }
        )

    for conv in sorted(conversations, key=lambda c: c.bytes, reverse=True):
        reasons = host_reasons.get(str(conv.src), []) + host_reasons.get(str(conv.dst), [])
        if not reasons:
            continue
        pivots.append(
            {
                "conversation": f"{conv.src}->{conv.dst}",
                "protocol": conv.protocol,
                "packets": conv.packets,
                "bytes": conv.bytes,
                "duration_s": max(0.0, float(conv.end_ts or 0.0) - float(conv.start_ts or 0.0)),
                "reasons": list(dict.fromkeys(reasons))[:4],
            }
        )

    verdict_score = 0
    verdict_score += 2 if checks["boundary_cross_zone_protocol"] else 0
    verdict_score += 2 if checks["ot_protocol_boundary_crossing"] else 0
    verdict_score += 1 if checks["anomalous_protocol_sequence"] else 0
    verdict_score += 1 if checks["cross_protocol_corroboration"] else 0
    verdict_score += 1 if checks["tunneling_or_encapsulation_signal"] else 0
    verdict_score += 1 if checks["periodic_beacon_profile"] else 0
    verdict_score += 1 if checks["role_inversion_signal"] else 0
    verdict_score += 1 if len([a for a in anomalies if str(a.severity).upper() in {"HIGH", "CRITICAL"}]) >= 3 else 0

    analyst_reasons: List[str] = []
    if checks["boundary_cross_zone_protocol"]:
        analyst_reasons.append("Administrative protocols crossed internal/public boundaries")
    if checks["ot_protocol_boundary_crossing"]:
        analyst_reasons.append("OT protocols crossed expected network boundaries")
    if checks["cross_protocol_corroboration"]:
        analyst_reasons.append("Multiple independent protocol anomaly signals corroborate")
    if checks["anomalous_protocol_sequence"]:
        analyst_reasons.append("Suspicious sequence pattern observed in protocol events")
    if checks["tunneling_or_encapsulation_signal"]:
        analyst_reasons.append("Potential protocol tunneling/encapsulation signals observed")

    if verdict_score >= 8:
        verdict = "YES - HIGH-CONFIDENCE PROTOCOL ABUSE OR LATERAL-MOVEMENT PATTERN DETECTED"
        confidence = "high"
    elif verdict_score >= 5:
        verdict = "LIKELY - MULTIPLE CORROBORATING PROTOCOL RISK INDICATORS DETECTED"
        confidence = "medium"
    elif verdict_score >= 2:
        verdict = "POSSIBLE - PROTOCOL RISK SIGNALS REQUIRE VALIDATION"
        confidence = "medium"
    else:
        verdict = "NO STRONG SIGNAL - NO CONVINCING HIGH-CONFIDENCE PROTOCOL ABUSE PATTERN"
        confidence = "low"

    risk_matrix: List[Dict[str, str]] = [
        {
            "category": "Anomalous Sequence",
            "risk": "High" if checks["anomalous_protocol_sequence"] else "None",
            "confidence": "High" if checks["anomalous_protocol_sequence"] else "Low",
            "evidence": str(len(checks["anomalous_protocol_sequence"])) if checks["anomalous_protocol_sequence"] else "No matching detections",
        },
        {
            "category": "Cross-Zone Protocol Exposure",
            "risk": "High" if checks["boundary_cross_zone_protocol"] else "None",
            "confidence": "High" if checks["boundary_cross_zone_protocol"] else "Low",
            "evidence": str(len(checks["boundary_cross_zone_protocol"])) if checks["boundary_cross_zone_protocol"] else "No matching detections",
        },
        {
            "category": "Tunneling/Encapsulation",
            "risk": "Medium" if checks["tunneling_or_encapsulation_signal"] else "None",
            "confidence": "Medium" if checks["tunneling_or_encapsulation_signal"] else "Low",
            "evidence": str(len(checks["tunneling_or_encapsulation_signal"])) if checks["tunneling_or_encapsulation_signal"] else "No matching detections",
        },
        {
            "category": "Periodic Beaconing",
            "risk": "Medium" if checks["periodic_beacon_profile"] else "None",
            "confidence": "Medium" if checks["periodic_beacon_profile"] else "Low",
            "evidence": str(len(checks["periodic_beacon_profile"])) if checks["periodic_beacon_profile"] else "No matching detections",
        },
        {
            "category": "Role Inversion",
            "risk": "Medium" if checks["role_inversion_signal"] else "None",
            "confidence": "Medium" if checks["role_inversion_signal"] else "Low",
            "evidence": str(len(checks["role_inversion_signal"])) if checks["role_inversion_signal"] else "No matching detections",
        },
        {
            "category": "OT Boundary Crossing",
            "risk": "High" if checks["ot_protocol_boundary_crossing"] else "None",
            "confidence": "High" if checks["ot_protocol_boundary_crossing"] else "Low",
            "evidence": str(len(checks["ot_protocol_boundary_crossing"])) if checks["ot_protocol_boundary_crossing"] else "No matching detections",
        },
    ]

    false_positive_context: List[str] = []
    if checks["boundary_cross_zone_protocol"] and not checks["cross_protocol_corroboration"]:
        false_positive_context.append("Boundary crossings may be expected for approved remote administration or managed gateways")
    if checks["periodic_beacon_profile"]:
        false_positive_context.append("Periodic behavior can be caused by health checks, backup agents, or telemetry polling")
    if not checks["anomalous_protocol_sequence"]:
        false_positive_context.append("No strong deterministic protocol-event sequence crossed high-confidence thresholds")
    false_positive_context.append("Baseline drift is estimated from this capture only unless historical baselines are provided")

    return {
        "analyst_verdict": verdict,
        "analyst_confidence": confidence,
        "analyst_reasons": analyst_reasons if analyst_reasons else ["No high-confidence protocol threat heuristic crossed threshold"],
        "deterministic_checks": checks,
        "corroborated_findings": corroborated_findings[:40],
        "sequence_profiles": sequence_profiles[:40],
        "zone_protocol_profiles": zone_profiles[:40],
        "baseline_drift_profiles": baseline_drift_profiles[:40],
        "tunneling_profiles": tunneling_profiles[:40],
        "beacon_profiles": beacon_profiles[:40],
        "role_inversion_profiles": role_inversion_profiles[:40],
        "investigation_pivots": pivots[:40],
        "risk_matrix": risk_matrix,
        "false_positive_context": false_positive_context[:8],
    }


def merge_protocols_summaries(
    summaries: List[ProtocolSummary] | Tuple[ProtocolSummary, ...] | Set[ProtocolSummary]
) -> ProtocolSummary:
    summary_list = list(summaries)
    if not summary_list:
        return ProtocolSummary(
            path=Path("ALL_PCAPS_0"),
            total_packets=0,
            duration=0.0,
            hierarchy=ProtocolStat("Root"),
            conversations=[],
            endpoints=[],
            anomalies=[],
            top_protocols=[],
            port_protocols=[],
            ethertype_protocols=[],
            errors=[],
            analyst_verdict="",
            analyst_confidence="low",
            analyst_reasons=[],
            deterministic_checks={},
            corroborated_findings=[],
            sequence_profiles=[],
            zone_protocol_profiles=[],
            baseline_drift_profiles=[],
            tunneling_profiles=[],
            beacon_profiles=[],
            role_inversion_profiles=[],
            investigation_pivots=[],
            risk_matrix=[],
            false_positive_context=[],
        )

    def _merge_node(target: ProtocolStat, source: ProtocolStat) -> None:
        target.packets += source.packets
        target.bytes += source.bytes
        for name, child in source.sub_protocols.items():
            if name not in target.sub_protocols:
                target.sub_protocols[name] = ProtocolStat(name)
            _merge_node(target.sub_protocols[name], child)

    total_packets = 0
    duration = 0.0
    hierarchy = ProtocolStat("Root")
    conversations: List[Conversation] = []
    endpoints_map: Dict[str, Endpoint] = {}
    anomalies: List[Anomaly] = []
    top_counter: Counter[str] = Counter()
    port_counter: Counter[str] = Counter()
    eth_counter: Counter[str] = Counter()
    errors: List[str] = []

    for summary in summary_list:
        total_packets += summary.total_packets
        duration += float(summary.duration or 0.0)
        _merge_node(hierarchy, summary.hierarchy)
        conversations.extend(summary.conversations)
        anomalies.extend(summary.anomalies)
        errors.extend(summary.errors)

        for name, count in summary.top_protocols:
            top_counter[name] += int(count)
        for name, count in summary.port_protocols:
            port_counter[name] += int(count)
        for name, count in summary.ethertype_protocols:
            eth_counter[name] += int(count)

        for endpoint in summary.endpoints:
            existing = endpoints_map.get(endpoint.address)
            if existing is None:
                endpoints_map[endpoint.address] = Endpoint(
                    address=endpoint.address,
                    packets_sent=endpoint.packets_sent,
                    packets_recv=endpoint.packets_recv,
                    bytes_sent=endpoint.bytes_sent,
                    bytes_recv=endpoint.bytes_recv,
                    protocols=set(endpoint.protocols),
                )
            else:
                existing.packets_sent += endpoint.packets_sent
                existing.packets_recv += endpoint.packets_recv
                existing.bytes_sent += endpoint.bytes_sent
                existing.bytes_recv += endpoint.bytes_recv
                existing.protocols.update(endpoint.protocols)

    top_protocols = top_counter.most_common(10)
    port_protocols = port_counter.most_common(10)
    ethertype_protocols = eth_counter.most_common(10)

    context = _build_protocol_hunting_context(
        total_packets=total_packets,
        duration=duration,
        conversations=conversations,
        endpoints=list(endpoints_map.values()),
        anomalies=anomalies,
        top_protocols=top_protocols,
        port_protocols=port_protocols,
        ethertype_protocols=ethertype_protocols,
    )

    return ProtocolSummary(
        path=Path("ALL_PCAPS"),
        total_packets=total_packets,
        duration=duration,
        hierarchy=hierarchy,
        conversations=conversations,
        endpoints=list(endpoints_map.values()),
        anomalies=anomalies,
        top_protocols=top_protocols,
        port_protocols=port_protocols,
        ethertype_protocols=ethertype_protocols,
        errors=errors,
        analyst_verdict=str(context.get("analyst_verdict", "")),
        analyst_confidence=str(context.get("analyst_confidence", "low")),
        analyst_reasons=[str(v) for v in list(context.get("analyst_reasons", []) or [])],
        deterministic_checks={
            str(key): [str(v) for v in list(values or [])]
            for key, values in dict(context.get("deterministic_checks", {}) or {}).items()
        },
        corroborated_findings=list(context.get("corroborated_findings", []) or []),
        sequence_profiles=list(context.get("sequence_profiles", []) or []),
        zone_protocol_profiles=list(context.get("zone_protocol_profiles", []) or []),
        baseline_drift_profiles=list(context.get("baseline_drift_profiles", []) or []),
        tunneling_profiles=list(context.get("tunneling_profiles", []) or []),
        beacon_profiles=list(context.get("beacon_profiles", []) or []),
        role_inversion_profiles=list(context.get("role_inversion_profiles", []) or []),
        investigation_pivots=list(context.get("investigation_pivots", []) or []),
        risk_matrix=[dict(item) for item in list(context.get("risk_matrix", []) or []) if isinstance(item, dict)],
        false_positive_context=[str(v) for v in list(context.get("false_positive_context", []) or [])],
    )

# --- Analysis ---

INDUSTRIAL_PORTS = {
    102: "S7/MMS/ICCP",
    319: "PTP Event",
    320: "PTP General",
    502: "Modbus/TCP",
    9600: "FINS",
    20000: "DNP3",
    2404: "IEC-104",
    47808: "BACnet/IP",
    44818: "EtherNet/IP",
    2222: "CIP/ENIP-IO",
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

ETHERTYPE_PROTOCOLS = {
    0x88A4: "EtherCAT",
    0x8892: "PROFINET RT",
    0x88CC: "LLDP",
    0x88B8: "IEC 61850 GOOSE",
    0x88BA: "IEC 61850 SV",
    0x88F7: "PTP",
}

KNOWN_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    88: "Kerberos", 110: "POP3", 123: "NTP", 135: "RPC",
    137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 162: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 514: "Syslog", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
    5353: "mDNS",
}
KNOWN_PORTS.update(INDUSTRIAL_PORTS)

OSCILLATION_REPEAT_CAP = 3

def _get_proto_name(pkt: Packet) -> str:
    # Heuristic based on layers
    if IP in pkt:
        proto_num = pkt[IP].proto
        if proto_num == 6 and TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            return KNOWN_PORTS.get(sport) or KNOWN_PORTS.get(dport) or "TCP"
        elif proto_num == 17 and UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            return KNOWN_PORTS.get(sport) or KNOWN_PORTS.get(dport) or "UDP"
        elif proto_num == 1:
            return "ICMP"
        return "IP"
    elif IPv6 in pkt:
        return "IPv6"
    elif ARP in pkt:
        return "ARP"
    
    # Fallback to layer name
    try:
        # Try to find the highest layer
        layer = pkt
        while layer.payload and layer.payload.name != "NoPayload":
            layer = layer.payload
        return layer.name
    except Exception:
        return "Unknown"

def analyze_protocols(path: Path, show_status: bool = True) -> ProtocolSummary:
    if IP is None:
         return ProtocolSummary(path, 0, 0, ProtocolStat("Root"), [], [], [], [], [], [], ["Scapy not available"])

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path, show_status=show_status
        )
    except Exception as e:
        return ProtocolSummary(path, 0, 0, ProtocolStat("Root"), [], [], [], [], [], [], [f"Error opening pcap: {e}"])
    size_bytes = size_bytes

    # Stats containers
    hierarchy = ProtocolStat("Root")
    convs: Dict[Tuple[str, str, str], Conversation] = {}
    eps: Dict[str, Endpoint] = defaultdict(lambda: Endpoint("", 0, 0, 0, 0, set()))
    anomalies: List[Anomaly] = []
    broadcast_frames = 0
    arp_ip_macs: Dict[str, Set[str]] = defaultdict(set)
    gratuitous_arp = 0
    tcp_syn_sources: Counter[str] = Counter()
    tcp_syn_ports: Dict[str, Set[int]] = defaultdict(set)
    tcp_rst_sources: Counter[str] = Counter()
    tcp_null_scan: Counter[str] = Counter()
    tcp_fin_scan: Counter[str] = Counter()
    tcp_xmas_scan: Counter[str] = Counter()
    ip_fragments = 0
    icmp_large_payloads: List[Tuple[str, str, int]] = []
    
    start_ts = None
    end_ts = None
    pkt_idx = 0
    port_protocol_counts: Counter[str] = Counter()
    ethertype_protocol_counts: Counter[str] = Counter()
    
    errors = []

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            pkt_idx += 1
            ts = safe_float(getattr(pkt, "time", 0))
            if start_ts is None:
                start_ts = ts
            end_ts = ts
            
            pkt_len = len(pkt)
            port_protocol_counts[_get_proto_name(pkt)] += 1
            if Ether in pkt:
                try:
                    ethertype = int(pkt[Ether].type)
                except Exception:
                    ethertype = None
                if ethertype is not None:
                    label = ETHERTYPE_PROTOCOLS.get(ethertype)
                    if label:
                        ethertype_protocol_counts[label] += 1
            
            # 1. Hierarchy Update
            # Traverse layers while avoiding double-counting VLAN-tagged traffic.
            current_node = hierarchy
            current_node.packets += 1
            current_node.bytes += pkt_len

            layer = pkt
            prev_effective_layer: str | None = None
            effective_path_layers: List[str] = []
            oscillation_repeats = 0
            visited_layer_ids: Set[int] = set()
            depth = 0
            l4_node: ProtocolStat | None = None
            while layer:
                depth += 1
                if depth > 256:
                    break
                layer_id = id(layer)
                if layer_id in visited_layer_ids:
                    break
                visited_layer_ids.add(layer_id)
                try:
                    lname = layer.name
                    if not lname:  # Fallback
                        lname = layer.__class__.__name__
                except Exception:
                    lname = "Unknown"

                if lname not in {"NoPayload", "Raw", "Padding"}:
                    if lname in {"802.1Q", "Dot1Q"}:
                        # Count VLAN tags, but do not make them the parent of L3/L4.
                        vlan_parent = current_node
                        if vlan_parent.name != "Ethernet":
                            vlan_parent = hierarchy.sub_protocols.get("Ethernet", vlan_parent)
                        if lname not in vlan_parent.sub_protocols:
                            vlan_parent.sub_protocols[lname] = ProtocolStat(lname)
                        vlan_node = vlan_parent.sub_protocols[lname]
                        vlan_node.packets += 1
                        vlan_node.bytes += pkt_len
                    else:
                        if lname == prev_effective_layer:
                            layer = layer.payload
                            continue
                        if (
                            len(effective_path_layers) >= 3
                            and effective_path_layers[-3] == effective_path_layers[-1]
                            and effective_path_layers[-2] == lname
                            and effective_path_layers[-3] != effective_path_layers[-2]
                        ):
                            oscillation_repeats += 1
                            if oscillation_repeats >= OSCILLATION_REPEAT_CAP:
                                break
                        else:
                            oscillation_repeats = 0
                        if lname not in current_node.sub_protocols:
                            current_node.sub_protocols[lname] = ProtocolStat(lname)
                        current_node = current_node.sub_protocols[lname]
                        current_node.packets += 1
                        current_node.bytes += pkt_len
                        if lname in {"TCP", "UDP"}:
                            l4_node = current_node
                        prev_effective_layer = lname
                        effective_path_layers.append(lname)
                layer = layer.payload

            # 1b. Inject port-based industrial protocol labels under L4 when no dissector exists.
            port_label = None
            if TCP in pkt:
                try:
                    port_label = KNOWN_PORTS.get(int(pkt[TCP].sport)) or KNOWN_PORTS.get(int(pkt[TCP].dport))
                except Exception:
                    port_label = None
            elif UDP in pkt:
                try:
                    port_label = KNOWN_PORTS.get(int(pkt[UDP].sport)) or KNOWN_PORTS.get(int(pkt[UDP].dport))
                except Exception:
                    port_label = None
            if l4_node is not None and port_label and port_label not in effective_path_layers:
                child = l4_node.sub_protocols.get(port_label)
                if child is None:
                    child = ProtocolStat(port_label)
                    l4_node.sub_protocols[port_label] = child
                child.packets += 1
                child.bytes += pkt_len

            # 2. Extract Endpoints & Conversations
            src = None
            dst = None
            proto = "Ethernet"
            ports = set()
            
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = "IP"
                if TCP in pkt:
                    proto = KNOWN_PORTS.get(pkt[TCP].sport) or KNOWN_PORTS.get(pkt[TCP].dport) or "TCP"
                    ports.add(pkt[TCP].sport)
                    ports.add(pkt[TCP].dport)
                elif UDP in pkt:
                    proto = KNOWN_PORTS.get(pkt[UDP].sport) or KNOWN_PORTS.get(pkt[UDP].dport) or "UDP"
                    ports.add(pkt[UDP].sport)
                    ports.add(pkt[UDP].dport)
                elif ICMP in pkt:
                    proto = "ICMP"
            elif IPv6 in pkt:
                src = pkt[IPv6].src
                dst = pkt[IPv6].dst
                proto = "IPv6"
            elif ARP in pkt:
                src = pkt[ARP].psrc
                dst = pkt[ARP].pdst
                proto = "ARP"
                try:
                    hwsrc = str(pkt[ARP].hwsrc)
                    psrc = str(pkt[ARP].psrc)
                    if psrc and hwsrc:
                        arp_ip_macs[psrc].add(hwsrc)
                    op = getattr(pkt[ARP], "op", None)
                    if op == 2 and psrc == dst:
                        gratuitous_arp += 1
                except Exception:
                    pass
            elif Ether in pkt:
                # Fallback L2
                src = pkt[Ether].src
                dst = pkt[Ether].dst

            if Ether in pkt:
                try:
                    eth_dst = str(pkt[Ether].dst).lower()
                    if eth_dst == "ff:ff:ff:ff:ff:ff":
                        broadcast_frames += 1
                except Exception:
                    pass
            
            if src and dst:
                # Endpoints
                e_src = eps[src]
                e_src.address = src
                e_src.packets_sent += 1
                e_src.bytes_sent += pkt_len
                e_src.protocols.add(proto)
                
                e_dst = eps[dst]
                e_dst.address = dst
                e_dst.packets_recv += 1
                e_dst.bytes_recv += pkt_len
                e_dst.protocols.add(proto)
                
                # Conversations (Order insensitive Key)
                key = tuple(sorted([src, dst])) + (proto,)
                if key not in convs:
                    convs[key] = Conversation(
                        src=src, dst=dst, protocol=proto, packets=0, bytes=0,
                        start_ts=ts, end_ts=ts, ports=set()
                    )
                c = convs[key]
                c.packets += 1
                c.bytes += pkt_len
                c.end_ts = ts
                c.ports.update(ports)

            # 3. Anomaly Detection (Basic)
            if IP in pkt:
                try:
                    ip_layer = pkt[IP]
                    if getattr(ip_layer, "frag", 0) or getattr(ip_layer, "flags", 0):
                        if getattr(ip_layer, "frag", 0) > 0 or str(getattr(ip_layer, "flags", "")).lower().find("mf") >= 0:
                            ip_fragments += 1
                except Exception:
                    pass

            # Cleartext Credentials
            if TCP in pkt and Raw in pkt:
                payload = bytes(pkt[Raw])
                # FTP/Telnet/HTTP Basic Auth check (very basic)
                if (pkt[TCP].dport == 21 or pkt[TCP].sport == 21) or \
                   (pkt[TCP].dport == 23 or pkt[TCP].sport == 23):
                     if b"USER" in payload or b"PASS" in payload:
                         anomalies.append(Anomaly("HIGH", "Cleartext Creds", f"Potential {proto} cleartext credentials", pkt_idx, src, dst))
                
                if b"Authorization: Basic" in payload:
                     anomalies.append(Anomaly("MEDIUM", "Basic Auth", "HTTP Basic Auth used (Base64 cleartext)", pkt_idx, src, dst))

                try:
                    text = payload.decode("utf-8", errors="ignore")
                except Exception:
                    text = ""

                if text:
                    # HTTP query/body credentials
                    cred_patterns = [
                        r"(?i)(password|passwd|pwd|pass)=([^&\s]{3,})",
                        r"(?i)(username|user|login|email)=([^&\s]{3,})",
                        r"(?i)(api[_-]?key|token|session)=([^&\s]{8,})",
                    ]
                    for pattern in cred_patterns:
                        match = re.search(pattern, text)
                        if match:
                            key = match.group(1)
                            anomalies.append(Anomaly("MEDIUM", "Credential Leakage", f"Potential {key} disclosure in cleartext payload", pkt_idx, src, dst))
                            break

                    # SMTP/IMAP/POP3 auth indicators
                    if re.search(r"(?i)AUTH\s+LOGIN", text) or re.search(r"(?i)AUTH\s+PLAIN", text):
                        anomalies.append(Anomaly("MEDIUM", "Cleartext Auth", "SMTP/IMAP auth sequence observed", pkt_idx, src, dst))

                    # FTP explicit USER/PASS lines
                    if re.search(r"(?i)^USER\s+\S+", text) and re.search(r"(?i)^PASS\s+\S+", text):
                        anomalies.append(Anomaly("HIGH", "Cleartext Creds", "FTP USER/PASS observed", pkt_idx, src, dst))

            if TCP in pkt:
                try:
                    flags = pkt[TCP].flags
                except Exception:
                    flags = None

                syn = ack = fin = rst = psh = urg = False
                if isinstance(flags, str):
                    syn = "S" in flags
                    ack = "A" in flags
                    fin = "F" in flags
                    rst = "R" in flags
                    psh = "P" in flags
                    urg = "U" in flags
                elif isinstance(flags, int):
                    syn = bool(flags & 0x02)
                    ack = bool(flags & 0x10)
                    fin = bool(flags & 0x01)
                    rst = bool(flags & 0x04)
                    psh = bool(flags & 0x08)
                    urg = bool(flags & 0x20)

                if syn and not ack and src:
                    tcp_syn_sources[src] += 1
                    try:
                        tcp_syn_ports[src].add(int(pkt[TCP].dport))
                    except Exception:
                        pass

                if rst and src:
                    tcp_rst_sources[src] += 1

                if flags == 0 and src:
                    tcp_null_scan[src] += 1

                if fin and not (syn or ack or rst) and src:
                    tcp_fin_scan[src] += 1

                if fin and psh and urg and src:
                    tcp_xmas_scan[src] += 1

            if ICMP in pkt and Raw in pkt:
                payload = bytes(pkt[Raw])
                if len(payload) >= 512:
                    icmp_large_payloads.append((src or "-", dst or "-", len(payload)))

            # Non-Standard Ports for known protocols? 
            # (Hard without deep inspection, skipping for now to keep it safe)
            
            # Syn Scan? (Lots of SYNs from one source) - post process

    except Exception as e:
        errors.append(str(e))
    finally:
        status.finish()
        reader.close()

    duration = (end_ts - start_ts) if (start_ts and end_ts) else 0.0

    # Post-process anomalies
    for ip_addr, macs in arp_ip_macs.items():
        if len(macs) >= 2:
            anomalies.append(Anomaly(
                "HIGH",
                "ARP Spoofing",
                f"Multiple MACs for {ip_addr}: {', '.join(sorted(macs))}",
                0,
                ip_addr,
                None,
            ))

    if gratuitous_arp > 50:
        anomalies.append(Anomaly(
            "MEDIUM",
            "Gratuitous ARP",
            f"High gratuitous ARP volume: {gratuitous_arp} packets",
            0,
        ))

    if pkt_idx and broadcast_frames / pkt_idx > 0.3:
        anomalies.append(Anomaly(
            "MEDIUM",
            "Broadcast Storm",
            f"Broadcast frames are {broadcast_frames}/{pkt_idx} packets.",
            0,
        ))

    # TCP scan heuristics
    for ip, count in tcp_syn_sources.items():
        unique_ports = len(tcp_syn_ports.get(ip, set()))
        if count > 200 or unique_ports > 100:
            anomalies.append(Anomaly(
                "MEDIUM",
                "Port Scan",
                f"Potential SYN scan activity ({count} SYNs, {unique_ports} ports) from {ip}",
                0,
                ip,
                None,
            ))

    for ip, count in tcp_null_scan.items():
        if count >= 10:
            anomalies.append(Anomaly(
                "MEDIUM",
                "TCP Null Scan",
                f"Null scan pattern observed ({count} packets) from {ip}",
                0,
                ip,
                None,
            ))

    for ip, count in tcp_fin_scan.items():
        if count >= 10:
            anomalies.append(Anomaly(
                "MEDIUM",
                "TCP FIN Scan",
                f"FIN scan pattern observed ({count} packets) from {ip}",
                0,
                ip,
                None,
            ))

    for ip, count in tcp_xmas_scan.items():
        if count >= 10:
            anomalies.append(Anomaly(
                "MEDIUM",
                "TCP Xmas Scan",
                f"Xmas scan pattern observed ({count} packets) from {ip}",
                0,
                ip,
                None,
            ))

    for ip, count in tcp_rst_sources.items():
        if count > 500:
            anomalies.append(Anomaly(
                "LOW",
                "TCP Reset Flood",
                f"High TCP RST volume ({count} packets) from {ip}",
                0,
                ip,
                None,
            ))

    if ip_fragments > 50:
        anomalies.append(Anomaly(
            "MEDIUM",
            "IP Fragmentation",
            f"Elevated IP fragmentation observed ({ip_fragments} fragments)",
            0,
        ))

    if len(icmp_large_payloads) > 10:
        src, dst, size = max(icmp_large_payloads, key=lambda item: item[2])
        anomalies.append(Anomaly(
            "MEDIUM",
            "Large ICMP Payloads",
            f"Large ICMP payloads observed ({len(icmp_large_payloads)} packets, max {size} bytes)",
            0,
            src,
            dst,
        ))

    # Calculate Top Protocols
    # Flatten hierarchy counts? Or just use root children?
    # Let's use layer occurrences
    layer_counts = Counter()
    def traverse(node):
        layer_counts[node.name] += node.packets
        for child in node.sub_protocols.values():
            traverse(child)
    traverse(hierarchy)
    # Remove Root
    del layer_counts["Root"]
    
    conversations = list(convs.values())
    endpoints = list(eps.values())
    top_protocols = layer_counts.most_common(10)
    port_protocols = port_protocol_counts.most_common(12)
    ethertype_protocols = ethertype_protocol_counts.most_common(12)
    context = _build_protocol_hunting_context(
        total_packets=pkt_idx,
        duration=duration,
        conversations=conversations,
        endpoints=endpoints,
        anomalies=anomalies,
        top_protocols=top_protocols,
        port_protocols=port_protocols,
        ethertype_protocols=ethertype_protocols,
    )

    return ProtocolSummary(
        path=path,
        total_packets=pkt_idx,
        duration=duration,
        hierarchy=hierarchy,
        conversations=conversations,
        endpoints=endpoints,
        anomalies=anomalies,
        top_protocols=top_protocols,
        port_protocols=port_protocols,
        ethertype_protocols=ethertype_protocols,
        errors=errors,
        analyst_verdict=str(context.get("analyst_verdict", "")),
        analyst_confidence=str(context.get("analyst_confidence", "low")),
        analyst_reasons=[str(v) for v in list(context.get("analyst_reasons", []) or [])],
        deterministic_checks={
            str(key): [str(v) for v in list(values or [])]
            for key, values in dict(context.get("deterministic_checks", {}) or {}).items()
        },
        corroborated_findings=list(context.get("corroborated_findings", []) or []),
        sequence_profiles=list(context.get("sequence_profiles", []) or []),
        zone_protocol_profiles=list(context.get("zone_protocol_profiles", []) or []),
        baseline_drift_profiles=list(context.get("baseline_drift_profiles", []) or []),
        tunneling_profiles=list(context.get("tunneling_profiles", []) or []),
        beacon_profiles=list(context.get("beacon_profiles", []) or []),
        role_inversion_profiles=list(context.get("role_inversion_profiles", []) or []),
        investigation_pivots=list(context.get("investigation_pivots", []) or []),
        risk_matrix=[dict(item) for item in list(context.get("risk_matrix", []) or []) if isinstance(item, dict)],
        false_positive_context=[str(v) for v in list(context.get("false_positive_context", []) or [])],
    )
