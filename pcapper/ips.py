from __future__ import annotations


from .utils import shannon_entropy as _shannon_entropy, tcp_flags_int as _tcp_flags_int
from .utils import is_public_ip as _is_public_ip
import hashlib
import ipaddress
import json
import os
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Optional

from .pcap_cache import get_reader
from .tls_fingerprints import (
    _coerce_int_list,
    _extract_alpn,
    _extract_sni,
    _iter_tls_extensions,
    _ja3_from_client_hello,
    _ja4_from_client_hello,
    _ja4s_from_server_hello,
    _tls_extension_type,
)
from .utils import counter_inc, memoize_analysis, packet_length, safe_float, safe_read_text, set_add_cap, setdict_add

MAX_ENDPOINTS = int(os.getenv("PCAPPER_MAX_ENDPOINTS", "20000"))
MAX_CONVERSATIONS = int(os.getenv("PCAPPER_MAX_CONVERSATIONS", "50000"))
MAX_UNIQUE_IPS = int(os.getenv("PCAPPER_MAX_UNIQUE_IPS", "200000"))
MAX_SET_VALUES = int(os.getenv("PCAPPER_MAX_SET_VALUES", "2000"))

try:
    from scapy.layers.inet import IP  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore

try:
    from scapy.layers.inet import TCP  # type: ignore
except Exception:  # pragma: no cover
    TCP = None  # type: ignore

try:
    from scapy.layers.inet import UDP  # type: ignore
except Exception:  # pragma: no cover
    UDP = None  # type: ignore

try:
    from scapy.layers.inet import ICMP  # type: ignore
except Exception:  # pragma: no cover
    ICMP = None  # type: ignore

try:
    from scapy.layers.l2 import ARP, Ether  # type: ignore
except Exception:  # pragma: no cover
    ARP = None  # type: ignore
    Ether = None  # type: ignore

try:
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IPv6 = None  # type: ignore

try:
    from scapy.layers.inet6 import ICMPv6  # type: ignore
except Exception:  # pragma: no cover
    ICMPv6 = None  # type: ignore

try:
    import geoip2.database  # type: ignore
except Exception:  # pragma: no cover
    geoip2 = None  # type: ignore

try:
    from scapy.layers.tls.handshake import TLSClientHello  # type: ignore
except Exception:  # pragma: no cover
    TLSClientHello = None  # type: ignore

try:
    from scapy.layers.tls.handshake import (  # type: ignore
        TLSCertificate,
        TLSServerHello,
    )
except Exception:  # pragma: no cover
    TLSServerHello = None  # type: ignore
    TLSCertificate = None  # type: ignore

try:
    from scapy.layers.tls.record import TLS  # type: ignore
except Exception:  # pragma: no cover
    TLS = None  # type: ignore

try:
    from cryptography import x509  # type: ignore
    from cryptography.hazmat.backends import default_backend  # type: ignore
except Exception:  # pragma: no cover
    x509 = None  # type: ignore
    default_backend = None  # type: ignore


@dataclass(frozen=True)
class IpConversation:
    src: str
    dst: str
    protocol: str
    packets: int
    bytes: int
    first_seen: Optional[float]
    last_seen: Optional[float]
    ports: list[int]


@dataclass(frozen=True)
class IpEndpoint:
    ip: str
    packets_sent: int
    packets_recv: int
    bytes_sent: int
    bytes_recv: int
    protocols: list[str]
    peers: list[str]
    ports: list[int]
    first_seen: Optional[float]
    last_seen: Optional[float]
    geo: Optional[str]
    asn: Optional[str]


@dataclass(frozen=True)
class IpSummary:
    path: Path
    total_packets: int
    total_bytes: int
    unique_ips: int
    unique_sources: int
    unique_destinations: int
    ipv4_count: int
    ipv6_count: int
    protocol_counts: Counter[str]
    src_counts: Counter[str]
    dst_counts: Counter[str]
    ip_category_counts: Counter[str]
    ip_mac_counts: dict[str, Counter[str]]
    ip_hostnames: dict[str, Counter[str]]
    endpoints: list[IpEndpoint]
    conversations: list[IpConversation]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]
    tls_client_hellos: int
    ja3_counts: Counter[str]
    ja4_counts: Counter[str]
    ja4s_counts: Counter[str]
    sni_counts: Counter[str]
    sni_entropy: dict[str, float]
    ja_reputation_hits: list[dict[str, object]]
    tls_cert_risks: list[dict[str, object]]
    suspicious_port_profiles: list[dict[str, object]]
    lateral_movement_scores: list[dict[str, object]]
    intel_findings: list[dict[str, object]]
    detections: list[dict[str, object]]
    errors: list[str]
    confirmed_tcp_service_ports: dict[str, list[int]] = field(default_factory=dict)
    analyst_verdict: str = ""
    analyst_confidence: str = "low"
    analyst_reasons: list[str] = field(default_factory=list)
    deterministic_checks: dict[str, list[str]] = field(default_factory=dict)
    exposure_profiles: list[dict[str, object]] = field(default_factory=list)
    priority_asset_profiles: list[dict[str, object]] = field(default_factory=list)
    infrastructure_clusters: list[dict[str, object]] = field(default_factory=list)
    intent_profiles: list[dict[str, object]] = field(default_factory=list)
    corroborated_findings: list[dict[str, object]] = field(default_factory=list)
    risk_matrix: list[dict[str, str]] = field(default_factory=list)
    false_positive_context: list[str] = field(default_factory=list)


def _tcp_is_syn(flags: object) -> bool:
    value = _tcp_flags_int(flags)
    return bool(value & 0x02) and not bool(value & 0x10)


def _tcp_is_synack(flags: object) -> bool:
    value = _tcp_flags_int(flags)
    return bool(value & 0x02) and bool(value & 0x10)


def _tcp_is_final_handshake_ack(flags: object) -> bool:
    value = _tcp_flags_int(flags)
    return (
        bool(value & 0x10)
        and not bool(value & 0x02)
        and not bool(value & 0x04)
        and not bool(value & 0x01)
    )


def _build_ips_enrichment(
    *,
    endpoints: list[IpEndpoint],
    conversations: list[IpConversation],
    suspicious_port_profiles: list[dict[str, object]],
    lateral_movement_scores: list[dict[str, object]],
    intel_findings: list[dict[str, object]],
    detections: list[dict[str, object]],
) -> dict[str, object]:
    _ = (endpoints,)
    checks: dict[str, list[str]] = defaultdict(list)

    # Indicator quality gate: external IOC hits (AbuseIPDB/OTX/VT) and TLS
    # reputation/cert IOC matches are high-quality, low-FP signals.
    for finding in intel_findings or []:
        ip = str(finding.get("ip", "?"))
        bits = []
        if finding.get("score"):
            bits.append(f"AbuseIPDB score {finding.get('score')}")
        if finding.get("pulses"):
            bits.append(f"OTX pulses {finding.get('pulses')}")
        if finding.get("malicious") or finding.get("suspicious"):
            bits.append(
                f"VT malicious={finding.get('malicious', 0)}/suspicious={finding.get('suspicious', 0)}"
            )
        checks["indicator_quality_gate"].append(
            f"{ip}: {', '.join(bits) if bits else 'threat-intel hit'}"
        )

    # Intent heuristics from the analyzer's already-thresholded detections.
    for det in detections or []:
        sev = str(det.get("severity", "info")).lower()
        summary_text = str(det.get("summary", ""))
        blob = summary_text.lower()
        ev = summary_text + (f" — {det.get('details','')}" if det.get("details") else "")
        if any(
            t in blob
            for t in ("port scanning", "scan", "sweep", "lateral movement", "fan-out", "fan-in")
        ):
            if sev != "info":
                checks["intent_heuristics"].append(ev)
        if any(t in blob for t in ("reputation", "certificate risk", "fingerprint reputation")):
            checks["indicator_quality_gate"].append(ev)

    # Corroborated multi-signal hit: an IP that appears in two or more
    # independent signal sources (scan profile / lateral movement / intel).
    signal_sources: dict[str, set[str]] = defaultdict(set)
    for prof in suspicious_port_profiles or []:
        src = str(prof.get("src", ""))
        if src:
            signal_sources[src].add("port-scan")
    for lm in lateral_movement_scores or []:
        ip = str(lm.get("ip", ""))
        if ip:
            signal_sources[ip].add("lateral-movement")
    for finding in intel_findings or []:
        ip = str(finding.get("ip", ""))
        if ip:
            signal_sources[ip].add("threat-intel")
    for ip, sources in signal_sources.items():
        if len(sources) >= 2:
            checks["corroborated_multi_signal_hit"].append(
                f"{ip}: {', '.join(sorted(sources))}"
            )

    if suspicious_port_profiles:
        for prof in suspicious_port_profiles[:5]:
            checks["intent_heuristics"].append(
                f"{prof.get('src','?')}: {prof.get('type','scan')} "
                f"({prof.get('unique_ports',0)} ports / {prof.get('unique_dsts',0)} hosts)"
            )

    # Boundary cross-zone contact, but only for IPs already flagged by another
    # signal — private<->public contact alone is normal internet traffic and
    # would fire on every capture, so it is reported as corroborating context.
    def _is_priv(addr: str) -> bool:
        try:
            return ipaddress.ip_address(addr).is_private
        except Exception:
            return False

    def _is_global_unicast(addr: str) -> bool:
        try:
            ip = ipaddress.ip_address(addr)
            return ip.is_global and not ip.is_multicast
        except Exception:
            return False

    flagged_ips = set(signal_sources.keys())
    if flagged_ips:
        boundary_seen: set[frozenset[str]] = set()
        for conv in conversations or []:
            s, d = str(conv.src), str(conv.dst)
            if not (s in flagged_ips or d in flagged_ips):
                continue
            if not (
                (_is_priv(s) and _is_global_unicast(d))
                or (_is_priv(d) and _is_global_unicast(s))
            ):
                continue
            pair = frozenset((s, d))
            if pair in boundary_seen:
                continue
            boundary_seen.add(pair)
            checks["boundary_cross_zone_contact"].append(
                f"{s} <-> {d} ({conv.protocol})"
            )

    provenance = []
    if intel_findings:
        provenance.append(f"external threat-intel ({len(intel_findings)})")
    if suspicious_port_profiles:
        provenance.append(f"port-scan profiles ({len(suspicious_port_profiles)})")
    if lateral_movement_scores:
        provenance.append(f"lateral-movement scoring ({len(lateral_movement_scores)})")
    if detections:
        provenance.append(f"IP detections ({len(detections)})")
    if provenance:
        checks["evidence_provenance"].append("; ".join(provenance))

    score = 0
    reasons: list[str] = []
    if checks.get("indicator_quality_gate"):
        score += 3
        reasons.append("High-quality threat indicator (external IOC / TLS reputation / cert IOC)")
    if checks.get("corroborated_multi_signal_hit"):
        score += 3
        reasons.append("An IP is implicated by multiple independent signals")
    if suspicious_port_profiles:
        score += 2
        reasons.append("Port-scanning profile(s) observed")
    # Broad internal fan-out alone is too often benign infrastructure (a DNS/AD
    # server, a monitoring poller, OT discovery such as BACnet Who-Is) to drive
    # a verdict on its own — `peers` counts inbound contacts too. It only scores
    # when corroborated by another signal (handled by corroborated_multi_signal_hit);
    # standalone it is shown as context under intent_heuristics.
    if lateral_movement_scores:
        reasons.append("Broad internal fan-out observed (context; verify against --tcp/--smb)")
    high_ct = sum(
        1 for d in (detections or []) if str(d.get("severity", "")).lower() in {"high", "critical"}
    )
    if high_ct:
        reasons.append(f"High-severity IP detections: {high_ct}")

    if score >= 6:
        verdict = "YES - high-confidence malicious IP activity (corroborated intel / scanning / lateral movement) is present."
        confidence = "high"
    elif score >= 4:
        verdict = "LIKELY - suspicious IP activity with attack indicators is present."
        confidence = "medium"
    elif score >= 2:
        verdict = "POSSIBLE - notable IP activity (recon / lateral movement) observed; corroboration recommended."
        confidence = "low"
    elif score >= 1:
        verdict = "LOW SIGNAL - minor IP anomalies present but not strongly corroborated."
        confidence = "low"
    else:
        verdict = ""
        confidence = "low"
    if not reasons and verdict:
        reasons.append("IP intelligence heuristics crossed threshold")

    _risk_meta = {
        "indicator_quality_gate": ("Threat Indicator", "High"),
        "corroborated_multi_signal_hit": ("Corroborated Hit", "High"),
        "intent_heuristics": ("Recon / Lateral Movement", "Medium"),
        "boundary_cross_zone_contact": ("Zone Boundary Contact", "Low"),
    }
    risk_matrix = [
        {
            "category": cat,
            "risk": risk,
            "confidence": "High" if len(checks.get(key, [])) >= 2 else "Medium",
            "evidence": f"{len(checks.get(key, []))} signal(s)",
        }
        for key, (cat, risk) in _risk_meta.items()
        if checks.get(key)
    ]

    return {
        "analyst_verdict": verdict,
        "analyst_confidence": confidence,
        "analyst_reasons": reasons,
        "deterministic_checks": {k: list(dict.fromkeys(v)) for k, v in checks.items()},
        "risk_matrix": risk_matrix,
    }

def merge_ips_summaries(summaries: Iterable[IpSummary]) -> IpSummary:
    summary_list = list(summaries)
    if not summary_list:
        return IpSummary(
            path=Path("ALL_PCAPS_0"),
            total_packets=0,
            total_bytes=0,
            unique_ips=0,
            unique_sources=0,
            unique_destinations=0,
            ipv4_count=0,
            ipv6_count=0,
            protocol_counts=Counter(),
            src_counts=Counter(),
            dst_counts=Counter(),
            ip_category_counts=Counter(),
            ip_mac_counts={},
            ip_hostnames={},
            endpoints=[],
            conversations=[],
            first_seen=None,
            last_seen=None,
            duration_seconds=0.0,
            tls_client_hellos=0,
            ja3_counts=Counter(),
            ja4_counts=Counter(),
            ja4s_counts=Counter(),
            sni_counts=Counter(),
            sni_entropy={},
            ja_reputation_hits=[],
            tls_cert_risks=[],
            suspicious_port_profiles=[],
            lateral_movement_scores=[],
            intel_findings=[],
            detections=[],
            errors=[],
        )

    total_packets = 0
    total_bytes = 0
    tls_client_hellos = 0
    duration_seconds = 0.0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    protocol_counts: Counter[str] = Counter()
    src_counts: Counter[str] = Counter()
    dst_counts: Counter[str] = Counter()
    ip_category_counts: Counter[str] = Counter()
    ip_mac_counts: dict[str, Counter[str]] = {}
    ip_hostnames: dict[str, Counter[str]] = {}
    ja3_counts: Counter[str] = Counter()
    ja4_counts: Counter[str] = Counter()
    ja4s_counts: Counter[str] = Counter()
    sni_counts: Counter[str] = Counter()
    sni_entropy: dict[str, float] = {}

    endpoint_map: dict[str, dict[str, object]] = {}
    conversation_map: dict[tuple[str, str, str], dict[str, object]] = {}
    all_ips: set[str] = set()

    tls_cert_risks: list[dict[str, object]] = []
    suspicious_port_profiles: list[dict[str, object]] = []
    lateral_movement_scores: list[dict[str, object]] = []
    intel_findings: list[dict[str, object]] = []

    detection_seen: set[tuple[str, str, str]] = set()
    detections: list[dict[str, object]] = []

    error_seen: set[str] = set()
    errors: list[str] = []

    rep_hits: dict[tuple[str, str, str], int] = defaultdict(int)
    confirmed_tcp_service_ports: dict[str, set[int]] = defaultdict(set)

    for summary in summary_list:
        total_packets += summary.total_packets
        total_bytes += summary.total_bytes
        tls_client_hellos += summary.tls_client_hellos
        if summary.duration_seconds is not None:
            duration_seconds += summary.duration_seconds

        if summary.first_seen is not None:
            if first_seen is None or summary.first_seen < first_seen:
                first_seen = summary.first_seen
        if summary.last_seen is not None:
            if last_seen is None or summary.last_seen > last_seen:
                last_seen = summary.last_seen

        protocol_counts.update(summary.protocol_counts)
        src_counts.update(summary.src_counts)
        dst_counts.update(summary.dst_counts)
        ip_category_counts.update(summary.ip_category_counts)
        for ip_value, counter in summary.ip_mac_counts.items():
            existing = ip_mac_counts.setdefault(ip_value, Counter())
            existing.update(counter)
        for ip_value, counter in summary.ip_hostnames.items():
            existing = ip_hostnames.setdefault(ip_value, Counter())
            existing.update(counter)
        ja3_counts.update(summary.ja3_counts)
        ja4_counts.update(summary.ja4_counts)
        ja4s_counts.update(summary.ja4s_counts)
        sni_counts.update(summary.sni_counts)
        for ip_text, ports in (summary.confirmed_tcp_service_ports or {}).items():
            confirmed_tcp_service_ports[ip_text].update(
                int(port)
                for port in list(ports or [])
                if isinstance(port, int) or str(port).isdigit()
            )

        all_ips.update(summary.src_counts.keys())
        all_ips.update(summary.dst_counts.keys())

        for sni, entropy in summary.sni_entropy.items():
            existing = sni_entropy.get(sni)
            if existing is None or entropy > existing:
                sni_entropy[sni] = entropy

        for item in summary.ja_reputation_hits:
            rep_type = str(item.get("type", "-"))
            fp = str(item.get("fingerprint", "-"))
            label = str(item.get("label", "-"))
            count = int(item.get("count", 0) or 0)
            rep_hits[(rep_type, fp, label)] += count

        tls_cert_risks.extend(summary.tls_cert_risks)
        suspicious_port_profiles.extend(summary.suspicious_port_profiles)
        lateral_movement_scores.extend(summary.lateral_movement_scores)
        intel_findings.extend(summary.intel_findings)

        for detection in summary.detections:
            key = (
                str(detection.get("severity", "info")),
                str(detection.get("summary", "")),
                str(detection.get("details", "")),
            )
            if key in detection_seen:
                continue
            detection_seen.add(key)
            detections.append(detection)

        for err in summary.errors:
            if err in error_seen:
                continue
            error_seen.add(err)
            errors.append(err)

        for endpoint in summary.endpoints:
            entry = endpoint_map.setdefault(
                endpoint.ip,
                {
                    "packets_sent": 0,
                    "packets_recv": 0,
                    "bytes_sent": 0,
                    "bytes_recv": 0,
                    "protocols": set(),
                    "peers": set(),
                    "ports": set(),
                    "first_seen": None,
                    "last_seen": None,
                    "geo": None,
                    "asn": None,
                },
            )
            entry["packets_sent"] = int(entry["packets_sent"]) + endpoint.packets_sent
            entry["packets_recv"] = int(entry["packets_recv"]) + endpoint.packets_recv
            entry["bytes_sent"] = int(entry["bytes_sent"]) + endpoint.bytes_sent
            entry["bytes_recv"] = int(entry["bytes_recv"]) + endpoint.bytes_recv
            entry["protocols"].update(endpoint.protocols)
            entry["peers"].update(endpoint.peers)
            entry["ports"].update(endpoint.ports)

            ep_first = endpoint.first_seen
            ep_last = endpoint.last_seen
            cur_first = entry["first_seen"]
            cur_last = entry["last_seen"]
            if ep_first is not None and (cur_first is None or ep_first < cur_first):
                entry["first_seen"] = ep_first
            if ep_last is not None and (cur_last is None or ep_last > cur_last):
                entry["last_seen"] = ep_last

            if entry["geo"] is None and endpoint.geo:
                entry["geo"] = endpoint.geo
            if entry["asn"] is None and endpoint.asn:
                entry["asn"] = endpoint.asn

        for conv in summary.conversations:
            key = (conv.src, conv.dst, conv.protocol)
            entry = conversation_map.setdefault(
                key,
                {
                    "packets": 0,
                    "bytes": 0,
                    "first_seen": None,
                    "last_seen": None,
                    "ports": set(),
                },
            )
            entry["packets"] = int(entry["packets"]) + conv.packets
            entry["bytes"] = int(entry["bytes"]) + conv.bytes
            entry["ports"].update(conv.ports)

            cur_first = entry["first_seen"]
            cur_last = entry["last_seen"]
            if conv.first_seen is not None and (
                cur_first is None or conv.first_seen < cur_first
            ):
                entry["first_seen"] = conv.first_seen
            if conv.last_seen is not None and (
                cur_last is None or conv.last_seen > cur_last
            ):
                entry["last_seen"] = conv.last_seen

    endpoint_rows: list[IpEndpoint] = []
    for ip_text, data in endpoint_map.items():
        endpoint_rows.append(
            IpEndpoint(
                ip=ip_text,
                packets_sent=int(data["packets_sent"]),
                packets_recv=int(data["packets_recv"]),
                bytes_sent=int(data["bytes_sent"]),
                bytes_recv=int(data["bytes_recv"]),
                protocols=sorted(list(data["protocols"])),
                peers=sorted(list(data["peers"])),
                ports=sorted(list(data["ports"])),
                first_seen=data["first_seen"],
                last_seen=data["last_seen"],
                geo=data["geo"],
                asn=data["asn"],
            )
        )

    conversation_rows: list[IpConversation] = []
    for (src, dst, proto), data in conversation_map.items():
        conversation_rows.append(
            IpConversation(
                src=src,
                dst=dst,
                protocol=proto,
                packets=int(data["packets"]),
                bytes=int(data["bytes"]),
                first_seen=data["first_seen"],
                last_seen=data["last_seen"],
                ports=sorted(list(data["ports"])),
            )
        )

    ipv4_count = 0
    ipv6_count = 0
    for ip_text in all_ips:
        try:
            addr = ipaddress.ip_address(ip_text)
            if addr.version == 4:
                ipv4_count += 1
            elif addr.version == 6:
                ipv6_count += 1
        except Exception:
            continue

    ja_reputation_hits = [
        {
            "type": rep_type,
            "fingerprint": fingerprint,
            "label": label,
            "count": count,
        }
        for (rep_type, fingerprint, label), count in rep_hits.items()
    ]

    enrichment = _build_ips_enrichment(
        endpoints=endpoint_rows,
        conversations=conversation_rows,
        suspicious_port_profiles=suspicious_port_profiles,
        lateral_movement_scores=lateral_movement_scores,
        intel_findings=intel_findings,
        detections=detections,
    )

    return IpSummary(
        path=Path(f"ALL_PCAPS_{len(summary_list)}"),
        total_packets=total_packets,
        total_bytes=total_bytes,
        unique_ips=len(all_ips),
        unique_sources=len(src_counts),
        unique_destinations=len(dst_counts),
        ipv4_count=ipv4_count,
        ipv6_count=ipv6_count,
        protocol_counts=protocol_counts,
        src_counts=src_counts,
        dst_counts=dst_counts,
        ip_category_counts=ip_category_counts,
        ip_mac_counts=ip_mac_counts,
        ip_hostnames=ip_hostnames,
        endpoints=endpoint_rows,
        conversations=conversation_rows,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
        tls_client_hellos=tls_client_hellos,
        ja3_counts=ja3_counts,
        ja4_counts=ja4_counts,
        ja4s_counts=ja4s_counts,
        sni_counts=sni_counts,
        sni_entropy=sni_entropy,
        ja_reputation_hits=ja_reputation_hits,
        tls_cert_risks=tls_cert_risks,
        suspicious_port_profiles=suspicious_port_profiles,
        lateral_movement_scores=lateral_movement_scores,
        intel_findings=intel_findings,
        detections=detections,
        errors=errors,
        confirmed_tcp_service_ports={
            ip_text: sorted(list(ports))
            for ip_text, ports in confirmed_tcp_service_ports.items()
            if ports
        },
        analyst_verdict=str(enrichment.get("analyst_verdict", "") or ""),
        analyst_confidence=str(
            enrichment.get("analyst_confidence", "low") or "low"
        ),
        analyst_reasons=list(enrichment.get("analyst_reasons", []) or []),
        deterministic_checks=dict(
            enrichment.get("deterministic_checks", {}) or {}
        ),
        exposure_profiles=list(enrichment.get("exposure_profiles", []) or []),
        priority_asset_profiles=list(
            enrichment.get("priority_asset_profiles", []) or []
        ),
        infrastructure_clusters=list(
            enrichment.get("infrastructure_clusters", []) or []
        ),
        intent_profiles=list(enrichment.get("intent_profiles", []) or []),
        corroborated_findings=list(
            enrichment.get("corroborated_findings", []) or []
        ),
        risk_matrix=list(enrichment.get("risk_matrix", []) or []),
        false_positive_context=list(
            enrichment.get("false_positive_context", []) or []
        ),
    )


@lru_cache(maxsize=100000)
def _classify_ip(ip_text: str) -> list[str]:
    categories: list[str] = []
    try:
        addr = ipaddress.ip_address(ip_text)
    except ValueError:
        return ["invalid"]

    if addr.version == 4 and ip_text == "255.255.255.255":
        categories.append("broadcast")
    if addr.is_multicast:
        categories.append("multicast")
    if addr.is_loopback:
        categories.append("loopback")
    if addr.is_link_local:
        categories.append("link_local")
    if addr.is_private:
        categories.append("private")
    if addr.is_reserved:
        categories.append("reserved")
    if addr.is_unspecified:
        categories.append("unspecified")
    if addr.is_global:
        categories.append("public")

    if not categories:
        categories.append("unknown")
    return categories







# JA3/JA4/JA4S construction lives in tls_fingerprints (shared with tls.py).
def _load_reputation_list(path_value: Optional[str]) -> dict[str, str]:
    if not path_value:
        return {}
    path = Path(path_value)
    if not path.exists():
        return {}

    raw = safe_read_text(path, encoding="utf-8", errors="ignore")
    if not raw:
        return {}
    raw = raw.strip()
    if not raw:
        return {}

    if raw.lstrip().startswith("{"):
        try:
            data = json.loads(raw)
        except Exception:
            return {}
        if isinstance(data, dict):
            return {str(k).strip(): str(v) for k, v in data.items()}
        if isinstance(data, list):
            return {str(item).strip(): "listed" for item in data}
        return {}

    rep: dict[str, str] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "," in line:
            key, label = line.split(",", 1)
            rep[key.strip()] = label.strip() or "listed"
        else:
            rep[line] = "listed"
    return rep


def _tls_cert_risks_from_payload(cert_payload: object) -> list[dict[str, object]]:
    if x509 is None or default_backend is None:
        return []
    certs = []
    for attr in ("certs", "certificates", "certs_data"):
        value = getattr(cert_payload, attr, None)
        if value:
            certs = value
            break
    if not certs:
        return []

    risks: list[dict[str, object]] = []
    for cert_item in certs:
        raw_bytes = None
        if isinstance(cert_item, (bytes, bytearray)):
            raw_bytes = bytes(cert_item)
        else:
            raw_bytes = getattr(cert_item, "data", None)
            if isinstance(raw_bytes, bytearray):
                raw_bytes = bytes(raw_bytes)
        if not raw_bytes:
            continue

        try:
            cert = x509.load_der_x509_certificate(raw_bytes, default_backend())
        except Exception:
            continue

        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        if subject == issuer:
            risks.append({"type": "self_signed", "details": subject})

        current = None
        try:
            from datetime import datetime, timezone

            current = datetime.now(timezone.utc)
        except Exception:
            current = None

        if current is not None:
            try:
                if cert.not_valid_after < current:
                    risks.append({"type": "expired", "details": subject})
                if cert.not_valid_before > current:
                    risks.append({"type": "not_yet_valid", "details": subject})
            except Exception:
                pass

        sig_alg = cert.signature_hash_algorithm
        if sig_alg and sig_alg.name in {"md5", "sha1"}:
            risks.append({"type": "weak_signature", "details": sig_alg.name})

        pubkey = cert.public_key()
        try:
            key_size = getattr(pubkey, "key_size", None)
            if key_size and key_size < 2048:
                risks.append({"type": "weak_key", "details": f"{key_size} bits"})
        except Exception:
            pass

    return risks


def _load_geoip_readers() -> tuple[object | None, object | None, list[str]]:
    errors: list[str] = []
    city_db = os.environ.get("PCAPPER_GEOIP_CITY_DB")
    asn_db = os.environ.get("PCAPPER_GEOIP_ASN_DB")

    if (city_db or asn_db) and ("geoip2" not in globals() or geoip2 is None):  # type: ignore[truthy-bool]
        errors.append(
            "GeoIP DB configured but geoip2 is not installed (pip install geoip2)."
        )
        return None, None, errors
    city_reader = None
    asn_reader = None

    if city_db:
        try:
            city_reader = geoip2.database.Reader(city_db)  # type: ignore[attr-defined]
        except Exception:
            city_reader = None
    if asn_db:
        try:
            asn_reader = geoip2.database.Reader(asn_db)  # type: ignore[attr-defined]
        except Exception:
            asn_reader = None
    return city_reader, asn_reader, errors


def _geoip_lookup(
    ip_text: str, city_reader: object | None, asn_reader: object | None
) -> tuple[Optional[str], Optional[str]]:
    geo_label = None
    asn_label = None

    if city_reader is not None:
        try:
            city_resp = city_reader.city(ip_text)  # type: ignore[attr-defined]
            country = getattr(getattr(city_resp, "country", None), "name", None)
            city = getattr(getattr(city_resp, "city", None), "name", None)
            region = None
            subdivisions = getattr(city_resp, "subdivisions", None)
            if subdivisions:
                try:
                    region = subdivisions.most_specific.name
                except Exception:
                    region = None
            parts = [p for p in [city, region, country] if p]
            if parts:
                geo_label = ", ".join(parts)
        except Exception:
            geo_label = None

    if asn_reader is not None:
        try:
            asn_resp = asn_reader.asn(ip_text)  # type: ignore[attr-defined]
            asn = getattr(asn_resp, "autonomous_system_number", None)
            org = getattr(asn_resp, "autonomous_system_organization", None)
            if asn or org:
                asn_label = f"AS{asn} {org}".strip()
        except Exception:
            asn_label = None

    return geo_label, asn_label


def _fetch_json(
    url: str, headers: dict[str, str], timeout: float = 5.0
) -> Optional[dict[str, object]]:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read()
        return json.loads(payload.decode("utf-8", errors="ignore"))
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError):
        return None


def _abuseipdb_lookup(ip_text: str, api_key: str) -> Optional[dict[str, object]]:
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_text}&maxAgeInDays=90&verbose=true"
    headers = {"Key": api_key, "Accept": "application/json"}
    data = _fetch_json(url, headers)
    if not data:
        return None
    payload = data.get("data")
    if not isinstance(payload, dict):
        return None
    return {
        "source": "AbuseIPDB",
        "score": payload.get("abuseConfidenceScore"),
        "reports": payload.get("totalReports"),
        "usage": payload.get("usageType"),
        "isp": payload.get("isp"),
        "country": payload.get("countryCode"),
    }


def _otx_lookup(ip_text: str, api_key: str) -> Optional[dict[str, object]]:
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_text}/general"
    headers = {"X-OTX-API-KEY": api_key, "Accept": "application/json"}
    data = _fetch_json(url, headers)
    if not data:
        return None
    pulse_info = data.get("pulse_info")
    if not isinstance(pulse_info, dict):
        return None
    pulse_count = pulse_info.get("count")
    if pulse_count is None:
        return None
    return {
        "source": "OTX",
        "pulses": pulse_count,
    }


def _virustotal_lookup(ip_text: str, api_key: str) -> Optional[dict[str, object]]:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_text}"
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    data = _fetch_json(url, headers)
    if not data:
        return None
    data_obj = data.get("data")
    if not isinstance(data_obj, dict):
        return None
    attrs = data_obj.get("attributes")
    if not isinstance(attrs, dict):
        return None
    stats = attrs.get("last_analysis_stats")
    if not isinstance(stats, dict):
        return None
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    return {
        "source": "VirusTotal",
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
    }


def _infer_protocol(pkt) -> str:
    if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
        return "TCP"
    if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
        return "UDP"
    if ICMP is not None and pkt.haslayer(ICMP):  # type: ignore[truthy-bool]
        return "ICMP"
    if ICMPv6 is not None and pkt.haslayer(ICMPv6):  # type: ignore[truthy-bool]
        return "ICMPv6"
    if ARP is not None and pkt.haslayer(ARP):  # type: ignore[truthy-bool]
        return "ARP"
    return "OTHER"


@memoize_analysis
def analyze_ips(path: Path, show_status: bool = True) -> IpSummary:
    errors: list[str] = []
    if IP is None and IPv6 is None and ARP is None:
        errors.append("Scapy IP layers unavailable; install scapy for IP analysis.")
        return IpSummary(
            path=path,
            total_packets=0,
            total_bytes=0,
            unique_ips=0,
            unique_sources=0,
            unique_destinations=0,
            ipv4_count=0,
            ipv6_count=0,
            protocol_counts=Counter(),
            src_counts=Counter(),
            dst_counts=Counter(),
            ip_category_counts=Counter(),
            ip_mac_counts={},
            ip_hostnames={},
            endpoints=[],
            conversations=[],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
            tls_client_hellos=0,
            ja3_counts=Counter(),
            ja4_counts=Counter(),
            ja4s_counts=Counter(),
            sni_counts=Counter(),
            sni_entropy={},
            ja_reputation_hits=[],
            tls_cert_risks=[],
            suspicious_port_profiles=[],
            lateral_movement_scores=[],
            intel_findings=[],
            detections=[],
            errors=errors,
        )

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, show_status=show_status
    )

    total_packets = 0
    total_bytes = 0
    protocol_counts: Counter[str] = Counter()
    src_counts: Counter[str] = Counter()
    dst_counts: Counter[str] = Counter()
    ip_category_counts: Counter[str] = Counter()
    ip_mac_counts: dict[str, Counter[str]] = defaultdict(Counter)
    ip_hostnames: dict[str, Counter[str]] = defaultdict(Counter)

    endpoints: dict[str, dict[str, object]] = defaultdict(
        lambda: {
            "packets_sent": 0,
            "packets_recv": 0,
            "bytes_sent": 0,
            "bytes_recv": 0,
            "protocols": set(),
            "peers": set(),
            "ports": set(),
            "first_seen": None,
            "last_seen": None,
        }
    )

    conversations: dict[tuple[str, str, str], dict[str, object]] = defaultdict(
        lambda: {
            "packets": 0,
            "bytes": 0,
            "ports": set(),
            "first_seen": None,
            "last_seen": None,
        }
    )

    unique_ips: set[str] = set()
    src_ips: set[str] = set()
    dst_ips: set[str] = set()

    ipv4_set: set[str] = set()
    ipv6_set: set[str] = set()

    src_to_ports: dict[str, set[int]] = defaultdict(set)
    src_to_dsts: dict[str, set[str]] = defaultdict(set)
    dst_to_ports: dict[str, set[int]] = defaultdict(set)
    dst_to_srcs: dict[str, set[str]] = defaultdict(set)
    syn_seen: set[tuple[str, str, int, int]] = set()
    syn_ack_seen: set[tuple[str, str, int, int]] = set()
    handshake_complete: set[tuple[str, str, int, int]] = set()
    confirmed_tcp_service_ports: dict[str, set[int]] = defaultdict(set)

    tls_client_hellos = 0
    ja3_counts: Counter[str] = Counter()
    ja4_counts: Counter[str] = Counter()
    ja4s_counts: Counter[str] = Counter()
    sni_counts: Counter[str] = Counter()
    sni_entropy: dict[str, float] = {}
    tls_cert_risks: list[dict[str, object]] = []
    cert_seen: set[tuple[str, str, str]] = set()

    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    skipped_endpoints = 0
    skipped_conversations = 0

    def _record_mac(ip_text: str, mac: str) -> None:
        if not ip_text or not mac:
            return
        mac_value = mac.lower()
        if mac_value == "00:00:00:00:00:00":
            return
        counter = ip_mac_counts[ip_text]
        if mac_value in counter or len(counter) < MAX_SET_VALUES:
            counter[mac_value] += 1

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            src_ip = None
            dst_ip = None
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                ip_layer = pkt[IP]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))
                if src_ip:
                    set_add_cap(ipv4_set, src_ip, max_size=MAX_UNIQUE_IPS)
                if dst_ip:
                    set_add_cap(ipv4_set, dst_ip, max_size=MAX_UNIQUE_IPS)
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                ip_layer = pkt[IPv6]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))
                if src_ip:
                    set_add_cap(ipv6_set, src_ip, max_size=MAX_UNIQUE_IPS)
                if dst_ip:
                    set_add_cap(ipv6_set, dst_ip, max_size=MAX_UNIQUE_IPS)
            elif ARP is not None and pkt.haslayer(ARP):  # type: ignore[truthy-bool]
                arp_layer = pkt[ARP]  # type: ignore[index]
                src_ip = str(getattr(arp_layer, "psrc", ""))
                dst_ip = str(getattr(arp_layer, "pdst", ""))
                if src_ip:
                    set_add_cap(ipv4_set, src_ip, max_size=MAX_UNIQUE_IPS)
                if dst_ip:
                    set_add_cap(ipv4_set, dst_ip, max_size=MAX_UNIQUE_IPS)
            else:
                continue

            if not src_ip or not dst_ip:
                continue

            if Ether is not None and pkt.haslayer(Ether):  # type: ignore[truthy-bool]
                eth_layer = pkt[Ether]  # type: ignore[index]
                _record_mac(src_ip, str(getattr(eth_layer, "src", "")))
                _record_mac(dst_ip, str(getattr(eth_layer, "dst", "")))

            total_packets += 1
            pkt_len = packet_length(pkt)
            total_bytes += pkt_len

            # Dissect TCP/UDP once per packet; reused for protocol inference,
            # conversation tracking, and the per-endpoint loop below.
            tcp_layer = pkt.getlayer(TCP) if TCP is not None else None  # type: ignore[arg-type]
            udp_layer = (
                pkt.getlayer(UDP)  # type: ignore[arg-type]
                if UDP is not None and tcp_layer is None
                else None
            )
            if tcp_layer is not None:
                protocol = "TCP"
            elif udp_layer is not None:
                protocol = "UDP"
            else:
                protocol = _infer_protocol(pkt)
            counter_inc(protocol_counts, protocol)

            set_add_cap(unique_ips, src_ip, max_size=MAX_UNIQUE_IPS)
            set_add_cap(unique_ips, dst_ip, max_size=MAX_UNIQUE_IPS)
            set_add_cap(src_ips, src_ip, max_size=MAX_UNIQUE_IPS)
            set_add_cap(dst_ips, dst_ip, max_size=MAX_UNIQUE_IPS)

            counter_inc(src_counts, src_ip)
            counter_inc(dst_counts, dst_ip)

            for category in _classify_ip(src_ip):
                counter_inc(ip_category_counts, category)
            for category in _classify_ip(dst_ip):
                counter_inc(ip_category_counts, category)

            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            conv_key = (src_ip, dst_ip, protocol)
            conv = None
            if (
                conv_key not in conversations
                and len(conversations) >= MAX_CONVERSATIONS
            ):
                skipped_conversations += 1
                conv = None
            else:
                conv = conversations[conv_key]
                conv["packets"] = int(conv["packets"]) + 1
                conv["bytes"] = int(conv["bytes"]) + pkt_len

            if conv is not None and ts is not None:
                if conv["first_seen"] is None or ts < conv["first_seen"]:  # type: ignore[operator]
                    conv["first_seen"] = ts
                if conv["last_seen"] is None or ts > conv["last_seen"]:  # type: ignore[operator]
                    conv["last_seen"] = ts

            if tcp_layer is not None:
                sport = getattr(tcp_layer, "sport", None)
                dport = getattr(tcp_layer, "dport", None)
                flags = getattr(tcp_layer, "flags", 0)
                if conv is not None and sport is not None:
                    set_add_cap(conv["ports"], int(sport), max_size=MAX_SET_VALUES)
                if conv is not None and dport is not None:
                    set_add_cap(conv["ports"], int(dport), max_size=MAX_SET_VALUES)
                if sport is not None and dport is not None:
                    flow_key = (src_ip, dst_ip, int(sport), int(dport))
                    reverse_key = (dst_ip, src_ip, int(dport), int(sport))
                    if _tcp_is_syn(flags):
                        syn_seen.add(flow_key)
                    elif _tcp_is_synack(flags):
                        if reverse_key in syn_seen:
                            syn_ack_seen.add(reverse_key)
                    elif _tcp_is_final_handshake_ack(flags):
                        if flow_key in syn_seen and flow_key in syn_ack_seen:
                            handshake_complete.add(flow_key)

                    if flow_key in handshake_complete:
                        confirmed_tcp_service_ports[dst_ip].add(int(dport))
                    elif reverse_key in handshake_complete:
                        confirmed_tcp_service_ports[src_ip].add(int(sport))

                    setdict_add(
                        src_to_ports, src_ip, int(dport), max_values=MAX_SET_VALUES
                    )
                    setdict_add(src_to_dsts, src_ip, dst_ip, max_values=MAX_SET_VALUES)
                    setdict_add(
                        dst_to_ports, dst_ip, int(dport), max_values=MAX_SET_VALUES
                    )
                    setdict_add(dst_to_srcs, dst_ip, src_ip, max_values=MAX_SET_VALUES)
            elif udp_layer is not None:
                sport = getattr(udp_layer, "sport", None)
                dport = getattr(udp_layer, "dport", None)
                if conv is not None and sport is not None:
                    set_add_cap(conv["ports"], int(sport), max_size=MAX_SET_VALUES)
                if conv is not None and dport is not None:
                    set_add_cap(conv["ports"], int(dport), max_size=MAX_SET_VALUES)
                if sport is not None and dport is not None:
                    setdict_add(
                        src_to_ports, src_ip, int(dport), max_values=MAX_SET_VALUES
                    )
                    setdict_add(src_to_dsts, src_ip, dst_ip, max_values=MAX_SET_VALUES)
                    setdict_add(
                        dst_to_ports, dst_ip, int(dport), max_values=MAX_SET_VALUES
                    )
                    setdict_add(dst_to_srcs, dst_ip, src_ip, max_values=MAX_SET_VALUES)

            for ip_text, direction in ((src_ip, "sent"), (dst_ip, "recv")):
                if ip_text not in endpoints and len(endpoints) >= MAX_ENDPOINTS:
                    skipped_endpoints += 1
                    continue
                entry = endpoints[ip_text]
                if direction == "sent":
                    entry["packets_sent"] = int(entry["packets_sent"]) + 1
                    entry["bytes_sent"] = int(entry["bytes_sent"]) + pkt_len
                else:
                    entry["packets_recv"] = int(entry["packets_recv"]) + 1
                    entry["bytes_recv"] = int(entry["bytes_recv"]) + pkt_len

                set_add_cap(entry["protocols"], protocol, max_size=MAX_SET_VALUES)
                peer = dst_ip if ip_text == src_ip else src_ip
                set_add_cap(entry["peers"], peer, max_size=MAX_SET_VALUES)

                if tcp_layer is not None:
                    port = getattr(
                        tcp_layer, "sport" if ip_text == src_ip else "dport", None
                    )
                    if port is not None:
                        set_add_cap(entry["ports"], int(port), max_size=MAX_SET_VALUES)
                elif udp_layer is not None:
                    port = getattr(
                        udp_layer, "sport" if ip_text == src_ip else "dport", None
                    )
                    if port is not None:
                        set_add_cap(entry["ports"], int(port), max_size=MAX_SET_VALUES)

                if ts is not None:
                    if entry["first_seen"] is None or ts < entry["first_seen"]:  # type: ignore[operator]
                        entry["first_seen"] = ts
                    if entry["last_seen"] is None or ts > entry["last_seen"]:  # type: ignore[operator]
                        entry["last_seen"] = ts

            if TLSClientHello is not None and pkt.haslayer(TLSClientHello):  # type: ignore[truthy-bool]
                tls_client_hellos += 1
                client_hello = pkt[TLSClientHello]  # type: ignore[index]
                exts = _iter_tls_extensions(client_hello)
                sni_val = None
                alpn_vals: list[str] = []
                for ext in exts:
                    if sni_val is None:
                        sni_val = _extract_sni(ext)
                    if not alpn_vals:
                        alpn_vals = _extract_alpn(ext)
                if sni_val:
                    sni_counts[sni_val] += 1
                    sni_entropy[sni_val] = _shannon_entropy(sni_val)
                    ip_hostnames[dst_ip][str(sni_val).strip(".").lower()] += 1

                ja3 = _ja3_from_client_hello(client_hello)
                if ja3:
                    ja3_hash = hashlib.md5(
                        ja3.encode("utf-8", errors="ignore")
                    ).hexdigest()
                    ja3_counts[ja3_hash] += 1

                ja4 = _ja4_from_client_hello(client_hello, sni_val, alpn_vals)
                if ja4:
                    ja4_counts[ja4] += 1

            if TLSServerHello is not None and pkt.haslayer(TLSServerHello):  # type: ignore[truthy-bool]
                server_hello = pkt[TLSServerHello]  # type: ignore[index]
                server_alpn: list[str] = []
                for ext in _iter_tls_extensions(server_hello):
                    if not server_alpn:
                        server_alpn = _extract_alpn(ext)
                ja4s = _ja4s_from_server_hello(server_hello, server_alpn)
                if ja4s:
                    ja4s_counts[ja4s] += 1

            if TLSCertificate is not None and pkt.haslayer(TLSCertificate):  # type: ignore[truthy-bool]
                cert_layer = pkt[TLSCertificate]  # type: ignore[index]
                risks = _tls_cert_risks_from_payload(cert_layer)
                if risks:
                    key = (src_ip, dst_ip, str(len(risks)))
                    if key not in cert_seen:
                        cert_seen.add(key)
                        tls_cert_risks.append(
                            {
                                "src": src_ip,
                                "dst": dst_ip,
                                "risks": risks,
                            }
                        )
    finally:
        status.finish()
        reader.close()

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)
    if skipped_endpoints:
        errors.append(
            f"Endpoint cap reached; {skipped_endpoints} endpoint updates skipped."
        )
    if skipped_conversations:
        errors.append(
            f"Conversation cap reached; {skipped_conversations} conversation updates skipped."
        )
    if len(unique_ips) >= MAX_UNIQUE_IPS:
        errors.append("Unique IP cap reached; additional IPs not counted.")

    endpoint_rows: list[IpEndpoint] = []
    for ip_text, data in endpoints.items():
        endpoint_rows.append(
            IpEndpoint(
                ip=ip_text,
                packets_sent=int(data["packets_sent"]),
                packets_recv=int(data["packets_recv"]),
                bytes_sent=int(data["bytes_sent"]),
                bytes_recv=int(data["bytes_recv"]),
                protocols=sorted(list(data["protocols"])),
                peers=sorted(list(data["peers"])),
                ports=sorted(list(data["ports"])),
                first_seen=data["first_seen"],
                last_seen=data["last_seen"],
                geo=None,
                asn=None,
            )
        )

    conversation_rows: list[IpConversation] = []
    for (src_ip, dst_ip, protocol), data in conversations.items():
        conversation_rows.append(
            IpConversation(
                src=src_ip,
                dst=dst_ip,
                protocol=protocol,
                packets=int(data["packets"]),
                bytes=int(data["bytes"]),
                first_seen=data["first_seen"],
                last_seen=data["last_seen"],
                ports=sorted(list(data["ports"])),
            )
        )

    def _is_scan_target(addr: str) -> bool:
        # A real scan/sweep targets unicast hosts. Broadcast/multicast/link-local
        # destinations are service-discovery chatter (mDNS/SSDP/NAT-PMP), not
        # scan targets, and must not count toward the destination breadth.
        try:
            ip = ipaddress.ip_address(addr)
        except Exception:
            return False
        if ip.is_multicast or ip.is_link_local or ip.is_loopback or ip.is_unspecified:
            return False
        if str(addr).endswith(".255") or str(addr).endswith(".0"):
            return False
        return True

    def _dst_is_internal(addr: str) -> bool:
        try:
            ip = ipaddress.ip_address(addr)
            return ip.is_private and not (
                ip.is_link_local or ip.is_multicast or ip.is_loopback
            )
        except Exception:
            return False

    suspicious_port_profiles: list[dict[str, object]] = []
    for src_ip, ports in src_to_ports.items():
        unique_ports = len(ports)
        dsts = {d for d in src_to_dsts.get(src_ip, set()) if _is_scan_target(str(d))}
        unique_dsts = len(dsts)
        high_ports = sum(1 for p in ports if p >= 1024)
        # Distinguish internal-network reconnaissance from ordinary outbound
        # client egress: a host connecting to many PUBLIC hosts on high ports
        # (P2P, CDN, app traffic) is not scanning. Flag only when destinations
        # are substantially internal, or it is a vertical scan (many ports per
        # host = port enumeration), which is suspicious against any target.
        internal_dsts = sum(1 for d in dsts if _dst_is_internal(str(d)))
        internal_frac = internal_dsts / max(unique_dsts, 1)
        ports_per_dst = unique_ports / max(unique_dsts, 1)
        is_internal_recon = internal_frac >= 0.5
        is_vertical_scan = ports_per_dst >= 10
        if not (is_internal_recon or is_vertical_scan):
            continue
        if unique_ports >= 100 and unique_dsts >= 10:
            suspicious_port_profiles.append(
                {
                    "type": "broad_scan",
                    "src": src_ip,
                    "unique_ports": unique_ports,
                    "unique_dsts": unique_dsts,
                    "high_ports": high_ports,
                }
            )
        elif (
            unique_ports >= 50
            and unique_dsts >= 3
            and high_ports / max(unique_ports, 1) > 0.8
        ):
            suspicious_port_profiles.append(
                {
                    "type": "high_port_sweep",
                    "src": src_ip,
                    "unique_ports": unique_ports,
                    "unique_dsts": unique_dsts,
                    "high_ports": high_ports,
                }
            )

    # Lateral movement is INTERNAL host-to-host spread. Scoring on ALL peers
    # (the old behavior) made any workstation browsing many public HTTPS sites
    # look like lateral movement; only private<->private reach counts, gated on
    # contacting several distinct internal hosts.
    def _is_real_internal_host(addr: str, self_ip: str) -> bool:
        # A genuine lateral-movement target: an RFC1918 unicast host that is not
        # the endpoint itself, the broadcast/network address, link-local
        # (169.254), loopback, multicast, or the unspecified address. Counting
        # those inflated the score with gateways/broadcast/self and produced
        # false lateral-movement verdicts on ordinary hosts.
        if addr == self_ip:
            return False
        try:
            ip = ipaddress.ip_address(addr)
        except Exception:
            return False
        if not ip.is_private:
            return False
        if (
            ip.is_link_local
            or ip.is_loopback
            or ip.is_multicast
            or ip.is_unspecified
            or ip.is_reserved
        ):
            return False
        if str(addr).endswith(".255") or str(addr).endswith(".0"):
            return False
        return True

    lateral_movement_scores: list[dict[str, object]] = []
    for endpoint in endpoint_rows:
        # The actor must itself be a real internal unicast host that actually
        # initiated traffic — broadcast/multicast addresses and passive
        # receive-only endpoints (packets_sent == 0, e.g. a host that merely
        # received LAN broadcasts from many sources) are not lateral movers.
        if not _is_real_internal_host(endpoint.ip, ""):
            continue
        if endpoint.packets_sent <= 0:
            continue
        internal_peers = sum(
            1 for p in endpoint.peers if _is_real_internal_host(p, endpoint.ip)
        )
        unique_ports = len(endpoint.ports)
        # Lateral movement is BREADTH of internal reach, not packet volume: a
        # chatty node (OT cyclic polling, a busy server) sends huge volumes to a
        # few peers and must not score. Require contact with many distinct
        # internal hosts; small (<10-host) spread is left to --tcp/--smb/--threats.
        score = (internal_peers / 10.0) + (unique_ports / 50.0)
        if internal_peers >= 10:
                lateral_movement_scores.append(
                    {
                        "ip": endpoint.ip,
                        "score": round(score, 2),
                        "peers": internal_peers,
                        "ports": unique_ports,
                        "packets_sent": endpoint.packets_sent,
                    }
                )

    intel_findings: list[dict[str, object]] = []
    ja_reputation_hits: list[dict[str, object]] = []
    geo_reader, asn_reader, geo_errors = _load_geoip_readers()
    errors.extend(geo_errors)

    ja3_rep = _load_reputation_list(os.environ.get("PCAPPER_JA3_REP"))
    ja4_rep = _load_reputation_list(os.environ.get("PCAPPER_JA4_REP"))
    ja4s_rep = _load_reputation_list(os.environ.get("PCAPPER_JA4S_REP"))
    abuse_key = os.environ.get("PCAPPER_ABUSEIPDB_KEY")
    otx_key = os.environ.get("PCAPPER_OTX_KEY")
    vt_key = os.environ.get("PCAPPER_VT_KEY")
    opt_in_raw = os.environ.get("PCAPPER_INTEL_OPT_IN", "0").strip().lower()
    opt_in = opt_in_raw in {"1", "true", "yes", "y"}
    if not opt_in and (abuse_key or otx_key or vt_key):
        errors.append(
            "External IP intelligence lookups disabled; set PCAPPER_INTEL_OPT_IN=1 to enable."
        )
        abuse_key = None
        otx_key = None
        vt_key = None
    try:
        intel_limit = int(os.environ.get("PCAPPER_IP_INTEL_LIMIT", "10"))
    except Exception:
        intel_limit = 10

    top_endpoints = sorted(
        endpoint_rows,
        key=lambda e: e.bytes_sent + e.bytes_recv,
        reverse=True,
    )

    enriched: dict[str, tuple[Optional[str], Optional[str]]] = {}
    for endpoint in top_endpoints:
        if len(enriched) >= intel_limit:
            break
        if not _is_public_ip(endpoint.ip):
            continue

        geo_label, asn_label = _geoip_lookup(endpoint.ip, geo_reader, asn_reader)
        enriched[endpoint.ip] = (geo_label, asn_label)

        if abuse_key:
            abuse_data = _abuseipdb_lookup(endpoint.ip, abuse_key)
            if abuse_data and abuse_data.get("score"):
                intel_findings.append(
                    {
                        "ip": endpoint.ip,
                        **abuse_data,
                    }
                )

        if otx_key:
            otx_data = _otx_lookup(endpoint.ip, otx_key)
            if otx_data and otx_data.get("pulses"):
                intel_findings.append(
                    {
                        "ip": endpoint.ip,
                        **otx_data,
                    }
                )

        if vt_key:
            vt_data = _virustotal_lookup(endpoint.ip, vt_key)
            if vt_data and (vt_data.get("malicious") or vt_data.get("suspicious")):
                intel_findings.append(
                    {
                        "ip": endpoint.ip,
                        **vt_data,
                    }
                )

    if enriched:
        updated_rows: list[IpEndpoint] = []
        for endpoint in endpoint_rows:
            geo_label, asn_label = enriched.get(endpoint.ip, (None, None))
            updated_rows.append(
                IpEndpoint(
                    ip=endpoint.ip,
                    packets_sent=endpoint.packets_sent,
                    packets_recv=endpoint.packets_recv,
                    bytes_sent=endpoint.bytes_sent,
                    bytes_recv=endpoint.bytes_recv,
                    protocols=endpoint.protocols,
                    peers=endpoint.peers,
                    ports=endpoint.ports,
                    first_seen=endpoint.first_seen,
                    last_seen=endpoint.last_seen,
                    geo=geo_label,
                    asn=asn_label,
                )
            )
        endpoint_rows = updated_rows

    if ja3_rep:
        for ja3_hash, count in ja3_counts.items():
            if ja3_hash in ja3_rep:
                ja_reputation_hits.append(
                    {
                        "type": "JA3",
                        "fingerprint": ja3_hash,
                        "label": ja3_rep[ja3_hash],
                        "count": count,
                    }
                )

    if ja4_rep:
        for ja4_hash, count in ja4_counts.items():
            if ja4_hash in ja4_rep:
                ja_reputation_hits.append(
                    {
                        "type": "JA4",
                        "fingerprint": ja4_hash,
                        "label": ja4_rep[ja4_hash],
                        "count": count,
                    }
                )

    if ja4s_rep:
        for ja4s_hash, count in ja4s_counts.items():
            if ja4s_hash in ja4s_rep:
                ja_reputation_hits.append(
                    {
                        "type": "JA4S",
                        "fingerprint": ja4s_hash,
                        "label": ja4s_rep[ja4s_hash],
                        "count": count,
                    }
                )

    if geo_reader is not None:
        try:
            geo_reader.close()  # type: ignore[attr-defined]
        except Exception:
            pass
    if asn_reader is not None:
        try:
            asn_reader.close()  # type: ignore[attr-defined]
        except Exception:
            pass

    # Enrich IP->hostname mapping using the dedicated hostname analyzer so
    # --ips is not limited to TLS SNI-only hostname signals.
    try:
        from .hostname import analyze_hostname

        hostname_summary = analyze_hostname(
            path,
            target_ip=None,
            show_status=False,
            include_related=False,
        )
        for finding in list(getattr(hostname_summary, "findings", []) or []):
            mapped_ip = str(getattr(finding, "mapped_ip", "") or "").strip()
            hostname = str(getattr(finding, "hostname", "") or "").strip().lower()
            if not mapped_ip or not hostname:
                continue
            ip_hostnames[mapped_ip][hostname] += int(getattr(finding, "count", 1) or 1)
    except Exception:
        # Keep IPS resilient; fallback to in-band hostname signals only.
        pass

    detections: list[dict[str, object]] = []
    if total_packets == 0:
        detections.append(
            {
                "severity": "info",
                "summary": "No IP traffic detected",
                "details": "No IPv4/IPv6 packets observed in capture.",
            }
        )
    else:
        if tls_client_hellos > 0:
            high_entropy_sni = [
                (sni, entropy)
                for sni, entropy in sni_entropy.items()
                if entropy >= 4.0 and len(sni) >= 12
            ]
            if high_entropy_sni:
                sample = ", ".join(
                    f"{name}({entropy:.2f})" for name, entropy in high_entropy_sni[:5]
                )
                detections.append(
                    {
                        "severity": "warning",
                        "summary": "High-entropy TLS SNI values detected",
                        "details": f"Potential DGA or tunneling indicators: {sample}",
                    }
                )

            if len(ja3_counts) > 100:
                detections.append(
                    {
                        "severity": "info",
                        "summary": "High JA3 diversity",
                        "details": f"Observed {len(ja3_counts)} unique JA3 hashes; may indicate client variety or evasion.",
                    }
                )

        if suspicious_port_profiles:
            detections.append(
                {
                    "severity": "warning",
                    "summary": "Suspicious port scanning profiles observed",
                    "details": f"{len(suspicious_port_profiles)} source(s) show broad/high-port sweep behavior.",
                }
            )

        if lateral_movement_scores:
            top_lm = sorted(
                lateral_movement_scores, key=lambda x: x.get("score", 0), reverse=True
            )[:5]
            details = ", ".join(f"{item['ip']}({item['score']})" for item in top_lm)
            detections.append(
                {
                    "severity": "warning",
                    "summary": "Potential lateral movement patterns",
                    "details": f"High internal fan-out/port reach: {details}",
                }
            )

        if ja_reputation_hits:
            detections.append(
                {
                    "severity": "warning",
                    "summary": "TLS fingerprint reputation hits",
                    "details": f"{len(ja_reputation_hits)} JA3/JA4/JA4S matches found.",
                }
            )

        if tls_cert_risks:
            detections.append(
                {
                    "severity": "warning",
                    "summary": "TLS certificate risk indicators",
                    "details": f"{len(tls_cert_risks)} certificate risk observations.",
                }
            )
        for category in (
            "broadcast",
            "multicast",
            "loopback",
            "link_local",
            "unspecified",
        ):
            if ip_category_counts.get(category, 0) > 0:
                detections.append(
                    {
                        "severity": "warning"
                        if category in ("broadcast", "loopback", "unspecified")
                        else "info",
                        "summary": f"{category.replace('_', ' ').title()} traffic observed",
                        "details": f"{ip_category_counts.get(category, 0)} packets involved in {category} addressing.",
                    }
                )

        # Sustained high rate only — guard against a few packets in a sub-second
        # capture producing a meaningless pkt/s via a near-zero duration.
        if duration_seconds and duration_seconds >= 1.0:
            top_src = src_counts.most_common(1)
            if top_src:
                src_ip, src_count = top_src[0]
                src_rate = src_count / duration_seconds
                if src_rate > 5000 and src_count >= 1000:
                    detections.append(
                        {
                            "severity": "warning",
                            "summary": "High packet rate from a single source",
                            "details": f"{src_ip} sent {src_count} packets (~{src_rate:.1f} pkt/s).",
                            "top_sources": src_counts.most_common(3),
                        }
                    )

        for endpoint in endpoint_rows:
            if len(endpoint.peers) > 200:
                detections.append(
                    {
                        "severity": "warning",
                        "summary": "High fan-out detected",
                        "details": f"{endpoint.ip} communicated with {len(endpoint.peers)} unique peers.",
                        "top_sources": [(endpoint.ip, len(endpoint.peers))],
                    }
                )
                break

        for endpoint in endpoint_rows:
            inbound_peers = len(endpoint.peers)
            if inbound_peers > 200 and endpoint.packets_recv > endpoint.packets_sent:
                detections.append(
                    {
                        "severity": "warning",
                        "summary": "High fan-in detected",
                        "details": f"{endpoint.ip} received traffic from {inbound_peers} unique peers.",
                        "top_destinations": [(endpoint.ip, inbound_peers)],
                    }
                )
                break

        if total_bytes > 0:
            sorted_endpoints = sorted(
                endpoint_rows, key=lambda e: e.bytes_sent + e.bytes_recv, reverse=True
            )
            if sorted_endpoints:
                top_endpoint = sorted_endpoints[0]
                share = (
                    top_endpoint.bytes_sent + top_endpoint.bytes_recv
                ) / total_bytes
                if share > 0.5:
                    detections.append(
                        {
                            "severity": "info",
                            "summary": "Traffic concentration on a single host",
                            "details": f"{top_endpoint.ip} accounts for {share * 100:.1f}% of IP bytes.",
                        }
                    )

    enrichment = _build_ips_enrichment(
        endpoints=endpoint_rows,
        conversations=conversation_rows,
        suspicious_port_profiles=suspicious_port_profiles,
        lateral_movement_scores=lateral_movement_scores,
        intel_findings=intel_findings,
        detections=detections,
    )

    return IpSummary(
        path=path,
        total_packets=total_packets,
        total_bytes=total_bytes,
        unique_ips=len(unique_ips),
        unique_sources=len(src_ips),
        unique_destinations=len(dst_ips),
        ipv4_count=len(ipv4_set),
        ipv6_count=len(ipv6_set),
        protocol_counts=protocol_counts,
        src_counts=src_counts,
        dst_counts=dst_counts,
        ip_category_counts=ip_category_counts,
        ip_mac_counts=ip_mac_counts,
        ip_hostnames=dict(ip_hostnames),
        endpoints=endpoint_rows,
        conversations=conversation_rows,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
        tls_client_hellos=tls_client_hellos,
        ja3_counts=ja3_counts,
        ja4_counts=ja4_counts,
        ja4s_counts=ja4s_counts,
        sni_counts=sni_counts,
        sni_entropy=sni_entropy,
        ja_reputation_hits=ja_reputation_hits,
        tls_cert_risks=tls_cert_risks,
        suspicious_port_profiles=suspicious_port_profiles,
        lateral_movement_scores=lateral_movement_scores,
        intel_findings=intel_findings,
        detections=detections,
        errors=errors,
        confirmed_tcp_service_ports={
            ip_text: sorted(list(ports))
            for ip_text, ports in confirmed_tcp_service_ports.items()
            if ports
        },
        analyst_verdict=str(enrichment.get("analyst_verdict", "") or ""),
        analyst_confidence=str(
            enrichment.get("analyst_confidence", "low") or "low"
        ),
        analyst_reasons=list(enrichment.get("analyst_reasons", []) or []),
        deterministic_checks=dict(
            enrichment.get("deterministic_checks", {}) or {}
        ),
        exposure_profiles=list(enrichment.get("exposure_profiles", []) or []),
        priority_asset_profiles=list(
            enrichment.get("priority_asset_profiles", []) or []
        ),
        infrastructure_clusters=list(
            enrichment.get("infrastructure_clusters", []) or []
        ),
        intent_profiles=list(enrichment.get("intent_profiles", []) or []),
        corroborated_findings=list(
            enrichment.get("corroborated_findings", []) or []
        ),
        risk_matrix=list(enrichment.get("risk_matrix", []) or []),
        false_positive_context=list(
            enrichment.get("false_positive_context", []) or []
        ),
    )
