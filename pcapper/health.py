from __future__ import annotations

import ipaddress
import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .certificates import analyze_certificates
from .pcap_cache import get_reader
from .progress import run_with_busy_status
from .utils import extract_packet_endpoints, safe_float

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.layers.l2 import Ether  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore
    Ether = None  # type: ignore
    Raw = None  # type: ignore


@dataclass(frozen=True)
class HealthSummary:
    path: Path
    total_packets: int
    total_bytes: int
    tcp_packets: int
    udp_packets: int
    retransmissions: int
    retransmission_rate: float
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]
    endpoint_packets: Counter[str]
    endpoint_bytes: Counter[str]
    flow_duration_buckets: dict[str, Counter[str]]
    tcp_syn: int
    tcp_syn_ack: int
    tcp_rst: int
    tcp_zero_window: int
    tcp_small_window: int
    tcp_syn_sources: Counter[str]
    tcp_rst_sources: Counter[str]
    tcp_zero_window_sources: Counter[str]
    udp_amp_candidates: list[str]
    ot_timing: dict[str, list[dict[str, object]]]
    ttl_expired: int
    ttl_low: int
    dscp_counts: Counter[int]
    ecn_counts: Counter[int]
    snmp_packets: int
    snmp_versions: Counter[str]
    snmp_communities: Counter[str]
    expired_certs: int
    self_signed_certs: int
    findings: list[dict[str, object]]
    analyst_verdict: str
    analyst_confidence: str
    analyst_reasons: list[str]
    deterministic_checks: dict[str, list[str]]
    sequence_findings: list[dict[str, object]]
    host_risk_profiles: list[dict[str, object]]
    outlier_windows: list[dict[str, object]]
    snmp_risks: list[dict[str, object]]
    ot_risk_profiles: list[dict[str, object]]
    zone_anomalies: list[str]
    evidence_anchors: list[dict[str, object]]
    benign_context: list[str]
    errors: list[str]


def merge_health_summaries(
    summaries: list[HealthSummary] | tuple[HealthSummary, ...] | set[HealthSummary],
) -> HealthSummary:
    summary_list = list(summaries)
    if not summary_list:
        return HealthSummary(
            path=Path("ALL_PCAPS_0"),
            total_packets=0,
            total_bytes=0,
            tcp_packets=0,
            udp_packets=0,
            retransmissions=0,
            retransmission_rate=0.0,
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
            endpoint_packets=Counter(),
            endpoint_bytes=Counter(),
            flow_duration_buckets={
                "all": Counter(),
                "tcp": Counter(),
                "udp": Counter(),
            },
            tcp_syn=0,
            tcp_syn_ack=0,
            tcp_rst=0,
            tcp_zero_window=0,
            tcp_small_window=0,
            tcp_syn_sources=Counter(),
            tcp_rst_sources=Counter(),
            tcp_zero_window_sources=Counter(),
            udp_amp_candidates=[],
            ot_timing={"profinet_rt": [], "enip_io": [], "s7_rosctr": []},
            ttl_expired=0,
            ttl_low=0,
            dscp_counts=Counter(),
            ecn_counts=Counter(),
            snmp_packets=0,
            snmp_versions=Counter(),
            snmp_communities=Counter(),
            expired_certs=0,
            self_signed_certs=0,
            findings=[],
            analyst_verdict="",
            analyst_confidence="low",
            analyst_reasons=[],
            deterministic_checks={},
            sequence_findings=[],
            host_risk_profiles=[],
            outlier_windows=[],
            snmp_risks=[],
            ot_risk_profiles=[],
            zone_anomalies=[],
            evidence_anchors=[],
            benign_context=[],
            errors=[],
        )

    total_packets = 0
    total_bytes = 0
    tcp_packets = 0
    udp_packets = 0
    retransmissions = 0
    tcp_syn = 0
    tcp_syn_ack = 0
    tcp_rst = 0
    tcp_zero_window = 0
    tcp_small_window = 0
    ttl_expired = 0
    ttl_low = 0
    snmp_packets = 0
    expired_certs = 0
    self_signed_certs = 0

    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    endpoint_packets: Counter[str] = Counter()
    endpoint_bytes: Counter[str] = Counter()
    flow_duration_buckets: dict[str, Counter[str]] = {
        "all": Counter(),
        "tcp": Counter(),
        "udp": Counter(),
    }
    tcp_syn_sources: Counter[str] = Counter()
    tcp_rst_sources: Counter[str] = Counter()
    tcp_zero_window_sources: Counter[str] = Counter()
    dscp_counts: Counter[int] = Counter()
    ecn_counts: Counter[int] = Counter()
    snmp_versions: Counter[str] = Counter()
    snmp_communities: Counter[str] = Counter()

    udp_amp_candidates: list[str] = []
    ot_timing: dict[str, list[dict[str, object]]] = {
        "profinet_rt": [],
        "enip_io": [],
        "s7_rosctr": [],
    }
    errors: list[str] = []
    analyst_reasons: list[str] = []
    deterministic_checks: dict[str, list[str]] = {}
    sequence_findings: list[dict[str, object]] = []
    host_risk_profiles: list[dict[str, object]] = []
    outlier_windows: list[dict[str, object]] = []
    snmp_risks: list[dict[str, object]] = []
    ot_risk_profiles: list[dict[str, object]] = []
    zone_anomalies: list[str] = []
    evidence_anchors: list[dict[str, object]] = []
    benign_context: list[str] = []

    for summary in summary_list:
        total_packets += summary.total_packets
        total_bytes += summary.total_bytes
        tcp_packets += summary.tcp_packets
        udp_packets += summary.udp_packets
        retransmissions += summary.retransmissions
        tcp_syn += summary.tcp_syn
        tcp_syn_ack += summary.tcp_syn_ack
        tcp_rst += summary.tcp_rst
        tcp_zero_window += summary.tcp_zero_window
        tcp_small_window += summary.tcp_small_window
        ttl_expired += summary.ttl_expired
        ttl_low += summary.ttl_low
        snmp_packets += summary.snmp_packets
        expired_certs += summary.expired_certs
        self_signed_certs += summary.self_signed_certs

        if summary.first_seen is not None:
            first_seen = (
                summary.first_seen
                if first_seen is None
                else min(first_seen, summary.first_seen)
            )
        if summary.last_seen is not None:
            last_seen = (
                summary.last_seen
                if last_seen is None
                else max(last_seen, summary.last_seen)
            )

        endpoint_packets.update(summary.endpoint_packets)
        endpoint_bytes.update(summary.endpoint_bytes)

        for key in ("all", "tcp", "udp"):
            flow_duration_buckets.setdefault(key, Counter()).update(
                summary.flow_duration_buckets.get(key, Counter())
            )

        tcp_syn_sources.update(summary.tcp_syn_sources)
        tcp_rst_sources.update(summary.tcp_rst_sources)
        tcp_zero_window_sources.update(summary.tcp_zero_window_sources)
        dscp_counts.update(summary.dscp_counts)
        ecn_counts.update(summary.ecn_counts)
        snmp_versions.update(summary.snmp_versions)
        snmp_communities.update(summary.snmp_communities)
        for reason in summary.analyst_reasons:
            if reason not in analyst_reasons:
                analyst_reasons.append(reason)
        for key, values in summary.deterministic_checks.items():
            bucket = deterministic_checks.setdefault(key, [])
            for value in values:
                if value not in bucket:
                    bucket.append(value)
        for item in summary.sequence_findings:
            if item not in sequence_findings:
                sequence_findings.append(item)
        for item in summary.host_risk_profiles:
            if item not in host_risk_profiles:
                host_risk_profiles.append(item)
        for item in summary.outlier_windows:
            if item not in outlier_windows:
                outlier_windows.append(item)
        for item in summary.snmp_risks:
            if item not in snmp_risks:
                snmp_risks.append(item)
        for item in summary.ot_risk_profiles:
            if item not in ot_risk_profiles:
                ot_risk_profiles.append(item)
        for item in summary.zone_anomalies:
            if item not in zone_anomalies:
                zone_anomalies.append(item)
        for item in summary.evidence_anchors:
            if item not in evidence_anchors:
                evidence_anchors.append(item)
        for item in summary.benign_context:
            if item not in benign_context:
                benign_context.append(item)

        udp_amp_candidates.extend(summary.udp_amp_candidates)
        for key in ("profinet_rt", "enip_io", "s7_rosctr"):
            ot_timing[key].extend(summary.ot_timing.get(key, []))
        errors.extend(summary.errors)

    if udp_amp_candidates:
        seen_amp: set[str] = set()
        unique_amp: list[str] = []
        for item in udp_amp_candidates:
            if item in seen_amp:
                continue
            seen_amp.add(item)
            unique_amp.append(item)
        udp_amp_candidates = unique_amp

    retransmission_rate = (retransmissions / tcp_packets) if tcp_packets else 0.0
    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    findings: list[dict[str, object]] = []
    if retransmissions > 50 and retransmission_rate > 0.01:
        findings.append(
            {
                "severity": "warning",
                "summary": "Elevated TCP retransmissions",
                "details": f"{retransmissions} retransmissions ({retransmission_rate:.2%} of TCP packets).",
            }
        )
    if tcp_syn:
        syn_only = tcp_syn - tcp_syn_ack
        if syn_only > 50:
            findings.append(
                {
                    "severity": "warning",
                    "summary": "High SYN without SYN-ACK",
                    "details": f"SYN-only count: {syn_only}.",
                }
            )
        rst_ratio = tcp_rst / max(tcp_syn, 1)
        if tcp_rst > 50 and rst_ratio >= 0.2:
            findings.append(
                {
                    "severity": "warning",
                    "summary": "High TCP RST/SYN ratio",
                    "details": f"RST {tcp_rst} vs SYN {tcp_syn} ({rst_ratio:.2%}).",
                }
            )
    if tcp_zero_window > 20:
        findings.append(
            {
                "severity": "warning",
                "summary": "TCP zero-window events",
                "details": f"{tcp_zero_window} packets with zero window observed.",
            }
        )
    if udp_amp_candidates:
        findings.append(
            {
                "severity": "warning",
                "summary": "Potential UDP amplification patterns",
                "details": ", ".join(udp_amp_candidates[:3]),
            }
        )
    if ttl_expired:
        findings.append(
            {
                "severity": "warning",
                "summary": "Expired TTL/Hop Limit observed",
                "details": f"{ttl_expired} packets with TTL/Hop Limit <= 1.",
            }
        )
    if ttl_low and ttl_low > ttl_expired:
        findings.append(
            {
                "severity": "info",
                "summary": "Low TTL/Hop Limit values",
                "details": f"{ttl_low} packets with TTL/Hop Limit <= 5.",
            }
        )
    if expired_certs:
        findings.append(
            {
                "severity": "warning",
                "summary": "Expired certificates detected",
                "details": f"{expired_certs} expired or invalid certificate(s).",
            }
        )
    if snmp_packets:
        findings.append(
            {
                "severity": "warning",
                "summary": "SNMP traffic observed",
                "details": f"{snmp_packets} SNMP packets detected; review community strings and access controls.",
            }
        )
        if any(comm.lower() in {"public", "private"} for comm in snmp_communities):
            findings.append(
                {
                    "severity": "critical",
                    "summary": "Default SNMP community strings detected",
                    "details": "SNMP community strings include 'public' or 'private'.",
                }
            )

    merged_score = 0
    merged_score += (
        2
        if any(v for v in deterministic_checks.get("udp_reflection_amplification", []))
        else 0
    )
    merged_score += (
        2 if any(v for v in deterministic_checks.get("snmp_exposure_risk", [])) else 0
    )
    merged_score += (
        2 if any(v for v in deterministic_checks.get("ot_cycle_instability", [])) else 0
    )
    merged_score += (
        1
        if any(v for v in deterministic_checks.get("syn_scan_or_exhaustion", []))
        else 0
    )
    merged_score += (
        1 if any(v for v in deterministic_checks.get("tcp_reset_storm", [])) else 0
    )
    merged_score += (
        1
        if any(v for v in deterministic_checks.get("persistent_zero_window", []))
        else 0
    )
    merged_score += (
        1
        if any(v for v in deterministic_checks.get("certificate_hygiene_risk", []))
        else 0
    )
    if merged_score >= 7:
        merged_verdict = (
            "YES - high-confidence network health security risk pattern detected"
        )
        merged_conf = "high"
    elif merged_score >= 4:
        merged_verdict = (
            "LIKELY - multiple corroborating network health risk indicators detected"
        )
        merged_conf = "medium"
    elif merged_score >= 2:
        merged_verdict = (
            "POSSIBLE - suspicious network health indicators require validation"
        )
        merged_conf = "medium"
    else:
        merged_verdict = "NO STRONG SIGNAL - no convincing high-confidence health risk pattern from current heuristics"
        merged_conf = "low"

    return HealthSummary(
        path=Path("ALL_PCAPS"),
        total_packets=total_packets,
        total_bytes=total_bytes,
        tcp_packets=tcp_packets,
        udp_packets=udp_packets,
        retransmissions=retransmissions,
        retransmission_rate=retransmission_rate,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
        endpoint_packets=endpoint_packets,
        endpoint_bytes=endpoint_bytes,
        flow_duration_buckets=flow_duration_buckets,
        tcp_syn=tcp_syn,
        tcp_syn_ack=tcp_syn_ack,
        tcp_rst=tcp_rst,
        tcp_zero_window=tcp_zero_window,
        tcp_small_window=tcp_small_window,
        tcp_syn_sources=tcp_syn_sources,
        tcp_rst_sources=tcp_rst_sources,
        tcp_zero_window_sources=tcp_zero_window_sources,
        udp_amp_candidates=udp_amp_candidates,
        ot_timing=ot_timing,
        ttl_expired=ttl_expired,
        ttl_low=ttl_low,
        dscp_counts=dscp_counts,
        ecn_counts=ecn_counts,
        snmp_packets=snmp_packets,
        snmp_versions=snmp_versions,
        snmp_communities=snmp_communities,
        expired_certs=expired_certs,
        self_signed_certs=self_signed_certs,
        findings=findings,
        analyst_verdict=merged_verdict,
        analyst_confidence=merged_conf,
        analyst_reasons=analyst_reasons,
        deterministic_checks=deterministic_checks,
        sequence_findings=sequence_findings,
        host_risk_profiles=host_risk_profiles,
        outlier_windows=outlier_windows,
        snmp_risks=snmp_risks,
        ot_risk_profiles=ot_risk_profiles,
        zone_anomalies=zone_anomalies,
        evidence_anchors=evidence_anchors,
        benign_context=benign_context,
        errors=errors,
    )


AMPLIFICATION_PORTS = {19, 53, 123, 161, 389, 1900, 5353, 11211}
FLOW_BUCKETS = [
    (0.0, 1.0, "<=1s"),
    (1.0, 10.0, "1-10s"),
    (10.0, 60.0, "10-60s"),
    (60.0, 300.0, "1-5m"),
    (300.0, 1800.0, "5-30m"),
    (1800.0, float("inf"), ">30m"),
]


def _bucketize_duration(duration: float) -> str:
    for low, high, label in FLOW_BUCKETS:
        if low <= duration <= high:
            return label
    return ">30m"


def _extract_s7_rosctr(payload: bytes) -> Optional[str]:
    if not payload:
        return None
    try:
        idx = payload.index(0x32)
    except ValueError:
        return None
    if idx + 1 >= len(payload):
        return None
    rosctr = payload[idx + 1]
    rosctr_map = {1: "Job", 2: "Ack", 3: "AckData", 7: "UserData"}
    return rosctr_map.get(rosctr, f"ROSCTR {rosctr}")


def _timing_stats(
    intervals: dict[str, list[float]], limit: int = 5
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for key, samples in intervals.items():
        if len(samples) < 6:
            continue
        avg = sum(samples) / len(samples)
        if avg <= 0:
            continue
        variance = sum((val - avg) ** 2 for val in samples) / len(samples)
        std_dev = math.sqrt(variance)
        rows.append(
            {
                "session": key,
                "count": len(samples),
                "avg": avg,
                "min": min(samples),
                "max": max(samples),
                "std": std_dev,
                "cv": (std_dev / avg) if avg > 0 else 0.0,
            }
        )
    rows.sort(key=lambda item: (item["cv"], item["avg"]))
    return rows[:limit]


def _read_ber_length(payload: bytes, offset: int) -> tuple[Optional[int], int]:
    if offset >= len(payload):
        return None, offset
    first = payload[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    num_bytes = first & 0x7F
    if num_bytes == 0 or offset + num_bytes > len(payload):
        return None, offset
    length = int.from_bytes(payload[offset : offset + num_bytes], "big")
    offset += num_bytes
    return length, offset


def _parse_snmp(payload: bytes) -> tuple[Optional[str], Optional[str]]:
    if not payload or payload[0] != 0x30:
        return None, None
    length, idx = _read_ber_length(payload, 1)
    if length is None or idx >= len(payload):
        return None, None
    if idx >= len(payload) or payload[idx] != 0x02:
        return None, None
    ver_len, idx = _read_ber_length(payload, idx + 1)
    if ver_len is None or idx + ver_len > len(payload):
        return None, None
    version_val = int.from_bytes(payload[idx : idx + ver_len], "big")
    idx += ver_len
    if idx >= len(payload) or payload[idx] != 0x04:
        return None, None
    comm_len, idx = _read_ber_length(payload, idx + 1)
    if comm_len is None or idx + comm_len > len(payload):
        return None, None
    community = payload[idx : idx + comm_len].decode("latin-1", errors="ignore")

    version_map = {0: "v1", 1: "v2c", 3: "v3"}
    return version_map.get(version_val, f"v{version_val}"), community


def _parse_snmp_pdu(payload: bytes) -> Optional[str]:
    if not payload or payload[0] != 0x30:
        return None
    length, idx = _read_ber_length(payload, 1)
    if length is None or idx >= len(payload):
        return None
    if idx >= len(payload) or payload[idx] != 0x02:
        return None
    ver_len, idx = _read_ber_length(payload, idx + 1)
    if ver_len is None or idx + ver_len > len(payload):
        return None
    idx += ver_len
    if idx >= len(payload) or payload[idx] != 0x04:
        return None
    comm_len, idx = _read_ber_length(payload, idx + 1)
    if comm_len is None or idx + comm_len > len(payload):
        return None
    idx += comm_len
    if idx >= len(payload):
        return None
    pdu = payload[idx]
    return {
        0xA0: "GetRequest",
        0xA1: "GetNextRequest",
        0xA2: "GetResponse",
        0xA3: "SetRequest",
        0xA4: "Trap",
        0xA5: "GetBulkRequest",
        0xA6: "InformRequest",
        0xA7: "SNMPv2-Trap",
        0xA8: "Report",
    }.get(pdu)


def analyze_health(path: Path, show_status: bool = True) -> HealthSummary:
    errors: list[str] = []

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, show_status=show_status
    )

    total_packets = 0
    total_bytes = 0
    tcp_packets = 0
    udp_packets = 0
    retransmissions = 0
    first_seen = None
    last_seen = None
    endpoint_packets: Counter[str] = Counter()
    endpoint_bytes: Counter[str] = Counter()
    tcp_syn = 0
    tcp_syn_ack = 0
    tcp_rst = 0
    tcp_zero_window = 0
    tcp_small_window = 0
    tcp_syn_sources: Counter[str] = Counter()
    tcp_rst_sources: Counter[str] = Counter()
    tcp_zero_window_sources: Counter[str] = Counter()
    ttl_expired = 0
    ttl_low = 0
    dscp_counts: Counter[int] = Counter()
    ecn_counts: Counter[int] = Counter()
    snmp_packets = 0
    snmp_versions: Counter[str] = Counter()
    snmp_communities: Counter[str] = Counter()
    snmp_sources: Counter[str] = Counter()
    snmp_set_sources: Counter[str] = Counter()

    tcp_flows: dict[tuple[str, str, int, int], dict[str, Optional[float]]] = (
        defaultdict(lambda: {"first": None, "last": None})
    )
    udp_flows: dict[tuple[str, str, int, int], dict[str, Optional[float]]] = (
        defaultdict(lambda: {"first": None, "last": None})
    )
    amp_flows: dict[tuple[str, str, int], dict[str, int]] = defaultdict(
        lambda: {"client": 0, "server": 0}
    )
    profinet_last_ts: dict[str, float] = {}
    profinet_intervals: dict[str, list[float]] = defaultdict(list)
    enip_io_last_ts: dict[str, float] = {}
    enip_io_intervals: dict[str, list[float]] = defaultdict(list)
    s7_last_ts: dict[str, float] = {}
    s7_intervals: dict[str, list[float]] = defaultdict(list)
    seen_seq: dict[tuple[str, str, int, int], set[tuple[int, int]]] = defaultdict(set)

    packet_index = 0
    event_anchors: list[dict[str, object]] = []
    zone_anomalies: list[str] = []
    mgmt_zone_events: set[str] = set()
    host_syn_targets: dict[str, set[str]] = defaultdict(set)
    host_mgmt_targets: dict[str, set[str]] = defaultdict(set)
    host_snmp_default: Counter[str] = Counter()
    host_scores: Counter[str] = Counter()
    host_reasons: dict[str, list[str]] = defaultdict(list)
    minute_metrics: dict[int, Counter[str]] = defaultdict(Counter)
    minute_samples: dict[int, list[str]] = defaultdict(list)

    management_ports = {
        22,
        23,
        53,
        102,
        135,
        139,
        161,
        162,
        389,
        445,
        502,
        636,
        3389,
        5985,
        5986,
        20000,
        3268,
        3269,
    }

    try:
        for pkt in reader:
            packet_index += 1
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            total_packets += 1
            pkt_len = int(len(pkt)) if hasattr(pkt, "__len__") else 0
            total_bytes += pkt_len
            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            src_ip, dst_ip = extract_packet_endpoints(pkt)
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                ip_layer = pkt[IP]  # type: ignore[index]
                ttl_val = int(getattr(ip_layer, "ttl", 0) or 0)
                if ttl_val <= 1:
                    ttl_expired += 1
                if ttl_val and ttl_val <= 5:
                    ttl_low += 1
                tos = int(getattr(ip_layer, "tos", 0) or 0)
                dscp_counts[(tos >> 2) & 0x3F] += 1
                ecn_counts[tos & 0x03] += 1
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                ip_layer = pkt[IPv6]  # type: ignore[index]
                hlim = int(getattr(ip_layer, "hlim", 0) or 0)
                if hlim <= 1:
                    ttl_expired += 1
                if hlim and hlim <= 5:
                    ttl_low += 1
                tc = int(getattr(ip_layer, "tc", 0) or 0)
                dscp_counts[(tc >> 2) & 0x3F] += 1
                ecn_counts[tc & 0x03] += 1

            if src_ip:
                endpoint_packets[src_ip] += 1
                endpoint_bytes[src_ip] += pkt_len
            if dst_ip:
                endpoint_packets[dst_ip] += 1
                endpoint_bytes[dst_ip] += pkt_len

            if Ether is not None and pkt.haslayer(Ether):  # type: ignore[truthy-bool]
                try:
                    eth_layer = pkt[Ether]  # type: ignore[index]
                    etype = int(getattr(eth_layer, "type", 0) or 0)
                    if etype == 0x8892:
                        src_mac = str(getattr(eth_layer, "src", "?"))
                        dst_mac = str(getattr(eth_layer, "dst", "?"))
                        pn_key = f"{src_mac} -> {dst_mac}"
                        if ts is not None:
                            last_ts_val = profinet_last_ts.get(pn_key)
                            if last_ts_val is not None:
                                interval = ts - last_ts_val
                                if interval >= 0:
                                    profinet_intervals[pn_key].append(interval)
                            profinet_last_ts[pn_key] = ts
                except Exception:
                    pass

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp_packets += 1
                tcp_layer = pkt[TCP]  # type: ignore[index]
                if src_ip and dst_ip:
                    try:
                        seq = int(getattr(tcp_layer, "seq", 0) or 0)
                        sport = int(getattr(tcp_layer, "sport", 0) or 0)
                        dport = int(getattr(tcp_layer, "dport", 0) or 0)
                        flags = int(getattr(tcp_layer, "flags", 0) or 0)
                        window = int(getattr(tcp_layer, "window", 0) or 0)
                        payload_len = 0
                        if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                            payload_len = len(bytes(pkt[Raw]))  # type: ignore[index]
                        else:
                            try:
                                payload_len = len(bytes(tcp_layer.payload))
                            except Exception:
                                payload_len = 0

                        key = (src_ip, dst_ip, sport, dport)
                        sig = (seq, payload_len)
                        if sig in seen_seq[key]:
                            retransmissions += 1
                            if ts is not None:
                                minute_metrics[int(ts // 60)]["retrans"] += 1
                                minute_samples[int(ts // 60)].append(
                                    f"Retrans {src_ip}->{dst_ip}:{dport}"
                                )
                        else:
                            seen_seq[key].add(sig)
                        if len(seen_seq[key]) > 20000:
                            seen_seq[key].clear()

                        flow = tcp_flows[key]
                        if ts is not None:
                            if flow["first"] is None or ts < float(flow["first"] or ts):
                                flow["first"] = ts
                            if flow["last"] is None or ts > float(flow["last"] or ts):
                                flow["last"] = ts

                        if flags & 0x02:
                            tcp_syn += 1
                            tcp_syn_sources[src_ip] += 1
                            host_syn_targets[src_ip].add(dst_ip)
                            if ts is not None:
                                minute_metrics[int(ts // 60)]["syn"] += 1
                                minute_samples[int(ts // 60)].append(
                                    f"SYN {src_ip}->{dst_ip}:{dport}"
                                )
                        if flags & 0x12 == 0x12:
                            tcp_syn_ack += 1
                        if flags & 0x04:
                            tcp_rst += 1
                            tcp_rst_sources[src_ip] += 1
                            if ts is not None:
                                minute_metrics[int(ts // 60)]["rst"] += 1
                                minute_samples[int(ts // 60)].append(
                                    f"RST {src_ip}->{dst_ip}:{dport}"
                                )
                        if window == 0:
                            tcp_zero_window += 1
                            tcp_zero_window_sources[src_ip] += 1
                            if ts is not None:
                                minute_metrics[int(ts // 60)]["zero_window"] += 1
                                minute_samples[int(ts // 60)].append(
                                    f"ZeroWindow {src_ip}->{dst_ip}:{dport}"
                                )
                        elif window < 1024:
                            tcp_small_window += 1

                        if dport in management_ports:
                            host_mgmt_targets[src_ip].add(dst_ip)
                            try:
                                src_is_private = ipaddress.ip_address(src_ip).is_private
                                dst_is_private = ipaddress.ip_address(dst_ip).is_private
                            except Exception:
                                src_is_private = True
                                dst_is_private = True
                            if src_is_private != dst_is_private:
                                drift = f"Mgmt/OT service cross-zone flow: {src_ip}->{dst_ip}:{dport}"
                                if drift not in mgmt_zone_events:
                                    mgmt_zone_events.add(drift)
                                    zone_anomalies.append(drift)
                                    event_anchors.append(
                                        {
                                            "packet": packet_index,
                                            "signal": "zone_policy_drift",
                                            "details": drift,
                                        }
                                    )

                        if sport == 102 or dport == 102:
                            s7_payload = b""
                            if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                                s7_payload = bytes(pkt[Raw])  # type: ignore[index]
                            else:
                                try:
                                    s7_payload = bytes(tcp_layer.payload)
                                except Exception:
                                    s7_payload = b""
                            rosctr = _extract_s7_rosctr(s7_payload) or "ROSCTR ?"
                            s7_key = f"{src_ip}:{sport} -> {dst_ip}:{dport} ({rosctr})"
                            if ts is not None:
                                last_s7 = s7_last_ts.get(s7_key)
                                if last_s7 is not None:
                                    interval = ts - last_s7
                                    if interval >= 0:
                                        s7_intervals[s7_key].append(interval)
                                s7_last_ts[s7_key] = ts
                    except Exception:
                        pass

            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp_packets += 1
                udp_layer = pkt[UDP]  # type: ignore[index]
                sport = int(getattr(udp_layer, "sport", 0) or 0)
                dport = int(getattr(udp_layer, "dport", 0) or 0)
                if src_ip and dst_ip:
                    flow = udp_flows[(src_ip, dst_ip, sport, dport)]
                    if ts is not None:
                        if flow["first"] is None or ts < float(flow["first"] or ts):
                            flow["first"] = ts
                        if flow["last"] is None or ts > float(flow["last"] or ts):
                            flow["last"] = ts

                if dport in AMPLIFICATION_PORTS or sport in AMPLIFICATION_PORTS:
                    payload_len = 0
                    if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                        payload_len = len(bytes(pkt[Raw]))  # type: ignore[index]
                    else:
                        try:
                            payload_len = len(bytes(udp_layer.payload))
                        except Exception:
                            payload_len = 0
                    if dport in AMPLIFICATION_PORTS:
                        client = src_ip or "-"
                        server = dst_ip or "-"
                        amp_flows[(client, server, dport)]["client"] += payload_len
                    else:
                        client = dst_ip or "-"
                        server = src_ip or "-"
                        amp_flows[(client, server, sport)]["server"] += payload_len

                if (sport == 2222 or dport == 2222) and src_ip and dst_ip:
                    enip_key = f"{src_ip}:{sport} -> {dst_ip}:{dport}"
                    if ts is not None:
                        last_enip = enip_io_last_ts.get(enip_key)
                        if last_enip is not None:
                            interval = ts - last_enip
                            if interval >= 0:
                                enip_io_intervals[enip_key].append(interval)
                        enip_io_last_ts[enip_key] = ts

                if sport in (161, 162) or dport in (161, 162):
                    snmp_packets += 1
                    if src_ip:
                        snmp_sources[src_ip] += 1
                    if ts is not None:
                        minute_metrics[int(ts // 60)]["snmp"] += 1

                    payload = None
                    if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                        payload = bytes(pkt[Raw])  # type: ignore[index]
                    else:
                        try:
                            payload = bytes(udp_layer.payload)
                        except Exception:
                            payload = None
                    if payload:
                        version, community = _parse_snmp(payload)
                        pdu = _parse_snmp_pdu(payload)
                        if version:
                            snmp_versions[version] += 1
                        if community:
                            snmp_communities[community] += 1
                            if community.lower() in {"public", "private"} and src_ip:
                                host_snmp_default[src_ip] += 1
                                event_anchors.append(
                                    {
                                        "packet": packet_index,
                                        "signal": "snmp_exposure_risk",
                                        "details": f"Default SNMP community '{community}' from {src_ip}",
                                    }
                                )
                        if pdu == "SetRequest" and src_ip:
                            snmp_set_sources[src_ip] += 1
                            event_anchors.append(
                                {
                                    "packet": packet_index,
                                    "signal": "snmp_set_request",
                                    "details": f"SNMP SetRequest from {src_ip} to {dst_ip or '-'}",
                                }
                            )
    finally:
        status.finish()
        reader.close()

    retransmission_rate = (retransmissions / tcp_packets) if tcp_packets else 0.0
    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    flow_duration_buckets: dict[str, Counter[str]] = {
        "all": Counter(),
        "tcp": Counter(),
        "udp": Counter(),
    }
    for flow_map, label_name in ((tcp_flows, "tcp"), (udp_flows, "udp")):
        for info in flow_map.values():
            start = info.get("first")
            end = info.get("last")
            if start is None or end is None:
                continue
            bucket = _bucketize_duration(max(0.0, float(end) - float(start)))
            flow_duration_buckets[label_name][bucket] += 1
            flow_duration_buckets["all"][bucket] += 1

    udp_amp_candidates: list[str] = []
    for (client, server, port), volumes in amp_flows.items():
        client_bytes = volumes.get("client", 0)
        server_bytes = volumes.get("server", 0)
        if server_bytes >= 10000 and (
            client_bytes == 0 or server_bytes / max(client_bytes, 1) >= 5
        ):
            text = f"{client} -> {server}:{port} ({server_bytes}/{client_bytes} bytes)"
            udp_amp_candidates.append(text)
            event_anchors.append(
                {
                    "packet": None,
                    "signal": "udp_reflection_amplification",
                    "details": f"{client}->{server}:{port} server_bytes={server_bytes} client_bytes={client_bytes}",
                }
            )

    ot_timing = {
        "profinet_rt": _timing_stats(profinet_intervals),
        "enip_io": _timing_stats(enip_io_intervals),
        "s7_rosctr": _timing_stats(s7_intervals),
    }

    expired_certs = 0
    self_signed_certs = 0
    try:
        cert_summary = run_with_busy_status(
            path,
            show_status,
            "Health: Certificates",
            analyze_certificates,
            path,
            show_status=False,
        )
        expired_certs = len(cert_summary.expired)
        self_signed_certs = len(cert_summary.self_signed)
        errors.extend(cert_summary.errors)
    except Exception as exc:
        errors.append(str(exc))

    findings: list[dict[str, object]] = []
    if retransmissions > 50 and retransmission_rate > 0.01:
        findings.append(
            {
                "severity": "warning",
                "summary": "Elevated TCP retransmissions",
                "details": f"{retransmissions} retransmissions ({retransmission_rate:.2%} of TCP packets).",
            }
        )
    if tcp_syn:
        syn_only = tcp_syn - tcp_syn_ack
        if syn_only > 50:
            findings.append(
                {
                    "severity": "warning",
                    "summary": "High SYN without SYN-ACK",
                    "details": f"SYN-only count: {syn_only}.",
                }
            )
        rst_ratio = tcp_rst / max(tcp_syn, 1)
        if tcp_rst > 50 and rst_ratio >= 0.2:
            findings.append(
                {
                    "severity": "warning",
                    "summary": "High TCP RST/SYN ratio",
                    "details": f"RST {tcp_rst} vs SYN {tcp_syn} ({rst_ratio:.2%}).",
                }
            )
    if tcp_zero_window > 20:
        findings.append(
            {
                "severity": "warning",
                "summary": "TCP zero-window events",
                "details": f"{tcp_zero_window} packets with zero window observed.",
            }
        )
    if udp_amp_candidates:
        findings.append(
            {
                "severity": "warning",
                "summary": "Potential UDP amplification patterns",
                "details": ", ".join(udp_amp_candidates[:3]),
            }
        )
    if ttl_expired:
        findings.append(
            {
                "severity": "warning",
                "summary": "Expired TTL/Hop Limit observed",
                "details": f"{ttl_expired} packets with TTL/Hop Limit <= 1.",
            }
        )
    if ttl_low and ttl_low > ttl_expired:
        findings.append(
            {
                "severity": "info",
                "summary": "Low TTL/Hop Limit values",
                "details": f"{ttl_low} packets with TTL/Hop Limit <= 5.",
            }
        )
    if expired_certs:
        findings.append(
            {
                "severity": "warning",
                "summary": "Expired certificates detected",
                "details": f"{expired_certs} expired or invalid certificate(s).",
            }
        )
    if snmp_packets:
        findings.append(
            {
                "severity": "warning",
                "summary": "SNMP traffic observed",
                "details": f"{snmp_packets} SNMP packets detected; review community strings and access controls.",
            }
        )
        if any(comm.lower() in {"public", "private"} for comm in snmp_communities):
            findings.append(
                {
                    "severity": "critical",
                    "summary": "Default SNMP community strings detected",
                    "details": "SNMP community strings include 'public' or 'private'.",
                }
            )

    deterministic_checks: dict[str, list[str]] = {
        "syn_scan_or_exhaustion": [],
        "tcp_reset_storm": [],
        "persistent_zero_window": [],
        "udp_reflection_amplification": [],
        "qos_marking_anomaly": [],
        "snmp_exposure_risk": [],
        "ot_cycle_instability": [],
        "certificate_hygiene_risk": [],
        "sequence_degradation_chain": [],
        "zone_policy_drift": [],
        "evidence_provenance": [],
    }

    for src, count in tcp_syn_sources.most_common(8):
        target_count = len(host_syn_targets.get(src, set()))
        if count >= 120 or (count >= 60 and target_count >= 10):
            deterministic_checks["syn_scan_or_exhaustion"].append(
                f"{src} generated {count} SYN packets across {target_count} targets"
            )
            host_scores[src] += 2
            host_reasons[src].append("SYN scan or exhaustion pattern")

    for src, count in tcp_rst_sources.most_common(8):
        syn_count = tcp_syn_sources.get(src, 0)
        rst_ratio = count / max(syn_count, 1)
        if count >= 60 and rst_ratio >= 0.25:
            deterministic_checks["tcp_reset_storm"].append(
                f"{src} generated {count} RST packets with RST/SYN ratio {rst_ratio:.2f}"
            )
            host_scores[src] += 2
            host_reasons[src].append("TCP reset storm behavior")

    for src, count in tcp_zero_window_sources.most_common(8):
        if count >= 20:
            deterministic_checks["persistent_zero_window"].append(
                f"{src} observed with {count} zero-window packets"
            )
            host_scores[src] += 1
            host_reasons[src].append("Persistent zero-window collapse")

    deterministic_checks["udp_reflection_amplification"].extend(udp_amp_candidates[:8])

    suspicious_dscp = [
        (dscp, count)
        for dscp, count in dscp_counts.items()
        if dscp >= 40 and count >= 20
    ]
    for dscp, count in sorted(suspicious_dscp, key=lambda v: -v[1])[:6]:
        deterministic_checks["qos_marking_anomaly"].append(
            f"DSCP {dscp} appears {count} times"
        )

    for src, count in host_snmp_default.most_common(8):
        deterministic_checks["snmp_exposure_risk"].append(
            f"{src} used default SNMP communities {count} times"
        )
        host_scores[src] += 2
        host_reasons[src].append("SNMP default community usage")
    if snmp_versions.get("v1", 0) > 0:
        deterministic_checks["snmp_exposure_risk"].append(
            f"SNMP v1 traffic observed ({snmp_versions.get('v1', 0)})"
        )
    if sum(snmp_set_sources.values()) > 0:
        deterministic_checks["snmp_exposure_risk"].append(
            f"SNMP SetRequest activity observed from {len(snmp_set_sources)} source(s)"
        )

    ot_risk_profiles: list[dict[str, object]] = []
    for family, label_name in (
        ("profinet_rt", "Profinet RT"),
        ("enip_io", "ENIP IO"),
        ("s7_rosctr", "S7 ROSCTR"),
    ):
        for item in ot_timing.get(family, [])[:10]:
            cv = float(item.get("cv", 0.0) or 0.0)
            if cv >= 0.35:
                deterministic_checks["ot_cycle_instability"].append(
                    f"{label_name} {item.get('session')} cv={cv:.2f} avg={float(item.get('avg', 0.0)):.3f}s"
                )
                ot_risk_profiles.append(
                    {
                        "family": label_name,
                        "session": str(item.get("session", "-")),
                        "avg": float(item.get("avg", 0.0) or 0.0),
                        "std": float(item.get("std", 0.0) or 0.0),
                        "cv": cv,
                        "count": int(item.get("count", 0) or 0),
                        "severity": "high" if cv >= 0.5 else "medium",
                    }
                )

    if expired_certs or self_signed_certs:
        deterministic_checks["certificate_hygiene_risk"].append(
            f"expired={expired_certs} self_signed={self_signed_certs}"
        )

    deterministic_checks["zone_policy_drift"].extend(zone_anomalies[:8])

    sequence_findings: list[dict[str, object]] = []
    if (
        deterministic_checks["syn_scan_or_exhaustion"]
        and deterministic_checks["tcp_reset_storm"]
    ):
        sequence_findings.append(
            {
                "sequence": "recon_to_rst_disruption",
                "confidence": "high",
                "details": "SYN fan-out was followed by elevated RST activity",
            }
        )
        deterministic_checks["sequence_degradation_chain"].append(
            "SYN fan-out followed by RST storm behavior"
        )
    if retransmission_rate >= 0.01 and tcp_zero_window >= 20:
        sequence_findings.append(
            {
                "sequence": "load_retrans_zero_window",
                "confidence": "medium",
                "details": "Elevated retransmission rate with persistent zero-window events",
            }
        )
        deterministic_checks["sequence_degradation_chain"].append(
            "Retransmission pressure followed by zero-window collapse"
        )
    if deterministic_checks["ot_cycle_instability"] and (
        deterministic_checks["tcp_reset_storm"]
        or deterministic_checks["persistent_zero_window"]
    ):
        sequence_findings.append(
            {
                "sequence": "ot_jitter_transport_instability",
                "confidence": "medium",
                "details": "OT timing instability coincides with transport degradation signals",
            }
        )
        deterministic_checks["sequence_degradation_chain"].append(
            "OT timing instability overlaps with transport instability"
        )

    outlier_windows: list[dict[str, object]] = []
    for metric in ["syn", "rst", "zero_window", "snmp", "retrans"]:
        values = [int(bucket.get(metric, 0)) for bucket in minute_metrics.values()]
        if not values:
            continue
        mean = sum(values) / len(values)
        variance = sum((val - mean) ** 2 for val in values) / len(values)
        std = math.sqrt(variance)
        threshold = max(5.0, mean + 2.0 * std)
        for minute, bucket in minute_metrics.items():
            value = int(bucket.get(metric, 0))
            if value < threshold:
                continue
            outlier_windows.append(
                {
                    "metric": metric,
                    "window_start": float(minute * 60),
                    "window_end": float(minute * 60 + 59),
                    "value": value,
                    "baseline": round(mean, 2),
                    "threshold": round(threshold, 2),
                    "sample": "; ".join(minute_samples.get(minute, [])[:3]),
                }
            )
    outlier_windows.sort(
        key=lambda item: (
            -(float(item.get("value", 0.0) or 0.0)),
            str(item.get("metric", "")),
        )
    )
    outlier_windows = outlier_windows[:12]

    snmp_risks: list[dict[str, object]] = []
    if snmp_packets:
        snmp_risks.append(
            {
                "risk": "snmp_versions",
                "details": ", ".join(
                    f"{ver}({count})" for ver, count in snmp_versions.most_common(4)
                ),
            }
        )
    if host_snmp_default:
        snmp_risks.append(
            {
                "risk": "default_communities",
                "details": ", ".join(
                    f"{src}({count})" for src, count in host_snmp_default.most_common(6)
                ),
            }
        )
    if snmp_set_sources:
        snmp_risks.append(
            {
                "risk": "set_requests",
                "details": ", ".join(
                    f"{src}({count})" for src, count in snmp_set_sources.most_common(6)
                ),
            }
        )

    for item in zone_anomalies:
        flow = item.split(":", 1)[-1].strip()
        if "->" in flow:
            src = flow.split("->", 1)[0].strip()
            host_scores[src] += 1
            host_reasons[src].append("Cross-zone management/OT service flow")
    for src, targets in host_mgmt_targets.items():
        if len(targets) >= 4:
            host_scores[src] += 1
            host_reasons[src].append("Broad management service fan-out")

    host_risk_profiles: list[dict[str, object]] = []
    for host, score in host_scores.most_common(20):
        reasons: list[str] = []
        for reason in host_reasons.get(host, []):
            if reason not in reasons:
                reasons.append(reason)
        if not reasons:
            continue
        if score >= 5:
            severity = "high"
            confidence = "high"
        elif score >= 3:
            severity = "medium"
            confidence = "medium"
        else:
            severity = "low"
            confidence = "low"
        host_risk_profiles.append(
            {
                "host": host,
                "score": int(score),
                "severity": severity,
                "confidence": confidence,
                "syn": int(tcp_syn_sources.get(host, 0)),
                "rst": int(tcp_rst_sources.get(host, 0)),
                "zero_window": int(tcp_zero_window_sources.get(host, 0)),
                "snmp_default": int(host_snmp_default.get(host, 0)),
                "targets": len(
                    host_syn_targets.get(host, set())
                    | host_mgmt_targets.get(host, set())
                ),
                "reasons": reasons[:4],
            }
        )

    deterministic_checks["evidence_provenance"].append(
        f"{len(event_anchors)} anchor event(s) captured with packet provenance"
    )

    verdict_score = 0
    verdict_score += 2 if deterministic_checks["udp_reflection_amplification"] else 0
    verdict_score += 2 if deterministic_checks["snmp_exposure_risk"] else 0
    verdict_score += 2 if deterministic_checks["ot_cycle_instability"] else 0
    verdict_score += 1 if deterministic_checks["syn_scan_or_exhaustion"] else 0
    verdict_score += 1 if deterministic_checks["tcp_reset_storm"] else 0
    verdict_score += 1 if deterministic_checks["persistent_zero_window"] else 0
    verdict_score += 1 if deterministic_checks["certificate_hygiene_risk"] else 0
    verdict_score += 1 if deterministic_checks["zone_policy_drift"] else 0

    analyst_reasons: list[str] = []
    if deterministic_checks["udp_reflection_amplification"]:
        analyst_reasons.append("UDP reflection/amplification profile detected")
    if deterministic_checks["snmp_exposure_risk"]:
        analyst_reasons.append(
            "SNMP exposure risks detected (version/community/write behavior)"
        )
    if deterministic_checks["ot_cycle_instability"]:
        analyst_reasons.append("OT cycle-time jitter instability detected")
    if deterministic_checks["syn_scan_or_exhaustion"]:
        analyst_reasons.append("SYN scan/exhaustion behavior detected")
    if deterministic_checks["tcp_reset_storm"]:
        analyst_reasons.append("TCP RST storm behavior detected")
    if deterministic_checks["sequence_degradation_chain"]:
        analyst_reasons.append("Sequence-based degradation chain observed")
    if deterministic_checks["zone_policy_drift"]:
        analyst_reasons.append("Cross-zone management/OT service flows observed")

    if verdict_score >= 8:
        analyst_verdict = (
            "YES - HIGH-CONFIDENCE NETWORK HEALTH SECURITY RISK PATTERN DETECTED"
        )
        analyst_confidence = "high"
    elif verdict_score >= 5:
        analyst_verdict = (
            "LIKELY - MULTIPLE CORROBORATING NETWORK HEALTH RISK INDICATORS"
        )
        analyst_confidence = "medium"
    elif verdict_score >= 3:
        analyst_verdict = "POSSIBLE - SUSPICIOUS HEALTH INDICATORS REQUIRE VALIDATION"
        analyst_confidence = "medium"
    else:
        analyst_verdict = (
            "NO STRONG SIGNAL - NO CONVINCING HIGH-CONFIDENCE HEALTH RISK PATTERN"
        )
        analyst_confidence = "low"

    benign_context: list[str] = []
    if not deterministic_checks["syn_scan_or_exhaustion"]:
        benign_context.append(
            "No sustained SYN fan-out behavior exceeded scan/exhaustion thresholds"
        )
    if not deterministic_checks["udp_reflection_amplification"]:
        benign_context.append("No strong UDP reflection/amplification profile detected")
    if not deterministic_checks["ot_cycle_instability"]:
        benign_context.append(
            "OT timing jitter remained within expected variability thresholds"
        )
    if not deterministic_checks["zone_policy_drift"]:
        benign_context.append(
            "No cross-zone management/OT service placement drift detected"
        )

    return HealthSummary(
        path=path,
        total_packets=total_packets,
        total_bytes=total_bytes,
        tcp_packets=tcp_packets,
        udp_packets=udp_packets,
        retransmissions=retransmissions,
        retransmission_rate=retransmission_rate,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
        endpoint_packets=endpoint_packets,
        endpoint_bytes=endpoint_bytes,
        flow_duration_buckets=flow_duration_buckets,
        tcp_syn=tcp_syn,
        tcp_syn_ack=tcp_syn_ack,
        tcp_rst=tcp_rst,
        tcp_zero_window=tcp_zero_window,
        tcp_small_window=tcp_small_window,
        tcp_syn_sources=tcp_syn_sources,
        tcp_rst_sources=tcp_rst_sources,
        tcp_zero_window_sources=tcp_zero_window_sources,
        udp_amp_candidates=udp_amp_candidates,
        ot_timing=ot_timing,
        ttl_expired=ttl_expired,
        ttl_low=ttl_low,
        dscp_counts=dscp_counts,
        ecn_counts=ecn_counts,
        snmp_packets=snmp_packets,
        snmp_versions=snmp_versions,
        snmp_communities=snmp_communities,
        expired_certs=expired_certs,
        self_signed_certs=self_signed_certs,
        findings=findings,
        analyst_verdict=analyst_verdict,
        analyst_confidence=analyst_confidence,
        analyst_reasons=analyst_reasons
        if analyst_reasons
        else ["No high-confidence health risk checks crossed threshold"],
        deterministic_checks=deterministic_checks,
        sequence_findings=sequence_findings,
        host_risk_profiles=host_risk_profiles,
        outlier_windows=outlier_windows,
        snmp_risks=snmp_risks,
        ot_risk_profiles=ot_risk_profiles,
        zone_anomalies=zone_anomalies,
        evidence_anchors=event_anchors[:30],
        benign_context=benign_context,
        errors=errors,
    )
