from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from .pcap_cache import get_reader
from .utils import safe_float

try:
    from scapy.layers.l2 import ARP, Ether  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:
    ARP = Ether = Raw = None  # type: ignore


_FILENAME_RE = re.compile(
    r"[\w\-.()\[\] ]+\.(?:exe|dll|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|txt|bat|ps1|jpg|jpeg|png|gif|iso|img|tar|gz|7z|rar)",
    re.IGNORECASE,
)

_VIRTUAL_MAC_PREFIXES = (
    "00:00:5e:00:01",  # VRRP
    "00:00:5e:00:02",  # CARP
    "00:00:0c:07:ac",  # HSRP
)


@dataclass
class ArpConversation:
    src_ip: str
    dst_ip: str
    src_mac: str
    dst_mac: str
    opcode: str
    packets: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None


@dataclass
class ArpSession:
    client_ip: str
    server_ip: str
    requests: int = 0
    replies: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None


@dataclass
class ArpArtifact:
    kind: str
    detail: str
    src: str
    dst: str
    ts: float


@dataclass
class ArpAnomaly:
    severity: str
    title: str
    description: str
    src: str
    dst: str
    ts: float


@dataclass
class ArpSummary:
    path: Path
    duration: float = 0.0
    total_packets: int = 0
    arp_packets: int = 0
    arp_requests: int = 0
    arp_replies: int = 0
    gratuitous_arp: int = 0
    arp_probes: int = 0
    unsolicited_replies: int = 0
    src_ips: Counter[str] = field(default_factory=Counter)
    dst_ips: Counter[str] = field(default_factory=Counter)
    src_macs: Counter[str] = field(default_factory=Counter)
    dst_macs: Counter[str] = field(default_factory=Counter)
    opcode_counts: Counter[str] = field(default_factory=Counter)
    response_codes: Counter[str] = field(default_factory=Counter)
    request_summary: Counter[str] = field(default_factory=Counter)
    server_details: Counter[str] = field(default_factory=Counter)
    client_details: Counter[str] = field(default_factory=Counter)
    client_versions: Counter[str] = field(default_factory=Counter)
    server_versions: Counter[str] = field(default_factory=Counter)
    plaintext_observed: Counter[str] = field(default_factory=Counter)
    files_discovered: list[str] = field(default_factory=list)
    conversations: list[ArpConversation] = field(default_factory=list)
    sessions: list[ArpSession] = field(default_factory=list)
    artifacts: list[ArpArtifact] = field(default_factory=list)
    timeline: list[ArpArtifact] = field(default_factory=list)
    anomalies: list[ArpAnomaly] = field(default_factory=list)
    threats: Counter[str] = field(default_factory=Counter)
    benign_indicators: Counter[str] = field(default_factory=Counter)
    risk_factors: Counter[str] = field(default_factory=Counter)
    gateway_ip: str = ""
    gateway_mac_candidates: Counter[str] = field(default_factory=Counter)
    victim_conflicts: dict[str, Counter[str]] = field(default_factory=dict)
    proxy_arp_candidates: list[dict[str, object]] = field(default_factory=list)
    pps_by_source: dict[str, float] = field(default_factory=dict)
    reply_latency_summary: dict[str, float] = field(default_factory=dict)
    deterministic_checks: dict[str, list[str]] = field(default_factory=dict)
    rate_peaks: dict[str, float] = field(default_factory=dict)
    anomalies_dropped: int = 0
    errors: list[str] = field(default_factory=list)


def _opcode_name(op: int) -> str:
    mapping = {
        1: "Request",
        2: "Reply",
        3: "RARP Request",
        4: "RARP Reply",
        8: "InARP Request",
        9: "InARP Reply",
    }
    return mapping.get(op, f"Opcode {op}")


def _version_label(hwtype: int, ptype: int) -> str:
    if hwtype == 1 and ptype == 0x0800:
        return "Ethernet/IPv4"
    if hwtype == 1 and ptype == 0x86DD:
        return "Ethernet/IPv6"
    return f"hw={hwtype},ptype=0x{ptype:04x}"


def _extract_payload_strings(pkt: object) -> list[str]:
    payload_bytes = b""
    if Raw is not None and hasattr(pkt, "haslayer") and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
        try:
            payload_bytes = bytes(pkt[Raw].load)  # type: ignore[index]
        except Exception:
            payload_bytes = b""
    if not payload_bytes:
        return []
    text = payload_bytes.decode("latin-1", errors="ignore")
    tokens = []
    for token in re.findall(r"[ -~]{6,}", text):
        cleaned = " ".join(token.split())
        if cleaned:
            tokens.append(cleaned[:96])
    return tokens


def _extract_filenames(strings: list[str]) -> set[str]:
    found: set[str] = set()
    for item in strings:
        found.update(_FILENAME_RE.findall(item))
    return found


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    svals = sorted(values)
    mid = len(svals) // 2
    if len(svals) % 2 == 0:
        return (svals[mid - 1] + svals[mid]) / 2.0
    return svals[mid]


def _mad(values: list[float], center: float) -> float:
    if not values:
        return 0.0
    return _median([abs(v - center) for v in values])


def _is_virtual_mac(mac: str) -> bool:
    lower = (mac or "").lower()
    return any(lower.startswith(prefix) for prefix in _VIRTUAL_MAC_PREFIXES)


def _is_private_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except Exception:
        return False


def analyze_arp(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
) -> ArpSummary:
    if ARP is None:
        return ArpSummary(path=path, errors=["Scapy unavailable (ARP layer missing)"])

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path,
            show_status=show_status,
            packets=packets,
            meta=meta,
        )
    except Exception as exc:
        return ArpSummary(path=path, errors=[f"Error opening pcap: {exc}"])

    summary = ArpSummary(path=path)
    start_ts: Optional[float] = None
    end_ts: Optional[float] = None

    ip_to_macs: dict[str, set[str]] = defaultdict(set)
    mac_to_ips: dict[str, set[str]] = defaultdict(set)
    req_pairs: Counter[tuple[str, str]] = Counter()
    reply_pairs: Counter[tuple[str, str]] = Counter()
    request_targets: dict[str, set[str]] = defaultdict(set)
    request_times: dict[tuple[str, str], deque[float]] = defaultdict(deque)
    reply_latencies_by_responder: dict[str, list[float]] = defaultdict(list)
    unsolicited_by_src_ip: Counter[str] = Counter()
    unsolicited_by_src_mac: Counter[str] = Counter()
    unsolicited_to_broadcast_by_src_mac: Counter[str] = Counter()
    probes_by_src_mac: Counter[str] = Counter()
    probe_targets_by_src_mac: dict[str, set[str]] = defaultdict(set)
    ip_mac_reply_timeline: dict[str, list[tuple[float, str]]] = defaultdict(list)
    reply_dst_targets_by_mac: dict[str, set[str]] = defaultdict(set)
    reply_dst_targets_by_ip: dict[str, set[str]] = defaultdict(set)
    replies_by_ip_mac: dict[str, Counter[str]] = defaultdict(Counter)
    arp_packets_by_second: Counter[int] = Counter()
    conversations: dict[tuple[str, str, str, str, str], ArpConversation] = {}
    sessions: dict[tuple[str, str], ArpSession] = {}
    src_first_seen: dict[str, float] = {}
    mac_first_seen: dict[str, float] = {}
    files: set[str] = set()
    plain: Counter[str] = Counter()
    deterministic_checks: dict[str, list[str]] = {
        "gateway_integrity": [],
        "duplicate_ip_ownership": [],
        "poisoning_pair_pattern": [],
        "unsolicited_reply_abuse": [],
        "arp_recon_sweep": [],
        "arp_storm_flood": [],
        "proxy_arp_misuse": [],
        "recon_to_poison_progression": [],
        "rapid_gateway_mac_flip": [],
        "probe_spray": [],
        "broadcast_unsolicited_reply": [],
        "timing_automation_signal": [],
        "likely_benign_failover": [],
    }

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    status.update(int(min(100, (pos / size_bytes) * 100)))
                except Exception:
                    pass

            summary.total_packets += 1
            if not hasattr(pkt, "haslayer") or not pkt.haslayer(ARP):  # type: ignore[truthy-bool]
                continue

            summary.arp_packets += 1
            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if start_ts is None or ts < start_ts:
                    start_ts = ts
                if end_ts is None or ts > end_ts:
                    end_ts = ts
                arp_packets_by_second[int(ts)] += 1

            arp_layer = pkt[ARP]  # type: ignore[index]
            op = int(getattr(arp_layer, "op", 0) or 0)
            opcode_name = _opcode_name(op)
            src_ip = str(getattr(arp_layer, "psrc", "0.0.0.0") or "0.0.0.0")
            dst_ip = str(getattr(arp_layer, "pdst", "0.0.0.0") or "0.0.0.0")
            src_mac = str(
                getattr(arp_layer, "hwsrc", "00:00:00:00:00:00") or "00:00:00:00:00:00"
            )
            dst_mac = str(
                getattr(arp_layer, "hwdst", "00:00:00:00:00:00") or "00:00:00:00:00:00"
            )
            hwtype = int(getattr(arp_layer, "hwtype", 0) or 0)
            ptype = int(getattr(arp_layer, "ptype", 0) or 0)
            version = _version_label(hwtype, ptype)

            summary.src_ips[src_ip] += 1
            summary.dst_ips[dst_ip] += 1
            summary.src_macs[src_mac] += 1
            summary.dst_macs[dst_mac] += 1
            summary.opcode_counts[opcode_name] += 1
            if ts is not None:
                if src_ip not in src_first_seen:
                    src_first_seen[src_ip] = ts
                if src_mac not in mac_first_seen:
                    mac_first_seen[src_mac] = ts

            key = (src_ip, dst_ip, src_mac, dst_mac, opcode_name)
            convo = conversations.get(key)
            if convo is None:
                convo = ArpConversation(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_mac=src_mac,
                    dst_mac=dst_mac,
                    opcode=opcode_name,
                )
                conversations[key] = convo
            convo.packets += 1
            if ts is not None:
                if convo.first_seen is None or ts < convo.first_seen:
                    convo.first_seen = ts
                if convo.last_seen is None or ts > convo.last_seen:
                    convo.last_seen = ts

            ip_to_macs[src_ip].add(src_mac)
            mac_to_ips[src_mac].add(src_ip)
            if op == 2:
                replies_by_ip_mac[src_ip][src_mac] += 1
                reply_dst_targets_by_mac[src_mac].add(dst_ip)
                reply_dst_targets_by_ip[src_ip].add(dst_ip)

            if op == 1:
                summary.arp_requests += 1
                summary.request_summary["Request"] += 1
                summary.client_details[src_ip] += 1
                summary.client_versions[version] += 1
                req_pairs[(src_ip, dst_ip)] += 1
                if dst_ip != "0.0.0.0":
                    request_targets[src_ip].add(dst_ip)
                    if ts is not None:
                        request_times[(src_ip, dst_ip)].append(ts)
                if src_ip == dst_ip:
                    summary.gratuitous_arp += 1
                    summary.request_summary["Gratuitous Request"] += 1
                if src_ip == "0.0.0.0":
                    summary.arp_probes += 1
                    summary.request_summary["Probe"] += 1
                    probes_by_src_mac[src_mac] += 1
                    if dst_ip != "0.0.0.0":
                        probe_targets_by_src_mac[src_mac].add(dst_ip)
            elif op == 2:
                summary.arp_replies += 1
                summary.response_codes["Reply"] += 1
                summary.server_details[src_ip] += 1
                summary.server_versions[version] += 1
                reply_pairs[(src_ip, dst_ip)] += 1
                if src_ip == dst_ip:
                    summary.gratuitous_arp += 1
                    summary.response_codes["Gratuitous Reply"] += 1
                if req_pairs.get((dst_ip, src_ip), 0) == 0:
                    summary.unsolicited_replies += 1
                    unsolicited_by_src_ip[src_ip] += 1
                    unsolicited_by_src_mac[src_mac] += 1
                    summary.response_codes["Unsolicited Reply"] += 1
                    if dst_mac.lower() == "ff:ff:ff:ff:ff:ff":
                        unsolicited_to_broadcast_by_src_mac[src_mac] += 1
                elif ts is not None:
                    pending = request_times.get((dst_ip, src_ip))
                    if pending:
                        req_ts = pending.popleft()
                        if ts >= req_ts:
                            reply_latencies_by_responder[src_ip].append(ts - req_ts)
                if ts is not None:
                    ip_mac_reply_timeline[src_ip].append((ts, src_mac))
            else:
                summary.response_codes[opcode_name] += 1

            if op == 1:
                session_key = (src_ip, dst_ip)
            elif op == 2:
                session_key = (dst_ip, src_ip)
            else:
                session_key = (dst_ip, src_ip)
            session = sessions.get(session_key)
            if session is None:
                session = ArpSession(client_ip=session_key[0], server_ip=session_key[1])
                sessions[session_key] = session
            if op == 1:
                session.requests += 1
            elif op == 2:
                session.replies += 1
            if ts is not None:
                if session.first_seen is None or ts < session.first_seen:
                    session.first_seen = ts
                if session.last_seen is None or ts > session.last_seen:
                    session.last_seen = ts

            strings = _extract_payload_strings(pkt)
            for token in strings:
                plain[token] += 1
            files.update(_extract_filenames(strings))

    except Exception as exc:
        summary.errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        status.finish()
        try:
            reader.close()
        except Exception:
            pass

    if start_ts is not None and end_ts is not None:
        summary.duration = max(0.0, end_ts - start_ts)

    summary.plaintext_observed = Counter({k: v for k, v in plain.most_common(25)})
    summary.files_discovered = sorted(files)[:50]
    summary.conversations = sorted(
        conversations.values(), key=lambda item: item.packets, reverse=True
    )
    summary.sessions = sorted(
        sessions.values(),
        key=lambda item: (item.requests + item.replies),
        reverse=True,
    )

    if summary.duration > 0:
        summary.pps_by_source = {
            src: (count / summary.duration)
            for src, count in summary.client_details.items()
            if count > 0
        }

    latency_values = [
        v for values in reply_latencies_by_responder.values() for v in values if v >= 0
    ]
    if latency_values:
        summary.reply_latency_summary = {
            "median_s": _median(latency_values),
            "p95_s": sorted(latency_values)[
                int(
                    max(
                        0,
                        min(
                            len(latency_values) - 1,
                            math.ceil(len(latency_values) * 0.95) - 1,
                        ),
                    )
                )
            ],
            "samples": float(len(latency_values)),
        }
    if arp_packets_by_second:
        peak_second, peak_count = arp_packets_by_second.most_common(1)[0]
        avg_rate = (
            (summary.arp_packets / summary.duration)
            if summary.duration > 0
            else float(peak_count)
        )
        summary.rate_peaks = {
            "peak_pps": float(peak_count),
            "avg_pps": float(avg_rate),
            "peak_second": float(peak_second),
        }

    if summary.server_details:
        gateway_scores: Counter[str] = Counter()
        for ip_value, count in summary.server_details.items():
            if ip_value == "0.0.0.0":
                continue
            weight = int(count)
            if _is_private_ipv4(ip_value):
                weight += 5
            weight += min(20, len(reply_dst_targets_by_ip.get(ip_value, set())))
            gateway_scores[ip_value] += weight
        gateway_guess = ""
        if gateway_scores:
            gateway_guess, _score = gateway_scores.most_common(1)[0]
        if gateway_guess and gateway_guess != "0.0.0.0":
            summary.gateway_ip = gateway_guess
            summary.gateway_mac_candidates = Counter(
                replies_by_ip_mac.get(gateway_guess, Counter())
            )

    max_anomalies = 200

    def _add_anomaly(item: ArpAnomaly) -> None:
        if len(summary.anomalies) >= max_anomalies:
            summary.anomalies_dropped += 1
            return
        summary.anomalies.append(item)

    target_counts = [len(v) for v in request_targets.values() if v]
    target_center = _median([float(v) for v in target_counts]) if target_counts else 0.0
    target_spread = (
        _mad([float(v) for v in target_counts], target_center) if target_counts else 0.0
    )
    if target_spread <= 0.0:
        target_spread = max(2.0, target_center * 0.25)
    sweep_threshold = max(16, int(math.ceil(target_center + (4.0 * target_spread))))
    unsolicited_threshold = max(10, int(summary.arp_packets * 0.05))
    gratuitous_threshold = max(10, int(summary.arp_replies * 0.15))
    arp_ratio = (
        (summary.arp_packets / summary.total_packets) if summary.total_packets else 0.0
    )

    for ip_value, macs in ip_to_macs.items():
        if len(macs) > 1:
            summary.threats["ARP Spoofing"] += 1
            if _is_virtual_mac(next(iter(macs), "")):
                summary.benign_indicators["Virtual IP failover MAC pattern"] += 1
                deterministic_checks["likely_benign_failover"].append(
                    f"{ip_value} multi-mac includes virtual MAC prefix ({', '.join(sorted(macs)[:4])})"
                )
            summary.risk_factors["IP claimed by multiple MAC addresses"] += 1
            summary.victim_conflicts[ip_value] = Counter(
                replies_by_ip_mac.get(ip_value, Counter())
            )
            deterministic_checks["duplicate_ip_ownership"].append(
                f"{ip_value} claimed by {len(macs)} MACs ({', '.join(sorted(macs)[:4])})"
            )
            _add_anomaly(
                ArpAnomaly(
                    severity="HIGH",
                    title="ARP IP/MAC Conflict",
                    description=f"IP {ip_value} observed with multiple MACs: {', '.join(sorted(macs))}",
                    src=ip_value,
                    dst="-",
                    ts=src_first_seen.get(ip_value, start_ts or 0.0),
                )
            )

    for mac_value, ips in mac_to_ips.items():
        if len(ips) >= 8:
            summary.threats["Address Impersonation"] += 1
            summary.risk_factors["Single MAC claims many IPs"] += 1
            _add_anomaly(
                ArpAnomaly(
                    severity="MEDIUM",
                    title="MAC Claims Many IPs",
                    description=f"MAC {mac_value} claimed {len(ips)} unique IPs.",
                    src=mac_value,
                    dst="-",
                    ts=mac_first_seen.get(mac_value, start_ts or 0.0),
                )
            )

    for src_ip, targets in request_targets.items():
        if len(targets) >= sweep_threshold:
            summary.threats["ARP Sweep"] += 1
            summary.risk_factors["Broad ARP target sweep"] += 1
            deterministic_checks["arp_recon_sweep"].append(
                f"{src_ip} requested {len(targets)} distinct ARP targets"
            )
            _add_anomaly(
                ArpAnomaly(
                    severity="MEDIUM",
                    title="ARP Sweep Activity",
                    description=f"Source {src_ip} requested {len(targets)} distinct ARP targets.",
                    src=src_ip,
                    dst="-",
                    ts=src_first_seen.get(src_ip, start_ts or 0.0),
                )
            )

    if summary.unsolicited_replies >= unsolicited_threshold:
        summary.threats["Poisoning Indicators"] += 1
        summary.risk_factors["High unsolicited ARP reply volume"] += 1
        deterministic_checks["unsolicited_reply_abuse"].append(
            f"unsolicited ARP replies={summary.unsolicited_replies} threshold={unsolicited_threshold}"
        )
        _add_anomaly(
            ArpAnomaly(
                severity="HIGH",
                title="High Unsolicited ARP Replies",
                description=f"Observed {summary.unsolicited_replies} unsolicited ARP replies.",
                src="-",
                dst="-",
                ts=start_ts or 0.0,
            )
        )

    if summary.total_packets and summary.arp_packets >= 150 and arp_ratio >= 0.35:
        summary.threats["Layer2 Flooding"] += 1
        summary.risk_factors["High ARP traffic ratio"] += 1
        deterministic_checks["arp_storm_flood"].append(
            f"arp traffic ratio={arp_ratio:.1%}"
        )
        _add_anomaly(
            ArpAnomaly(
                severity="MEDIUM",
                title="High ARP Traffic Share",
                description=f"ARP traffic ratio is {arp_ratio:.1%} of capture.",
                src="-",
                dst="-",
                ts=start_ts or 0.0,
            )
        )

    if summary.gratuitous_arp >= gratuitous_threshold:
        summary.threats["Failover/Poisoning Signal"] += 1
        summary.risk_factors["Excess gratuitous ARP"] += 1
        deterministic_checks["gateway_integrity"].append(
            f"gratuitous ARP frames elevated ({summary.gratuitous_arp}) threshold={gratuitous_threshold}"
        )
        _add_anomaly(
            ArpAnomaly(
                severity="MEDIUM",
                title="Excess Gratuitous ARP",
                description=f"Observed {summary.gratuitous_arp} gratuitous ARP frames.",
                src="-",
                dst="-",
                ts=start_ts or 0.0,
            )
        )

    if summary.gateway_ip and len(summary.gateway_mac_candidates) > 1:
        top = ", ".join(
            f"{mac}({count})"
            for mac, count in summary.gateway_mac_candidates.most_common(4)
        )
        severity = (
            "MEDIUM"
            if any(_is_virtual_mac(mac) for mac in summary.gateway_mac_candidates)
            else "HIGH"
        )
        if severity == "MEDIUM":
            summary.benign_indicators[
                "Gateway MAC changed with virtual MAC prefix"
            ] += 1
            deterministic_checks["likely_benign_failover"].append(
                f"gateway {summary.gateway_ip} MAC change includes virtual prefix ({top})"
            )
        summary.threats["Gateway ARP Integrity Risk"] += 1
        summary.risk_factors["Gateway IP mapped to multiple MACs"] += 1
        deterministic_checks["gateway_integrity"].append(
            f"gateway {summary.gateway_ip} mapped to multiple MACs ({top})"
        )
        _add_anomaly(
            ArpAnomaly(
                severity=severity,
                title="Gateway ARP MAC Flip",
                description=f"Gateway {summary.gateway_ip} observed with multiple MACs: {top}",
                src=summary.gateway_ip,
                dst="-",
                ts=src_first_seen.get(summary.gateway_ip, start_ts or 0.0),
            )
        )

    suspect_pairs: list[tuple[str, list[str], int]] = []
    gateway_set = {summary.gateway_ip} if summary.gateway_ip else set()
    high_value_ips = set(gateway_set)
    for ip_value, count in summary.server_details.most_common(6):
        if count >= 5 and ip_value != "0.0.0.0":
            high_value_ips.add(ip_value)
    for mac_value, ips in mac_to_ips.items():
        overlap = sorted(set(ips) & high_value_ips)
        if len(overlap) >= 2 and unsolicited_by_src_mac.get(mac_value, 0) >= 5:
            suspect_pairs.append(
                (mac_value, overlap, int(unsolicited_by_src_mac[mac_value]))
            )
    if suspect_pairs:
        suspect_pairs.sort(key=lambda row: row[2], reverse=True)
        detail = ", ".join(
            f"{mac} ips={';'.join(ips)} unsolicited={count}"
            for mac, ips, count in suspect_pairs[:4]
        )
        summary.threats["ARP Poisoning Pair Pattern"] += len(suspect_pairs)
        summary.risk_factors["One MAC claims multiple high-value IPs"] += 1
        deterministic_checks["poisoning_pair_pattern"].append(detail)
        _add_anomaly(
            ArpAnomaly(
                severity="HIGH",
                title="Poisoning Pair Pattern",
                description=detail,
                src="-",
                dst="-",
                ts=start_ts or 0.0,
            )
        )

    if summary.pps_by_source:
        pps_values = list(summary.pps_by_source.values())
        center = _median(pps_values)
        spread = _mad(pps_values, center)
        if spread <= 0:
            spread = max(0.1, center * 0.25)
        outliers = [
            (src, pps)
            for src, pps in summary.pps_by_source.items()
            if pps > center + (4.0 * spread) and pps >= 10.0
        ]
        if outliers:
            outliers.sort(key=lambda row: row[1], reverse=True)
            text = ", ".join(f"{src}={pps:.1f}pps" for src, pps in outliers[:6])
            summary.threats["ARP Flood Source"] += len(outliers)
            summary.risk_factors["Source ARP pps outlier"] += 1
            deterministic_checks["arp_storm_flood"].append(
                f"pps outlier vs median {center:.2f}pps: {text}"
            )
            _add_anomaly(
                ArpAnomaly(
                    severity="HIGH",
                    title="ARP Broadcast/Request Storm",
                    description=f"Per-source ARP rates outlier (median={center:.2f}pps): {text}",
                    src="-",
                    dst="-",
                    ts=start_ts or 0.0,
                )
            )

    for responder_ip, latencies in reply_latencies_by_responder.items():
        if len(latencies) < 10:
            continue
        med = _median(latencies)
        if med < 0.001 and summary.unsolicited_replies >= max(
            5, unsolicited_threshold // 2
        ):
            summary.threats["Automated ARP Response Pattern"] += 1
            summary.risk_factors[
                "Near-zero ARP reply latency with unsolicited replies"
            ] += 1
            deterministic_checks["timing_automation_signal"].append(
                f"{responder_ip} median_reply_ms={med * 1000.0:.2f} samples={len(latencies)}"
            )
            _add_anomaly(
                ArpAnomaly(
                    severity="MEDIUM",
                    title="ARP Reply Timing Anomaly",
                    description=f"Responder {responder_ip} median ARP reply latency is {med * 1000:.2f} ms over {len(latencies)} samples.",
                    src=responder_ip,
                    dst="-",
                    ts=src_first_seen.get(responder_ip, start_ts or 0.0),
                )
            )
            break

    for mac_value, dst_set in reply_dst_targets_by_mac.items():
        claimed_ips = mac_to_ips.get(mac_value, set())
        if len(dst_set) >= 8 and len(claimed_ips) >= 3:
            candidate = {
                "mac": mac_value,
                "dst_targets": len(dst_set),
                "claimed_ips": len(claimed_ips),
            }
            summary.proxy_arp_candidates.append(candidate)
    if summary.proxy_arp_candidates:
        summary.proxy_arp_candidates = sorted(
            summary.proxy_arp_candidates,
            key=lambda item: (
                int(item.get("dst_targets", 0)),
                int(item.get("claimed_ips", 0)),
            ),
            reverse=True,
        )
        top = summary.proxy_arp_candidates[0]
        summary.threats["Proxy ARP-like Behavior"] += len(summary.proxy_arp_candidates)
        summary.risk_factors["Responder MAC handles many destination ARP targets"] += 1
        deterministic_checks["proxy_arp_misuse"].append(
            f"{top.get('mac')} targets={top.get('dst_targets')} claimed_ips={top.get('claimed_ips')}"
        )
        _add_anomaly(
            ArpAnomaly(
                severity="MEDIUM",
                title="Proxy ARP-like Responder",
                description=(
                    f"MAC {top.get('mac')} replied across many targets "
                    f"(targets={top.get('dst_targets')}, claimed_ips={top.get('claimed_ips')})."
                ),
                src=str(top.get("mac", "-")),
                dst="-",
                ts=mac_first_seen.get(str(top.get("mac", "")), start_ts or 0.0),
            )
        )

    for src_ip, targets in request_targets.items():
        if (
            len(targets) >= sweep_threshold
            and unsolicited_by_src_ip.get(src_ip, 0) >= 5
        ):
            summary.threats["Recon + Poisoning Sequence"] += 1
            summary.risk_factors["ARP sweep followed by unsolicited replies"] += 1
            deterministic_checks["recon_to_poison_progression"].append(
                f"{src_ip} sweep_targets={len(targets)} unsolicited={unsolicited_by_src_ip.get(src_ip, 0)}"
            )
            _add_anomaly(
                ArpAnomaly(
                    severity="HIGH",
                    title="Recon-to-Poisoning Progression",
                    description=(
                        f"Source {src_ip} swept {len(targets)} targets and later emitted "
                        f"{unsolicited_by_src_ip.get(src_ip, 0)} unsolicited replies."
                    ),
                    src=src_ip,
                    dst="-",
                    ts=src_first_seen.get(src_ip, start_ts or 0.0),
                )
            )

    for mac, count in probes_by_src_mac.items():
        target_count = len(probe_targets_by_src_mac.get(mac, set()))
        if count >= 20 and target_count >= 16:
            summary.threats["Probe Spray Activity"] += 1
            summary.risk_factors["High-volume ARP probe spray"] += 1
            deterministic_checks["probe_spray"].append(
                f"{mac} probes={count} unique_probe_targets={target_count}"
            )
            _add_anomaly(
                ArpAnomaly(
                    severity="MEDIUM",
                    title="ARP Probe Spray",
                    description=f"MAC {mac} sent {count} ARP probes across {target_count} targets.",
                    src=mac,
                    dst="-",
                    ts=mac_first_seen.get(mac, start_ts or 0.0),
                )
            )

    for mac, count in unsolicited_to_broadcast_by_src_mac.items():
        if count >= 5:
            summary.threats["Broadcast ARP Reply Abuse"] += 1
            summary.risk_factors["Unsolicited broadcast ARP replies"] += 1
            deterministic_checks["broadcast_unsolicited_reply"].append(
                f"{mac} unsolicited_replies_to_broadcast={count}"
            )
            _add_anomaly(
                ArpAnomaly(
                    severity="HIGH",
                    title="Broadcast Unsolicited ARP Replies",
                    description=f"MAC {mac} sent {count} unsolicited replies to broadcast destination.",
                    src=mac,
                    dst="ff:ff:ff:ff:ff:ff",
                    ts=mac_first_seen.get(mac, start_ts or 0.0),
                )
            )

    if summary.gateway_ip:
        gateway_events = sorted(
            ip_mac_reply_timeline.get(summary.gateway_ip, []), key=lambda item: item[0]
        )
        if len(gateway_events) >= 4:
            last_mac = ""
            flips = 0
            window_starts: list[float] = []
            for event_ts, event_mac in gateway_events:
                if event_mac != last_mac and last_mac:
                    flips += 1
                    window_starts.append(event_ts)
                last_mac = event_mac
            if flips >= 3:
                spread = (
                    (window_starts[-1] - window_starts[0])
                    if len(window_starts) >= 2
                    else summary.duration
                )
                if spread <= 300:
                    summary.threats["Rapid Gateway MAC Flip"] += 1
                    summary.risk_factors[
                        "Gateway MAC changed repeatedly in short window"
                    ] += 1
                    deterministic_checks["rapid_gateway_mac_flip"].append(
                        f"gateway={summary.gateway_ip} flips={flips} window_s={spread:.1f}"
                    )
                    _add_anomaly(
                        ArpAnomaly(
                            severity="HIGH",
                            title="Rapid Gateway MAC Flips",
                            description=(
                                f"Gateway {summary.gateway_ip} changed responding MAC {flips} times "
                                f"within {spread:.1f}s."
                            ),
                            src=summary.gateway_ip,
                            dst="-",
                            ts=src_first_seen.get(summary.gateway_ip, start_ts or 0.0),
                        )
                    )

    peak_pps = float(summary.rate_peaks.get("peak_pps", 0.0) or 0.0)
    avg_pps = float(summary.rate_peaks.get("avg_pps", 0.0) or 0.0)
    if peak_pps >= 120.0 and peak_pps >= max(4.0 * max(avg_pps, 1.0), 120.0):
        summary.threats["ARP Burst Storm"] += 1
        summary.risk_factors["Extreme per-second ARP burst"] += 1
        deterministic_checks["arp_storm_flood"].append(
            f"peak_pps={peak_pps:.1f} avg_pps={avg_pps:.1f}"
        )
        _add_anomaly(
            ArpAnomaly(
                severity="HIGH",
                title="Extreme ARP Burst",
                description=f"Peak ARP rate {peak_pps:.1f}pps (avg {avg_pps:.1f}pps).",
                src="-",
                dst="-",
                ts=float(
                    summary.rate_peaks.get("peak_second", start_ts or 0.0)
                    or (start_ts or 0.0)
                ),
            )
        )

    external_arp_claims = [
        ip_value
        for ip_value in summary.src_ips
        if ip_value not in {"0.0.0.0", "255.255.255.255"}
        and not _is_private_ipv4(ip_value)
    ]
    if external_arp_claims:
        summary.benign_indicators[
            "Non-private ARP source claims (possible SPAN/misconfig/noise)"
        ] += len(external_arp_claims)
        deterministic_checks["likely_benign_failover"].append(
            f"non-private ARP source IPs seen ({len(external_arp_claims)}): {', '.join(sorted(external_arp_claims)[:5])}"
        )

    summary.deterministic_checks = {
        key: list(dict.fromkeys(values))
        for key, values in deterministic_checks.items()
        if values
    }

    for item in summary.anomalies[:120]:
        summary.timeline.append(
            ArpArtifact(
                kind="timeline",
                detail=f"[{item.severity}] {item.title}: {item.description}",
                src=item.src,
                dst=item.dst,
                ts=item.ts,
            )
        )

    for threat_name, count in summary.threats.items():
        summary.artifacts.append(
            ArpArtifact(
                kind="threat",
                detail=f"{threat_name}: {count}",
                src="-",
                dst="-",
                ts=end_ts or start_ts or 0.0,
            )
        )

    if summary.files_discovered:
        for name in summary.files_discovered[:10]:
            summary.artifacts.append(
                ArpArtifact(
                    kind="file",
                    detail=name,
                    src="-",
                    dst="-",
                    ts=end_ts or start_ts or 0.0,
                )
            )

    return summary


def merge_arp_summaries(summaries: Iterable[ArpSummary]) -> ArpSummary:
    summary_list = list(summaries)
    if not summary_list:
        return ArpSummary(path=Path("ALL_PCAPS"))

    merged = ArpSummary(path=Path("ALL_PCAPS"))
    deterministic_checks: dict[str, list[str]] = defaultdict(list)
    seen_check_values: dict[str, set[str]] = defaultdict(set)

    for item in summary_list:
        merged.duration += float(item.duration or 0.0)
        merged.total_packets += int(item.total_packets or 0)
        merged.arp_packets += int(item.arp_packets or 0)
        merged.arp_requests += int(item.arp_requests or 0)
        merged.arp_replies += int(item.arp_replies or 0)
        merged.gratuitous_arp += int(item.gratuitous_arp or 0)
        merged.arp_probes += int(item.arp_probes or 0)
        merged.unsolicited_replies += int(item.unsolicited_replies or 0)
        merged.anomalies_dropped += int(getattr(item, "anomalies_dropped", 0) or 0)

        merged.src_ips.update(item.src_ips)
        merged.dst_ips.update(item.dst_ips)
        merged.src_macs.update(item.src_macs)
        merged.dst_macs.update(item.dst_macs)
        merged.opcode_counts.update(item.opcode_counts)
        merged.response_codes.update(item.response_codes)
        merged.request_summary.update(item.request_summary)
        merged.server_details.update(item.server_details)
        merged.client_details.update(item.client_details)
        merged.client_versions.update(item.client_versions)
        merged.server_versions.update(item.server_versions)
        merged.plaintext_observed.update(item.plaintext_observed)
        merged.threats.update(item.threats)
        merged.benign_indicators.update(item.benign_indicators)
        merged.risk_factors.update(item.risk_factors)

        for key, value in (item.victim_conflicts or {}).items():
            merged.victim_conflicts.setdefault(key, Counter()).update(value)

        merged.conversations.extend(item.conversations)
        merged.sessions.extend(item.sessions)
        merged.artifacts.extend(item.artifacts)
        merged.timeline.extend(item.timeline)
        merged.anomalies.extend(item.anomalies)
        merged.proxy_arp_candidates.extend(item.proxy_arp_candidates)
        merged.files_discovered.extend(item.files_discovered)
        merged.errors.extend(item.errors)

        for src, pps in (item.pps_by_source or {}).items():
            merged.pps_by_source[src] = max(
                float(merged.pps_by_source.get(src, 0.0)), float(pps)
            )
        for key, value in (item.rate_peaks or {}).items():
            merged.rate_peaks[key] = max(
                float(merged.rate_peaks.get(key, 0.0)), float(value)
            )

        if item.reply_latency_summary:
            existing_samples = float(
                merged.reply_latency_summary.get("samples", 0.0) or 0.0
            )
            new_samples = float(item.reply_latency_summary.get("samples", 0.0) or 0.0)
            if new_samples > existing_samples:
                merged.reply_latency_summary = dict(item.reply_latency_summary)

        if item.gateway_ip and item.gateway_ip != "0.0.0.0":
            if not merged.gateway_ip:
                merged.gateway_ip = item.gateway_ip
            if item.gateway_ip == merged.gateway_ip:
                merged.gateway_mac_candidates.update(item.gateway_mac_candidates)

        for check_key, values in (item.deterministic_checks or {}).items():
            for value in values or []:
                text = str(value).strip()
                if not text or text in seen_check_values[check_key]:
                    continue
                seen_check_values[check_key].add(text)
                deterministic_checks[check_key].append(text)

    merged.conversations = sorted(
        merged.conversations, key=lambda row: row.packets, reverse=True
    )[:500]
    merged.sessions = sorted(
        merged.sessions, key=lambda row: (row.requests + row.replies), reverse=True
    )[:500]
    merged.anomalies = sorted(
        merged.anomalies,
        key=lambda row: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(row.severity, 9),
            row.ts,
        ),
    )[:500]
    merged.timeline = sorted(merged.timeline, key=lambda row: row.ts)[:500]
    merged.artifacts = merged.artifacts[:500]
    merged.proxy_arp_candidates = sorted(
        merged.proxy_arp_candidates,
        key=lambda row: (
            int(row.get("dst_targets", 0)),
            int(row.get("claimed_ips", 0)),
        ),
        reverse=True,
    )[:200]
    merged.files_discovered = sorted(set(merged.files_discovered))[:200]
    merged.deterministic_checks = {
        key: values[:120] for key, values in deterministic_checks.items()
    }

    return merged
