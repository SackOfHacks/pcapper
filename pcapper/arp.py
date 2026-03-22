from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
import math
import re
from typing import Optional

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


def analyze_arp(path: Path, show_status: bool = True) -> ArpSummary:
    if ARP is None:
        return ArpSummary(path=path, errors=["Scapy unavailable (ARP layer missing)"])

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)
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
    reply_dst_targets_by_mac: dict[str, set[str]] = defaultdict(set)
    replies_by_ip_mac: dict[str, Counter[str]] = defaultdict(Counter)
    conversations: dict[tuple[str, str, str, str, str], ArpConversation] = {}
    sessions: dict[tuple[str, str], ArpSession] = {}
    files: set[str] = set()
    plain: Counter[str] = Counter()

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

            arp_layer = pkt[ARP]  # type: ignore[index]
            op = int(getattr(arp_layer, "op", 0) or 0)
            opcode_name = _opcode_name(op)
            src_ip = str(getattr(arp_layer, "psrc", "0.0.0.0") or "0.0.0.0")
            dst_ip = str(getattr(arp_layer, "pdst", "0.0.0.0") or "0.0.0.0")
            src_mac = str(getattr(arp_layer, "hwsrc", "00:00:00:00:00:00") or "00:00:00:00:00:00")
            dst_mac = str(getattr(arp_layer, "hwdst", "00:00:00:00:00:00") or "00:00:00:00:00:00")
            hwtype = int(getattr(arp_layer, "hwtype", 0) or 0)
            ptype = int(getattr(arp_layer, "ptype", 0) or 0)
            version = _version_label(hwtype, ptype)

            summary.src_ips[src_ip] += 1
            summary.dst_ips[dst_ip] += 1
            summary.src_macs[src_mac] += 1
            summary.dst_macs[dst_mac] += 1
            summary.opcode_counts[opcode_name] += 1

            key = (src_ip, dst_ip, src_mac, dst_mac, opcode_name)
            convo = conversations.get(key)
            if convo is None:
                convo = ArpConversation(src_ip=src_ip, dst_ip=dst_ip, src_mac=src_mac, dst_mac=dst_mac, opcode=opcode_name)
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
                elif ts is not None:
                    pending = request_times.get((dst_ip, src_ip))
                    if pending:
                        req_ts = pending.popleft()
                        if ts >= req_ts:
                            reply_latencies_by_responder[src_ip].append(ts - req_ts)
            else:
                summary.response_codes[opcode_name] += 1

            session_key = (dst_ip, src_ip)
            session = sessions.get(session_key)
            if session is None:
                session = ArpSession(client_ip=dst_ip, server_ip=src_ip)
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
    summary.conversations = sorted(conversations.values(), key=lambda item: item.packets, reverse=True)
    summary.sessions = sorted(
        sessions.values(),
        key=lambda item: (item.requests + item.replies),
        reverse=True,
    )

    if summary.duration > 0:
        summary.pps_by_source = {
            src: (count / summary.duration) for src, count in summary.client_details.items() if count > 0
        }

    latency_values = [v for values in reply_latencies_by_responder.values() for v in values if v >= 0]
    if latency_values:
        summary.reply_latency_summary = {
            "median_s": _median(latency_values),
            "p95_s": sorted(latency_values)[int(max(0, min(len(latency_values) - 1, math.ceil(len(latency_values) * 0.95) - 1)))],
            "samples": float(len(latency_values)),
        }

    if summary.server_details:
        gateway_guess, _count = summary.server_details.most_common(1)[0]
        if gateway_guess and gateway_guess != "0.0.0.0":
            summary.gateway_ip = gateway_guess
            summary.gateway_mac_candidates = Counter(replies_by_ip_mac.get(gateway_guess, Counter()))

    max_anomalies = 200

    for ip_value, macs in ip_to_macs.items():
        if len(macs) > 1 and len(summary.anomalies) < max_anomalies:
            summary.threats["ARP Spoofing"] += 1
            if _is_virtual_mac(next(iter(macs), "")):
                summary.benign_indicators["Virtual IP failover MAC pattern"] += 1
            summary.risk_factors["IP claimed by multiple MAC addresses"] += 1
            summary.victim_conflicts[ip_value] = Counter(replies_by_ip_mac.get(ip_value, Counter()))
            summary.anomalies.append(
                ArpAnomaly(
                    severity="HIGH",
                    title="ARP IP/MAC Conflict",
                    description=f"IP {ip_value} observed with multiple MACs: {', '.join(sorted(macs))}",
                    src=ip_value,
                    dst="-",
                    ts=0.0,
                )
            )

    for mac_value, ips in mac_to_ips.items():
        if len(ips) >= 8 and len(summary.anomalies) < max_anomalies:
            summary.threats["Address Impersonation"] += 1
            summary.risk_factors["Single MAC claims many IPs"] += 1
            summary.anomalies.append(
                ArpAnomaly(
                    severity="MEDIUM",
                    title="MAC Claims Many IPs",
                    description=f"MAC {mac_value} claimed {len(ips)} unique IPs.",
                    src=mac_value,
                    dst="-",
                    ts=0.0,
                )
            )

    for src_ip, targets in request_targets.items():
        if len(targets) >= 32 and len(summary.anomalies) < max_anomalies:
            summary.threats["ARP Sweep"] += 1
            summary.risk_factors["Broad ARP target sweep"] += 1
            summary.anomalies.append(
                ArpAnomaly(
                    severity="MEDIUM",
                    title="ARP Sweep Activity",
                    description=f"Source {src_ip} requested {len(targets)} distinct ARP targets.",
                    src=src_ip,
                    dst="-",
                    ts=0.0,
                )
            )

    if summary.unsolicited_replies >= 20 and len(summary.anomalies) < max_anomalies:
        summary.threats["Poisoning Indicators"] += 1
        summary.risk_factors["High unsolicited ARP reply volume"] += 1
        summary.anomalies.append(
            ArpAnomaly(
                severity="HIGH",
                title="High Unsolicited ARP Replies",
                description=f"Observed {summary.unsolicited_replies} unsolicited ARP replies.",
                src="-",
                dst="-",
                ts=0.0,
            )
        )

    if summary.total_packets and (summary.arp_packets / summary.total_packets) >= 0.35 and len(summary.anomalies) < max_anomalies:
        summary.threats["Layer2 Flooding"] += 1
        summary.risk_factors["High ARP traffic ratio"] += 1
        summary.anomalies.append(
            ArpAnomaly(
                severity="MEDIUM",
                title="High ARP Traffic Share",
                description=f"ARP traffic ratio is {(summary.arp_packets / summary.total_packets):.1%} of capture.",
                src="-",
                dst="-",
                ts=0.0,
            )
        )

    if summary.gratuitous_arp >= 25 and len(summary.anomalies) < max_anomalies:
        summary.threats["Failover/Poisoning Signal"] += 1
        summary.risk_factors["Excess gratuitous ARP"] += 1
        summary.anomalies.append(
            ArpAnomaly(
                severity="MEDIUM",
                title="Excess Gratuitous ARP",
                description=f"Observed {summary.gratuitous_arp} gratuitous ARP frames.",
                src="-",
                dst="-",
                ts=0.0,
            )
        )

    if summary.gateway_ip and len(summary.gateway_mac_candidates) > 1 and len(summary.anomalies) < max_anomalies:
        top = ", ".join(f"{mac}({count})" for mac, count in summary.gateway_mac_candidates.most_common(4))
        severity = "MEDIUM" if any(_is_virtual_mac(mac) for mac in summary.gateway_mac_candidates) else "HIGH"
        if severity == "MEDIUM":
            summary.benign_indicators["Gateway MAC changed with virtual MAC prefix"] += 1
        summary.threats["Gateway ARP Integrity Risk"] += 1
        summary.risk_factors["Gateway IP mapped to multiple MACs"] += 1
        summary.anomalies.append(
            ArpAnomaly(
                severity=severity,
                title="Gateway ARP MAC Flip",
                description=f"Gateway {summary.gateway_ip} observed with multiple MACs: {top}",
                src=summary.gateway_ip,
                dst="-",
                ts=0.0,
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
            suspect_pairs.append((mac_value, overlap, int(unsolicited_by_src_mac[mac_value])))
    if suspect_pairs and len(summary.anomalies) < max_anomalies:
        suspect_pairs.sort(key=lambda row: row[2], reverse=True)
        detail = ", ".join(f"{mac} ips={';'.join(ips)} unsolicited={count}" for mac, ips, count in suspect_pairs[:4])
        summary.threats["ARP Poisoning Pair Pattern"] += len(suspect_pairs)
        summary.risk_factors["One MAC claims multiple high-value IPs"] += 1
        summary.anomalies.append(
            ArpAnomaly(
                severity="HIGH",
                title="Poisoning Pair Pattern",
                description=detail,
                src="-",
                dst="-",
                ts=0.0,
            )
        )

    if summary.pps_by_source:
        pps_values = list(summary.pps_by_source.values())
        center = _median(pps_values)
        spread = _mad(pps_values, center)
        if spread <= 0:
            spread = max(0.1, center * 0.25)
        outliers = [(src, pps) for src, pps in summary.pps_by_source.items() if pps > center + (4.0 * spread) and pps >= 10.0]
        if outliers and len(summary.anomalies) < max_anomalies:
            outliers.sort(key=lambda row: row[1], reverse=True)
            text = ", ".join(f"{src}={pps:.1f}pps" for src, pps in outliers[:6])
            summary.threats["ARP Flood Source"] += len(outliers)
            summary.risk_factors["Source ARP pps outlier"] += 1
            summary.anomalies.append(
                ArpAnomaly(
                    severity="HIGH",
                    title="ARP Broadcast/Request Storm",
                    description=f"Per-source ARP rates outlier (median={center:.2f}pps): {text}",
                    src="-",
                    dst="-",
                    ts=0.0,
                )
            )

    for responder_ip, latencies in reply_latencies_by_responder.items():
        if len(latencies) < 10:
            continue
        med = _median(latencies)
        if med < 0.001 and summary.unsolicited_replies >= 10 and len(summary.anomalies) < max_anomalies:
            summary.threats["Automated ARP Response Pattern"] += 1
            summary.risk_factors["Near-zero ARP reply latency with unsolicited replies"] += 1
            summary.anomalies.append(
                ArpAnomaly(
                    severity="MEDIUM",
                    title="ARP Reply Timing Anomaly",
                    description=f"Responder {responder_ip} median ARP reply latency is {med*1000:.2f} ms over {len(latencies)} samples.",
                    src=responder_ip,
                    dst="-",
                    ts=0.0,
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
    if summary.proxy_arp_candidates and len(summary.anomalies) < max_anomalies:
        summary.proxy_arp_candidates = sorted(
            summary.proxy_arp_candidates,
            key=lambda item: (int(item.get("dst_targets", 0)), int(item.get("claimed_ips", 0))),
            reverse=True,
        )
        top = summary.proxy_arp_candidates[0]
        summary.threats["Proxy ARP-like Behavior"] += len(summary.proxy_arp_candidates)
        summary.risk_factors["Responder MAC handles many destination ARP targets"] += 1
        summary.anomalies.append(
            ArpAnomaly(
                severity="MEDIUM",
                title="Proxy ARP-like Responder",
                description=(
                    f"MAC {top.get('mac')} replied across many targets "
                    f"(targets={top.get('dst_targets')}, claimed_ips={top.get('claimed_ips')})."
                ),
                src=str(top.get("mac", "-")),
                dst="-",
                ts=0.0,
            )
        )

    for src_ip, targets in request_targets.items():
        if len(targets) >= 32 and unsolicited_by_src_ip.get(src_ip, 0) >= 5 and len(summary.anomalies) < max_anomalies:
            summary.threats["Recon + Poisoning Sequence"] += 1
            summary.risk_factors["ARP sweep followed by unsolicited replies"] += 1
            summary.anomalies.append(
                ArpAnomaly(
                    severity="HIGH",
                    title="Recon-to-Poisoning Progression",
                    description=(
                        f"Source {src_ip} swept {len(targets)} targets and later emitted "
                        f"{unsolicited_by_src_ip.get(src_ip, 0)} unsolicited replies."
                    ),
                    src=src_ip,
                    dst="-",
                    ts=0.0,
                )
            )

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
                ts=0.0,
            )
        )

    if summary.files_discovered:
        for name in summary.files_discovered[:10]:
            summary.artifacts.append(
                ArpArtifact(kind="file", detail=name, src="-", dst="-", ts=0.0)
            )

    return summary
