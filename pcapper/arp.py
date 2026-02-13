from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
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
    anomalies: list[ArpAnomaly] = field(default_factory=list)
    threats: Counter[str] = field(default_factory=Counter)
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

            if op == 1:
                summary.arp_requests += 1
                summary.request_summary["Request"] += 1
                summary.client_details[src_ip] += 1
                summary.client_versions[version] += 1
                req_pairs[(src_ip, dst_ip)] += 1
                if dst_ip != "0.0.0.0":
                    request_targets[src_ip].add(dst_ip)
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
                    summary.response_codes["Unsolicited Reply"] += 1
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

    max_anomalies = 200

    for ip_value, macs in ip_to_macs.items():
        if len(macs) > 1 and len(summary.anomalies) < max_anomalies:
            summary.threats["ARP Spoofing"] += 1
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
