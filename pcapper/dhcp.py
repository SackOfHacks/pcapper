from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
import ipaddress
import math
import re
from typing import Optional

from .pcap_cache import get_reader
from .utils import safe_float
from .device_detection import device_fingerprints_from_text

try:
    from scapy.layers.inet import IP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.layers.l2 import Ether  # type: ignore
    from scapy.layers.dhcp import DHCP, BOOTP  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:
    IP = UDP = IPv6 = Ether = DHCP = BOOTP = Raw = None


_FILENAME_RE = re.compile(
    r"[\w\-.()\[\] ]+\.(?:exe|dll|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|txt|bat|ps1|jpg|jpeg|png|gif|iso|img|tar|gz|7z|rar)",
    re.IGNORECASE,
)

_DHCP_MESSAGE_TYPES = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM",
}

_SERVER_MSG_TYPES = {"OFFER", "ACK", "NAK"}
_CLIENT_MSG_TYPES = {"DISCOVER", "REQUEST", "DECLINE", "RELEASE", "INFORM"}


@dataclass
class DhcpConversation:
    src_ip: str
    dst_ip: str
    src_mac: str
    dst_mac: str
    src_port: int
    dst_port: int
    message_type: str
    packets: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None


@dataclass
class DhcpSession:
    client_mac: str
    client_ip: str
    server_ip: str
    requests: int = 0
    offers: int = 0
    acks: int = 0
    naks: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None


@dataclass
class DhcpArtifact:
    kind: str
    detail: str
    src: str
    dst: str
    ts: float


@dataclass
class DhcpAnomaly:
    severity: str
    title: str
    description: str
    src: str
    dst: str
    ts: float


@dataclass
class DhcpSummary:
    path: Path
    duration: float = 0.0
    total_packets: int = 0
    dhcp_packets: int = 0
    conversations: list[DhcpConversation] = field(default_factory=list)
    sessions: list[DhcpSession] = field(default_factory=list)
    message_types: Counter[str] = field(default_factory=Counter)
    src_ips: Counter[str] = field(default_factory=Counter)
    dst_ips: Counter[str] = field(default_factory=Counter)
    src_macs: Counter[str] = field(default_factory=Counter)
    dst_macs: Counter[str] = field(default_factory=Counter)
    client_details: Counter[str] = field(default_factory=Counter)
    server_details: Counter[str] = field(default_factory=Counter)
    relay_agents: Counter[str] = field(default_factory=Counter)
    requested_ips: Counter[str] = field(default_factory=Counter)
    offered_ips: Counter[str] = field(default_factory=Counter)
    hostnames: Counter[str] = field(default_factory=Counter)
    domains: Counter[str] = field(default_factory=Counter)
    vendor_classes: Counter[str] = field(default_factory=Counter)
    vendor_classes_by_mac: dict[str, Counter[str]] = field(default_factory=dict)
    vendor_classes_by_ip: dict[str, Counter[str]] = field(default_factory=dict)
    client_ids: Counter[str] = field(default_factory=Counter)
    lease_servers: Counter[str] = field(default_factory=Counter)
    lease_time_buckets: Counter[str] = field(default_factory=Counter)
    plaintext_observed: Counter[str] = field(default_factory=Counter)
    files_discovered: list[str] = field(default_factory=list)
    attacks: Counter[str] = field(default_factory=Counter)
    threat_summary: Counter[str] = field(default_factory=Counter)
    beacon_candidates: Counter[str] = field(default_factory=Counter)
    exfil_candidates: Counter[str] = field(default_factory=Counter)
    probe_sources: Counter[str] = field(default_factory=Counter)
    brute_force_sources: Counter[str] = field(default_factory=Counter)
    artifacts: list[DhcpArtifact] = field(default_factory=list)
    anomalies: list[DhcpAnomaly] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


def _decode_name(value: object) -> str:
    if isinstance(value, (bytes, bytearray)):
        return value.decode("latin-1", errors="ignore").strip("\x00").strip()
    return str(value).strip()


def _format_mac(value: object) -> str:
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if len(raw) >= 6:
            raw = raw[:6]
            return ":".join(f"{b:02x}" for b in raw)
    text = _decode_name(value).lower().replace("-", ":")
    if re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", text):
        return text
    return text or "00:00:00:00:00:00"


def _extract_ip_pair(pkt) -> tuple[str, str]:
    if IP is not None and pkt.haslayer(IP):
        return str(pkt[IP].src), str(pkt[IP].dst)
    if IPv6 is not None and pkt.haslayer(IPv6):
        return str(pkt[IPv6].src), str(pkt[IPv6].dst)
    return "0.0.0.0", "0.0.0.0"


def _extract_mac_pair(pkt) -> tuple[str, str]:
    if Ether is not None and pkt.haslayer(Ether):
        try:
            return str(pkt[Ether].src), str(pkt[Ether].dst)
        except Exception:
            return "00:00:00:00:00:00", "00:00:00:00:00:00"
    return "00:00:00:00:00:00", "00:00:00:00:00:00"


def _extract_payload(pkt) -> bytes:
    if Raw is not None and pkt.haslayer(Raw):
        try:
            return bytes(pkt[Raw].load)
        except Exception:
            return b""
    if UDP is not None and pkt.haslayer(UDP):
        try:
            return bytes(pkt[UDP].payload)
        except Exception:
            return b""
    return b""


def _extract_payload_strings(payload: bytes) -> list[str]:
    if not payload:
        return []
    text = payload.decode("latin-1", errors="ignore")
    tokens: list[str] = []
    for token in re.findall(r"[ -~]{6,}", text):
        cleaned = " ".join(token.split())
        if cleaned:
            tokens.append(cleaned[:120])
    return tokens


def _extract_files(strings: list[str]) -> set[str]:
    found: set[str] = set()
    for item in strings:
        found.update(_FILENAME_RE.findall(item))
    return found


def _iter_dhcp_options(dhcp_layer: object) -> list[tuple[str, object]]:
    options = getattr(dhcp_layer, "options", None)
    if not isinstance(options, (list, tuple)):
        return []

    output: list[tuple[str, object]] = []
    for option in options:
        if not isinstance(option, tuple) or len(option) < 2:
            continue
        key = str(option[0]).strip().lower()
        if not key or key in {"end", "pad"}:
            continue
        output.append((key, option[1]))
    return output


def _message_type_name(value: object) -> str:
    if isinstance(value, str):
        text = value.strip().upper()
        return text or "UNKNOWN"
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if len(raw) == 1:
            code = int(raw[0])
            return _DHCP_MESSAGE_TYPES.get(code, f"TYPE_{code}")
        text = _decode_name(raw).upper()
        return text or "UNKNOWN"
    try:
        code = int(value)
    except Exception:
        return "UNKNOWN"
    return _DHCP_MESSAGE_TYPES.get(code, f"TYPE_{code}")


def _lease_bucket(seconds: int) -> str:
    if seconds <= 600:
        return "<=10m"
    if seconds <= 3600:
        return "10m-1h"
    if seconds <= 21600:
        return "1h-6h"
    if seconds <= 86400:
        return "6h-24h"
    if seconds <= 604800:
        return "1d-7d"
    return ">7d"


def analyze_dhcp(path: Path, show_status: bool = True) -> DhcpSummary:
    if DHCP is None or BOOTP is None or UDP is None:
        return DhcpSummary(path=path, errors=["Scapy unavailable (DHCP/BOOTP/UDP layer missing)"])

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)
    except Exception as exc:
        return DhcpSummary(path=path, errors=[f"Error opening pcap: {exc}"])

    summary = DhcpSummary(path=path)
    start_ts: Optional[float] = None
    end_ts: Optional[float] = None

    conversations: dict[tuple[str, str, str, str, int, int, str], DhcpConversation] = {}
    sessions: dict[tuple[str, str, str], DhcpSession] = {}
    vendor_classes_by_mac: dict[str, Counter[str]] = defaultdict(Counter)
    vendor_classes_by_ip: dict[str, Counter[str]] = defaultdict(Counter)

    discover_intervals: dict[str, list[float]] = defaultdict(list)
    last_discover_ts: dict[str, float] = {}
    client_xids: dict[str, set[int]] = defaultdict(set)
    client_requested_ips: dict[str, set[str]] = defaultdict(set)
    src_unique_client_macs: dict[str, set[str]] = defaultdict(set)
    offer_servers_by_client: dict[str, set[str]] = defaultdict(set)
    nak_by_server: Counter[str] = Counter()

    exfil_signals: Counter[str] = Counter()
    strings_counter: Counter[str] = Counter()
    files: set[str] = set()
    seen_device_artifacts: set[str] = set()
    max_anomalies = 250

    def _append_anomaly(severity: str, title: str, description: str, src: str, dst: str, ts: float) -> None:
        if len(summary.anomalies) >= max_anomalies:
            return
        summary.anomalies.append(
            DhcpAnomaly(
                severity=severity,
                title=title,
                description=description,
                src=src,
                dst=dst,
                ts=ts,
            )
        )

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    status.update(int(min(100, (stream.tell() / size_bytes) * 100)))
                except Exception:
                    pass

            summary.total_packets += 1
            if not pkt.haslayer(UDP):
                continue

            udp_layer = pkt[UDP]
            sport = int(getattr(udp_layer, "sport", 0) or 0)
            dport = int(getattr(udp_layer, "dport", 0) or 0)
            if {sport, dport}.isdisjoint({67, 68}):
                continue

            if not (pkt.haslayer(DHCP) and pkt.haslayer(BOOTP)):
                continue

            summary.dhcp_packets += 1
            ts = safe_float(getattr(pkt, "time", None)) or 0.0
            if start_ts is None or ts < start_ts:
                start_ts = ts
            if end_ts is None or ts > end_ts:
                end_ts = ts

            src_ip, dst_ip = _extract_ip_pair(pkt)
            src_mac, dst_mac = _extract_mac_pair(pkt)
            payload = _extract_payload(pkt)

            summary.src_ips[src_ip] += 1
            summary.dst_ips[dst_ip] += 1
            summary.src_macs[src_mac] += 1
            summary.dst_macs[dst_mac] += 1

            dhcp_layer = pkt[DHCP]
            bootp_layer = pkt[BOOTP]

            chaddr = _format_mac(getattr(bootp_layer, "chaddr", b""))
            ciaddr = str(getattr(bootp_layer, "ciaddr", "0.0.0.0") or "0.0.0.0")
            yiaddr = str(getattr(bootp_layer, "yiaddr", "0.0.0.0") or "0.0.0.0")
            siaddr = str(getattr(bootp_layer, "siaddr", "0.0.0.0") or "0.0.0.0")
            xid = int(getattr(bootp_layer, "xid", 0) or 0)

            options = _iter_dhcp_options(dhcp_layer)
            option_map: dict[str, object] = {key: value for key, value in options}
            msg_type = _message_type_name(option_map.get("message-type", "UNKNOWN"))
            summary.message_types[msg_type] += 1

            server_id = _decode_name(option_map.get("server_id", option_map.get("server-id", "")))
            requested_ip = _decode_name(option_map.get("requested_addr", option_map.get("requested-address", "")))
            hostname = _decode_name(option_map.get("hostname", option_map.get("host_name", ""))).lower()
            domain = _decode_name(option_map.get("domain", option_map.get("domain_name", ""))).lower()
            vendor_class = _decode_name(option_map.get("vendor_class_id", option_map.get("vendor_class", "")))
            client_id = _decode_name(option_map.get("client_id", ""))

            session_client_ip = ciaddr if ciaddr != "0.0.0.0" else src_ip

            relay_ip = _decode_name(option_map.get("relay_agent_Information", option_map.get("relay_agent_information", "")))
            if relay_ip:
                summary.relay_agents[relay_ip] += 1

            lease_time_val = option_map.get("lease_time")
            if lease_time_val is not None:
                try:
                    lease_seconds = int(lease_time_val)
                    summary.lease_time_buckets[_lease_bucket(lease_seconds)] += 1
                except Exception:
                    pass

            if requested_ip:
                summary.requested_ips[requested_ip] += 1
            if yiaddr and yiaddr != "0.0.0.0":
                summary.offered_ips[yiaddr] += 1
            if server_id:
                summary.lease_servers[server_id] += 1
            if hostname:
                summary.hostnames[hostname] += 1
            if domain:
                summary.domains[domain] += 1
            if vendor_class:
                summary.vendor_classes[vendor_class] += 1
                vendor_classes_by_mac[chaddr][vendor_class] += 1
                if session_client_ip and session_client_ip != "0.0.0.0":
                    vendor_classes_by_ip[session_client_ip][vendor_class] += 1
                if requested_ip and requested_ip != "0.0.0.0":
                    vendor_classes_by_ip[requested_ip][vendor_class] += 1
                if yiaddr and yiaddr != "0.0.0.0":
                    vendor_classes_by_ip[yiaddr][vendor_class] += 1
            if client_id:
                summary.client_ids[client_id] += 1

            for value, source_label in (
                (vendor_class, "DHCP vendor class"),
                (hostname, "DHCP hostname"),
                (client_id, "DHCP client-id"),
            ):
                if not value:
                    continue
                for detail in device_fingerprints_from_text(str(value), source=source_label):
                    key = f"device:{detail}"
                    if key in seen_device_artifacts:
                        continue
                    seen_device_artifacts.add(key)
                    summary.artifacts.append(
                        DhcpArtifact(
                            kind="device",
                            detail=detail,
                            src=src_ip,
                            dst=dst_ip,
                            ts=ts,
                        )
                    )

            if msg_type in _CLIENT_MSG_TYPES:
                summary.client_details[chaddr] += 1
            if msg_type in _SERVER_MSG_TYPES:
                server_key = server_id or src_ip
                summary.server_details[server_key] += 1

            convo_key = (src_ip, dst_ip, src_mac, dst_mac, sport, dport, msg_type)
            convo = conversations.get(convo_key)
            if convo is None:
                convo = DhcpConversation(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_mac=src_mac,
                    dst_mac=dst_mac,
                    src_port=sport,
                    dst_port=dport,
                    message_type=msg_type,
                )
                conversations[convo_key] = convo
            convo.packets += 1
            if convo.first_seen is None or ts < convo.first_seen:
                convo.first_seen = ts
            if convo.last_seen is None or ts > convo.last_seen:
                convo.last_seen = ts

            session_server = server_id or siaddr or src_ip
            session_client_ip = ciaddr if ciaddr != "0.0.0.0" else src_ip
            sess_key = (chaddr, session_client_ip, session_server)
            session = sessions.get(sess_key)
            if session is None:
                session = DhcpSession(client_mac=chaddr, client_ip=session_client_ip, server_ip=session_server)
                sessions[sess_key] = session

            if msg_type == "REQUEST":
                session.requests += 1
            elif msg_type == "OFFER":
                session.offers += 1
                offer_servers_by_client[chaddr].add(server_id or src_ip)
            elif msg_type == "ACK":
                session.acks += 1
            elif msg_type == "NAK":
                session.naks += 1
                nak_by_server[server_id or src_ip] += 1

            if session.first_seen is None or ts < session.first_seen:
                session.first_seen = ts
            if session.last_seen is None or ts > session.last_seen:
                session.last_seen = ts

            if msg_type == "DISCOVER":
                prev = last_discover_ts.get(chaddr)
                if prev is not None and ts > prev:
                    discover_intervals[chaddr].append(ts - prev)
                last_discover_ts[chaddr] = ts

            if xid:
                client_xids[chaddr].add(xid)
            if requested_ip:
                client_requested_ips[chaddr].add(requested_ip)
            src_unique_client_macs[src_ip].add(chaddr)

            # Exfil/abuse heuristics for option values
            for value in (hostname, domain, vendor_class, client_id):
                if not value:
                    continue
                entropy = _shannon_entropy(value)
                if len(value) >= 80 or entropy >= 3.8:
                    exfil_signals[chaddr] += 1
                    summary.exfil_candidates[chaddr] += 1
                    summary.artifacts.append(
                        DhcpArtifact(
                            kind="suspicious-option",
                            detail=f"value={value[:96]} len={len(value)} entropy={entropy:.2f}",
                            src=src_ip,
                            dst=dst_ip,
                            ts=ts,
                        )
                    )

            strings = _extract_payload_strings(payload)
            for token in strings:
                strings_counter[token] += 1
            files.update(_extract_files(strings))

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

    summary.plaintext_observed = Counter({item: count for item, count in strings_counter.most_common(30)})
    summary.files_discovered = sorted(files)[:80]
    summary.vendor_classes_by_mac = dict(vendor_classes_by_mac)
    summary.vendor_classes_by_ip = dict(vendor_classes_by_ip)
    summary.conversations = sorted(conversations.values(), key=lambda item: item.packets, reverse=True)
    summary.sessions = sorted(sessions.values(), key=lambda item: (item.requests + item.offers + item.acks + item.naks), reverse=True)

    # Threat hunting detections
    for client_mac, req_ips in client_requested_ips.items():
        unique_ip_count = len(req_ips)
        unique_xid_count = len(client_xids.get(client_mac, set()))
        req_count = summary.client_details.get(client_mac, 0)
        if req_count >= 40 and (unique_xid_count >= 25 or unique_ip_count >= 20):
            summary.attacks["DHCP Starvation"] += 1
            summary.threat_summary["DHCP Starvation"] += 1
            summary.brute_force_sources[client_mac] += req_count
            _append_anomaly(
                "HIGH",
                "DHCP Starvation Pattern",
                f"Client {client_mac} issued {req_count} client messages with {unique_xid_count} XIDs and {unique_ip_count} requested addresses.",
                client_mac,
                "-",
                0.0,
            )

        if unique_ip_count >= 30:
            summary.attacks["Lease Brute Force/Enumeration"] += 1
            summary.threat_summary["Lease Brute Force/Enumeration"] += 1
            summary.brute_force_sources[client_mac] += unique_ip_count
            _append_anomaly(
                "MEDIUM",
                "DHCP Lease Brute Force",
                f"Client {client_mac} requested {unique_ip_count} distinct IP addresses.",
                client_mac,
                "-",
                0.0,
            )

    offer_servers = [server for server, count in summary.server_details.items() if count >= 3]
    if len(offer_servers) >= 2:
        summary.attacks["Rogue DHCP Server"] += 1
        summary.threat_summary["Rogue DHCP Server"] += 1
        _append_anomaly(
            "HIGH",
            "Multiple DHCP Servers Detected",
            f"Potential rogue/competing DHCP servers observed: {', '.join(offer_servers[:8])}",
            ", ".join(offer_servers[:4]),
            "-",
            0.0,
        )

    for server, count in nak_by_server.items():
        if count >= 20:
            summary.attacks["DHCP NAK Flooding"] += 1
            summary.threat_summary["DHCP NAK Flooding"] += 1
            _append_anomaly(
                "HIGH",
                "DHCP NAK Flood",
                f"Server {server} sent {count} DHCP NAK responses.",
                server,
                "-",
                0.0,
            )

    for src_ip, macs in src_unique_client_macs.items():
        if len(macs) >= 20:
            summary.attacks["DHCP Probing/Scanning"] += 1
            summary.threat_summary["DHCP Probing/Scanning"] += 1
            summary.probe_sources[src_ip] += len(macs)
            _append_anomaly(
                "MEDIUM",
                "DHCP Client Sweep",
                f"Source {src_ip} carried DHCP traffic for {len(macs)} unique client MACs.",
                src_ip,
                "-",
                0.0,
            )

    for client_mac, intervals in discover_intervals.items():
        if len(intervals) < 8:
            continue
        avg = sum(intervals) / len(intervals)
        if avg <= 0:
            continue
        variance = sum((value - avg) ** 2 for value in intervals) / len(intervals)
        cv = math.sqrt(variance) / avg
        if 3.0 <= avg <= 180.0 and cv <= 0.2:
            summary.beacon_candidates[client_mac] += len(intervals)
            summary.threat_summary["DHCP Beaconing"] += 1
            _append_anomaly(
                "MEDIUM",
                "Periodic DHCP Beacon",
                f"Client {client_mac} shows periodic DHCP discover cadence (avg={avg:.2f}s, cv={cv:.2f}, n={len(intervals)}).",
                client_mac,
                "-",
                0.0,
            )

    for client_mac, signal_count in exfil_signals.items():
        if signal_count < 3:
            continue
        summary.attacks["DHCP Option Exfiltration"] += 1
        summary.threat_summary["DHCP Option Exfiltration"] += 1
        _append_anomaly(
            "HIGH",
            "Potential DHCP Option Exfiltration",
            f"Client {client_mac} produced {signal_count} suspicious high-entropy/long DHCP option values.",
            client_mac,
            "-",
            0.0,
        )

    for attack_name, count in summary.attacks.items():
        summary.artifacts.append(
            DhcpArtifact(
                kind="attack",
                detail=f"{attack_name}: {count}",
                src="-",
                dst="-",
                ts=0.0,
            )
        )

    for file_name in summary.files_discovered[:20]:
        summary.artifacts.append(
            DhcpArtifact(
                kind="file",
                detail=file_name,
                src="-",
                dst="-",
                ts=0.0,
            )
        )

    # Bonus endpoint details for public-facing DHCP relays/servers
    for ip_value in list(summary.server_details.keys()):
        try:
            if ipaddress.ip_address(ip_value).is_global:
                summary.threat_summary["Public DHCP Infrastructure Exposure"] += 1
        except Exception:
            continue

    return summary
