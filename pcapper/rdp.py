from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import re

from .pcap_cache import get_reader
from .utils import safe_float

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


RDP_TCP_PORTS = {3389, 3390, 3388}
RDP_UDP_PORTS = {3389, 3390, 3391, 3392}
MSTSHASH_RE = re.compile(r"Cookie:\s*mstshash=([^\r\n;]+)", re.IGNORECASE)

SUSPICIOUS_PLAINTEXT = [
    (re.compile(r"password\s*[:=]", re.IGNORECASE), "Credential indicator"),
    (re.compile(r"user(name)?\s*[:=]", re.IGNORECASE), "User indicator"),
    (re.compile(r"cmd\.exe|powershell|psexec|wmic", re.IGNORECASE), "Administrative tooling"),
    (re.compile(r"mimikatz|cobalt|beacon|meterpreter", re.IGNORECASE), "Offensive tooling"),
]

FILE_NAME_RE = re.compile(
    r"[\w\-.()\[\]/ ]+\.(?:exe|dll|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|rar|7z|tar|gz|tgz|txt|csv|log|ps1|sh|bat|py|js|jar|apk|iso|img)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class RdpConversation:
    client_ip: str
    server_ip: str
    server_port: int
    client_port: int
    client_mac: Optional[str]
    server_mac: Optional[str]
    packets: int
    bytes: int
    client_packets: int
    server_packets: int
    client_bytes: int
    server_bytes: int
    first_seen: Optional[float]
    last_seen: Optional[float]
    client_name: Optional[str]
    tls_detected: bool
    udp_detected: bool


@dataclass(frozen=True)
class RdpSummary:
    path: Path
    total_packets: int
    rdp_packets: int
    total_bytes: int
    client_packets: int
    server_packets: int
    client_bytes: int
    server_bytes: int
    total_sessions: int
    tcp_sessions: int
    udp_sessions: int
    unique_clients: int
    unique_servers: int
    client_counts: Counter[str]
    server_counts: Counter[str]
    client_macs: Counter[str]
    server_macs: Counter[str]
    ip_to_macs: dict[str, list[str]]
    server_tcp_ports: Counter[int]
    server_udp_ports: Counter[int]
    client_names: Counter[str]
    tls_handshakes: int
    plaintext_strings: Counter[str]
    suspicious_plaintext: Counter[str]
    file_artifacts: Counter[str]
    conversations: list[RdpConversation]
    detections: list[dict[str, object]]
    anomalies: list[dict[str, object]]
    artifacts: list[str]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "total_packets": self.total_packets,
            "rdp_packets": self.rdp_packets,
            "total_bytes": self.total_bytes,
            "client_packets": self.client_packets,
            "server_packets": self.server_packets,
            "client_bytes": self.client_bytes,
            "server_bytes": self.server_bytes,
            "total_sessions": self.total_sessions,
            "tcp_sessions": self.tcp_sessions,
            "udp_sessions": self.udp_sessions,
            "unique_clients": self.unique_clients,
            "unique_servers": self.unique_servers,
            "client_counts": dict(self.client_counts),
            "server_counts": dict(self.server_counts),
            "client_macs": dict(self.client_macs),
            "server_macs": dict(self.server_macs),
            "ip_to_macs": {key: list(value) for key, value in self.ip_to_macs.items()},
            "server_tcp_ports": dict(self.server_tcp_ports),
            "server_udp_ports": dict(self.server_udp_ports),
            "client_names": dict(self.client_names),
            "tls_handshakes": self.tls_handshakes,
            "plaintext_strings": dict(self.plaintext_strings),
            "suspicious_plaintext": dict(self.suspicious_plaintext),
            "file_artifacts": dict(self.file_artifacts),
            "conversations": [
                {
                    "client_ip": conv.client_ip,
                    "server_ip": conv.server_ip,
                    "server_port": conv.server_port,
                    "client_port": conv.client_port,
                    "client_mac": conv.client_mac,
                    "server_mac": conv.server_mac,
                    "packets": conv.packets,
                    "bytes": conv.bytes,
                    "client_packets": conv.client_packets,
                    "server_packets": conv.server_packets,
                    "client_bytes": conv.client_bytes,
                    "server_bytes": conv.server_bytes,
                    "first_seen": conv.first_seen,
                    "last_seen": conv.last_seen,
                    "client_name": conv.client_name,
                    "tls_detected": conv.tls_detected,
                    "udp_detected": conv.udp_detected,
                }
                for conv in self.conversations
            ],
            "detections": list(self.detections),
            "anomalies": list(self.anomalies),
            "artifacts": list(self.artifacts),
            "errors": list(self.errors),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": self.duration_seconds,
        }


def merge_rdp_summaries(summaries: list[RdpSummary] | tuple[RdpSummary, ...] | set[RdpSummary]) -> RdpSummary:
    summary_list = list(summaries)
    if not summary_list:
        return RdpSummary(
            path=Path("ALL_PCAPS_0"),
            total_packets=0,
            rdp_packets=0,
            total_bytes=0,
            client_packets=0,
            server_packets=0,
            client_bytes=0,
            server_bytes=0,
            total_sessions=0,
            tcp_sessions=0,
            udp_sessions=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            client_macs=Counter(),
            server_macs=Counter(),
            ip_to_macs={},
            server_tcp_ports=Counter(),
            server_udp_ports=Counter(),
            client_names=Counter(),
            tls_handshakes=0,
            plaintext_strings=Counter(),
            suspicious_plaintext=Counter(),
            file_artifacts=Counter(),
            conversations=[],
            detections=[],
            anomalies=[],
            artifacts=[],
            errors=[],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    total_packets = 0
    rdp_packets = 0
    total_bytes = 0
    client_packets = 0
    server_packets = 0
    client_bytes = 0
    server_bytes = 0
    total_sessions = 0
    tcp_sessions = 0
    udp_sessions = 0
    tls_handshakes = 0

    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    client_macs: Counter[str] = Counter()
    server_macs: Counter[str] = Counter()
    ip_to_macs: dict[str, set[str]] = defaultdict(set)
    server_tcp_ports: Counter[int] = Counter()
    server_udp_ports: Counter[int] = Counter()
    client_names: Counter[str] = Counter()
    plaintext_strings: Counter[str] = Counter()
    suspicious_plaintext: Counter[str] = Counter()
    file_artifacts: Counter[str] = Counter()
    conversations: list[RdpConversation] = []
    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []
    artifacts: list[str] = []
    errors: list[str] = []

    for summary in summary_list:
        total_packets += summary.total_packets
        rdp_packets += summary.rdp_packets
        total_bytes += summary.total_bytes
        client_packets += summary.client_packets
        server_packets += summary.server_packets
        client_bytes += summary.client_bytes
        server_bytes += summary.server_bytes
        total_sessions += summary.total_sessions
        tcp_sessions += summary.tcp_sessions
        udp_sessions += summary.udp_sessions
        tls_handshakes += summary.tls_handshakes

        if summary.first_seen is not None:
            first_seen = summary.first_seen if first_seen is None else min(first_seen, summary.first_seen)
        if summary.last_seen is not None:
            last_seen = summary.last_seen if last_seen is None else max(last_seen, summary.last_seen)

        client_counts.update(summary.client_counts)
        server_counts.update(summary.server_counts)
        client_macs.update(summary.client_macs)
        server_macs.update(summary.server_macs)
        for ip_value, macs in summary.ip_to_macs.items():
            ip_to_macs[ip_value].update(macs)
        server_tcp_ports.update(summary.server_tcp_ports)
        server_udp_ports.update(summary.server_udp_ports)
        client_names.update(summary.client_names)
        plaintext_strings.update(summary.plaintext_strings)
        suspicious_plaintext.update(summary.suspicious_plaintext)
        file_artifacts.update(summary.file_artifacts)
        conversations.extend(summary.conversations)
        detections.extend(summary.detections)
        anomalies.extend(summary.anomalies)
        artifacts.extend(summary.artifacts)
        errors.extend(summary.errors)

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    return RdpSummary(
        path=Path("ALL_PCAPS"),
        total_packets=total_packets,
        rdp_packets=rdp_packets,
        total_bytes=total_bytes,
        client_packets=client_packets,
        server_packets=server_packets,
        client_bytes=client_bytes,
        server_bytes=server_bytes,
        total_sessions=total_sessions,
        tcp_sessions=tcp_sessions,
        udp_sessions=udp_sessions,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        client_macs=client_macs,
        server_macs=server_macs,
        ip_to_macs={key: sorted(value) for key, value in ip_to_macs.items()},
        server_tcp_ports=server_tcp_ports,
        server_udp_ports=server_udp_ports,
        client_names=client_names,
        tls_handshakes=tls_handshakes,
        plaintext_strings=plaintext_strings,
        suspicious_plaintext=suspicious_plaintext,
        file_artifacts=file_artifacts,
        conversations=conversations,
        detections=detections,
        anomalies=anomalies,
        artifacts=artifacts,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )


@dataclass
class _SessionState:
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    is_udp: bool
    client_mac: Optional[str] = None
    server_mac: Optional[str] = None
    packets: int = 0
    bytes: int = 0
    client_packets: int = 0
    server_packets: int = 0
    client_bytes: int = 0
    server_bytes: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    client_name: Optional[str] = None
    tls_detected: bool = False


def _extract_ascii_strings(data: bytes, min_len: int = 4, max_len: int = 200) -> list[str]:
    results: list[str] = []
    if not data:
        return results
    current = bytearray()
    for b in data:
        if 32 <= b <= 126:
            current.append(b)
        else:
            if len(current) >= min_len:
                value = current.decode("latin-1", errors="ignore")
                results.append(value[:max_len])
            current = bytearray()
    if len(current) >= min_len:
        value = current.decode("latin-1", errors="ignore")
        results.append(value[:max_len])
    return results


def _scan_plaintext(
    payload: bytes,
    plaintext_counter: Counter[str],
    suspicious_counter: Counter[str],
    file_counter: Counter[str],
    artifacts: list[str],
    max_unique: int = 2000,
) -> None:
    for item in _extract_ascii_strings(payload):
        if not item:
            continue
        if len(plaintext_counter) < max_unique or item in plaintext_counter:
            plaintext_counter[item] += 1
        for pattern, reason in SUSPICIOUS_PLAINTEXT:
            if pattern.search(item):
                suspicious_counter[f"{reason}: {item}"] += 1
        for match in FILE_NAME_RE.findall(item):
            file_counter[match] += 1
        if "mstshash=" in item.lower():
            artifacts.append(item)
        if "credssp" in item.lower():
            artifacts.append(item)
        if "ntlmssp" in item.lower():
            artifacts.append(item)


def _direction(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    is_udp: bool,
) -> tuple[str, str, int, int]:
    ports = RDP_UDP_PORTS if is_udp else RDP_TCP_PORTS
    if dport in ports:
        return src_ip, dst_ip, sport, dport
    if sport in ports:
        return dst_ip, src_ip, dport, sport
    if dport < 1024 and sport >= 1024:
        return src_ip, dst_ip, sport, dport
    if sport < 1024 and dport >= 1024:
        return dst_ip, src_ip, dport, sport
    return src_ip, dst_ip, sport, dport


def _beaconing_score(times: list[float]) -> Optional[dict[str, float]]:
    if len(times) < 5:
        return None
    times_sorted = sorted(times)
    deltas = [b - a for a, b in zip(times_sorted, times_sorted[1:]) if b > a]
    if len(deltas) < 4:
        return None
    avg = sum(deltas) / len(deltas)
    if avg <= 0:
        return None
    variance = sum((d - avg) ** 2 for d in deltas) / len(deltas)
    stddev = variance ** 0.5
    if avg < 5 or avg > 86400:
        return None
    if stddev > max(5.0, avg * 0.25):
        return None
    return {"avg": avg, "stddev": stddev}


def analyze_rdp(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
) -> RdpSummary:
    errors: list[str] = []
    if (TCP is None and UDP is None) or (IP is None and IPv6 is None):
        errors.append("Scapy IP/TCP/UDP layers unavailable; install scapy for RDP analysis.")
        return RdpSummary(
            path=path,
            total_packets=0,
            rdp_packets=0,
            total_bytes=0,
            client_packets=0,
            server_packets=0,
            client_bytes=0,
            server_bytes=0,
            total_sessions=0,
            tcp_sessions=0,
            udp_sessions=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            client_macs=Counter(),
            server_macs=Counter(),
            ip_to_macs={},
            server_tcp_ports=Counter(),
            server_udp_ports=Counter(),
            client_names=Counter(),
            tls_handshakes=0,
            plaintext_strings=Counter(),
            suspicious_plaintext=Counter(),
            file_artifacts=Counter(),
            conversations=[],
            detections=[],
            anomalies=[],
            artifacts=[],
            errors=errors,
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, packets=packets, meta=meta, show_status=show_status
    )

    total_packets = 0
    rdp_packets = 0
    total_bytes = 0
    client_packets = 0
    server_packets = 0
    client_bytes = 0
    server_bytes = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    sessions: dict[tuple[str, int, str, int, bool], _SessionState] = {}
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    client_macs: Counter[str] = Counter()
    server_macs: Counter[str] = Counter()
    ip_to_macs: dict[str, set[str]] = defaultdict(set)
    server_tcp_ports: Counter[int] = Counter()
    server_udp_ports: Counter[int] = Counter()
    client_names: Counter[str] = Counter()
    tls_handshakes = 0

    plaintext_strings: Counter[str] = Counter()
    suspicious_plaintext: Counter[str] = Counter()
    file_artifacts: Counter[str] = Counter()
    artifacts: list[str] = []

    short_session_counts: Counter[tuple[str, str]] = Counter()
    short_session_by_client: Counter[str] = Counter()
    short_session_targets: dict[str, set[str]] = defaultdict(set)
    pair_first_seen: dict[tuple[str, str], list[float]] = defaultdict(list)

    try:
        for pkt in reader:
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

            ip_layer = None
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                ip_layer = pkt[IP]  # type: ignore[index]
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                ip_layer = pkt[IPv6]  # type: ignore[index]
            if ip_layer is None:
                continue

            src_ip = str(getattr(ip_layer, "src", ""))
            dst_ip = str(getattr(ip_layer, "dst", ""))
            if not src_ip or not dst_ip:
                continue

            is_udp = UDP is not None and pkt.haslayer(UDP)  # type: ignore[truthy-bool]
            is_tcp = TCP is not None and pkt.haslayer(TCP)  # type: ignore[truthy-bool]
            if not (is_tcp or is_udp):
                continue

            if is_tcp:
                tcp = pkt[TCP]  # type: ignore[index]
                sport = int(getattr(tcp, "sport", 0) or 0)
                dport = int(getattr(tcp, "dport", 0) or 0)
            else:
                udp = pkt[UDP]  # type: ignore[index]
                sport = int(getattr(udp, "sport", 0) or 0)
                dport = int(getattr(udp, "dport", 0) or 0)

            payload = b""
            if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                try:
                    payload = bytes(pkt[Raw])  # type: ignore[index]
                except Exception:
                    payload = b""
            else:
                try:
                    if is_tcp:
                        payload = bytes(tcp.payload)
                    else:
                        payload = bytes(udp.payload)
                except Exception:
                    payload = b""

            payload_prefix = payload[:64] if payload else b""
            is_rdp = (
                (is_tcp and (sport in RDP_TCP_PORTS or dport in RDP_TCP_PORTS))
                or (is_udp and (sport in RDP_UDP_PORTS or dport in RDP_UDP_PORTS))
                or (payload_prefix and (b"Cookie: mstshash=" in payload_prefix or b"RDPUDP" in payload_prefix))
            )
            if not is_rdp:
                continue

            rdp_packets += 1
            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            eth_src = None
            eth_dst = None
            if Ether is not None and pkt.haslayer(Ether):  # type: ignore[truthy-bool]
                try:
                    eth_layer = pkt[Ether]  # type: ignore[index]
                    eth_src = str(getattr(eth_layer, "src", "")) or None
                    eth_dst = str(getattr(eth_layer, "dst", "")) or None
                except Exception:
                    eth_src = None
                    eth_dst = None

            client_ip, server_ip, client_port, server_port = _direction(
                src_ip, dst_ip, sport, dport, is_udp
            )

            client_counts[client_ip] += 1
            server_counts[server_ip] += 1
            if is_udp:
                server_udp_ports[server_port] += 1
            else:
                server_tcp_ports[server_port] += 1

            if eth_src and src_ip:
                ip_to_macs[src_ip].add(eth_src.lower())
            if eth_dst and dst_ip:
                ip_to_macs[dst_ip].add(eth_dst.lower())
            if eth_src and src_ip == client_ip:
                client_macs[eth_src.lower()] += 1
            if eth_dst and dst_ip == server_ip:
                server_macs[eth_dst.lower()] += 1

            session_key = (client_ip, client_port, server_ip, server_port, is_udp)
            session = sessions.get(session_key)
            if session is None:
                session = _SessionState(
                    client_ip=client_ip,
                    server_ip=server_ip,
                    client_port=client_port,
                    server_port=server_port,
                    is_udp=is_udp,
                    first_seen=ts,
                    last_seen=ts,
                )
                sessions[session_key] = session
            if session.client_mac is None and eth_src and src_ip == client_ip:
                session.client_mac = eth_src.lower()
            if session.server_mac is None and eth_dst and dst_ip == server_ip:
                session.server_mac = eth_dst.lower()

            session.packets += 1
            session.bytes += pkt_len
            if src_ip == client_ip:
                session.client_packets += 1
                session.client_bytes += pkt_len
                client_packets += 1
                client_bytes += pkt_len
            else:
                session.server_packets += 1
                session.server_bytes += pkt_len
                server_packets += 1
                server_bytes += pkt_len

            if ts is not None:
                if session.first_seen is None or ts < session.first_seen:
                    session.first_seen = ts
                if session.last_seen is None or ts > session.last_seen:
                    session.last_seen = ts

            text = ""
            if payload:
                try:
                    text = payload.decode("latin-1", errors="ignore")
                except Exception:
                    text = ""

            if text:
                match = MSTSHASH_RE.search(text)
                if match:
                    client_name = match.group(1).strip()
                    if client_name:
                        session.client_name = session.client_name or client_name
                        client_names[client_name] += 1
                if "Cookie: mstshash=" in text:
                    artifacts.append(text.strip())
                if "CredSSP" in text or "NTLMSSP" in text:
                    artifacts.append(text.strip())
                _scan_plaintext(payload, plaintext_strings, suspicious_plaintext, file_artifacts, artifacts)

            if payload_prefix.startswith(b"\x16\x03"):
                tls_handshakes += 1
                session.tls_detected = True

    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        reader.close()

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    conversations: list[RdpConversation] = []
    tcp_sessions = 0
    udp_sessions = 0
    for session in sessions.values():
        conversations.append(
            RdpConversation(
                client_ip=session.client_ip,
                server_ip=session.server_ip,
                server_port=session.server_port,
                client_port=session.client_port,
                client_mac=session.client_mac,
                server_mac=session.server_mac,
                packets=session.packets,
                bytes=session.bytes,
                client_packets=session.client_packets,
                server_packets=session.server_packets,
                client_bytes=session.client_bytes,
                server_bytes=session.server_bytes,
                first_seen=session.first_seen,
                last_seen=session.last_seen,
                client_name=session.client_name,
                tls_detected=session.tls_detected,
                udp_detected=session.is_udp,
            )
        )
        if session.is_udp:
            udp_sessions += 1
        else:
            tcp_sessions += 1
        if session.packets <= 6 and session.bytes < 2000:
            short_session_counts[(session.client_ip, session.server_ip)] += 1
            short_session_by_client[session.client_ip] += 1
            short_session_targets[session.client_ip].add(session.server_ip)
        if session.first_seen is not None:
            pair_first_seen[(session.client_ip, session.server_ip)].append(session.first_seen)

    detections: list[dict[str, object]] = []
    anomalies: list[dict[str, object]] = []

    non_standard_ports = [port for port in server_tcp_ports if port != 3389]
    non_standard_ports += [port for port in server_udp_ports if port != 3389]
    if non_standard_ports:
        detections.append({
            "severity": "info",
            "summary": "RDP observed on non-standard ports",
            "details": ", ".join(str(port) for port in sorted(set(non_standard_ports))),
        })

    if server_udp_ports:
        detections.append({
            "severity": "info",
            "summary": "RDP UDP transport observed",
            "details": ", ".join(str(port) for port in sorted(server_udp_ports.keys())),
        })

    if suspicious_plaintext:
        detections.append({
            "severity": "warning",
            "summary": "Suspicious plaintext strings observed in RDP payloads",
            "details": "Potential credentials, tooling, or sensitive strings in cleartext.",
        })

    for (client_ip, server_ip), count in short_session_counts.items():
        if count >= 20:
            anomalies.append({
                "title": "Potential brute force or probing",
                "details": f"{client_ip} -> {server_ip} short sessions: {count}",
            })

    for client_ip, count in short_session_by_client.items():
        targets = short_session_targets.get(client_ip, set())
        if count >= 30 and len(targets) >= 10:
            anomalies.append({
                "title": "Potential RDP scanning",
                "details": f"{client_ip} short sessions: {count} across {len(targets)} servers",
            })

    for (client_ip, server_ip), times in pair_first_seen.items():
        score = _beaconing_score(times)
        if score:
            detections.append({
                "severity": "info",
                "summary": "Potential RDP beaconing",
                "details": f"{client_ip} -> {server_ip} avg interval {score['avg']:.1f}s, stddev {score['stddev']:.1f}s",
            })

    for session in sessions.values():
        if session.client_bytes >= 50 * 1024 * 1024 and session.client_bytes > session.server_bytes * 3:
            detections.append({
                "severity": "warning",
                "summary": "Potential RDP data upload/exfiltration",
                "details": (
                    f"{session.client_ip} -> {session.server_ip} "
                    f"client->server {session.client_bytes / (1024 * 1024):.1f} MB"
                ),
            })
        if session.server_bytes >= 200 * 1024 * 1024 and session.server_bytes > session.client_bytes * 3:
            detections.append({
                "severity": "info",
                "summary": "High server->client RDP data volume",
                "details": (
                    f"{session.server_ip} -> {session.client_ip} "
                    f"server->client {session.server_bytes / (1024 * 1024):.1f} MB"
                ),
            })
        if session.last_seen is not None and session.first_seen is not None:
            duration = session.last_seen - session.first_seen
            if duration >= 4 * 3600:
                anomalies.append({
                    "title": "Long-lived RDP session",
                    "details": f"{session.client_ip} -> {session.server_ip} duration {duration:.0f}s",
                })

    total_sessions = len(conversations)

    return RdpSummary(
        path=path,
        total_packets=total_packets,
        rdp_packets=rdp_packets,
        total_bytes=total_bytes,
        client_packets=client_packets,
        server_packets=server_packets,
        client_bytes=client_bytes,
        server_bytes=server_bytes,
        total_sessions=total_sessions,
        tcp_sessions=tcp_sessions,
        udp_sessions=udp_sessions,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        client_macs=client_macs,
        server_macs=server_macs,
        ip_to_macs={key: sorted(value) for key, value in ip_to_macs.items()},
        server_tcp_ports=server_tcp_ports,
        server_udp_ports=server_udp_ports,
        client_names=client_names,
        tls_handshakes=tls_handshakes,
        plaintext_strings=plaintext_strings,
        suspicious_plaintext=suspicious_plaintext,
        file_artifacts=file_artifacts,
        conversations=conversations,
        detections=detections,
        anomalies=anomalies,
        artifacts=artifacts,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )
