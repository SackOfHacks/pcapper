from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import ipaddress
import math

from .pcap_cache import get_reader
from .utils import safe_float
from .http import analyze_http
from .files import analyze_files
from .services import analyze_services

try:
    from scapy.layers.inet import IP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.layers.dns import DNS  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore
    DNS = None  # type: ignore


@dataclass(frozen=True)
class UdpConversation:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    packets: int
    bytes: int
    first_seen: Optional[float]
    last_seen: Optional[float]


@dataclass(frozen=True)
class UdpSummary:
    path: Path
    total_packets: int
    total_bytes: int
    udp_packets: int
    udp_bytes: int
    udp_payload_bytes: int
    conversations: list[UdpConversation]
    client_counts: Counter[str]
    client_bytes: Counter[str]
    server_counts: Counter[str]
    server_bytes: Counter[str]
    port_counts: Counter[int]
    port_destinations: dict[int, Counter[str]]
    endpoint_packets: Counter[str]
    endpoint_bytes: Counter[str]
    packet_size_hist: Counter[str]
    payload_size_hist: Counter[str]
    packet_size_stats: dict[str, float]
    payload_size_stats: dict[str, float]
    zero_payload_packets: int
    http_requests: int
    http_responses: int
    http_methods: Counter[str]
    http_statuses: Counter[str]
    http_urls: Counter[str]
    http_user_agents: Counter[str]
    http_files: Counter[str]
    file_artifacts: Counter[str]
    services: list[dict[str, object]]
    detections: list[dict[str, object]]
    artifacts: list[str]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


AMPLIFICATION_PORTS = {19, 53, 123, 161, 389, 1900, 5353, 11211}
PACKET_BUCKETS = [
    (64, "<=64"),
    (128, "65-128"),
    (256, "129-256"),
    (512, "257-512"),
    (1024, "513-1024"),
    (1500, "1025-1500"),
    (9000, "1501-9000"),
]


def _bucketize(size: int) -> str:
    for ceiling, label in PACKET_BUCKETS:
        if size <= ceiling:
            return label
    return ">9000"


def _append_sample(samples: list[int], value: int, max_len: int = 50000) -> None:
    samples.append(value)
    if len(samples) > max_len:
        del samples[::2]


def _percentile(sorted_vals: list[int], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = int(round((pct / 100.0) * (len(sorted_vals) - 1)))
    idx = max(0, min(len(sorted_vals) - 1, idx))
    return float(sorted_vals[idx])


def _stats_from_samples(samples: list[int]) -> dict[str, float]:
    if not samples:
        return {"min": 0.0, "max": 0.0, "avg": 0.0, "p50": 0.0, "p95": 0.0}
    sorted_vals = sorted(samples)
    total = sum(sorted_vals)
    return {
        "min": float(sorted_vals[0]),
        "max": float(sorted_vals[-1]),
        "avg": total / max(len(sorted_vals), 1),
        "p50": _percentile(sorted_vals, 50.0),
        "p95": _percentile(sorted_vals, 95.0),
    }


def _is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except Exception:
        return False


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except Exception:
        return False


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


def analyze_udp(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
) -> UdpSummary:
    errors: list[str] = []
    if IP is None and IPv6 is None:
        errors.append("Scapy IP layers unavailable; install scapy for UDP analysis.")
        return UdpSummary(
            path=path,
            total_packets=0,
            total_bytes=0,
            udp_packets=0,
            udp_bytes=0,
            udp_payload_bytes=0,
            conversations=[],
            client_counts=Counter(),
            client_bytes=Counter(),
            server_counts=Counter(),
            server_bytes=Counter(),
            port_counts=Counter(),
            port_destinations=defaultdict(Counter),
            endpoint_packets=Counter(),
            endpoint_bytes=Counter(),
            packet_size_hist=Counter(),
            payload_size_hist=Counter(),
            packet_size_stats={},
            payload_size_stats={},
            zero_payload_packets=0,
            http_requests=0,
            http_responses=0,
            http_methods=Counter(),
            http_statuses=Counter(),
            http_urls=Counter(),
            http_user_agents=Counter(),
            http_files=Counter(),
            file_artifacts=Counter(),
            services=[],
            detections=[],
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
    total_bytes = 0
    udp_packets = 0
    udp_bytes = 0
    udp_payload_bytes = 0
    conversations: dict[tuple[str, str, int, int], dict[str, object]] = defaultdict(lambda: {
        "packets": 0,
        "bytes": 0,
        "first_seen": None,
        "last_seen": None,
    })

    client_counts: Counter[str] = Counter()
    client_bytes: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    server_bytes: Counter[str] = Counter()
    port_counts: Counter[int] = Counter()
    port_destinations: dict[int, Counter[str]] = defaultdict(Counter)
    endpoint_packets: Counter[str] = Counter()
    endpoint_bytes: Counter[str] = Counter()
    packet_size_hist: Counter[str] = Counter()
    payload_size_hist: Counter[str] = Counter()
    zero_payload_packets = 0
    packet_size_samples: list[int] = []
    payload_size_samples: list[int] = []
    src_to_ports: dict[str, set[int]] = defaultdict(set)
    src_to_dsts: dict[str, set[str]] = defaultdict(set)
    dst_to_ports: dict[str, set[int]] = defaultdict(set)
    dst_to_srcs: dict[str, set[str]] = defaultdict(set)
    src_dst_ports: dict[tuple[str, str], set[int]] = defaultdict(set)
    src_port_dsts: dict[tuple[str, int], set[str]] = defaultdict(set)
    amp_flows: dict[tuple[str, str, int], dict[str, int]] = defaultdict(lambda: {"client": 0, "server": 0})
    dns_query_lengths: list[int] = []
    dns_long_queries = Counter()
    dns_entropy_scores: list[float] = []
    dns_unique_queries: dict[str, set[str]] = defaultdict(set)
    dns_query_counts: Counter[str] = Counter()
    outbound_flow_bytes: Counter[tuple[str, str]] = Counter()
    beacon_trackers: dict[tuple[str, str, int, int], dict[str, object]] = defaultdict(lambda: {
        "last_ts": None,
        "intervals": [],
        "payloads": [],
        "count": 0,
    })

    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

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
            ts = safe_float(getattr(pkt, "time", None))

            src_ip = None
            dst_ip = None
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                ip_layer = pkt[IP]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                ip_layer = pkt[IPv6]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))

            if src_ip and dst_ip and ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            if UDP is None or not pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                continue

            udp_packets += 1
            udp_bytes += pkt_len
            udp_layer = pkt[UDP]  # type: ignore[index]
            sport = int(getattr(udp_layer, "sport", 0))
            dport = int(getattr(udp_layer, "dport", 0))

            client_key = src_ip or "-"
            server_key = dst_ip or "-"
            client_counts[client_key] += 1
            server_counts[server_key] += 1
            client_bytes[client_key] += pkt_len
            server_bytes[server_key] += pkt_len
            endpoint_packets[client_key] += 1
            endpoint_packets[server_key] += 1
            endpoint_bytes[client_key] += pkt_len
            endpoint_bytes[server_key] += pkt_len
            port_counts[dport] += 1
            if dst_ip:
                port_destinations[dport][dst_ip] += 1

            src_to_ports[client_key].add(dport)
            src_to_dsts[client_key].add(server_key)
            dst_to_ports[server_key].add(dport)
            dst_to_srcs[server_key].add(client_key)
            src_dst_ports[(client_key, server_key)].add(dport)
            src_port_dsts[(client_key, dport)].add(server_key)

            convo_key = (src_ip or "-", dst_ip or "-", sport, dport)
            convo = conversations[convo_key]
            convo["packets"] = int(convo["packets"]) + 1
            convo["bytes"] = int(convo["bytes"]) + pkt_len
            if ts is not None:
                if convo["first_seen"] is None or ts < convo["first_seen"]:
                    convo["first_seen"] = ts
                if convo["last_seen"] is None or ts > convo["last_seen"]:
                    convo["last_seen"] = ts

            payload_len = 0
            try:
                payload_len = len(bytes(udp_layer.payload))
            except Exception:
                payload_len = 0
            udp_payload_bytes += payload_len
            packet_size_hist[_bucketize(pkt_len)] += 1
            payload_size_hist[_bucketize(payload_len)] += 1
            _append_sample(packet_size_samples, pkt_len)
            _append_sample(payload_size_samples, payload_len)
            if payload_len == 0:
                zero_payload_packets += 1

            if src_ip and dst_ip and _is_private_ip(src_ip) and _is_public_ip(dst_ip):
                outbound_flow_bytes[(src_ip, dst_ip)] += pkt_len

            tracker = beacon_trackers[convo_key]
            tracker["count"] = int(tracker["count"]) + 1
            if ts is not None:
                last_ts = tracker["last_ts"]
                if isinstance(last_ts, float):
                    interval = ts - last_ts
                    if interval > 0:
                        intervals = tracker["intervals"]
                        if len(intervals) < 25:
                            intervals.append(interval)
                tracker["last_ts"] = ts
            payloads = tracker["payloads"]
            if len(payloads) < 25:
                payloads.append(payload_len)

            if dport in AMPLIFICATION_PORTS or sport in AMPLIFICATION_PORTS:
                if dport in AMPLIFICATION_PORTS:
                    client = src_ip or "-"
                    server = dst_ip or "-"
                    server_port = dport
                    amp_flows[(client, server, server_port)]["client"] += payload_len
                else:
                    client = dst_ip or "-"
                    server = src_ip or "-"
                    server_port = sport
                    amp_flows[(client, server, server_port)]["server"] += payload_len

            if DNS is not None and pkt.haslayer(DNS):  # type: ignore[truthy-bool]
                dns_layer = pkt[DNS]  # type: ignore[index]
                if getattr(dns_layer, "qr", 0) == 0:
                    qname = None
                    if getattr(dns_layer, "qd", None):
                        qname = getattr(dns_layer.qd, "qname", None)
                    if isinstance(qname, bytes):
                        qname = qname.decode("utf-8", errors="ignore")
                    if qname:
                        qname = qname.strip(".")
                        dns_query_counts[src_ip or "-"] += 1
                        dns_unique_queries[src_ip or "-"].add(qname)
                        dns_query_lengths.append(len(qname))
                        if len(qname) >= 50:
                            dns_long_queries[src_ip or "-"] += 1
                        entropy = _shannon_entropy(qname)
                        dns_entropy_scores.append(entropy)

    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        reader.close()

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    conversation_rows: list[UdpConversation] = []
    for (src_ip, dst_ip, sport, dport), data in conversations.items():
        conversation_rows.append(UdpConversation(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=sport,
            dst_port=dport,
            packets=int(data["packets"]),
            bytes=int(data["bytes"]),
            first_seen=data["first_seen"],
            last_seen=data["last_seen"],
        ))

    http_summary = analyze_http(path, show_status=False, packets=packets, meta=meta)
    file_summary = analyze_files(path, show_status=False)
    services_summary = analyze_services(path, show_status=False)

    file_artifacts = Counter()
    for art in getattr(file_summary, "artifacts", []) or []:
        name = getattr(art, "filename", None)
        if name:
            file_artifacts[str(name)] += 1

    service_rows = []
    for asset in getattr(services_summary, "assets", [])[:10]:
        if asset.protocol.upper() != "UDP":
            continue
        clients_preview = ", ".join(sorted(asset.clients)[:5]) if asset.clients else "-"
        service_rows.append({
            "service": asset.service_name,
            "port": asset.port,
            "count": asset.packets,
            "proto": asset.protocol,
            "endpoint": asset.ip,
            "clients": clients_preview,
            "client_count": len(asset.clients),
        })

    detections: list[dict[str, object]] = []
    broad_scans = []
    for src_ip, ports in src_to_ports.items():
        if len(ports) >= 50 and len(src_to_dsts.get(src_ip, set())) >= 5:
            broad_scans.append(src_ip)
    if broad_scans:
        detections.append({
            "severity": "high",
            "summary": "Potential UDP port scan activity",
            "details": ", ".join(broad_scans[:5]),
        })

    high_fanout = []
    for src_ip, dsts in src_to_dsts.items():
        if len(dsts) >= 50:
            high_fanout.append(src_ip)
    if high_fanout:
        detections.append({
            "severity": "warning",
            "summary": "High UDP fan-out",
            "details": ", ".join(high_fanout[:5]),
        })

    port_sweeps = []
    for (src_ip, dst_ip), ports in src_dst_ports.items():
        if len(ports) >= 50:
            port_sweeps.append(f"{src_ip} -> {dst_ip} ({len(ports)} ports)")
    if port_sweeps:
        detections.append({
            "severity": "high",
            "summary": "Potential UDP port sweep",
            "details": ", ".join(port_sweeps[:5]),
        })

    host_sweeps = []
    for (src_ip, dport), dsts in src_port_dsts.items():
        if len(dsts) >= 50:
            host_sweeps.append(f"{src_ip} -> *:{dport} ({len(dsts)} hosts)")
    if host_sweeps:
        detections.append({
            "severity": "warning",
            "summary": "Potential UDP host sweep",
            "details": ", ".join(host_sweeps[:5]),
        })

    amp_hits = []
    for (client, server, port), volumes in amp_flows.items():
        client_bytes = volumes.get("client", 0)
        server_bytes = volumes.get("server", 0)
        if server_bytes >= 10000 and (client_bytes == 0 or server_bytes / max(client_bytes, 1) >= 5):
            amp_hits.append(f"{client} -> {server}:{port} ({server_bytes}/{client_bytes} bytes)")
    if amp_hits:
        detections.append({
            "severity": "high",
            "summary": "Potential UDP amplification patterns",
            "details": ", ".join(amp_hits[:5]),
        })

    if dns_query_counts:
        avg_len = sum(dns_query_lengths) / max(len(dns_query_lengths), 1)
        avg_entropy = sum(dns_entropy_scores) / max(len(dns_entropy_scores), 1)
        suspicious_clients = []
        for src_ip, total in dns_query_counts.items():
            unique = len(dns_unique_queries.get(src_ip, set()))
            long_q = dns_long_queries.get(src_ip, 0)
            if total >= 20 and (unique / max(total, 1) >= 0.8) and (avg_len >= 30 or avg_entropy >= 3.5 or long_q >= 10):
                suspicious_clients.append(f"{src_ip} (unique {unique}/{total})")
        if suspicious_clients:
            detections.append({
                "severity": "high",
                "summary": "Possible DNS tunneling behavior",
                "details": ", ".join(suspicious_clients[:5]),
            })

    zero_ratio = zero_payload_packets / max(udp_packets, 1)
    if udp_packets >= 200 and zero_ratio >= 0.6:
        detections.append({
            "severity": "warning",
            "summary": "High rate of empty UDP payloads",
            "details": f"{zero_payload_packets}/{udp_packets} UDP packets have zero-length payloads.",
        })

    beacon_hits = []
    for (src_ip, dst_ip, sport, dport), tracker in beacon_trackers.items():
        intervals = tracker.get("intervals") or []
        payloads = tracker.get("payloads") or []
        if len(intervals) < 6:
            continue
        mean_interval = sum(intervals) / max(len(intervals), 1)
        if mean_interval <= 1.0:
            continue
        variance = sum((val - mean_interval) ** 2 for val in intervals) / max(len(intervals), 1)
        std_dev = math.sqrt(variance)
        cv = std_dev / mean_interval if mean_interval > 0 else 1.0
        if cv >= 0.2:
            continue
        payload_mean = sum(payloads) / max(len(payloads), 1) if payloads else 0
        if payload_mean > 512:
            continue
        beacon_hits.append(f"{src_ip}:{sport} -> {dst_ip}:{dport} ({mean_interval:.2f}s avg)")
    if beacon_hits:
        detections.append({
            "severity": "high",
            "summary": "Possible UDP beaconing",
            "details": ", ".join(beacon_hits[:5]),
        })

    if outbound_flow_bytes:
        top_outbound = outbound_flow_bytes.most_common(1)[0]
        if top_outbound[1] >= 5_000_000:
            detections.append({
                "severity": "high",
                "summary": "Large outbound UDP transfer",
                "details": f"{top_outbound[0][0]} -> {top_outbound[0][1]} sent {top_outbound[1]} bytes.",
            })

    artifacts: list[str] = []
    for ip, count in client_counts.most_common(5):
        artifacts.append(f"Client: {ip} ({count})")
    for ip, count in server_counts.most_common(5):
        artifacts.append(f"Server: {ip} ({count})")
    for port, count in port_counts.most_common(5):
        artifacts.append(f"Port: {port} ({count})")

    return UdpSummary(
        path=path,
        total_packets=total_packets,
        total_bytes=total_bytes,
        udp_packets=udp_packets,
        udp_bytes=udp_bytes,
        udp_payload_bytes=udp_payload_bytes,
        conversations=sorted(conversation_rows, key=lambda c: c.packets, reverse=True),
        client_counts=client_counts,
        client_bytes=client_bytes,
        server_counts=server_counts,
        server_bytes=server_bytes,
        port_counts=port_counts,
        port_destinations=port_destinations,
        endpoint_packets=endpoint_packets,
        endpoint_bytes=endpoint_bytes,
        packet_size_hist=packet_size_hist,
        payload_size_hist=payload_size_hist,
        packet_size_stats=_stats_from_samples(packet_size_samples),
        payload_size_stats=_stats_from_samples(payload_size_samples),
        zero_payload_packets=zero_payload_packets,
        http_requests=http_summary.total_requests,
        http_responses=http_summary.total_responses,
        http_methods=http_summary.method_counts,
        http_statuses=http_summary.status_counts,
        http_urls=http_summary.url_counts,
        http_user_agents=http_summary.user_agents,
        http_files=http_summary.file_artifacts,
        file_artifacts=file_artifacts,
        services=service_rows,
        detections=detections,
        artifacts=artifacts,
        errors=errors + http_summary.errors + file_summary.errors + services_summary.errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )
