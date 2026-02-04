from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .pcap_cache import get_reader
from .utils import safe_float
from .http import analyze_http
from .files import analyze_files
from .services import analyze_services

try:
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    IPv6 = None  # type: ignore


@dataclass(frozen=True)
class TcpConversation:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    packets: int
    bytes: int
    syn: int
    syn_ack: int
    rst: int
    fin: int
    ack: int
    first_seen: Optional[float]
    last_seen: Optional[float]


@dataclass(frozen=True)
class TcpSummary:
    path: Path
    total_packets: int
    tcp_packets: int
    conversations: list[TcpConversation]
    client_counts: Counter[str]
    server_counts: Counter[str]
    port_counts: Counter[int]
    syn_counts: Counter[str]
    rst_counts: Counter[str]
    retrans_timeseries: list[int]
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


def analyze_tcp(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
) -> TcpSummary:
    errors: list[str] = []
    if IP is None and IPv6 is None:
        errors.append("Scapy IP layers unavailable; install scapy for TCP analysis.")
        return TcpSummary(
            path=path,
            total_packets=0,
            tcp_packets=0,
            conversations=[],
            client_counts=Counter(),
            server_counts=Counter(),
            port_counts=Counter(),
            syn_counts=Counter(),
            rst_counts=Counter(),
            retrans_timeseries=[],
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
    tcp_packets = 0
    conversations: dict[tuple[str, str, int, int], dict[str, object]] = defaultdict(lambda: {
        "packets": 0,
        "bytes": 0,
        "syn": 0,
        "syn_ack": 0,
        "rst": 0,
        "fin": 0,
        "ack": 0,
        "first_seen": None,
        "last_seen": None,
    })

    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    port_counts: Counter[int] = Counter()
    syn_counts: Counter[str] = Counter()
    rst_counts: Counter[str] = Counter()
    src_to_ports: dict[str, set[int]] = defaultdict(set)
    src_to_dsts: dict[str, set[str]] = defaultdict(set)
    retrans_counts: Counter[str] = Counter()
    zero_window_counts: Counter[str] = Counter()
    small_window_counts: Counter[str] = Counter()
    flow_seq_seen: dict[tuple[str, str, int, int], set[int]] = defaultdict(set)
    retrans_bins: Counter[int] = Counter()

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

            if TCP is None or not pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                continue

            tcp_packets += 1
            tcp_layer = pkt[TCP]  # type: ignore[index]
            sport = int(getattr(tcp_layer, "sport", 0))
            dport = int(getattr(tcp_layer, "dport", 0))
            flags = getattr(tcp_layer, "flags", 0)
            flags_val = int(flags)
            seq = int(getattr(tcp_layer, "seq", 0))
            window = int(getattr(tcp_layer, "window", 0))

            client_counts[src_ip or "-"] += 1
            server_counts[dst_ip or "-"] += 1
            port_counts[dport] += 1

            src_to_ports[src_ip or "-"].add(dport)
            src_to_dsts[src_ip or "-"].add(dst_ip or "-")

            convo_key = (src_ip or "-", dst_ip or "-", sport, dport)
            convo = conversations[convo_key]
            convo["packets"] = int(convo["packets"]) + 1
            convo["bytes"] = int(convo["bytes"]) + pkt_len

            seq_set = flow_seq_seen[convo_key]
            if seq in seq_set:
                retrans_counts[src_ip or "-"] += 1
                if ts is not None:
                    retrans_bins[int(ts // 60)] += 1
            else:
                seq_set.add(seq)
                if len(seq_set) > 5000:
                    seq_set.clear()

            if window == 0:
                zero_window_counts[src_ip or "-"] += 1
            elif window < 1024:
                small_window_counts[src_ip or "-"] += 1
            if flags_val & 0x02:
                convo["syn"] = int(convo["syn"]) + 1
                syn_counts[src_ip or "-"] += 1
            if flags_val & 0x12 == 0x12:
                convo["syn_ack"] = int(convo["syn_ack"]) + 1
            if flags_val & 0x04:
                convo["rst"] = int(convo["rst"]) + 1
                rst_counts[src_ip or "-"] += 1
            if flags_val & 0x01:
                convo["fin"] = int(convo["fin"]) + 1
            if flags_val & 0x10:
                convo["ack"] = int(convo["ack"]) + 1

            if ts is not None:
                if convo["first_seen"] is None or ts < convo["first_seen"]:
                    convo["first_seen"] = ts
                if convo["last_seen"] is None or ts > convo["last_seen"]:
                    convo["last_seen"] = ts

    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        reader.close()

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    conversation_rows: list[TcpConversation] = []
    for (src_ip, dst_ip, sport, dport), data in conversations.items():
        conversation_rows.append(TcpConversation(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=sport,
            dst_port=dport,
            packets=int(data["packets"]),
            bytes=int(data["bytes"]),
            syn=int(data["syn"]),
            syn_ack=int(data["syn_ack"]),
            rst=int(data["rst"]),
            fin=int(data["fin"]),
            ack=int(data["ack"]),
            first_seen=data["first_seen"],
            last_seen=data["last_seen"],
        ))

    http_summary = analyze_http(path, show_status=False, packets=packets, meta=meta)
    file_summary = analyze_files(path, show_status=False)
    services_summary = analyze_services(path, show_status=False)

    detections: list[dict[str, object]] = []
    if tcp_packets and (sum(rst_counts.values()) / max(tcp_packets, 1)) > 0.2:
        detections.append({
            "severity": "warning",
            "summary": "High TCP RST rate",
            "details": f"RST packets: {sum(rst_counts.values())} of {tcp_packets}",
        })

    syn_only = sum(syn_counts.values()) - sum(int(c.syn_ack) for c in conversation_rows)
    if syn_only > 50:
        detections.append({
            "severity": "warning",
            "summary": "High SYN without SYN-ACK",
            "details": f"Potential scan or blocked services (SYN-only: {syn_only}).",
        })

    total_retrans = sum(retrans_counts.values())
    if total_retrans > 100:
        top_retrans = ", ".join(f"{ip}({count})" for ip, count in retrans_counts.most_common(5))
        detections.append({
            "severity": "warning",
            "summary": "TCP retransmission spikes",
            "details": f"Total retransmissions: {total_retrans}. Top sources: {top_retrans}",
        })

    total_zero_window = sum(zero_window_counts.values())
    if total_zero_window > 20:
        top_zero = ", ".join(f"{ip}({count})" for ip, count in zero_window_counts.most_common(5))
        detections.append({
            "severity": "warning",
            "summary": "TCP zero-window events",
            "details": f"Total zero-window packets: {total_zero_window}. Top sources: {top_zero}",
        })

    total_small_window = sum(small_window_counts.values())
    if total_small_window > 100:
        top_small = ", ".join(f"{ip}({count})" for ip, count in small_window_counts.most_common(5))
        detections.append({
            "severity": "info",
            "summary": "TCP small-window anomalies",
            "details": f"Total small-window packets: {total_small_window}. Top sources: {top_small}",
        })

    broad_scans = []
    for src_ip, ports in src_to_ports.items():
        if len(ports) >= 50 and len(src_to_dsts.get(src_ip, set())) >= 5:
            broad_scans.append(src_ip)
    if broad_scans:
        detections.append({
            "severity": "high",
            "summary": "Potential TCP port scan activity",
            "details": ", ".join(broad_scans[:5]),
        })

    artifacts: list[str] = []
    for ip, count in client_counts.most_common(5):
        artifacts.append(f"Client: {ip} ({count})")
    for ip, count in server_counts.most_common(5):
        artifacts.append(f"Server: {ip} ({count})")
    for port, count in port_counts.most_common(5):
        artifacts.append(f"Port: {port} ({count})")

    file_artifacts = Counter()
    for art in getattr(file_summary, "artifacts", []) or []:
        name = getattr(art, "filename", None)
        if name:
            file_artifacts[str(name)] += 1

    service_rows = []
    for asset in getattr(services_summary, "assets", [])[:10]:
        service_rows.append({
            "service": asset.service_name,
            "port": asset.port,
            "count": asset.packets,
            "proto": asset.protocol,
        })

    return TcpSummary(
        path=path,
        total_packets=total_packets,
        tcp_packets=tcp_packets,
        conversations=sorted(conversation_rows, key=lambda c: c.packets, reverse=True),
        client_counts=client_counts,
        server_counts=server_counts,
        port_counts=port_counts,
        syn_counts=syn_counts,
        rst_counts=rst_counts,
        retrans_timeseries=[count for _, count in sorted(retrans_bins.items())],
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
