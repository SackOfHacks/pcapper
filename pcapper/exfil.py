from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import math
import ipaddress

from .pcap_cache import get_reader
from .utils import safe_float, format_bytes_as_mb
from .http import analyze_http
from .dns import analyze_dns
from .files import analyze_files

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.layers.dns import DNS  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore
    DNS = None  # type: ignore


@dataclass(frozen=True)
class ExfilSummary:
    path: Path
    total_packets: int
    total_bytes: int
    outbound_bytes: int
    outbound_flows: list[dict[str, object]]
    top_external_dsts: Counter[str]
    dns_tunnel_suspects: list[dict[str, object]]
    http_post_suspects: list[dict[str, object]]
    file_artifacts: list[dict[str, object]]
    detections: list[dict[str, object]]
    artifacts: list[str]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except Exception:
        return False
    return ip.is_global


def _is_private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except Exception:
        return False
    return ip.is_private


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


def analyze_exfil(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
) -> ExfilSummary:
    errors: list[str] = []
    if IP is None and IPv6 is None:
        errors.append("Scapy IP layers unavailable; install scapy for exfil analysis.")
        return ExfilSummary(
            path=path,
            total_packets=0,
            total_bytes=0,
            outbound_bytes=0,
            outbound_flows=[],
            top_external_dsts=Counter(),
            dns_tunnel_suspects=[],
            http_post_suspects=[],
            file_artifacts=[],
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
    outbound_bytes = 0
    outbound_flow_bytes: Counter[tuple[str, str]] = Counter()
    external_dsts: Counter[str] = Counter()

    dns_query_counts: Counter[str] = Counter()
    dns_unique_queries: dict[str, set[str]] = defaultdict(set)
    dns_long_queries: Counter[str] = Counter()
    dns_entropy_scores: list[float] = []

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

            if not src_ip or not dst_ip:
                continue

            if _is_private_ip(src_ip) and _is_public_ip(dst_ip):
                outbound_bytes += pkt_len
                outbound_flow_bytes[(src_ip, dst_ip)] += pkt_len
                external_dsts[dst_ip] += pkt_len

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
                        dns_query_counts[src_ip] += 1
                        dns_unique_queries[src_ip].add(qname)
                        if len(qname) >= 50:
                            dns_long_queries[src_ip] += 1
                        dns_entropy_scores.append(_shannon_entropy(qname))

    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        reader.close()

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    outbound_flows = [
        {
            "src": src,
            "dst": dst,
            "bytes": bytes_sent,
        }
        for (src, dst), bytes_sent in outbound_flow_bytes.most_common(10)
    ]

    http_summary = analyze_http(path, show_status=False, packets=packets, meta=meta)
    dns_summary = analyze_dns(path, show_status=False, packets=packets, meta=meta)
    file_summary = analyze_files(path, show_status=False)

    http_post_suspects: list[dict[str, object]] = []
    for item in http_summary.post_payloads:
        try:
            size = int(item.get("bytes", 0))
        except Exception:
            size = 0
        if size >= 1_000_000:
            http_post_suspects.append(item)

    dns_tunnel_suspects: list[dict[str, object]] = []
    avg_entropy = sum(dns_entropy_scores) / max(len(dns_entropy_scores), 1)
    for src_ip, total in dns_query_counts.items():
        unique = len(dns_unique_queries.get(src_ip, set()))
        long_q = dns_long_queries.get(src_ip, 0)
        if total >= 20 and unique / max(total, 1) >= 0.8 and (long_q >= 10 or avg_entropy >= 3.5):
            dns_tunnel_suspects.append({
                "src": src_ip,
                "total": total,
                "unique": unique,
                "long": long_q,
            })

    file_artifacts: list[dict[str, object]] = []
    for art in getattr(file_summary, "artifacts", []) or []:
        name = getattr(art, "filename", None)
        size = getattr(art, "size_bytes", None)
        if name:
            file_artifacts.append({
                "filename": str(name),
                "size": int(size) if isinstance(size, int) else None,
                "note": getattr(art, "note", None),
            })

    detections: list[dict[str, object]] = []
    if outbound_flows:
        top_flow = outbound_flows[0]
        if int(top_flow.get("bytes", 0)) >= 5_000_000:
            detections.append({
                "severity": "high",
                "summary": "Large outbound data transfer",
                "details": f"{top_flow.get('src')} -> {top_flow.get('dst')} sent {format_bytes_as_mb(int(top_flow.get('bytes', 0)))}",
            })

    if dns_tunnel_suspects:
        detections.append({
            "severity": "high",
            "summary": "Possible DNS tunneling",
            "details": ", ".join(f"{item['src']}({item['unique']}/{item['total']})" for item in dns_tunnel_suspects[:5]),
        })

    if http_post_suspects:
        detections.append({
            "severity": "warning",
            "summary": "Large HTTP POST payloads",
            "details": f"{len(http_post_suspects)} POST bodies >= 1MB",
        })

    if dns_summary.qname_counts:
        top_dns = ", ".join(f"{host}({count})" for host, count in dns_summary.qname_counts.most_common(5))
        detections.append({
            "severity": "info",
            "summary": "Top DNS query hosts",
            "details": top_dns,
        })

    artifacts: list[str] = []
    for dst, bytes_sent in external_dsts.most_common(5):
        artifacts.append(f"External dst: {dst} ({format_bytes_as_mb(bytes_sent)})")
    for host, count in http_summary.host_counts.most_common(5):
        artifacts.append(f"HTTP host: {host} ({count})")

    return ExfilSummary(
        path=path,
        total_packets=total_packets,
        total_bytes=total_bytes,
        outbound_bytes=outbound_bytes,
        outbound_flows=outbound_flows,
        top_external_dsts=external_dsts,
        dns_tunnel_suspects=dns_tunnel_suspects,
        http_post_suspects=http_post_suspects,
        file_artifacts=file_artifacts,
        detections=detections,
        artifacts=artifacts,
        errors=errors + http_summary.errors + dns_summary.errors + file_summary.errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )
