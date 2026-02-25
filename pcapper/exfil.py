from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import math
import ipaddress

from .pcap_cache import get_reader
from .utils import safe_float, format_bytes_as_mb, format_duration
from .http import analyze_http
from .dns import analyze_dns
from .files import analyze_files
from .progress import run_with_busy_status

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
    internal_flows: list[dict[str, object]]
    ot_flows: list[dict[str, object]]
    top_external_dsts: Counter[str]
    dns_tunnel_suspects: list[dict[str, object]]
    http_post_suspects: list[dict[str, object]]
    file_artifacts: list[dict[str, object]]
    file_exfil_suspects: list[dict[str, object]]
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


OT_PORTS = {
    102, 502, 9600, 20000, 2404, 47808, 44818, 2222, 34962, 34963, 34964,
    4840, 1911, 4911, 5094, 18245, 18246, 20547, 1962, 5006, 5007, 5683,
    5684, 2455, 1217, 34378, 34379, 34380,
}

FILE_TRANSFER_PORTS = {
    20, 21, 22, 69, 80, 443, 445, 139, 2049, 111, 2121, 990, 989,
}

EMAIL_PORTS = {25, 465, 587, 110, 143, 993, 995}

REMOTE_MGMT_PORTS = {22, 23, 135, 139, 445, 3389, 5900, 5938, 5985, 5986}

SUSPICIOUS_EXFIL_EXTS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    ".csv", ".sql", ".bak", ".db", ".sqlite", ".dump",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pcap", ".pcapng", ".log", ".cfg", ".conf", ".ini",
}


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
            internal_flows=[],
            ot_flows=[],
            top_external_dsts=Counter(),
            dns_tunnel_suspects=[],
            http_post_suspects=[],
            file_artifacts=[],
            file_exfil_suspects=[],
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
    outbound_flow_bytes: Counter[tuple[str, str, str, Optional[int]]] = Counter()
    outbound_flow_packets: Counter[tuple[str, str, str, Optional[int]]] = Counter()
    outbound_flow_first: dict[tuple[str, str, str, Optional[int]], float] = {}
    outbound_flow_last: dict[tuple[str, str, str, Optional[int]], float] = {}
    outbound_port_bytes: Counter[tuple[str, int]] = Counter()
    external_dsts: Counter[str] = Counter()
    internal_flow_bytes: Counter[tuple[str, str, str, Optional[int]]] = Counter()
    internal_flow_packets: Counter[tuple[str, str, str, Optional[int]]] = Counter()
    internal_flow_first: dict[tuple[str, str, str, Optional[int]], float] = {}
    internal_flow_last: dict[tuple[str, str, str, Optional[int]], float] = {}
    ot_flow_bytes: Counter[tuple[str, str, str, Optional[int]]] = Counter()
    ot_flow_packets: Counter[tuple[str, str, str, Optional[int]]] = Counter()
    ot_flow_first: dict[tuple[str, str, str, Optional[int]], float] = {}
    ot_flow_last: dict[tuple[str, str, str, Optional[int]], float] = {}
    remote_mgmt_bytes: Counter[tuple[str, str, str, Optional[int]]] = Counter()

    dns_query_counts: Counter[str] = Counter()
    dns_unique_queries: dict[str, set[str]] = defaultdict(set)
    dns_long_queries: Counter[str] = Counter()
    dns_entropy_scores: list[float] = []
    dns_entropy_by_src: dict[str, list[float]] = defaultdict(list)
    dns_max_label_by_src: Counter[str] = Counter()

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
            proto = "IP"
            src_port: Optional[int] = None
            dst_port: Optional[int] = None
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                ip_layer = pkt[IP]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                ip_layer = pkt[IPv6]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                proto = "TCP"
                src_port = int(getattr(pkt[TCP], "sport", 0) or 0)  # type: ignore[index]
                dst_port = int(getattr(pkt[TCP], "dport", 0) or 0)  # type: ignore[index]
            elif UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                proto = "UDP"
                src_port = int(getattr(pkt[UDP], "sport", 0) or 0)  # type: ignore[index]
                dst_port = int(getattr(pkt[UDP], "dport", 0) or 0)  # type: ignore[index]

            if src_ip and dst_ip and ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            if not src_ip or not dst_ip:
                continue

            if _is_private_ip(src_ip) and _is_public_ip(dst_ip):
                flow_key = (src_ip, dst_ip, proto, dst_port)
                outbound_bytes += pkt_len
                outbound_flow_bytes[flow_key] += pkt_len
                outbound_flow_packets[flow_key] += 1
                if ts is not None:
                    if flow_key not in outbound_flow_first:
                        outbound_flow_first[flow_key] = ts
                    outbound_flow_last[flow_key] = ts
                external_dsts[dst_ip] += pkt_len
                if dst_port is not None and dst_port > 0:
                    outbound_port_bytes[(proto, dst_port)] += pkt_len

            if _is_private_ip(src_ip) and _is_private_ip(dst_ip):
                flow_key = (src_ip, dst_ip, proto, dst_port)
                internal_flow_bytes[flow_key] += pkt_len
                internal_flow_packets[flow_key] += 1
                if ts is not None:
                    if flow_key not in internal_flow_first:
                        internal_flow_first[flow_key] = ts
                    internal_flow_last[flow_key] = ts

            ot_port = None
            if src_port in OT_PORTS:
                ot_port = src_port
            elif dst_port in OT_PORTS:
                ot_port = dst_port
            if ot_port:
                flow_key = (src_ip, dst_ip, proto, ot_port)
                ot_flow_bytes[flow_key] += pkt_len
                ot_flow_packets[flow_key] += 1
                if ts is not None:
                    if flow_key not in ot_flow_first:
                        ot_flow_first[flow_key] = ts
                    ot_flow_last[flow_key] = ts

            if dst_port in REMOTE_MGMT_PORTS or src_port in REMOTE_MGMT_PORTS:
                flow_key = (src_ip, dst_ip, proto, dst_port or src_port)
                remote_mgmt_bytes[flow_key] += pkt_len

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
                        entropy = _shannon_entropy(qname)
                        dns_entropy_scores.append(entropy)
                        dns_entropy_by_src[src_ip].append(entropy)
                        max_label = max((len(label) for label in qname.split(".") if label), default=0)
                        if max_label > dns_max_label_by_src[src_ip]:
                            dns_max_label_by_src[src_ip] = max_label

    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        reader.close()

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    def _build_flow_list(
        counter_bytes: Counter[tuple[str, str, str, Optional[int]]],
        counter_packets: Counter[tuple[str, str, str, Optional[int]]],
        first_map: dict[tuple[str, str, str, Optional[int]], float],
        last_map: dict[tuple[str, str, str, Optional[int]], float],
        limit: int = 15,
    ) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        for (src, dst, proto, dst_port), bytes_sent in counter_bytes.most_common(limit):
            duration = 0.0
            if (src, dst, proto, dst_port) in last_map:
                duration = max(
                    0.0,
                    last_map.get((src, dst, proto, dst_port), 0.0)
                    - first_map.get((src, dst, proto, dst_port), 0.0),
                )
            rows.append({
                "src": src,
                "dst": dst,
                "proto": proto,
                "dst_port": dst_port,
                "bytes": bytes_sent,
                "packets": counter_packets.get((src, dst, proto, dst_port), 0),
                "duration_seconds": duration,
            })
        return rows

    outbound_flows = _build_flow_list(
        outbound_flow_bytes,
        outbound_flow_packets,
        outbound_flow_first,
        outbound_flow_last,
        limit=15,
    )
    internal_flows = _build_flow_list(
        internal_flow_bytes,
        internal_flow_packets,
        internal_flow_first,
        internal_flow_last,
        limit=15,
    )
    ot_flows = _build_flow_list(
        ot_flow_bytes,
        ot_flow_packets,
        ot_flow_first,
        ot_flow_last,
        limit=15,
    )

    for bucket in (outbound_flows, internal_flows, ot_flows):
        for item in bucket:
            packets_count = int(item.get("packets", 0) or 0)
            bytes_sent = int(item.get("bytes", 0) or 0)
            duration = float(item.get("duration_seconds", 0.0) or 0.0)
            item["avg_packet_bytes"] = (bytes_sent / packets_count) if packets_count > 0 else 0.0
            item["bytes_per_second"] = (bytes_sent / duration) if duration > 0 else 0.0

    def _busy(desc: str, func, *args, **kwargs):
        return run_with_busy_status(path, show_status, f"Exfil: {desc}", func, *args, **kwargs)

    http_summary = _busy("HTTP", analyze_http, path, show_status=False, packets=packets, meta=meta)
    dns_summary = _busy("DNS", analyze_dns, path, show_status=False, packets=packets, meta=meta)
    file_summary = _busy("Files", analyze_files, path, show_status=False)

    http_post_suspects: list[dict[str, object]] = []
    post_aggregates: dict[tuple[str, str, str], dict[str, object]] = {}
    for item in http_summary.post_payloads:
        src = str(item.get("src", "-"))
        dst = str(item.get("dst", "-"))
        host = str(item.get("host", "-"))
        uri = str(item.get("uri", "-"))
        content_type = str(item.get("content_type", "-"))
        try:
            size = int(item.get("bytes", 0))
        except Exception:
            size = 0
        agg_key = (src, dst, host)
        aggregate = post_aggregates.setdefault(
            agg_key,
            {
                "bytes": 0,
                "requests": 0,
                "max_single": 0,
                "uris": set(),
                "content_types": set(),
            },
        )
        aggregate["bytes"] = int(aggregate.get("bytes", 0)) + max(size, 0)
        aggregate["requests"] = int(aggregate.get("requests", 0)) + 1
        aggregate["max_single"] = max(int(aggregate.get("max_single", 0)), size)
        uris = aggregate.get("uris")
        if isinstance(uris, set):
            uris.add(uri)
        cts = aggregate.get("content_types")
        if isinstance(cts, set) and content_type and content_type != "-":
            cts.add(content_type)
        if size >= 1_000_000:
            flagged = dict(item)
            flagged["mode"] = "single"
            flagged["requests"] = 1
            http_post_suspects.append(flagged)

    for (src, dst, host), aggregate in post_aggregates.items():
        total_post_bytes = int(aggregate.get("bytes", 0))
        request_count = int(aggregate.get("requests", 0))
        if total_post_bytes >= 3_000_000 or (request_count >= 15 and total_post_bytes >= 1_500_000):
            uris = sorted(str(uri) for uri in (aggregate.get("uris") or set()))
            content_types = sorted(str(value) for value in (aggregate.get("content_types") or set()))
            http_post_suspects.append({
                "src": src,
                "dst": dst,
                "host": host,
                "uri": ", ".join(uris[:3]) if uris else "-",
                "bytes": total_post_bytes,
                "content_type": ", ".join(content_types[:3]) if content_types else "-",
                "requests": request_count,
                "mode": "aggregate",
            })

    dns_tunnel_suspects: list[dict[str, object]] = []
    for src_ip, total in dns_query_counts.items():
        unique = len(dns_unique_queries.get(src_ip, set()))
        long_q = dns_long_queries.get(src_ip, 0)
        entropy_values = dns_entropy_by_src.get(src_ip, [])
        avg_entropy = sum(entropy_values) / max(len(entropy_values), 1)
        max_label = int(dns_max_label_by_src.get(src_ip, 0))
        if total >= 20 and unique / max(total, 1) >= 0.75 and (long_q >= 8 or avg_entropy >= 3.6 or max_label >= 35):
            dns_tunnel_suspects.append({
                "src": src_ip,
                "total": total,
                "unique": unique,
                "long": long_q,
                "avg_entropy": round(avg_entropy, 2),
                "max_label": max_label,
            })

    file_artifacts: list[dict[str, object]] = []
    file_exfil_suspects: list[dict[str, object]] = []
    for art in getattr(file_summary, "artifacts", []) or []:
        name = getattr(art, "filename", None)
        size = getattr(art, "size_bytes", None)
        if name:
            file_artifacts.append({
                "filename": str(name),
                "size": int(size) if isinstance(size, int) else None,
                "note": getattr(art, "note", None),
            })
        src_ip = getattr(art, "src_ip", None)
        dst_ip = getattr(art, "dst_ip", None)
        proto = str(getattr(art, "protocol", "") or "-")
        packet_index = getattr(art, "packet_index", None)
        size_val = int(size) if isinstance(size, int) else 0
        ext = ""
        if name and "." in str(name):
            ext = "." + str(name).lower().rsplit(".", 1)[-1]
        if src_ip and dst_ip:
            src_private = _is_private_ip(str(src_ip))
            dst_public = _is_public_ip(str(dst_ip))
            is_ot_proto = proto.upper() in {"ENIP", "S7", "MODBUS", "DNP3", "IEC104", "OPC", "OPC UA", "BACNET"}
            is_file_proto = proto.upper() in {"HTTP", "HTTPS/SSL", "FTP", "TFTP", "SMB", "NFS", "SMTP", "IMAP", "POP3", "ENIP"}
            if src_private and size_val >= 500_000 and (dst_public or is_ot_proto or is_file_proto):
                file_exfil_suspects.append({
                    "src": str(src_ip),
                    "dst": str(dst_ip),
                    "protocol": proto,
                    "filename": str(name) if name else "-",
                    "size": size_val,
                    "packet": packet_index,
                    "note": getattr(art, "note", None),
                    "file_type": getattr(art, "file_type", None),
                    "flagged_ext": ext if ext in SUSPICIOUS_EXFIL_EXTS else None,
                })

    detections: list[dict[str, object]] = []
    if outbound_flows:
        top_flow = outbound_flows[0]
        if int(top_flow.get("bytes", 0)) >= 5_000_000:
            flow_proto = str(top_flow.get("proto", "IP"))
            flow_port = top_flow.get("dst_port")
            flow_port_text = str(flow_port) if isinstance(flow_port, int) and flow_port > 0 else "-"
            detections.append({
                "severity": "high",
                "summary": "Large outbound data transfer",
                "details": f"{top_flow.get('src')} -> {top_flow.get('dst')} ({flow_proto}/{flow_port_text}) sent {format_bytes_as_mb(int(top_flow.get('bytes', 0)))}",
                "evidence": [
                    f"packets={int(top_flow.get('packets', 0))}",
                    f"duration={format_duration(float(top_flow.get('duration_seconds', 0.0)))}",
                    f"throughput={format_bytes_as_mb(int(top_flow.get('bytes_per_second', 0.0) * 60))}/min",
                ],
            })

    if total_bytes >= 2_000_000:
        outbound_ratio = outbound_bytes / max(total_bytes, 1)
        if outbound_ratio >= 0.60:
            detections.append({
                "severity": "warning",
                "summary": "Outbound-heavy traffic profile",
                "details": f"Outbound traffic is {outbound_ratio * 100:.1f}% of observed bytes ({format_bytes_as_mb(outbound_bytes)} / {format_bytes_as_mb(total_bytes)}).",
            })

    if external_dsts and outbound_bytes >= 3_000_000:
        top_dst, top_dst_bytes = external_dsts.most_common(1)[0]
        dst_share = top_dst_bytes / max(outbound_bytes, 1)
        if dst_share >= 0.70:
            detections.append({
                "severity": "warning",
                "summary": "Exfiltration concentrated to single external destination",
                "details": f"{top_dst} received {dst_share * 100:.1f}% of outbound bytes ({format_bytes_as_mb(top_dst_bytes)}).",
            })

    internal_candidates = []
    for flow in internal_flows:
        bytes_val = int(flow.get("bytes", 0) or 0)
        port_val = flow.get("dst_port")
        if bytes_val >= 10_000_000:
            internal_candidates.append(flow)
            continue
        if bytes_val >= 1_000_000 and (
            port_val in OT_PORTS
            or port_val in FILE_TRANSFER_PORTS
            or port_val in REMOTE_MGMT_PORTS
        ):
            internal_candidates.append(flow)
    if internal_candidates:
        detections.append({
            "severity": "warning",
            "summary": "Large internal data transfers",
            "details": "; ".join(
                f"{flow.get('src')}->{flow.get('dst')} {flow.get('proto')}/{flow.get('dst_port') or '-'} "
                f"{format_bytes_as_mb(int(flow.get('bytes', 0) or 0))}"
                for flow in internal_candidates[:6]
            ),
            "evidence": [
                f"{flow.get('src')}->{flow.get('dst')} bytes={format_bytes_as_mb(int(flow.get('bytes', 0) or 0))} "
                f"dur={format_duration(float(flow.get('duration_seconds', 0.0) or 0.0))}"
                for flow in internal_candidates[:8]
            ],
        })

    ot_candidates = [
        flow for flow in ot_flows
        if int(flow.get("bytes", 0) or 0) >= 1_000_000
    ]
    if ot_candidates:
        external_ot = [
            flow for flow in ot_candidates
            if _is_public_ip(str(flow.get("src", ""))) or _is_public_ip(str(flow.get("dst", "")))
        ]
        severity = "critical" if external_ot else "warning"
        detections.append({
            "severity": severity,
            "summary": "OT/ICS data movement on control ports",
            "details": "; ".join(
                f"{flow.get('src')}->{flow.get('dst')} {flow.get('proto')}/{flow.get('dst_port') or '-'} "
                f"{format_bytes_as_mb(int(flow.get('bytes', 0) or 0))}"
                for flow in ot_candidates[:6]
            ),
            "evidence": [
                f"{flow.get('src')}->{flow.get('dst')} bytes={format_bytes_as_mb(int(flow.get('bytes', 0) or 0))} "
                f"dur={format_duration(float(flow.get('duration_seconds', 0.0) or 0.0))}"
                for flow in ot_candidates[:8]
            ],
        })

    mgmt_suspects = [
        (src, dst, proto, port, bytes_sent)
        for (src, dst, proto, port), bytes_sent in remote_mgmt_bytes.most_common(8)
        if bytes_sent >= 1_000_000
    ]
    if mgmt_suspects:
        detections.append({
            "severity": "warning",
            "summary": "High-volume transfers over management ports",
            "details": "; ".join(
                f"{src}->{dst} {proto}/{port or '-'} {format_bytes_as_mb(bytes_sent)}"
                for src, dst, proto, port, bytes_sent in mgmt_suspects[:6]
            ),
        })

    if dns_tunnel_suspects:
        detections.append({
            "severity": "high",
            "summary": "Possible DNS tunneling",
            "details": ", ".join(
                f"{item['src']}({item['unique']}/{item['total']},H={item['avg_entropy']},L={item['max_label']})"
                for item in dns_tunnel_suspects[:5]
            ),
            "evidence": [
                f"{item['src']} unique_ratio={item['unique'] / max(item['total'], 1):.2f} long={item['long']} entropy={item['avg_entropy']} max_label={item['max_label']}"
                for item in dns_tunnel_suspects[:8]
            ],
        })

    if http_post_suspects:
        aggregate_count = sum(1 for item in http_post_suspects if str(item.get("mode", "single")) == "aggregate")
        detections.append({
            "severity": "warning",
            "summary": "Large HTTP POST payloads",
            "details": f"{len(http_post_suspects)} suspicious POST channel(s); {aggregate_count} cumulative high-volume stream(s).",
            "evidence": [
                f"{item.get('src')}->{item.get('dst')} host={item.get('host')} bytes={format_bytes_as_mb(int(item.get('bytes', 0)))} requests={item.get('requests', 1)} mode={item.get('mode', 'single')}"
                for item in http_post_suspects[:8]
            ],
        })

    if file_exfil_suspects:
        detections.append({
            "severity": "warning",
            "summary": "Suspicious file transfer volume",
            "details": "; ".join(
                f"{item.get('src')}->{item.get('dst')} {item.get('protocol')} {item.get('filename')} "
                f"{format_bytes_as_mb(int(item.get('size', 0) or 0))}"
                for item in file_exfil_suspects[:6]
            ),
            "evidence": [
                f"pkt={item.get('packet', '-')}, {item.get('src')}->{item.get('dst')} "
                f"{item.get('protocol')} size={format_bytes_as_mb(int(item.get('size', 0) or 0))} "
                f"type={item.get('file_type') or '-'}"
                for item in file_exfil_suspects[:8]
            ],
        })

    common_outbound_ports = {
        20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995,
        3306, 3389, 5060, 8080, 8443,
    }
    uncommon_channels = [
        (proto, port, bytes_sent)
        for (proto, port), bytes_sent in outbound_port_bytes.items()
        if port not in common_outbound_ports and bytes_sent >= 1_000_000
    ]
    uncommon_channels.sort(key=lambda row: row[2], reverse=True)
    if uncommon_channels:
        detections.append({
            "severity": "warning",
            "summary": "High-volume outbound traffic on uncommon ports",
            "details": ", ".join(
                f"{proto}/{port}={format_bytes_as_mb(bytes_sent)}"
                for proto, port, bytes_sent in uncommon_channels[:6]
            ),
        })

    txt_queries = int(dns_summary.type_counts.get("TXT", 0))
    if dns_summary.query_packets and txt_queries:
        txt_ratio = txt_queries / max(dns_summary.query_packets, 1)
        if txt_ratio >= 0.2 and txt_queries >= 20:
            detections.append({
                "severity": "warning",
                "summary": "High DNS TXT query volume",
                "details": f"TXT queries are {txt_ratio * 100:.1f}% of DNS requests ({txt_queries}/{dns_summary.query_packets}).",
            })

    email_bytes = sum(
        bytes_sent for (_proto, port), bytes_sent in outbound_port_bytes.items() if port in EMAIL_PORTS
    )
    if email_bytes >= 2_000_000:
        detections.append({
            "severity": "warning",
            "summary": "High-volume outbound email traffic",
            "details": f"Outbound email ports carried {format_bytes_as_mb(email_bytes)}.",
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
    for (proto, port), bytes_sent in outbound_port_bytes.most_common(5):
        artifacts.append(f"Outbound channel: {proto}/{port} ({format_bytes_as_mb(bytes_sent)})")
    for host, count in http_summary.host_counts.most_common(5):
        artifacts.append(f"HTTP host: {host} ({count})")
    for item in dns_tunnel_suspects[:5]:
        artifacts.append(
            f"DNS suspect: {item['src']} unique={item['unique']}/{item['total']} entropy={item['avg_entropy']}"
        )
    for flow in ot_flows[:3]:
        artifacts.append(
            f"OT flow: {flow.get('src')}->{flow.get('dst')} {flow.get('proto')}/{flow.get('dst_port') or '-'} ({format_bytes_as_mb(int(flow.get('bytes', 0) or 0))})"
        )
    for item in file_exfil_suspects[:3]:
        artifacts.append(
            f"File transfer: {item.get('src')}->{item.get('dst')} {item.get('protocol')} {item.get('filename')} ({format_bytes_as_mb(int(item.get('size', 0) or 0))})"
        )

    return ExfilSummary(
        path=path,
        total_packets=total_packets,
        total_bytes=total_bytes,
        outbound_bytes=outbound_bytes,
        outbound_flows=outbound_flows,
        internal_flows=internal_flows,
        ot_flows=ot_flows,
        top_external_dsts=external_dsts,
        dns_tunnel_suspects=dns_tunnel_suspects,
        http_post_suspects=http_post_suspects,
        file_artifacts=file_artifacts,
        file_exfil_suspects=file_exfil_suspects,
        detections=detections,
        artifacts=artifacts,
        errors=errors + http_summary.errors + dns_summary.errors + file_summary.errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )
