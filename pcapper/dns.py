from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import math

from scapy.utils import PcapReader, PcapNgReader

from .progress import build_statusbar
from .utils import safe_float, detect_file_type

try:
    from scapy.layers.dns import DNS, DNSQR, DNSRR  # type: ignore
    from scapy.layers.inet import IP, UDP, TCP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    DNS = None  # type: ignore
    DNSQR = None  # type: ignore
    DNSRR = None  # type: ignore
    IP = None  # type: ignore
    UDP = None  # type: ignore
    TCP = None  # type: ignore
    IPv6 = None  # type: ignore


@dataclass(frozen=True)
class DnsSummary:
    path: Path
    total_packets: int
    total_bytes: int
    query_packets: int
    response_packets: int
    udp_packets: int
    tcp_packets: int
    mdns_packets: int
    mdns_query_packets: int
    mdns_response_packets: int
    mdns_error_responses: int
    mdns_qname_counts: Counter[str]
    mdns_service_counts: Counter[str]
    mdns_client_counts: Counter[str]
    mdns_server_counts: Counter[str]
    unique_mdns_clients: int
    unique_mdns_servers: int
    packet_length_stats: list[dict[str, object]]
    multicast_streams: list[dict[str, object]]
    type_counts: Counter[str]
    rcode_counts: Counter[str]
    qname_counts: Counter[str]
    client_counts: Counter[str]
    server_counts: Counter[str]
    unique_clients: int
    unique_servers: int
    unique_qnames: int
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]
    detections: list[dict[str, str | list[tuple[str, int]] | int]]
    errors: list[str]


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


def _base_domain(name: str) -> str:
    parts = [part for part in name.strip(".").split(".") if part]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return name.strip(".")


def analyze_dns(path: Path, show_status: bool = True) -> DnsSummary:
    errors: list[str] = []
    if DNS is None:
        errors.append("Scapy DNS layers unavailable; install scapy for DNS analysis.")
        return DnsSummary(
            path=path,
            total_packets=0,
            total_bytes=0,
            query_packets=0,
            response_packets=0,
            udp_packets=0,
            tcp_packets=0,
            mdns_packets=0,
            mdns_query_packets=0,
            mdns_response_packets=0,
            mdns_error_responses=0,
            mdns_qname_counts=Counter(),
            mdns_service_counts=Counter(),
            mdns_client_counts=Counter(),
            mdns_server_counts=Counter(),
            unique_mdns_clients=0,
            unique_mdns_servers=0,
            packet_length_stats=[],
            multicast_streams=[],
            type_counts=Counter(),
            rcode_counts=Counter(),
            qname_counts=Counter(),
            client_counts=Counter(),
            server_counts=Counter(),
            unique_clients=0,
            unique_servers=0,
            unique_qnames=0,
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
            detections=[],
            errors=errors,
        )

    file_type = detect_file_type(path)
    reader = PcapNgReader(str(path)) if file_type == "pcapng" else PcapReader(str(path))

    size_bytes = 0
    try:
        size_bytes = path.stat().st_size
    except Exception:
        pass
        
    status = build_statusbar(path, enabled=show_status)
    stream = None
    for attr in ("fd", "f", "fh", "_fh", "_file", "file"):
        candidate = getattr(reader, attr, None)
        if candidate is not None:
            stream = candidate
            break

    total_packets = 0
    total_bytes = 0
    query_packets = 0
    response_packets = 0
    udp_packets = 0
    tcp_packets = 0
    mdns_packets = 0
    mdns_query_packets = 0
    mdns_response_packets = 0
    mdns_error_responses = 0
    mdns_unicast_packets = 0
    udp_multicast_packets = 0
    multicast_streams: dict[tuple[str, str, int], dict[str, object]] = defaultdict(lambda: {
        "count": 0,
        "bytes": 0,
        "sources": Counter(),
        "first_seen": None,
        "last_seen": None,
    })
    mdns_qname_counts: Counter[str] = Counter()
    mdns_service_counts: Counter[str] = Counter()
    mdns_client_counts: Counter[str] = Counter()
    mdns_server_counts: Counter[str] = Counter()

    type_counts: Counter[str] = Counter()
    rcode_counts: Counter[str] = Counter()
    qname_counts: Counter[str] = Counter()
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    qtype_counts: Counter[int] = Counter()
    mdns_qtype_counts: Counter[int] = Counter()

    qname_entropy: Counter[str] = Counter()
    qname_lengths: Counter[str] = Counter()
    base_domain_counts: Counter[str] = Counter()
    answers_by_qname: dict[str, set[str]] = defaultdict(set)
    base_domain_answers: dict[str, set[str]] = defaultdict(set)
    zone_transfer_requests: set[str] = set()
    txt_query_names: set[str] = set()

    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    packet_len_buckets = [
        (0, 100, "0-100"),
        (101, 300, "101-300"),
        (301, 600, "301-600"),
        (601, 1200, "601-1200"),
        (1201, 2000, "1201-2000"),
        (2001, 65535, "2001+"),
    ]
    bucket_counts: dict[str, int] = defaultdict(int)
    bucket_sizes: dict[str, list[int]] = defaultdict(list)
    bucket_times: dict[str, list[float]] = defaultdict(list)

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            if not pkt.haslayer(DNS):  # type: ignore[truthy-bool]
                continue

            total_packets += 1
            pkt_len = int(len(pkt)) if hasattr(pkt, "__len__") else 0
            total_bytes += pkt_len
            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                for low, high, label in packet_len_buckets:
                    if low <= pkt_len <= high:
                        bucket_counts[label] += 1
                        bucket_sizes[label].append(pkt_len)
                        bucket_times[label].append(ts)
                        break

            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp_packets += 1
            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp_packets += 1

            dns_layer = pkt[DNS]  # type: ignore[index]
            if getattr(dns_layer, "qr", 0) == 0:
                query_packets += 1
            else:
                response_packets += 1

            rcode = getattr(dns_layer, "rcode", None)
            if rcode is not None:
                rcode_counts[str(rcode)] += 1

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

            is_mdns = False
            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp_layer = pkt[UDP]  # type: ignore[index]
                sport = int(getattr(udp_layer, "sport", 0) or 0)
                dport = int(getattr(udp_layer, "dport", 0) or 0)
                if sport == 5353 or dport == 5353:
                    is_mdns = True
            if dst_ip in ("224.0.0.251", "ff02::fb"):
                is_mdns = True

            if src_ip and dst_ip:
                if getattr(dns_layer, "qr", 0) == 0:
                    client_counts[src_ip] += 1
                    server_counts[dst_ip] += 1
                else:
                    client_counts[dst_ip] += 1
                    server_counts[src_ip] += 1

                if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                    if dst_ip.startswith("224.") or dst_ip.startswith("ff02::"):
                        udp_multicast_packets += 1
                        udp_layer = pkt[UDP]  # type: ignore[index]
                        dport = int(getattr(udp_layer, "dport", 0) or 0)
                        key = (dst_ip, "UDP", dport)
                        stream = multicast_streams[key]
                        stream["count"] = int(stream["count"]) + 1
                        stream["bytes"] = int(stream["bytes"]) + pkt_len
                        stream["sources"][src_ip] += 1  # type: ignore[index]
                        if ts is not None:
                            if stream["first_seen"] is None or ts < stream["first_seen"]:  # type: ignore[operator]
                                stream["first_seen"] = ts
                            if stream["last_seen"] is None or ts > stream["last_seen"]:  # type: ignore[operator]
                                stream["last_seen"] = ts

                if is_mdns:
                    mdns_packets += 1
                    if dst_ip not in ("224.0.0.251", "ff02::fb"):
                        mdns_unicast_packets += 1
                    if getattr(dns_layer, "qr", 0) == 0:
                        mdns_query_packets += 1
                        mdns_client_counts[src_ip] += 1
                        mdns_server_counts[dst_ip] += 1
                    else:
                        mdns_response_packets += 1
                        mdns_client_counts[dst_ip] += 1
                        mdns_server_counts[src_ip] += 1
                        if rcode is not None and int(rcode) != 0:
                            mdns_error_responses += 1

            qd = getattr(dns_layer, "qd", None)
            qdcount = int(getattr(dns_layer, "qdcount", 0) or 0)
            if qd is not None and qdcount > 0 and getattr(qd, "qname", None):
                raw_name = qd.qname
                try:
                    name = raw_name.decode(errors="ignore")
                except Exception:
                    name = str(raw_name)
                name = name.strip(".")
                if name:
                    qname_counts[name] += 1
                    base_domain_counts[_base_domain(name)] += 1
                    qname_entropy[name] = int(_shannon_entropy(name) * 100)
                    qname_lengths[name] = len(name)
                    if is_mdns:
                        mdns_qname_counts[name] += 1
                qtype = getattr(qd, "qtype", None)
                if qtype is not None:
                    qtype_counts[int(qtype)] += 1
                    type_counts[str(qtype)] += 1
                    if is_mdns:
                        mdns_qtype_counts[int(qtype)] += 1
                    if int(qtype) in {251, 252}:
                        zone_transfer_requests.add(name)
                    if int(qtype) == 16:
                        txt_query_names.add(name)
                    if is_mdns and int(qtype) == 33 and name:
                        mdns_service_counts[name] += 1

            if getattr(dns_layer, "qr", 0) == 1:
                an_records = getattr(dns_layer, "an", None)
                if an_records is not None:
                    try:
                        # Iterate directly over parsed records instead of using header count
                        for rr in an_records:
                            rrtype = getattr(rr, "type", None)
                            rrname = getattr(rr, "rrname", None)
                            rdata = getattr(rr, "rdata", None)
                            if rrname is not None and rdata is not None:
                                try:
                                    rrname_str = rrname.decode(errors="ignore").strip(".")
                                except Exception:
                                    rrname_str = str(rrname).strip(".")
                                answers_by_qname[rrname_str].add(str(rdata))
                                if rrtype in {1, 28}:  # A or AAAA
                                    base_domain_answers[_base_domain(rrname_str)].add(str(rdata))
                                if is_mdns:
                                    if rrtype == 33:
                                        mdns_service_counts[rrname_str] += 1
                                    if rrtype == 12:
                                        try:
                                            service_name = str(rdata).strip(".")
                                        except Exception:
                                            service_name = str(rdata)
                                        if service_name and ("_tcp" in service_name or "_udp" in service_name):
                                            mdns_service_counts[service_name] += 1
                    except Exception:
                        pass

            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts
    finally:
        status.finish()
        reader.close()

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    packet_length_stats: list[dict[str, object]] = []
    for low, high, label in packet_len_buckets:
        count = bucket_counts.get(label, 0)
        if count == 0:
            continue
        sizes = bucket_sizes.get(label, [])
        avg_size = sum(sizes) / len(sizes) if sizes else 0.0
        min_size = min(sizes) if sizes else 0
        max_size = max(sizes) if sizes else 0
        pct = (count / total_packets) * 100 if total_packets else 0.0
        rate = (count / duration_seconds) if duration_seconds and duration_seconds > 0 else 0.0

        burst_rate = 0.0
        burst_start = None
        times = sorted(bucket_times.get(label, []))
        if times:
            left = 0
            for right in range(len(times)):
                while times[right] - times[left] > 1.0:
                    left += 1
                window_count = right - left + 1
                if window_count > burst_rate:
                    burst_rate = float(window_count)
                    burst_start = times[left]

        packet_length_stats.append({
            "bucket": label,
            "count": count,
            "avg": avg_size,
            "min": min_size,
            "max": max_size,
            "rate": rate,
            "pct": pct,
            "burst_rate": burst_rate,
            "burst_start": burst_start,
        })

    detections: list[dict[str, str | list[tuple[str, int]] | int]] = []
    if total_packets == 0:
        detections.append({
            "type": "no_dns",
            "severity": "info",
            "summary": "No DNS traffic detected",
            "details": "DNS not observed in capture.",
        })
    else:
        if duration_seconds and duration_seconds > 0:
            pps = total_packets / duration_seconds
            if pps > 2000:
                detections.append({
                    "type": "dns_flood",
                    "severity": "warning",
                    "summary": f"High DNS rate observed ({pps:.1f} pkt/s)",
                    "details": "Excessive DNS traffic may indicate abuse or misconfiguration.",
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                })

        nxdomain = rcode_counts.get("3", 0)
        if nxdomain > 100 and total_packets > 0 and (nxdomain / total_packets) > 0.3:
            detections.append({
                "type": "dns_nxdomain",
                "severity": "warning",
                "summary": f"High NXDOMAIN rate ({nxdomain} responses)",
                "details": "Potential DGA, misconfiguration, or scanning.",
                "top_clients": client_counts.most_common(3),
                "top_servers": server_counts.most_common(3),
            })

        suspicious_qnames = [
            name for name, count in qname_counts.items()
            if qname_lengths.get(name, 0) > 50 or (qname_entropy.get(name, 0) / 100) > 4.0
        ]
        if len(suspicious_qnames) > 30:
            detections.append({
                "type": "dns_tunnel_indicator",
                "severity": "warning",
                "summary": "Potential DNS tunneling behavior",
                "details": "Many long/high-entropy query names detected.",
                "top_clients": client_counts.most_common(3),
                "top_servers": server_counts.most_common(3),
            })

        for base, count in base_domain_counts.items():
            if count > 1000:
                detections.append({
                    "type": "dns_domain_concentration",
                    "severity": "info",
                    "summary": f"High query volume for {base} ({count} queries)",
                    "details": "Check for beaconing or resolver issues.",
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                })
                break

        for qname, answers in answers_by_qname.items():
            if len(answers) >= 6:
                detections.append({
                    "type": "dns_poisoning_indicator",
                    "severity": "warning",
                    "summary": f"Multiple answers observed for {qname}",
                    "details": f"Observed {len(answers)} distinct answers; verify expected CDN/rotation.",
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                })
                break

        for base, answers in base_domain_answers.items():
            if len(answers) >= 10:
                detections.append({
                    "type": "dns_fast_flux",
                    "severity": "warning",
                    "summary": f"Fast-flux indicator for {base}",
                    "details": f"Observed {len(answers)} unique A/AAAA answers.",
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                })
                break

        if zone_transfer_requests:
            sample = ", ".join(sorted(list(zone_transfer_requests))[:5])
            detections.append({
                "type": "dns_zone_transfer",
                "severity": "warning",
                "summary": "Zone transfer attempt detected",
                "details": f"AXFR/IXFR requested for: {sample}",
                "top_clients": client_counts.most_common(3),
                "top_servers": server_counts.most_common(3),
            })

        txt_queries = qtype_counts.get(16, 0)
        if txt_queries > 100 and total_packets > 0 and (txt_queries / total_packets) > 0.2:
            detections.append({
                "type": "dns_txt_exfil",
                "severity": "warning",
                "summary": f"High TXT query volume ({txt_queries} queries)",
                "details": "TXT-heavy traffic can indicate data exfiltration or policy misuse.",
                "top_clients": client_counts.most_common(3),
                "top_servers": server_counts.most_common(3),
            })

        if mdns_packets > 0:
            detections.append({
                "type": "mdns_present",
                "severity": "info",
                "summary": f"mDNS traffic observed ({mdns_packets} packets)",
                "details": "mDNS/Bonjour discovery seen; verify expected endpoints and services.",
                "top_clients": mdns_client_counts.most_common(3),
                "top_servers": mdns_server_counts.most_common(3),
            })

            if mdns_packets > 1000:
                detections.append({
                    "type": "mdns_chatty",
                    "severity": "warning",
                    "summary": "High mDNS volume",
                    "details": f"Observed {mdns_packets} mDNS packets; potential chatter or misconfiguration.",
                    "top_clients": mdns_client_counts.most_common(3),
                })

            for name, count in mdns_qname_counts.items():
                if name.endswith(".local") and count > 200:
                    detections.append({
                        "type": "mdns_burst",
                        "severity": "warning",
                        "summary": f"High mDNS query volume for {name}",
                        "details": "Investigate for discovery storms or spoofing.",
                        "top_clients": mdns_client_counts.most_common(3),
                    })
                    break

            if mdns_unicast_packets > 0:
                detections.append({
                    "type": "mdns_unicast",
                    "severity": "warning",
                    "summary": "Unicast mDNS traffic detected",
                    "details": f"Observed {mdns_unicast_packets} mDNS packets sent via unicast; review for abuse or misconfiguration.",
                    "top_clients": mdns_client_counts.most_common(3),
                    "top_servers": mdns_server_counts.most_common(3),
                })

            if udp_multicast_packets > 0:
                detections.append({
                    "type": "udp_multicast_streams",
                    "severity": "warning",
                    "summary": "UDP multicast streams detected",
                    "details": f"Observed {udp_multicast_packets} UDP multicast DNS packets; review for discovery abuse.",
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                })

            allowed_types = {1, 28, 12, 16, 33}
            unusual_mdns = [(t, c) for t, c in mdns_qtype_counts.items() if t not in allowed_types]
            if unusual_mdns:
                top_unusual = ", ".join(f"{t}({c})" for t, c in sorted(unusual_mdns, key=lambda x: x[1], reverse=True)[:5])
                detections.append({
                    "type": "mdns_unusual_qtypes",
                    "severity": "warning",
                    "summary": "Unusual mDNS query record types detected",
                    "details": f"Observed uncommon mDNS qtypes: {top_unusual}",
                    "top_clients": mdns_client_counts.most_common(3),
                })

            mdns_txt_queries = mdns_qtype_counts.get(16, 0)
            if mdns_txt_queries > 0:
                detections.append({
                    "type": "mdns_txt_records",
                    "severity": "warning",
                    "summary": "mDNS TXT Record Analysis",
                    "details": f"Observed {mdns_txt_queries} mDNS TXT queries; review for metadata leakage or abuse.",
                    "top_clients": mdns_client_counts.most_common(3),
                    "top_servers": mdns_server_counts.most_common(3),
                })

    return DnsSummary(
        path=path,
        total_packets=total_packets,
        total_bytes=total_bytes,
        query_packets=query_packets,
        response_packets=response_packets,
        udp_packets=udp_packets,
        tcp_packets=tcp_packets,
        mdns_packets=mdns_packets,
        mdns_query_packets=mdns_query_packets,
        mdns_response_packets=mdns_response_packets,
        mdns_error_responses=mdns_error_responses,
        mdns_qname_counts=mdns_qname_counts,
        mdns_service_counts=mdns_service_counts,
        mdns_client_counts=mdns_client_counts,
        mdns_server_counts=mdns_server_counts,
        unique_mdns_clients=len(mdns_client_counts),
        unique_mdns_servers=len(mdns_server_counts),
        packet_length_stats=packet_length_stats,
        multicast_streams=[
            {
                "group": group,
                "protocol": proto,
                "port": port,
                "count": data.get("count", 0),
                "bytes": data.get("bytes", 0),
                "sources": data.get("sources", Counter()).most_common(5),
                "first_seen": data.get("first_seen"),
                "last_seen": data.get("last_seen"),
            }
            for (group, proto, port), data in multicast_streams.items()
        ],
        type_counts=type_counts,
        rcode_counts=rcode_counts,
        qname_counts=qname_counts,
        client_counts=client_counts,
        server_counts=server_counts,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        unique_qnames=len(qname_counts),
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
        detections=detections,
        errors=errors,
    )
