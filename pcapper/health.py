from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import math

from .pcap_cache import get_reader
from .utils import detect_file_type, safe_float
from .certificates import analyze_certificates

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


@dataclass(frozen=True)
class HealthSummary:
    path: Path
    total_packets: int
    total_bytes: int
    tcp_packets: int
    udp_packets: int
    retransmissions: int
    retransmission_rate: float
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]
    endpoint_packets: Counter[str]
    endpoint_bytes: Counter[str]
    flow_duration_buckets: dict[str, Counter[str]]
    tcp_syn: int
    tcp_syn_ack: int
    tcp_rst: int
    tcp_zero_window: int
    tcp_small_window: int
    tcp_syn_sources: Counter[str]
    tcp_rst_sources: Counter[str]
    tcp_zero_window_sources: Counter[str]
    udp_amp_candidates: list[str]
    ot_timing: dict[str, list[dict[str, object]]]
    ttl_expired: int
    ttl_low: int
    dscp_counts: Counter[int]
    ecn_counts: Counter[int]
    snmp_packets: int
    snmp_versions: Counter[str]
    snmp_communities: Counter[str]
    expired_certs: int
    self_signed_certs: int
    findings: list[dict[str, object]]
    errors: list[str]


def merge_health_summaries(summaries: list[HealthSummary] | tuple[HealthSummary, ...] | set[HealthSummary]) -> HealthSummary:
    summary_list = list(summaries)
    if not summary_list:
        return HealthSummary(
            path=Path("ALL_PCAPS_0"),
            total_packets=0,
            total_bytes=0,
            tcp_packets=0,
            udp_packets=0,
            retransmissions=0,
            retransmission_rate=0.0,
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
            endpoint_packets=Counter(),
            endpoint_bytes=Counter(),
            flow_duration_buckets={"all": Counter(), "tcp": Counter(), "udp": Counter()},
            tcp_syn=0,
            tcp_syn_ack=0,
            tcp_rst=0,
            tcp_zero_window=0,
            tcp_small_window=0,
            tcp_syn_sources=Counter(),
            tcp_rst_sources=Counter(),
            tcp_zero_window_sources=Counter(),
            udp_amp_candidates=[],
            ot_timing={"profinet_rt": [], "enip_io": [], "s7_rosctr": []},
            ttl_expired=0,
            ttl_low=0,
            dscp_counts=Counter(),
            ecn_counts=Counter(),
            snmp_packets=0,
            snmp_versions=Counter(),
            snmp_communities=Counter(),
            expired_certs=0,
            self_signed_certs=0,
            findings=[],
            errors=[],
        )

    total_packets = 0
    total_bytes = 0
    tcp_packets = 0
    udp_packets = 0
    retransmissions = 0
    tcp_syn = 0
    tcp_syn_ack = 0
    tcp_rst = 0
    tcp_zero_window = 0
    tcp_small_window = 0
    ttl_expired = 0
    ttl_low = 0
    snmp_packets = 0
    expired_certs = 0
    self_signed_certs = 0

    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    endpoint_packets: Counter[str] = Counter()
    endpoint_bytes: Counter[str] = Counter()
    flow_duration_buckets: dict[str, Counter[str]] = {
        "all": Counter(),
        "tcp": Counter(),
        "udp": Counter(),
    }
    tcp_syn_sources: Counter[str] = Counter()
    tcp_rst_sources: Counter[str] = Counter()
    tcp_zero_window_sources: Counter[str] = Counter()
    dscp_counts: Counter[int] = Counter()
    ecn_counts: Counter[int] = Counter()
    snmp_versions: Counter[str] = Counter()
    snmp_communities: Counter[str] = Counter()

    udp_amp_candidates: list[str] = []
    ot_timing: dict[str, list[dict[str, object]]] = {
        "profinet_rt": [],
        "enip_io": [],
        "s7_rosctr": [],
    }
    errors: list[str] = []

    for summary in summary_list:
        total_packets += summary.total_packets
        total_bytes += summary.total_bytes
        tcp_packets += summary.tcp_packets
        udp_packets += summary.udp_packets
        retransmissions += summary.retransmissions
        tcp_syn += summary.tcp_syn
        tcp_syn_ack += summary.tcp_syn_ack
        tcp_rst += summary.tcp_rst
        tcp_zero_window += summary.tcp_zero_window
        tcp_small_window += summary.tcp_small_window
        ttl_expired += summary.ttl_expired
        ttl_low += summary.ttl_low
        snmp_packets += summary.snmp_packets
        expired_certs += summary.expired_certs
        self_signed_certs += summary.self_signed_certs

        if summary.first_seen is not None:
            first_seen = summary.first_seen if first_seen is None else min(first_seen, summary.first_seen)
        if summary.last_seen is not None:
            last_seen = summary.last_seen if last_seen is None else max(last_seen, summary.last_seen)

        endpoint_packets.update(summary.endpoint_packets)
        endpoint_bytes.update(summary.endpoint_bytes)

        for key in ("all", "tcp", "udp"):
            flow_duration_buckets.setdefault(key, Counter()).update(summary.flow_duration_buckets.get(key, Counter()))

        tcp_syn_sources.update(summary.tcp_syn_sources)
        tcp_rst_sources.update(summary.tcp_rst_sources)
        tcp_zero_window_sources.update(summary.tcp_zero_window_sources)
        dscp_counts.update(summary.dscp_counts)
        ecn_counts.update(summary.ecn_counts)
        snmp_versions.update(summary.snmp_versions)
        snmp_communities.update(summary.snmp_communities)

        udp_amp_candidates.extend(summary.udp_amp_candidates)
        for key in ("profinet_rt", "enip_io", "s7_rosctr"):
            ot_timing[key].extend(summary.ot_timing.get(key, []))
        errors.extend(summary.errors)

    if udp_amp_candidates:
        seen_amp: set[str] = set()
        unique_amp: list[str] = []
        for item in udp_amp_candidates:
            if item in seen_amp:
                continue
            seen_amp.add(item)
            unique_amp.append(item)
        udp_amp_candidates = unique_amp

    retransmission_rate = (retransmissions / tcp_packets) if tcp_packets else 0.0
    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    findings: list[dict[str, object]] = []
    if retransmissions > 50 and retransmission_rate > 0.01:
        findings.append({
            "severity": "warning",
            "summary": "Elevated TCP retransmissions",
            "details": f"{retransmissions} retransmissions ({retransmission_rate:.2%} of TCP packets).",
        })
    if tcp_syn:
        syn_only = tcp_syn - tcp_syn_ack
        if syn_only > 50:
            findings.append({
                "severity": "warning",
                "summary": "High SYN without SYN-ACK",
                "details": f"SYN-only count: {syn_only}.",
            })
        rst_ratio = tcp_rst / max(tcp_syn, 1)
        if tcp_rst > 50 and rst_ratio >= 0.2:
            findings.append({
                "severity": "warning",
                "summary": "High TCP RST/SYN ratio",
                "details": f"RST {tcp_rst} vs SYN {tcp_syn} ({rst_ratio:.2%}).",
            })
    if tcp_zero_window > 20:
        findings.append({
            "severity": "warning",
            "summary": "TCP zero-window events",
            "details": f"{tcp_zero_window} packets with zero window observed.",
        })
    if udp_amp_candidates:
        findings.append({
            "severity": "warning",
            "summary": "Potential UDP amplification patterns",
            "details": ", ".join(udp_amp_candidates[:3]),
        })
    if ttl_expired:
        findings.append({
            "severity": "warning",
            "summary": "Expired TTL/Hop Limit observed",
            "details": f"{ttl_expired} packets with TTL/Hop Limit <= 1.",
        })
    if ttl_low and ttl_low > ttl_expired:
        findings.append({
            "severity": "info",
            "summary": "Low TTL/Hop Limit values",
            "details": f"{ttl_low} packets with TTL/Hop Limit <= 5.",
        })
    if expired_certs:
        findings.append({
            "severity": "warning",
            "summary": "Expired certificates detected",
            "details": f"{expired_certs} expired or invalid certificate(s).",
        })
    if snmp_packets:
        findings.append({
            "severity": "warning",
            "summary": "SNMP traffic observed",
            "details": f"{snmp_packets} SNMP packets detected; review community strings and access controls.",
        })
        if any(comm.lower() in {"public", "private"} for comm in snmp_communities):
            findings.append({
                "severity": "critical",
                "summary": "Default SNMP community strings detected",
                "details": "SNMP community strings include 'public' or 'private'.",
            })

    return HealthSummary(
        path=Path("ALL_PCAPS"),
        total_packets=total_packets,
        total_bytes=total_bytes,
        tcp_packets=tcp_packets,
        udp_packets=udp_packets,
        retransmissions=retransmissions,
        retransmission_rate=retransmission_rate,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
        endpoint_packets=endpoint_packets,
        endpoint_bytes=endpoint_bytes,
        flow_duration_buckets=flow_duration_buckets,
        tcp_syn=tcp_syn,
        tcp_syn_ack=tcp_syn_ack,
        tcp_rst=tcp_rst,
        tcp_zero_window=tcp_zero_window,
        tcp_small_window=tcp_small_window,
        tcp_syn_sources=tcp_syn_sources,
        tcp_rst_sources=tcp_rst_sources,
        tcp_zero_window_sources=tcp_zero_window_sources,
        udp_amp_candidates=udp_amp_candidates,
        ot_timing=ot_timing,
        ttl_expired=ttl_expired,
        ttl_low=ttl_low,
        dscp_counts=dscp_counts,
        ecn_counts=ecn_counts,
        snmp_packets=snmp_packets,
        snmp_versions=snmp_versions,
        snmp_communities=snmp_communities,
        expired_certs=expired_certs,
        self_signed_certs=self_signed_certs,
        findings=findings,
        errors=errors,
    )


AMPLIFICATION_PORTS = {19, 53, 123, 161, 389, 1900, 5353, 11211}
FLOW_BUCKETS = [
    (0.0, 1.0, "<=1s"),
    (1.0, 10.0, "1-10s"),
    (10.0, 60.0, "10-60s"),
    (60.0, 300.0, "1-5m"),
    (300.0, 1800.0, "5-30m"),
    (1800.0, float("inf"), ">30m"),
]


def _bucketize_duration(duration: float) -> str:
    for low, high, label in FLOW_BUCKETS:
        if low <= duration <= high:
            return label
    return ">30m"


def _extract_s7_rosctr(payload: bytes) -> Optional[str]:
    if not payload:
        return None
    try:
        idx = payload.index(0x32)
    except ValueError:
        return None
    if idx + 1 >= len(payload):
        return None
    rosctr = payload[idx + 1]
    rosctr_map = {1: "Job", 2: "Ack", 3: "AckData", 7: "UserData"}
    return rosctr_map.get(rosctr, f"ROSCTR {rosctr}")


def _timing_stats(intervals: dict[str, list[float]], limit: int = 5) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for key, samples in intervals.items():
        if len(samples) < 6:
            continue
        avg = sum(samples) / len(samples)
        if avg <= 0:
            continue
        variance = sum((val - avg) ** 2 for val in samples) / len(samples)
        std_dev = math.sqrt(variance)
        rows.append({
            "session": key,
            "count": len(samples),
            "avg": avg,
            "min": min(samples),
            "max": max(samples),
            "std": std_dev,
            "cv": (std_dev / avg) if avg > 0 else 0.0,
        })
    rows.sort(key=lambda item: (item["cv"], item["avg"]))
    return rows[:limit]


def _read_ber_length(payload: bytes, offset: int) -> tuple[Optional[int], int]:
    if offset >= len(payload):
        return None, offset
    first = payload[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    num_bytes = first & 0x7F
    if num_bytes == 0 or offset + num_bytes > len(payload):
        return None, offset
    length = int.from_bytes(payload[offset:offset + num_bytes], "big")
    offset += num_bytes
    return length, offset


def _parse_snmp(payload: bytes) -> tuple[Optional[str], Optional[str]]:
    if not payload or payload[0] != 0x30:
        return None, None
    length, idx = _read_ber_length(payload, 1)
    if length is None or idx >= len(payload):
        return None, None
    if idx >= len(payload) or payload[idx] != 0x02:
        return None, None
    ver_len, idx = _read_ber_length(payload, idx + 1)
    if ver_len is None or idx + ver_len > len(payload):
        return None, None
    version_val = int.from_bytes(payload[idx:idx + ver_len], "big")
    idx += ver_len
    if idx >= len(payload) or payload[idx] != 0x04:
        return None, None
    comm_len, idx = _read_ber_length(payload, idx + 1)
    if comm_len is None or idx + comm_len > len(payload):
        return None, None
    community = payload[idx:idx + comm_len].decode("latin-1", errors="ignore")

    version_map = {0: "v1", 1: "v2c", 3: "v3"}
    return version_map.get(version_val, f"v{version_val}"), community


def analyze_health(path: Path, show_status: bool = True) -> HealthSummary:
    errors: list[str] = []

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, show_status=show_status
    )

    total_packets = 0
    total_bytes = 0
    tcp_packets = 0
    udp_packets = 0
    retransmissions = 0
    first_seen = None
    last_seen = None
    endpoint_packets: Counter[str] = Counter()
    endpoint_bytes: Counter[str] = Counter()
    tcp_syn = 0
    tcp_syn_ack = 0
    tcp_rst = 0
    tcp_zero_window = 0
    tcp_small_window = 0
    tcp_syn_sources: Counter[str] = Counter()
    tcp_rst_sources: Counter[str] = Counter()
    tcp_zero_window_sources: Counter[str] = Counter()
    ttl_expired = 0
    ttl_low = 0
    dscp_counts: Counter[int] = Counter()
    ecn_counts: Counter[int] = Counter()
    snmp_packets = 0
    snmp_versions: Counter[str] = Counter()
    snmp_communities: Counter[str] = Counter()
    tcp_flows: dict[tuple[str, str, int, int], dict[str, Optional[float]]] = defaultdict(lambda: {
        "first": None,
        "last": None,
    })
    udp_flows: dict[tuple[str, str, int, int], dict[str, Optional[float]]] = defaultdict(lambda: {
        "first": None,
        "last": None,
    })
    amp_flows: dict[tuple[str, str, int], dict[str, int]] = defaultdict(lambda: {"client": 0, "server": 0})
    profinet_last_ts: dict[str, float] = {}
    profinet_intervals: dict[str, list[float]] = defaultdict(list)
    enip_io_last_ts: dict[str, float] = {}
    enip_io_intervals: dict[str, list[float]] = defaultdict(list)
    s7_last_ts: dict[str, float] = {}
    s7_intervals: dict[str, list[float]] = defaultdict(list)

    seen_seq: dict[tuple[str, str, int, int], set[tuple[int, int]]] = defaultdict(set)

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
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            src_ip = None
            dst_ip = None
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                ip_layer = pkt[IP]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))
                ttl_val = int(getattr(ip_layer, "ttl", 0) or 0)
                if ttl_val <= 1:
                    ttl_expired += 1
                if ttl_val and ttl_val <= 5:
                    ttl_low += 1
                tos = int(getattr(ip_layer, "tos", 0) or 0)
                dscp_counts[(tos >> 2) & 0x3F] += 1
                ecn_counts[tos & 0x03] += 1
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                ip_layer = pkt[IPv6]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))
                hlim = int(getattr(ip_layer, "hlim", 0) or 0)
                if hlim <= 1:
                    ttl_expired += 1
                if hlim and hlim <= 5:
                    ttl_low += 1
                tc = int(getattr(ip_layer, "tc", 0) or 0)
                dscp_counts[(tc >> 2) & 0x3F] += 1
                ecn_counts[tc & 0x03] += 1

            if src_ip:
                endpoint_packets[src_ip] += 1
                endpoint_bytes[src_ip] += pkt_len
            if dst_ip:
                endpoint_packets[dst_ip] += 1
                endpoint_bytes[dst_ip] += pkt_len

            if Ether is not None and pkt.haslayer(Ether):  # type: ignore[truthy-bool]
                try:
                    eth_layer = pkt[Ether]  # type: ignore[index]
                    etype = int(getattr(eth_layer, "type", 0) or 0)
                    if etype == 0x8892:
                        src_mac = str(getattr(eth_layer, "src", "?"))
                        dst_mac = str(getattr(eth_layer, "dst", "?"))
                        pn_key = f"{src_mac} -> {dst_mac}"
                        if ts is not None:
                            last_ts = profinet_last_ts.get(pn_key)
                            if last_ts is not None:
                                interval = ts - last_ts
                                if interval >= 0:
                                    profinet_intervals[pn_key].append(interval)
                            profinet_last_ts[pn_key] = ts
                except Exception:
                    pass

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp_packets += 1
                tcp_layer = pkt[TCP]  # type: ignore[index]
                if src_ip and dst_ip:
                    try:
                        seq = int(getattr(tcp_layer, "seq", 0) or 0)
                        sport = int(getattr(tcp_layer, "sport", 0) or 0)
                        dport = int(getattr(tcp_layer, "dport", 0) or 0)
                        flags = int(getattr(tcp_layer, "flags", 0) or 0)
                        window = int(getattr(tcp_layer, "window", 0) or 0)
                        payload_len = 0
                        if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                            payload_len = len(bytes(pkt[Raw]))  # type: ignore[index]
                        else:
                            try:
                                payload_len = len(bytes(tcp_layer.payload))
                            except Exception:
                                payload_len = 0
                        key = (src_ip, dst_ip, sport, dport)
                        sig = (seq, payload_len)
                        if sig in seen_seq[key]:
                            retransmissions += 1
                        else:
                            seen_seq[key].add(sig)
                        if len(seen_seq[key]) > 20000:
                            seen_seq[key].clear()
                        flow = tcp_flows[key]
                        if ts is not None:
                            if flow["first"] is None or ts < float(flow["first"] or ts):
                                flow["first"] = ts
                            if flow["last"] is None or ts > float(flow["last"] or ts):
                                flow["last"] = ts
                        if flags & 0x02:
                            tcp_syn += 1
                            tcp_syn_sources[src_ip] += 1
                        if flags & 0x12 == 0x12:
                            tcp_syn_ack += 1
                        if flags & 0x04:
                            tcp_rst += 1
                            tcp_rst_sources[src_ip] += 1
                        if window == 0:
                            tcp_zero_window += 1
                            tcp_zero_window_sources[src_ip] += 1
                        elif window < 1024:
                            tcp_small_window += 1

                        if sport == 102 or dport == 102:
                            s7_payload = b""
                            if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                                s7_payload = bytes(pkt[Raw])  # type: ignore[index]
                            else:
                                try:
                                    s7_payload = bytes(tcp_layer.payload)
                                except Exception:
                                    s7_payload = b""
                            rosctr = _extract_s7_rosctr(s7_payload) or "ROSCTR ?"
                            s7_key = f"{src_ip}:{sport} -> {dst_ip}:{dport} ({rosctr})"
                            if ts is not None:
                                last_ts = s7_last_ts.get(s7_key)
                                if last_ts is not None:
                                    interval = ts - last_ts
                                    if interval >= 0:
                                        s7_intervals[s7_key].append(interval)
                                s7_last_ts[s7_key] = ts
                    except Exception:
                        pass

            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp_packets += 1
                udp_layer = pkt[UDP]  # type: ignore[index]
                sport = int(getattr(udp_layer, "sport", 0) or 0)
                dport = int(getattr(udp_layer, "dport", 0) or 0)
                if src_ip and dst_ip:
                    flow = udp_flows[(src_ip, dst_ip, sport, dport)]
                    if ts is not None:
                        if flow["first"] is None or ts < float(flow["first"] or ts):
                            flow["first"] = ts
                        if flow["last"] is None or ts > float(flow["last"] or ts):
                            flow["last"] = ts
                if dport in AMPLIFICATION_PORTS or sport in AMPLIFICATION_PORTS:
                    payload_len = 0
                    if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                        payload_len = len(bytes(pkt[Raw]))  # type: ignore[index]
                    else:
                        try:
                            payload_len = len(bytes(udp_layer.payload))
                        except Exception:
                            payload_len = 0
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

                if (sport == 2222 or dport == 2222) and src_ip and dst_ip:
                    enip_key = f"{src_ip}:{sport} -> {dst_ip}:{dport}"
                    if ts is not None:
                        last_ts = enip_io_last_ts.get(enip_key)
                        if last_ts is not None:
                            interval = ts - last_ts
                            if interval >= 0:
                                enip_io_intervals[enip_key].append(interval)
                        enip_io_last_ts[enip_key] = ts
                if sport in (161, 162) or dport in (161, 162):
                    snmp_packets += 1
                    payload = None
                    if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                        payload = bytes(pkt[Raw])  # type: ignore[index]
                    else:
                        try:
                            payload = bytes(udp_layer.payload)
                        except Exception:
                            payload = None
                    if payload:
                        version, community = _parse_snmp(payload)
                        if version:
                            snmp_versions[version] += 1
                        if community:
                            snmp_communities[community] += 1
    finally:
        status.finish()
        reader.close()

    retransmission_rate = (retransmissions / tcp_packets) if tcp_packets else 0.0

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    flow_duration_buckets: dict[str, Counter[str]] = {
        "all": Counter(),
        "tcp": Counter(),
        "udp": Counter(),
    }
    for flow_map, label in ((tcp_flows, "tcp"), (udp_flows, "udp")):
        for info in flow_map.values():
            start = info.get("first")
            end = info.get("last")
            if start is None or end is None:
                continue
            duration = max(0.0, float(end) - float(start))
            bucket = _bucketize_duration(duration)
            flow_duration_buckets[label][bucket] += 1
            flow_duration_buckets["all"][bucket] += 1

    udp_amp_candidates = []
    for (client, server, port), volumes in amp_flows.items():
        client_bytes = volumes.get("client", 0)
        server_bytes = volumes.get("server", 0)
        if server_bytes >= 10000 and (client_bytes == 0 or server_bytes / max(client_bytes, 1) >= 5):
            udp_amp_candidates.append(f"{client} -> {server}:{port} ({server_bytes}/{client_bytes} bytes)")

    ot_timing = {
        "profinet_rt": _timing_stats(profinet_intervals),
        "enip_io": _timing_stats(enip_io_intervals),
        "s7_rosctr": _timing_stats(s7_intervals),
    }

    expired_certs = 0
    self_signed_certs = 0
    try:
        cert_summary = analyze_certificates(path, show_status=False)
        expired_certs = len(cert_summary.expired)
        self_signed_certs = len(cert_summary.self_signed)
        errors.extend(cert_summary.errors)
    except Exception as exc:
        errors.append(str(exc))

    findings: list[dict[str, object]] = []
    if retransmissions > 50 and retransmission_rate > 0.01:
        findings.append({
            "severity": "warning",
            "summary": "Elevated TCP retransmissions",
            "details": f"{retransmissions} retransmissions ({retransmission_rate:.2%} of TCP packets).",
        })
    if tcp_syn:
        syn_only = tcp_syn - tcp_syn_ack
        if syn_only > 50:
            findings.append({
                "severity": "warning",
                "summary": "High SYN without SYN-ACK",
                "details": f"SYN-only count: {syn_only}.",
            })
        rst_ratio = tcp_rst / max(tcp_syn, 1)
        if tcp_rst > 50 and rst_ratio >= 0.2:
            findings.append({
                "severity": "warning",
                "summary": "High TCP RST/SYN ratio",
                "details": f"RST {tcp_rst} vs SYN {tcp_syn} ({rst_ratio:.2%}).",
            })
    if tcp_zero_window > 20:
        findings.append({
            "severity": "warning",
            "summary": "TCP zero-window events",
            "details": f"{tcp_zero_window} packets with zero window observed.",
        })
    if udp_amp_candidates:
        findings.append({
            "severity": "warning",
            "summary": "Potential UDP amplification patterns",
            "details": ", ".join(udp_amp_candidates[:3]),
        })
    if ttl_expired:
        findings.append({
            "severity": "warning",
            "summary": "Expired TTL/Hop Limit observed",
            "details": f"{ttl_expired} packets with TTL/Hop Limit <= 1.",
        })
    if ttl_low and ttl_low > ttl_expired:
        findings.append({
            "severity": "info",
            "summary": "Low TTL/Hop Limit values",
            "details": f"{ttl_low} packets with TTL/Hop Limit <= 5.",
        })
    if expired_certs:
        findings.append({
            "severity": "warning",
            "summary": "Expired certificates detected",
            "details": f"{expired_certs} expired or invalid certificate(s).",
        })
    if snmp_packets:
        findings.append({
            "severity": "warning",
            "summary": "SNMP traffic observed",
            "details": f"{snmp_packets} SNMP packets detected; review community strings and access controls.",
        })
        if any(comm.lower() in {"public", "private"} for comm in snmp_communities):
            findings.append({
                "severity": "critical",
                "summary": "Default SNMP community strings detected",
                "details": "SNMP community strings include 'public' or 'private'.",
            })

    return HealthSummary(
        path=path,
        total_packets=total_packets,
        total_bytes=total_bytes,
        tcp_packets=tcp_packets,
        udp_packets=udp_packets,
        retransmissions=retransmissions,
        retransmission_rate=retransmission_rate,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
        endpoint_packets=endpoint_packets,
        endpoint_bytes=endpoint_bytes,
        flow_duration_buckets=flow_duration_buckets,
        tcp_syn=tcp_syn,
        tcp_syn_ack=tcp_syn_ack,
        tcp_rst=tcp_rst,
        tcp_zero_window=tcp_zero_window,
        tcp_small_window=tcp_small_window,
        tcp_syn_sources=tcp_syn_sources,
        tcp_rst_sources=tcp_rst_sources,
        tcp_zero_window_sources=tcp_zero_window_sources,
        udp_amp_candidates=udp_amp_candidates,
        ot_timing=ot_timing,
        ttl_expired=ttl_expired,
        ttl_low=ttl_low,
        dscp_counts=dscp_counts,
        ecn_counts=ecn_counts,
        snmp_packets=snmp_packets,
        snmp_versions=snmp_versions,
        snmp_communities=snmp_communities,
        expired_certs=expired_certs,
        self_signed_certs=self_signed_certs,
        findings=findings,
        errors=errors,
    )
