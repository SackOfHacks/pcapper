from __future__ import annotations

import hashlib
import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .dns import analyze_dns
from .http import analyze_http
from .pcap_cache import get_reader
from .services import COMMON_PORTS
from .utils import safe_float

try:
    from scapy.layers.inet import ICMP, IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.layers.l2 import Ether  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore
    ICMP = None  # type: ignore
    Ether = None  # type: ignore


OT_PORTS = {
    102,
    502,
    9600,
    20000,
    2404,
    47808,
    44818,
    2222,
    34962,
    34963,
    34964,
    4840,
    1911,
    4911,
    5094,
    18245,
    18246,
    20547,
    1962,
    5006,
    5007,
    5683,
    5684,
    2455,
    1217,
    34378,
    34379,
    34380,
}

MGMT_PORTS = {
    22,
    23,
    135,
    139,
    445,
    3389,
    5900,
    5938,
    5985,
    5986,
}

TUNNEL_PORTS = {53, 123, 443, 784, 853, 1194, 1701, 1723, 4500, 500, 51820}

MAX_BEACON_PACKET_SAMPLES = 10

L2_ETHERTYPE_NAMES: dict[int, str] = {
    0x0806: "L2:ARP",
    0x88A4: "L2:EtherCAT",
    0x8892: "L2:PROFINET-RT",
    0x88B8: "L2:GOOSE",
    0x88BA: "L2:SV",
    0x88CC: "L2:LLDP",
    0x88F7: "L2:PTP",
}


@dataclass(frozen=True)
class BeaconCandidate:
    src_ip: str
    dst_ip: str
    proto: str
    src_port: Optional[int]
    dst_port: Optional[int]
    count: int
    avg_bytes: float
    interval_range: float
    size_range: int
    top_interval: int
    top_size: int
    mean_interval: float
    std_interval: float
    jitter: float
    median_interval: float
    mad_interval: float
    median_bytes: float
    mad_bytes: float
    duration_seconds: float
    periodicity_score: float
    size_score: float
    duration_score: float
    count_score: float
    score: float
    first_seen: Optional[float]
    last_seen: Optional[float]
    timeline: list[int]
    packet_samples: list[int]


@dataclass(frozen=True)
class BeaconSummary:
    path: Path
    total_packets: int
    candidate_count: int
    candidates: list[BeaconCandidate]
    http_post_beacons: list[dict[str, object]]
    protocol_beacon_checks: dict[str, list[str]]
    deterministic_checks: dict[str, list[str]] = field(default_factory=dict)
    threat_hypotheses: list[dict[str, object]] = field(default_factory=list)
    hunting_pivots: list[dict[str, object]] = field(default_factory=list)
    benign_context: list[str] = field(default_factory=list)
    risk_matrix: list[dict[str, str]] = field(default_factory=list)
    deterministic_category_checks: dict[str, list[str]] = field(default_factory=dict)
    campaign_summaries: list[dict[str, object]] = field(default_factory=list)
    host_rollups: list[dict[str, object]] = field(default_factory=list)
    beacon_pivots: list[dict[str, object]] = field(default_factory=list)
    explainability: list[str] = field(default_factory=list)
    detections: list[dict[str, object]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _flow_key(pkt) -> Optional[tuple[str, str, str, Optional[int], Optional[int]]]:
    src_ip = None
    dst_ip = None
    if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
        ip = pkt[IP]  # type: ignore[index]
        src_ip = str(getattr(ip, "src", ""))
        dst_ip = str(getattr(ip, "dst", ""))
    elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
        ip = pkt[IPv6]  # type: ignore[index]
        src_ip = str(getattr(ip, "src", ""))
        dst_ip = str(getattr(ip, "dst", ""))
    elif Ether is not None and pkt.haslayer(Ether):  # type: ignore[truthy-bool]
        eth = pkt[Ether]  # type: ignore[index]
        src_ip = str(getattr(eth, "src", ""))
        dst_ip = str(getattr(eth, "dst", ""))

    if not src_ip or not dst_ip:
        return None

    if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
        layer = pkt[TCP]  # type: ignore[index]
        return (
            src_ip,
            dst_ip,
            "TCP",
            int(getattr(layer, "sport", 0)),
            int(getattr(layer, "dport", 0)),
        )
    if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
        layer = pkt[UDP]  # type: ignore[index]
        return (
            src_ip,
            dst_ip,
            "UDP",
            int(getattr(layer, "sport", 0)),
            int(getattr(layer, "dport", 0)),
        )
    if ICMP is not None and pkt.haslayer(ICMP):  # type: ignore[truthy-bool]
        return (src_ip, dst_ip, "ICMP", None, None)

    if Ether is not None and pkt.haslayer(Ether):  # type: ignore[truthy-bool]
        try:
            ethertype = int(getattr(pkt[Ether], "type", 0))  # type: ignore[index]
        except Exception:
            ethertype = 0
        label = L2_ETHERTYPE_NAMES.get(
            ethertype, f"L2:0x{ethertype:04x}" if ethertype else "L2"
        )
        return (src_ip, dst_ip, label, None, None)

    return (src_ip, dst_ip, "IP", None, None)


def _flow_key_bidirectional(
    pkt,
) -> Optional[tuple[str, str, str, Optional[int], Optional[int]]]:
    key = _flow_key(pkt)
    if not key:
        return None
    src_ip, dst_ip, proto, sport, dport = key
    a, b = sorted([src_ip, dst_ip])
    ports = [p for p in (sport, dport) if p is not None]
    min_port = min(ports) if ports else None
    max_port = max(ports) if ports else None
    return (a, b, proto, min_port, max_port)


def _normalize_pair(src_ip: str, dst_ip: str) -> tuple[str, str]:
    try:
        src_addr = ipaddress.ip_address(src_ip)
        dst_addr = ipaddress.ip_address(dst_ip)
        if src_addr.is_private and dst_addr.is_global:
            return src_ip, dst_ip
        if dst_addr.is_private and src_addr.is_global:
            return dst_ip, src_ip
    except Exception:
        pass
    if src_ip <= dst_ip:
        return src_ip, dst_ip
    return dst_ip, src_ip


def _compute_stats(timestamps: list[float]) -> tuple[float, float, float]:
    if len(timestamps) < 2:
        return 0.0, 0.0, 0.0
    deltas = [b - a for a, b in zip(timestamps, timestamps[1:]) if b >= a]
    if not deltas:
        return 0.0, 0.0, 0.0
    mean = sum(deltas) / len(deltas)
    variance = sum((d - mean) ** 2 for d in deltas) / len(deltas)
    std = variance**0.5
    jitter = std / mean if mean > 0 else 0.0
    return mean, std, jitter


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    vals = sorted(values)
    mid = len(vals) // 2
    if len(vals) % 2 == 0:
        return (vals[mid - 1] + vals[mid]) / 2
    return vals[mid]


def _mad(values: list[float], center: float) -> float:
    if not values:
        return 0.0
    deviations = [abs(v - center) for v in values]
    return _median(deviations)


def _timeline(timestamps: list[float], bins: int = 32) -> list[int]:
    if len(timestamps) < 2:
        return [0] * bins
    start = timestamps[0]
    end = timestamps[-1]
    if end <= start:
        return [0] * bins
    span = end - start
    bucket = span / bins
    counts = [0] * bins
    for ts in timestamps:
        idx = int(min(bins - 1, (ts - start) / bucket))
        counts[idx] += 1
    return counts


def _cadence_family(mean_interval: float) -> str:
    if mean_interval <= 0:
        return "unknown"
    if mean_interval < 15:
        return "very_fast"
    if mean_interval < 60:
        return "fast"
    if mean_interval < 300:
        return "medium"
    if mean_interval < 1800:
        return "slow"
    return "very_slow"


def _burst_sleep_score(timeline: list[int]) -> float:
    if not timeline:
        return 0.0
    active = sum(1 for value in timeline if value > 0)
    idle = len(timeline) - active
    peak = max(timeline) if timeline else 0
    avg = (sum(timeline) / len(timeline)) if timeline else 0.0
    if avg <= 0:
        return 0.0
    burstiness = min(1.0, peak / max(avg, 1e-9) / 4.0)
    sleepiness = min(1.0, idle / len(timeline))
    return (0.6 * burstiness) + (0.4 * sleepiness)


def analyze_beacons(
    path: Path, show_status: bool = True, min_events: int = 20
) -> BeaconSummary:
    errors: list[str] = []
    if IP is None and IPv6 is None and Ether is None:
        errors.append("Scapy layers unavailable; install scapy for beacon analysis.")
        return BeaconSummary(
            path=path,
            total_packets=0,
            candidate_count=0,
            candidates=[],
            http_post_beacons=[],
            protocol_beacon_checks={"dns": [], "http_https": [], "icmp": [], "ntp": []},
            detections=[],
            errors=errors,
        )

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, show_status=show_status
    )

    session_conn_times: dict[tuple[str, str, str, Optional[int]], list[float]] = (
        defaultdict(list)
    )
    session_conn_sizes: dict[tuple[str, str, str, Optional[int]], list[int]] = (
        defaultdict(list)
    )
    session_conn_packets: dict[tuple[str, str, str, Optional[int]], list[int]] = (
        defaultdict(list)
    )
    udp_session_times: dict[tuple[str, str, str, Optional[int]], list[float]] = (
        defaultdict(list)
    )
    udp_session_sizes: dict[tuple[str, str, str, Optional[int]], list[int]] = (
        defaultdict(list)
    )
    udp_session_packets: dict[tuple[str, str, str, Optional[int]], list[int]] = (
        defaultdict(list)
    )
    icmp_session_times: dict[tuple[str, str, str, Optional[int]], list[float]] = (
        defaultdict(list)
    )
    icmp_session_sizes: dict[tuple[str, str, str, Optional[int]], list[int]] = (
        defaultdict(list)
    )
    icmp_session_packets: dict[tuple[str, str, str, Optional[int]], list[int]] = (
        defaultdict(list)
    )
    l2_session_times: dict[tuple[str, str, str, Optional[int]], list[float]] = (
        defaultdict(list)
    )
    l2_session_sizes: dict[tuple[str, str, str, Optional[int]], list[int]] = (
        defaultdict(list)
    )
    l2_session_packets: dict[tuple[str, str, str, Optional[int]], list[int]] = (
        defaultdict(list)
    )
    conn_first_ts: dict[tuple[str, str, str, Optional[int], Optional[int]], float] = {}
    conn_syn_ts: dict[tuple[str, str, str, Optional[int], Optional[int]], float] = {}
    conn_first_idx: dict[tuple[str, str, str, Optional[int], Optional[int]], int] = {}
    conn_syn_idx: dict[tuple[str, str, str, Optional[int], Optional[int]], int] = {}
    conn_bytes: dict[tuple[str, str, str, Optional[int], Optional[int]], int] = (
        defaultdict(int)
    )
    total_packets = 0

    try:
        for pkt_index, pkt in enumerate(reader, start=1):
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            total_packets += 1
            ts = safe_float(getattr(pkt, "time", None))
            if ts is None:
                continue
            pkt_len = int(len(pkt)) if hasattr(pkt, "__len__") else 0

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp_layer = pkt[TCP]  # type: ignore[index]
                flags = getattr(tcp_layer, "flags", None)
                is_syn = False
                if isinstance(flags, str):
                    is_syn = "S" in flags and "A" not in flags
                elif isinstance(flags, int):
                    is_syn = (flags & 0x02) != 0 and (flags & 0x10) == 0
                key = _flow_key(pkt)
                if not key:
                    continue
                src_ip, dst_ip, proto, sport, dport = key
                ports = [p for p in (sport, dport) if p is not None]
                if not ports:
                    continue
                server_port = min(ports)
                client_port = max(ports)
                client_ip, server_ip = _normalize_pair(src_ip, dst_ip)
                session_key = (client_ip, server_ip, proto, server_port)
                conn_key = (client_ip, server_ip, proto, server_port, client_port)

                if conn_key not in conn_first_ts:
                    conn_first_ts[conn_key] = ts
                    conn_first_idx[conn_key] = pkt_index
                conn_bytes[conn_key] += pkt_len
                if is_syn:
                    conn_syn_ts[conn_key] = ts
                    conn_syn_idx[conn_key] = pkt_index
            elif UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                key = _flow_key(pkt)
                if not key:
                    continue
                src_ip, dst_ip, proto, sport, dport = key
                ports = [p for p in (sport, dport) if p is not None]
                if not ports:
                    continue
                server_port = min(ports)
                client_ip, server_ip = _normalize_pair(src_ip, dst_ip)
                session_key = (client_ip, server_ip, proto, server_port)
                udp_session_times[session_key].append(ts)
                udp_session_sizes[session_key].append(pkt_len)
                if len(udp_session_packets[session_key]) < MAX_BEACON_PACKET_SAMPLES:
                    udp_session_packets[session_key].append(pkt_index)
            elif ICMP is not None and pkt.haslayer(ICMP):  # type: ignore[truthy-bool]
                key = _flow_key(pkt)
                if not key:
                    continue
                src_ip, dst_ip, _proto, _sport, _dport = key
                client_ip, server_ip = _normalize_pair(src_ip, dst_ip)
                session_key = (client_ip, server_ip, "ICMP", None)
                icmp_session_times[session_key].append(ts)
                icmp_session_sizes[session_key].append(pkt_len)
                if len(icmp_session_packets[session_key]) < MAX_BEACON_PACKET_SAMPLES:
                    icmp_session_packets[session_key].append(pkt_index)
            else:
                key = _flow_key(pkt)
                if not key:
                    continue
                src_ip, dst_ip, proto, _sport, _dport = key
                if not proto.startswith("L2:"):
                    continue
                client_ip, server_ip = _normalize_pair(src_ip, dst_ip)
                session_key = (client_ip, server_ip, proto, None)
                l2_session_times[session_key].append(ts)
                l2_session_sizes[session_key].append(pkt_len)
                if len(l2_session_packets[session_key]) < MAX_BEACON_PACKET_SAMPLES:
                    l2_session_packets[session_key].append(pkt_index)
    finally:
        status.finish()
        reader.close()

    candidates: list[BeaconCandidate] = []

    for conn_key, first_ts in conn_first_ts.items():
        client_ip, server_ip, proto, server_port, _client_port = conn_key
        session_key = (client_ip, server_ip, proto, server_port)
        ts = conn_syn_ts.get(conn_key, first_ts)
        session_conn_times[session_key].append(ts)
        session_conn_sizes[session_key].append(conn_bytes.get(conn_key, 0))
        pkt_idx = conn_syn_idx.get(conn_key, conn_first_idx.get(conn_key))
        if (
            pkt_idx is not None
            and len(session_conn_packets[session_key]) < MAX_BEACON_PACKET_SAMPLES
        ):
            session_conn_packets[session_key].append(pkt_idx)

    combined_flows: list[
        tuple[
            tuple[str, str, str, Optional[int], Optional[int]],
            list[float],
            list[int],
            list[int],
        ]
    ] = []
    for (client, server, proto, server_port), times in session_conn_times.items():
        sizes = session_conn_sizes.get((client, server, proto, server_port), [])
        packets = session_conn_packets.get((client, server, proto, server_port), [])
        combined_flows.append(
            ((client, server, proto, server_port, None), times, sizes, packets)
        )
    for (client, server, proto, server_port), times in udp_session_times.items():
        sizes = udp_session_sizes.get((client, server, proto, server_port), [])
        packets = udp_session_packets.get((client, server, proto, server_port), [])
        combined_flows.append(
            ((client, server, proto, server_port, None), times, sizes, packets)
        )
    for (client, server, proto, server_port), times in icmp_session_times.items():
        sizes = icmp_session_sizes.get((client, server, proto, server_port), [])
        packets = icmp_session_packets.get((client, server, proto, server_port), [])
        combined_flows.append(
            ((client, server, proto, server_port, None), times, sizes, packets)
        )
    for (client, server, proto, server_port), times in l2_session_times.items():
        sizes = l2_session_sizes.get((client, server, proto, server_port), [])
        packets = l2_session_packets.get((client, server, proto, server_port), [])
        combined_flows.append(
            ((client, server, proto, server_port, None), times, sizes, packets)
        )
    seen_keys: set[tuple[str, str, str, Optional[int], Optional[int]]] = set()

    benign_service_ports = {
        53,
        123,
        137,
        138,
        139,
        135,
        389,
        445,
        464,
        3268,
        3269,
        593,
        88,
    }

    def _is_public(ip_text: str) -> bool:
        try:
            return ipaddress.ip_address(ip_text).is_global
        except Exception:
            return False

    def _is_private(ip_text: str) -> bool:
        try:
            return ipaddress.ip_address(ip_text).is_private
        except Exception:
            return False

    for (src_ip, dst_ip, proto, sport, dport), times, sizes, packets in combined_flows:
        key_id = (src_ip, dst_ip, proto, sport, dport)
        if key_id in seen_keys:
            continue
        seen_keys.add(key_id)
        times_sorted = sorted(times)
        long_duration = (
            (times_sorted[-1] - times_sorted[0]) if len(times_sorted) >= 2 else 0.0
        )
        if len(times_sorted) < min_events and long_duration < 1800:
            continue
        mean, std, jitter = _compute_stats(times_sorted)
        if mean <= 0:
            continue
        deltas = [b - a for a, b in zip(times_sorted, times_sorted[1:]) if b >= a]
        interval_range = (max(deltas) - min(deltas)) if deltas else 0.0
        median_interval = _median(deltas)
        mad_interval = _mad(deltas, median_interval)

        avg_bytes = (sum(sizes) / len(sizes)) if sizes else 0.0
        size_range = (max(sizes) - min(sizes)) if sizes else 0
        median_bytes = _median([float(val) for val in sizes]) if sizes else 0.0
        mad_bytes = _mad([float(val) for val in sizes], median_bytes) if sizes else 0.0
        top_interval = 0
        if deltas:
            interval_counts = Counter(int(round(delta)) for delta in deltas)
            top_interval = interval_counts.most_common(1)[0][0]
        top_size = 0
        if sizes:
            top_size = Counter(sizes).most_common(1)[0][0]

        duration_seconds = long_duration
        periodicity_score = 0.0
        if median_interval > 0:
            periodicity_score = max(0.0, 1.0 - min(1.0, mad_interval / median_interval))
        size_score = 0.0
        if median_bytes > 0:
            size_score = max(0.0, 1.0 - min(1.0, mad_bytes / median_bytes))
        duration_score = (
            min(1.0, duration_seconds / 3600.0) if duration_seconds > 0 else 0.0
        )
        count_score = min(1.0, len(times_sorted) / 50.0)
        score = (
            (0.5 * periodicity_score)
            + (0.2 * size_score)
            + (0.2 * duration_score)
            + (0.1 * count_score)
        )

        port_value = sport or dport
        is_l2_flow = proto.startswith("L2:")
        has_public = _is_public(src_ip) or _is_public(dst_ip)
        is_internal = _is_private(src_ip) and _is_private(dst_ip)
        is_ot_port = port_value in OT_PORTS
        is_mgmt_port = port_value in MGMT_PORTS

        if mean < 1.0 or mean > 86400.0:
            continue
        if score < 0.35 and len(times_sorted) < (min_events * 2):
            continue
        if proto == "UDP" and (
            len(times_sorted) < max(min_events, 15) or periodicity_score < 0.6
        ):
            continue
        if not is_l2_flow:
            if port_value in benign_service_ports:
                if has_public:
                    if score < 0.8 and periodicity_score < 0.8:
                        continue
                else:
                    if score < 0.9 and periodicity_score < 0.85:
                        continue
            if not has_public:
                if not is_internal:
                    continue
                if not (
                    is_ot_port
                    or is_mgmt_port
                    or score >= 0.85
                    or periodicity_score >= 0.9
                ):
                    continue
        else:
            # L2 beaconing has no routable IP context; rely on cadence/shape quality.
            if score < 0.45 and periodicity_score < 0.65:
                continue

        packet_samples: list[int] = []
        if packets:
            paired = sorted(zip(times, packets), key=lambda item: item[0])
            packet_samples = [
                pkt_id for _ts, pkt_id in paired[:MAX_BEACON_PACKET_SAMPLES]
            ]

        candidates.append(
            BeaconCandidate(
                src_ip=src_ip,
                dst_ip=dst_ip,
                proto=proto,
                src_port=sport,
                dst_port=dport,
                count=len(times_sorted),
                avg_bytes=avg_bytes,
                interval_range=interval_range,
                size_range=size_range,
                top_interval=top_interval,
                top_size=top_size,
                mean_interval=mean,
                std_interval=std,
                jitter=jitter,
                median_interval=median_interval,
                mad_interval=mad_interval,
                median_bytes=median_bytes,
                mad_bytes=mad_bytes,
                duration_seconds=duration_seconds,
                periodicity_score=periodicity_score,
                size_score=size_score,
                duration_score=duration_score,
                count_score=count_score,
                score=score,
                first_seen=times_sorted[0],
                last_seen=times_sorted[-1],
                timeline=_timeline(times_sorted),
                packet_samples=packet_samples,
            )
        )

    candidates.sort(key=lambda item: (item.score, item.count), reverse=True)

    def _format_duration(seconds: float) -> str:
        if seconds <= 0:
            return "0s"
        if seconds >= 3600:
            return f"{seconds / 3600:.2f}h"
        if seconds >= 60:
            return f"{seconds / 60:.2f}m"
        return f"{seconds:.1f}s"

    http_flow_score: dict[tuple[str, str], float] = {}
    http_flow_interval: dict[tuple[str, str], float] = {}
    for item in candidates:
        port_value = item.src_port or item.dst_port
        if port_value not in {80, 443, 8080, 8443}:
            continue
        key = (item.src_ip, item.dst_ip)
        prev_score = float(http_flow_score.get(key, 0.0))
        if item.score > prev_score:
            http_flow_score[key] = item.score
            http_flow_interval[key] = item.mean_interval

    def _discover_http_post_beacons(
        post_payloads: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        aggregates: dict[tuple[str, str, str], dict[str, object]] = {}
        suspicious_content_markers = (
            "octet-stream",
            "application/zip",
            "application/gzip",
            "x-zip",
            "application/x-7z",
            "application/x-rar",
            "multipart/form-data",
        )
        for item in post_payloads:
            src = str(item.get("src", "-"))
            dst = str(item.get("dst", "-"))
            host = str(item.get("host", "-"))
            uri = str(item.get("uri", "-"))
            sample = str(item.get("sample", "") or "").strip()
            try:
                size = int(item.get("bytes", 0) or 0)
            except Exception:
                size = 0
            packet_id = item.get("packet")
            agg_key = (src, dst, host)
            agg = aggregates.setdefault(
                agg_key,
                {
                    "src": src,
                    "dst": dst,
                    "host": host,
                    "bytes": 0,
                    "requests": 0,
                    "sizes": [],
                    "uris": set(),
                    "content_types": set(),
                    "packets": set(),
                    "samples": [],
                },
            )
            agg["bytes"] = int(agg.get("bytes", 0)) + max(size, 0)
            agg["requests"] = int(agg.get("requests", 0)) + 1
            sizes = agg.get("sizes")
            if isinstance(sizes, list):
                sizes.append(size)
            uris = agg.get("uris")
            if isinstance(uris, set):
                uris.add(uri)
            ctype = str(item.get("content_type", "-"))
            if ctype and ctype != "-":
                cts = agg.get("content_types")
                if isinstance(cts, set):
                    cts.add(ctype)
            packets = agg.get("packets")
            if isinstance(packets, set) and isinstance(packet_id, int):
                packets.add(packet_id)
            samples = agg.get("samples")
            if isinstance(samples, list) and sample and len(samples) < 3:
                samples.append(sample[:120])

        suspects: list[dict[str, object]] = []
        for (_src, _dst, _host), agg in aggregates.items():
            reqs = int(agg.get("requests", 0) or 0)
            total_bytes = int(agg.get("bytes", 0) or 0)
            sizes = (
                [float(v) for v in agg.get("sizes", [])]
                if isinstance(agg.get("sizes"), list)
                else []
            )
            median_size = _median(sizes)
            mad_size = _mad(sizes, median_size)
            size_stability = 1.0
            if median_size > 0:
                size_stability = max(0.0, 1.0 - min(1.0, mad_size / median_size))

            src = str(agg.get("src", "-"))
            dst = str(agg.get("dst", "-"))
            pair = (src, dst)
            linked_beacon_score = float(http_flow_score.get(pair, 0.0))
            linked_beacon_interval = float(http_flow_interval.get(pair, 0.0))

            risk_score = 0
            risk_reasons: list[str] = []
            if reqs >= 8:
                risk_score += 1
                risk_reasons.append(f"requests={reqs}")
            if total_bytes >= 200_000:
                risk_score += 1
                risk_reasons.append(f"post_volume={total_bytes}")
            if size_stability >= 0.88 and reqs >= 10:
                risk_score += 1
                risk_reasons.append(f"stable_sizes={size_stability:.2f}")
            content_types = sorted(str(v) for v in agg.get("content_types", set()))
            if any(
                any(marker in ctype.lower() for marker in suspicious_content_markers)
                for ctype in content_types
            ):
                risk_score += 1
                risk_reasons.append("suspicious_content_type")
            if linked_beacon_score >= 0.75:
                risk_score += 2
                risk_reasons.append(
                    f"linked_periodic_http_score={linked_beacon_score:.2f}"
                )
            elif linked_beacon_score >= 0.60:
                risk_score += 1
                risk_reasons.append(
                    f"linked_periodic_http_score={linked_beacon_score:.2f}"
                )

            if risk_score >= 2:
                packet_examples = sorted(
                    int(v) for v in (agg.get("packets") or set()) if isinstance(v, int)
                )
                sample_values = [
                    str(v) for v in (agg.get("samples") or []) if str(v).strip()
                ]
                suspects.append(
                    {
                        "src": src,
                        "dst": dst,
                        "host": str(agg.get("host", "-")),
                        "uri": ", ".join(
                            sorted(str(v) for v in agg.get("uris", set()))[:3]
                        ),
                        "bytes": total_bytes,
                        "requests": reqs,
                        "median_size": median_size,
                        "mad_size": mad_size,
                        "size_stability": size_stability,
                        "content_type": ", ".join(content_types[:3])
                        if content_types
                        else "-",
                        "linked_beacon_score": linked_beacon_score,
                        "linked_beacon_interval": linked_beacon_interval,
                        "risk_score": risk_score,
                        "risk_reasons": risk_reasons,
                        "packet_examples": ",".join(str(v) for v in packet_examples[:5])
                        if packet_examples
                        else "-",
                        "sample": " | ".join(sample_values[:2])
                        if sample_values
                        else "-",
                    }
                )

        suspects.sort(
            key=lambda item: (
                int(item.get("risk_score", 0) or 0),
                int(item.get("requests", 0) or 0),
                int(item.get("bytes", 0) or 0),
                float(item.get("size_stability", 0.0) or 0.0),
            ),
            reverse=True,
        )
        return suspects

    http_summary = analyze_http(path, show_status=False)
    dns_summary = analyze_dns(path, show_status=False)
    http_post_beacons = _discover_http_post_beacons(
        list(getattr(http_summary, "post_payloads", []) or [])
    )

    protocol_beacon_checks: dict[str, list[str]] = {
        "dns": [],
        "http_https": [],
        "icmp": [],
        "ntp": [],
    }
    deterministic_category_checks: dict[str, list[str]] = {
        "single_target_periodic_c2": [],
        "multi_target_synchronized": [],
        "cross_protocol_cadence": [],
        "burst_sleep_pattern": [],
        "low_slow_persistence": [],
        "benign_periodic_likely": [],
    }

    dns_candidates = [c for c in candidates if (c.src_port or c.dst_port) == 53]
    for item in dns_candidates[:8]:
        protocol_beacon_checks["dns"].append(
            f"{item.src_ip}->{item.dst_ip} count={item.count} mean={item.mean_interval:.1f}s score={item.score:.2f}"
        )
    txt_queries = int(getattr(dns_summary, "type_counts", Counter()).get("TXT", 0))
    if getattr(dns_summary, "query_packets", 0) and txt_queries:
        ratio = txt_queries / max(int(getattr(dns_summary, "query_packets", 0)), 1)
        if ratio >= 0.2 and txt_queries >= 20:
            protocol_beacon_checks["dns"].append(
                f"TXT query ratio {ratio * 100:.1f}% ({txt_queries}/{getattr(dns_summary, 'query_packets', 0)})"
            )

    http_candidates = [
        c for c in candidates if (c.src_port or c.dst_port) in {80, 443, 8080, 8443}
    ]
    for item in http_candidates[:8]:
        protocol_beacon_checks["http_https"].append(
            f"{item.src_ip}->{item.dst_ip} {(item.src_port or item.dst_port) or '-'} count={item.count} mean={item.mean_interval:.1f}s score={item.score:.2f}"
        )
    for item in http_post_beacons[:8]:
        risk_score = int(item.get("risk_score", 0) or 0)
        reasons = item.get("risk_reasons", [])
        reason_text = (
            ",".join(str(v) for v in reasons[:2])
            if isinstance(reasons, list) and reasons
            else "-"
        )
        protocol_beacon_checks["http_https"].append(
            f"POST {item.get('src')}->{item.get('dst')} host={item.get('host')} requests={item.get('requests')} bytes={int(item.get('bytes', 0) or 0)} stability={float(item.get('size_stability', 0.0) or 0.0):.2f} linked_score={float(item.get('linked_beacon_score', 0.0) or 0.0):.2f} risk={risk_score} why={reason_text}"
        )

    icmp_candidates = [c for c in candidates if c.proto == "ICMP"]
    for item in icmp_candidates[:8]:
        protocol_beacon_checks["icmp"].append(
            f"{item.src_ip}->{item.dst_ip} count={item.count} mean={item.mean_interval:.1f}s score={item.score:.2f}"
        )

    ntp_candidates = [
        c
        for c in candidates
        if c.proto == "UDP" and (c.src_port == 123 or c.dst_port == 123)
    ]
    for item in ntp_candidates[:8]:
        protocol_beacon_checks["ntp"].append(
            f"{item.src_ip}->{item.dst_ip} UDP/123 count={item.count} mean={item.mean_interval:.1f}s score={item.score:.2f}"
        )

    detections: list[dict[str, object]] = []
    campaign_summaries: list[dict[str, object]] = []
    host_rollups: list[dict[str, object]] = []
    beacon_pivots: list[dict[str, object]] = []
    explainability: list[str] = []
    deterministic_checks: dict[str, list[str]] = {
        "external_periodic_beaconing": [],
        "dns_beaconing_or_tunnel_pattern": [],
        "http_post_checkin_pattern": [],
        "management_port_persistence": [],
        "ot_control_periodicity": [],
        "l2_periodic_control_signal": [],
        "high_stability_low_jitter_beacon": [],
    }
    threat_hypotheses: list[dict[str, object]] = []
    hunting_pivots: list[dict[str, object]] = []
    benign_context: list[str] = []
    risk_matrix: list[dict[str, str]] = []
    if candidates:
        severity_rank = {"info": 0, "warning": 1, "high": 2, "critical": 3}

        def _port_label(port_value: Optional[int]) -> str:
            if not port_value:
                return "-"
            svc = COMMON_PORTS.get(port_value)
            if svc:
                return f"{port_value}({svc})"
            return str(port_value)

        def _proto_label(item: BeaconCandidate) -> str:
            port_value = item.src_port or item.dst_port
            port_text = _port_label(port_value)
            if port_text != "-":
                return f"{item.proto}:{port_text}"
            return item.proto

        def _candidate_severity(item: BeaconCandidate) -> str:
            port_value = item.src_port or item.dst_port
            is_external = _is_public(item.src_ip) or _is_public(item.dst_ip)
            is_ot = port_value in OT_PORTS
            if is_external and is_ot and item.score >= 0.75 and item.count >= 15:
                return "critical"
            if (
                item.score >= 0.88
                and item.count >= 30
                and item.duration_seconds >= 3600
                and is_external
            ):
                return "critical"
            if item.score >= 0.80 and item.count >= 20 and is_external:
                return "high"
            if item.score >= 0.72 and item.count >= 15:
                return "warning"
            return "info"

        def _candidate_evidence(item: BeaconCandidate) -> str:
            pkt_text = (
                ",".join(str(pkt) for pkt in item.packet_samples[:5])
                if item.packet_samples
                else "-"
            )
            return (
                f"{item.src_ip}->{item.dst_ip} {_proto_label(item)} count={item.count} "
                f"interval={item.top_interval}s size={item.top_size} pkt={pkt_text}"
            )

        src_counts: Counter[str] = Counter()
        dst_counts: Counter[str] = Counter()
        flow_details: list[str] = []
        flow_evidence: list[str] = []
        peak_severity = "info"
        for item in candidates[:3]:
            duration = 0.0
            if item.first_seen is not None and item.last_seen is not None:
                duration = max(0.0, item.last_seen - item.first_seen)
            proto_label = _proto_label(item)
            flow_details.append(
                f"{item.src_ip}->{item.dst_ip} {proto_label}, {item.count} beacons, mean {item.mean_interval:.2f}s, "
                f"median {item.median_interval:.2f}s, MAD {item.mad_interval:.2f}s, duration {_format_duration(duration)}, "
                f"avg bytes {item.avg_bytes:.0f}, size MAD {item.mad_bytes:.0f}, score {item.score:.2f}"
            )
            flow_evidence.append(_candidate_evidence(item))
            src_counts[item.src_ip] += item.count
            dst_counts[item.dst_ip] += item.count
            candidate_severity = _candidate_severity(item)
            if severity_rank[candidate_severity] > severity_rank[peak_severity]:
                peak_severity = candidate_severity
        detections.append(
            {
                "type": "beaconing",
                "severity": peak_severity,
                "summary": f"{len(candidates)} beacon-like flows detected",
                "details": "Periodic communication patterns may indicate C2 or scheduled tasks. "
                f"Top flows: {'; '.join(flow_details)}",
                "top_sources": src_counts.most_common(5),
                "top_destinations": dst_counts.most_common(5),
                "evidence": flow_evidence,
            }
        )

        src_to_dsts: dict[str, set[str]] = defaultdict(set)
        src_to_events: Counter[str] = Counter()
        for item in candidates:
            if item.score < 0.70:
                continue
            src_to_dsts[item.src_ip].add(item.dst_ip)
            src_to_events[item.src_ip] += item.count
        fanout_rows = [
            (src, len(dsts), src_to_events[src])
            for src, dsts in src_to_dsts.items()
            if len(dsts) >= 3 and src_to_events[src] >= 15
        ]
        if fanout_rows:
            fanout_rows.sort(key=lambda row: (row[1], row[2]), reverse=True)
            detections.append(
                {
                    "type": "beacon_fanout",
                    "severity": "high",
                    "summary": "Source beaconing to multiple destinations",
                    "details": ", ".join(
                        f"{src} -> {dst_count} destinations ({events} events)"
                        for src, dst_count, events in fanout_rows[:5]
                    ),
                    "top_sources": [
                        (src, events) for src, _dst_count, events in fanout_rows[:5]
                    ],
                }
            )
            for src, dst_count, events in fanout_rows[:8]:
                deterministic_category_checks["multi_target_synchronized"].append(
                    f"{src} reached {dst_count} destinations with periodic flows ({events} events)"
                )

        by_src: dict[str, list[BeaconCandidate]] = defaultdict(list)
        for item in candidates:
            if item.score >= 0.65:
                by_src[item.src_ip].append(item)
        synchronized_rows: list[tuple[str, int, float]] = []
        for src, items in by_src.items():
            if len(items) < 2:
                continue
            means = sorted(
                float(item.mean_interval) for item in items if item.mean_interval > 0
            )
            if len(means) < 2:
                continue
            center = _median(means)
            close = [
                value
                for value in means
                if abs(value - center) / max(center, 1.0) <= 0.2
            ]
            if len(close) >= 2:
                synchronized_rows.append((src, len(close), center))
        if synchronized_rows:
            synchronized_rows.sort(key=lambda row: row[1], reverse=True)
            detections.append(
                {
                    "type": "beacon_multi_target_sync",
                    "severity": "high",
                    "summary": "Synchronized multi-destination beacon cadence",
                    "details": "; ".join(
                        f"{src} synchronized flows={count} cadence≈{cadence:.1f}s"
                        for src, count, cadence in synchronized_rows[:5]
                    ),
                }
            )
            for src, count, cadence in synchronized_rows[:8]:
                deterministic_category_checks["multi_target_synchronized"].append(
                    f"{src} synchronized {count} destinations around {cadence:.1f}s"
                )

        by_pair: dict[tuple[str, str], list[BeaconCandidate]] = defaultdict(list)
        for item in candidates:
            by_pair[(item.src_ip, item.dst_ip)].append(item)
        cross_proto_rows: list[tuple[str, str, int, float]] = []
        for (src, dst), items in by_pair.items():
            protos = {item.proto for item in items}
            if len(protos) < 2:
                continue
            means = [
                float(item.mean_interval) for item in items if item.mean_interval > 0
            ]
            if len(means) < 2:
                continue
            center = _median(means)
            spread = _mad(means, center)
            if center > 0 and (spread / center) <= 0.35:
                cross_proto_rows.append((src, dst, len(protos), center))
        if cross_proto_rows:
            cross_proto_rows.sort(key=lambda row: row[2], reverse=True)
            detections.append(
                {
                    "type": "beacon_cross_protocol",
                    "severity": "high",
                    "summary": "Cross-protocol cadence reuse",
                    "details": "; ".join(
                        f"{src}->{dst} protocols={proto_count} cadence≈{cadence:.1f}s"
                        for src, dst, proto_count, cadence in cross_proto_rows[:6]
                    ),
                }
            )
            for src, dst, proto_count, cadence in cross_proto_rows[:10]:
                deterministic_category_checks["cross_protocol_cadence"].append(
                    f"{src}->{dst} reused cadence {cadence:.1f}s across {proto_count} protocols"
                )

        low_and_slow = [
            item
            for item in candidates
            if item.mean_interval >= 300
            and item.periodicity_score >= 0.80
            and item.duration_seconds >= 3600
            and item.count >= 10
        ]
        if low_and_slow:
            detections.append(
                {
                    "type": "beacon_low_slow",
                    "severity": "high",
                    "summary": "Low-and-slow periodic beaconing pattern",
                    "details": "; ".join(
                        f"{item.src_ip}->{item.dst_ip} interval≈{item.mean_interval:.0f}s duration={_format_duration(item.duration_seconds)}"
                        for item in low_and_slow[:5]
                    ),
                    "top_sources": Counter(
                        item.src_ip for item in low_and_slow
                    ).most_common(5),
                    "top_destinations": Counter(
                        item.dst_ip for item in low_and_slow
                    ).most_common(5),
                }
            )
            for item in low_and_slow[:10]:
                deterministic_category_checks["low_slow_persistence"].append(
                    f"{item.src_ip}->{item.dst_ip} interval≈{item.mean_interval:.0f}s duration={_format_duration(item.duration_seconds)}"
                )

        burst_sleep = [
            item
            for item in candidates
            if _burst_sleep_score(item.timeline) >= 0.65
            and item.count >= 12
            and item.duration_seconds >= 900
        ]
        if burst_sleep:
            detections.append(
                {
                    "type": "beacon_burst_sleep",
                    "severity": "warning",
                    "summary": "Burst-then-sleep beacon profile",
                    "details": "; ".join(
                        f"{item.src_ip}->{item.dst_ip} cadence≈{item.mean_interval:.1f}s burst_sleep={_burst_sleep_score(item.timeline):.2f}"
                        for item in burst_sleep[:6]
                    ),
                }
            )
            for item in burst_sleep[:10]:
                deterministic_category_checks["burst_sleep_pattern"].append(
                    f"{item.src_ip}->{item.dst_ip} burst_sleep={_burst_sleep_score(item.timeline):.2f}"
                )

        external_candidates = [
            item
            for item in candidates
            if _is_public(item.src_ip) or _is_public(item.dst_ip)
        ]
        internal_candidates = [
            item
            for item in candidates
            if _is_private(item.src_ip) and _is_private(item.dst_ip)
        ]
        ot_external = [
            item
            for item in external_candidates
            if (item.src_port or item.dst_port) in OT_PORTS
        ]
        ot_internal = [
            item
            for item in internal_candidates
            if (item.src_port or item.dst_port) in OT_PORTS
        ]
        mgmt_internal = [
            item
            for item in internal_candidates
            if (item.src_port or item.dst_port) in MGMT_PORTS
        ]
        tunnel_external = [
            item
            for item in external_candidates
            if (item.src_port or item.dst_port) in TUNNEL_PORTS
            and item.avg_bytes <= 400
        ]
        icmp_candidates = [item for item in candidates if item.proto == "ICMP"]
        uncommon_external = [
            item
            for item in external_candidates
            if (item.src_port or item.dst_port) not in COMMON_PORTS
            and (item.src_port or item.dst_port) is not None
        ]
        l2_candidates = [
            item for item in candidates if str(item.proto).startswith("L2:")
        ]

        for item in external_candidates[:16]:
            deterministic_checks["external_periodic_beaconing"].append(
                f"{item.src_ip}->{item.dst_ip} {(item.src_port or item.dst_port) or '-'} "
                f"count={item.count} interval={item.mean_interval:.1f}s score={item.score:.2f}"
            )
        for item in ot_external[:12]:
            deterministic_checks["ot_control_periodicity"].append(
                f"{item.src_ip}->{item.dst_ip} {(item.src_port or item.dst_port) or '-'} "
                f"interval={item.mean_interval:.1f}s score={item.score:.2f}"
            )
        for item in mgmt_internal[:12]:
            deterministic_checks["management_port_persistence"].append(
                f"{item.src_ip}->{item.dst_ip} {(item.src_port or item.dst_port) or '-'} "
                f"interval={item.mean_interval:.1f}s count={item.count}"
            )
        for item in l2_candidates[:12]:
            deterministic_checks["l2_periodic_control_signal"].append(
                f"{item.src_ip}->{item.dst_ip} {item.proto} interval={item.mean_interval:.1f}s score={item.score:.2f}"
            )
        for item in candidates[:20]:
            if item.score >= 0.82 and item.jitter <= 0.20 and item.count >= 18:
                deterministic_checks["high_stability_low_jitter_beacon"].append(
                    f"{item.src_ip}->{item.dst_ip} score={item.score:.2f} jitter={item.jitter:.2f} interval={item.mean_interval:.1f}s"
                )

        if ot_external:
            detections.append(
                {
                    "type": "beacon_ot_external",
                    "severity": "critical",
                    "summary": "OT/ICS beaconing to public IPs",
                    "details": "; ".join(
                        f"{item.src_ip}->{item.dst_ip} {_proto_label(item)} interval≈{item.mean_interval:.1f}s score={item.score:.2f}"
                        for item in ot_external[:5]
                    ),
                    "top_sources": Counter(
                        item.src_ip for item in ot_external
                    ).most_common(5),
                    "top_destinations": Counter(
                        item.dst_ip for item in ot_external
                    ).most_common(5),
                    "evidence": [_candidate_evidence(item) for item in ot_external[:8]],
                }
            )

        if ot_internal:
            detections.append(
                {
                    "type": "beacon_ot_internal",
                    "severity": "warning",
                    "summary": "OT/ICS periodic control-channel patterns",
                    "details": "; ".join(
                        f"{item.src_ip}->{item.dst_ip} {_proto_label(item)} interval≈{item.mean_interval:.1f}s score={item.score:.2f}"
                        for item in ot_internal[:5]
                    ),
                    "top_sources": Counter(
                        item.src_ip for item in ot_internal
                    ).most_common(5),
                    "top_destinations": Counter(
                        item.dst_ip for item in ot_internal
                    ).most_common(5),
                    "evidence": [_candidate_evidence(item) for item in ot_internal[:8]],
                }
            )

        if mgmt_internal:
            detections.append(
                {
                    "type": "beacon_internal_mgmt",
                    "severity": "warning",
                    "summary": "Internal periodic beacons on management ports",
                    "details": "; ".join(
                        f"{item.src_ip}->{item.dst_ip} {_proto_label(item)} interval≈{item.mean_interval:.1f}s count={item.count}"
                        for item in mgmt_internal[:5]
                    ),
                    "top_sources": Counter(
                        item.src_ip for item in mgmt_internal
                    ).most_common(5),
                    "top_destinations": Counter(
                        item.dst_ip for item in mgmt_internal
                    ).most_common(5),
                    "evidence": [
                        _candidate_evidence(item) for item in mgmt_internal[:8]
                    ],
                }
            )

        if tunnel_external:
            detections.append(
                {
                    "type": "beacon_tunnel_ports",
                    "severity": "warning",
                    "summary": "Periodic beacons over tunnel-friendly ports",
                    "details": "; ".join(
                        f"{item.src_ip}->{item.dst_ip} {_proto_label(item)} interval≈{item.mean_interval:.1f}s avg_bytes≈{item.avg_bytes:.0f}"
                        for item in tunnel_external[:5]
                    ),
                    "top_sources": Counter(
                        item.src_ip for item in tunnel_external
                    ).most_common(5),
                    "top_destinations": Counter(
                        item.dst_ip for item in tunnel_external
                    ).most_common(5),
                    "evidence": [
                        _candidate_evidence(item) for item in tunnel_external[:8]
                    ],
                }
            )

        if icmp_candidates:
            detections.append(
                {
                    "type": "beacon_icmp",
                    "severity": "warning",
                    "summary": "ICMP beacon-like activity",
                    "details": "; ".join(
                        f"{item.src_ip}->{item.dst_ip} interval≈{item.mean_interval:.1f}s count={item.count}"
                        for item in icmp_candidates[:5]
                    ),
                    "top_sources": Counter(
                        item.src_ip for item in icmp_candidates
                    ).most_common(5),
                    "top_destinations": Counter(
                        item.dst_ip for item in icmp_candidates
                    ).most_common(5),
                    "evidence": [
                        _candidate_evidence(item) for item in icmp_candidates[:8]
                    ],
                }
            )

        if uncommon_external:
            detections.append(
                {
                    "type": "beacon_uncommon_port",
                    "severity": "warning",
                    "summary": "Beaconing to public IPs on uncommon ports",
                    "details": "; ".join(
                        f"{item.src_ip}->{item.dst_ip} {_proto_label(item)} interval≈{item.mean_interval:.1f}s"
                        for item in uncommon_external[:5]
                    ),
                    "top_sources": Counter(
                        item.src_ip for item in uncommon_external
                    ).most_common(5),
                    "top_destinations": Counter(
                        item.dst_ip for item in uncommon_external
                    ).most_common(5),
                    "evidence": [
                        _candidate_evidence(item) for item in uncommon_external[:8]
                    ],
                }
            )

        high_frequency = [
            item
            for item in candidates
            if item.mean_interval <= 30
            and item.periodicity_score >= 0.75
            and item.count >= 30
            and item.duration_seconds >= 600
        ]
        if high_frequency:
            detections.append(
                {
                    "type": "beacon_high_frequency",
                    "severity": "warning",
                    "summary": "High-frequency periodic check-in pattern",
                    "details": "; ".join(
                        f"{item.src_ip}->{item.dst_ip} interval≈{item.mean_interval:.1f}s count={item.count}"
                        for item in high_frequency[:5]
                    ),
                    "top_sources": Counter(
                        item.src_ip for item in high_frequency
                    ).most_common(5),
                    "top_destinations": Counter(
                        item.dst_ip for item in high_frequency
                    ).most_common(5),
                }
            )

        for item in candidates[:3]:
            duration = 0.0
            if item.first_seen is not None and item.last_seen is not None:
                duration = max(0.0, item.last_seen - item.first_seen)
            detections.append(
                {
                    "type": "beacon_candidate",
                    "severity": _candidate_severity(item),
                    "summary": f"Beacon candidate {item.src_ip} -> {item.dst_ip}",
                    "details": f"{item.count} events, mean {item.mean_interval:.2f}s, median {item.median_interval:.2f}s, "
                    f"MAD {item.mad_interval:.2f}s, duration {_format_duration(duration)}, avg bytes {item.avg_bytes:.0f}, "
                    f"size MAD {item.mad_bytes:.0f}, periodicity {item.periodicity_score:.2f}, size {item.size_score:.2f}, "
                    f"duration {item.duration_score:.2f}, count {item.count_score:.2f}, score {item.score:.2f}",
                    "evidence": [
                        f"timeline={','.join(str(value) for value in item.timeline[:16])}",
                        f"top_interval={item.top_interval}s top_size={item.top_size} bytes",
                        _candidate_evidence(item),
                    ],
                }
            )

        if http_post_beacons:
            highest_risk = max(
                (int(item.get("risk_score", 0) or 0) for item in http_post_beacons),
                default=0,
            )
            detections.append(
                {
                    "type": "beacon_http_post",
                    "severity": "warning",
                    "summary": "HTTP POST beacon-like check-in activity",
                    "details": "; ".join(
                        f"{item.get('src')}->{item.get('dst')} host={item.get('host')} req={item.get('requests')} risk={int(item.get('risk_score', 0) or 0)}"
                        for item in http_post_beacons[:5]
                    )
                    + f"; highest risk={highest_risk}",
                    "evidence": [
                        f"{item.get('src')}->{item.get('dst')} host={item.get('host')} uri={item.get('uri')} requests={item.get('requests')} bytes={item.get('bytes')} size_stability={float(item.get('size_stability', 0.0) or 0.0):.2f} linked_score={float(item.get('linked_beacon_score', 0.0) or 0.0):.2f} risk={int(item.get('risk_score', 0) or 0)} packets={item.get('packet_examples', '-')}"
                        for item in http_post_beacons[:8]
                    ],
                }
            )

        for item in candidates:
            if item.score >= 0.80 and item.count >= max(12, min_events):
                deterministic_category_checks["single_target_periodic_c2"].append(
                    f"{item.src_ip}->{item.dst_ip} score={item.score:.2f} cadence≈{item.mean_interval:.1f}s"
                )

        benign_hits: list[str] = []
        for item in candidates:
            port_value = item.src_port or item.dst_port
            if (
                port_value in benign_service_ports
                and item.score < 0.90
                and item.periodicity_score < 0.85
            ):
                benign_hits.append(
                    f"{item.src_ip}->{item.dst_ip} {_proto_label(item)} appears service-like (score={item.score:.2f})"
                )
        if benign_hits:
            detections.append(
                {
                    "type": "beacon_benign_periodic",
                    "severity": "info",
                    "summary": "Likely benign periodic service traffic",
                    "details": "; ".join(benign_hits[:6]),
                }
            )
            deterministic_category_checks["benign_periodic_likely"].extend(
                benign_hits[:12]
            )

        dns_nx = int(getattr(dns_summary, "rcode_counts", Counter()).get("NXDOMAIN", 0))
        dns_queries = int(getattr(dns_summary, "query_packets", 0) or 0)
        if dns_queries > 0 and dns_nx / dns_queries >= 0.25 and dns_nx >= 30:
            deterministic_checks["dns_beaconing_or_tunnel_pattern"].append(
                f"NXDOMAIN ratio={dns_nx}/{dns_queries} ({(dns_nx / max(dns_queries, 1)) * 100.0:.1f}%)"
            )
            detections.append(
                {
                    "type": "beacon_dns_nxdomain",
                    "severity": "warning",
                    "summary": "DNS beacon semantics: elevated NXDOMAIN rate",
                    "details": f"NXDOMAIN ratio={dns_nx}/{dns_queries} ({(dns_nx / max(dns_queries, 1)) * 100.0:.1f}%)",
                }
            )

        by_host: dict[str, list[BeaconCandidate]] = defaultdict(list)
        for item in candidates:
            by_host[item.src_ip].append(item)
        for src, items in sorted(
            by_host.items(), key=lambda kv: len(kv[1]), reverse=True
        ):
            channels = sorted({item.proto for item in items})
            destinations = sorted({item.dst_ip for item in items})
            top = max(items, key=lambda cand: cand.score)
            host_rollups.append(
                {
                    "host": src,
                    "candidate_count": len(items),
                    "channels": channels,
                    "destinations": len(destinations),
                    "top_cadence_s": round(float(top.mean_interval), 2),
                    "max_score": round(float(top.score), 2),
                }
            )

        campaign_map: dict[tuple[str, str], dict[str, object]] = {}
        for item in candidates:
            family = _cadence_family(float(item.mean_interval))
            key = (item.src_ip, family)
            camp = campaign_map.setdefault(
                key,
                {
                    "host": item.src_ip,
                    "cadence_family": family,
                    "count": 0,
                    "destinations": set(),
                    "channels": set(),
                    "max_score": 0.0,
                },
            )
            camp["count"] = int(camp["count"]) + 1
            cast_dests = camp.get("destinations")
            if isinstance(cast_dests, set):
                cast_dests.add(item.dst_ip)
            cast_channels = camp.get("channels")
            if isinstance(cast_channels, set):
                cast_channels.add(item.proto)
            camp["max_score"] = max(float(camp["max_score"]), float(item.score))

        for idx, ((_host, _family), value) in enumerate(
            sorted(
                campaign_map.items(),
                key=lambda row: (
                    int(row[1].get("count", 0)),
                    float(row[1].get("max_score", 0.0)),
                ),
                reverse=True,
            ),
            start=1,
        ):
            destinations = value.get("destinations")
            channels = value.get("channels")
            campaign_id = f"BCN-{idx:03d}"
            campaign_summaries.append(
                {
                    "campaign_id": campaign_id,
                    "host": str(value.get("host", "-")),
                    "cadence_family": str(value.get("cadence_family", "unknown")),
                    "flows": int(value.get("count", 0)),
                    "destinations": len(destinations)
                    if isinstance(destinations, set)
                    else 0,
                    "channels": ",".join(sorted(channels))
                    if isinstance(channels, set)
                    else "-",
                    "max_score": round(float(value.get("max_score", 0.0)), 2),
                }
            )

        for item in candidates[:25]:
            uri_template = "-"
            for post in http_post_beacons:
                if (
                    str(post.get("src")) == item.src_ip
                    and str(post.get("dst")) == item.dst_ip
                ):
                    uri_template = str(post.get("uri", "-") or "-")
                    break
            template_hash = (
                hashlib.sha1(uri_template.encode("utf-8", errors="ignore")).hexdigest()[
                    :12
                ]
                if uri_template != "-"
                else "-"
            )
            beacon_pivots.append(
                {
                    "src": item.src_ip,
                    "dst": item.dst_ip,
                    "proto": _proto_label(item),
                    "interval": round(float(item.mean_interval), 2),
                    "score": round(float(item.score), 2),
                    "first_seen": item.first_seen,
                    "last_seen": item.last_seen,
                    "uri_template_hash": template_hash,
                }
            )

        for item in candidates[:15]:
            explainability.append(
                f"{item.src_ip}->{item.dst_ip} flagged because interval MAD={item.mad_interval:.2f}s, "
                f"size MAD={item.mad_bytes:.1f}, persistence={_format_duration(item.duration_seconds)}, score={item.score:.2f}"
            )
        for item in http_post_beacons[:12]:
            deterministic_checks["http_post_checkin_pattern"].append(
                f"{item.get('src')}->{item.get('dst')} host={item.get('host')} uri={item.get('uri')} "
                f"requests={int(item.get('requests', 0) or 0)} linked_score={float(item.get('linked_beacon_score', 0.0) or 0.0):.2f} "
                f"risk={int(item.get('risk_score', 0) or 0)}"
            )
    else:
        detections.append(
            {
                "type": "no_beaconing",
                "severity": "info",
                "summary": "No beacon-like flows detected",
                "details": "No periodic flows met detection thresholds.",
            }
        )

    if (
        deterministic_checks["external_periodic_beaconing"]
        and deterministic_checks["http_post_checkin_pattern"]
    ):
        threat_hypotheses.append(
            {
                "hypothesis": "External C2 check-in pattern likely (periodic network cadence plus HTTP POST check-ins)",
                "confidence": "high",
                "evidence": len(deterministic_checks["external_periodic_beaconing"])
                + len(deterministic_checks["http_post_checkin_pattern"]),
            }
        )
    if (
        deterministic_checks["ot_control_periodicity"]
        and deterministic_checks["external_periodic_beaconing"]
    ):
        threat_hypotheses.append(
            {
                "hypothesis": "Potential OT/ICS telemetry beaconing beyond trust boundary",
                "confidence": "high",
                "evidence": len(deterministic_checks["ot_control_periodicity"])
                + len(deterministic_checks["external_periodic_beaconing"]),
            }
        )
    if (
        deterministic_checks["dns_beaconing_or_tunnel_pattern"]
        and deterministic_checks["high_stability_low_jitter_beacon"]
    ):
        threat_hypotheses.append(
            {
                "hypothesis": "DGA/failover-assisted beaconing likely (DNS failures plus stable periodic cadence)",
                "confidence": "medium",
                "evidence": len(deterministic_checks["dns_beaconing_or_tunnel_pattern"])
                + len(deterministic_checks["high_stability_low_jitter_beacon"]),
            }
        )

    for item in beacon_pivots[:20]:
        hunting_pivots.append(
            {
                "pivot": "beacon_flow",
                "entity": f"{item.get('src')}->{item.get('dst')}",
                "value": f"{item.get('proto')} interval={item.get('interval')} score={item.get('score')}",
            }
        )
    for item in http_post_beacons[:10]:
        hunting_pivots.append(
            {
                "pivot": "http_post_template",
                "entity": f"{item.get('src')}->{item.get('dst')}",
                "value": f"host={item.get('host')} uri={item.get('uri')} packets={item.get('packet_examples', '-')}",
            }
        )

    if not deterministic_checks["external_periodic_beaconing"]:
        benign_context.append(
            "No strong private-to-public periodic beacon profile crossed thresholds"
        )
    if not deterministic_checks["dns_beaconing_or_tunnel_pattern"]:
        benign_context.append(
            "No strong DNS failover/tunnel-like beaconing signal identified"
        )
    if not deterministic_checks["ot_control_periodicity"]:
        benign_context.append(
            "No periodic OT/ICS control-channel beacon profile to public infrastructure observed"
        )
    if not deterministic_checks["high_stability_low_jitter_beacon"]:
        benign_context.append(
            "No high-stability low-jitter beaconing pattern dominated the capture"
        )

    def _risk_row(
        label_text: str, key: str, high: bool = False, medium: bool = False
    ) -> None:
        evidence_items = [
            str(v)
            for v in list(deterministic_checks.get(key, []) or [])
            if str(v).strip()
        ]
        if evidence_items:
            if high:
                risk_value, conf_value = "High", "High"
            elif medium:
                risk_value, conf_value = "Medium", "Medium"
            else:
                risk_value, conf_value = "Low", "Medium"
            evidence_text = f"{len(evidence_items)} signal(s)"
        else:
            risk_value, conf_value, evidence_text = (
                "None",
                "Low",
                "No matching evidence",
            )
        risk_matrix.append(
            {
                "category": label_text,
                "risk": risk_value,
                "confidence": conf_value,
                "evidence": evidence_text,
            }
        )

    _risk_row("External Periodic Beaconing", "external_periodic_beaconing", high=True)
    _risk_row(
        "DNS Beaconing or Tunnel Pattern", "dns_beaconing_or_tunnel_pattern", high=True
    )
    _risk_row("HTTP POST Check-In Pattern", "http_post_checkin_pattern", high=True)
    _risk_row("Management Port Persistence", "management_port_persistence", medium=True)
    _risk_row("OT Control Periodicity", "ot_control_periodicity", high=True)
    _risk_row(
        "Layer-2 Periodic Control Signal", "l2_periodic_control_signal", medium=True
    )
    _risk_row(
        "High Stability Low Jitter Beacon",
        "high_stability_low_jitter_beacon",
        medium=True,
    )

    return BeaconSummary(
        path=path,
        total_packets=total_packets,
        candidate_count=len(candidates),
        candidates=candidates,
        http_post_beacons=http_post_beacons,
        protocol_beacon_checks=protocol_beacon_checks,
        deterministic_checks=deterministic_checks,
        threat_hypotheses=threat_hypotheses,
        hunting_pivots=hunting_pivots,
        benign_context=benign_context,
        risk_matrix=risk_matrix,
        deterministic_category_checks=deterministic_category_checks,
        campaign_summaries=campaign_summaries,
        host_rollups=host_rollups,
        beacon_pivots=beacon_pivots,
        explainability=explainability,
        detections=detections,
        errors=errors
        + list(getattr(http_summary, "errors", []) or [])
        + list(getattr(dns_summary, "errors", []) or []),
    )
