from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import ipaddress

from .pcap_cache import get_reader
from .utils import safe_float, detect_file_type

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore


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


@dataclass(frozen=True)
class BeaconSummary:
    path: Path
    total_packets: int
    candidate_count: int
    candidates: list[BeaconCandidate]
    detections: list[dict[str, object]]
    errors: list[str]


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

    if not src_ip or not dst_ip:
        return None

    if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
        layer = pkt[TCP]  # type: ignore[index]
        return (src_ip, dst_ip, "TCP", int(getattr(layer, "sport", 0)), int(getattr(layer, "dport", 0)))
    if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
        layer = pkt[UDP]  # type: ignore[index]
        return (src_ip, dst_ip, "UDP", int(getattr(layer, "sport", 0)), int(getattr(layer, "dport", 0)))

    return (src_ip, dst_ip, "IP", None, None)


def _flow_key_bidirectional(pkt) -> Optional[tuple[str, str, str, Optional[int], Optional[int]]]:
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
    std = variance ** 0.5
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


def analyze_beacons(path: Path, show_status: bool = True, min_events: int = 20) -> BeaconSummary:
    errors: list[str] = []
    if IP is None and IPv6 is None:
        errors.append("Scapy IP layers unavailable; install scapy for beacon analysis.")
        return BeaconSummary(path=path, total_packets=0, candidate_count=0, candidates=[], detections=[], errors=errors)

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, show_status=show_status
    )

    session_conn_times: dict[tuple[str, str, str, Optional[int]], list[float]] = defaultdict(list)
    session_conn_sizes: dict[tuple[str, str, str, Optional[int]], list[int]] = defaultdict(list)
    udp_session_times: dict[tuple[str, str, str, Optional[int]], list[float]] = defaultdict(list)
    udp_session_sizes: dict[tuple[str, str, str, Optional[int]], list[int]] = defaultdict(list)
    conn_first_ts: dict[tuple[str, str, str, Optional[int], Optional[int]], float] = {}
    conn_syn_ts: dict[tuple[str, str, str, Optional[int], Optional[int]], float] = {}
    conn_bytes: dict[tuple[str, str, str, Optional[int], Optional[int]], int] = defaultdict(int)
    total_packets = 0

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
                conn_bytes[conn_key] += pkt_len
                if is_syn:
                    conn_syn_ts[conn_key] = ts
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
            else:
                continue
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

    combined_flows: list[tuple[tuple[str, str, str, Optional[int], Optional[int]], list[float], list[int]]] = []
    for (client, server, proto, server_port), times in session_conn_times.items():
        sizes = session_conn_sizes.get((client, server, proto, server_port), [])
        combined_flows.append(((client, server, proto, server_port, None), times, sizes))
    for (client, server, proto, server_port), times in udp_session_times.items():
        sizes = udp_session_sizes.get((client, server, proto, server_port), [])
        combined_flows.append(((client, server, proto, server_port, None), times, sizes))
    seen_keys: set[tuple[str, str, str, Optional[int], Optional[int]]] = set()

    benign_service_ports = {
        53, 123, 137, 138, 139, 135, 389, 445, 464, 3268, 3269, 593, 88
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

    for (src_ip, dst_ip, proto, sport, dport), times, sizes in combined_flows:
        key_id = (src_ip, dst_ip, proto, sport, dport)
        if key_id in seen_keys:
            continue
        seen_keys.add(key_id)

        has_public = _is_public(src_ip) or _is_public(dst_ip)
        if not has_public:
            continue
        times_sorted = sorted(times)
        long_duration = (times_sorted[-1] - times_sorted[0]) if len(times_sorted) >= 2 else 0.0
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
        duration_score = min(1.0, duration_seconds / 3600.0) if duration_seconds > 0 else 0.0
        count_score = min(1.0, len(times_sorted) / 50.0)
        score = (
            (0.5 * periodicity_score)
            + (0.2 * size_score)
            + (0.2 * duration_score)
            + (0.1 * count_score)
        )

        if mean < 1.0 or mean > 86400.0:
            continue
        if score < 0.35 and len(times_sorted) < (min_events * 2):
            continue
        if proto == "UDP" and (len(times_sorted) < max(min_events, 15) or periodicity_score < 0.6):
            continue
        if sport in benign_service_ports or dport in benign_service_ports:
            if score < 0.8 and periodicity_score < 0.8:
                continue

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

    detections: list[dict[str, object]] = []
    if candidates:
        severity_rank = {"info": 0, "warning": 1, "high": 2, "critical": 3}

        def _candidate_severity(item: BeaconCandidate) -> str:
            is_external = _is_private(item.src_ip) and _is_public(item.dst_ip)
            if item.score >= 0.88 and item.count >= 30 and item.duration_seconds >= 3600 and is_external:
                return "critical"
            if item.score >= 0.78 and item.count >= 20 and is_external:
                return "high"
            if item.score >= 0.70 and item.count >= 15:
                return "warning"
            return "info"

        src_counts: Counter[str] = Counter()
        dst_counts: Counter[str] = Counter()
        flow_details: list[str] = []
        flow_evidence: list[str] = []
        peak_severity = "info"
        for item in candidates[:3]:
            duration = 0.0
            if item.first_seen is not None and item.last_seen is not None:
                duration = max(0.0, item.last_seen - item.first_seen)
            if item.src_port and item.dst_port:
                proto_label = f"{item.proto}:{item.src_port}->{item.dst_port}"
            elif item.dst_port:
                proto_label = f"{item.proto}:{item.dst_port}"
            else:
                proto_label = item.proto
            flow_details.append(
                f"{item.src_ip}->{item.dst_ip} {proto_label}, {item.count} beacons, mean {item.mean_interval:.2f}s, "
                f"median {item.median_interval:.2f}s, MAD {item.mad_interval:.2f}s, duration {_format_duration(duration)}, "
                f"avg bytes {item.avg_bytes:.0f}, size MAD {item.mad_bytes:.0f}, score {item.score:.2f}"
            )
            flow_evidence.append(
                f"{item.src_ip}->{item.dst_ip} {proto_label} count={item.count} top_interval={item.top_interval}s top_size={item.top_size}"
            )
            src_counts[item.src_ip] += item.count
            dst_counts[item.dst_ip] += item.count
            candidate_severity = _candidate_severity(item)
            if severity_rank[candidate_severity] > severity_rank[peak_severity]:
                peak_severity = candidate_severity
        detections.append({
            "type": "beaconing",
            "severity": peak_severity,
            "summary": f"{len(candidates)} beacon-like flows detected",
            "details": "Periodic communication patterns may indicate C2 or scheduled tasks. "
                       f"Top flows: {'; '.join(flow_details)}",
            "top_sources": src_counts.most_common(5),
            "top_destinations": dst_counts.most_common(5),
            "evidence": flow_evidence,
        })

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
            detections.append({
                "type": "beacon_fanout",
                "severity": "high",
                "summary": "Source beaconing to multiple destinations",
                "details": ", ".join(
                    f"{src} -> {dst_count} destinations ({events} events)"
                    for src, dst_count, events in fanout_rows[:5]
                ),
                "top_sources": [(src, events) for src, _dst_count, events in fanout_rows[:5]],
            })

        low_and_slow = [
            item
            for item in candidates
            if item.mean_interval >= 300
            and item.periodicity_score >= 0.80
            and item.duration_seconds >= 3600
            and item.count >= 10
        ]
        if low_and_slow:
            detections.append({
                "type": "beacon_low_slow",
                "severity": "high",
                "summary": "Low-and-slow periodic beaconing pattern",
                "details": "; ".join(
                    f"{item.src_ip}->{item.dst_ip} interval≈{item.mean_interval:.0f}s duration={_format_duration(item.duration_seconds)}"
                    for item in low_and_slow[:5]
                ),
                "top_sources": Counter(item.src_ip for item in low_and_slow).most_common(5),
                "top_destinations": Counter(item.dst_ip for item in low_and_slow).most_common(5),
            })

        high_frequency = [
            item
            for item in candidates
            if item.mean_interval <= 30
            and item.periodicity_score >= 0.75
            and item.count >= 30
            and item.duration_seconds >= 600
        ]
        if high_frequency:
            detections.append({
                "type": "beacon_high_frequency",
                "severity": "warning",
                "summary": "High-frequency periodic check-in pattern",
                "details": "; ".join(
                    f"{item.src_ip}->{item.dst_ip} interval≈{item.mean_interval:.1f}s count={item.count}"
                    for item in high_frequency[:5]
                ),
                "top_sources": Counter(item.src_ip for item in high_frequency).most_common(5),
                "top_destinations": Counter(item.dst_ip for item in high_frequency).most_common(5),
            })

        for item in candidates[:3]:
            duration = 0.0
            if item.first_seen is not None and item.last_seen is not None:
                duration = max(0.0, item.last_seen - item.first_seen)
            detections.append({
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
                ],
            })
    else:
        detections.append({
            "type": "no_beaconing",
            "severity": "info",
            "summary": "No beacon-like flows detected",
            "details": "No periodic flows met detection thresholds.",
        })

    return BeaconSummary(
        path=path,
        total_packets=total_packets,
        candidate_count=len(candidates),
        candidates=candidates,
        detections=detections,
        errors=errors,
    )
