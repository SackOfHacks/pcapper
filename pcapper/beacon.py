from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import ipaddress

from scapy.utils import PcapReader, PcapNgReader

from .progress import build_statusbar
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
    detections: list[dict[str, str]]
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

    session_conn_times: dict[tuple[str, str, str, Optional[int]], list[float]] = defaultdict(list)
    session_conn_sizes: dict[tuple[str, str, str, Optional[int]], list[int]] = defaultdict(list)
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
            if TCP is None or not pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                continue

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
            ts = safe_float(getattr(pkt, "time", None))
            if ts is None:
                continue
            pkt_len = int(len(pkt)) if hasattr(pkt, "__len__") else 0
            if key:
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
    seen_keys: set[tuple[str, str, str, Optional[int], Optional[int]]] = set()

    for (src_ip, dst_ip, proto, sport, dport), times, sizes in combined_flows:
        key_id = (src_ip, dst_ip, proto, sport, dport)
        if key_id in seen_keys:
            continue
        seen_keys.add(key_id)
        long_duration = (times[-1] - times[0]) if len(times) >= 2 else 0.0
        if len(times) < min_events and long_duration < 1800:
            continue
        times.sort()
        mean, std, jitter = _compute_stats(times)
        if mean <= 0:
            continue
        deltas = [b - a for a, b in zip(times, times[1:]) if b >= a]
        interval_range = (max(deltas) - min(deltas)) if deltas else 0.0

        avg_bytes = (sum(sizes) / len(sizes)) if sizes else 0.0
        size_range = (max(sizes) - min(sizes)) if sizes else 0
        top_interval = 0
        if deltas:
            interval_counts = Counter(int(round(delta)) for delta in deltas)
            top_interval = interval_counts.most_common(1)[0][0]
        top_size = 0
        if sizes:
            top_size = Counter(sizes).most_common(1)[0][0]

        regularity = max(0.0, min(1.0, 1.0 - (std / mean))) if mean > 0 else 0.0
        score = regularity

        if mean < 1.0 or mean > 86400.0:
            continue
        if score < 0.4 and not (len(times) >= (min_events * 2) and regularity >= 0.2):
            continue

        candidates.append(
            BeaconCandidate(
                src_ip=src_ip,
                dst_ip=dst_ip,
                proto=proto,
                src_port=sport,
                dst_port=dport,
                count=len(times),
                avg_bytes=avg_bytes,
                interval_range=interval_range,
                size_range=size_range,
                top_interval=top_interval,
                top_size=top_size,
                mean_interval=mean,
                std_interval=std,
                jitter=jitter,
                score=score,
                first_seen=times[0],
                last_seen=times[-1],
                timeline=_timeline(times),
            )
        )

    candidates.sort(key=lambda item: (item.score, item.count), reverse=True)

    detections: list[dict[str, str]] = []
    if candidates:
        detections.append({
            "type": "beaconing",
            "severity": "warning",
            "summary": f"{len(candidates)} beacon-like flows detected",
            "details": "Periodic communication patterns may indicate C2 or scheduled tasks.",
        })
        for item in candidates[:3]:
            detections.append({
                "type": "beacon_candidate",
                "severity": "info",
                "summary": f"Beacon candidate {item.src_ip} -> {item.dst_ip}",
                "details": f"{item.count} events, mean {item.mean_interval:.2f}s, avg bytes {item.avg_bytes:.0f}, interval range {item.interval_range:.0f}, score {item.score:.2f}",
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
