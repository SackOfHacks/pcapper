from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from scapy.utils import PcapReader, PcapNgReader

from .progress import build_statusbar
from .utils import detect_file_type, safe_float, format_bytes_as_mb, sparkline


@dataclass(frozen=True)
class SizeBucketStat:
    label: str
    count: int
    avg: float
    min: int
    max: int
    rate: float
    pct: float
    burst_rate: float
    burst_start: Optional[float]


@dataclass(frozen=True)
class SizeSummary:
    path: Path
    total_packets: int
    total_bytes: int
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]
    buckets: list[SizeBucketStat]
    detections: list[dict[str, object]]
    errors: list[str]


PACKET_BUCKETS = [
    (0, 19, "0-19"),
    (20, 39, "20-39"),
    (40, 79, "40-79"),
    (80, 159, "80-159"),
    (160, 319, "160-319"),
    (320, 639, "320-639"),
    (640, 1279, "640-1279"),
    (1280, 2559, "1280-2559"),
    (2560, 5119, "2560-5119"),
    (5120, 65535, "5120+"),
]


def analyze_sizes(path: Path, show_status: bool = True) -> SizeSummary:
    errors: list[str] = []
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
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

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

            total_packets += 1
            pkt_len = int(len(pkt)) if hasattr(pkt, "__len__") else 0
            total_bytes += pkt_len
            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            for low, high, label in PACKET_BUCKETS:
                if low <= pkt_len <= high:
                    bucket_counts[label] += 1
                    bucket_sizes[label].append(pkt_len)
                    if ts is not None:
                        bucket_times[label].append(ts)
                    break
    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        reader.close()

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    buckets: list[SizeBucketStat] = []
    for low, high, label in PACKET_BUCKETS:
        count = bucket_counts.get(label, 0)
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

        buckets.append(SizeBucketStat(
            label=label,
            count=count,
            avg=avg_size,
            min=min_size,
            max=max_size,
            rate=rate,
            pct=pct,
            burst_rate=burst_rate,
            burst_start=burst_start,
        ))

    detections: list[dict[str, object]] = []
    if total_packets == 0:
        detections.append({
            "severity": "info",
            "summary": "No packets observed",
            "details": "No packet sizes to analyze.",
        })
    else:
        jumbo = next((b for b in buckets if b.label == "1501-9000" or b.label == "9001+"), None)
        if jumbo and jumbo.pct > 5:
            detections.append({
                "severity": "warning",
                "summary": "High volume of jumbo packets",
                "details": f"{jumbo.pct:.1f}% of traffic exceeds 1500 bytes; check for tunneling or exfil.",
            })
        tiny = next((b for b in buckets if b.label in {"0-64", "65-128"}), None)
        if tiny and tiny.pct > 40:
            detections.append({
                "severity": "warning",
                "summary": "Tiny-packet heavy profile",
                "details": f"{tiny.pct:.1f}% of packets are <=128 bytes; possible scanning or keepalive chatter.",
            })

    return SizeSummary(
        path=path,
        total_packets=total_packets,
        total_bytes=total_bytes,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
        buckets=buckets,
        detections=detections,
        errors=errors,
    )


def render_size_sparkline(buckets: list[SizeBucketStat]) -> str:
    values = [b.count for b in buckets]
    return sparkline(values)
