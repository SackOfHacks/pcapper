from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .pcap_cache import PcapMeta, iter_packets
from .utils import memoize_analysis, packet_wirelen, safe_float, sparkline


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


# The last bucket is open-ended: a capture taken with segmentation offload
# active (Linux GRO/TSO, Windows RSC) carries "packets" of 64 KB and more,
# and those used to fall through every bucket and vanish from the table.
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
    (5120, None, "5120+"),
]


def _bucket_label(size: int) -> str:
    for low, high, label in PACKET_BUCKETS:
        if size >= low and (high is None or size <= high):
            return label
    return PACKET_BUCKETS[-1][2]


@memoize_analysis
def analyze_sizes(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> SizeSummary:
    errors: list[str] = []
    total_packets = 0
    total_bytes = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    # Per-bucket running stats; keeping every packet's size in a list cost a
    # Python int per packet on multi-million-packet captures for no gain.
    bucket_count: dict[str, int] = {}
    bucket_sum: dict[str, int] = {}
    bucket_min: dict[str, int] = {}
    bucket_max: dict[str, int] = {}
    bucket_times: dict[str, list[float]] = {}

    for pkt in iter_packets(path, packets=packets, meta=meta, show_status=show_status):
        total_packets += 1
        # Sizes are what was on the wire. The captured length is capped by the
        # snaplen, so a truncated capture would otherwise report every packet
        # as at most snaplen bytes and its total volume a fraction of reality.
        pkt_len = packet_wirelen(pkt)
        total_bytes += pkt_len
        ts = safe_float(getattr(pkt, "time", None))
        if ts is not None:
            if first_seen is None or ts < first_seen:
                first_seen = ts
            if last_seen is None or ts > last_seen:
                last_seen = ts

        label = _bucket_label(pkt_len)
        bucket_count[label] = bucket_count.get(label, 0) + 1
        bucket_sum[label] = bucket_sum.get(label, 0) + pkt_len
        current_min = bucket_min.get(label)
        if current_min is None or pkt_len < current_min:
            bucket_min[label] = pkt_len
        current_max = bucket_max.get(label)
        if current_max is None or pkt_len > current_max:
            bucket_max[label] = pkt_len
        if ts is not None:
            bucket_times.setdefault(label, []).append(ts)

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    buckets: list[SizeBucketStat] = []
    for _low, _high, label in PACKET_BUCKETS:
        count = bucket_count.get(label, 0)
        avg_size = (bucket_sum.get(label, 0) / count) if count else 0.0
        min_size = bucket_min.get(label, 0)
        max_size = bucket_max.get(label, 0)
        pct = (count / total_packets) * 100 if total_packets else 0.0
        rate = (
            (count / duration_seconds)
            if duration_seconds and duration_seconds > 0
            else 0.0
        )

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

        buckets.append(
            SizeBucketStat(
                label=label,
                count=count,
                avg=avg_size,
                min=min_size,
                max=max_size,
                rate=rate,
                pct=pct,
                burst_rate=burst_rate,
                burst_start=burst_start,
            )
        )

    detections: list[dict[str, object]] = []
    if total_packets == 0:
        detections.append(
            {
                "severity": "info",
                "summary": "No packets observed",
                "details": "No packet sizes to analyze.",
            }
        )
    else:
        # Aggregate by byte range using the PACKET_BUCKETS bounds keyed by label
        # (the previous "1501-9000"/"0-64" label lookups never matched any real
        # label, so these detections were dead). SizeBucketStat has no low/high,
        # so resolve bounds from PACKET_BUCKETS.
        _pct_by_label = {b.label: b.pct for b in buckets}
        jumbo_pct = sum(
            _pct_by_label.get(lbl, 0.0) for (lo, _hi, lbl) in PACKET_BUCKETS if lo >= 1280
        )
        if jumbo_pct > 5:
            detections.append(
                {
                    "severity": "warning",
                    "summary": "High volume of large/jumbo packets",
                    "details": f"{jumbo_pct:.1f}% of traffic is >=1280 bytes (at/over typical MTU); check for tunneling or exfil.",
                }
            )
        tiny_pct = sum(
            _pct_by_label.get(lbl, 0.0)
            for (_lo, hi, lbl) in PACKET_BUCKETS
            if hi is not None and hi <= 159
        )
        if tiny_pct > 40:
            detections.append(
                {
                    "severity": "warning",
                    "summary": "Tiny-packet heavy profile",
                    "details": f"{tiny_pct:.1f}% of packets are <=159 bytes; possible scanning or keepalive chatter.",
                }
            )

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
