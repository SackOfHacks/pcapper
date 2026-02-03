from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from collections import Counter


@dataclass(frozen=True)
class InterfaceStat:
    name: str
    linktype: Optional[str]
    snaplen: Optional[int]
    packet_count: Optional[int]
    dropped_packets: Optional[int]
    capture_filter: Optional[str]
    description: Optional[str]
    speed_bps: Optional[int]
    mac: Optional[str]
    os: Optional[str]
    vlan_ids: list[int]


@dataclass(frozen=True)
class PcapSummary:
    path: Path
    file_type: str
    size_bytes: int
    packet_count: int
    start_ts: Optional[float]
    end_ts: Optional[float]
    duration_seconds: Optional[float]
    interface_stats: list[InterfaceStat]
    protocol_counts: Counter[str]
