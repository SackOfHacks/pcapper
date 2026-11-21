"""The packet at a position in a capture (``--packet N``), as an analysis.

Memoised like any analyzer, so a run's plan can include it: read from disk
in a shared pass it takes its packet from the run's one read (and stops
there) instead of a read of its own; held in memory it is an index lookup.
"""

from __future__ import annotations

from pathlib import Path

from .pcap_cache import PcapMeta, iter_packets
from .utils import memoize_analysis


@memoize_analysis
def analyze_packet_at(
    path: Path,
    index: int,
    show_status: bool = False,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> object | None:
    """Packet number ``index`` (1-based) of the capture, or None."""
    if index <= 0:
        return None
    if packets is not None:
        return packets[index - 1] if index <= len(packets) else None
    for position, pkt in enumerate(
        iter_packets(path, packets=packets, meta=meta, show_status=show_status), start=1
    ):
        if position == index:
            return pkt
    return None
