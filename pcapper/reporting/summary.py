"""Rendered output for the capture summary (the report with no analyzer
flag): what the capture is -- size, packets, time span, who captured it on
what -- its hashes for chain of custody, the protocols present, and the
quality caveats (drops, snaplen-truncated packets, retransmissions) that
bound every later conclusion. Interface detail and the full protocol table
are -v."""

from __future__ import annotations

from collections import Counter

from ..capture_parts import capture_parts
from ..models import PcapSummary
from ..utils import format_duration, format_ts, is_gzip_file
from . import _style as st
from .pcapmeta import linktype_text


def _format_linktype(value: object | None) -> str:
    """Kept for callers outside this module (re-exported by the package)."""
    return linktype_text(value, number=False)


def _protocol_rows(protocol_counts: Counter[str], packet_count: int, limit: int) -> list[list[str]]:
    """Kept for callers outside this module: ``Protocol / Packets /
    Presence`` rows with a header row."""
    rows = [["Protocol", "Packets", "Presence"]]
    for name, n in protocol_counts.most_common(limit):
        rows.append([name, str(n), f"{(n / packet_count) * 100:.1f}%" if packet_count else "-"])
    return rows


def render_summary(summary: PcapSummary, protocol_limit: int = 15) -> str:
    del protocol_limit
    rep = st.Report("Capture", summary.path)
    parts = capture_parts(summary.path)
    ifaces = list(summary.interface_stats or [])
    linktypes = sorted({i.linktype for i in ifaces if i.linktype}, key=str)
    snaplens = sorted({i.snaplen for i in ifaces if i.snaplen is not None})
    drops = [i.dropped_packets for i in ifaces if i.dropped_packets is not None]
    gzipped = " (gzip)" if is_gzip_file(summary.path) else ""
    rep.headline(False, st.join([
        f"{st.count(summary.packet_count)} packets", st.size(summary.size_bytes),
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
        st.ts_range(summary.start_ts, summary.end_ts) if summary.start_ts else "",
    ]), st.join([
        f"{summary.file_type}{gzipped}", ", ".join(linktype_text(v, number=False) for v in linktypes),
        f"snaplen {', '.join(str(v) for v in snaplens)}" if snaplens else "",
        st.plural(len(ifaces), "interface") if ifaces else "",
        (st.bad(f"{sum(drops)} packets dropped") if sum(drops) else "no drops recorded") if drops else "",
    ]))
    if len(parts) > 1:
        rep.scope(f"{len(parts)} split-capture parts joined as one ({parts[0].name} .. {parts[-1].name})")
    origin = st.join([summary.capture_application, f"on {summary.capture_os}" if summary.capture_os else "",
                      f"({summary.capture_hardware})" if summary.capture_hardware else ""], " ")
    if origin:
        rep.scope(f"captured with {origin}")
    truncated = int(getattr(summary, "truncated_packets", 0) or 0)
    if truncated:
        rep.scope(st.caution(f"{st.count(truncated)} packets cut short by the snaplen: byte totals are lower bounds"))

    hash_note = st.dim(" (all parts, in order)") if len(parts) > 1 else ""
    rep.section("Integrity", st.kv([("SHA-256", (summary.hash_sha256 or "-") + hash_note), ("SHA-1", (summary.hash_sha1 or "-") + hash_note)]))
    rep.section("Protocols", st.table(
        ["Protocol", "Packets", "Share"],
        [[name, st.count(n), f"{n / summary.packet_count:.1%}" if summary.packet_count else "-"]
         for name, n in summary.protocol_counts.most_common()],
        align="lrr", max_rows=st.TOP_ROWS, tail=st.TOP_ROWS, noun="protocol",
    ))
    vlans = sorted({v for i in ifaces for v in i.vlan_ids})
    tcp = int(getattr(summary, "tcp_packets", 0) or 0)
    retrans = int(getattr(summary, "retransmissions", 0) or 0)
    rate = float(getattr(summary, "retransmission_rate", 0.0) or 0.0)
    rep.section("Quality", st.kv([
        ("Retransmissions", f"{retrans} ({rate:.2%} of {st.count(tcp)} TCP packets)" if tcp and (retrans or st.verbose()) else
         ("no TCP packets" if st.verbose() and not tcp else "")),
        ("Truncated packets", st.count(truncated) if st.verbose() else ""),
        ("VLANs", f"{len(vlans)}: {st.listing(vlans, 12)}" if vlans else ("none tagged" if st.verbose() else "")),
    ]))

    def _dropped(i) -> str:
        if i.dropped_packets is not None:
            return str(i.dropped_packets)
        return "not recorded" if summary.file_type == "pcap" else "-"

    rep.section("Interfaces", st.table(
        ["Name", "Link type", "Snaplen", "Packets", "Dropped", "Filter", "Description", "Speed", "MAC", "OS"],
        [[i.name, linktype_text(i.linktype), i.snaplen if i.snaplen is not None else "-", i.packet_count if i.packet_count is not None else "-",
          _dropped(i), i.capture_filter or ("not recorded" if summary.file_type == "pcap" else "-"), i.description or "-",
          f"{i.speed_bps} bps" if i.speed_bps else "-", i.mac or "-", i.os or "-"] for i in ifaces],
        max_rows=None,
    ), detail=True)
    rep.section("File", st.kv([
        st.path_field(summary), ("Type", f"{summary.file_type}{gzipped}"), ("Size", f"{summary.size_bytes} bytes"),
        ("Start / end", f"{format_ts(summary.start_ts)} / {format_ts(summary.end_ts)}"),
        ("Duration", format_duration(summary.duration_seconds)),
        ("Capture hardware / OS / application", " / ".join(str(v or "not recorded") for v in
                                                           (summary.capture_hardware, summary.capture_os, summary.capture_application))),
    ]), detail=True)
    return rep.render()
