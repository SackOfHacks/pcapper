"""Rendered output for summary analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from collections import Counter
from ..coloring import (
    header,
    muted,
)
from ..models import PcapSummary
from ..utils import (
    format_bytes_as_mb,
    format_duration,
    format_ts,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _FULL_OUTPUT_LIMIT,
    _finalize_output,
    _format_kv,
    _format_table,
)


def _format_linktype(value: object | None) -> str:
    if value is None:
        return "-"
    try:
        if isinstance(value, str) and value.isdigit():
            value = int(value)
        if isinstance(value, int):
            common = {
                0: "Null/Loopback",
                1: "Ethernet",
                6: "802.5 Token Ring",
                7: "ARCnet",
                8: "SLIP",
                9: "PPP",
                101: "Raw IP",
                105: "IEEE 802.11",
                113: "Linux cooked capture",
            }
            if value in common:
                return common[value]
            try:
                from scapy.data import l2types  # type: ignore

                mapped = l2types.get(value)
                if mapped is not None:
                    return str(mapped)
            except Exception:
                pass
            return f"LINKTYPE_{value}"
        return str(value)
    except Exception:
        return str(value)


def _protocol_rows(
    protocol_counts: Counter[str], packet_count: int, limit: int
) -> list[list[str]]:
    rows = [["Protocol", "Packets", "Presence"]]
    for name, count in protocol_counts.most_common(limit):
        pct = "-"
        if packet_count:
            pct = f"{(count / packet_count) * 100:.1f}%"
        rows.append([name, str(count), pct])
    return rows


def render_summary(summary: PcapSummary, protocol_limit: int = 15) -> str:
    del protocol_limit
    protocol_limit = _FULL_OUTPUT_LIMIT
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"PCAPPER REPORT :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    lines.append(_format_kv("Path", str(summary.path)))
    lines.append(_format_kv("Type", summary.file_type))
    lines.append(_format_kv("Size", format_bytes_as_mb(summary.size_bytes)))
    lines.append(_format_kv("Packets", str(summary.packet_count)))
    lines.append(_format_kv("Start", format_ts(summary.start_ts)))
    lines.append(_format_kv("End", format_ts(summary.end_ts)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))
    lines.append(_format_kv("Interfaces", str(len(summary.interface_stats))))
    linktypes = sorted(
        {iface.linktype for iface in summary.interface_stats if iface.linktype}
    )
    snaplens = sorted(
        {
            iface.snaplen
            for iface in summary.interface_stats
            if iface.snaplen is not None
        }
    )
    if linktypes:
        lines.append(_format_kv("LinkTypes", ", ".join(linktypes)))
    if snaplens:
        lines.append(_format_kv("SnapLen", ", ".join(str(val) for val in snaplens)))
    encapsulations = sorted({_format_linktype(value) for value in linktypes})
    lines.append(
        _format_kv(
            "Encapsulation", ", ".join(encapsulations) if encapsulations else "-"
        )
    )
    lines.append(_format_kv("Hash (SHA256)", summary.hash_sha256 or "-"))
    lines.append(_format_kv("Hash (SHA1)", summary.hash_sha1 or "-"))

    def _capture_value(value: object | None) -> str:
        text = str(value or "").strip()
        return text if text else "not recorded"

    lines.append(SUBSECTION_BAR)
    lines.append(header("Capture"))
    lines.append(_format_kv("Hardware", _capture_value(summary.capture_hardware)))
    lines.append(_format_kv("OS", _capture_value(summary.capture_os)))
    lines.append(
        _format_kv("Application", _capture_value(summary.capture_application))
    )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Interface Statistics"))
    rows = [
        [
            "Interface Name",
            "Dropped Packets",
            "Capture Filter",
            "Link Type",
            "Packet Size Limit",
        ]
    ]
    for iface in summary.interface_stats:
        if summary.file_type == "pcap":
            dropped = (
                str(iface.dropped_packets)
                if iface.dropped_packets is not None
                else "not recorded"
            )
            capture_filter = iface.capture_filter or "not recorded"
        else:
            dropped = (
                str(iface.dropped_packets) if iface.dropped_packets is not None else "-"
            )
            capture_filter = iface.capture_filter or "-"
        link_type = _format_linktype(iface.linktype)
        snaplen = str(iface.snaplen) if iface.snaplen is not None else "-"
        rows.append(
            [
                iface.name,
                dropped,
                capture_filter,
                link_type,
                snaplen,
            ]
        )
    lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Protocol Summary (presence across packets)"))
    lines.append(
        _format_table(
            _protocol_rows(
                summary.protocol_counts, summary.packet_count, protocol_limit
            )
        )
    )

    lines.append(SUBSECTION_BAR)
    lines.append(header("VLAN Summary"))
    vlan_ids: set[int] = set()
    for iface in summary.interface_stats:
        vlan_ids.update(iface.vlan_ids)
    if vlan_ids:
        vlan_list = ", ".join(str(vlan) for vlan in sorted(vlan_ids))
        lines.append(_format_kv("VLANs Observed", str(len(vlan_ids))))
        lines.append(_format_kv("VLAN IDs", vlan_list))
    else:
        lines.append(muted("No VLAN-tagged traffic detected."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Retransmissions"))
    lines.append(
        _format_kv(
            "TCP Retransmissions", str(int(getattr(summary, "retransmissions", 0) or 0))
        )
    )
    lines.append(
        _format_kv(
            "Retransmission Rate",
            f"{float(getattr(summary, 'retransmission_rate', 0.0) or 0.0):.2%}",
        )
    )
    tcp_packets = int(getattr(summary, "tcp_packets", 0) or 0)
    if tcp_packets == 0:
        lines.append(
            muted("No TCP packets observed; retransmission heuristics not applicable.")
        )
    lines.append(SECTION_BAR)

    return _finalize_output(lines, show_truncation_note=False)
