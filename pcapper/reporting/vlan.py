"""Rendered output for vlan analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from collections import Counter
from pathlib import Path
from typing import Iterable
from ..coloring import (
    danger,
    header,
    label,
    muted,
    ok,
    warn,
)
from ..utils import (
    format_bytes_as_mb,
    format_ts,
)
from ..vlan import VlanStat, VlanSummary

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _apply_verbose_limit,
    _filtered_detections,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
    _render_protocol_verdict,
)


def render_vlan_summary(
    summary: VlanSummary, limit: int = 20, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit)
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"VLAN ANALYSIS :: {summary.path.name}"))
    _render_protocol_verdict(
        lines,
        label="VLAN",
        detections=getattr(summary, "detections", None),
        anomalies=getattr(summary, "anomalies", None),
    )
    lines.append(SECTION_BAR)

    lines.append(_format_kv("Tagged Packets", str(summary.total_tagged_packets)))
    lines.append(
        _format_kv("Tagged Bytes", format_bytes_as_mb(summary.total_tagged_bytes))
    )

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    if getattr(summary, "analysis_notes", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Notes"))
        for note in summary.analysis_notes:
            lines.append(muted(f"- {note}"))

    if summary.vlan_stats:
        lines.append(SUBSECTION_BAR)
        lines.append(header("VLAN Inventory"))
        rows = [
            [
                "VLAN",
                "Packets",
                "Bytes",
                "IPs",
                "Top Protocols",
                "First Seen",
                "Last Seen",
            ]
        ]
        for vlan in summary.vlan_stats[:limit]:
            ip_count = len(vlan.src_ips.union(vlan.dst_ips))
            proto_preview = (
                ", ".join(
                    name for name, _count in vlan.protocols.most_common(_limit_value(4))
                )
                or "-"
            )
            rows.append(
                [
                    str(vlan.vlan_id),
                    str(vlan.packets),
                    format_bytes_as_mb(vlan.bytes),
                    str(ip_count),
                    proto_preview,
                    format_ts(vlan.first_seen),
                    format_ts(vlan.last_seen),
                ]
            )
        lines.append(_format_table(rows))

        lines.append(SUBSECTION_BAR)
        lines.append(header("IPs Per VLAN"))
        ip_rows = [["VLAN", "IP Count", "IPs"]]
        for vlan in summary.vlan_stats[:limit]:
            ip_list = sorted(vlan.src_ips.union(vlan.dst_ips))
            preview = ip_list[: _limit_value(10)]
            if len(ip_list) > 10:
                preview_text = ", ".join(preview) + f" (+{len(ip_list) - 10} more)"
            else:
                preview_text = ", ".join(preview) if preview else "-"
            ip_rows.append(
                [
                    str(vlan.vlan_id),
                    str(len(ip_list)),
                    preview_text,
                ]
            )
        lines.append(_format_table(ip_rows))

        if verbose:
            lines.append(SUBSECTION_BAR)
            lines.append(header("VLAN Detailed Artifacts"))
            for vlan in summary.vlan_stats[:limit]:
                lines.append(label(f"VLAN {vlan.vlan_id}"))
                ip_list = sorted(vlan.src_ips.union(vlan.dst_ips))
                mac_list = sorted(vlan.src_macs.union(vlan.dst_macs))
                proto_list = ", ".join(
                    f"{name}({count})"
                    for name, count in vlan.protocols.most_common(_limit_value(10))
                )
                lines.append(f"  IPs: {', '.join(ip_list) if ip_list else '-'}")
                lines.append(f"  MACs: {', '.join(mac_list) if mac_list else '-'}")
                lines.append(f"  Protocols: {proto_list if proto_list else '-'}")
    else:
        lines.append(muted("No VLAN-tagged traffic detected."))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
            severity = item.get("severity", "info")
            summary_text = item.get("summary", "")
            details = item.get("details", "")
            if severity == "warning":
                marker = warn("[WARN]")
            elif severity == "critical":
                marker = danger("[CRIT]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))
            packet_count = item.get("packet_count")
            unique_sources = item.get("unique_sources")
            unique_destinations = item.get("unique_destinations")
            if packet_count is not None:
                lines.append(muted(f"  Packets: {packet_count}"))
            if unique_sources is not None or unique_destinations is not None:
                src_val = str(unique_sources) if unique_sources is not None else "-"
                dst_val = (
                    str(unique_destinations) if unique_destinations is not None else "-"
                )
                lines.append(muted(f"  Unique Sources/Dests: {src_val}/{dst_val}"))
            top_sources = item.get("top_sources")
            if top_sources:
                src_text = ", ".join(f"{ip}({count})" for ip, count in top_sources)
                lines.append(muted(f"  Sources: {src_text}"))
            top_destinations = item.get("top_destinations")
            if top_destinations:
                dst_text = ", ".join(f"{ip}({count})" for ip, count in top_destinations)
                lines.append(muted(f"  Destinations: {dst_text}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_vlan_rollup(
    summaries: Iterable[VlanSummary], limit: int = 20, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit)
    summary_list = list(summaries)
    if not summary_list:
        return ""

    combined: dict[int, dict[str, object]] = {}
    total_tagged_packets = 0
    total_tagged_bytes = 0
    errors: set[str] = set()

    for summary in summary_list:
        total_tagged_packets += summary.total_tagged_packets
        total_tagged_bytes += summary.total_tagged_bytes
        errors.update(summary.errors)
        for stat in summary.vlan_stats:
            info = combined.setdefault(
                stat.vlan_id,
                {
                    "packets": 0,
                    "bytes": 0,
                    "src_macs": set(),
                    "dst_macs": set(),
                    "src_ips": set(),
                    "dst_ips": set(),
                    "protocols": Counter(),
                    "first_seen": None,
                    "last_seen": None,
                },
            )
            info["packets"] = int(info["packets"]) + stat.packets
            info["bytes"] = int(info["bytes"]) + stat.bytes
            info["src_macs"].update(stat.src_macs)
            info["dst_macs"].update(stat.dst_macs)
            info["src_ips"].update(stat.src_ips)
            info["dst_ips"].update(stat.dst_ips)
            info["protocols"].update(stat.protocols)
            if stat.first_seen is not None:
                if info["first_seen"] is None or stat.first_seen < info["first_seen"]:
                    info["first_seen"] = stat.first_seen
            if stat.last_seen is not None:
                if info["last_seen"] is None or stat.last_seen > info["last_seen"]:
                    info["last_seen"] = stat.last_seen

    stats_list: list[VlanStat] = []
    for vlan_id, info in combined.items():
        stats_list.append(
            VlanStat(
                vlan_id=vlan_id,
                packets=int(info["packets"]),
                bytes=int(info["bytes"]),
                src_macs=set(info["src_macs"]),
                dst_macs=set(info["dst_macs"]),
                src_ips=set(info["src_ips"]),
                dst_ips=set(info["dst_ips"]),
                protocols=Counter(info["protocols"]),
                first_seen=info["first_seen"],
                last_seen=info["last_seen"],
            )
        )

    stats_list.sort(key=lambda item: item.packets, reverse=True)

    detections: list[dict[str, str]] = []
    if stats_list:
        vlan_ids = sorted(v.vlan_id for v in stats_list)
        if 1 in vlan_ids:
            detections.append(
                {
                    "type": "vlan_default_used",
                    "severity": "warning",
                    "summary": "VLAN 1 (default) observed",
                    "details": "Default VLAN is in use; consider verifying network segmentation policy.",
                }
            )

        total_packets = sum(v.packets for v in stats_list)
        for stat in stats_list:
            if total_packets > 0:
                ratio = stat.packets / total_packets
                if ratio > 0.8 and stat.packets > 1000:
                    detections.append(
                        {
                            "type": "vlan_traffic_concentration",
                            "severity": "warning",
                            "summary": f"VLAN {stat.vlan_id} carries {ratio:.1%} of tagged traffic",
                            "details": "Check for misconfiguration or single-VLAN dependency.",
                        }
                    )
                if stat.packets < 10:
                    detections.append(
                        {
                            "type": "vlan_low_activity",
                            "severity": "info",
                            "summary": f"VLAN {stat.vlan_id} has low activity ({stat.packets} packets)",
                            "details": "Low activity VLANs can be normal; validate against expectations.",
                        }
                    )

    rollup_summary = VlanSummary(
        path=Path("ALL_PCAPS"),
        total_tagged_packets=total_tagged_packets,
        total_tagged_bytes=total_tagged_bytes,
        vlan_stats=stats_list,
        detections=detections,
        errors=sorted(errors),
    )
    return render_vlan_summary(rollup_summary, limit=limit, verbose=verbose)
