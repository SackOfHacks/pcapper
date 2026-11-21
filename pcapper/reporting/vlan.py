"""Rendered output for vlan analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Iterable

from ..vlan import VlanStat, VlanSummary
from . import _style as st
from ._common import (
    _apply_verbose_limit,
)
from ._kv import findings_for


def render_vlan_summary(summary: VlanSummary, limit: int = 20, verbose: bool = False) -> str:
    """802.1Q VLANs: each VLAN's traffic, hosts and protocols (segmentation
    as observed), with default-VLAN and double-tagging (VLAN hopping)
    findings first; full IP/MAC lists per VLAN are -v."""
    rep = st.Report("VLAN", summary.path)
    findings = findings_for(summary, ot=False)
    stats = list(summary.vlan_stats or [])
    if not summary.total_tagged_packets and not st.material(findings):
        return rep.absent("VLAN-tagged traffic", summary.errors)
    severity, text = st.verdict(findings, high="VLAN hopping / segmentation issue: investigate", medium="VLAN configuration to review")
    double = int(getattr(summary, "double_tagged_packets", 0) or 0)
    rep.headline(severity, text, st.join([
        f"{st.count(summary.total_tagged_packets)} tagged packets · {st.size(summary.total_tagged_bytes)}",
        st.plural(len(stats), "VLAN"),
        st.bad(f"{double} double-tagged") if double else "",
    ]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))
    rep.section("VLANs", st.table(
        ["VLAN", "Packets", "Bytes", "Hosts", "MACs", "Protocols", "First", "Last"],
        [[v.vlan_id, st.count(v.packets), st.size(v.bytes), st.count(len(v.src_ips | v.dst_ips)), st.count(len(v.src_macs | v.dst_macs)),
          st.top(v.protocols, 4), st.ts(v.first_seen), st.ts(v.last_seen)] for v in stats],
        align="rrrrrlll", max_rows=20, noun="VLAN",
    ))
    rep.section("Hosts per VLAN", st.table(
        ["VLAN", "Hosts"],
        [[v.vlan_id, ", ".join(sorted(v.src_ips | v.dst_ips)) if st.verbose() else
          (", ".join(sorted(v.src_ips | v.dst_ips)[:8]) + (st.dim(f", +{len(v.src_ips | v.dst_ips) - 8} more")
                                                          if len(v.src_ips | v.dst_ips) > 8 else ""))] for v in stats],
        align="rl", max_rows=20, noun="VLAN",
    ))
    rep.section("Details", [line for v in stats for line in (
        [f"  {st.strong(f'VLAN {v.vlan_id}')}"] + st.kv([
            ("IPs", ", ".join(sorted(v.src_ips | v.dst_ips)) or "-"),
            ("MACs", ", ".join(sorted(v.src_macs | v.dst_macs)) or "-"),
            ("Protocols", st.top(v.protocols, None) or "-"),
        ], indent=4))], detail=True)
    rep.section("Notes", st.bullets(getattr(summary, "analysis_notes", None) or [], max_items=None), detail=True)
    return rep.render()


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
