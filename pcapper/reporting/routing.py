"""Rendered output for routing analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    danger,
    header,
    muted,
    warn,
)
from ..routing import RoutingSummary

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _apply_verbose_limit,
    _filtered_detections,
    _finalize_output,
    _format_counter,
    _format_kv,
    _limit_value,
    _redact_in_text,
    _render_protocol_verdict,
)


def render_routing_summary(
    summary: RoutingSummary, limit: int = 200, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit)
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"ROUTING ANALYSIS :: {summary.path.name}"))
    _render_protocol_verdict(
        lines,
        label="Routing",
        detections=getattr(summary, "detections", None),
        anomalies=getattr(summary, "anomalies", None),
    )
    lines.append(SECTION_BAR)

    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("Routing Packets", str(summary.routing_packets)))
    if summary.duration_seconds is not None:
        lines.append(_format_kv("Duration", f"{summary.duration_seconds:.1f}s"))
    if summary.endpoint_counts:
        lines.append(_format_kv("Unique Endpoints", str(len(summary.endpoint_counts))))

    if summary.protocol_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Protocols"))
        for name, count in summary.protocol_counts.most_common(_limit_value(12)):
            lines.append(muted(f"- {name}: {count}"))

    if summary.message_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Message Types"))
        for name, count in summary.message_counts.most_common(_limit_value(12)):
            lines.append(muted(f"- {name}: {count}"))

    if summary.lsa_type_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OSPF LSA Types"))
        for name, count in summary.lsa_type_counts.most_common(_limit_value(12)):
            lines.append(muted(f"- {name}: {count}"))

    if summary.lsa_adv_router_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OSPF LSA Advertising Routers"))
        for rid, count in summary.lsa_adv_router_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {rid}: {count}"))

    if summary.lsa_id_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OSPF LSA IDs"))
        for ls_id, count in summary.lsa_id_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {ls_id}: {count}"))

    if summary.bgp_prefix_counts or summary.bgp_withdraw_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("BGP Prefixes"))
        if summary.bgp_prefix_counts:
            lines.append(
                muted(f"- Announced: {_format_counter(summary.bgp_prefix_counts, 8)}")
            )
        if summary.bgp_withdraw_counts:
            lines.append(
                muted(f"- Withdrawn: {_format_counter(summary.bgp_withdraw_counts, 8)}")
            )

    if summary.bgp_next_hop_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("BGP Next-Hops"))
        for hop, count in summary.bgp_next_hop_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {hop}: {count}"))

    if summary.bgp_path_attr_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("BGP Path Attributes"))
        for name, count in summary.bgp_path_attr_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {name}: {count}"))

    if summary.bgp_as_path_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("BGP AS Paths"))
        for path, count in summary.bgp_as_path_counts.most_common(_limit_value(6)):
            lines.append(muted(f"- {path}: {count}"))

    if summary.isis_system_id_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("IS-IS System IDs"))
        for sysid, count in summary.isis_system_id_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {sysid}: {count}"))

    if summary.isis_area_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("IS-IS Areas"))
        for area, count in summary.isis_area_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {area}: {count}"))

    if summary.isis_hostname_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("IS-IS Hostnames"))
        for host, count in summary.isis_hostname_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {host}: {count}"))

    if summary.isis_neighbor_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("IS-IS Neighbors"))
        for nbr, count in summary.isis_neighbor_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {nbr}: {count}"))

    if summary.isis_reachability_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("IS-IS Reachability"))
        for prefix, count in summary.isis_reachability_counts.most_common(
            _limit_value(8)
        ):
            lines.append(muted(f"- {prefix}: {count}"))

    if summary.isis_tlv_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("IS-IS TLVs"))
        for name, count in summary.isis_tlv_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {name}: {count}"))

    if summary.isis_lsp_id_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("IS-IS LSP IDs"))
        for lsp_id, count in summary.isis_lsp_id_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {lsp_id}: {count}"))

    if summary.pim_type_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("PIM Messages"))
        for name, count in summary.pim_type_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {name}: {count}"))

    if summary.pim_group_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("PIM Groups"))
        for group, count in summary.pim_group_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {group}: {count}"))

    if summary.pim_source_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("PIM Sources"))
        for source, count in summary.pim_source_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {source}: {count}"))

    if summary.pim_options_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("PIM Hello Options"))
        for name, count in summary.pim_options_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {name}: {count}"))

    if summary.pim_dr_priority_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("PIM DR Priorities"))
        for pri, count in summary.pim_dr_priority_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {pri}: {count}"))

    if summary.sessions:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Sessions"))
        sessions = sorted(summary.sessions, key=lambda s: s.packets, reverse=True)
        if not verbose:
            sessions = sessions[: _limit_value(12)]
        for sess in sessions:
            ports = ""
            if sess.src_port or sess.dst_port:
                ports = f":{sess.src_port}->{sess.dst_port}"
            detail = f"{sess.protocol} {sess.src_ip}{ports} -> {sess.dst_ip} ({sess.packets} pkts)"
            if sess.details:
                detail = f"{detail} [{sess.details}]"
            lines.append(muted(f"- {detail}"))

    if summary.endpoint_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Endpoints"))
        for name, count in summary.endpoint_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {name}: {count}"))

    if summary.router_id_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Router IDs"))
        for rid, count in summary.router_id_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {rid}: {count}"))

    if summary.asn_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ASNs"))
        for asn, count in summary.asn_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {asn}: {count}"))

    if summary.auth_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Authentication"))
        for name, count in summary.auth_counts.most_common(_limit_value(10)):
            lines.append(muted(f"- {name}: {count}"))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections[: _limit_value(10)]:
            sev = str(item.get("severity", "info")).upper()
            summary_text = _redact_in_text(str(item.get("summary", "")))
            details = _redact_in_text(str(item.get("details", "")))
            sev_color = danger if sev in {"CRITICAL", "HIGH"} else warn
            if sev in {"INFO", "LOW"}:
                sev_color = muted
            lines.append(sev_color(f"[{sev}] {summary_text}"))
            if details:
                lines.append(muted(f"  {details}"))

    if summary.insights:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Insights"))
        for item in summary.insights[: _limit_value(8)]:
            lines.append(muted(f"- {_redact_in_text(str(item))}"))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts"))
        artifact_rows = (
            summary.artifacts if verbose else summary.artifacts[: _limit_value(20)]
        )
        for item in artifact_rows:
            detail = _redact_in_text(str(getattr(item, "detail", item)))
            lines.append(muted(f"- {detail}"))
        if not verbose and len(summary.artifacts) > _limit_value(20):
            lines.append(
                muted(
                    f"... {len(summary.artifacts) - _limit_value(20)} additional artifacts"
                )
            )

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
