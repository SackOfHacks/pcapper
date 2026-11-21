"""Rendered output for routing protocols (OSPF, BGP, IS-IS, EIGRP, RIP,
PIM, VRRP/HSRP): route-injection and authentication findings first, then
who speaks which protocol (routers, ASNs, sessions) and what they announce;
per-protocol counters are -v detail."""

from __future__ import annotations

from ..routing import RoutingSummary
from . import _style as st
from ._common import _redact_in_text
from ._kv import counter_line, findings_for


def render_routing_summary(summary: RoutingSummary, limit: int = 200, verbose: bool = False) -> str:
    rep = st.Report("Routing", summary.path)
    findings = findings_for(summary, ot=False)
    if not summary.routing_packets and not st.material(findings):
        return rep.absent("routing protocol traffic", summary.errors)
    severity, text = st.verdict(findings, high="routing manipulation risk (unauthenticated peers, injection): investigate",
                                medium="routing activity to review")
    rep.headline(severity, text, st.join([
        f"{st.count(summary.routing_packets)} routing packets",
        st.top(summary.protocol_counts, 6),
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
    ]))
    rep.scope(st.join([st.plural(len(summary.endpoint_counts), "speaker"), st.plural(len(summary.sessions), "session")]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))
    rep.section("Routers", st.kv([
        counter_line("Router IDs", summary.router_id_counts, 8),
        counter_line("ASNs", summary.asn_counts, 8),
        counter_line("IS-IS hosts", summary.isis_hostname_counts, 8),
        counter_line("VRRP VRIDs", getattr(summary, "vrid_counts", None), 6),
        counter_line("HSRP groups", getattr(summary, "hsrp_group_counts", None), 6),
        counter_line("Authentication", summary.auth_counts, 6),
    ]))
    rep.section("Announcements", st.kv([
        counter_line("BGP announced", summary.bgp_prefix_counts, 8),
        counter_line("BGP withdrawn", summary.bgp_withdraw_counts, 8),
        counter_line("BGP next hops", summary.bgp_next_hop_counts, 6),
        counter_line("BGP AS paths", summary.bgp_as_path_counts, 4),
        counter_line("OSPF advertising routers", summary.lsa_adv_router_counts, 6),
        counter_line("IS-IS reachability", summary.isis_reachability_counts, 6),
        counter_line("PIM groups", summary.pim_group_counts, 6),
    ]))
    sessions = sorted(summary.sessions, key=lambda s: s.packets, reverse=True)
    rep.section("Sessions", st.table(
        ["Protocol", "Source", "Destination", "Packets", "First", "Last", "Details"],
        [[s.protocol, f"{s.src_ip}:{s.src_port}" if s.src_port else s.src_ip, f"{s.dst_ip}:{s.dst_port}" if s.dst_port else s.dst_ip,
          st.count(s.packets), st.ts(s.first_seen), st.ts(s.last_seen), _redact_in_text(str(s.details or "-"))] for s in sessions],
        align="lllrlll", widths=(None, None, None, None, None, None, 50), max_rows=12, noun="session",
    ))
    rep.section("Insights", st.bullets([_redact_in_text(str(i)) for i in summary.insights or []], max_items=8, noun="insight"))

    rep.section("Protocol detail", st.kv([
        counter_line("Messages", summary.message_counts, None),
        counter_line("OSPF LSA types", summary.lsa_type_counts, None),
        counter_line("OSPF LSA IDs", summary.lsa_id_counts, None),
        ("OSPF MaxAge / high-seq LSAs", f"{getattr(summary, 'lsa_maxage_count', 0)} / {getattr(summary, 'lsa_seq_high_count', 0)}"),
        counter_line("BGP path attributes", summary.bgp_path_attr_counts, None),
        counter_line("IS-IS system IDs", summary.isis_system_id_counts, None),
        counter_line("IS-IS areas", summary.isis_area_counts, None),
        counter_line("IS-IS neighbors", summary.isis_neighbor_counts, None),
        counter_line("IS-IS TLVs", summary.isis_tlv_counts, None),
        counter_line("IS-IS LSP IDs", summary.isis_lsp_id_counts, None),
        ("IS-IS high-seq LSPs", str(getattr(summary, "isis_lsp_seq_high_count", 0) or "")),
        counter_line("PIM messages", summary.pim_type_counts, None),
        counter_line("PIM sources", summary.pim_source_counts, None),
        counter_line("PIM hello options", summary.pim_options_counts, None),
        counter_line("PIM DR priorities", summary.pim_dr_priority_counts, None),
        counter_line("Endpoints", summary.endpoint_counts, None),
    ]), detail=True)
    artifacts: dict[tuple[str, str, str, str], int] = {}  # each distinct artifact once, with how often
    for a in summary.artifacts:
        key = (str(getattr(a, "kind", "") or ""), _redact_in_text(str(getattr(a, "detail", a))),
               str(getattr(a, "src", "") or ""), str(getattr(a, "dst", "") or ""))
        artifacts[key] = artifacts.get(key, 0) + 1
    rep.section("Artifacts", st.table(
        ["Kind", "Value", "Seen from", "To", "Times"],
        [[kind.replace("_", " ") or "-", value, src or "-", dst or "-", n] for (kind, value, src, dst), n in artifacts.items()],
        align="llllr", max_rows=None,
    ), detail=True)
    rep.section("Traffic", st.kv([("Packets", f"{summary.total_packets} total · {summary.routing_packets} routing"),
                                  ("Window", st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else ""),
                                  ("Duration", f"{summary.duration_seconds:.1f}s" if summary.duration_seconds is not None else "")]),
                detail=True)
    return rep.render()
