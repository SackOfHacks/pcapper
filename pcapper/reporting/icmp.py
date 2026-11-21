"""Rendered output for ICMP: sweeps, tunneling and control-plane abuse
first, the message types seen and the payloads they carried (where covert
channels hide), then echo sessions; asymmetry, cadence, zone and role
profiles are -v detail."""

from __future__ import annotations

from ..icmp import IcmpSummary
from ..utils import format_ts
from . import _style as st
from ._common import _render_deterministic_checks
from ._kv import counter_line, findings_for


def _icmpv4_type_name(type_id: int) -> str:
    return {
        0: "Echo Reply",
        3: "Destination Unreachable",
        4: "Source Quench",
        5: "Redirect",
        8: "Echo Request",
        9: "Router Advertisement",
        10: "Router Solicitation",
        11: "Time Exceeded",
        12: "Parameter Problem",
        13: "Timestamp",
        14: "Timestamp Reply",
        15: "Information Request",
        16: "Information Reply",
        17: "Address Mask Request",
        18: "Address Mask Reply",
    }.get(type_id, "Unknown")

def _icmpv4_code_name(type_id: int, code_id: int) -> str:
    if type_id == 3:
        return {
            0: "Network Unreachable",
            1: "Host Unreachable",
            2: "Protocol Unreachable",
            3: "Port Unreachable",
            4: "Fragmentation Needed",
            5: "Source Route Failed",
            6: "Network Unknown",
            7: "Host Unknown",
            8: "Host Isolated",
            9: "Network Prohibited",
            10: "Host Prohibited",
            11: "Network Unreachable for TOS",
            12: "Host Unreachable for TOS",
            13: "Communication Prohibited",
            14: "Host Precedence Violation",
            15: "Precedence Cutoff",
        }.get(code_id, "Unknown")
    if type_id == 5:
        return {
            0: "Redirect for Network",
            1: "Redirect for Host",
            2: "Redirect for TOS and Network",
            3: "Redirect for TOS and Host",
        }.get(code_id, "Unknown")
    if type_id == 11:
        return {
            0: "TTL Exceeded in Transit",
            1: "Fragment Reassembly Time Exceeded",
        }.get(code_id, "Unknown")
    if type_id == 12:
        return {
            0: "Pointer Indicates Error",
            1: "Missing Required Option",
            2: "Bad Length",
        }.get(code_id, "Unknown")
    return "Unknown"

def _icmpv6_type_name(type_id: int) -> str:
    return {
        1: "Destination Unreachable",
        2: "Packet Too Big",
        3: "Time Exceeded",
        4: "Parameter Problem",
        128: "Echo Request",
        129: "Echo Reply",
        133: "Router Solicitation",
        134: "Router Advertisement",
        135: "Neighbor Solicitation",
        136: "Neighbor Advertisement",
        137: "Redirect",
    }.get(type_id, "Unknown")

def _icmpv6_code_name(type_id: int, code_id: int) -> str:
    if type_id == 1:
        return {
            0: "No Route to Destination",
            1: "Admin Prohibited",
            2: "Beyond Scope",
            3: "Address Unreachable",
            4: "Port Unreachable",
            5: "Source Address Failed Policy",
            6: "Reject Route",
        }.get(code_id, "Unknown")
    if type_id == 3:
        return {
            0: "Hop Limit Exceeded",
            1: "Fragment Reassembly Time Exceeded",
        }.get(code_id, "Unknown")
    if type_id == 4:
        return {
            0: "Erroneous Header Field",
            1: "Unrecognized Next Header",
            2: "Unrecognized IPv6 Option",
        }.get(code_id, "Unknown")
    return "Unknown"

def _type_label(key: str) -> str:
    try:
        family, type_id = key.split(":", 1)
        type_num = int(type_id)
    except Exception:
        return key
    if family == "icmpv4":
        return f"ICMPv4 {_icmpv4_type_name(type_num)} [{type_num}]"
    if family == "icmpv6":
        return f"ICMPv6 {_icmpv6_type_name(type_num)} [{type_num}]"
    return key

def _code_label(key: str) -> str:
    try:
        family, type_id, code_id = key.split(":", 2)
        type_num = int(type_id)
        code_num = int(code_id)
    except Exception:
        return key
    if family == "icmpv4":
        return f"ICMPv4 {_icmpv4_type_name(type_num)}: {_icmpv4_code_name(type_num, code_num)} [{type_num}/{code_num}]"
    if family == "icmpv6":
        return f"ICMPv6 {_icmpv6_type_name(type_num)}: {_icmpv6_code_name(type_num, code_num)} [{type_num}/{code_num}]"
    return key


def _rows(profiles: list, keys: tuple[str, ...]) -> list[list[object]]:
    return [[p.get(k, "-") for k in keys] for p in profiles if isinstance(p, dict)]


def render_icmp_summary(summary: IcmpSummary, limit: int = 12, verbose: bool = False) -> str:
    rep = st.Report("ICMP", summary.path)
    findings = findings_for(summary, ot=False)
    if not summary.total_packets and not st.material(findings):
        return rep.absent("ICMP traffic", summary.errors)
    severity, text = st.verdict(findings, high="ICMP abuse (tunneling, redirects, sweeps): investigate",
                                medium="ICMP activity to review")
    dur = summary.duration_seconds
    rep.headline(severity, text, st.join([
        f"{st.count(summary.total_packets)} ICMP packets ({summary.ipv4_packets} v4, {summary.ipv6_packets} v6)",
        st.size(summary.total_bytes),
        st.duration(dur) if dur else "",
        f"{summary.total_packets / dur:.1f} pkt/s" if dur else "",
        st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else "",
    ]))
    rep.scope(st.join([f"{st.plural(len(summary.src_ips), 'source')} -> {st.plural(len(summary.dst_ips), 'destination')}",
                       f"payload avg {summary.avg_payload_bytes:.0f} B, max {summary.max_payload_bytes} B, "
                       f"{summary.payload_size_variants} sizes"]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    rep.section("Types", st.kv([("Types", st.top(summary.type_counts, 8, fmt=lambda k, v: f"{_type_label(str(k))} ({st.count(v)})"))]))
    rep.section("Recon", st.table(["Source", "Targets", "Packets", "Confidence"],
                                  _rows(list(summary.recon_profiles or []), ("source", "targets", "packets", "confidence")),
                                  align="lrrl", max_rows=8, noun="source"))
    rep.section("Tunneling", st.table(["Entropy", "Size", "Count", "Preview", "Confidence"],
                                      _rows(list(summary.tunneling_profiles or []), ("entropy", "size", "count", "preview", "confidence")),
                                      align="rrrll", max_rows=8, noun="profile"))
    rep.section("Control plane", st.table(["Type", "Count", "Confidence"],
                                          _rows(list(summary.control_plane_profiles or []), ("type", "count", "confidence")),
                                          align="lrl", max_rows=8))
    rep.section("Payloads", st.table(
        ["Payload (preview)", "Count", "Size", "Entropy", "Sources", "Destinations"],
        [[p.get("payload_preview", "-"), st.count(p.get("count", 0)), p.get("size", "-"), f"{p.get('entropy', 0):.2f}",
          ", ".join(f"{ip} ({n})" for ip, n in p.get("top_sources", [])) or "-",
          ", ".join(f"{ip} ({n})" for ip, n in p.get("top_destinations", [])) or "-"] for p in summary.payload_summaries],
        align="lrrrll", widths=(48, None, None, None, 36, 36), noun="payload",
        max_rows=st.TOP_ROWS, tail=st.TOP_ROWS, total=getattr(summary, "payload_digests", 0) or None,
    ))
    rep.section("Echo sessions", st.table(
        ["Source", "Destination", "ID", "Requests", "Replies", "First", "Last"],
        [[s.get("src", "-"), s.get("dst", "-"), s.get("id", "-"), s.get("requests", "-"), s.get("replies", "-"),
          st.ts(s.get("first_seen")), st.ts(s.get("last_seen"))] for s in summary.sessions],
        align="lllrrll", max_rows=8, noun="session",
    ))

    # ---- reference (-v) --------------------------------------------------
    verdict = str(getattr(summary, "analyst_verdict", "") or "")
    confidence = str(getattr(summary, "analyst_confidence", "") or "")
    rep.section("Assessment", st.kv([("Verdict", verdict), ("Confidence", confidence)])
                + st.bullets([str(r) for r in (getattr(summary, "analyst_reasons", None) or [])], max_items=None), detail=True)
    rep.section("Codes", st.kv([("Codes", st.top(summary.code_counts, None, fmt=lambda k, v: f"{_code_label(str(k))} ({v})"))]),
                detail=True)
    categories = sorted(set(summary.request_counts) | set(summary.response_counts))
    rep.section("Requests and responses", st.table(
        ["Category", "Requests", "Responses"],
        [[c, st.count(summary.request_counts.get(c, 0)), st.count(summary.response_counts.get(c, 0))] for c in categories],
        align="lrr", max_rows=None,
    ), detail=True)
    for title, field_name, header_row, keys in (
        ("Asymmetry", "asymmetry_profiles", ["Scope", "Requests", "Replies", "Reply ratio", "Confidence"],
         ("scope", "requests", "replies", "reply_ratio", "confidence")),
        ("Fragmentation", "fragmentation_profiles", ["Packet too big", "Fragmentation related", "Confidence"],
         ("packet_too_big", "fragmentation_related", "confidence")),
        ("Cadence", "cadence_profiles", ["Flow", "Packets", "Duration (s)", "Packets/s", "Confidence"],
         ("flow", "packets", "duration_s", "pps", "confidence")),
        ("Zones", "zone_profiles", ["Source", "Destination", "Zone", "Packets", "Confidence"],
         ("src", "dst", "zone", "packets", "confidence")),
        ("Role drift", "role_drift_profiles", ["Host", "Destination", "Packets", "Reason", "Confidence"],
         ("host", "dst", "packets", "reason", "confidence")),
        ("OT boundary", "ot_boundary_profiles", ["Source", "Destination", "Packets", "Confidence"],
         ("src", "dst", "packets", "confidence")),
    ):
        rep.section(title, st.table(header_row, _rows(list(getattr(summary, field_name, None) or []), keys), max_rows=None),
                    detail=True)
    rep.section("Corroborated", st.table(
        ["Host", "Score", "Confidence", "Reasons"],
        [[f.get("host", "-"), f.get("score", "-"), f.get("confidence", "-"), ", ".join(str(r) for r in f.get("reasons", []) or [])]
         for f in (summary.corroborated_findings or []) if isinstance(f, dict)], max_rows=None,
    ), detail=True)
    rep.section("Conversations", st.table(
        ["Source", "Destination", "Proto", "Packets", "Bytes", "First", "Last"],
        [[c.get("src", "-"), c.get("dst", "-"), c.get("protocol", "-"), st.count(c.get("packets", 0)), st.size(c.get("bytes", 0)),
          st.ts(c.get("first_seen")), st.ts(c.get("last_seen"))]
         for c in sorted(summary.conversations, key=lambda c: c.get("packets", 0), reverse=True)],
        align="lllrrll", max_rows=None,
    ), detail=True)
    rep.section("Endpoints", st.kv([
        ("Sources", ", ".join(sorted(summary.src_ips))), ("Destinations", ", ".join(sorted(summary.dst_ips))),
        counter_line("Top sources", summary.src_ip_counts, None), counter_line("Top destinations", summary.dst_ip_counts, None),
        ("Artifacts", ", ".join(summary.artifacts or [])), counter_line("Users", summary.observed_users, None),
        ("Files", ", ".join(summary.files_discovered or [])),
    ]), detail=True)
    rep.section("False-positive context", st.bullets([str(v) for v in (summary.false_positive_context or []) if str(v).strip()],
                                                     max_items=None), detail=True)
    rep.section("Traffic", st.kv([("First / last seen", f"{format_ts(summary.first_seen)} / {format_ts(summary.last_seen)}"),
                                  ("Avg / max payload", f"{summary.avg_payload_bytes:.1f} / {summary.max_payload_bytes} bytes")]),
                detail=True)

    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic ICMP Security Checks", [
            ("icmp_recon_sweep_behavior", "ICMP recon/sweep behavior"),
            ("icmp_control_plane_abuse", "ICMP control-plane abuse"),
            ("icmp_tunneling_signal", "ICMP tunneling/covert signal"),
            ("icmp_zone_boundary_exposure", "ICMP internet-boundary crossing"),
        ])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
