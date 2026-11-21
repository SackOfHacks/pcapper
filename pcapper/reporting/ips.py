"""Rendered output for --ips (IP intelligence): findings and threat-intel
hits first, then every host -- internal or external, its role (server,
client, scanner, DC ...), names, geo/ASN and the services it offered --
then top talkers, scanners, lateral movement and TLS reputation. Endpoint,
conversation and profile tables are -v."""

from __future__ import annotations

from collections import Counter

from ..ips import IpSummary
from ..utils import format_duration, format_ts
from ..utils import is_public_ip as _is_public_ip
from . import _style as st
from ._common import _render_deterministic_checks, _short_browser_role
from ._kv import counter_line, findings_for

_CATEGORY_ORDER = ["public", "private", "multicast", "broadcast", "loopback", "link_local", "reserved", "unspecified", "invalid",
                   "unknown"]


def _intel_signal(item: dict) -> tuple[str, str]:
    source = str(item.get("source", ""))
    details: list[str] = []
    signal = "-"
    if source == "AbuseIPDB":
        if item.get("score") is not None:
            signal = f"score {item.get('score')}"
        for key in ("reports", "usage", "country"):
            if item.get(key):
                details.append(f"{key} {item.get(key)}")
    elif source == "OTX":
        if item.get("pulses") is not None:
            signal = f"pulses {item.get('pulses')}"
    elif source == "VirusTotal":
        signal = f"mal {item.get('malicious')} / sus {item.get('suspicious')}"
        if item.get("harmless") is not None:
            details.append(f"harmless {item.get('harmless')}")
    return signal, "; ".join(details) or "-"


def render_ips_summary(summary: IpSummary, limit: int = 12, verbose: bool = False) -> str:
    rep = st.Report("IP intelligence", summary.path)
    findings = findings_for(summary, ot=False)
    if not summary.total_packets and not st.material(findings):
        return rep.absent("IP traffic", summary.errors)
    severity, text = st.verdict(findings, high="high-severity IP activity: investigate", medium="IP activity to review")
    rep.headline(severity, text, st.join([
        f"{st.plural(summary.unique_ips, 'IP')} ({summary.ipv4_count} v4, {summary.ipv6_count} v6)",
        f"{st.count(summary.total_packets)} packets · {st.size(summary.total_bytes)}",
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
        st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else "",
    ]))
    rep.scope(st.join([f"{st.plural(summary.unique_sources, 'source')} -> {st.plural(summary.unique_destinations, 'destination')}",
                       f"{summary.tls_client_hellos} TLS ClientHellos" if summary.tls_client_hellos else ""]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    intel = list(summary.intel_findings or [])
    rep.section("Threat intel", st.table(
        ["IP", "Source", "Signal", "Details"], [[i.get("ip", "-"), i.get("source", "-"), *_intel_signal(i)] for i in intel],
        max_rows=15, noun="hit",
    ))

    endpoints = {ep.ip: ep for ep in summary.endpoints}
    confirmed = {str(ip): sorted({int(p) for p in (ports or []) if isinstance(p, int) or str(p).isdigit()})
                 for ip, ports in (getattr(summary, "confirmed_tcp_service_ports", {}) or {}).items()}
    scanners = {str(p.get("src", "")) for p in (summary.suspicious_port_profiles or []) if p.get("src")}
    enrichment = getattr(summary, "ip_enrichment", {}) or {}
    roles = getattr(summary, "ip_roles", {}) or {}
    os_by_ip = getattr(summary, "ip_os", {}) or {}
    host_rows = []
    ranked_ips = sorted(set(summary.ip_mac_counts) | set(endpoints),
                        key=lambda ip: -((endpoints[ip].bytes_sent + endpoints[ip].bytes_recv) if ip in endpoints else 0))
    for ip in ranked_ips:
        external = _is_public_ip(ip)
        role = _short_browser_role(roles.get(ip, [])) or ("scanner" if ip in scanners else "server" if confirmed.get(ip) else "client")
        names = sorted(((summary.ip_hostnames or {}).get(ip, Counter())).items(), key=lambda kv: (-kv[1], kv[0]))
        name_text = ", ".join(n for n, _ in names[:2]) or "-"
        if os_by_ip.get(ip):
            name_text = f"{name_text} [{os_by_ip[ip].split(' (')[0]}]" if name_text != "-" else f"[{os_by_ip[ip].split(' (')[0]}]"
        enr = enrichment.get(ip, {})
        geo = [str(enr.get("country") or enr.get("geo") or "")] + [str(enr.get("asn") or enr.get("org") or "")]
        flags = [f for f in ("hosting", "proxy", "mobile") if enr.get(f)]
        geo_text = " · ".join(g for g in geo if g) + (f" [{','.join(flags)}]" if flags else "")
        ep = endpoints.get(ip)
        macs = ", ".join(sorted((summary.ip_mac_counts or {}).get(ip, {}))) or "-"
        host_rows.append([
            st.bad(ip) if external and ip in scanners else ip, f"{'ext' if external else 'int'}/{role}", name_text,
            geo_text or ("-" if external else "internal"), ",".join(str(p) for p in confirmed.get(ip, [])[:8]) or "-",
            f"{st.size(ep.bytes_sent + ep.bytes_recv)} ({ep.packets_sent}/{ep.packets_recv} pkts)" if ep else "-",
        ] + ([macs] if st.verbose() else []))
    rep.section("Hosts", st.table(
        ["IP", "Class/role", "Hostname", "Geo / ASN", "Serves", "Traffic"] + (["MACs"] if st.verbose() else []), host_rows,
        widths=(None, None, 40, 40, 24), max_rows=st.TOP_ROWS, tail=st.TOP_ROWS, noun="host",
    ))
    total = summary.total_packets or 1
    def _share(k: object, v: object) -> str:
        return f"{k} ({v} packets, {v / total:.1%})" if st.verbose() else f"{k} ({v / total:.0%})"

    rep.section("Top talkers", st.kv([("Sources", st.top(summary.src_counts, 6, fmt=_share)),
                                      ("Destinations", st.top(summary.dst_counts, 6, fmt=_share))]))
    rep.section("Scanners", st.table(
        ["Type", "Source", "Ports", "Targets", "High ports"],
        [[p.get("type", "-"), p.get("src", "-"), p.get("unique_ports", "-"), p.get("unique_dsts", "-"), p.get("high_ports", "-")]
         for p in summary.suspicious_port_profiles or []], align="llrrr", max_rows=10, noun="source",
    ))
    rep.section("Lateral movement", st.table(
        ["IP", "Score", "Peers", "Ports", "Packets sent"],
        [[i.get("ip", "-"), i.get("score", "-"), i.get("peers", "-"), i.get("ports", "-"), i.get("packets_sent", "-")]
         for i in sorted(summary.lateral_movement_scores or [], key=lambda x: x.get("score", 0), reverse=True)],
        align="lrrrr", max_rows=5, noun="host",
    ))
    rep.section("TLS reputation", st.table(
        ["Type", "Fingerprint", "Label", "Count"],
        [[i.get("type", "-"), i.get("fingerprint", "-"), st.bad(str(i.get("label", "-"))), i.get("count", "-")]
         for i in summary.ja_reputation_hits or []], max_rows=10,
    ) + st.table(
        ["Server", "Risk", "Details"],
        [[st.flow(i.get("src", "-"), i.get("dst", "-")), r.get("type", "-"), r.get("details", "-")]
         for i in summary.tls_cert_risks or [] for r in (i.get("risks") or []) if isinstance(r, dict)], max_rows=10,
    ))

    rep.section("Assessment", st.kv([("Verdict", str(getattr(summary, "analyst_verdict", "") or "")),
                                     ("Confidence", str(getattr(summary, "analyst_confidence", "") or ""))])
                + st.bullets([str(r) for r in (getattr(summary, "analyst_reasons", None) or [])], max_items=None), detail=True)

    def _profile(title: str, field: str, header_row: list[str], keys: list[str]) -> None:
        rows = [[", ".join(str(x) for x in p.get(k)) if isinstance(p.get(k), (list, tuple, set)) else p.get(k, "-") for k in keys]
                for p in (getattr(summary, field, None) or []) if isinstance(p, dict)]
        rep.section(title, st.table(header_row, rows, max_rows=None), detail=True)

    _profile("Priority assets", "priority_asset_profiles", ["IP", "Score", "Peers", "Ports", "Packets sent", "Confidence"],
             ["ip", "score", "peers", "ports", "packets_sent", "confidence"])
    _profile("Exposure", "exposure_profiles", ["Source", "Destination", "Protocol", "Direction", "Packets", "Bytes", "Confidence"],
             ["src", "dst", "protocol", "direction", "packets", "bytes", "confidence"])
    _profile("Corroborated", "corroborated_findings", ["IP", "Score", "Confidence", "Reasons"], ["ip", "score", "confidence", "reasons"])
    _profile("Infrastructure clusters", "infrastructure_clusters", ["Cluster", "IPs", "Members", "Confidence"],
             ["cluster", "ip_count", "ips", "confidence"])
    _profile("Intent", "intent_profiles", ["Source", "Destination", "Protocol", "Ports", "Intent", "Confidence"],
             ["src", "dst", "protocol", "ports", "intent", "confidence"])
    rep.section("Protocols and addressing", st.kv([
        ("Protocols", st.top(summary.protocol_counts, None, fmt=lambda k, v: f"{k} ({v}, {v / total:.1%})")),
        ("Addressing", ", ".join(f"{c.replace('_', ' ')} ({summary.ip_category_counts[c]})" for c in _CATEGORY_ORDER
                                 if summary.ip_category_counts.get(c, 0))),
        counter_line("SNI", getattr(summary, "sni_counts", None), None),
        counter_line("JA3", getattr(summary, "ja3_counts", None), None),
        counter_line("JA4", getattr(summary, "ja4_counts", None), None),
        counter_line("JA4S", getattr(summary, "ja4s_counts", None), None),
    ]), detail=True)
    eps = sorted(summary.endpoints, key=lambda e: e.bytes_sent + e.bytes_recv, reverse=True)
    rep.section("Endpoints", st.table(
        ["IP", "Sent", "Received", "Total", "Peers", "Ports", "Protocols", "Geo", "ASN", "First", "Last", "Duration"],
        [[e.ip, st.size(e.bytes_sent), st.size(e.bytes_recv), st.size(e.bytes_sent + e.bytes_recv), len(e.peers),
          ",".join(str(p) for p in e.ports) or "-", ",".join(e.protocols) or "-", e.geo or "-", e.asn or "-", format_ts(e.first_seen),
          format_ts(e.last_seen), format_duration(e.last_seen - e.first_seen) if e.first_seen is not None and e.last_seen is not None else "-"]
         for e in eps], align="lrrrrlllllll", max_rows=None,
    ), detail=True)
    rep.section("Conversations", st.table(
        ["Source", "Destination", "Proto", "Packets", "Bytes", "Duration", "Ports"],
        [[c.src, c.dst, c.protocol, st.count(c.packets), st.size(c.bytes),
          format_duration(c.last_seen - c.first_seen) if c.first_seen is not None and c.last_seen is not None else "-",
          ",".join(str(p) for p in c.ports) or "-"] for c in sorted(summary.conversations, key=lambda c: c.bytes, reverse=True)],
        align="lllrrll", max_rows=None,
    ), detail=True)
    rep.section("False-positive context", st.bullets([str(v) for v in (getattr(summary, "false_positive_context", None) or [])],
                                                     max_items=None), detail=True)
    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic IPS Security Checks", [
            ("indicator_quality_gate", "Indicator quality gate"), ("boundary_cross_zone_contact", "Boundary cross-zone contact"),
            ("corroborated_multi_signal_hit", "Corroborated multi-signal hit"), ("intent_heuristics", "Intent heuristics"),
            ("evidence_provenance", "Evidence provenance"),
        ])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
