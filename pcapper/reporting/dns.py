"""Rendered output for DNS analysis (plus mDNS and LLMNR).

Default view: findings with their client/server pivots, zone transfers,
transaction-integrity violations, reputation hits, the query and response
mix, the most and the rarest queried domains, clients and resolvers. -v adds
the analyzer's assessment score, every statistic and every anomaly table
(drift, abuse profiles, TTL/CNAME outliers, amplification, timeline,
packet-length analysis, multicast streams, mDNS detail).
"""

from __future__ import annotations

from ..dns import PUBLIC_DNS_RESOLVERS, DnsSummary, rcode_name
from ..utils import format_bytes_as_mb, format_duration, sparkline
from . import _style as st
from ._common import _filtered_detections, _redact_in_text
from ._kv import counter_line


def _dns_type_name(type_id: int) -> str:
    # IANA DNS RR TYPEs (https://www.iana.org/assignments/dns-parameters).
    name = {
        1: "A",
        2: "NS",
        3: "MD",
        4: "MF",
        5: "CNAME",
        6: "SOA",
        7: "MB",
        8: "MG",
        9: "MR",
        10: "NULL",
        11: "WKS",
        12: "PTR",
        13: "HINFO",
        14: "MINFO",
        15: "MX",
        16: "TXT",
        17: "RP",
        18: "AFSDB",
        24: "SIG",
        25: "KEY",
        28: "AAAA",
        29: "LOC",
        33: "SRV",
        35: "NAPTR",
        36: "KX",
        37: "CERT",
        39: "DNAME",
        41: "OPT",
        42: "APL",
        43: "DS",
        44: "SSHFP",
        45: "IPSECKEY",
        46: "RRSIG",
        47: "NSEC",
        48: "DNSKEY",
        49: "DHCID",
        50: "NSEC3",
        51: "NSEC3PARAM",
        52: "TLSA",
        53: "SMIMEA",
        55: "HIP",
        59: "CDS",
        60: "CDNSKEY",
        61: "OPENPGPKEY",
        62: "CSYNC",
        63: "ZONEMD",
        64: "SVCB",
        65: "HTTPS",
        99: "SPF",
        108: "EUI48",
        109: "EUI64",
        249: "TKEY",
        250: "TSIG",
        251: "IXFR",
        252: "AXFR",
        253: "MAILB",
        254: "MAILA",
        255: "ANY",
        256: "URI",
        257: "CAA",
        32768: "TA",
        32769: "DLV",
    }.get(type_id)
    if name:
        return name
    if type_id == 0 or 65280 <= type_id <= 65535:
        return "RESERVED"
    return "UNASSIGNED"

_dns_rcode_name = rcode_name

def _dns_opcode_name(opcode_id: int) -> str:
    # IANA DNS OpCodes. 3 and 7-15 are unassigned/reserved; their presence on
    # port 53 usually means malformed traffic, a non-DNS protocol parsed as
    # DNS, or deliberate tunneling/evasion rather than a real DNS operation.
    name = {
        0: "QUERY",
        1: "IQUERY",
        2: "STATUS",
        4: "NOTIFY",
        5: "UPDATE",
        6: "DSO",
    }.get(opcode_id)
    if name:
        return name
    return "RESERVED/UNASSIGNED"


def _labelled(counter: object, namer) -> str:  # type: ignore[no-untyped-def]
    """``A (52), NXDOMAIN (4)``; -v adds the numeric code: ``A/1 (52)``."""
    def fmt(k: object, v: object) -> str:
        try:
            name = namer(int(k))
        except (TypeError, ValueError):
            return f"{k} ({st.count(v)})"
        return f"{name}/{k} ({st.count(v)})" if st.verbose() else f"{name} ({st.count(v)})"
    return st.top(counter, 8, lambda k, v: fmt(k, v)) if counter else ""


def _vt(summary: DnsSummary, name: str) -> str:
    if not summary.vt_results:
        return ""
    parts = [p for p in name.strip(".").split(".") if p]
    info = summary.vt_results.get(name) or summary.vt_results.get(".".join(parts[-2:]) if len(parts) >= 2 else name)
    return f"{info.get('score', '-')} {info.get('rating', '-')}" if info else ""


def _assessment(summary: DnsSummary) -> list[str]:
    """The analyzer's DNS abuse score: warning detections, high-signal checks,
    transaction violations and resolver drift."""
    score, reasons = 0, []
    warn_count = sum(1 for d in (summary.detections or []) if str(d.get("severity", "")).lower() == "warning")
    if warn_count:
        score += min(3, warn_count)
        reasons.append(f"Warning-level DNS detections observed ({warn_count})")
    checks = summary.deterministic_checks if isinstance(summary.deterministic_checks, dict) else {}
    for key in ("dns_tunneling_indicators", "dga_like_behavior", "fast_flux_or_rebinding",
                "zone_transfer_attempt", "dnssec_or_integrity_anomaly", "amplification_abuse_signal"):
        if checks.get(key):
            score += 1
            reasons.append(f"{key.replace('_', ' ')} evidence observed ({len(checks[key])})")
    if summary.transaction_violations:
        score += 2
        reasons.append(f"Transaction integrity violations observed ({len(summary.transaction_violations)})")
    if summary.resolver_drift:
        score += 1
        reasons.append(f"Resolver drift observed ({len(summary.resolver_drift)} clients)")
    verdict = ("YES - high-confidence suspicious DNS abuse or compromise indicators" if score >= 8 else
               "LIKELY - significant suspicious DNS behavior" if score >= 5 else
               "POSSIBLE - weak-to-moderate suspicious DNS indicators" if score >= 2 else
               "NO STRONG SIGNAL - no convincing high-risk DNS pattern")
    confidence = "High" if score >= 8 else "Medium" if score >= 5 else "Low"
    return st.kv([("Verdict", verdict), ("Confidence", f"{confidence} (score={score})")]) + st.bullets(
        reasons or ["No high-confidence DNS threat heuristic crossed threshold"], max_items=None)


def render_dns_summary(summary: DnsSummary, limit: int = 12, verbose: bool = False) -> str:
    rep = st.Report("DNS", summary.path)
    detections = _filtered_detections(summary, st.verbose() or verbose)
    findings = [st.finding(d) for d in detections]
    if not summary.total_packets and not st.material(findings):
        return rep.absent("DNS traffic", summary.errors)
    rows = None if (st.verbose() or verbose) else 8
    severity, text = st.verdict(
        findings,
        high="high-severity DNS activity (tunneling, DGA, spoofing, transfer): investigate the clients below",
        medium="suspicious DNS behaviour to review",
    )
    rep.headline(severity, text, st.join([
        f"{st.count(summary.total_packets)} DNS packets ({st.count(summary.query_packets)} queries / "
        f"{st.count(summary.response_packets)} responses)",
        st.size(summary.total_bytes),
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
        st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else "",
    ]))
    rep.scope(st.join([
        f"{st.plural(summary.unique_clients, 'client')} -> {st.plural(summary.unique_servers, 'server')}",
        st.plural(summary.unique_qnames, "unique name"),
        f"{st.count(summary.llmnr_packets)} LLMNR" if summary.llmnr_packets else "",
        f"{st.count(summary.mdns_packets)} mDNS" if summary.mdns_packets else "",
    ]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    if summary.zone_transfer_requests:
        rep.section("Zone transfer requests", [f"  {st.bad(', '.join(sorted(summary.zone_transfer_requests)))}"])
    rep.section("Transaction integrity violations", st.table(
        ["DNS ID", "Source", "Destination", "Time"],
        [[v.get("id", "-"), v.get("src", "-"), v.get("dst", "-"), st.ts(v.get("ts"))] for v in (summary.transaction_violations or [])],
        max_rows=rows, noun="violation",
    ))
    vt_hits = [v for v in (summary.vt_results or {}).values() if int(v.get("score", 0) or 0) > 0]
    rep.section("Reputation (VirusTotal)", st.table(
        ["Domain", "Score", "Rating", "Reputation", "Last analysis"],
        [[v.get("domain", "-"), v.get("score", "-"), v.get("rating", "-"), v.get("reputation", "-"),
          st.ts(v.get("last_analysis_date")) if v.get("last_analysis_date") else "-"]
         for v in sorted(vt_hits, key=lambda e: int(e.get("score", 0) or 0), reverse=True)],
        align="lrlrl", max_rows=rows,
    ) if vt_hits else ([f"  {st.dim('no malicious or suspicious hits in the sampled domains')}"] if summary.vt_results else []))

    rep.section("Queries", st.kv([
        ("Types", _labelled(summary.type_counts, _dns_type_name)),
        ("Responses", _labelled(summary.rcode_counts, _dns_rcode_name)),
        ("Opcodes", _labelled(summary.opcode_counts, _dns_opcode_name)
         if any(int(k) != 0 for k in (summary.opcode_counts or {}) if str(k).isdigit()) else ""),
        ("TXT names", ", ".join(sorted(summary.txt_query_names)[: None if st.verbose() else 8])
         + (st.dim(f" +{len(summary.txt_query_names) - 8} more") if len(summary.txt_query_names) > 8 and not st.verbose() else "")),
    ]))

    def _domain_rows(items: list) -> list:
        return [[name, st.count(n)] + ([_vt(summary, name) or "-"] if summary.vt_results else []) for name, n in items]

    vt_col = ["VT"] if summary.vt_results else []
    # The top 10 and the bottom 10 (the rarest) registered domains; -v all.
    rep.section("Domains", st.ranked(["Base domain", "Queries"] + vt_col, _domain_rows(summary.base_domain_counts.most_common()),
                                     align="lr", noun="domain", **({"max_rows": None} if rows is None else {})))
    rep.section("Resolvers and clients", st.kv([
        counter_line("Clients", summary.client_counts),
        counter_line("Servers", summary.server_counts),
        ("Public resolvers", st.top(summary.public_resolver_counts, 5,
                                    lambda k, v: f"{k} {PUBLIC_DNS_RESOLVERS.get(k, '')} ({st.count(v)})".replace("  ", " "))
         if summary.public_resolver_counts else ""),
        counter_line("LLMNR clients", summary.llmnr_client_counts),
        counter_line("LLMNR responders", summary.llmnr_server_counts),
    ]))

    # ---- reference material (-v) ----------------------------------------
    rep.section("Assessment", _assessment(summary), detail=True)
    q_resp = f"{summary.query_packets / max(1, summary.response_packets):.2f}" if summary.response_packets else "-"
    rep.section("Traffic", st.kv([
        ("DNS packets", str(summary.total_packets)),
        ("DNS bytes", format_bytes_as_mb(summary.total_bytes)),
        ("Queries / responses", f"{summary.query_packets} / {summary.response_packets} (ratio {q_resp})"),
        ("UDP / TCP", f"{summary.udp_packets} / {summary.tcp_packets}"),
        ("Clients / servers / names", f"{summary.unique_clients} / {summary.unique_servers} / {summary.unique_qnames}"),
        ("First / last seen", f"{st.ts(summary.first_seen)} / {st.ts(summary.last_seen)}"),
        ("Duration", format_duration(summary.duration_seconds)),
        ("EDNS0 OPT records", str(summary.edns0_opt_count) if getattr(summary, "edns0_opt_count", 0) else ""),
        ("LLMNR", f"{summary.llmnr_packets} packets · {summary.llmnr_query_packets} queries · "
                  f"{summary.llmnr_response_packets} responses" if summary.llmnr_packets else ""),
    ]), detail=True)
    rep.section("Flags and sizes", st.kv([
        counter_line("Flags", summary.flag_counts, None),
        ("Query sizes", ", ".join(f"{k} {v:.1f}" if isinstance(v, float) else f"{k} {v}" for k, v in (summary.query_size_stats or {}).items())),
        ("Response sizes", ", ".join(f"{k} {v:.1f}" if isinstance(v, float) else f"{k} {v}" for k, v in (summary.response_size_stats or {}).items())),
        ("Query types (all)", _labelled(summary.qtype_counts, _dns_type_name) if getattr(summary, "qtype_counts", None) else ""),
    ]), detail=True)
    rep.section("All names", st.table(["Name", "Queries"] + vt_col, _domain_rows(summary.qname_counts.most_common()),
                                      align="lr", max_rows=None), detail=True)
    rep.section("TLDs", [f"  {st.top(summary.tld_counts, None)}"] if summary.tld_counts else [], detail=True)

    def _answers(mapping: dict) -> list:
        cands = [(n, a) for n, a in (mapping or {}).items() if len(a) > 1]
        return [[n, st.count(len(a)), ", ".join(sorted(a))] for n, a in sorted(cands, key=lambda kv: len(kv[1]), reverse=True)]

    rep.section("Answer variability (names)", st.table(["Name", "Answers", "Values"], _answers(summary.answers_by_qname),
                                                       align="lrl", max_rows=None), detail=True)
    rep.section("Answer variability (base domains)", st.table(["Domain", "Answers", "Values"], _answers(summary.base_domain_answers),
                                                              align="lrl", max_rows=None), detail=True)
    rep.section("Resolver drift", st.table(
        ["Client", "Resolvers", "Public", "Private", "Top resolvers"],
        [[d.get("client", "-"), d.get("resolver_count", "-"), d.get("public", "-"), d.get("private", "-"),
          ", ".join(f"{ip} ({n})" for ip, n in (d.get("top_resolvers") or [])[:3])] for d in (summary.resolver_drift or [])],
        align="lrrrl", max_rows=None), detail=True)
    rep.section("Client abuse profiles", st.table(
        ["Client", "Queries", "Unique", "Unique ratio", "Avg entropy", "NXDOMAIN", "TXT", "Long"],
        [[p.get("client", "-"), p.get("queries", "-"), p.get("unique_qnames", "-"), p.get("unique_ratio", "-"),
          p.get("avg_entropy", "-"), p.get("nxdomain", "-"), p.get("txt_queries", "-"), p.get("long_queries", "-")]
         for p in (summary.client_abuse_profiles or [])],
        align="lrrrrrrr", max_rows=None), detail=True)
    rep.section("Periodicity", st.table(
        ["Profile"], [[str(p)] for p in (getattr(summary, "periodicity_profiles", None) or [])], max_rows=None), detail=True)
    rep.section("TTL outliers", st.table(
        ["Name", "Samples", "Unique TTL", "Min TTL", "Max TTL"],
        [[t.get("qname", "-"), t.get("samples", "-"), t.get("unique_ttl", "-"), t.get("min_ttl", "-"), t.get("max_ttl", "-")]
         for t in (summary.ttl_outliers or [])], align="lrrrr", max_rows=None), detail=True)
    rep.section("CNAME anomalies", st.table(
        ["Name", "Targets", "Sample targets"],
        [[c.get("qname", "-"), c.get("target_count", "-"), ", ".join(str(v) for v in (c.get("targets") or [])[:3])]
         for c in (summary.cname_anomalies or [])], align="lrl", max_rows=None), detail=True)
    rep.section("Amplification candidates", st.table(
        ["Client", "Resolver", "Query bytes", "Response bytes", "Ratio"],
        [[a.get("client", "-"), a.get("resolver", "-"), a.get("query_bytes", "-"), a.get("response_bytes", "-"), a.get("ratio", "-")]
         for a in (summary.amplification_candidates or [])], align="llrrr", max_rows=None), detail=True)
    rep.section("Timeline", st.table(
        ["Time", "Event", "Summary", "Details"],
        [[st.ts(t.get("ts")), t.get("event", "-"), _redact_in_text(str(t.get("summary", "-"))),
          _redact_in_text(str(t.get("details", "-")))] for t in (summary.timeline or [])], max_rows=None), detail=True)
    rep.section("False-positive context", st.bullets([_redact_in_text(str(b)) for b in (summary.benign_context or [])],
                                                     max_items=None), detail=True)
    rep.section("Local and OT names", st.kv([
        counter_line("Unicast local-TLD queries", summary.local_unicast_qname_counts, None),
        counter_line("OT/ICS keywords", summary.ot_keyword_counts, None),
        counter_line("OT/ICS hostnames", summary.ot_qname_counts, None),
        ("TXT query names", ", ".join(sorted(summary.txt_query_names))),
    ]), detail=True)

    if summary.mdns_packets:
        share = summary.mdns_packets / summary.total_packets * 100.0 if summary.total_packets else 0.0
        ratio = (summary.mdns_query_packets / max(1, summary.mdns_response_packets)
                 if summary.mdns_response_packets else float(summary.mdns_query_packets))
        rep.section("mDNS", st.kv([
            ("Packets", f"{summary.mdns_packets} ({share:.2f}% of DNS packets)"),
            ("Queries / responses", f"{summary.mdns_query_packets} / {summary.mdns_response_packets} (ratio {ratio:.2f})"),
            ("Error responses", str(summary.mdns_error_responses)),
            ("Clients / responders", f"{summary.unique_mdns_clients} / {summary.unique_mdns_servers}"),
            ("Names / services", f"{len(summary.mdns_qname_counts)} / {len(summary.mdns_service_counts)}"),
            ("Query types", _labelled(summary.mdns_qtype_counts, _dns_type_name)),
            counter_line("Clients", summary.mdns_client_counts, None),
            counter_line("Responders", summary.mdns_server_counts, None),
            counter_line("Names", summary.mdns_qname_counts, None),
            counter_line("Services", summary.mdns_service_counts, None),
        ]), detail=True)

    stats = list(summary.packet_length_stats or [])
    if stats:
        total = summary.total_packets or sum(int(i.get("count", 0) or 0) for i in stats)

        def _bounds(label_text: str) -> tuple[int, object]:
            if label_text.endswith("+"):
                return (int(label_text[:-1]) if label_text[:-1].isdigit() else 0), None
            low, _, high = label_text.partition("-")
            return (int(low) if low.isdigit() else 0), (int(high) if high.isdigit() else 0)

        short = long_ = 0
        dominant, dominant_pct = None, 0.0
        outliers = []
        threshold = max(50, int(total * 0.25)) if total else 50
        for i in stats:
            label_text, n = str(i.get("bucket", "-")), int(i.get("count", 0) or 0)
            pct = n / total * 100 if total else 0.0
            low, high = _bounds(label_text)
            notes = []
            if high is not None and high <= 100:
                short += n
                notes.append("very short")
            if low >= 1201:
                long_ += n
                notes.append("very long")
            notes.append("dominant") if pct >= 40.0 else (notes.append("high count") if n >= threshold else None)
            if pct > dominant_pct:
                dominant, dominant_pct = label_text, pct
            if notes:
                outliers.append(f"{label_text}: {n} ({pct:.1f}%) {', '.join(notes)}")
        length_head = st.kv([
            ("Very short (<=100B)", f"{short} ({(short / total * 100 if total else 0.0):.1f}%)"),
            ("Very large (>=1201B)", f"{long_} ({(long_ / total * 100 if total else 0.0):.1f}%)"),
            ("Dominant bucket", f"{dominant} ({dominant_pct:.1f}%)" if dominant else ""),
            ("Outlier buckets", "; ".join(outliers)),
        ]) + [""]
        rep.section("Packet lengths", length_head + st.table(
            ["Bucket", "Count", "Avg", "Min", "Max", "Rate pkt/s", "%", "Burst rate", "Burst start"],
            [[i.get("bucket", "-"), i.get("count", "-"), f"{i.get('avg', 0):.1f}", i.get("min", "-"), i.get("max", "-"),
              f"{i.get('rate', 0):.2f}", f"{i.get('pct', 0):.1f}%", f"{i.get('burst_rate', 0):.0f}",
              st.ts(i.get("burst_start")) if i.get("burst_start") else "-"] for i in stats],
            align="lrrrrrrrl", max_rows=None,
        ) + [f"  {st.dim('distribution')} {sparkline([int(i.get('count', 0) or 0) for i in stats])}  "
             f"{st.dim(f'of {total} packets')}"], detail=True)
    rep.section("Multicast streams", st.table(
        ["Group", "Protocol", "Port", "Packets", "Bytes", "Sources", "First", "Last"],
        [[m.get("group", "-"), m.get("protocol", "-"), m.get("port", "-"), m.get("count", "-"),
          format_bytes_as_mb(int(m.get("bytes", 0))), ", ".join(f"{ip} ({n})" for ip, n in (m.get("sources") or [])),
          st.ts(m.get("first_seen")), st.ts(m.get("last_seen"))] for m in (summary.multicast_streams or [])],
        align="lllrrlll", max_rows=None), detail=True)
    return rep.render()
