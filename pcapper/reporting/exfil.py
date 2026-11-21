"""Rendered output for exfil analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations

from ..exfil import ExfilSummary
from ..utils import (
    format_bytes_as_mb,
    format_duration,
)
from . import _style as st
from ._common import (
    _redact_in_text,
    _render_deterministic_checks,
)
from ._kv import findings_for


def _assessment(summary: ExfilSummary) -> tuple[str, str, int, list[str]]:
    reasons: list[str] = []
    score = 0
    total, outbound = int(summary.total_bytes or 0), int(summary.outbound_bytes or 0)
    ratio = outbound / max(total, 1) if total else 0.0
    if outbound >= 5_000_000:
        score += 2
        reasons.append(f"outbound volume {format_bytes_as_mb(outbound)} exceeds the high-risk threshold")
    if total >= 2_000_000 and ratio >= 0.60:
        score += 1
        reasons.append(f"outbound is {ratio * 100:.1f}% of capture bytes")
    if summary.outbound_flows and int(summary.outbound_flows[0].get("bytes", 0) or 0) >= 5_000_000:
        top = summary.outbound_flows[0]
        score += 2
        reasons.append(f"dominant outbound flow {top.get('src')}->{top.get('dst')} carried {format_bytes_as_mb(int(top.get('bytes', 0)))}")
    if summary.top_external_dsts and outbound >= 3_000_000:
        dst, dst_bytes = summary.top_external_dsts.most_common(1)[0]
        if dst_bytes / max(outbound, 1) >= 0.70:
            score += 1
            reasons.append(f"{dst} received {dst_bytes / max(outbound, 1) * 100:.1f}% of outbound bytes")
    if summary.dns_tunnel_suspects:
        best = 0
        for item in summary.dns_tunnel_suspects:
            try:
                n, unique, long_q = int(item.get("total", 0) or 0), int(item.get("unique", 0) or 0), int(item.get("long", 0) or 0)
                points = sum([n >= 50 and unique >= int(n * 0.85), long_q >= 20, float(item.get("avg_entropy", 0) or 0) >= 3.6,
                              int(item.get("max_label", 0) or 0) >= 45])
            except (TypeError, ValueError):
                continue
            best = max(best, points)
        score += 4 if best >= 2 else 3
        reasons.append(f"{'high-confidence ' if best >= 2 else ''}DNS tunneling heuristics from {len(summary.dns_tunnel_suspects)} source(s)")
    if summary.http_post_suspects:
        score += 1
        reasons.append(f"large HTTP POST channels ({len(summary.http_post_suspects)})")
    if summary.file_exfil_suspects:
        high = [i for i in summary.file_exfil_suspects if int(i.get("risk_score", 0) or 0) >= 5]
        score += 2 if high else 1
        reasons.append(f"suspicious file transfers ({len(summary.file_exfil_suspects)}; high-risk {len(high)})")
    if any(int(i.get("bytes", 0) or 0) >= 1_000_000 for i in summary.ot_flows or []):
        score += 1
        reasons.append("large OT/ICS control-port transfers")
    if score >= 7:
        return "YES - exfiltration likely, corroborated indicators", "High", score, reasons
    if score >= 5:
        return "LIKELY - exfiltration suspected, multiple indicators", "Medium", score, reasons
    if score >= 3:
        return "POSSIBLE - weak-to-moderate exfiltration indicators", "Low", score, reasons
    return "NO STRONG SIGNAL from the current heuristics", "Low", score, reasons


def _flow_rows(flows: list) -> list[list[object]]:
    rows = []
    for item in flows:
        rate = float(item.get("bytes_per_second", 0.0) or 0.0)
        port = item.get("dst_port")
        rows.append([item.get("src", "-"), item.get("dst", "-"), item.get("proto", "-"),
                     port if isinstance(port, int) and port > 0 else "-", st.count(item.get("packets", 0)),
                     st.size(int(item.get("bytes", 0) or 0)), st.duration(float(item.get("duration_seconds", 0.0) or 0.0)),
                     f"{st.size(int(rate * 60))}/min" if rate > 0 else "-"])
    return rows


_FLOW_HEADER = ["Source", "Destination", "Proto", "Port", "Packets", "Bytes", "Duration", "Rate"]


def render_exfil_summary(summary: ExfilSummary, limit: int = 12, verbose: bool = False) -> str:
    """Exfiltration: the largest outbound flows and where the bytes went,
    then the channel-specific evidence -- DNS tunneling, large HTTP POSTs,
    file transfers, OT control-port bulk -- with findings first; internal
    flows, per-protocol checks and the scored assessment are -v."""
    rep = st.Report("Exfiltration", summary.path)
    findings = findings_for(summary, ot=False)
    if not summary.total_packets and not st.material(findings):
        return rep.absent("traffic", summary.errors)
    severity, text = st.verdict(findings, high="exfiltration indicators: investigate", medium="egress to review",
                                clean="no exfiltration indicators")
    total, outbound = int(summary.total_bytes or 0), int(summary.outbound_bytes or 0)
    rep.headline(severity, text, st.join([
        f"{st.size(outbound)} outbound of {st.size(total)}" + (f" ({outbound / total:.0%})" if total else ""),
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
        st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else "",
    ]))
    if summary.top_external_dsts:
        dst, dst_bytes = summary.top_external_dsts.most_common(1)[0]
        rep.scope(f"top destination {dst}: {st.size(dst_bytes)} ({dst_bytes / max(outbound, 1):.0%} of outbound)")
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))
    rep.section("Outbound flows", st.table(_FLOW_HEADER, _flow_rows(summary.outbound_flows), align="lllrrrrr", max_rows=8,
                                           noun="flow"))
    rep.section("DNS tunneling", st.table(
        ["Source", "Queries", "Unique", "Long", "Entropy", "Max label"],
        [[i.get("src", "-"), i.get("total", "-"), i.get("unique", "-"), i.get("long", "-"), i.get("avg_entropy", "-"),
          i.get("max_label", "-")] for i in summary.dns_tunnel_suspects], align="lrrrrr", max_rows=8, noun="source",
    ))
    verbose_view = st.verbose()
    post_rows = []
    for i in summary.http_post_suspects:
        reasons = i.get("risk_reasons", []) or []
        post_rows.append([i.get("src", "-"), i.get("dst", "-"), i.get("host", "-"), i.get("uri", "-"), st.size(int(i.get("bytes", 0) or 0)),
                          int(i.get("requests", 1) or 1), i.get("mode", "single"), int(i.get("risk_score", 0) or 0),
                          _redact_in_text(", ".join(str(r) for r in reasons)) or "-"]
                         + ([str(i.get("packet_examples", i.get("packet", "-")) or "-"), _redact_in_text(str(i.get("sample", "") or "-"))]
                            if verbose_view else []))
    rep.section("HTTP POST", st.table(
        ["Source", "Destination", "Host", "URI", "Bytes", "Requests", "Mode", "Risk", "Why"] + (["Packets", "Sample"] if verbose_view else []),
        post_rows, align="llllrrlrl", widths=(None, None, 32, 40, None, None, None, None, 50), max_rows=8, noun="channel",
    ))
    file_rows = []
    for i in summary.file_exfil_suspects or []:
        score = int(i.get("risk_score", 0) or 0)
        level = "high" if score >= 5 else "medium" if score >= 3 else "low"
        reasons = i.get("risk_reasons", []) or []
        size_val = i.get("size")
        file_rows.append([i.get("src", "-"), i.get("dst", "-"), i.get("protocol", "-"), i.get("filename", "-"), i.get("file_type", "-") or "-",
                          st.size(int(size_val)) if isinstance(size_val, int) else "-",
                          (st.bad if level == "high" else st.caution if level == "medium" else str)(f"{level} ({score})"),
                          i.get("packet", "-"), ", ".join(str(r) for r in reasons) or (i.get("note") or "-")])
    rep.section("File transfers", st.table(
        ["Source", "Destination", "Proto", "File", "Type", "Size", "Risk", "Packet", "Why"], file_rows,
        align="lllllrlrl", widths=(None, None, None, 48), max_rows=8, noun="file",
    ))
    rep.section("OT control-port flows", st.table(_FLOW_HEADER, _flow_rows(summary.ot_flows), align="lllrrrrr", max_rows=8,
                                                  noun="flow"))

    verdict, confidence, score, reasons = _assessment(summary)
    rep.section("Assessment", st.kv([("Verdict", verdict), ("Confidence", f"{confidence} (score={score})")])
                + st.bullets([_redact_in_text(r) for r in reasons], max_items=None), detail=True)
    rep.section("Internal flows", st.table(_FLOW_HEADER, _flow_rows(summary.internal_flows), align="lllrrrrr", max_rows=None),
                detail=True)
    rep.section("External destinations", st.kv([("By bytes", st.top(summary.top_external_dsts, None,
                                                                    fmt=lambda k, v: f"{k} ({st.size(v)})"))]), detail=True)
    rep.section("Files seen", st.table(
        ["Filename", "Size", "Note"],
        [[i.get("filename", "-"), st.size(int(i["size"])) if isinstance(i.get("size"), int) else "-", i.get("note", "-")]
         for i in summary.file_artifacts or []], max_rows=None,
    ), detail=True)
    hyp = [f"[{h.get('confidence', '?')}] {h.get('hypothesis', '-')} (evidence={h.get('evidence', '')})"
           for h in (getattr(summary, "threat_hypotheses", None) or []) if isinstance(h, dict)]
    rep.section("Threat hypotheses", st.bullets(hyp, max_items=None), detail=True)
    rep.section("Benign context", st.bullets([str(b) for b in (getattr(summary, "benign_context", None) or [])], max_items=None),
                detail=True)
    rep.section("Artifacts", st.bullets([str(a) for a in summary.artifacts or []], max_items=None), detail=True)
    rep.section("Traffic", st.kv([("Packets", str(summary.total_packets)), ("Bytes", f"{total} total · {outbound} outbound"),
                                  ("Duration", format_duration(summary.duration_seconds) if summary.duration_seconds is not None else "")]),
                detail=True)
    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic Exfiltration Checks", [
            ("dns_tunnel_indicators", "DNS Tunnel Indicators"), ("http_post_exfil_channels", "HTTP POST Exfil Channels"),
            ("ot_control_channel_exfil", "OT/ICS Control-Channel Exfil"),
            ("internal_staging_then_external_exfil", "Internal Staging -> External Exfil"),
            ("file_exfiltration_candidates", "File Exfiltration Candidates"),
            ("management_port_bulk_transfer", "Management-Port Bulk Transfer"),
            ("uncommon_egress_channels", "Uncommon Egress Channels"),
            ("stealth_low_rate_long_lived_egress", "Stealth Low-Rate Long-Lived Egress"),
        ])
        rep.section("Deterministic checks", legacy[2:])
        protocol_checks = getattr(summary, "protocol_exfil_checks", {}) or {}
        rep.section("Protocol checks", [line for key, label_text in (
            ("dns", "DNS"), ("http_https", "HTTP/HTTPS"), ("icmp", "ICMP"), ("ftp", "FTP"), ("smtp", "SMTP"),
            ("websockets", "WebSockets"), ("ntp", "NTP")) for line in (
            [f"  {st.strong(label_text)}"] + st.bullets([_redact_in_text(str(e)) for e in protocol_checks.get(key, []) or []],
                                                        max_items=None, indent=4)) if protocol_checks.get(key)])
    return rep.render()
