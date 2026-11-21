"""Rendered output for ARP: poisoning and MITM first -- the gateway's MAC
bindings, addresses claimed by more than one MAC, the attack timeline -- then
sweep sources; conversations, rates and fingerprints are -v detail."""

from __future__ import annotations

from ..arp import ArpSummary
from ..ipmac import mac_manufacturer
from . import _style as st
from ._common import _redact_in_text, _render_deterministic_checks
from ._kv import counter_line, findings_for


def _assessment(summary: ArpSummary) -> tuple[str, str, int, list[str]]:
    score = 0
    reasons: list[str] = []
    high = sum(1 for a in summary.anomalies if a.severity in {"HIGH", "CRITICAL"})
    medium = sum(1 for a in summary.anomalies if a.severity == "MEDIUM")
    if high:
        score += min(5, high * 2)
        reasons.append(f"high-severity ARP anomalies ({high})")
    if medium >= 2:
        score += 1
        reasons.append(f"multiple medium-severity ARP anomalies ({medium})")
    if summary.unsolicited_replies >= 20:
        score += 2
        reasons.append(f"elevated unsolicited ARP replies ({summary.unsolicited_replies})")
    if summary.gateway_ip and len(summary.gateway_mac_candidates or {}) > 1:
        score += 2
        reasons.append("gateway ARP MAC mapping changed")
    if summary.gratuitous_arp >= 25:
        score += 1
        reasons.append(f"excess gratuitous ARP ({summary.gratuitous_arp})")
    if (summary.threats or {}).get("ARP Sweep") or (summary.deterministic_checks or {}).get("arp_recon_sweep"):
        score += 2
        reasons.append("ARP host-sweep reconnaissance (subnet mapping)")
    if score >= 7:
        verdict, confidence = "YES - high-confidence ARP poisoning or MITM behavior", "High"
    elif score >= 4:
        verdict, confidence = "LIKELY - suspicious ARP behavior with attack indicators", "Medium"
    elif score >= 2:
        verdict, confidence = "POSSIBLE - potentially malicious ARP behavior; corroborate", "Low"
    else:
        verdict, confidence = "NO STRONG SIGNAL from the current heuristics", "Low"
    return verdict, confidence, score, reasons


def _mac(mac: object) -> str:
    vendor = mac_manufacturer(str(mac))
    return f"{mac} ({vendor})" if vendor and vendor != "-" else str(mac)


def render_arp_summary(summary: ArpSummary, limit: int = 15, verbose: bool = False) -> str:
    rep = st.Report("ARP", summary.path)
    findings = findings_for(summary, ot=False)
    if not summary.arp_packets and not st.material(findings):
        return rep.absent("ARP traffic", summary.errors)
    severity, text = st.verdict(findings, high="ARP poisoning / MITM indicators: investigate",
                                medium="ARP activity to review")
    rep.headline(severity, text, st.join([
        f"{st.count(summary.arp_packets)} ARP packets",
        f"{summary.arp_requests} requests · {summary.arp_replies} replies",
        f"{summary.gratuitous_arp} gratuitous" if summary.gratuitous_arp else "",
        f"{summary.arp_probes} probes" if summary.arp_probes else "",
        st.caution(st.plural(summary.unsolicited_replies, "unsolicited reply", "unsolicited replies"))
        if summary.unsolicited_replies else "",
    ]))
    rep.scope(st.join([
        st.duration(summary.duration) if summary.duration else "",
        f"gateway {summary.gateway_ip}" if summary.gateway_ip else "",
        f"{st.plural(len(summary.src_macs), 'MAC')} · {st.plural(len(summary.src_ips), 'sender address', 'sender addresses')}",
    ]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    gw_macs = summary.gateway_mac_candidates or {}
    rep.section("Gateway", st.table(
        ["Gateway", "MAC", "Replies"],
        [[summary.gateway_ip or "-", (st.bad(_mac(m)) if len(gw_macs) > 1 else _mac(m)), st.count(n)]
         for m, n in sorted(gw_macs.items(), key=lambda kv: -kv[1])],
        align="llr", noun="MAC",
    ))
    conflicts = sorted((summary.victim_conflicts or {}).items(), key=lambda kv: sum(kv[1].values()), reverse=True)
    rep.section("Address conflicts", st.table(
        ["Address", "Claimed by", "Claims"],
        [[ip, ", ".join(f"{_mac(m)} ×{n}" for m, n in macs.most_common()), st.count(sum(macs.values()))] for ip, macs in conflicts],
        align="llr", max_rows=10, noun="address",
    ))
    rep.section("Timeline", st.table(
        ["Time", "Event", "Source", "Destination"],
        [[st.ts(t.ts), _redact_in_text(t.detail), t.src, t.dst] for t in (summary.timeline or [])],
        widths=(None, 80), max_rows=10, noun="event",
    ))
    rep.section("Proxy ARP", st.table(
        ["MAC", "Destination targets", "Claimed addresses"],
        [[_mac(p.get("mac", "-")), p.get("dst_targets", "-"), p.get("claimed_ips", "-")] for p in (summary.proxy_arp_candidates or [])],
        max_rows=10,
    ))
    rep.section("Activity", st.kv([
        counter_line("Top requesters", summary.client_details, 6),
        counter_line("Top responders", summary.server_details, 6),
        counter_line("Threats", summary.threats, 6),
    ]))

    # ---- reference (-v) --------------------------------------------------
    verdict, confidence, score, reasons = _assessment(summary)
    rep.section("Assessment", st.kv([("Verdict", verdict), ("Confidence", f"{confidence} (score={score})")])
                + st.bullets(reasons, max_items=None), detail=True)
    latency = summary.reply_latency_summary or {}
    rep.section("Reply timing", st.kv([
        ("Median reply latency", f"{float(latency.get('median_s', 0.0)) * 1000.0:.2f} ms" if latency else ""),
        ("p95 reply latency", f"{float(latency.get('p95_s', 0.0)) * 1000.0:.2f} ms" if latency else ""),
        ("Samples", str(int(float(latency.get("samples", 0.0)))) if latency else ""),
    ]), detail=True)
    rep.section("Request rates", st.table(
        ["Source", "Requests", "Packets/s"],
        [[src, st.count(n), f"{float((summary.pps_by_source or {}).get(src, 0.0)):.2f}"] for src, n in summary.client_details.most_common()],
        align="lrr", max_rows=None,
    ), detail=True)
    rep.section("Conversations", st.table(
        ["Source IP", "Destination IP", "Source MAC", "Destination MAC", "Opcode", "Packets", "First", "Last"],
        [[c.src_ip, c.dst_ip, c.src_mac, c.dst_mac, c.opcode, st.count(c.packets), st.ts(c.first_seen), st.ts(c.last_seen)]
         for c in summary.conversations], align="lllllrll", max_rows=None,
    ), detail=True)
    rep.section("Request/reply pairs", st.table(
        ["Client", "Server", "Requests", "Replies", "First", "Last"],
        [[s.client_ip, s.server_ip, s.requests, s.replies, st.ts(s.first_seen), st.ts(s.last_seen)] for s in summary.sessions],
        align="llrrll", max_rows=None,
    ), detail=True)
    rep.section("Counters", st.kv([
        counter_line("Opcodes", summary.opcode_counts, None),
        counter_line("Response types", summary.response_codes, None),
        counter_line("Request types", summary.request_summary, None),
        counter_line("Source IPs", summary.src_ips, None),
        counter_line("Destination IPs", summary.dst_ips, None),
        counter_line("Source MACs", summary.src_macs, None),
        counter_line("Destination MACs", summary.dst_macs, None),
        counter_line("Client fingerprints", summary.client_versions, None),
        counter_line("Server fingerprints", summary.server_versions, None),
        counter_line("Rate peaks", getattr(summary, "rate_peaks", None), None),
        ("Anomalies dropped", str(getattr(summary, "anomalies_dropped", 0) or "")),
    ]), detail=True)
    rep.section("Context", st.bullets([_redact_in_text(str(x)) for x in (summary.benign_indicators or [])]
                                      + [_redact_in_text(str(x)) for x in (summary.risk_factors or [])], max_items=None),
                detail=True)
    rep.section("Artifacts", st.table(
        ["Kind", "Detail", "Flow", "Time"],
        [[a.kind, _redact_in_text(str(a.detail)), st.flow(a.src, a.dst), st.ts(a.ts)] for a in summary.artifacts], max_rows=None,
    ), detail=True)
    rep.section("Plaintext", st.table(["String", "Count"], [[t, st.count(n)] for t, n in summary.plaintext_observed.most_common()],
                                      align="lr", max_rows=None), detail=True)
    rep.section("Files", st.bullets([str(f) for f in summary.files_discovered or []], max_items=None), detail=True)
    rep.section("Traffic", st.kv([("Duration", f"{summary.duration:.2f}s"),
                                  ("Packets", f"{summary.total_packets} total · {summary.arp_packets} ARP")]), detail=True)

    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic ARP Security Checks", [
            ("gateway_integrity", "Gateway ARP Integrity"), ("poisoning_pair_pattern", "Poisoning Pair Pattern"),
            ("unsolicited_reply_abuse", "Unsolicited Reply Abuse"), ("broadcast_unsolicited_reply", "Broadcast Unsolicited Replies"),
            ("rapid_gateway_mac_flip", "Rapid Gateway MAC Flip"), ("recon_to_poison_progression", "Recon-to-Poison Progression"),
            ("arp_recon_sweep", "ARP Recon/Sweep Activity"), ("probe_spray", "ARP Probe Spray"),
            ("arp_storm_flood", "ARP Flood/Storm"), ("duplicate_ip_ownership", "Duplicate IP Ownership"),
            ("proxy_arp_misuse", "Proxy ARP Misuse"), ("timing_automation_signal", "Timing/Automation Signal"),
            ("likely_benign_failover", "Likely Benign Failover"),
        ])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
