"""Rendered output for --health: findings, TCP vitals (handshakes,
resets, windows, retransmissions, TTL), hosts at risk, degradation chains,
OT cycle safety, SNMP exposure and certificate hygiene; throughput, QoS,
talkers, flow-duration buckets, outlier windows and OT cycle timing are
-v detail."""

from __future__ import annotations

from collections import Counter

from ..health import HealthSummary
from ..utils import (
    format_duration,
    format_speed_bps,
    format_ts,
)
from . import _style as st
from ._common import _redact_in_text, _redact_secret, _render_deterministic_checks
from ._kv import counter_line


def render_health_summary(summary: HealthSummary) -> str:
    """Traffic health: findings first, then the TCP vitals (handshakes,
    resets, zero windows, retransmissions), TTL problems and per-host risk;
    throughput, QoS, SNMP, certificate counts, flow-duration buckets and OT
    cycle timing follow (timing and outlier windows are -v)."""
    rep = st.Report("Health", summary.path)
    findings = [st.finding(f) for f in (summary.findings or [])]
    if not summary.total_packets and not st.material(findings):
        return rep.absent("traffic", summary.errors)
    severity, text = st.verdict(findings, high="network health problems that affect evidence or operations",
                                medium="health issues to review", clean="no health problems")
    dur = summary.duration_seconds
    # A rollup's first..last spans unrelated captures: no duration or rate.
    single = not st.is_rollup(summary)
    rep.headline(severity, text, st.join([
        f"{st.count(summary.total_packets)} packets ({summary.tcp_packets} TCP, {summary.udp_packets} UDP)",
        st.size(summary.total_bytes), st.duration(dur) if dur and single else "",
        f"{format_speed_bps(int(summary.total_bytes * 8 / dur))}" if dur and single else "",
    ]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    syn_only = max(0, summary.tcp_syn - summary.tcp_syn_ack)
    rst_ratio = summary.tcp_rst / summary.tcp_syn if summary.tcp_syn else 0.0
    rep.section("TCP", st.kv([
        ("Handshakes", f"SYN {summary.tcp_syn} · SYN-ACK {summary.tcp_syn_ack} · unanswered {syn_only}"),
        ("Resets", f"{summary.tcp_rst} ({rst_ratio:{'.2%' if st.verbose() else '.0%'}} of SYN)"
                   + (f" · from {st.top(summary.tcp_rst_sources, 4)}" if summary.tcp_rst_sources else "")),
        ("Windows", f"zero {summary.tcp_zero_window} · small {summary.tcp_small_window}"
                    + (f" · zero from {st.top(summary.tcp_zero_window_sources, 4)}" if summary.tcp_zero_window_sources else "")),
        ("Retransmissions", f"{summary.retransmissions} ({summary.retransmission_rate:.2%})"),
        ("TTL / hop limit", f"expired {summary.ttl_expired} · low (<=5) {summary.ttl_low}"),
        ("UDP amplification", f"{len(summary.udp_amp_candidates)}: " + ", ".join(summary.udp_amp_candidates[:5]) if summary.udp_amp_candidates else ""),
    ]))
    hosts = list(getattr(summary, "host_risk_profiles", None) or [])
    rep.section("Hosts at risk", st.table(
        ["Host", "Score", "Severity", "Confidence", "SYN", "RST", "Zero win", "Targets", "Reasons"],
        [[i.get("host", "-"), i.get("score", "-"), str(i.get("severity", "-")).upper(), str(i.get("confidence", "-")).upper(),
          i.get("syn", "-"), i.get("rst", "-"), i.get("zero_window", "-"), i.get("targets", "-"),
          " | ".join(str(r) for r in (i.get("reasons") or []))] for i in hosts],
        align="lrllrrrrl", widths=(None, None, None, None, None, None, None, None, 72), max_rows=10, noun="host",
    ))
    rep.section("Degradation", st.table(
        ["Sequence", "Confidence", "Details"],
        [[i.get("sequence", "-"), str(i.get("confidence", "-")).upper(), i.get("details", "-")] for i in (getattr(summary, "sequence_findings", None) or [])],
        widths=(None, None, 90), max_rows=10,
    ))
    rep.section("OT safety", st.table(
        ["Family", "Session", "Avg (s)", "Std (s)", "CV", "Samples", "Severity"],
        [[i.get("family", "-"), i.get("session", "-"), f"{float(i.get('avg', 0.0)):.3f}", f"{float(i.get('std', 0.0)):.3f}",
          f"{float(i.get('cv', 0.0)):.2f}", i.get("count", "-"), str(i.get("severity", "-")).upper()]
         for i in (getattr(summary, "ot_risk_profiles", None) or [])], align="llrrrrl", max_rows=10,
    ))
    rep.section("SNMP", st.kv([
        ("Packets", str(summary.snmp_packets) if summary.snmp_packets else ""),
        counter_line("Versions", summary.snmp_versions, 5),
        ("Communities", st.top(summary.snmp_communities, 5, fmt=lambda k, v: f"{_redact_secret(str(k))} ({v})")),
    ]) + st.table(["Risk", "Details"], [[i.get("risk", "-"), i.get("details", "-")] for i in (getattr(summary, "snmp_risks", None) or [])],
                  widths=(None, 96), max_rows=10))
    rep.section("Certificates", st.kv([("Expired / invalid", str(summary.expired_certs) if summary.expired_certs else ""),
                                       ("Self-signed", str(summary.self_signed_certs) if summary.self_signed_certs else "")]))

    rep.section("Assessment", st.kv([
        ("Verdict", summary.analyst_verdict or "NO STRONG SIGNAL from the current heuristics"),
        ("Confidence", (summary.analyst_confidence or "low").strip().lower()),
    ]) + st.bullets([_redact_in_text(str(r)) for r in (summary.analyst_reasons or [])], max_items=None), detail=True)
    rep.section("Throughput", st.kv([
        ("Window", f"{format_ts(summary.first_seen)} / {format_ts(summary.last_seen)}"),
        ("Duration", format_duration(dur)),
        ("Packets/s · bits/s", f"{summary.total_packets / dur:.2f} · {format_speed_bps(int(summary.total_bytes * 8 / dur))}"
         if dur and single else ""),
        counter_line("DSCP", summary.dscp_counts, None),
        counter_line("ECN", summary.ecn_counts, None),
        counter_line("SYN sources", getattr(summary, "tcp_syn_sources", None), None),
    ]), detail=True)
    endpoint_packets = summary.endpoint_packets if isinstance(summary.endpoint_packets, Counter) else Counter()
    endpoint_bytes = summary.endpoint_bytes if isinstance(summary.endpoint_bytes, Counter) else Counter()
    rep.section("Top talkers", st.table(
        ["Endpoint", "Packets", "Bytes"], [[ip, st.count(endpoint_packets.get(ip, 0)), st.size(b)] for ip, b in endpoint_bytes.most_common()],
        align="lrr", max_rows=None,
    ), detail=True)
    order = ["<=1s", "1-10s", "10-60s", "1-5m", "5-30m", ">30m"]
    rep.section("Flow durations", st.kv([
        (label_text, f"{st.sparkline_of([int(b.get(k, 0)) for k in order])}  " + ", ".join(f"{k} {int(b.get(k, 0))}" for k in order))
        for key, label_text in (("all", "All"), ("tcp", "TCP"), ("udp", "UDP"))
        for b in [summary.flow_duration_buckets.get(key, Counter())] if b
    ]), detail=True)
    rep.section("Outlier windows", st.table(
        ["Metric", "Start", "End", "Value", "Baseline", "Threshold", "Sample"],
        [[i.get("metric", "-"), st.ts(i.get("window_start")), st.ts(i.get("window_end")), i.get("value", "-"), i.get("baseline", "-"),
          i.get("threshold", "-"), i.get("sample", "-")] for i in (getattr(summary, "outlier_windows", None) or [])], max_rows=None,
    ), detail=True)
    timing: list[str] = []
    for key, label_text in (("profinet_rt", "Profinet RT"), ("enip_io", "ENIP IO"), ("s7_rosctr", "S7 COTP/ROSCTR")):
        entries = (summary.ot_timing or {}).get(key, [])
        if entries:
            timing.append(f"  {st.strong(label_text)}")
            timing += st.table(["Session", "Avg (s)", "Std (s)", "CV", "Min", "Max", "Samples"],
                               [[e.get("session", "-"), f"{float(e.get('avg', 0.0)):.3f}", f"{float(e.get('std', 0.0)):.3f}",
                                 f"{float(e.get('cv', 0.0)):.2f}", f"{float(e.get('min', 0.0)):.3f}", f"{float(e.get('max', 0.0)):.3f}",
                                 e.get("count", 0)] for e in entries], align="lrrrrrr", max_rows=None)
    rep.section("OT cycle timing", timing, detail=True)
    rep.section("Zoning", st.bullets([_redact_in_text(str(z)) for z in (summary.zone_anomalies or [])], max_items=None), detail=True)
    rep.section("Evidence anchors", st.table(
        ["Packet", "Signal", "Details"], [[i.get("packet", "-"), i.get("signal", "-"), i.get("details", "-")]
                                          for i in (getattr(summary, "evidence_anchors", None) or [])], max_rows=None,
    ), detail=True)
    rep.section("False-positive context", st.bullets([_redact_in_text(str(b)) for b in (getattr(summary, "benign_context", None) or [])],
                                                     max_items=None), detail=True)
    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic Health Security Checks", [
            ("syn_scan_or_exhaustion", "SYN Scan or Service Exhaustion"), ("tcp_reset_storm", "TCP Reset Storm"),
            ("persistent_zero_window", "Persistent Zero-Window"), ("udp_reflection_amplification", "UDP Reflection/Amplification"),
            ("qos_marking_anomaly", "QoS Marking Anomaly"), ("snmp_exposure_risk", "SNMP Exposure Risk"),
            ("ot_cycle_instability", "OT Cycle-Time Instability"), ("certificate_hygiene_risk", "Certificate Hygiene Risk"),
            ("sequence_degradation_chain", "Sequence Degradation Chain"), ("zone_policy_drift", "Peer Trust Zoning Drift"),
            ("evidence_provenance", "Evidence Provenance"),
        ])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
