"""Rendered output for health analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from collections import Counter
from ..coloring import (
    danger,
    header,
    label,
    muted,
    ok,
    warn,
)
from ..health import HealthSummary
from ..utils import (
    format_bytes_as_mb,
    format_duration,
    format_speed_bps,
    format_ts,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
    _redact_in_text,
    _truncate_text,
)


def render_health_summary(summary: HealthSummary) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"TRAFFIC HEALTH :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("TCP Packets", str(summary.tcp_packets)))
    lines.append(_format_kv("UDP Packets", str(summary.udp_packets)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Throughput"))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))
    if summary.duration_seconds:
        pps = summary.total_packets / summary.duration_seconds
        bps = (summary.total_bytes / summary.duration_seconds) * 8
        lines.append(_format_kv("Packets/sec", f"{pps:.2f}"))
        lines.append(_format_kv("Bits/sec", format_speed_bps(int(bps))))

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    verdict = (
        summary.analyst_verdict
        or "NO STRONG SIGNAL - no convincing high-confidence health risk pattern from current heuristics"
    )
    confidence = (summary.analyst_confidence or "low").strip().lower()
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", confidence.capitalize()))
    if summary.analyst_reasons:
        lines.append(muted("Why confidence:"))
        for reason in summary.analyst_reasons[: _limit_value(8)]:
            lines.append(muted(f"- {_redact_in_text(str(reason))}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Health Security Checks"))
    checks = summary.deterministic_checks or {}
    check_labels = [
        ("syn_scan_or_exhaustion", "SYN Scan or Service Exhaustion"),
        ("tcp_reset_storm", "TCP Reset Storm"),
        ("persistent_zero_window", "Persistent Zero-Window"),
        ("udp_reflection_amplification", "UDP Reflection/Amplification"),
        ("qos_marking_anomaly", "QoS Marking Anomaly"),
        ("snmp_exposure_risk", "SNMP Exposure Risk"),
        ("ot_cycle_instability", "OT Cycle-Time Instability"),
        ("certificate_hygiene_risk", "Certificate Hygiene Risk"),
        ("sequence_degradation_chain", "Sequence Degradation Chain"),
        ("zone_policy_drift", "Peer Trust Zoning Drift"),
        ("evidence_provenance", "Evidence Provenance"),
    ]
    for key, label_text in check_labels:
        evidence_items = [
            str(v) for v in list(checks.get(key, []) or []) if str(v).strip()
        ]
        lines.append(label(label_text))
        if evidence_items:
            lines.append(
                warn(
                    f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"
                )
            )
            for item in evidence_items[: _limit_value(6)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))
        else:
            lines.append(
                ok(
                    f"No, there is no strong evidence for {label_text.lower()} in this capture."
                )
            )

    sequence_rows = list(getattr(summary, "sequence_findings", []) or [])
    if sequence_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Sequence-Based Degradation Checks"))
        rows = [["Sequence", "Confidence", "Details"]]
        for item in sequence_rows[: _limit_value(10)]:
            rows.append(
                [
                    str(item.get("sequence", "-")),
                    str(item.get("confidence", "-")).upper(),
                    _truncate_text(str(item.get("details", "-")), 90),
                ]
            )
        lines.append(_format_table(rows))

    host_rows = list(getattr(summary, "host_risk_profiles", []) or [])
    if host_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Per-Host Risk Profiles"))
        rows = [
            [
                "Host",
                "Score",
                "Severity",
                "Confidence",
                "SYN",
                "RST",
                "ZeroWin",
                "Targets",
                "Reasons",
            ]
        ]
        for item in host_rows[: _limit_value(12)]:
            reasons = item.get("reasons", [])
            reason_text = (
                " | ".join(str(v) for v in reasons[:3])
                if isinstance(reasons, list)
                else str(reasons)
            )
            rows.append(
                [
                    str(item.get("host", "-")),
                    str(item.get("score", "-")),
                    str(item.get("severity", "-")).upper(),
                    str(item.get("confidence", "-")).upper(),
                    str(item.get("syn", "-")),
                    str(item.get("rst", "-")),
                    str(item.get("zero_window", "-")),
                    str(item.get("targets", "-")),
                    _truncate_text(reason_text or "-", 72),
                ]
            )
        lines.append(_format_table(rows))

    outlier_rows = list(getattr(summary, "outlier_windows", []) or [])
    if outlier_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Temporal Outlier Windows"))
        rows = [
            [
                "Metric",
                "Window Start",
                "Window End",
                "Value",
                "Baseline",
                "Threshold",
                "Sample",
            ]
        ]
        for item in outlier_rows[: _limit_value(12)]:
            rows.append(
                [
                    str(item.get("metric", "-")),
                    format_ts(item.get("window_start")),
                    format_ts(item.get("window_end")),
                    str(item.get("value", "-")),
                    str(item.get("baseline", "-")),
                    str(item.get("threshold", "-")),
                    _truncate_text(str(item.get("sample", "-")), 72),
                ]
            )
        lines.append(_format_table(rows))

    snmp_rows = list(getattr(summary, "snmp_risks", []) or [])
    if snmp_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SNMP Security Analytics"))
        rows = [["Risk", "Details"]]
        for item in snmp_rows[: _limit_value(10)]:
            rows.append(
                [
                    str(item.get("risk", "-")),
                    _truncate_text(str(item.get("details", "-")), 96),
                ]
            )
        lines.append(_format_table(rows))

    ot_rows = list(getattr(summary, "ot_risk_profiles", []) or [])
    if ot_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT Health Safety Checks"))
        rows = [["Family", "Session", "Avg(s)", "Std(s)", "CV", "Samples", "Severity"]]
        for item in ot_rows[: _limit_value(10)]:
            rows.append(
                [
                    str(item.get("family", "-")),
                    _truncate_text(str(item.get("session", "-")), 44),
                    f"{float(item.get('avg', 0.0)):.3f}",
                    f"{float(item.get('std', 0.0)):.3f}",
                    f"{float(item.get('cv', 0.0)):.2f}",
                    str(item.get("count", "-")),
                    str(item.get("severity", "-")).upper(),
                ]
            )
        lines.append(_format_table(rows))

    if summary.zone_anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Peer Trust Zoning Checks"))
        for item in summary.zone_anomalies[: _limit_value(10)]:
            lines.append(muted(f"- {_redact_in_text(str(item))}"))

    anchors = list(getattr(summary, "evidence_anchors", []) or [])
    if anchors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Evidence Anchors"))
        rows = [["Packet", "Signal", "Details"]]
        for item in anchors[: _limit_value(12)]:
            rows.append(
                [
                    str(item.get("packet", "-")),
                    str(item.get("signal", "-")),
                    _truncate_text(str(item.get("details", "-")), 88),
                ]
            )
        lines.append(_format_table(rows))

    benign = list(getattr(summary, "benign_context", []) or [])
    if benign:
        lines.append(SUBSECTION_BAR)
        lines.append(header("False-Positive Context"))
        for item in benign[: _limit_value(8)]:
            lines.append(muted(f"- {_redact_in_text(str(item))}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Retransmissions"))
    lines.append(_format_kv("TCP Retransmissions", str(summary.retransmissions)))
    lines.append(
        _format_kv("Retransmission Rate", f"{summary.retransmission_rate:.2%}")
    )

    if summary.endpoint_bytes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Talkers"))
        rows = [["Endpoint", "Packets", "Bytes"]]
        endpoint_packets = (
            summary.endpoint_packets
            if isinstance(summary.endpoint_packets, Counter)
            else Counter()
        )
        endpoint_bytes = (
            summary.endpoint_bytes
            if isinstance(summary.endpoint_bytes, Counter)
            else Counter()
        )
        for ip, byte_count in endpoint_bytes.most_common(_limit_value(10)):
            rows.append(
                [
                    ip,
                    str(endpoint_packets.get(ip, 0)),
                    format_bytes_as_mb(byte_count),
                ]
            )
        lines.append(_format_table(rows))

    if summary.flow_duration_buckets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Flow Duration Distribution"))
        bucket_order = ["<=1s", "1-10s", "10-60s", "1-5m", "5-30m", ">30m"]
        for key, label_text in (("all", "All"), ("tcp", "TCP"), ("udp", "UDP")):
            buckets = summary.flow_duration_buckets.get(key, Counter())
            if not buckets:
                continue
            counts = [int(buckets.get(bucket, 0)) for bucket in bucket_order]
            lines.append(_format_kv(f"{label_text} Buckets", ", ".join(bucket_order)))
            lines.append(
                _format_kv(
                    f"{label_text} Counts", ", ".join(str(val) for val in counts)
                )
            )

    lines.append(SUBSECTION_BAR)
    lines.append(header("TTL / Hop Limit"))
    lines.append(_format_kv("Expired TTL/Hop Limit", str(summary.ttl_expired)))
    lines.append(_format_kv("Low TTL/Hop Limit (<=5)", str(summary.ttl_low)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("TCP/UDP Health Indicators"))
    syn_only = summary.tcp_syn - summary.tcp_syn_ack
    rst_ratio = (summary.tcp_rst / summary.tcp_syn) if summary.tcp_syn else 0.0
    lines.append(_format_kv("TCP SYN", str(summary.tcp_syn)))
    lines.append(_format_kv("TCP SYN-ACK", str(summary.tcp_syn_ack)))
    lines.append(_format_kv("TCP RST", str(summary.tcp_rst)))
    lines.append(_format_kv("SYN without SYN-ACK", str(max(0, syn_only))))
    lines.append(_format_kv("RST/SYN Ratio", f"{rst_ratio:.2%}"))
    lines.append(_format_kv("Zero-Window", str(summary.tcp_zero_window)))
    lines.append(_format_kv("Small-Window", str(summary.tcp_small_window)))
    if summary.tcp_zero_window_sources:
        top_zero = ", ".join(
            f"{ip}({count})"
            for ip, count in summary.tcp_zero_window_sources.most_common(
                _limit_value(5)
            )
        )
        lines.append(_format_kv("Zero-Window Sources", top_zero))
    if summary.tcp_rst_sources:
        top_rst = ", ".join(
            f"{ip}({count})"
            for ip, count in summary.tcp_rst_sources.most_common(_limit_value(5))
        )
        lines.append(_format_kv("RST Sources", top_rst))
    if summary.udp_amp_candidates:
        lines.append(
            _format_kv("UDP Amplification", str(len(summary.udp_amp_candidates)))
        )
        lines.append(
            _format_kv(
                "Top Candidates",
                ", ".join(summary.udp_amp_candidates[: _limit_value(5)]),
            )
        )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Quality of Service (DSCP/ECN)"))
    top_dscp = (
        ", ".join(
            f"{dscp}({count})"
            for dscp, count in summary.dscp_counts.most_common(_limit_value(5))
        )
        or "-"
    )
    top_ecn = (
        ", ".join(
            f"{ecn}({count})"
            for ecn, count in summary.ecn_counts.most_common(_limit_value(5))
        )
        or "-"
    )
    lines.append(_format_kv("Top DSCP", top_dscp))
    lines.append(_format_kv("Top ECN", top_ecn))

    lines.append(SUBSECTION_BAR)
    lines.append(header("SNMP"))
    lines.append(_format_kv("SNMP Packets", str(summary.snmp_packets)))
    versions = (
        ", ".join(
            f"{ver}({count})"
            for ver, count in summary.snmp_versions.most_common(_limit_value(5))
        )
        or "-"
    )
    communities = (
        ", ".join(
            f"{comm}({count})"
            for comm, count in summary.snmp_communities.most_common(_limit_value(5))
        )
        or "-"
    )
    lines.append(_format_kv("Versions", versions))
    lines.append(_format_kv("Communities", communities))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Certificates"))
    lines.append(_format_kv("Expired/Invalid", str(summary.expired_certs)))
    lines.append(_format_kv("Self-Signed", str(summary.self_signed_certs)))

    if summary.ot_timing:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT Cycle/Jitter"))
        for key, label_text in (
            ("profinet_rt", "Profinet RT"),
            ("enip_io", "ENIP IO"),
            ("s7_rosctr", "S7 COTP/ROSCTR"),
        ):
            entries = summary.ot_timing.get(key, [])
            if not entries:
                continue
            lines.append(muted(label_text))
            rows = [["Session", "Avg(s)", "Std(s)", "CV", "Min", "Max", "Samples"]]
            for item in entries:
                rows.append(
                    [
                        str(item.get("session", "-")),
                        f"{float(item.get('avg', 0.0)):.3f}",
                        f"{float(item.get('std', 0.0)):.3f}",
                        f"{float(item.get('cv', 0.0)):.2f}",
                        f"{float(item.get('min', 0.0)):.3f}",
                        f"{float(item.get('max', 0.0)):.3f}",
                        str(item.get("count", 0)),
                    ]
                )
            lines.append(_format_table(rows))

    if summary.findings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Findings"))
        for item in summary.findings:
            severity = str(item.get("severity", "info"))
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity == "critical":
                marker = danger("[CRIT]")
            elif severity == "warning":
                marker = warn("[WARN]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
