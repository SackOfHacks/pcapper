"""Rendered output for exfil analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    danger,
    header,
    label,
    muted,
    ok,
    warn,
)
from ..exfil import ExfilSummary
from ..utils import (
    format_bytes_as_mb,
    format_duration,
    format_ts,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _apply_verbose_limit,
    _filtered_detections,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
    _redact_in_text,
)


def render_exfil_summary(
    summary: ExfilSummary, limit: int = 12, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit) or limit
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"EXFILTRATION ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(
        _format_kv("Outbound Bytes", format_bytes_as_mb(summary.outbound_bytes))
    )
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))

    def _exfil_verdict() -> tuple[str, str, list[str], int]:
        reasons: list[str] = []
        score = 0

        total = int(summary.total_bytes or 0)
        outbound = int(summary.outbound_bytes or 0)
        outbound_ratio = (outbound / max(total, 1)) if total > 0 else 0.0
        if outbound >= 5_000_000:
            score += 2
            reasons.append(
                f"Outbound volume {format_bytes_as_mb(outbound)} exceeds high-risk threshold"
            )
        if total >= 2_000_000 and outbound_ratio >= 0.60:
            score += 1
            reasons.append(
                f"Outbound ratio is {outbound_ratio * 100:.1f}% of capture bytes"
            )

        if summary.outbound_flows:
            top = summary.outbound_flows[0]
            top_bytes = int(top.get("bytes", 0) or 0)
            if top_bytes >= 5_000_000:
                score += 2
                reasons.append(
                    f"Dominant outbound flow {top.get('src')}->{top.get('dst')} carried {format_bytes_as_mb(top_bytes)}"
                )

        if summary.top_external_dsts and outbound >= 3_000_000:
            dst, dst_bytes = summary.top_external_dsts.most_common(1)[0]
            share = dst_bytes / max(outbound, 1)
            if share >= 0.70:
                score += 1
                reasons.append(
                    f"{dst} received {share * 100:.1f}% of outbound bytes ({format_bytes_as_mb(dst_bytes)})"
                )

        if summary.dns_tunnel_suspects:
            strongest_dns_confidence = 0
            for item in summary.dns_tunnel_suspects:
                try:
                    total = int(item.get("total", 0) or 0)
                    unique = int(item.get("unique", 0) or 0)
                    long_q = int(item.get("long", 0) or 0)
                    entropy = float(item.get("avg_entropy", 0.0) or 0.0)
                    max_label = int(item.get("max_label", 0) or 0)
                except Exception:
                    continue

                confidence_points = 0
                if total >= 50 and unique >= int(total * 0.85):
                    confidence_points += 1
                if long_q >= 20:
                    confidence_points += 1
                if entropy >= 3.6:
                    confidence_points += 1
                if max_label >= 45:
                    confidence_points += 1
                if confidence_points > strongest_dns_confidence:
                    strongest_dns_confidence = confidence_points

            if strongest_dns_confidence >= 2:
                score += 4
                reasons.append(
                    f"High-confidence DNS tunneling heuristics triggered by {len(summary.dns_tunnel_suspects)} source(s)"
                )
            else:
                score += 3
                reasons.append(
                    f"DNS tunneling heuristics triggered by {len(summary.dns_tunnel_suspects)} source(s)"
                )
        if summary.http_post_suspects:
            score += 1
            reasons.append(
                f"Large HTTP POST channels detected ({len(summary.http_post_suspects)})"
            )
        if summary.file_exfil_suspects:
            high_risk_files = [
                item
                for item in summary.file_exfil_suspects
                if int(item.get("risk_score", 0) or 0) >= 5
            ]
            score += 2 if high_risk_files else 1
            reasons.append(
                f"Suspicious file transfer suspects detected ({len(summary.file_exfil_suspects)}; high-risk={len(high_risk_files)})"
            )
        if summary.ot_flows:
            large_ot = [
                item
                for item in summary.ot_flows
                if int(item.get("bytes", 0) or 0) >= 1_000_000
            ]
            if large_ot:
                score += 1
                reasons.append(
                    f"Large OT/ICS control-port transfers observed ({len(large_ot)})"
                )

        if score >= 7:
            verdict = "YES - exfiltration activity is likely occurring in this PCAP based on corroborated indicators."
            confidence = "High"
        elif score >= 5:
            verdict = "LIKELY - exfiltration activity is suspected with multiple supporting indicators."
            confidence = "Medium"
        elif score >= 3:
            verdict = "POSSIBLE - weak-to-moderate exfiltration indicators are present."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - current heuristics do not show convincing exfiltration activity."
            confidence = "Low"

        if not reasons:
            reasons.append(
                "No high-confidence exfiltration heuristic crossed its threshold"
            )
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _exfil_verdict()
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", f"{confidence} (score={verdict_score})"))
    lines.append(muted("Why confidence:"))
    for reason in verdict_reasons[: _limit_value(8)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    # Add concrete evidence context directly in the verdict block for analyst triage.
    if summary.outbound_flows:
        lines.append(muted("Where:"))
        lines.append(muted("- Dominant outbound flows"))
        for item in summary.outbound_flows[: _limit_value(6)]:
            lines.append(
                muted(
                    f"- {item.get('src', '-')}->{item.get('dst', '-')} "
                    f"proto={item.get('proto', '-')} dport={item.get('dst_port', '-')} "
                    f"bytes={format_bytes_as_mb(int(item.get('bytes', 0) or 0))} "
                    f"packets={int(item.get('packets', 0) or 0)}"
                )
            )

    if summary.dns_tunnel_suspects:
        lines.append(muted("What:"))
        lines.append(muted("- DNS tunnel suspects"))
        for item in summary.dns_tunnel_suspects[: _limit_value(6)]:
            lines.append(
                muted(
                    f"- src={item.get('src', '-')} total={item.get('total', '-')} unique={item.get('unique', '-')} "
                    f"long={item.get('long', '-')} entropy={item.get('avg_entropy', '-')} max_label={item.get('max_label', '-')}"
                )
            )

    if summary.http_post_suspects:
        lines.append(muted("What:"))
        lines.append(muted("- HTTP POST exfil channels"))
        for item in summary.http_post_suspects[: _limit_value(6)]:
            lines.append(
                muted(
                    f"- {item.get('src', '-')}->{item.get('dst', '-')} host={item.get('host', '-')} "
                    f"uri={item.get('uri', '-')} bytes={format_bytes_as_mb(int(item.get('bytes', 0) or 0))} "
                    f"req={int(item.get('requests', 0) or 0)} risk={int(item.get('risk_score', 0) or 0)}"
                )
            )

    if getattr(summary, "file_exfil_suspects", None):
        file_suspects = list(summary.file_exfil_suspects or [])
        if file_suspects:
            lines.append(muted("What:"))
            lines.append(muted("- File exfil suspects"))
            for item in file_suspects[: _limit_value(6)]:
                lines.append(
                    muted(
                        f"- {item.get('src', '-')}->{item.get('dst', '-')} file={item.get('filename', '-')} "
                        f"type={item.get('file_type', '-') or '-'} size={format_bytes_as_mb(int(item.get('size', 0) or 0))} "
                        f"risk={int(item.get('risk_score', 0) or 0)} packet={item.get('packet', '-')}"
                    )
                )

    # The analyzer's own deterministic exfil checks (with per-finding evidence)
    # were previously computed but only fed the cross-protocol threats rollup;
    # surface them here in the exfil section too.
    exfil_checks = getattr(summary, "deterministic_checks", {}) or {}
    exfil_check_labels = [
        ("dns_tunnel_indicators", "DNS Tunnel Indicators"),
        ("http_post_exfil_channels", "HTTP POST Exfil Channels"),
        ("ot_control_channel_exfil", "OT/ICS Control-Channel Exfil"),
        ("internal_staging_then_external_exfil", "Internal Staging -> External Exfil"),
        ("file_exfiltration_candidates", "File Exfiltration Candidates"),
        ("management_port_bulk_transfer", "Management-Port Bulk Transfer"),
        ("uncommon_egress_channels", "Uncommon Egress Channels"),
        ("stealth_low_rate_long_lived_egress", "Stealth Low-Rate Long-Lived Egress"),
    ]
    if any(exfil_checks.get(k) for k, _ in exfil_check_labels):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Deterministic Exfiltration Checks"))
        for key, label_text in exfil_check_labels:
            evidence = [
                str(v) for v in list(exfil_checks.get(key, []) or []) if str(v).strip()
            ]
            if not evidence:
                continue
            lines.append(label(label_text))
            lines.append(
                warn(
                    f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"
                )
            )
            for item in evidence[: _limit_value(8 if verbose else 5)]:
                lines.append(muted(f"- {_redact_in_text(str(item))}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Protocol Checks"))

    protocol_labels = [
        ("dns", "DNS"),
        ("http_https", "HTTP/HTTPS"),
        ("icmp", "ICMP"),
        ("ftp", "FTP"),
        ("smtp", "SMTP"),
        ("websockets", "WebSockets"),
        ("ntp", "NTP"),
    ]
    protocol_checks = getattr(summary, "protocol_exfil_checks", {}) or {}
    for key, label_text in protocol_labels:
        evidence = (
            protocol_checks.get(key, []) if isinstance(protocol_checks, dict) else []
        )
        lines.append(label(f"{label_text} Exfil Check"))
        if evidence:
            lines.append(
                warn(
                    f"Yes, there is evidence for {label_text} exfil, here is the evidence:"
                )
            )
            for item in evidence[: _limit_value(8 if verbose else 5)]:
                lines.append(muted(f"- {_redact_in_text(str(item))}"))
        else:
            lines.append(
                ok(
                    f"No, there is no strong evidence for {label_text} exfil in this capture."
                )
            )

    if summary.outbound_flows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Outbound Flows (Private -> Public)"))
        rows = [
            ["Src", "Dst", "Proto", "DPort", "Packets", "Bytes", "Duration", "Rate"]
        ]
        for item in summary.outbound_flows[:limit]:
            duration_seconds = float(item.get("duration_seconds", 0.0) or 0.0)
            bytes_per_second = float(item.get("bytes_per_second", 0.0) or 0.0)
            dport = item.get("dst_port")
            rows.append(
                [
                    str(item.get("src", "-")),
                    str(item.get("dst", "-")),
                    str(item.get("proto", "-")),
                    str(dport) if isinstance(dport, int) and dport > 0 else "-",
                    str(item.get("packets", "-")),
                    format_bytes_as_mb(int(item.get("bytes", 0))),
                    format_duration(duration_seconds),
                    f"{format_bytes_as_mb(int(bytes_per_second * 60))}/min"
                    if bytes_per_second > 0
                    else "-",
                ]
            )
        lines.append(_format_table(rows))
        if summary.top_external_dsts:
            top_dst, top_bytes = summary.top_external_dsts.most_common(1)[0]
            share = (top_bytes / max(int(summary.outbound_bytes or 0), 1)) * 100.0
            lines.append(
                muted(
                    f"Primary external destination: {top_dst} ({format_bytes_as_mb(top_bytes)}, {share:.1f}% of outbound)"
                )
            )

    if getattr(summary, "internal_flows", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Internal Flows (Private -> Private)"))
        rows = [
            ["Src", "Dst", "Proto", "DPort", "Packets", "Bytes", "Duration", "Rate"]
        ]
        for item in summary.internal_flows[:limit]:
            duration_seconds = float(item.get("duration_seconds", 0.0) or 0.0)
            bytes_per_second = float(item.get("bytes_per_second", 0.0) or 0.0)
            dport = item.get("dst_port")
            rows.append(
                [
                    str(item.get("src", "-")),
                    str(item.get("dst", "-")),
                    str(item.get("proto", "-")),
                    str(dport) if isinstance(dport, int) and dport > 0 else "-",
                    str(item.get("packets", "-")),
                    format_bytes_as_mb(int(item.get("bytes", 0))),
                    format_duration(duration_seconds),
                    f"{format_bytes_as_mb(int(bytes_per_second * 60))}/min"
                    if bytes_per_second > 0
                    else "-",
                ]
            )
        lines.append(_format_table(rows))

    if getattr(summary, "ot_flows", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT/ICS Control-Port Flows"))
        rows = [
            ["Src", "Dst", "Proto", "DPort", "Packets", "Bytes", "Duration", "Rate"]
        ]
        for item in summary.ot_flows[:limit]:
            duration_seconds = float(item.get("duration_seconds", 0.0) or 0.0)
            bytes_per_second = float(item.get("bytes_per_second", 0.0) or 0.0)
            dport = item.get("dst_port")
            rows.append(
                [
                    str(item.get("src", "-")),
                    str(item.get("dst", "-")),
                    str(item.get("proto", "-")),
                    str(dport) if isinstance(dport, int) and dport > 0 else "-",
                    str(item.get("packets", "-")),
                    format_bytes_as_mb(int(item.get("bytes", 0))),
                    format_duration(duration_seconds),
                    f"{format_bytes_as_mb(int(bytes_per_second * 60))}/min"
                    if bytes_per_second > 0
                    else "-",
                ]
            )
        lines.append(_format_table(rows))

    if summary.dns_tunnel_suspects:
        lines.append(SUBSECTION_BAR)
        lines.append(header("DNS Tunneling Heuristics"))
        rows = [["Src", "Total", "Unique", "Long", "Entropy", "MaxLabel"]]
        for item in summary.dns_tunnel_suspects[:limit]:
            rows.append(
                [
                    str(item.get("src", "-")),
                    str(item.get("total", "-")),
                    str(item.get("unique", "-")),
                    str(item.get("long", "-")),
                    str(item.get("avg_entropy", "-")),
                    str(item.get("max_label", "-")),
                ]
            )
        lines.append(_format_table(rows))

    if summary.http_post_suspects:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Large HTTP POST Payloads (Evidence)"))
        rows = [
            [
                "Src",
                "Dst",
                "Host",
                "URI",
                "Bytes",
                "Req",
                "Mode",
                "Risk",
                "Packets",
                "Assessment",
            ]
        ]
        for item in summary.http_post_suspects[:limit]:
            bytes_val = int(item.get("bytes", 0) or 0)
            req_val = int(item.get("requests", 1) or 1)
            risk_score = int(item.get("risk_score", 0) or 0)
            packet_examples = str(
                item.get("packet_examples", item.get("packet", "-")) or "-"
            )
            assessment = (
                "high"
                if risk_score >= 3 or bytes_val >= 5_000_000 or req_val >= 30
                else "medium"
            )
            rows.append(
                [
                    str(item.get("src", "-")),
                    str(item.get("dst", "-")),
                    str(item.get("host", "-")),
                    str(item.get("uri", "-")),
                    format_bytes_as_mb(bytes_val),
                    str(req_val),
                    str(item.get("mode", "single")),
                    str(risk_score),
                    packet_examples,
                    assessment,
                ]
            )
        lines.append(_format_table(rows))

        lines.append(muted("HTTP POST Evidence Details:"))
        for item in summary.http_post_suspects[: _limit_value(10 if verbose else 6)]:
            risk_score = int(item.get("risk_score", 0) or 0)
            risk_reasons = item.get("risk_reasons", [])
            reason_text = (
                ", ".join(str(v) for v in risk_reasons[:3])
                if isinstance(risk_reasons, list) and risk_reasons
                else "-"
            )
            packet_examples = str(
                item.get("packet_examples", item.get("packet", "-")) or "-"
            )
            lines.append(
                muted(
                    f"- {item.get('src')}->{item.get('dst')} host={item.get('host')} risk={risk_score} "
                    f"why={_redact_in_text(reason_text)} packets={packet_examples}"
                )
            )
            sample_text = str(item.get("sample", "") or "").strip()
            if sample_text and sample_text != "-":
                lines.append(muted(f"  sample={_redact_in_text(sample_text[:120])}"))

    if summary.file_artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files Discovered"))
        rows = [["Filename", "Size", "Note"]]
        for item in summary.file_artifacts[:limit]:
            size_val = item.get("size")
            rows.append(
                [
                    str(item.get("filename", "-")),
                    format_bytes_as_mb(int(size_val))
                    if isinstance(size_val, int)
                    else "-",
                    str(item.get("note", "-")),
                ]
            )
        lines.append(_format_table(rows))

    if getattr(summary, "file_exfil_suspects", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Potential Exfil File Transfers (Evidence)"))
        rows = [
            ["Src", "Dst", "Proto", "File", "Type", "Size", "Risk", "Packet", "Note"]
        ]
        for item in summary.file_exfil_suspects[:limit]:
            size_val = item.get("size")
            risk_score = int(item.get("risk_score", 0) or 0)
            risk_text = (
                "high" if risk_score >= 5 else "medium" if risk_score >= 3 else "low"
            )
            reasons = item.get("risk_reasons", [])
            reason_text = (
                ", ".join(str(r) for r in reasons[:3])
                if isinstance(reasons, list) and reasons
                else "-"
            )
            rows.append(
                [
                    str(item.get("src", "-")),
                    str(item.get("dst", "-")),
                    str(item.get("protocol", "-")),
                    str(item.get("filename", "-")),
                    str(item.get("file_type", "-") or "-"),
                    format_bytes_as_mb(int(size_val))
                    if isinstance(size_val, int)
                    else "-",
                    f"{risk_text} ({risk_score})",
                    str(item.get("packet", "-")),
                    reason_text
                    if reason_text != "-"
                    else (str(item.get("note", "-")) if item.get("note") else "-"),
                ]
            )
        lines.append(_format_table(rows))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections (Ranked Evidence)"))
        for item in detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity == "critical":
                marker = danger("[CRIT]")
            elif severity == "high":
                marker = danger("[HIGH]")
            elif severity == "warning":
                marker = warn("[WARN]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))
            evidence_items = item.get("evidence", [])
            if isinstance(evidence_items, list):
                for evidence in evidence_items[: _limit_value(8)]:
                    lines.append(muted(f"    - {_redact_in_text(str(evidence))}"))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts"))
        for item in summary.artifacts[:limit]:
            lines.append(muted(f"- {item}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)
