"""Rendered output for arp analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..arp import ArpSummary
from ..coloring import (
    danger,
    header,
    label,
    muted,
    ok,
    warn,
)
from ..utils import (
    format_ts,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _apply_verbose_limit,
    _counter_table,
    _finalize_output,
    _format_kv,
    _format_table,
    _highlight_public_ips,
    _limit_value,
    _redact_in_text,
    _truncate_text,
)


def render_arp_summary(
    summary: ArpSummary, limit: int = 15, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit)
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"ARP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Scan Duration", f"{summary.duration:.2f}s"))
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("ARP Packets", str(summary.arp_packets)))
    lines.append(_format_kv("ARP Requests", str(summary.arp_requests)))
    lines.append(_format_kv("ARP Replies", str(summary.arp_replies)))
    lines.append(_format_kv("Gratuitous ARP", str(summary.gratuitous_arp)))
    lines.append(_format_kv("ARP Probes", str(summary.arp_probes)))
    lines.append(_format_kv("Unsolicited Replies", str(summary.unsolicited_replies)))

    def _arp_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        high_anomalies = sum(
            1 for item in summary.anomalies if item.severity in {"HIGH", "CRITICAL"}
        )
        med_anomalies = sum(
            1 for item in summary.anomalies if item.severity == "MEDIUM"
        )
        if high_anomalies:
            score += min(5, high_anomalies * 2)
            reasons.append(f"High-severity ARP anomalies observed ({high_anomalies})")
        if med_anomalies >= 2:
            score += 1
            reasons.append(
                f"Multiple medium-severity ARP anomalies observed ({med_anomalies})"
            )
        if summary.unsolicited_replies >= 20:
            score += 2
            reasons.append(
                f"Unsolicited ARP replies are elevated ({summary.unsolicited_replies})"
            )
        if (
            getattr(summary, "gateway_ip", "")
            and len(getattr(summary, "gateway_mac_candidates", {})) > 1
        ):
            score += 2
            reasons.append("Gateway ARP MAC mapping changed")
        if summary.gratuitous_arp >= 25:
            score += 1
            reasons.append(
                f"Excess gratuitous ARP frames observed ({summary.gratuitous_arp})"
            )
        # An ARP host-sweep is reconnaissance / network mapping (often pre-attack
        # or lateral-movement scoping). It can be benign (admin scanners), so it
        # lifts the verdict to "POSSIBLE — corroborate", not a definitive attack.
        threats = getattr(summary, "threats", {}) or {}
        if threats.get("ARP Sweep") or (
            getattr(summary, "deterministic_checks", {}) or {}
        ).get("arp_recon_sweep"):
            score += 2
            reasons.append(
                "ARP host-sweep reconnaissance observed (subnet/network mapping)"
            )

        if score >= 7:
            verdict = (
                "YES - high-confidence ARP poisoning or MITM-style behavior is present."
            )
            confidence = "High"
        elif score >= 4:
            verdict = (
                "LIKELY - suspicious ARP behavior with attack indicators is present."
            )
            confidence = "Medium"
        elif score >= 2:
            verdict = "POSSIBLE - potentially malicious ARP behavior observed; corroboration recommended."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing high-risk ARP attack pattern from current heuristics."
            confidence = "Low"

        if not reasons:
            reasons.append("No high-confidence ARP attack heuristic crossed threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _arp_verdict()
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
    for reason in verdict_reasons[: _limit_value(10)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    # Add concrete context for immediate triage.
    if summary.gateway_ip:
        lines.append(muted("Where:"))
        lines.append(
            muted(
                f"- Gateway under observation: {_highlight_public_ips(summary.gateway_ip)}"
            )
        )
    if summary.gateway_mac_candidates:
        lines.append(muted("What:"))
        lines.append(muted("- Gateway MAC candidates"))
        for mac, count in summary.gateway_mac_candidates.most_common(_limit_value(6)):
            lines.append(muted(f"- {mac}: {int(count)} replies"))
    if summary.victim_conflicts:
        lines.append(muted("Who:"))
        lines.append(muted("- Victim conflict highlights"))
        for ip_value, mac_counter in sorted(
            summary.victim_conflicts.items(),
            key=lambda item: sum(item[1].values()),
            reverse=True,
        )[: _limit_value(6)]:
            claims = ", ".join(
                f"{mac}({cnt})" for mac, cnt in mac_counter.most_common(4)
            )
            lines.append(
                muted(f"- {_highlight_public_ips(ip_value)} claimed by {claims}")
            )
    if summary.anomalies:
        lines.append(muted("When:"))
        lines.append(muted("- Top ARP anomalies"))
        for item in summary.anomalies[: _limit_value(6)]:
            lines.append(
                muted(
                    f"- [{item.severity}] {_redact_in_text(item.title)}: {_redact_in_text(item.description)}"
                )
            )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic ARP Security Checks"))

    # Render the analyzer's own computed deterministic checks (authoritative,
    # with per-finding evidence) rather than re-deriving via free-text keyword
    # matching on threats/anomalies, which both under-covered the categories and
    # discarded the evidence the ARP analyzer already built.
    arp_checks = getattr(summary, "deterministic_checks", {}) or {}
    arp_check_labels = [
        ("gateway_integrity", "Gateway ARP Integrity"),
        ("poisoning_pair_pattern", "Poisoning Pair Pattern"),
        ("unsolicited_reply_abuse", "Unsolicited Reply Abuse"),
        ("broadcast_unsolicited_reply", "Broadcast Unsolicited Replies"),
        ("rapid_gateway_mac_flip", "Rapid Gateway MAC Flip"),
        ("recon_to_poison_progression", "Recon-to-Poison Progression"),
        ("arp_recon_sweep", "ARP Recon/Sweep Activity"),
        ("probe_spray", "ARP Probe Spray"),
        ("arp_storm_flood", "ARP Flood/Storm"),
        ("duplicate_ip_ownership", "Duplicate IP Ownership"),
        ("proxy_arp_misuse", "Proxy ARP Misuse"),
        ("timing_automation_signal", "Timing/Automation Signal"),
        ("likely_benign_failover", "Likely Benign Failover"),
    ]
    cleared_arp: list[str] = []
    fired_arp = False
    for key, label_text in arp_check_labels:
        evidence = [
            str(v) for v in list(arp_checks.get(key, []) or []) if str(v).strip()
        ]
        if evidence:
            fired_arp = True
            lines.append(label(label_text))
            lines.append(
                warn(
                    f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"
                )
            )
            for item in evidence[: _limit_value(6)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))
        else:
            cleared_arp.append(label_text)
    # Collapse the cleared checks into one line.
    if not fired_arp:
        lines.append(ok("No ARP attack checks crossed threshold in this capture."))
    elif cleared_arp:
        lines.append(muted(f"Cleared (no evidence): {', '.join(cleared_arp)}"))

    if getattr(summary, "gateway_mac_candidates", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Gateway Mapping Integrity"))
        rows = [["Gateway IP", "Observed MAC", "Replies"]]
        gateway_ip = getattr(summary, "gateway_ip", "-") or "-"
        for mac, count in summary.gateway_mac_candidates.most_common(limit):
            rows.append([gateway_ip, mac, str(count)])
        lines.append(_format_table(rows))

    if getattr(summary, "victim_conflicts", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Victim-Centric Conflict View"))
        rows = [["Victim IP", "Claiming MACs", "Conflict Count"]]
        for victim_ip, mac_counter in sorted(
            summary.victim_conflicts.items(),
            key=lambda item: sum(item[1].values()),
            reverse=True,
        )[:limit]:
            mac_text = ", ".join(
                f"{mac}({count})"
                for mac, count in mac_counter.most_common(_limit_value(3))
            )
            rows.append([victim_ip, mac_text or "-", str(sum(mac_counter.values()))])
        lines.append(_format_table(rows))

    if getattr(summary, "timeline", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Attack Chain Timeline"))
        rows = [["Timestamp", "Event", "Source", "Destination"]]
        for item in summary.timeline[:limit]:
            rows.append(
                [
                    format_ts(item.ts),
                    _truncate_text(_redact_in_text(item.detail), 88),
                    item.src,
                    item.dst,
                ]
            )
        lines.append(_format_table(rows))

    if getattr(summary, "proxy_arp_candidates", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Proxy ARP Candidates"))
        rows = [["MAC", "Dst Targets", "Claimed IPs"]]
        for item in summary.proxy_arp_candidates[:limit]:
            rows.append(
                [
                    str(item.get("mac", "-")),
                    str(item.get("dst_targets", "-")),
                    str(item.get("claimed_ips", "-")),
                ]
            )
        lines.append(_format_table(rows))

    if getattr(summary, "reply_latency_summary", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Reply Timing"))
        lines.append(
            _format_kv(
                "Median Reply Latency",
                f"{float(summary.reply_latency_summary.get('median_s', 0.0)) * 1000.0:.2f} ms",
            )
        )
        lines.append(
            _format_kv(
                "p95 Reply Latency",
                f"{float(summary.reply_latency_summary.get('p95_s', 0.0)) * 1000.0:.2f} ms",
            )
        )
        lines.append(
            _format_kv(
                "Samples",
                str(int(float(summary.reply_latency_summary.get("samples", 0.0)))),
            )
        )

    if getattr(summary, "pps_by_source", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("ARP Rate Baseline"))
        rows = [["Source", "Requests", "Packets/sec"]]
        for src, count in summary.client_details.most_common(limit):
            pps = float(summary.pps_by_source.get(src, 0.0))
            rows.append([src, str(count), f"{pps:.2f}"])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("ARP Conversations"))
    if not summary.conversations:
        lines.append(muted("No ARP conversations identified."))
    else:
        rows = [
            [
                "Src IP",
                "Dst IP",
                "Src MAC",
                "Dst MAC",
                "Opcode",
                "Packets",
                "First",
                "Last",
            ]
        ]
        for item in summary.conversations[:limit]:
            rows.append(
                [
                    item.src_ip,
                    item.dst_ip,
                    item.src_mac,
                    item.dst_mac,
                    item.opcode,
                    str(item.packets),
                    format_ts(item.first_seen),
                    format_ts(item.last_seen),
                ]
            )
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Source/Destination IP Statistics"))
    if summary.src_ips:
        rows = [["Source IP", "Packets"]]
        for ip, count in summary.src_ips.most_common(limit):
            rows.append([ip, str(count)])
        lines.append(_format_table(rows))
    if summary.dst_ips:
        rows = [["Destination IP", "Packets"]]
        for ip, count in summary.dst_ips.most_common(limit):
            rows.append([ip, str(count)])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("ARP Server/Service Details"))
    if not summary.server_details:
        lines.append(muted("No ARP server behavior identified."))
    else:
        rows = [["Responder IP", "Replies"]]
        for ip, count in summary.server_details.most_common(limit):
            rows.append([ip, str(count)])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("ARP Client Details"))
    if not summary.client_details:
        lines.append(muted("No ARP client behavior identified."))
    else:
        rows = [["Requester IP", "Requests"]]
        for ip, count in summary.client_details.most_common(limit):
            rows.append([ip, str(count)])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Observed Plaintext"))
    if not summary.plaintext_observed:
        lines.append(muted("No plaintext content observed in ARP-adjacent payloads."))
    else:
        rows = [["String", "Count"]]
        for value, count in summary.plaintext_observed.most_common(limit):
            rows.append([_truncate_text(value, 96), str(count)])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Client/Server Versions"))
    if not summary.client_versions and not summary.server_versions:
        lines.append(
            muted(
                "No explicit ARP stack versions available; using hw/proto tuple fingerprints."
            )
        )
    else:
        if summary.client_versions:
            lines.append(_counter_table(summary.client_versions, "Client Fingerprint", limit=limit))
        if summary.server_versions:
            lines.append(_counter_table(summary.server_versions, "Server Fingerprint", limit=limit))

    lines.append(SUBSECTION_BAR)
    lines.append(header("ARP Response Code Summary"))
    if not summary.response_codes:
        lines.append(muted("No ARP response codes/opcodes recorded."))
    else:
        lines.append(_counter_table(summary.response_codes, "Response Type", limit=limit))

    lines.append(SUBSECTION_BAR)
    lines.append(header("ARP Requests Summary"))
    if not summary.request_summary:
        lines.append(muted("No ARP request categories recorded."))
    else:
        lines.append(_counter_table(summary.request_summary, "Request Type", limit=limit))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Files Discovered"))
    if not summary.files_discovered:
        lines.append(muted("No file indicators discovered."))
    else:
        for name in summary.files_discovered[:limit]:
            lines.append(f"  - {name}")

    lines.append(SUBSECTION_BAR)
    lines.append(header("Observed Session Statistics"))
    if not summary.sessions:
        lines.append(muted("No ARP request/reply session pairs identified."))
    else:
        rows = [["Client", "Server", "Requests", "Replies", "First", "Last"]]
        for sess in summary.sessions[:limit]:
            rows.append(
                [
                    sess.client_ip,
                    sess.server_ip,
                    str(sess.requests),
                    str(sess.replies),
                    format_ts(sess.first_seen),
                    format_ts(sess.last_seen),
                ]
            )
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Threats / Attacks / Anomalies"))
    if not summary.threats and not summary.anomalies:
        lines.append(ok("No high-confidence ARP threats detected."))
    else:
        if summary.threats:
            lines.append(_counter_table(summary.threats, "Threat", limit=limit))
        for item in summary.anomalies[:limit]:
            sev = danger if item.severity in {"HIGH", "CRITICAL"} else warn
            lines.append(sev(f"[{item.severity}] {item.title}: {item.description}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Artifacts"))
    if not summary.artifacts:
        lines.append(muted("No ARP artifacts recorded."))
    else:
        rows = [["Kind", "Detail", "Src", "Dst", "TS"]]
        for item in summary.artifacts[:limit]:
            rows.append(
                [
                    item.kind,
                    _truncate_text(item.detail, 72),
                    item.src,
                    item.dst,
                    format_ts(item.ts),
                ]
            )
        lines.append(_format_table(rows))

    if verbose and summary.opcode_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Opcode Frequency"))
        lines.append(_counter_table(summary.opcode_counts, "Opcode", limit=limit))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
