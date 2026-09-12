"""Rendered output for compromised analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..utils import is_public_ip as _is_public_ip
from ..coloring import (
    danger,
    header,
    label,
    muted,
    ok,
    warn,
)
from ..compromised import CompromiseSummary
from ..utils import (
    format_duration,
    format_ts,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _apply_verbose_limit,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
    _redact_in_text,
    _truncate_text,
)


_COMPROMISE_ISSUE_REASONS = [
    # (substring to match in summary, why-this-indicates-compromise explanation)
    (
        "file hash ioc",
        "Files matching malware heuristics (executable/script/archive) were "
        "transferred in the clear; the hashes are pivotable IOCs — look them up "
        "in threat intel and correlate with the delivering host.",
    ),
    (
        "malicious file download",
        "A host downloaded executable/script/archive content from an external "
        "site — typical of exploit-kit payload delivery or a dropper.",
    ),
    (
        "covert-channel",
        "A large share of bytes is high-entropy on a cleartext port (e.g. HTTP/80) "
        "— consistent with an encrypted/packed malware payload or C2 hidden in "
        "plain-port traffic, not normal web content.",
    ),
    (
        "high-entropy payloads",
        "High-entropy (encrypted/packed) payloads were seen on a non-encrypted "
        "port — exploit-kit payloads and HTTP-based C2 look like this; normal "
        "port-80 traffic is low-entropy text.",
    ),
    (
        "recovered ioc/attack artifacts",
        "Attacker tradecraft (ATT&CK techniques / IOCs) was recovered from "
        "decoded payloads — direct evidence of malicious tooling on the wire.",
    ),
    (
        "carved file signatures",
        "Files were reconstructed from raw TCP streams (transfers outside normal "
        "file-sharing protocols) — inspect for droppers, exploits and payloads.",
    ),
    (
        "burst/fan-out reconnaissance",
        "One host issued many HTTP requests across many hosts/URLs in a short "
        "window — automated browsing through a redirect / exploit-kit chain.",
    ),
    (
        "beacon",
        "Periodic, regular outbound connections to an external host — "
        "command-and-control beaconing.",
    ),
    (
        "exfiltrat",
        "An unusually large or structured outbound transfer — possible data "
        "exfiltration.",
    ),
    (
        "credential",
        "Credential material or repeated authentication was observed — possible "
        "credential theft or brute force.",
    ),
    (
        "legacy tls",
        "Obsolete TLS was negotiated — weak transport, and often a marker of "
        "old/automated malware clients.",
    ),
]


def _compromise_issue_reason(summary_text: str, source: str) -> str:
    low = str(summary_text or "").lower()
    for needle, reason in _COMPROMISE_ISSUE_REASONS:
        if needle in low:
            return reason
    return (
        f"Flagged by the {source or 'threat'} analyzer as anomalous relative to "
        "benign baseline traffic."
    )


def _dedupe_compromise_issues(
    detections: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Collapse detections that are identical except for the attributed IP into
    one issue, unioning the involved hosts / evidence / IOCs. The analyzer emits
    one copy per attributed IP, which otherwise prints the same line 5-7x."""
    order: list[tuple[str, str]] = []
    grouped: dict[tuple[str, str], dict[str, object]] = {}
    sev_rank = {"critical": 3, "high": 2, "warning": 1, "medium": 1, "info": 0}
    for item in detections:
        summary_text = str(item.get("summary", ""))
        details = str(item.get("details", ""))
        key = (summary_text, details)
        if key not in grouped:
            order.append(key)
            grouped[key] = {
                "severity": str(item.get("severity", "info")).lower(),
                "summary": summary_text,
                "details": details,
                "source": str(item.get("source", "")),
                "ips": [],
                "evidence": [],
                "iocs": [],
                # Skeptical-filter annotations — carried through so the
                # renderer can surface a `[skeptical: rule]` tag + reason.
                "skeptical_downgraded": bool(item.get("skeptical_downgraded", False)),
                "skeptical_rule": str(item.get("skeptical_rule", "") or ""),
                "skeptical_reason": str(item.get("skeptical_reason", "") or ""),
                "skeptical_original_severity": str(
                    item.get("skeptical_original_severity", "") or ""
                ),
                # Hypothesis-lens annotation — carried through so the
                # renderer can prefix a `[relevant]` / `[adjacent]` tag.
                "hypothesis_relevance": str(
                    item.get("hypothesis_relevance", "") or ""
                ),
            }
        bucket = grouped[key]
        if sev_rank.get(str(item.get("severity", "info")).lower(), 0) > sev_rank.get(
            str(bucket["severity"]), 0
        ):
            bucket["severity"] = str(item.get("severity", "info")).lower()
        # Preserve any incoming skeptical annotation — same (summary, details)
        # bucket should always yield the same rule, so first-writer-wins is fine.
        if item.get("skeptical_downgraded") and not bucket.get("skeptical_rule"):
            bucket["skeptical_downgraded"] = True
            bucket["skeptical_rule"] = str(item.get("skeptical_rule", "") or "")
            bucket["skeptical_reason"] = str(item.get("skeptical_reason", "") or "")
            bucket["skeptical_original_severity"] = str(
                item.get("skeptical_original_severity", "") or ""
            )
        # Hypothesis-lens: upgrade the bucket's tag when a stronger one is
        # observed. Precedence: relevant > adjacent > unrelated > "".
        _rel_rank = {"relevant": 3, "adjacent": 2, "unrelated": 1, "": 0}
        cur_rel = str(bucket.get("hypothesis_relevance", "") or "")
        new_rel = str(item.get("hypothesis_relevance", "") or "")
        if _rel_rank.get(new_rel, 0) > _rel_rank.get(cur_rel, 0):
            bucket["hypothesis_relevance"] = new_rel
        ip_value = str(item.get("ip", "")).strip()
        if ip_value and ip_value not in bucket["ips"]:
            bucket["ips"].append(ip_value)
        for ev in item.get("evidence", []) or []:
            if str(ev) not in bucket["evidence"]:
                bucket["evidence"].append(str(ev))
        for ioc in item.get("iocs", []) or []:
            if str(ioc) not in bucket["iocs"]:
                bucket["iocs"].append(str(ioc))
    return [grouped[k] for k in order]


def render_compromised_summary(
    summary: CompromiseSummary, limit: int = 20, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit) or limit

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"COMPROMISE ASSESSMENT :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors if verbose else summary.errors[: _limit_value(20)]:
            lines.append(danger(f"- {err}"))
        if not verbose and len(summary.errors) > 20:
            lines.append(muted(f"... {len(summary.errors) - 20} more errors"))

    lines.append(_format_kv("Total Hosts", str(summary.total_hosts)))
    lines.append(_format_kv("Compromised Hosts", str(len(summary.compromised_hosts))))

    # ---- Synthesis-level verdict candidates (reviewer accept/reject) ----
    # Sits near the top of the compromise block so the reviewer reads the
    # synthesized classification (LIKELY_FP / LIKELY_CONTROL_WORKING /
    # TP_HARDENING / TP_MALICIOUS_CANDIDATE / INCONCLUSIVE) BEFORE
    # scrolling through the raw per-finding table. See pcapper.verdict_summary
    # for the classification rules.
    try:
        from ..verdict_summary import render as _render_verdict, summarize as _summarize_verdict
        _verdict = _summarize_verdict(summary.detections or [])
        if _verdict.total_detections > 0:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Verdict Candidates"))
            lines.append(_render_verdict(_verdict))
    except Exception:  # noqa: BLE001 — verdict summary must never break output
        pass

    def _compromised_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        high_hosts = [
            host
            for host in summary.compromised_hosts
            if host.severity in {"high", "critical"}
        ]
        if high_hosts:
            score += min(4, len(high_hosts))
            reasons.append(
                f"High-severity compromised hosts identified ({len(high_hosts)})"
            )
        if getattr(summary, "incidents", None):
            score += 1
            reasons.append(f"Incident clusters detected ({len(summary.incidents)})")
        if getattr(summary, "campaigns", None):
            score += 2
            reasons.append(
                f"Shared campaign indicators across hosts ({len(summary.campaigns)})"
            )

        checks = getattr(summary, "deterministic_checks", {}) or {}
        staged = (
            checks.get("multi_stage_sequence", []) if isinstance(checks, dict) else []
        )
        if staged:
            score += 2
            reasons.append(
                f"Multi-stage compromise sequencing observed ({len(staged)})"
            )

        if score >= 7:
            verdict = "YES - high-confidence host compromise activity is present."
            confidence = "High"
        elif score >= 4:
            verdict = "LIKELY - multiple compromise indicators are present."
            confidence = "Medium"
        elif score >= 2:
            verdict = "POSSIBLE - weak-to-moderate compromise indicators are present."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing high-confidence compromise pattern from current heuristics."
            confidence = "Low"

        if not reasons:
            reasons.append("No high-confidence compromise heuristic crossed threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _compromised_verdict()
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

    # Identify likely victims: internal hosts are the assets at risk; external
    # high-severity hosts are the adversary infrastructure they talked to.
    internal_victims = [
        h for h in summary.compromised_hosts if not _is_public_ip(h.ip)
    ]
    external_infra = [
        h
        for h in summary.compromised_hosts
        if _is_public_ip(h.ip) and h.severity in {"high", "critical"}
    ]
    if internal_victims:
        lines.append(muted("Suspected victim host(s):"))
        for host in internal_victims[: _limit_value(5)]:
            why = (
                host.evidence[0]
                if host.evidence
                else "multiple high-severity indicators"
            )
            lines.append(
                danger(
                    f"- {(host.hostname or '-')} ({host.ip}) — "
                    f"{_truncate_text(str(why), 100)}"
                )
            )
    if external_infra:
        infra = ", ".join(
            f"{h.ip}{f' ({h.hostname})' if h.hostname else ''}"
            for h in external_infra[: _limit_value(6)]
        )
        lines.append(muted(f"External infrastructure contacted: {infra}"))

    # Add concrete evidence context directly in the verdict block for analyst triage.
    incidents = list(getattr(summary, "incidents", []) or [])
    campaigns = list(getattr(summary, "campaigns", []) or [])
    if verbose and summary.compromised_hosts:
        lines.append(muted("Who:"))
        lines.append(muted("- Compromised hosts"))
        for host in summary.compromised_hosts[: _limit_value(8)]:
            lines.append(
                muted(
                    f"- {(host.hostname or '-')} ({host.ip}) severity={host.severity} "
                    f"score={host.score} detected={format_ts(host.detection_time)}"
                )
            )

    if verbose and incidents:
        lines.append(muted("When:"))
        lines.append(muted("- Incident clusters"))
        for item in incidents[: _limit_value(8)]:
            stages = item.get("stages", [])
            stage_text = (
                ",".join(str(v) for v in stages[:5])
                if isinstance(stages, list)
                else str(stages)
            )
            lines.append(
                muted(
                    f"- host={item.get('ip', '-')} events={item.get('count', '-')} "
                    f"window={format_ts(item.get('first_ts'))}..{format_ts(item.get('last_ts'))} "
                    f"stages={stage_text or '-'}"
                )
            )

    if verbose and campaigns:
        lines.append(muted("What:"))
        lines.append(muted("- Shared campaign indicators"))
        for item in campaigns[: _limit_value(8)]:
            hosts = item.get("hosts", [])
            host_text = (
                ", ".join(str(v) for v in hosts[: _limit_value(5)])
                if isinstance(hosts, list)
                else str(hosts)
            )
            lines.append(
                muted(
                    f"- {item.get('campaign_id', '-')} ioc={_redact_in_text(str(item.get('ioc', '-')))} "
                    f"host_count={item.get('host_count', '-')} hosts={host_text or '-'}"
                )
            )

    if not verbose:
        if not summary.compromised_hosts:
            lines.append(SUBSECTION_BAR)
            lines.append(
                ok("No hosts met compromise thresholds based on available evidence.")
            )
            lines.append(SECTION_BAR)
            return _finalize_output(lines, show_truncation_note=False)

        lines.append(SUBSECTION_BAR)
        lines.append(header("Most Likely Compromised Hosts"))
        lines.append(
            muted(
                "INTERNAL hosts are the assets at risk (the likely victims); "
                "EXTERNAL hosts are the adversary/peer infrastructure they "
                "contacted — not necessarily compromised themselves."
            )
        )
        # Surface internal victims first (higher triage priority than the
        # external infrastructure they communicated with).
        ranked_hosts = sorted(
            summary.compromised_hosts,
            key=lambda h: (_is_public_ip(h.ip), -int(h.score)),
        )
        rows = [["Host", "IP", "Scope", "Severity", "Score", "Detection Time", "Why"]]
        for host in ranked_hosts[: _limit_value(limit)]:
            evidence_text = " | ".join(host.evidence[:2]) if host.evidence else "-"
            rows.append(
                [
                    host.hostname or "-",
                    host.ip,
                    "INTERNAL" if not _is_public_ip(host.ip) else "external",
                    str(host.severity).upper(),
                    str(host.score),
                    format_ts(host.detection_time),
                    _truncate_text(evidence_text, 70),
                ]
            )
        lines.append(_format_table(rows))
        if len(summary.compromised_hosts) > _limit_value(limit):
            lines.append(
                muted(
                    f"... {len(summary.compromised_hosts) - _limit_value(limit)} additional compromised hosts"
                )
            )

        severe_detections = [
            item
            for item in list(getattr(summary, "detections", []) or [])
            if str(item.get("severity", "info")).lower()
            in {"critical", "high", "warning", "medium"}
        ]
        issues = _dedupe_compromise_issues(severe_detections)
        if issues:
            # Map IP -> hostname (and internal/external) for host attribution.
            host_name = {h.ip: (h.hostname or "") for h in summary.compromised_hosts}

            def _host_label(ip_value: str) -> str:
                name = host_name.get(ip_value, "")
                scope = "internal" if not _is_public_ip(ip_value) else "external"
                return f"{ip_value}{f' ({name})' if name else ''} [{scope}]"

            lines.append(SUBSECTION_BAR)
            lines.append(header("Most Likely Issues"))
            lines.append(
                muted(
                    "Each issue lists WHY it suggests compromise, the hosts involved, "
                    "and the concrete on-wire evidence."
                )
            )
            for item in issues[: _limit_value(12)]:
                severity = str(item.get("severity", "info")).lower()
                summary_text = _truncate_text(str(item.get("summary", "")), 120)
                details = _truncate_text(str(item.get("details", "")), 160)
                source = str(item.get("source", ""))
                if severity == "critical":
                    marker = danger("[CRITICAL]")
                elif severity == "high":
                    marker = danger("[HIGH]")
                else:
                    marker = warn("[MEDIUM]")
                # Skeptical-filter tag — sits between the severity marker and
                # the summary so the reviewer sees at-a-glance that the
                # verdict was already downgraded by a known-FP rule.
                skeptical_tag = ""
                if item.get("skeptical_downgraded"):
                    rule = str(item.get("skeptical_rule", "") or "")
                    orig = str(item.get("skeptical_original_severity", "") or "")
                    skeptical_tag = muted(
                        f" [skeptical: {rule}"
                        + (f", was {orig}" if orig else "")
                        + "]"
                    )
                # Hypothesis-lens tag — reviewer scans for [relevant] first
                # and can skip [unrelated] on a big capture. Only surfaced
                # when the lens was active (non-empty hypothesis_relevance).
                relevance = str(item.get("hypothesis_relevance", "") or "")
                hypothesis_tag = ""
                if relevance == "relevant":
                    hypothesis_tag = danger(" [relevant]")
                elif relevance == "adjacent":
                    hypothesis_tag = warn(" [adjacent]")
                elif relevance == "unrelated":
                    hypothesis_tag = muted(" [unrelated]")
                lines.append(
                    f"{marker}{hypothesis_tag}{skeptical_tag} {summary_text}"
                    + (f"  ({source})" if source else "")
                )
                lines.append(
                    muted(f"  Why: {_compromise_issue_reason(summary_text, source)}")
                )
                # Print the skeptical reason as its own indented line so the
                # analyst sees the concrete rationale for the downgrade
                # without having to read the module docstring.
                if item.get("skeptical_downgraded") and item.get("skeptical_reason"):
                    reason_text = _truncate_text(
                        str(item.get("skeptical_reason", "")), 240
                    )
                    lines.append(muted(f"  Skeptical filter: {reason_text}"))
                # Hosts involved — internal hosts first (the likely victims).
                ips = list(item.get("ips", []) or [])
                ips.sort(key=lambda v: (_is_public_ip(v), v))
                if ips:
                    shown = ", ".join(_host_label(v) for v in ips[: _limit_value(5)])
                    extra = len(ips) - _limit_value(5)
                    if extra > 0:
                        shown += f"  (+{extra} more)"
                    lines.append(muted(f"  Hosts: {shown}"))
                if details:
                    lines.append(muted(f"  Details: {details}"))
                evidence = item.get("evidence", []) or []
                if evidence:
                    lines.append(muted("  Evidence:"))
                    for ev in evidence[: _limit_value(3)]:
                        lines.append(muted(f"    - {_truncate_text(str(ev), 150)}"))
                iocs = item.get("iocs", []) or []
                if iocs:
                    lines.append(
                        muted(
                            "  IOCs: "
                            + _truncate_text(", ".join(str(i) for i in iocs[:10]), 150)
                        )
                    )

        if incidents:
            lines.append(
                _format_kv("Incident Clusters", str(len(incidents)))
            )
        if campaigns:
            lines.append(
                _format_kv("Shared Campaign Indicators", str(len(campaigns)))
            )
        if summary.errors:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Errors"))
            for err in summary.errors[: _limit_value(12)]:
                lines.append(danger(f"- {err}"))

        lines.append(SECTION_BAR)
        return _finalize_output(lines, show_truncation_note=False)

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Compromise Checks"))
    checks = getattr(summary, "deterministic_checks", {}) or {}
    check_labels = [
        ("credential_abuse", "Credential Abuse Evidence"),
        ("beacon_c2", "Beacon/C2 Evidence"),
        ("exfiltration", "Exfiltration Evidence"),
        ("lateral_movement", "Lateral Movement Evidence"),
        ("multi_stage_sequence", "Multi-Stage Sequence Evidence"),
        ("high_confidence_ioc", "High-Confidence IOC Correlation"),
        ("benign_automation_likely", "Likely Benign Automation"),
    ]

    for key, label_text in check_labels:
        evidence_items = checks.get(key, []) if isinstance(checks, dict) else []
        evidence_items = [str(v) for v in (evidence_items or []) if str(v).strip()]
        lines.append(label(label_text))
        if evidence_items:
            if key == "benign_automation_likely":
                lines.append(
                    ok(
                        f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"
                    )
                )
            else:
                lines.append(
                    warn(
                        f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"
                    )
                )
            for item in evidence_items[: _limit_value(8 if verbose else 5)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))
        else:
            lines.append(
                ok(
                    f"No, there is no strong evidence for {label_text.lower()} in this capture."
                )
            )

    priority_rows = list(getattr(summary, "host_priority", []) or [])
    if priority_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Host Priority Queue"))
        rows = [
            ["Host", "IP", "Score", "Severity", "Stages", "IOC Count", "Detection Time"]
        ]
        for item in priority_rows[:limit]:
            stages = item.get("stages", [])
            stage_text = ",".join(stages) if isinstance(stages, list) else str(stages)
            rows.append(
                [
                    str(item.get("host", "-")),
                    str(item.get("ip", "-")),
                    str(item.get("score", "-")),
                    str(item.get("severity", "-")),
                    stage_text or "-",
                    str(item.get("ioc_count", "-")),
                    format_ts(item.get("detection_time")),
                ]
            )
        lines.append(_format_table(rows))

    incidents = list(getattr(summary, "incidents", []) or [])
    if incidents:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Incident Timeline"))
        rows = [["Host IP", "First", "Last", "Events", "Stages", "Duration"]]
        for item in incidents[:limit]:
            first_ts = item.get("first_ts")
            last_ts = item.get("last_ts")
            duration = None
            if isinstance(first_ts, (int, float)) and isinstance(last_ts, (int, float)):
                duration = max(0.0, float(last_ts) - float(first_ts))
            stages = item.get("stages", [])
            rows.append(
                [
                    str(item.get("ip", "-")),
                    format_ts(first_ts),
                    format_ts(last_ts),
                    str(item.get("count", "-")),
                    ",".join(str(v) for v in stages)
                    if isinstance(stages, list)
                    else str(stages),
                    format_duration(duration),
                ]
            )
        lines.append(_format_table(rows))

    campaigns = list(getattr(summary, "campaigns", []) or [])
    if campaigns:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Campaign Correlation"))
        rows = [["Campaign", "Shared IOC", "Host Count", "Hosts"]]
        for item in campaigns[:limit]:
            hosts = item.get("hosts", [])
            host_text = (
                ", ".join(str(v) for v in hosts[: _limit_value(4)])
                if isinstance(hosts, list)
                else str(hosts)
            )
            if isinstance(hosts, list) and len(hosts) > _limit_value(4):
                host_text += "..."
            rows.append(
                [
                    str(item.get("campaign_id", "-")),
                    _truncate_text(str(item.get("ioc", "-")), 48),
                    str(item.get("host_count", "-")),
                    host_text or "-",
                ]
            )
        lines.append(_format_table(rows))

    benign_context = list(getattr(summary, "benign_context", []) or [])
    if benign_context:
        lines.append(SUBSECTION_BAR)
        lines.append(header("False-Positive Context"))
        for item in benign_context[: _limit_value(10 if verbose else 6)]:
            lines.append(muted(f"- {_redact_in_text(str(item))}"))

    if not summary.compromised_hosts:
        lines.append(SUBSECTION_BAR)
        lines.append(
            ok("No hosts met compromise thresholds based on available evidence.")
        )
        lines.append(SECTION_BAR)
        return _finalize_output(lines, show_truncation_note=False)

    lines.append(SUBSECTION_BAR)
    lines.append(header("Compromised Hosts"))
    rows = [["Hostname", "IP", "Detection Time", "Explanation", "Evidence", "IOCs"]]
    row_hosts = (
        summary.compromised_hosts if verbose else summary.compromised_hosts[:limit]
    )
    for host in row_hosts:
        evidence_text = " | ".join(host.evidence[:3]) if host.evidence else "-"
        ioc_text = ", ".join(host.iocs[:4]) if host.iocs else "-"
        rows.append(
            [
                host.hostname or "-",
                host.ip,
                format_ts(host.detection_time),
                _truncate_text(host.explanation or "-", 60),
                _truncate_text(evidence_text, 70),
                _truncate_text(ioc_text, 60),
            ]
        )
    lines.append(_format_table(rows))
    if not verbose and len(summary.compromised_hosts) > limit:
        lines.append(
            muted(
                f"... {len(summary.compromised_hosts) - limit} additional compromised hosts"
            )
        )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Forensics Notes"))
    lines.append(
        muted(
            "- Compromise assessment is heuristic and should be validated with endpoint telemetry."
        )
    )
    lines.append(
        muted(
            "- Evidence and IOCs are extracted from high-signal detections (beaconing, exfil, creds, threats)."
        )
    )

    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)
