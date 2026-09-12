"""Rendered output for threats analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
import ipaddress
import re
from collections import Counter
from ..coloring import (
    danger,
    header,
    muted,
    ok,
    warn,
)
from ..threats import ThreatSummary
from ..utils import (
    format_ts,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _filtered_detections,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
    _redact_in_text,
    _truncate_text,
)


def render_threats_summary(summary: ThreatSummary, verbose: bool = False) -> str:
    verbose = True
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"THREATS OVERVIEW :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    def _highlight_public_ips_local(text: str) -> str:
        tokens = text.split()
        for idx, token in enumerate(tokens):
            stripped = token.strip("[](),;|")
            try:
                ip = ipaddress.ip_address(stripped)
            except Exception:
                continue
            if ip.is_global:
                tokens[idx] = token.replace(stripped, danger(stripped))
        return " ".join(tokens)

    def _severity_level(value: object) -> str:
        sev = str(value or "info").strip().lower()
        if sev in {"critical", "high", "warning"}:
            return sev
        if sev in {"warn", "medium"}:
            return "warning"
        return "info"

    def _severity_rank(value: object) -> int:
        sev = _severity_level(value)
        return {"critical": 0, "high": 1, "warning": 2, "info": 3}.get(sev, 3)

    def _confidence_level(value: object) -> str:
        text = str(value or "").strip().lower()
        if text in {"high", "medium", "low"}:
            return text
        if text in {"med", "moderate"}:
            return "medium"
        if text in {"very-high", "very high", "strong"}:
            return "high"
        if text in {"weak", "none", "unknown"}:
            return "low"
        try:
            numeric = float(text)
            if numeric >= 0.75:
                return "high"
            if numeric >= 0.45:
                return "medium"
            return "low"
        except Exception:
            return "-"

    def _confidence_rank(value: object) -> int:
        level = _confidence_level(value)
        return {"high": 0, "medium": 1, "low": 2}.get(level, 3)

    def _is_network_attack_detection(item: dict[str, object]) -> bool:
        # The threat engine (_curate_threat_detections) has already dropped info
        # noise and signal-thresholded warnings, so anything reaching here at
        # warning severity or above is a real, corroborated threat lead — keep
        # it regardless of source. (A previous source/keyword whitelist silently
        # dropped genuine high-severity findings — recovered IOCs, attack
        # tradecraft, carved malware, malicious JA3/cert IOCs, crackable creds —
        # whenever the source name wasn't in a hardcoded list, badly
        # under-reporting infections like Hancitor.) Only the rare info-level
        # detection that slips through still needs the network-relevance gate.
        if _severity_level(item.get("severity", "info")) in {
            "critical",
            "high",
            "warning",
        }:
            return True

        source = str(item.get("source", "")).strip().lower()
        summary_text = str(item.get("summary", "")).strip().lower()
        details_text = str(item.get("details", "")).strip().lower()
        blob = f"{source} {summary_text} {details_text}"

        network_sources = {
            "arp",
            "dhcp",
            "dns",
            "icmp",
            "tcp",
            "udp",
            "recon",
            "traffic",
            "auth",
            "lateral",
            "c2",
            "exfil",
            "payload",
            "smb",
            "rdp",
            "winrm",
            "ssh",
            "rpc",
            "snmp",
            "suricata",
            "ot/ics",
            "credential",
            "execution",
            "safety",
            "correlation",
        }
        if source in network_sources:
            return True

        strong_network_tokens = (
            "arp",
            "spoof",
            "poison",
            "mitm",
            "scan",
            "probing",
            "recon",
            "syn",
            "flood",
            "dos",
            "denial of service",
            "dns tunn",
            "beacon",
            "c2",
            "lateral movement",
            "brute-force",
            "authentication fail",
            "exfil",
            "ot control",
            "threat-intel",
        )
        return any(token in blob for token in strong_network_tokens)

    def _pair_max_count(values: object) -> int:
        if not isinstance(values, list) or not values:
            return 0
        best = 0
        for pair in values:
            if not isinstance(pair, tuple) or len(pair) < 2:
                continue
            try:
                best = max(best, int(pair[1]))
            except Exception:
                continue
        return best

    def _detection_strength(item: dict[str, object]) -> int:
        sev = _severity_level(item.get("severity", "info"))
        base = {"critical": 50, "high": 35, "warning": 20, "info": 0}.get(sev, 0)
        evidence = item.get("evidence")
        evidence_count = (
            len(evidence)
            if isinstance(evidence, list)
            else (1 if isinstance(evidence, str) and evidence.strip() else 0)
        )
        peer_signal = max(
            _pair_max_count(item.get("top_sources")),
            _pair_max_count(item.get("top_destinations")),
            _pair_max_count(item.get("top_clients")),
            _pair_max_count(item.get("top_servers")),
        )
        detail_count = 0
        details = str(item.get("details", "")).strip()
        summary_text = str(item.get("summary", "")).strip().lower()
        for token in re.findall(r"\b(\d{1,6})\b", details):
            try:
                detail_count = max(detail_count, int(token))
            except Exception:
                continue
        recon_signal = any(
            token in f"{summary_text} {details.lower()}"
            for token in ("sweep", "scan", "recon", "enumeration", "probing")
        )
        recon_bonus = 0
        if recon_signal:
            if detail_count >= 20:
                recon_bonus = 8
            elif detail_count >= 10:
                recon_bonus = 4
        return (
            base
            + min(12, evidence_count * 3)
            + min(12, peer_signal)
            + (2 if detail_count >= 10 else 0)
            + recon_bonus
        )

    def _is_noisy_low_signal(item: dict[str, object], strength: int) -> bool:
        sev = _severity_level(item.get("severity", "info"))
        if sev == "info":
            return True
        if sev in {"critical", "high"}:
            return False

        summary_text = str(item.get("summary", "")).strip().lower()
        source_text = str(item.get("source", "")).strip().lower()
        details_text = str(item.get("details", "")).strip().lower()
        blob = f"{source_text} {summary_text} {details_text}"
        detail_count = 0
        for token in re.findall(r"\b(\d{1,6})\b", details_text):
            try:
                detail_count = max(detail_count, int(token))
            except Exception:
                continue
        recon_signal = any(
            token in blob
            for token in ("sweep", "scan", "recon", "enumeration", "probing")
        )
        strong_recon_signal = recon_signal and detail_count >= 20
        noisy_tokens = (
            "telemetry",
            "activity observed",
            "candidate flow",
            "high traffic concentration",
            "broad outbound external communication",
            "ot protocol function operations observed",
            "ot diagnostic/maintenance operations observed",
            "safety plc/sis traffic detected",
            "potential ",
        )
        has_context = False
        for key in (
            "top_sources",
            "top_destinations",
            "top_clients",
            "top_servers",
            "evidence",
        ):
            value = item.get(key)
            if isinstance(value, list) and value:
                has_context = True
                break
            if isinstance(value, str) and value.strip():
                has_context = True
                break

        min_strength = 26
        if any(token in blob for token in noisy_tokens) and not strong_recon_signal:
            min_strength = 31
        if strong_recon_signal:
            min_strength = min(min_strength, 24)
        if not has_context:
            min_strength += 4
        return strength < min_strength

    high_priority_tokens = (
        "critical",
        "multi-stage",
        "correlation",
        "beacon",
        "c2",
        "credential",
        "lateral",
        "exfil",
        "threat-intel",
        "brute-force",
        "internet-exposed",
        "ids alert",
        "suspicious command/tooling",
    )
    noisy_summary_tokens = (
        "telemetry",
        "activity observed",
        "candidate flow",
        "ot protocol activity observed",
        "ot protocol function operations observed",
        "ot diagnostic/maintenance operations observed",
        "safety plc/sis traffic detected",
        "high traffic concentration on a target",
        "broad outbound external communication",
    )

    def _is_priority_summary(text: str) -> bool:
        lowered = text.lower()
        return any(token in lowered for token in high_priority_tokens)

    def _is_noisy_summary(text: str) -> bool:
        lowered = text.lower()
        return any(token in lowered for token in noisy_summary_tokens)

    raw_detections = [
        item
        for item in _filtered_detections(summary, verbose=True)
        if isinstance(item, dict) and _is_network_attack_detection(item)
    ]

    filtered: list[dict[str, object]] = []
    suppressed: list[dict[str, object]] = []
    for item in raw_detections:
        strength = _detection_strength(item)
        enriched = dict(item)
        enriched["_strength"] = strength
        enriched["_severity"] = _severity_level(item.get("severity", "info"))
        enriched["_confidence"] = _confidence_level(item.get("confidence", "-"))
        if _is_noisy_low_signal(item, strength):
            suppressed.append(enriched)
            continue
        filtered.append(enriched)

    def _threats_verdict() -> tuple[str, str, list[str], int]:
        reasons: list[str] = []
        sev_counts = Counter(str(item.get("_severity", "info")) for item in filtered)
        score = 0

        critical_count = int(sev_counts.get("critical", 0) or 0)
        high_count = int(sev_counts.get("high", 0) or 0)
        warning_count = int(sev_counts.get("warning", 0) or 0)
        if critical_count:
            score += min(5, critical_count * 2)
            reasons.append(f"Critical detections: {critical_count}")
        if high_count:
            score += min(4, high_count)
            reasons.append(f"High-severity detections: {high_count}")
        if warning_count >= 4:
            score += 1
            reasons.append(f"Elevated warning volume: {warning_count}")
        if len(filtered) >= 10:
            score += 1
            reasons.append(f"Detection volume after filtering: {len(filtered)}")
        if summary.public_ot_pairs:
            score += 1
            reasons.append(
                f"Public OT/ICS communication pairs: {len(summary.public_ot_pairs)}"
            )
        if getattr(summary, "suricata_metadata", None):
            score += 1
            reasons.append("Suricata corroboration present")

        if score >= 8:
            return (
                "YES - high-confidence attack activity is present.",
                "High",
                reasons,
                score,
            )
        if score >= 5:
            return (
                "LIKELY - suspicious attack activity is present.",
                "Medium",
                reasons,
                score,
            )
        if score >= 3:
            return (
                "POSSIBLE - moderate threat indicators are present.",
                "Low",
                reasons,
                score,
            )
        if filtered:
            return (
                "LOW SIGNAL - weak threat indicators are present but not strongly corroborated.",
                "Low",
                reasons,
                score,
            )
        return (
            "NO STRONG SIGNAL - no high-confidence threat pattern after filtering.",
            "Low",
            reasons if reasons else ["Low-confidence/noisy detections were suppressed"],
            score,
        )

    def _rollup_likelihood(item: dict[str, object]) -> int:
        sev = _severity_level(item.get("severity", "info"))
        score = {"critical": 90, "high": 72, "warning": 48, "info": 12}.get(sev, 0)
        score += min(20, int(item.get("count", 0) or 0) * 3)
        score += min(16, int(item.get("strength", 0) or 0) // 2)
        conf_rank = int(item.get("confidence_rank", 3) or 3)
        score += {0: 14, 1: 8, 2: 3, 3: 0}.get(conf_rank, 0)
        if bool(item.get("priority", False)):
            score += 12
        if bool(item.get("noisy", False)):
            score -= 14
        src_counter = item.get("src_counts")
        dst_counter = item.get("dst_counts")
        if isinstance(src_counter, Counter) and src_counter:
            score += 3
        if isinstance(dst_counter, Counter) and dst_counter:
            score += 3
        evidence_values = item.get("evidence", [])
        if isinstance(evidence_values, list):
            score += min(6, len(evidence_values) * 2)
        return score

    def _build_rollups(
        values: list[dict[str, object]],
    ) -> tuple[list[dict[str, object]], Counter[str], Counter[str]]:
        rollups: dict[tuple[str, str, str], dict[str, object]] = {}
        overall_sources: Counter[str] = Counter()
        overall_destinations: Counter[str] = Counter()
        for item in values:
            severity = str(item.get("_severity", "info"))
            source = str(item.get("source", "Threats"))
            summary_text = str(item.get("summary", "")).strip() or "Detection"
            key = (severity, source, summary_text)
            bucket = rollups.get(key)
            if bucket is None:
                bucket = {
                    "severity": severity,
                    "source": source,
                    "summary": summary_text,
                    "count": 0,
                    "strength": 0,
                    "details": "",
                    "src_counts": Counter(),
                    "dst_counts": Counter(),
                    "evidence": [],
                    "confidence_rank": 3,
                    "priority": _is_priority_summary(summary_text),
                    "noisy": _is_noisy_summary(summary_text),
                }
                rollups[key] = bucket

            bucket["count"] = int(bucket["count"]) + 1
            bucket["strength"] = max(
                int(bucket["strength"]), int(item.get("_strength", 0) or 0)
            )
            bucket["confidence_rank"] = min(
                int(bucket["confidence_rank"]),
                _confidence_rank(item.get("_confidence", item.get("confidence", "-"))),
            )
            details = str(item.get("details", "")).strip()
            if details and not str(bucket["details"]).strip():
                bucket["details"] = details

            for key_name, target_counter in (
                ("top_sources", bucket["src_counts"]),
                ("top_clients", bucket["src_counts"]),
                ("top_destinations", bucket["dst_counts"]),
                ("top_servers", bucket["dst_counts"]),
            ):
                pair_values = item.get(key_name)
                if not isinstance(pair_values, list):
                    continue
                for pair in pair_values[: _limit_value(8)]:
                    if not isinstance(pair, tuple) or len(pair) < 2:
                        continue
                    label_text = str(pair[0]).strip()
                    if not label_text:
                        continue
                    try:
                        pair_count = int(pair[1])
                    except Exception:
                        continue
                    target_counter[label_text] += pair_count
                    if key_name in {"top_sources", "top_clients"}:
                        overall_sources[label_text] += pair_count
                    else:
                        overall_destinations[label_text] += pair_count

            bucket_evidence = bucket["evidence"]
            evidence_value = item.get("evidence")
            candidates: list[str] = []
            if isinstance(evidence_value, list):
                candidates.extend(str(entry) for entry in evidence_value)
            elif isinstance(evidence_value, str) and evidence_value.strip():
                candidates.append(evidence_value)
            for entry in candidates:
                cleaned = str(entry).strip()
                if not cleaned or cleaned in bucket_evidence:
                    continue
                bucket_evidence.append(cleaned)
                if len(bucket_evidence) >= 10:
                    break

        ranked_rollups = list(rollups.values())
        for item in ranked_rollups:
            item["likelihood"] = _rollup_likelihood(item)
            conf_rank = int(item.get("confidence_rank", 3) or 3)
            if conf_rank in {0, 1, 2}:
                item["confidence"] = {0: "high", 1: "medium", 2: "low"}[conf_rank]
            else:
                # Most internal detections carry no explicit confidence field;
                # derive one from the computed likelihood (which already folds in
                # severity, hit count, peer fan-out, and corroborating evidence)
                # so the triage table never shows a bare "-".
                likelihood = int(item.get("likelihood", 0) or 0)
                if likelihood >= 72:
                    item["confidence"] = "high"
                elif likelihood >= 45:
                    item["confidence"] = "medium"
                else:
                    item["confidence"] = "low"
        ranked_rollups.sort(
            key=lambda item: (
                _severity_rank(item.get("severity", "info")),
                -int(item.get("likelihood", 0) or 0),
                -int(item.get("count", 0) or 0),
                str(item.get("source", "")),
                str(item.get("summary", "")),
            )
        )
        return ranked_rollups, overall_sources, overall_destinations

    def _select_concise_rollups(
        values: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        concise: list[dict[str, object]] = []
        for item in values:
            sev = _severity_level(item.get("severity", "info"))
            likelihood = int(item.get("likelihood", 0) or 0)
            priority = bool(item.get("priority", False))
            noisy = bool(item.get("noisy", False))
            if sev in {"critical", "high"}:
                if noisy and not priority and likelihood < 72:
                    continue
                concise.append(item)
                continue
            if sev != "warning":
                continue
            if likelihood < 68 and not (priority and likelihood >= 58):
                continue
            if noisy and not priority:
                continue
            concise.append(item)
        if concise:
            return concise[:6]
        return values[:3]

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors[: _limit_value(8)]:
            lines.append(danger(f"- {err}"))

    verdict, confidence, verdict_reasons, verdict_score = _threats_verdict()
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif (
        verdict.startswith("LIKELY")
        or verdict.startswith("POSSIBLE")
        or verdict.startswith("LOW SIGNAL")
    ):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", f"{confidence} (score={verdict_score})"))
    if verdict_reasons:
        lines.append(muted("Why:"))
        for reason in verdict_reasons[: _limit_value(6)]:
            lines.append(muted(f"- {_redact_in_text(reason)}"))

    ranked_rollups, overall_sources, overall_destinations = _build_rollups(filtered)
    shown_rollups = (
        ranked_rollups if verbose else _select_concise_rollups(ranked_rollups)
    )
    suppressed_rollups: list[dict[str, object]] = []
    if suppressed:
        suppressed_rollups, _, _ = _build_rollups(suppressed)

    lines.append(SUBSECTION_BAR)
    lines.append(header("Snapshot"))
    lines.append(_format_kv("Threat Detections (raw)", str(len(raw_detections))))
    lines.append(_format_kv("Threat Detections (kept)", str(len(filtered))))
    if verbose:
        lines.append(
            _format_kv("Suppressed as low-confidence/noisy", str(len(suppressed)))
        )
    lines.append(_format_kv("Likely Categories Shown", str(len(shown_rollups))))
    if summary.total_packets:
        lines.append(_format_kv("Packets", str(summary.total_packets)))
    if summary.first_seen is not None or summary.last_seen is not None:
        lines.append(_format_kv("First Seen", format_ts(summary.first_seen)))
        lines.append(_format_kv("Last Seen", format_ts(summary.last_seen)))
    if summary.duration is not None:
        lines.append(_format_kv("Duration", f"{summary.duration:.1f}s"))

    hypotheses = list(getattr(summary, "threat_hypotheses", []) or [])
    if hypotheses:

        def _hyp_evidence(value: object) -> int:
            try:
                return int(str(value).strip())
            except Exception:
                return 0

        hypotheses = [
            item
            for item in hypotheses
            if isinstance(item, dict) and str(item.get("hypothesis", "")).strip()
        ]
        hypotheses.sort(
            key=lambda item: (
                _confidence_rank(item.get("confidence", "-")),
                -_hyp_evidence(item.get("evidence", 0)),
                str(item.get("hypothesis", "")),
            )
        )
        if hypotheses:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Most Likely Scenarios"))
            for item in hypotheses[: _limit_value(6 if verbose else 2)]:
                conf = _confidence_level(item.get("confidence", "-"))
                ev_count = _hyp_evidence(item.get("evidence", 0))
                if conf == "high":
                    marker = danger("[HIGH]")
                elif conf == "medium":
                    marker = warn("[MED]")
                else:
                    marker = muted("[LOW]")
                suffix = f"(confidence={conf}, signals={ev_count})"
                lines.append(
                    f"{marker} {_redact_in_text(str(item.get('hypothesis', '-')))} {muted(suffix)}"
                )

    if not filtered:
        lines.append(SUBSECTION_BAR)
        lines.append(ok("No notable high-confidence threats after noise suppression."))
        lines.append(SECTION_BAR)
        return _finalize_output(lines, show_truncation_note=False)

    lines.append(SUBSECTION_BAR)
    lines.append(
        header("Detection Summary (Ranked)" if verbose else "Most Likely Detections")
    )
    if verbose:
        rows = [
            [
                "Sev",
                "Source",
                "Detection",
                "Hits",
                "Confidence",
                "Likely",
                "Top Source",
                "Top Destination",
            ]
        ]
        max_rows = _limit_value(20)
    else:
        rows = [["Sev", "Detection", "Hits", "Confidence", "Top Source", "Top Target"]]
        max_rows = _limit_value(6)
    shown_rollups = shown_rollups[:max_rows]
    for item in shown_rollups:
        sev_text = str(item.get("severity", "info")).upper()[:4]
        src_counter = item.get("src_counts", Counter())
        dst_counter = item.get("dst_counts", Counter())
        top_src = "-"
        top_dst = "-"
        if isinstance(src_counter, Counter) and src_counter:
            src_ip, src_count = src_counter.most_common(1)[0]
            top_src = f"{_highlight_public_ips_local(str(src_ip))}({int(src_count)})"
        if isinstance(dst_counter, Counter) and dst_counter:
            dst_ip, dst_count = dst_counter.most_common(1)[0]
            top_dst = f"{_highlight_public_ips_local(str(dst_ip))}({int(dst_count)})"
        confidence_text = str(item.get("confidence", "-")).upper()
        if verbose:
            rows.append(
                [
                    sev_text,
                    str(item.get("source", "-")),
                    _highlight_public_ips_local(
                        _redact_in_text(str(item.get("summary", "-")))
                    ),
                    str(int(item.get("count", 0) or 0)),
                    confidence_text,
                    str(int(item.get("likelihood", 0) or 0)),
                    top_src,
                    top_dst,
                ]
            )
        else:
            rows.append(
                [
                    sev_text,
                    _highlight_public_ips_local(
                        _redact_in_text(str(item.get("summary", "-")))
                    ),
                    str(int(item.get("count", 0) or 0)),
                    confidence_text,
                    top_src,
                    top_dst,
                ]
            )
    lines.append(_format_table(rows))

    hidden_rollups = max(0, len(ranked_rollups) - len(shown_rollups))
    if hidden_rollups and not verbose:
        lines.append(
            muted(
                f"{hidden_rollups} additional high-signal category(s) hidden. Use `-v` for full ranked output."
            )
        )
    if len(suppressed_rollups) and not verbose:
        lines.append(
            muted(
                f"{len(suppressed_rollups)} low-signal/noisy category(s) hidden. Use `-v` to inspect."
            )
        )

    if (overall_sources or overall_destinations) and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Actors"))
        if overall_sources:
            lines.append(muted("Likely Sources:"))
            for ip_value, count in overall_sources.most_common(_limit_value(8)):
                lines.append(
                    muted(
                        f"- {_highlight_public_ips_local(str(ip_value))}: {int(count)}"
                    )
                )
        if overall_destinations:
            lines.append(muted("Likely Targets:"))
            for ip_value, count in overall_destinations.most_common(_limit_value(8)):
                lines.append(
                    muted(
                        f"- {_highlight_public_ips_local(str(ip_value))}: {int(count)}"
                    )
                )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Priority Evidence" if verbose else "Key Evidence"))
    evidence_limit = _limit_value(12 if verbose else 4)
    for item in shown_rollups[:evidence_limit]:
        sev = str(item.get("severity", "info")).lower()
        if sev == "critical":
            marker = danger("[CRIT]")
        elif sev == "high":
            marker = danger("[HIGH]")
        else:
            marker = warn("[WARN]")
        source_text = str(item.get("source", "Threats"))
        hit_count = int(item.get("count", 0) or 0)
        likelihood = int(item.get("likelihood", 0) or 0)
        confidence_text = str(item.get("confidence", "-")).upper()
        context_text = muted(
            f"({source_text}, hits={hit_count}, conf={confidence_text}, likely={likelihood})"
        )
        lines.append(
            f"{marker} {_highlight_public_ips_local(_redact_in_text(str(item.get('summary', '-'))))} {context_text}"
        )
        detail_text = str(item.get("details", "")).strip()
        show_detail = bool(detail_text) and (verbose or sev in {"critical", "high"})
        if show_detail:
            lines.append(
                muted(
                    f"  {_highlight_public_ips_local(_redact_in_text(_truncate_text(detail_text, 180)))}"
                )
            )
        evidence_values = item.get("evidence", [])
        if isinstance(evidence_values, list) and evidence_values:
            for entry in evidence_values[: _limit_value(4 if verbose else 1)]:
                lines.append(
                    muted(
                        f"    - {_highlight_public_ips_local(_redact_in_text(str(entry)))}"
                    )
                )

    if summary.ot_protocol_counts or summary.public_ot_pairs or summary.ot_risk_score:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT Context" if verbose else "OT Risk Signal"))
        if verbose and summary.ot_protocol_counts:
            proto_text = ", ".join(
                f"{name} ({count})"
                for name, count in sorted(
                    summary.ot_protocol_counts.items(),
                    key=lambda pair: (-int(pair[1]), str(pair[0])),
                )[: _limit_value(8)]
            )
            lines.append(_format_kv("OT Protocols", proto_text))
        if summary.public_ot_pairs:
            lines.append(
                _format_kv("Public OT Flows", str(len(summary.public_ot_pairs)))
            )
        if summary.ot_risk_score:
            posture = "LOW"
            if summary.ot_risk_score >= 60:
                posture = "HIGH"
            elif summary.ot_risk_score >= 25:
                posture = "MEDIUM"
            lines.append(
                _format_kv(
                    "OT Risk Posture", f"{summary.ot_risk_score}/100 ({posture})"
                )
            )
        if summary.ot_risk_findings:
            ot_findings = summary.ot_risk_findings[: _limit_value(6 if verbose else 1)]
            for finding in ot_findings:
                lines.append(muted(f"- {_redact_in_text(str(finding))}"))

    if summary.storyline and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Attack Storyline"))
        for story_line in summary.storyline[: _limit_value(8)]:
            lines.append(muted(f"- {_redact_in_text(str(story_line))}"))

    suricata_mode = bool(getattr(summary, "suricata_metadata", None)) or any(
        str(item.get("source", "")).strip().lower() == "suricata" for item in filtered
    )
    if suricata_mode:
        suricata_metadata = getattr(summary, "suricata_metadata", {}) or {}
        suricata_event_counts = getattr(summary, "suricata_event_counts", {}) or {}
        lines.append(SUBSECTION_BAR)
        lines.append(header("Suricata Snapshot" if verbose else "IDS Corroboration"))
        if verbose and suricata_metadata:
            for key, label_text in (
                ("engine", "Engine"),
                ("version", "Version"),
                ("rules_age_days", "Rules Age (days)"),
                ("pcaps_scanned", "PCAPs Scanned"),
            ):
                value = suricata_metadata.get(key)
                if value not in {None, ""}:
                    lines.append(_format_kv(label_text, str(value)))
        if suricata_event_counts:
            total_events = sum(int(v) for v in suricata_event_counts.values())
            lines.append(_format_kv("Parsed Events", str(total_events)))
            top_events = sorted(
                suricata_event_counts.items(),
                key=lambda pair: (-int(pair[1]), str(pair[0])),
            )[: _limit_value(8 if verbose else 4)]
            event_text = ", ".join(f"{name}({count})" for name, count in top_events)
            if event_text:
                lines.append(_format_kv("Top Event Types", event_text))
    if verbose and suppressed_rollups:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Suppressed / Low-Signal Context"))
        rows = [["Sev", "Source", "Detection", "Hits", "Likely"]]
        for item in suppressed_rollups[: _limit_value(12)]:
            rows.append(
                [
                    str(item.get("severity", "info")).upper()[:4],
                    str(item.get("source", "-")),
                    _highlight_public_ips_local(
                        _redact_in_text(str(item.get("summary", "-")))
                    ),
                    str(int(item.get("count", 0) or 0)),
                    str(int(item.get("likelihood", 0) or 0)),
                ]
            )
        lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)
