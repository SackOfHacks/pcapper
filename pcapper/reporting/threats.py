"""Rendered output for --threats: the cross-analyzer threat view. Every
detection is ranked (severity, likelihood, hits, confidence) and noisy
low-signal categories are suppressed; the report leads with the ranked
threats, their key evidence, the most likely scenarios, OT risk and IDS
corroboration. Actors, storyline, the suppressed context and the scored
assessment are -v detail."""

from __future__ import annotations

import re
from collections import Counter

from ..threats import ThreatSummary
from ..utils import format_ts
from . import _style as st
from ._common import _filtered_detections, _redact_in_text


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


def _threats_verdict(summary: ThreatSummary, filtered: list[dict[str, object]]) -> tuple[str, str, list[str], int]:
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
    rollups: dict[tuple[str, str], dict[str, object]] = {}
    overall_sources: Counter[str] = Counter()
    overall_destinations: Counter[str] = Counter()
    for item in values:
        severity = str(item.get("_severity", "info"))
        source = str(item.get("source", "Threats"))
        summary_text = str(item.get("summary", "")).strip() or "Detection"
        # One category per (severity, title) whatever its case: two analyzers
        # reporting the same thing ("SMBv1 detected" from Files and SMB) are
        # one threat seen by two sources, not two threats.
        key = (severity, summary_text.lower())
        bucket = rollups.get(key)
        if bucket is not None and source not in str(bucket["source"]).split(", "):
            bucket["source"] = f"{bucket['source']}, {source}"
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
            for pair in pair_values[:8]:
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


_HEADLINE = {
    "YES": "attack activity (high confidence)",
    "LIKELY": "likely attack activity",
    "POSSIBLE": "possible attack activity",
    "LOW SIGNAL": "weak threat indicators, not strongly corroborated",
    "NO STRONG SIGNAL": "no notable threat after noise suppression",
}


def _top_peer(counter: object) -> str:
    if isinstance(counter, Counter) and counter:
        peer, n = counter.most_common(1)[0]
        return f"{peer} ({int(n)})"
    return "-"


def _hypothesis_evidence(value: object) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return 0


def render_threats_summary(summary: ThreatSummary, verbose: bool = False) -> str:
    rep = st.Report("Threats", summary.path)
    raw = [i for i in _filtered_detections(summary, verbose=True) if isinstance(i, dict) and _is_network_attack_detection(i)]
    filtered: list[dict[str, object]] = []
    suppressed: list[dict[str, object]] = []
    for item in raw:
        strength = _detection_strength(item)
        enriched = dict(item, _strength=strength, _severity=_severity_level(item.get("severity", "info")),
                        _confidence=_confidence_level(item.get("confidence", "-")))
        (suppressed if _is_noisy_low_signal(item, strength) else filtered).append(enriched)
    ranked, actors_src, actors_dst = _build_rollups(filtered)
    suppressed_ranked = _build_rollups(suppressed)[0] if suppressed else []
    verdict, confidence, reasons, score = _threats_verdict(summary, filtered)
    shown = ranked if st.verbose() else _select_concise_rollups(ranked)

    worst = next((r["severity"] for r in ranked), None)
    rep.headline(worst if ranked else None, _HEADLINE[next(k for k in _HEADLINE if verdict.startswith(k))], st.join([
        f"{st.plural(len(ranked), 'threat category', 'threat categories')} from {st.plural(len(filtered), 'detection')}",
        f"{len(suppressed)} suppressed as noise" if suppressed else "",
        st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else "",
    ]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors[: None if st.verbose() else 8]])

    rep.section("Threats", st.table(
        ["Severity", "Detection", "Source", "Hits", "Confidence", "Top source", "Top target"] + (["Likelihood"] if st.verbose() else []),
        [[st.badge(r["severity"]), _redact_in_text(str(r["summary"])), r["source"], st.count(r["count"]), r["confidence"],
          _top_peer(r["src_counts"]), _top_peer(r["dst_counts"])] + ([r["likelihood"]] if st.verbose() else []) for r in shown],
        align="lllrlll" + ("r" if st.verbose() else ""), widths=(None, 60), max_rows=None,
    ) + ([st.more(len(ranked) - len(shown), "lower-likelihood category")] if len(ranked) > len(shown) else []))

    evidence: list[str] = []
    pad = " " * (st.BADGE_W + 4)
    for r in shown if st.verbose() else shown[:4]:
        context = f"{r['source']} · {st.plural(int(r['count']), 'hit')} · {r['confidence']} confidence"
        evidence.append(f"  {st.badge(r['severity'])}  {st.strong(_redact_in_text(str(r['summary'])))}  {st.dim(context)}")
        detail = str(r.get("details", "") or "").strip()
        if detail and (st.verbose() or r["severity"] in {"critical", "high"}):
            evidence.append(pad + st.dim(st.cut(_redact_in_text(detail), 150)))
        entries = [str(e) for e in (r.get("evidence") or []) if str(e).strip() and str(e).strip() not in detail]
        for entry in entries[: None if st.verbose() else 1]:
            evidence.append(pad + st.dim(st.cut("- " + _redact_in_text(entry), 150)))
    rep.section("Key evidence", evidence)

    hypotheses = sorted([h for h in (summary.threat_hypotheses or []) if isinstance(h, dict) and str(h.get("hypothesis", "")).strip()],
                        key=lambda h: (_confidence_rank(h.get("confidence", "-")), -_hypothesis_evidence(h.get("evidence", 0)),
                                       str(h.get("hypothesis", ""))))
    rep.section("Likely scenarios", [
        f"  {st.badge({'high': 'high', 'medium': 'medium'}.get(_confidence_level(h.get('confidence')), 'low'))}  "
        f"{_redact_in_text(str(h.get('hypothesis', '-')))}  {st.dim(st.plural(_hypothesis_evidence(h.get('evidence', 0)), 'signal'))}"
        for h in (hypotheses if st.verbose() else hypotheses[:2])])

    ot_lines: list[tuple[str, str]] = []
    if summary.ot_risk_score:
        posture = "HIGH" if summary.ot_risk_score >= 60 else "MEDIUM" if summary.ot_risk_score >= 25 else "LOW"
        ot_lines.append(("Risk posture", f"{summary.ot_risk_score}/100 ({posture})"))
    if summary.public_ot_pairs:
        ot_lines.append(("Public OT flows", st.bad(str(len(summary.public_ot_pairs)))))
    ot_lines.append(("Signals", "; ".join(_redact_in_text(str(f)).rstrip(".")
                                          for f in (summary.ot_risk_findings or [])[: None if st.verbose() else 2])))
    if st.verbose():
        ot_lines.append(("Protocols", st.top(Counter(summary.ot_protocol_counts or {}), None)))
        ot_lines.append(("Public OT pairs", ", ".join(str(p) for p in summary.public_ot_pairs or [])))
        ot_lines.append(("Internal OT peers", ", ".join(f"{p} ({n})" for p, n in summary.ot_peer_internal or [])))
        ot_lines.append(("External OT peers", ", ".join(f"{p} ({n})" for p, n in summary.ot_peer_external or [])))
    rep.section("OT risk", st.kv(ot_lines) if (summary.ot_risk_score or summary.public_ot_pairs or summary.ot_protocol_counts) else [])

    meta = getattr(summary, "suricata_metadata", None) or {}
    events = getattr(summary, "suricata_event_counts", None) or {}
    ids_mode = bool(meta) or any(str(r.get("source", "")).strip().lower() == "suricata" for r in filtered)
    rep.section("IDS corroboration", st.kv(
        ([(label_text, str(meta.get(key))) for key, label_text in (("engine", "Engine"), ("version", "Version"),
                                                                   ("rules_age_days", "Rules age (days)"), ("pcaps_scanned", "Captures scanned"))
          if st.verbose() and meta.get(key) not in (None, "")])
        + ([("Events", f"{sum(int(v) for v in events.values())}: {st.top(Counter({k: int(v) for k, v in events.items()}), 4)}")] if events else [])
    ) if ids_mode else [])

    rep.section("Assessment", st.kv([("Verdict", verdict), ("Confidence", f"{confidence} (score {score})"),
                                     ("Detections", f"{len(raw)} raw · {len(filtered)} kept · {len(suppressed)} suppressed"),
                                     ("Packets", st.count(summary.total_packets) if summary.total_packets else ""),
                                     ("Window", f"{format_ts(summary.first_seen)} / {format_ts(summary.last_seen)}"
                                      if summary.first_seen is not None else ""),
                                     ("Duration", f"{summary.duration:.1f}s" if summary.duration is not None else "")])
                + st.bullets([_redact_in_text(r) for r in reasons], max_items=None), detail=True)
    rep.section("Actors", st.kv([("Likely sources", st.top(actors_src, None)), ("Likely targets", st.top(actors_dst, None))]), detail=True)
    rep.section("Storyline", st.bullets([_redact_in_text(str(s)) for s in (summary.storyline or [])], max_items=None), detail=True)
    rep.section("Suppressed", st.table(
        ["Severity", "Source", "Detection", "Hits", "Likelihood"],
        [[st.badge(r["severity"]), r["source"], _redact_in_text(str(r["summary"])), r["count"], r["likelihood"]] for r in suppressed_ranked],
        align="lllrr", max_rows=None,
    ), detail=True)
    rep.section("False-positive context", st.bullets([_redact_in_text(str(b)) for b in (getattr(summary, "benign_context", None) or [])],
                                                     max_items=None), detail=True)
    return rep.render()
