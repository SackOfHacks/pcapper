"""Rendered output for --compromised: which hosts look compromised, why,
and the evidence -- see ``render_compromised_summary``."""

from __future__ import annotations

from ..compromised import CompromiseSummary
from ..utils import format_duration, format_ts
from ..utils import is_public_ip as _is_public_ip
from . import _style as st
from ._common import _redact_in_text, _render_deterministic_checks

_COMPROMISE_ISSUE_REASONS = [
    # (substring to match in summary, why-this-indicates-compromise explanation)
    (
        "file hash ioc",
        "Files matching malware heuristics (executable/script/archive) were "
        "transferred in the clear; the hashes are pivotable IOCs — look them up "
        "in threat intel and correlate with the delivering host.",
    ),
    (
        "executable payload",
        "An executable (EXE/DLL) was downloaded -- the classic dropper or "
        "second-stage delivery; pivot the SHA-256 in threat intel and find what "
        "ran it on the receiving host.",
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


_VERDICT_TAG = {
    "TP_MALICIOUS_CANDIDATE": ("malicious candidate", "bad"),
    "TP_HARDENING": ("hardening", "caution"),
    "LIKELY_FP": ("likely false positive", "dim"),
    "LIKELY_CONTROL_WORKING": ("control working", "dim"),
}


def _assessment(summary: CompromiseSummary) -> tuple[str, str, list[str], int]:
    """The weighted score the report used to lead with (kept as -v context)."""
    score, reasons = 0, []
    high_hosts = [h for h in summary.compromised_hosts if h.severity in {"high", "critical"}]
    if high_hosts:
        score += min(4, len(high_hosts))
        reasons.append(f"high-severity compromised hosts ({len(high_hosts)})")
    if summary.incidents:
        score += 1
        reasons.append(f"incident clusters ({len(summary.incidents)})")
    if summary.campaigns:
        score += 2
        reasons.append(f"shared campaign indicators across hosts ({len(summary.campaigns)})")
    checks = getattr(summary, "deterministic_checks", {}) or {}
    staged = checks.get("multi_stage_sequence", []) if isinstance(checks, dict) else []
    if staged:
        score += 2
        reasons.append(f"multi-stage compromise sequencing ({len(staged)})")
    if score >= 7:
        return "YES - high-confidence host compromise", "High", reasons, score
    if score >= 4:
        return "LIKELY - multiple compromise indicators", "Medium", reasons, score
    if score >= 2:
        return "POSSIBLE - weak-to-moderate compromise indicators", "Low", reasons, score
    return "NO STRONG SIGNAL from the current heuristics", "Low", reasons, score


def render_compromised_summary(summary: CompromiseSummary, limit: int = 20, verbose: bool = False) -> str:
    """Which hosts look compromised and why: suspected victims (internal)
    and the infrastructure they reached (external), then each distinct issue
    with why it suggests compromise, the hosts, the on-wire evidence and
    IOCs, tagged with its review class (malicious candidate / hardening /
    likely FP); incidents and shared campaign indicators follow. The scored
    assessment, priority queue and per-host detail are -v."""
    from ..verdict_summary import _classify

    rep = st.Report("Compromise", summary.path)
    hosts = sorted(summary.compromised_hosts, key=lambda h: (_is_public_ip(h.ip), -st.sev_rank(h.severity), -int(h.score or 0)))
    victims = [h for h in hosts if not _is_public_ip(h.ip)]
    infra = [h for h in hosts if _is_public_ip(h.ip)]
    issues = _dedupe_compromise_issues([d for d in (summary.detections or [])
                                        if st.sev_rank(d.get("severity", "info")) >= st.sev_rank("medium")])
    if not hosts:
        rep.headline(None, "no host met the compromise threshold", f"{st.plural(summary.total_hosts, 'host')} assessed")
    else:
        worst = max(hosts, key=lambda h: st.sev_rank(h.severity)).severity
        text = (f"{st.plural(len(victims), 'suspected victim')} · {st.plural(len(infra), 'external host')} involved" if victims
                else f"{st.plural(len(infra), 'external host')} flagged, no internal victim identified")
        rep.headline(worst, text, st.join([f"{st.plural(summary.total_hosts, 'host')} assessed",
                                           st.plural(len(issues), "issue") if issues else "",
                                           st.plural(len(summary.incidents), "incident") if summary.incidents else "",
                                           st.plural(len(summary.campaigns), "shared indicator") if summary.campaigns else ""]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors[: None if st.verbose() else 12]]
                    + ([st.more(len(summary.errors) - 12, "error")] if not st.verbose() and len(summary.errors) > 12 else []))

    def _why(h) -> str:
        return " | ".join(h.evidence[:2]) if h.evidence else (h.explanation or "-")

    rep.section("Hosts", st.table(
        ["Scope", "IP", "Host", "Severity", "Score", "Detected", "Why"],
        [[st.bad("victim") if not _is_public_ip(h.ip) else "external", h.ip, h.hostname or "-", st.badge(h.severity), h.score,
          st.ts(h.detection_time), _redact_in_text(_why(h))] for h in hosts],
        align="lllllrl", widths=(None, None, 28, None, None, None, 80), max_rows=10, noun="host",
    ) + ([st.dim("  victims are the internal assets at risk; external hosts are the infrastructure they reached, not necessarily compromised")]
         if victims and infra else []))

    names = {h.ip: h.hostname for h in summary.compromised_hosts if h.hostname and h.hostname != "-"}
    lines: list[str] = []
    pad = " " * (st.BADGE_W + 4)
    for item in issues if st.verbose() else issues[:8]:
        tags = []
        cls = _VERDICT_TAG.get(_classify(item))
        if cls:
            tags.append(getattr(st, cls[1])(f"[{cls[0]}]"))
        rel = str(item.get("hypothesis_relevance", "") or "")
        if rel:
            tags.append({"relevant": st.bad, "adjacent": st.caution}.get(rel, st.dim)(f"[{rel}]"))
        if item.get("skeptical_downgraded"):
            orig = str(item.get("skeptical_original_severity", "") or "")
            tags.append(st.dim(f"[skeptical: {item.get('skeptical_rule', '')}{f', was {orig}' if orig else ''}]"))
        source = str(item.get("source", "") or "")
        lines.append(f"  {st.badge(item.get('severity'))}  {st.strong(str(item.get('summary', '')))}"
                     + (st.dim(f"  ({source})") if source else "") + ("  " + " ".join(tags) if tags else ""))
        ips = sorted(item.get("ips") or [], key=lambda v: (_is_public_ip(v), v))
        host_text = st.listing([f"{ip}{f' ({names[ip]})' if names.get(ip) else ''}{'' if _is_public_ip(ip) else ' [internal]'}" for ip in ips], 5)
        evidence = [str(e) for e in (item.get("evidence") or [])]
        rows = [("why", _compromise_issue_reason(str(item.get("summary", "")), source)),
                ("skeptical", str(item.get("skeptical_reason", "") or "") if item.get("skeptical_downgraded") else ""),
                ("hosts", host_text), ("details", _redact_in_text(str(item.get("details", "") or "")))]
        rows += [("evidence", _redact_in_text(e)) for e in (evidence if st.verbose() else evidence[:2])]
        if not st.verbose() and len(evidence) > 2:
            rows.append(("", f"+{len(evidence) - 2} more evidence lines (-v)"))
        rows.append(("IOCs", st.listing([str(i) for i in (item.get("iocs") or [])], 6)))
        for label_text, value in rows:
            if value:
                lines.append(pad + st.dim(st.cut(f"{label_text + ': ' if label_text else ''}{value}", None if st.verbose() else 140)))
    if not st.verbose() and len(issues) > 8:
        lines.append(st.more(len(issues) - 8, "issue"))
    rep.section("Issues", lines)
    rep.section("Incidents", st.table(
        ["Host", "First", "Last", "Duration", "Events", "Stages"],
        [[i.get("ip", "-"), st.ts(i.get("first_ts")), st.ts(i.get("last_ts")),
          format_duration(float(i["last_ts"]) - float(i["first_ts"]))
          if isinstance(i.get("first_ts"), (int, float)) and isinstance(i.get("last_ts"), (int, float))
          and float(i["last_ts"]) > float(i["first_ts"]) else "-",
          i.get("count", "-"), ", ".join(str(v) for v in i.get("stages") or []) or "-"] for i in summary.incidents or []],
        align="llllrl", max_rows=5, noun="incident",
    ))
    rep.section("Shared indicators", st.table(
        ["Campaign", "Shared IOC", "Hosts"],
        [[c.get("campaign_id", "-"), _redact_in_text(str(c.get("ioc", "-"))), f"{c.get('host_count', '-')}: {st.listing(c.get('hosts') or [], 4)}"]
         for c in summary.campaigns or []], widths=(None, 48), max_rows=5, noun="indicator",
    ))

    verdict, confidence, reasons, score = _assessment(summary)
    rep.section("Assessment", st.kv([("Verdict", verdict), ("Confidence", f"{confidence} (score {score})")])
                + st.bullets(reasons, max_items=None)
                + [st.dim("  heuristic: validate with endpoint telemetry; evidence comes from beacon, exfil, credential and threat detections")],
                detail=True)
    try:
        from ..verdict_summary import render as _render_verdict
        from ..verdict_summary import summarize as _summarize_verdict

        verdict_summary = _summarize_verdict(summary.detections or [])
        block = _render_verdict(verdict_summary).splitlines() if verdict_summary.total_detections else []
    except Exception:  # noqa: BLE001 -- the verdict summary must never break output
        block = []
    rep.section("Verdict candidates", ["  " + line for line in block], detail=True)
    rep.section("Priority queue", st.table(
        ["Host", "IP", "Score", "Severity", "Stages", "IOCs", "Detected"],
        [[i.get("host", "-"), i.get("ip", "-"), i.get("score", "-"), st.badge(i.get("severity", "info")),
          ",".join(i.get("stages") or []) if isinstance(i.get("stages"), list) else str(i.get("stages", "-")), i.get("ioc_count", "-"),
          format_ts(i.get("detection_time"))] for i in (getattr(summary, "host_priority", None) or [])],
        align="llrllrl", max_rows=None,
    ), detail=True)
    rep.section("Host detail", st.table(
        ["Host", "IP", "Detected", "Roles", "Explanation", "Evidence", "IOCs"],
        [[h.hostname or "-", h.ip, format_ts(h.detection_time), ", ".join(getattr(h, "roles", None) or []) or "-",
          _redact_in_text(h.explanation or "-"), _redact_in_text(" | ".join(h.evidence)) or "-", ", ".join(h.iocs) or "-"] for h in hosts],
        max_rows=None,
    ), detail=True)
    rep.section("False-positive context", st.bullets([_redact_in_text(str(b)) for b in (getattr(summary, "benign_context", None) or [])],
                                                     max_items=None), detail=True)
    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic Compromise Checks", [
            ("credential_abuse", "Credential Abuse Evidence"), ("beacon_c2", "Beacon/C2 Evidence"), ("exfiltration", "Exfiltration Evidence"),
            ("lateral_movement", "Lateral Movement Evidence"), ("multi_stage_sequence", "Multi-Stage Sequence Evidence"),
            ("high_confidence_ioc", "High-Confidence IOC Correlation"), ("benign_automation_likely", "Likely Benign Automation"),
        ])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
