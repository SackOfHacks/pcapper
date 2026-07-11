"""Synthesized-verdict summary block for pcapper reviews.

The compromise-assessment module produces a wide table of individual
findings with per-detection severity. Reviewers then re-classify each
one into a review-level bucket (real threat vs. FP vs. control-working
vs. hardening item). That classification is deterministic given the
finding's shape — this module does it up-front so the reviewer accepts
or rejects candidates instead of deriving classifications from scratch.

Categories:

  * ``LIKELY_FP``
      The skeptical filter downgraded the finding via a rule that
      explicitly matches a well-known false-positive shape
      (`likely-vendor-polling`, `single-host-polling-not-fanout`).

  * ``LIKELY_CONTROL_WORKING``
      Skeptical rules that identify a *security-control-doing-its-job*
      signal — blocked egress at the firewall, blocked outbound tunnel
      at the proxy. Not a threat; documents that the control works.

  * ``TP_HARDENING``
      Real security finding that is orthogonal to the primary hunt
      hypothesis but should be surfaced in the closure narrative anyway.
      Cleartext credential exposure, SSLv2 on the wire, deprecated
      cipher suites, PII in cleartext, etc.

  * ``TP_MALICIOUS_CANDIDATE``
      High-severity finding that the skeptical filter did NOT downgrade
      AND that comes from a source class known to surface real adversary
      tradecraft (Malware, Obfuscation, Exfil, Beacon). Reviewer should
      inspect + confirm before treating as final.

  * ``INCONCLUSIVE``
      Everything else — needs analyst judgment or is bystander noise.

Rendered as a compact block near the top of the compromise output so the
reviewer reads it before scrolling into the per-finding detail.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

Detection = dict[str, Any]

# ---------------------------------------------------------------------------
# Classification rules
# ---------------------------------------------------------------------------

# Skeptical rule → verdict category. When a detection carries the rule
# ID as ``skeptical_rule``, the verdict is direct. Rules NOT in this map
# leave the verdict for the fallback logic.
_SKEPTICAL_RULE_TO_VERDICT: dict[str, str] = {
    "likely-vendor-polling":            "LIKELY_FP",
    "single-host-polling-not-fanout":   "LIKELY_FP",
    "blocked-egress-syn-flood":         "LIKELY_CONTROL_WORKING",
    "blocked-egress-connection-probe":  "LIKELY_CONTROL_WORKING",
    "blocked-outbound-tunnel":          "LIKELY_CONTROL_WORKING",
}

# Detections that match these patterns (case-insensitive) are hardening
# findings — real security issues that should be documented in the
# closure narrative but are orthogonal to any specific hunt hypothesis.
_HARDENING_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)credential\s+leakage"),
    re.compile(r"(?i)cleartext\s+credential"),
    re.compile(r"(?i)username\s+disclosure\s+in\s+cleartext"),
    re.compile(r"(?i)password\s+in\s+cleartext"),
    re.compile(r"(?i)ssl\s*v\s*2|sslv2"),
    re.compile(r"(?i)tls\s*1\.?0\b|tls\s*1\.?1\b"),
    re.compile(r"(?i)weak\s+cipher"),
    re.compile(r"(?i)expired\s+certificate|expired\s+cert"),
    re.compile(r"(?i)self[- ]signed\s+certificate"),
    re.compile(r"(?i)pii\s+in\s+cleartext|personally\s+identifiable"),
    re.compile(r"(?i)smb\s*v?1\b|smb\s+version\s+1"),
)

# Sources that, at HIGH severity + no skeptical downgrade, are strong
# candidates for real adversary tradecraft — worth surfacing at the top
# of the verdict-summary block for reviewer confirmation.
_MALICIOUS_CANDIDATE_SOURCES: tuple[str, ...] = (
    "Malware",
    "Obfuscation",
    "Exfil",
    "Beacon",
    "Files",       # carved suspicious files
    "Files/exfil",
)


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class VerdictCandidate:
    """One row in the summary block.

    ``examples`` holds up to N short evidence snippets (hostname pairs,
    URL fragments, etc.) so the reviewer sees WHY the candidate was
    classified without opening the per-finding table.
    """

    category: str
    summary: str
    source: str
    count: int
    severity: str
    skeptical_rule: str = ""
    hypothesis_relevance: str = ""
    examples: tuple[str, ...] = ()


@dataclass(frozen=True)
class VerdictSummary:
    """Aggregation of every detection into candidate verdicts.

    Reviewer flips CANDIDATE to CONFIRMED or REJECTED post-review; the
    module never claims a final verdict itself.
    """

    total_detections: int
    candidates: list[VerdictCandidate] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def _classify(detection: Detection) -> str:
    """Return the verdict category for a single detection."""
    # 1. Skeptical filter rule wins if it matches the known map.
    rule = str(detection.get("skeptical_rule", "") or "")
    if rule and rule in _SKEPTICAL_RULE_TO_VERDICT:
        return _SKEPTICAL_RULE_TO_VERDICT[rule]

    # 2. Hardening finding based on the summary text.
    summary_text = str(detection.get("summary", "") or "")
    if any(pat.search(summary_text) for pat in _HARDENING_PATTERNS):
        return "TP_HARDENING"

    # 3. High-severity + malicious-tradecraft source + no skeptical downgrade.
    severity = str(detection.get("severity", "") or "").lower()
    source = str(detection.get("source", "") or "")
    is_high = severity in ("critical", "high")
    is_downgraded = bool(detection.get("skeptical_downgraded", False))
    if is_high and not is_downgraded and source in _MALICIOUS_CANDIDATE_SOURCES:
        return "TP_MALICIOUS_CANDIDATE"

    return "INCONCLUSIVE"


def summarize(detections: Iterable[Detection]) -> VerdictSummary:
    """Aggregate detections into verdict candidates.

    Group by (category, summary, source) so an identical finding across
    many hosts collapses to one row with ``count`` = the number of hosts.
    Examples slot is populated with up to 3 short evidence strings.
    """
    grouped: dict[tuple[str, str, str], list[Detection]] = defaultdict(list)
    total = 0
    for det in detections:
        if not isinstance(det, dict):
            continue
        total += 1
        cat = _classify(det)
        key = (
            cat,
            str(det.get("summary", "")),
            str(det.get("source", "")),
        )
        grouped[key].append(det)

    def _sort_key(kv):
        _, dets = kv
        # Show TP_MALICIOUS_CANDIDATE first, then TP_HARDENING, then
        # LIKELY_CONTROL_WORKING, then LIKELY_FP, then INCONCLUSIVE.
        order = {
            "TP_MALICIOUS_CANDIDATE":   0,
            "TP_HARDENING":             1,
            "LIKELY_CONTROL_WORKING":   2,
            "LIKELY_FP":                3,
            "INCONCLUSIVE":             4,
        }
        first_det = dets[0]
        cat = _classify(first_det)
        # Within the category, sort by severity (higher first).
        sev_order = {"critical": 0, "high": 1, "warning": 2, "info": 3}
        sev = str(first_det.get("severity", "")).lower()
        return (order.get(cat, 99), sev_order.get(sev, 99))

    ordered = sorted(grouped.items(), key=_sort_key)

    candidates: list[VerdictCandidate] = []
    for (cat, summary_text, source), dets in ordered:
        head = dets[0]
        examples = tuple(
            str(d.get("details", ""))[:120] for d in dets[:3] if d.get("details")
        )
        relevance = ""
        for d in dets:
            r = str(d.get("hypothesis_relevance", "") or "")
            # relevance precedence: relevant > adjacent > unrelated > ""
            if r == "relevant":
                relevance = "relevant"
                break
            if r == "adjacent" and relevance != "relevant":
                relevance = "adjacent"
            elif r == "unrelated" and relevance not in ("relevant", "adjacent"):
                relevance = "unrelated"
        candidates.append(
            VerdictCandidate(
                category=cat,
                summary=summary_text,
                source=source,
                count=sum(1 for _ in dets),
                severity=str(head.get("severity", "")),
                skeptical_rule=str(head.get("skeptical_rule", "") or ""),
                hypothesis_relevance=relevance,
                examples=examples,
            )
        )

    return VerdictSummary(total_detections=total, candidates=candidates)


def render(summary: VerdictSummary) -> str:
    """Render the verdict summary as a plain-text block.

    Intentionally minimal formatting so it composes cleanly into the
    existing compromise-output stream without a color dependency.
    """
    if not summary.candidates:
        return "No verdict candidates — 0 detections."

    lines: list[str] = []
    lines.append("Synthesis-level verdict candidates (reviewer accept/reject):")

    by_cat: dict[str, list[VerdictCandidate]] = defaultdict(list)
    for c in summary.candidates:
        by_cat[c.category].append(c)

    ordered_cats = [
        "TP_MALICIOUS_CANDIDATE",
        "TP_HARDENING",
        "LIKELY_CONTROL_WORKING",
        "LIKELY_FP",
        "INCONCLUSIVE",
    ]
    for cat in ordered_cats:
        rows = by_cat.get(cat, [])
        if not rows:
            continue
        lines.append("")
        lines.append(f"  {cat}  ({len(rows)} row{'s' if len(rows) != 1 else ''}):")
        for row in rows:
            head = f"    - [{row.severity.upper()}] {row.summary}"
            if row.source:
                head += f" ({row.source})"
            if row.count > 1:
                head += f" x{row.count}"
            if row.skeptical_rule:
                head += f"  [skeptical: {row.skeptical_rule}]"
            if row.hypothesis_relevance == "relevant":
                head += "  [relevant]"
            elif row.hypothesis_relevance == "adjacent":
                head += "  [adjacent]"
            lines.append(head)
            for ex in row.examples[:2]:
                lines.append(f"        e.g., {ex}")

    lines.append("")
    lines.append(
        "  Legend: TP_MALICIOUS_CANDIDATE = inspect + confirm; "
        "TP_HARDENING = document in closure narrative; "
        "LIKELY_CONTROL_WORKING = security control is functioning as designed; "
        "LIKELY_FP = false-positive class."
    )
    return "\n".join(lines)


__all__ = [
    "VerdictCandidate",
    "VerdictSummary",
    "summarize",
    "render",
]
