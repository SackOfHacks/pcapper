"""Hypothesis-lens annotation for pcapper detections.

Given an operator-supplied hypothesis (free-text OR ATT&CK-technique regex),
tag each detection as:

  * ``relevant``  — the detection's summary / details / MITRE mapping matches
                    the hypothesis regex directly.
  * ``adjacent``  — the detection touches a related area (same source, or
                    a technique in the same tactic family) but doesn't
                    match the hypothesis directly. Reviewer decides whether
                    to fold into the disposition.
  * ``unrelated`` — no match; the finding is a bystander from other
                    activity in the capture.

The tag lets a reviewer scan a 47 KB / 662-line synthesis file for the
30% of findings that touch the hunt hypothesis and skip the noise.

Usage from the CLI:

    pcapper capture.pcap --http --compromised \
        --hypothesis 'referrer|host header|SNI|T1071|T1090'

The regex is matched case-insensitively against a synthetic search string
combining the detection's summary, details, source label, and any
recovered MITRE technique IDs from the ``iocs`` / ``evidence`` fields.

Nothing is dropped — every detection surfaces, with an added
``hypothesis_relevance`` key. Renderers can highlight ``relevant`` findings
first and de-emphasise ``unrelated`` ones.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

Detection = dict[str, Any]

# Tactic family map — used to compute the "adjacent" tag when a hypothesis
# names a specific technique. If the hypothesis matches T1071 (Application
# Layer Protocol / C2 comms), any other Command-and-Control-tactic
# technique in the same capture is `adjacent`.
_TACTIC_BY_TECHNIQUE: dict[str, str] = {
    # Reconnaissance
    "T1595": "recon", "T1592": "recon", "T1590": "recon", "T1596": "recon",
    "T1597": "recon", "T1598": "recon",
    # Initial Access
    "T1189": "initial-access", "T1190": "initial-access",
    "T1078": "initial-access", "T1200": "initial-access", "T1091": "initial-access",
    # Execution
    "T1059": "execution", "T1203": "execution", "T1204": "execution",
    "T1610": "execution", "T1053": "execution",
    # Persistence
    "T1547": "persistence", "T1546": "persistence", "T1543": "persistence",
    "T1136": "persistence",
    # Credential Access
    "T1110": "credential-access", "T1552": "credential-access",
    "T1555": "credential-access", "T1003": "credential-access",
    "T1187": "credential-access",
    # Discovery
    "T1046": "discovery", "T1018": "discovery", "T1082": "discovery",
    "T1049": "discovery",
    # Lateral Movement
    "T1021": "lateral-movement", "T1570": "lateral-movement",
    "T1210": "lateral-movement",
    # C2
    "T1071": "c2", "T1090": "c2", "T1573": "c2", "T1105": "c2",
    "T1571": "c2", "T1568": "c2",
    # Exfiltration
    "T1041": "exfil", "T1048": "exfil", "T1567": "exfil", "T1029": "exfil",
    # Impact
    "T1498": "impact", "T1499": "impact", "T1486": "impact",
    "T1489": "impact", "T1485": "impact",
    # ICS-only techniques (T0*) — same family map as-of ATT&CK for ICS
    "T0888": "recon", "T0846": "discovery", "T0842": "discovery",
    "T0840": "discovery", "T0801": "monitor-state",
    "T0868": "monitor-state", "T0811": "collection",
    "T0812": "credential-access", "T0839": "impair-integrity",
    "T0864": "initial-access", "T0836": "impair-process-control",
    "T0855": "impair-process-control", "T0859": "credential-access",
}

_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _collect_techniques(detection: Detection) -> set[str]:
    """Return every ATT&CK technique id embedded in the detection's
    summary/details/iocs/evidence fields."""
    parts: list[str] = [
        str(detection.get("summary", "")),
        str(detection.get("details", "")),
    ]
    for ioc in detection.get("iocs", []) or []:
        parts.append(str(ioc))
    for ev in detection.get("evidence", []) or []:
        parts.append(str(ev))
    blob = " ".join(parts)
    # Only the primary technique id (drop sub-technique suffix) for the
    # tactic-family map lookup.
    return {m.group(0).split(".")[0] for m in _TECHNIQUE_RE.finditer(blob)}


def _tactic_family(technique: str) -> str | None:
    """Return the tactic family for a technique id, or None if unknown."""
    return _TACTIC_BY_TECHNIQUE.get(technique)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class HypothesisLens:
    """A compiled hypothesis pattern + the tactic families it touches.

    Instantiate once (typically at CLI startup) and reuse across every
    detection. Cheap to construct — compiles the regex + walks the
    pattern once to identify the tactic families named by any T-id
    literals in the pattern.
    """

    __slots__ = ("_pattern", "_hypothesis_families")

    def __init__(self, pattern: str):
        self._pattern = re.compile(pattern, re.IGNORECASE) if pattern else None
        # Which tactic families are named by any T-ids embedded in the
        # hypothesis pattern? Used to compute the `adjacent` tag.
        self._hypothesis_families: set[str] = set()
        if pattern:
            for t in {m.group(0).split(".")[0] for m in _TECHNIQUE_RE.finditer(pattern)}:
                fam = _tactic_family(t)
                if fam:
                    self._hypothesis_families.add(fam)

    def enabled(self) -> bool:
        return self._pattern is not None

    def classify(self, detection: Detection) -> str:
        """Return one of ``relevant`` / ``adjacent`` / ``unrelated``.

        ``relevant`` — the compiled regex matches the detection's synthesized
        search blob (summary + details + source + technique ids).
        ``adjacent`` — no direct regex match, but the detection carries a
        technique id in a tactic family named by the hypothesis pattern's
        T-id literals.
        ``unrelated`` — neither of the above.
        """
        if self._pattern is None:
            return "unrelated"

        blob_parts: list[str] = [
            str(detection.get("summary", "")),
            str(detection.get("details", "")),
            str(detection.get("source", "")),
        ]
        for ev in detection.get("evidence", []) or []:
            blob_parts.append(str(ev))
        for ioc in detection.get("iocs", []) or []:
            blob_parts.append(str(ioc))
        blob = " ".join(blob_parts)
        if self._pattern.search(blob):
            return "relevant"

        # Adjacent: does the detection carry a technique in a tactic family
        # the hypothesis pattern named?
        for tech in _collect_techniques(detection):
            fam = _tactic_family(tech)
            if fam and fam in self._hypothesis_families:
                return "adjacent"

        return "unrelated"


# --- module-level singleton for CLI use -----------------------------------

_ACTIVE_LENS: HypothesisLens | None = None


def set_active_lens(pattern: str | None) -> None:
    """Set the module-level hypothesis lens. Called once by the CLI at
    startup from ``--hypothesis <REGEX>``. Pass None to clear."""
    global _ACTIVE_LENS
    _ACTIVE_LENS = HypothesisLens(pattern) if pattern else None


def get_active_lens() -> HypothesisLens | None:
    return _ACTIVE_LENS


def annotate(detection: Detection) -> Detection:
    """If a lens is active, add ``hypothesis_relevance`` to a copy of the
    detection. Otherwise return the detection unchanged. Never mutates."""
    lens = _ACTIVE_LENS
    if lens is None or not isinstance(detection, dict):
        return detection
    tag = lens.classify(detection)
    if tag == "unrelated" and not lens.enabled():
        return detection
    new = dict(detection)
    new["hypothesis_relevance"] = tag
    return new


def annotate_many(detections: Iterable[Detection]) -> list[Detection]:
    return [annotate(d) for d in detections]


__all__ = [
    "HypothesisLens",
    "annotate",
    "annotate_many",
    "set_active_lens",
    "get_active_lens",
]
