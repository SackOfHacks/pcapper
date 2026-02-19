from __future__ import annotations

from typing import Iterable

OT_RISK_THRESHOLDS = {
    "public_ot_weight": 30,
    "control_weight": 25,
    "anomaly_weight": 15,
    "ot_high_weight": 10,
    "general_high_weight": 5,
    "max_score": 100,
}


def compute_ot_risk_posture(
    *,
    public_ot_flows: int = 0,
    control_hits: int = 0,
    anomaly_hits: int = 0,
    high_sev_ot: int = 0,
    high_sev_general: int = 0,
) -> tuple[int, list[str]]:
    score = 0
    findings: list[str] = []

    if public_ot_flows:
        score += OT_RISK_THRESHOLDS["public_ot_weight"]
        findings.append(f"OT protocol traffic to public IPs ({public_ot_flows}).")
    if control_hits:
        score += OT_RISK_THRESHOLDS["control_weight"]
        findings.append(f"OT control/program operations detected ({control_hits}).")
    if anomaly_hits:
        score += min(OT_RISK_THRESHOLDS["anomaly_weight"], anomaly_hits * 3)
        findings.append(f"OT anomalies/control events observed ({anomaly_hits}).")
    if high_sev_ot:
        score += OT_RISK_THRESHOLDS["ot_high_weight"]
        findings.append(f"High-severity OT detections ({high_sev_ot}).")
    if high_sev_general:
        score += OT_RISK_THRESHOLDS["general_high_weight"]
        findings.append(f"High-severity IT detections ({high_sev_general}).")

    score = min(OT_RISK_THRESHOLDS["max_score"], score)
    return score, findings


def dedupe_findings(items: Iterable[str], limit: int = 6) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        output.append(item)
        if len(output) >= limit:
            break
    return output
