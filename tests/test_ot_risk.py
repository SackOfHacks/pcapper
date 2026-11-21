"""OT risk posture: IT detections alone are not OT risk."""

from __future__ import annotations

from pcapper.ot_risk import compute_ot_risk_posture


def test_it_detections_without_ot_activity_score_zero() -> None:
    assert compute_ot_risk_posture(high_sev_general=4) == (0, [])


def test_it_detections_add_to_existing_ot_risk() -> None:
    score, findings = compute_ot_risk_posture(control_hits=2, high_sev_general=3)
    assert score == 30
    assert any("IT detections" in f for f in findings)
