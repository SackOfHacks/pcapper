"""--mitre executive assessment."""

from __future__ import annotations

from pcapper.mitre import MitreHit, _executive_assessment


def test_enterprise_impact_is_not_ot_process_impact() -> None:
    def hit(tactic: str, framework: str) -> MitreHit:
        return MitreHit(framework=framework, tactic=tactic, tactic_id="TA0040", technique="Network Denial of Service",
                        technique_id="T1498", procedure="p", source="tcp", severity="high", confidence="low", details="d",
                        evidence=[], artifacts=[], iocs=[], first_seen=None, last_seen=None, occurrence=1)

    _v, _c, reasons = _executive_assessment(1, [hit("Impact", "enterprise")], [])
    assert not any("OT process" in r for r in reasons)
    _v, _c, reasons = _executive_assessment(1, [hit("Impair Process Control", "ics")], [])
    assert any("OT process" in r for r in reasons)
