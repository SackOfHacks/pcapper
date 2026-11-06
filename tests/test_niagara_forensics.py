from __future__ import annotations

from pcapper.niagara import (
    _detect_anomalies,
    _parse_artifacts,
    _parse_commands,
)


def test_niagara_text_patterns_extract_ord_and_explicit_opcodes() -> None:
    payload = b"ord:station:/demo/point opcode: 0x5a op=17 slot:1"

    commands = _parse_commands(payload)
    artifacts = _parse_artifacts(payload)

    assert "Niagara Put" not in commands
    assert "Niagara Opcode 0x5a" in commands
    assert "Niagara Opcode 17" in commands
    assert ("niagara_ord", "ord:station:/demo/point") in artifacts
    assert ("niagara_slot", "slot:1") in artifacts
    assert ("niagara_opcode", "0x5a") in artifacts


def test_niagara_input_value_does_not_trigger_put_command() -> None:
    payload = b"point=input"
    commands = _parse_commands(payload)

    assert "Niagara Put" not in commands
    assert _detect_anomalies(payload, "10.0.0.1", "10.0.0.2", 1.0, commands) == []


def test_niagara_put_is_still_alerted() -> None:
    payload = b"fox put ord:station:/demo/point"
    commands = _parse_commands(payload)

    findings = _detect_anomalies(payload, "10.0.0.1", "10.0.0.2", 1.0, commands)

    assert len(findings) == 1
    assert findings[0].title == "Niagara Fox Write/Invoke"
