from __future__ import annotations

from pcapper.modicon import _detect_anomalies, _parse_commands


def _mbap(function: int, subfunction: int | None = None, length: int | None = None) -> bytes:
    pdu = bytes((0, function))
    if subfunction is not None:
        pdu += bytes((0, subfunction))
    declared_length = len(pdu) if length is None else length
    return b"\x00\x01\x00\x00" + declared_length.to_bytes(2, "big") + pdu


def test_umas_responses_are_not_reported_as_control_operations() -> None:
    response = _mbap(0x5A, 0xFE)

    commands = _parse_commands(response)

    assert commands == ["UMAS Response"]
    assert _detect_anomalies(response, "10.0.0.2", "10.0.0.1", 1.0, commands) == []


def test_umas_program_download_and_process_writes_have_distinct_mappings() -> None:
    program_write = _mbap(0x5A, 0x21)
    variable_write = _mbap(0x5A, 0x23)

    program_findings = _detect_anomalies(
        program_write, "10.0.0.1", "10.0.0.2", 1.0, _parse_commands(program_write)
    )
    variable_findings = _detect_anomalies(
        variable_write, "10.0.0.1", "10.0.0.2", 1.0, _parse_commands(variable_write)
    )

    assert program_findings[0].attack == "T0843 Program Download"
    assert variable_findings[0].attack == "T0836 Modify Parameter"


def test_malformed_mbap_lengths_are_not_parsed_as_modicon() -> None:
    truncated = _mbap(0x5A, 0x41)[:-1]
    invalid_length = _mbap(0x5A, 0x41, length=1)

    assert _parse_commands(truncated) == []
    assert _parse_commands(invalid_length) == []
