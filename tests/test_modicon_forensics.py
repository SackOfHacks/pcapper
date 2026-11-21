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


def test_only_umas_frames_are_modicon() -> None:
    from pcapper.modicon import _umas_signature

    assert _umas_signature(_mbap(0x5A, 0x34))
    assert _umas_signature(_mbap(0x5A, 0xFE))  # a UMAS response
    assert not _umas_signature(_mbap(0x05))  # plain Modbus Write Single Coil belongs to --modbus
    assert not _umas_signature(_mbap(0x03))


def test_umas_program_transfer_directions_map_to_attack() -> None:
    # Schneider's "download" reads the program OUT of the PLC (ATT&CK Program
    # Upload); its "upload" writes one INTO the PLC (ATT&CK Program Download).
    read_out = _mbap(0x5A, 0x34)
    write_in = _mbap(0x5A, 0x31)
    assert _parse_commands(read_out) == ["UMAS DOWNLOAD_BLOCK (0x34)"]
    assert _detect_anomalies(read_out, "10.0.0.1", "10.0.0.2", 1.0, _parse_commands(read_out))[0].attack == "T0845 Program Upload"
    assert _detect_anomalies(write_in, "10.0.0.1", "10.0.0.2", 1.0, _parse_commands(write_in))[0].attack == "T0843 Program Download"
    assert _parse_commands(_mbap(0x5A, 0x12)) == ["UMAS KEEP_ALIVE (0x12)"]
