from __future__ import annotations

from pathlib import Path

from pcapper.iec104 import (
    _detect_anomalies,
    _parse_asdu,
    _parse_commands,
    analyze_iec104,
)
from test_review_batches import T0, _tcp, _write


def _apdu(type_id: int = 46, cot: int = 6, command: int = 2) -> bytes:
    asdu = bytes((type_id, 1, cot, 0)) + b"\x01\x00" + b"\x05\x00\x00" + bytes((command,))
    return b"\x68" + bytes((4 + len(asdu),)) + b"\x00\x00\x00\x00" + asdu


def _apdu_objects(vsq: int, objects: bytes, cot: int = 6) -> bytes:
    asdu = bytes((46, vsq, cot, 0)) + b"\x01\x00" + objects
    return b"\x68" + bytes((4 + len(asdu),)) + b"\x00\x00\x00\x00" + asdu


def _packet(payload: bytes, seq: int, ts: float):
    packet = _tcp("192.0.2.10", "192.0.2.20", 40000, 2404, payload, seq=seq)
    packet.time = ts
    return packet


def test_double_command_dco_values_follow_iec104_encoding() -> None:
    expected = {0: "INVALID (0)", 1: "OFF", 2: "ON", 3: "INVALID (3)"}
    for code, state in expected.items():
        commands, artifacts = _parse_asdu(_apdu(command=code))
        assert f"DC EXECUTE {state}" in commands
        assert any(detail == f"DC EXECUTE {state} IOA 5" for _, detail in artifacts)


def test_parser_rejects_truncated_and_invalid_length_apdus() -> None:
    frame = _apdu()

    assert _parse_commands(frame[:-1]) == []
    assert _parse_commands(b"\x68\xff" + frame[2:]) == []
    assert _parse_commands(b"\x68\x03\x00\x00\x00\x00" + frame) == _parse_commands(frame)


def test_identical_apdus_in_one_segment_are_counted_individually() -> None:
    commands = _parse_commands(_apdu() + _apdu())

    assert commands.count("DC EXECUTE ON") == 2
    assert commands.count("Control ASDU") == 2


def test_command_parser_preserves_multiple_vsq_objects() -> None:
    non_sequence = _apdu_objects(
        2,
        b"\x05\x00\x00\x02"
        + b"\x08\x00\x00\x01",
    )
    sequence = _apdu_objects(0x82, b"\x05\x00\x00\x02\x01")

    non_sequence_commands, non_sequence_artifacts = _parse_asdu(non_sequence)
    sequence_commands, sequence_artifacts = _parse_asdu(sequence)

    assert "IOA 5" in non_sequence_commands
    assert "IOA 8" in non_sequence_commands
    assert "DC EXECUTE ON" in non_sequence_commands
    assert "DC EXECUTE OFF" in non_sequence_commands
    assert ("iec104_ioa", "5") in non_sequence_artifacts
    assert ("iec104_ioa", "8") in non_sequence_artifacts
    assert ("iec104_ioa", "6") in sequence_artifacts
    assert sequence_commands.count("DC EXECUTE ON") == 1
    assert sequence_commands.count("DC EXECUTE OFF") == 1


def test_vsq_count_exceeding_available_objects_is_not_partially_decoded() -> None:
    malformed = bytearray(_apdu())
    malformed[7] = 2

    commands, artifacts = _parse_asdu(bytes(malformed))

    assert not any(command.startswith("IOA ") for command in commands)
    assert not any(kind == "iec104_ioa" for kind, _ in artifacts)


def test_confirmation_is_not_reported_as_a_control_activation() -> None:
    frame = _apdu(cot=7)
    commands = _parse_commands(frame)

    assert not any(
        anomaly.title == "IEC-104 Control Command"
        for anomaly in _detect_anomalies(frame, "a", "b", T0, commands)
    )


def test_mixed_apdus_keep_activation_attribution_per_apdu() -> None:
    payload = _apdu(cot=7) + _apdu(cot=6)

    anomalies = _detect_anomalies(payload, "a", "b", T0, _parse_commands(payload))

    assert sum(anomaly.title == "IEC-104 Control Command" for anomaly in anomalies) == 1


def test_reset_confirmation_is_not_reported_as_a_reset_command() -> None:
    frame = _apdu(type_id=105, cot=7, command=0)
    commands = _parse_commands(frame)

    assert not any(
        anomaly.title == "IEC-104 Reset Process"
        for anomaly in _detect_anomalies(frame, "a", "b", T0, commands)
    )


def test_tcp_segmented_apdu_is_reassembled(tmp_path: Path) -> None:
    frame = _apdu()
    split = 8
    capture = _write(
        tmp_path,
        "iec104_split.pcap",
        [
            _packet(frame[:split], 1000, T0),
            _packet(frame[split:], 1000 + split, T0 + 0.1),
        ],
    )

    result = analyze_iec104(capture, show_status=False)

    assert result.commands["DC EXECUTE ON"] == 1
    assert any(artifact.kind == "iec104_command" for artifact in result.artifacts)
    assert not result.errors


def test_tcp_gap_discards_partial_apdu_and_reports_diagnostic(
    tmp_path: Path,
) -> None:
    frame = _apdu()
    split = 8
    capture = _write(
        tmp_path,
        "iec104_gap.pcap",
        [
            _packet(frame[:split], 1000, T0),
            _packet(frame[split:], 1000 + split + 3, T0 + 0.1),
        ],
    )

    result = analyze_iec104(capture, show_status=False)

    assert result.commands["DC EXECUTE ON"] == 0
    assert any("sequence gap" in error for error in result.errors)


def test_incomplete_apdu_at_capture_end_is_reported(tmp_path: Path) -> None:
    frame = _apdu()
    capture = _write(
        tmp_path,
        "iec104_truncated.pcap",
        [_packet(frame[:8], 1000, T0)],
    )

    result = analyze_iec104(capture, show_status=False)

    assert result.commands["DC EXECUTE ON"] == 0
    assert any("incomplete APDU" in error for error in result.errors)
