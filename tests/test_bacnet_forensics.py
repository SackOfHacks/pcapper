from __future__ import annotations

from pcapper.bacnet import (
    _detect_anomalies,
    _parse_bacnet_payload,
    _parse_commands,
)


def _bvlc(function: int, body: bytes, declared_length: int | None = None) -> bytes:
    length = 4 + len(body) if declared_length is None else declared_length
    return b"\x81" + bytes((function,)) + length.to_bytes(2, "big") + body


def _npdu_apdu(apdu: bytes) -> bytes:
    return _bvlc(0x09, b"\x01\x00" + apdu)


def test_write_property_ack_is_not_reported_as_a_write_request() -> None:
    frame = _npdu_apdu(b"\x20\x01\x0f")
    commands = _parse_commands(frame)

    assert "WriteProperty" in commands
    assert not any(
        anomaly.title == "BACnet WriteProperty"
        for anomaly in _detect_anomalies(frame, "a", "b", 1.0, commands)
    )


def test_device_communication_control_ack_is_not_reported_as_command() -> None:
    frame = _npdu_apdu(b"\x30\x01\x11")
    commands = _parse_commands(frame)

    assert "DeviceCommunicationControl" in commands
    assert not any(
        anomaly.title == "BACnet Device Communication Control"
        for anomaly in _detect_anomalies(frame, "a", "b", 1.0, commands)
    )


def test_confirmed_request_still_reports_write_property() -> None:
    frame = _npdu_apdu(b"\x00\x05\x01\x0f")
    commands = _parse_commands(frame)

    assert any(
        anomaly.title == "BACnet WriteProperty"
        for anomaly in _detect_anomalies(frame, "a", "b", 1.0, commands)
    )


def test_segmented_complex_ack_reads_service_choice_at_correct_offset() -> None:
    frame = _npdu_apdu(b"\x38\x01\x00\x01\x0c")

    info = _parse_bacnet_payload(frame)

    assert info["apdu_name"] == "Complex-ACK"
    assert info["service_name"] == "ReadProperty"


def test_parser_does_not_read_npdu_beyond_declared_bvlc_length() -> None:
    trailing_npdu = b"\x01\x00\x10\x08"
    frame = _bvlc(0x09, trailing_npdu, declared_length=4)

    info = _parse_bacnet_payload(frame)

    assert info["service_name"] == ""
    assert any("does not match" in issue for issue in info["issues"])


def test_truncated_bvlc_header_is_reported() -> None:
    info = _parse_bacnet_payload(b"\x81\x09\x00")

    assert info["valid"]
    assert info["issues"] == ["Truncated BVLC header."]
