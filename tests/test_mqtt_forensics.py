from __future__ import annotations

from pcapper.mqtt import (
    _decode_remaining_length,
    _detect_anomalies,
    _parse_artifacts,
    _parse_commands,
    _parse_mqtt_packets,
)


def _mqtt_packet(header: int, body: bytes) -> bytes:
    assert len(body) < 128
    return bytes((header, len(body))) + body


def test_mqtt_parser_rejects_tls_bytes_and_invalid_fixed_header_flags() -> None:
    tls_record = b"\x16\x03\x03\x00\x10" + b"\x00" * 16
    invalid_connect = b"\x11\x00"

    assert _parse_mqtt_packets(tls_record) == []
    assert _parse_commands(invalid_connect) == []


def test_mqtt_publish_retain_detection_uses_flag_not_topic_text() -> None:
    retained = _mqtt_packet(0x31, b"\x00\x04testpayload")
    not_retained = _mqtt_packet(0x30, b"\x00\x0cretain/statevalue")

    retained_commands = _parse_commands(retained)
    normal_commands = _parse_commands(not_retained)

    assert retained_commands == ["PUBLISH test qos0 retain"]
    assert any(
        anomaly.title == "MQTT Retained Publish"
        for anomaly in _detect_anomalies(
            retained, "10.0.0.1", "10.0.0.2", 1.0, retained_commands
        )
    )
    assert not any(
        anomaly.title == "MQTT Retained Publish"
        for anomaly in _detect_anomalies(
            not_retained, "10.0.0.1", "10.0.0.2", 1.0, normal_commands
        )
    )


def test_mqtt_control_topic_keywords_match_whole_path_segments() -> None:
    commandment_topic = _mqtt_packet(0x30, b"\x00\x0bcommandment")
    command_topic = _mqtt_packet(0x30, b"\x00\x07command")

    assert not any(
        anomaly.title == "MQTT Control Topic"
        for anomaly in _detect_anomalies(
            commandment_topic,
            "10.0.0.1",
            "10.0.0.2",
            1.0,
            _parse_commands(commandment_topic),
        )
    )
    assert any(
        anomaly.title == "MQTT Control Topic"
        for anomaly in _detect_anomalies(
            command_topic,
            "10.0.0.1",
            "10.0.0.2",
            1.0,
            _parse_commands(command_topic),
        )
    )


def test_mqtt_connect_client_id_is_extracted_and_noncanonical_length_rejected() -> None:
    connect_data = b"\x00\x04MQTT\x04\x02\x00\x3c\x00\x01c"
    connect = _mqtt_packet(0x10, connect_data)

    assert _parse_commands(connect) == ["CONNECT"]
    assert _parse_artifacts(connect) == [("mqtt_client_id", "c")]
    assert _decode_remaining_length(b"\x80\x00", 0) == (None, 2)
