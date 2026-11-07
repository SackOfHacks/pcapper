from __future__ import annotations

from pcapper.coap import _detect_anomalies, _parse_commands


def test_coap_observe_response_is_not_mislabeled_as_registration() -> None:
    response = b"\x60\x45\x00\x01\x61\x00"
    commands = _parse_commands(response)

    assert "Observe Notification" in commands
    assert not any(
        anomaly.title == "CoAP Observe Registration"
        for anomaly in _detect_anomalies(
            response, "10.0.0.2", "10.0.0.1", 1.0, commands
        )
    )


def test_coap_observe_registration_is_reported_for_get_request() -> None:
    request = b"\x40\x01\x00\x01\x61\x00"
    commands = _parse_commands(request)

    anomalies = _detect_anomalies(
        request, "10.0.0.1", "10.0.0.2", 1.0, commands
    )

    assert "Observe Register" in commands
    assert [anomaly.title for anomaly in anomalies] == [
        "CoAP Observe Registration"
    ]


def test_coap_rejects_reserved_token_length() -> None:
    assert _parse_commands(b"\x49\x01" + b"\x00" * 11) == []
