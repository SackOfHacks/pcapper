from __future__ import annotations

from pathlib import Path

from pcapper.enip import _parse_list_identity_response, analyze_enip
from test_review_batches import T0, _tcp, _udp, _write


def _identity_cpf() -> bytes:
    product_name = b"Test PLC"
    identity = (
        b"\x01\x00"
        + b"\x00" * 16
        + (1).to_bytes(2, "little")
        + (12).to_bytes(2, "little")
        + (185).to_bytes(2, "little")
        + bytes((2, 3))
        + b"\x00\x00"
        + (0x12345678).to_bytes(4, "little")
        + bytes((len(product_name),))
        + product_name
        + b"\x03"
    )
    return (
        b"\x01\x00"
        + b"\x0c\x00"
        + len(identity).to_bytes(2, "little")
        + identity
    )


def _encapsulation(command: int, data: bytes = b"") -> bytes:
    return (
        command.to_bytes(2, "little")
        + len(data).to_bytes(2, "little")
        + b"\x00" * 20
        + data
    )


def test_list_identity_cpf_uses_identity_item_field_offsets() -> None:
    identities = _parse_list_identity_response(_identity_cpf(), "192.0.2.20")

    assert len(identities) == 1
    identity = identities[0]
    assert identity.vendor_id == 1
    assert identity.device_type == 12
    assert identity.product_code == 185
    assert identity.revision == "2.3"
    assert identity.serial_number == 0x12345678
    assert identity.product_name == "Test PLC"


def test_list_identity_truncated_item_is_not_emitted() -> None:
    cpf = _identity_cpf()[:-2]

    assert _parse_list_identity_response(cpf, "192.0.2.20") == []


def test_list_identity_capture_populates_device_inventory(tmp_path: Path) -> None:
    data = _identity_cpf()
    packet = _udp(
        "192.0.2.20",
        "192.0.2.10",
        44818,
        40000,
        _encapsulation(0x0063, data),
    )
    packet.time = T0
    capture = _write(tmp_path, "enip_identity.pcap", [packet])

    result = analyze_enip(capture, show_status=False)

    assert len(result.identities) == 1
    assert result.identities[0].product_name == "Test PLC"


def test_list_identity_response_is_not_counted_as_an_enumeration_request(
    tmp_path: Path,
) -> None:
    request = _udp(
        "192.0.2.10", "192.0.2.20", 40000, 44818, _encapsulation(0x0063)
    )
    response = _udp(
        "192.0.2.20",
        "192.0.2.10",
        44818,
        40000,
        _encapsulation(0x0063, _identity_cpf()),
    )
    request.time = T0
    response.time = T0 + 0.1
    capture = _write(tmp_path, "enip_identity_exchange.pcap", [request, response])

    result = analyze_enip(capture, show_status=False)

    assert result.source_enip_enum_commands["192.0.2.10"] == 1
    assert result.source_enip_enum_commands["192.0.2.20"] == 0
    assert sum(
        anomaly.title == "ENIP Enumeration/Session Command"
        for anomaly in result.anomalies
    ) == 1


def test_tcp_ack_on_enip_port_is_not_counted_as_protocol_data(
    tmp_path: Path,
) -> None:
    packet = _tcp("192.0.2.10", "192.0.2.20", 40000, 44818, flags="A")
    packet.time = T0
    capture = _write(tmp_path, "enip_ack.pcap", [packet])

    result = analyze_enip(capture, show_status=False)

    assert result.total_packets == 1
    assert result.enip_packets == 0


def test_encapsulation_control_commands_do_not_inflate_unconnected_cip_ratio(
    tmp_path: Path,
) -> None:
    packets = [
        _udp(
            "192.0.2.10",
            "192.0.2.20",
            40000 + index,
            44818,
            _encapsulation(0x0063),
        )
        for index in range(50)
    ]
    for index, packet in enumerate(packets):
        packet.time = T0 + index * 0.1
    capture = _write(tmp_path, "enip_identity_requests.pcap", packets)

    result = analyze_enip(capture, show_status=False)

    assert result.connected_packets == 0
    assert result.unconnected_packets == 0
    assert not any(
        anomaly.title == "High Unconnected ENIP/CIP Ratio"
        for anomaly in result.anomalies
    )
