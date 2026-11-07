from __future__ import annotations

from pcapper.cip import (
    _bytes_to_path_string,
    _parse_cip_message,
    _parse_pccc_command,
)
from pcapper.cip import analyze_cip
from test_review_batches import T0, _tcp, _udp, _write


def _request(path: bytes, data: bytes = b"") -> bytes:
    assert len(path) % 2 == 0
    return b"\x0e" + bytes((len(path) // 2,)) + path + data


def test_8_bit_logical_segments_preserve_instance_and_attribute_types() -> None:
    path = b"\x20\x01\x24\x01\x30\x01"

    parsed = _parse_cip_message(_request(path))

    assert parsed[5:8] == (1, 1, 1)
    assert "Class:1" in parsed[8]
    assert "Instance:1" in parsed[8]
    assert "Attribute:1" in parsed[8]
    assert "Attribute:1" not in parsed[8].split("/")[1]


def test_packed_16_bit_and_32_bit_logical_addresses_decode() -> None:
    class_16 = b"\x21\x05\x00\x24\x02\x30\x01\x00"
    class_32 = b"\x22\x78\x56\x34\x12\x24\x02\x30\x01\x00"

    parsed_16 = _parse_cip_message(_request(class_16))
    parsed_32 = _parse_cip_message(_request(class_32))

    assert parsed_16[5:8] == (5, 2, 1)
    assert parsed_32[5:8] == (0x12345678, 2, 1)
    assert "Instance:2" in parsed_16[8]
    assert "Attribute:1" in parsed_32[8]


def test_symbolic_path_is_decoded_and_request_data_is_preserved() -> None:
    path = b"\x91\x04Main"

    parsed = _parse_cip_message(_request(path, b"\x12\x34"))

    assert parsed[8] == "Symbol:Main"
    assert parsed[9] == b"\x12\x34"
    assert _bytes_to_path_string(path) == "Symbol:Main"


def test_tcp_ack_on_cip_port_is_not_counted_as_protocol_data(tmp_path) -> None:
    packet = _tcp("192.0.2.10", "192.0.2.20", 40000, 44818, flags="A")
    packet.time = T0
    capture = _write(tmp_path, "cip_ack.pcap", [packet])

    result = analyze_cip(capture, show_status=False)

    assert result.total_packets == 1
    assert result.cip_packets == 0


def test_encapsulation_control_messages_do_not_inflate_cip_ratio(tmp_path) -> None:
    data = b"\x63\x00\x00\x00" + b"\x00" * 20
    packets = [
        _udp(
            "192.0.2.10",
            "192.0.2.20",
            40000 + index,
            44818,
            data,
        )
        for index in range(50)
    ]
    for index, packet in enumerate(packets):
        packet.time = T0 + index * 0.1
    capture = _write(tmp_path, "cip_list_identity.pcap", packets)

    result = analyze_cip(capture, show_status=False)

    assert result.connected_packets == 0
    assert result.unconnected_packets == 0
    assert not any(
        anomaly.title == "High Unconnected ENIP/CIP Ratio"
        for anomaly in result.anomalies
    )


def test_pccc_typed_read_and_write_function_codes_are_classified_correctly() -> None:
    requestor_id = b"\x07" + b"\x00" * 6
    header = b"\x0f\x00\x01\x00"

    assert _parse_pccc_command(requestor_id + header + b"\x67") == (
        "Typed Write",
        True,
    )
    assert _parse_pccc_command(requestor_id + header + b"\x68") == (
        "Typed Read",
        False,
    )
