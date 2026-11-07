from __future__ import annotations

from scapy.all import Ether, IP, Raw, UDP, wrpcap

from pcapper.profinet import (
    DCP_OPTIONS,
    DCP_SERVICE_IDS,
    DCP_SUBOPTIONS,
    _decode_dcp_blocks,
    _parse_commands,
    _parse_dcp,
    _parse_port_commands,
    _parse_pnio_rpc,
    analyze_profinet,
)


def _dcp(
    service_id: int, service_type: int, blocks: bytes, *, length: int | None = None
) -> bytes:
    data_length = len(blocks) if length is None else length
    header = (
        b"\xfe\xfd"
        + bytes((service_id, service_type))
        + b"\x00" * 6
        + data_length.to_bytes(2, "big")
    )
    return header + blocks


def _pnio_read_rpc(*, response: bool = False) -> bytes:
    block_body = bytearray(58)
    block_body[0:2] = b"\x00\x0a"
    block_body[18:22] = b"\x00\x00\x00\x00"
    block_body[22:24] = b"\x00\x00"
    block_body[24:26] = b"\x00\x01"
    block_body[28:30] = b"\xf8\x40"
    block_body[30:34] = (104 if response else 32768).to_bytes(4, "big")
    block_type = 0x8009 if response else 0x0009
    block = block_type.to_bytes(2, "big") + b"\x00\x3c\x01\x00" + block_body
    stub = (
        (0).to_bytes(4, "little")
        + len(block).to_bytes(4, "little")
        + (32832).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + len(block).to_bytes(4, "little")
        + block
    )
    header = bytearray(80)
    header[:8] = bytes.fromhex("04 02 28 00 10 00 00 00") if response else bytes.fromhex("04 00 08 00 10 00 00 00")
    header[24:40] = bytes.fromhex("0100a0de976cd111827100a02442df7d")
    header[68:70] = (5).to_bytes(2, "little")
    header[74:76] = len(stub).to_bytes(2, "little")
    return bytes(header) + stub


def test_dcp_service_and_option_ids_match_profinet_values() -> None:
    assert DCP_SERVICE_IDS[0x03] == "Get"
    assert DCP_SERVICE_IDS[0x05] == "Identify"
    assert DCP_OPTIONS[0x05] == "Control"
    assert DCP_OPTIONS[0x06] == "DeviceInitiative"
    assert DCP_SUBOPTIONS[(0x05, 0x06)] == "Reset to Factory"


def test_dcp_zero_length_get_selector_is_not_dropped() -> None:
    commands, _, anomalies = _parse_dcp(
        _dcp(0x03, 0x00, b"\x02\x02\x00\x00")
    )

    assert "DCP Get Request" in commands
    assert "DCP Device/Device Name" in commands
    assert any(a.title == "PROFINET DCP Enumeration" for a in anomalies)


def test_dcp_set_request_detected_but_response_is_not_a_control_alert() -> None:
    set_name_block = b"\x02\x02\x00\x07\x00\x01PLC-1"
    request_commands, _, request_anomalies = _parse_dcp(
        _dcp(0x04, 0x00, set_name_block)
    )
    response_commands, _, response_anomalies = _parse_dcp(
        _dcp(0x04, 0x01, set_name_block)
    )

    assert "DCP Set Request" in request_commands
    assert any(a.title == "PROFINET DCP Device Name Set" for a in request_anomalies)
    assert "DCP Set Response" in response_commands
    assert not response_anomalies


def test_dcp_reset_control_option_is_alerted_only_on_request() -> None:
    reset_block = b"\x05\x06\x00\x02\x00\x01"
    _, _, request_anomalies = _parse_dcp(_dcp(0x04, 0x00, reset_block))
    _, _, response_anomalies = _parse_dcp(_dcp(0x04, 0x01, reset_block))

    assert any(a.title == "PROFINET DCP Reset" for a in request_anomalies)
    assert not response_anomalies


def test_dcp_declared_length_bounds_block_parsing() -> None:
    valid_but_outside_declared_length = b"\x02\x02\x00\x06\x00\x01PLC-1"

    commands, artifacts, anomalies = _parse_dcp(
        _dcp(0x04, 0x00, valid_but_outside_declared_length, length=0)
    )

    assert "DCP Truncated Data" not in commands
    assert not any(command.startswith("DCP Device/") for command in commands)
    assert not artifacts
    assert [a.title for a in anomalies] == ["PROFINET DCP Set/Reset"]


def test_dcp_truncated_declared_payload_is_reported() -> None:
    commands, _, _ = _parse_dcp(
        _dcp(0x04, 0x00, b"\x02\x02\x00\x02\x00\x01", length=20)
    )

    assert "DCP Truncated Data" in commands


def test_reserved_frame_id_is_not_misclassified_as_dcp() -> None:
    commands = _parse_commands(b"\xfe\x01\x80\x01\x00\x00\x00\x00\x00\x00\x00\x00")

    assert commands == ["FrameID 0xfe01"]


def test_dcp_block_parser_accepts_zero_length_selector_and_stops_at_truncation() -> None:
    blocks = _decode_dcp_blocks(b"\x02\x02\x00\x00", 0)
    truncated = _decode_dcp_blocks(b"\x02\x02\x00\x04\x00", 0)

    assert blocks == [(0x02, 0x02, b"")]
    assert not truncated


def test_pnio_cm_read_rpc_decodes_request_and_response_blocks() -> None:
    request_commands = _parse_port_commands(_pnio_read_rpc())
    response_commands = _parse_port_commands(_pnio_read_rpc(response=True))
    request_commands_from_rpc, request_artifacts = _parse_pnio_rpc(_pnio_read_rpc())

    assert "PNIO Device Read Implicit Request" in request_commands
    assert "PNIO IODReadReqHeader Block" in request_commands
    assert "PNIO Device Read Implicit Response" in response_commands
    assert "PNIO IODReadResHeader Block" in response_commands
    assert request_commands_from_rpc == request_commands
    assert any("index=0xf840" in detail for _, detail in request_artifacts)
    assert not any(command.startswith("FrameID") for command in request_commands)


def test_pnio_rpc_signature_classifies_response_to_low_source_port(tmp_path) -> None:
    packets = [
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=1566, dport=34964)
        / Raw(load=_pnio_read_rpc()),
        Ether()
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / UDP(sport=34964, dport=1566)
        / Raw(load=_pnio_read_rpc(response=True)),
    ]
    capture = tmp_path / "pnio_rpc.pcap"
    wrpcap(str(capture), packets)

    result = analyze_profinet(capture, show_status=False)

    assert result.protocol_packets == 2
    assert result.commands["PNIO Device Read Implicit Request"] == 1
    assert result.commands["PNIO Device Read Implicit Response"] == 1
