from __future__ import annotations

from pathlib import Path

from scapy.layers.l2 import Ether

from pcapper.dnp3 import (
    _crc16_dnp,
    _parse_objects,
    _parse_dnp3_frames,
    analyze_dnp3,
)
from test_review_batches import T0, _tcp, _udp, _write


def _frame(user_data: bytes, *, src: int = 3, dst: int = 1, control: int = 0xC4) -> bytes:
    header = (
        b"\x05\x64"
        + bytes((5 + len(user_data), control))
        + dst.to_bytes(2, "little")
        + src.to_bytes(2, "little")
    )
    frame = header + _crc16_dnp(header).to_bytes(2, "little")
    for offset in range(0, len(user_data), 16):
        block = user_data[offset : offset + 16]
        frame += block + _crc16_dnp(block).to_bytes(2, "little")
    return frame


def _tcp_packet(payload: bytes, seq: int, ts: float):
    pkt = _tcp("192.0.2.10", "192.0.2.20", 40000, 20000, payload, seq=seq)
    pkt.time = ts
    return pkt


def test_tcp_segmented_link_frame_is_reassembled(tmp_path: Path) -> None:
    frame = _frame(b"\xc0\xc0\x05")
    split = 7
    pcap = _write(
        tmp_path,
        "dnp3_split.pcap",
        [
            _tcp_packet(frame[:split], 1000, T0),
            _tcp_packet(frame[split:], 1000 + split, T0 + 0.1),
        ],
    )

    result = analyze_dnp3(pcap, show_status=False)

    assert len(result.messages) == 1
    assert result.messages[0].func_name == "Direct Operate"
    assert result.messages[0].is_master
    assert result.messages[0].ts == T0 + 0.1
    assert not any("CRC Mismatch" in anomaly.title for anomaly in result.anomalies)


def test_transport_reassembly_checks_sequence_wraparound(tmp_path: Path) -> None:
    first = _frame(b"\xbf\xc0")
    last = _frame(b"\x40\x05")
    pcap = _write(
        tmp_path,
        "dnp3_transport_split.pcap",
        [
            _tcp_packet(first, 1000, T0),
            _tcp_packet(last, 1000 + len(first), T0 + 0.1),
        ],
    )

    result = analyze_dnp3(pcap, show_status=False)

    assert [message.func_name for message in result.messages] == ["Direct Operate"]
    assert not any("transport sequence gap" in error for error in result.errors)


def test_transport_gap_discards_fragment_instead_of_forging_a_message(
    tmp_path: Path,
) -> None:
    first = _frame(b"\x81\xc0")
    last = _frame(b"\x43\x05")
    pcap = _write(
        tmp_path,
        "dnp3_transport_gap.pcap",
        [
            _tcp_packet(first, 1000, T0),
            _tcp_packet(last, 1000 + len(first), T0 + 0.1),
        ],
    )

    result = analyze_dnp3(pcap, show_status=False)

    assert not result.messages
    assert any("transport sequence gap" in error for error in result.errors)


def test_count_qualifier_sizes_follow_dnp3_wire_values() -> None:
    object_data = b"\x00" + (123).to_bytes(4, "little", signed=True)
    for qualifier, count_bytes in (
        (0x07, b"\x01"),
        (0x08, b"\x01\x00"),
        (0x09, b"\x01\x00\x00\x00"),
    ):
        objects, _ = _parse_objects(
            b"\x1e\x01" + bytes((qualifier,)) + count_bytes + object_data
        )
        assert objects[0]["count"] == 1
        assert objects[0]["values"] == [123]


def test_all_objects_qualifier_is_reported_without_consuming_data() -> None:
    objects, details = _parse_objects(b"\x3c\x01\x06")

    assert details == ["60.1"]
    assert objects[0]["summary"] == "Class Data 60.1 all"


def test_count_and_index_prefix_qualifier_preserves_point_indexes() -> None:
    object_data = b"\x00" + (123).to_bytes(4, "little", signed=True)
    for header in (b"\x17\x01", b"\x28\x01\x00"):
        prefix = b"\x05" if header[0] == 0x17 else b"\x05\x00"
        objects, _ = _parse_objects(
            b"\x1e\x01" + header + prefix + object_data
        )
        assert objects[0]["count"] == 1
        assert objects[0]["indices"] == [5]
        assert objects[0]["values"] == [123]


def test_link_control_frame_without_user_data_has_valid_crc() -> None:
    frame = _frame(b"")

    assert len(frame) == 10
    assert _parse_dnp3_frames(frame) == [(3, 1, 0xC4, b"", True)]


def test_udp_ethernet_padding_is_not_reported_as_crc_corruption(tmp_path: Path) -> None:
    frame = _frame(b"")
    packet = _udp("192.0.2.10", "192.0.2.20", 40000, 20000, frame)
    packet = Ether(bytes(packet) + b"\x00" * 8)
    packet.time = T0
    pcap = _write(tmp_path, "dnp3_padding.pcap", [packet])

    result = analyze_dnp3(pcap, show_status=False)

    assert not any("CRC Mismatch" in anomaly.title for anomaly in result.anomalies)


def test_tcp_ack_on_dnp3_port_is_not_counted_as_a_dnp3_packet(tmp_path: Path) -> None:
    packet = _tcp("192.0.2.10", "192.0.2.20", 40000, 20000, flags="A")
    pcap = _write(tmp_path, "dnp3_ack.pcap", [packet])

    result = analyze_dnp3(pcap, show_status=False)

    assert result.dnp3_packets == 0


def test_link_direction_bit_identifies_outstation_sender(tmp_path: Path) -> None:
    frame = _frame(b"\xc0\x81\x00\x00", src=1, dst=3, control=0x44)
    packet = _tcp("192.0.2.20", "192.0.2.10", 20000, 40000, frame)
    pcap = _write(tmp_path, "dnp3_response.pcap", [packet])

    result = analyze_dnp3(pcap, show_status=False)

    assert len(result.messages) == 1
    assert not result.messages[0].is_master


def test_duration_uses_protocol_timestamps_not_packet_order(tmp_path: Path) -> None:
    frame = _frame(b"\xc0\x01")
    packets = [
        _tcp_packet(frame, 1000, T0 + 10),
        _tcp_packet(frame, 1000 + len(frame), T0),
    ]
    pcap = _write(tmp_path, "dnp3_duration.pcap", packets)

    result = analyze_dnp3(pcap, show_status=False)

    assert result.duration == 10


def test_aggregate_findings_use_a_capture_timestamp(tmp_path: Path) -> None:
    pcap = _write(
        tmp_path,
        "dnp3_select.pcap",
        [_tcp_packet(_frame(b"\xc0\xc0\x03"), 1000, T0)],
    )

    result = analyze_dnp3(pcap, show_status=False)
    finding = next(
        anomaly
        for anomaly in result.anomalies
        if anomaly.title == "DNP3 Select Without Operate"
    )

    assert finding.ts == T0


def test_select_authorization_is_consumed_by_the_first_operate(
    tmp_path: Path,
) -> None:
    frames = [
        _frame(b"\xc0\xc0\x03"),
        _frame(b"\xc0\xc0\x04"),
        _frame(b"\xc0\xc0\x04"),
    ]
    packets = []
    seq = 1000
    for index, frame in enumerate(frames):
        packets.append(_tcp_packet(frame, seq, T0 + index * 0.1))
        seq += len(frame)
    pcap = _write(tmp_path, "dnp3_sbo.pcap", packets)

    result = analyze_dnp3(pcap, show_status=False)

    assert sum(
        anomaly.title == "DNP3 Operate Without Select"
        for anomaly in result.anomalies
    ) == 1


def test_message_detail_storage_is_bounded_and_reported(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("pcapper.dnp3.MAX_DNP3_MESSAGES", 1)
    frames = [_frame(b"\xc0\xc0\x01"), _frame(b"\xc0\xc0\x01")]
    packets = []
    seq = 1000
    for index, frame in enumerate(frames):
        packets.append(_tcp_packet(frame, seq, T0 + index * 0.1))
        seq += len(frame)
    pcap = _write(tmp_path, "dnp3_message_limit.pcap", packets)

    result = analyze_dnp3(pcap, show_status=False)

    assert len(result.messages) == 1
    assert sum(result.func_counts.values()) == 2
    assert any("message record limit" in error for error in result.errors)
