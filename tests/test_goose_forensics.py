from __future__ import annotations

import struct
from pathlib import Path

from scapy.layers.l2 import Dot1Q, Ether
from scapy.packet import Raw

from pcapper.goose import (
    _decode_all_data,
    _decode_bit_string,
    _parse_goose_payload,
    analyze_goose,
)
from test_review_batches import T0, _write


def _tlv(tag: int, value: bytes) -> bytes:
    length = len(value)
    if length < 0x80:
        return bytes((tag, length)) + value
    encoded_length = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((tag, 0x80 | len(encoded_length))) + encoded_length + value


def _goose_payload(
    *,
    all_data: bytes = b"",
    st_num: int = 1,
    sq_num: int = 0,
    appid: int = 1,
    simulation: bool = False,
) -> bytes:
    fields = b"".join(
        (
            _tlv(0x80, b"IED1/LLN0$GO$gcb1"),
            _tlv(0x81, (1000).to_bytes(2, "big")),
            _tlv(0x82, b"IED1/LLN0$dataset1"),
            _tlv(0x83, b"IED1-goose"),
            _tlv(0x85, st_num.to_bytes(4, "big")),
            _tlv(0x86, sq_num.to_bytes(4, "big")),
            _tlv(0x87, b"\x01" if simulation else b"\x00"),
            _tlv(0x88, b"\x01"),
            _tlv(0x89, b"\x00"),
            _tlv(0x8A, b"\x01"),
            _tlv(0xAB, all_data),
        )
    )
    pdu = _tlv(0x61, fields)
    return appid.to_bytes(2, "big") + (8 + len(pdu)).to_bytes(2, "big") + b"\x00" * 4 + pdu


def _goose_packet(
    payload: bytes,
    *,
    tagged: bool = False,
    src_mac: str = "02:00:00:00:00:10",
):
    ethernet = Ether(src=src_mac, dst="01:0c:cd:01:00:01")
    if tagged:
        return ethernet / Dot1Q(vlan=100, type=0x88B8) / Raw(load=payload)
    return Ether(src=ethernet.src, dst=ethernet.dst, type=0x88B8) / Raw(
        load=payload
    )


def test_all_data_uses_iec61850_tags_without_overwriting_goid() -> None:
    data = _tlv(0x83, b"\x01") + _tlv(0x85, b"\xff")
    info = _parse_goose_payload(_goose_payload(all_data=data))

    assert info["goID"] == "IED1-goose"
    assert info["allData_values"] == [("boolean", "true"), ("integer", "-1")]


def test_goose_decoder_handles_constructed_arrays_and_structures() -> None:
    data = _tlv(0xA2, _tlv(0x83, b"\x00") + _tlv(0x86, b"\x05"))

    assert _decode_all_data(data) == [("boolean", "false"), ("unsigned", "5")]


def test_goose_decoder_handles_mms_float_and_visible_string() -> None:
    single = b"\x08" + struct.pack(">f", 1.5)
    double = b"\x0b" + struct.pack(">d", -2.25)
    values = _decode_all_data(
        _tlv(0x87, single)
        + _tlv(0x87, double)
        + _tlv(0x8A, b"breaker-open")
    )

    assert values == [
        ("float", "1.5"),
        ("float", "-2.25"),
        ("visible-string", "breaker-open"),
    ]
    assert _decode_bit_string(b"\x08\xff") == ""


def test_vlan_tagged_goose_is_analyzed(tmp_path: Path) -> None:
    packet = _goose_packet(_goose_payload(), tagged=True)
    packet.time = T0
    pcap = _write(tmp_path, "goose_vlan.pcap", [packet])

    result = analyze_goose(pcap, show_status=False)

    assert result.goose_packets == 1
    assert result.gocb_refs["IED1/LLN0$GO$gcb1"] == 1


def test_declared_goose_length_excludes_ethernet_padding(tmp_path: Path) -> None:
    data = _tlv(0x83, b"\x01")
    payload = _goose_payload(all_data=data)
    packet = _goose_packet(payload + b"\xff" * 20)
    packet.time = T0
    pcap = _write(tmp_path, "goose_padding.pcap", [packet])

    result = analyze_goose(pcap, show_status=False)

    assert result.all_data_lengths == {3: 1}
    assert result.data_value_samples["boolean=true"] == 1


def test_truncated_goose_pdu_is_reported_and_not_parsed(tmp_path: Path) -> None:
    payload = _goose_payload()
    packet = _goose_packet(payload[:-2])
    packet.time = T0
    pcap = _write(tmp_path, "goose_truncated.pcap", [packet])

    result = analyze_goose(pcap, show_status=False)

    assert result.goose_packets == 1
    assert not result.gocb_refs
    assert any("declared length" in error for error in result.errors)


def test_state_counter_reset_after_tal_expiry_is_not_flagged(tmp_path: Path) -> None:
    packets = [
        _goose_packet(_goose_payload(st_num=7, sq_num=5)),
        _goose_packet(_goose_payload(st_num=1, sq_num=0)),
    ]
    packets[0].time = T0
    packets[1].time = T0 + 2
    pcap = _write(tmp_path, "goose_reboot.pcap", packets)

    result = analyze_goose(pcap, show_status=False)

    assert not any(
        detection["summary"] in {"GOOSE State Number Decrease", "GOOSE Sequence Reset"}
        for detection in result.detections
    )


def test_same_gocbref_on_distinct_appids_is_not_false_spoofing(tmp_path: Path) -> None:
    packets = [
        _goose_packet(_goose_payload(appid=1), src_mac="02:00:00:00:00:10"),
        _goose_packet(_goose_payload(appid=2), src_mac="02:00:00:00:00:20"),
    ]
    for index, packet in enumerate(packets):
        packet.time = T0 + index * 0.1
    pcap = _write(tmp_path, "goose_distinct_appid.pcap", packets)

    result = analyze_goose(pcap, show_status=False)

    assert not any(
        detection["summary"] == "GOOSE Publisher Spoofing"
        for detection in result.detections
    )


def test_detection_storage_is_bounded_and_reported(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr("pcapper.goose.MAX_GOOSE_DETECTIONS", 1)
    packet = _goose_packet(_goose_payload(simulation=True))
    packet.time = T0
    pcap = _write(tmp_path, "goose_detection_limit.pcap", [packet])

    result = analyze_goose(pcap, show_status=False)

    assert len(result.detections) == 1
    assert result.detections[0]["summary"] == "GOOSE Simulation/Test Bit Set"
    assert any("detection record limit" in error for error in result.errors)
