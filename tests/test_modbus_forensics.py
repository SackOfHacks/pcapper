from __future__ import annotations

from pathlib import Path

import pytest


def _modbus_packet(function_code: int, data: bytes, timestamp: float):
    scapy = pytest.importorskip("scapy.all")
    pdu = bytes([function_code]) + data
    mbap = b"\x00\x01\x00\x00" + (len(pdu) + 1).to_bytes(2, "big") + b"\x01"
    packet = (
        scapy.Ether()
        / scapy.IP(src="192.168.10.50", dst="192.168.10.10")
        / scapy.TCP(sport=40000, dport=502)
        / scapy.Raw(load=mbap + pdu)
    )
    packet.time = timestamp
    return packet


def test_modbus_write_finding_uses_request_timestamp(tmp_path: Path) -> None:
    from pcapper.modbus import analyze_modbus

    timestamp = 1_700_000_123.5
    packet = _modbus_packet(5, b"\x00\x01\xff\x00", timestamp)
    summary = analyze_modbus(
        tmp_path / "capture.pcap", show_status=False, packets=[packet]
    )

    finding = next(
        item for item in summary.anomalies if item.title == "Modbus Coil Force (output manipulation)"
    )
    assert finding.ts == timestamp


def test_modbus_duration_uses_timestamp_range_not_packet_order(
    tmp_path: Path,
) -> None:
    from pcapper.modbus import analyze_modbus

    packets = [
        _modbus_packet(3, b"\x00\x00\x00\x01", 1_700_000_010.0),
        _modbus_packet(3, b"\x00\x00\x00\x01", 1_700_000_000.0),
    ]
    summary = analyze_modbus(
        tmp_path / "capture.pcap", show_status=False, packets=packets
    )

    assert summary.duration == pytest.approx(10.0)


def test_device_id_parser_obeys_declared_object_count() -> None:
    from pcapper.modbus import _parse_device_id_response

    pdu = b"\x2b\x0e\x01\x01\x00\x00\x01\x00\x06vendor\x01\x06product"

    assert _parse_device_id_response(pdu) == {"vendor": "vendor"}


def test_device_id_parser_rejects_truncated_declared_objects() -> None:
    from pcapper.modbus import _parse_device_id_response

    pdu = b"\x2b\x0e\x01\x01\x00\x00\x02\x00\x06vendor\x01\x0a"

    assert _parse_device_id_response(pdu) == {}


def test_modbus_request_split_across_tcp_segments_is_reassembled(
    tmp_path: Path,
) -> None:
    scapy = pytest.importorskip("scapy.all")
    pdu = b"\x03\x00\x00\x00\x01"
    adu = b"\x00\x01\x00\x00\x00\x06\x01" + pdu
    split = 5
    first = (
        scapy.Ether()
        / scapy.IP(src="192.168.10.50", dst="192.168.10.10")
        / scapy.TCP(sport=40000, dport=502, seq=100)
        / scapy.Raw(load=adu[:split])
    )
    second = (
        scapy.Ether()
        / scapy.IP(src="192.168.10.50", dst="192.168.10.10")
        / scapy.TCP(sport=40000, dport=502, seq=100 + split)
        / scapy.Raw(load=adu[split:])
    )
    first.time = 1_700_000_000.0
    second.time = 1_700_000_001.0

    from pcapper.modbus import analyze_modbus

    summary = analyze_modbus(
        tmp_path / "capture.pcap",
        show_status=False,
        packets=[first, second],
    )

    assert len(summary.messages) == 1
    assert summary.messages[0].func_name == "Read Holding Registers"


def test_ethernet_padding_does_not_corrupt_modbus_stream_state(
    tmp_path: Path,
) -> None:
    scapy = pytest.importorskip("scapy.all")
    ack = (
        scapy.Ether()
        / scapy.IP(src="192.168.10.50", dst="192.168.10.10", len=40)
        / scapy.TCP(sport=40000, dport=502, seq=100, flags="A")
        / scapy.Padding(load=b"\x00" * 6)
    )
    packet = _modbus_packet(3, b"\x00\x00\x00\x01", 1_700_000_001.0)
    packet[scapy.TCP].seq = 100
    ack.time = 1_700_000_000.0

    from pcapper.modbus import analyze_modbus

    summary = analyze_modbus(
        tmp_path / "capture.pcap",
        show_status=False,
        packets=[ack, packet],
    )

    assert len(summary.messages) == 1
    assert summary.messages[0].func_name == "Read Holding Registers"
