from __future__ import annotations

from types import SimpleNamespace

from scapy.all import IP, Raw, TCP

from pcapper.codesys import (
    CODESYS_TCP_MAGIC,
    _CodesysTCPReassembler,
    _parse_commands,
    _parse_v3_datagram,
    analyze_codesys,
)
from test_review_batches import T0, _tcp, _udp, _write


def _codesys_v3_download(response: bool = False) -> bytes:
    service = (
        b"\x55\xcd"
        + b"\x10\x00"
        + (0x82 if response else 0x02).to_bytes(2, "little")
        + b"\x05\x00"
        + b"\x00" * 12
    )
    channel = (
        b"\x01\x01"
        + b"\x00" * 10
        + len(service).to_bytes(4, "little")
        + b"\x00" * 4
        + service
    )
    datagram = b"\xc5\x03\x00\x40\x01\x00\x00\x00" + channel
    length = 8 + len(datagram)
    return CODESYS_TCP_MAGIC + length.to_bytes(4, "little") + datagram


def test_codesys_v3_udp_discovery_port_is_recognized(tmp_path) -> None:
    packet = _udp("192.0.2.10", "192.0.2.255", 1740, 1740, b"CODESYS")
    packet.time = T0
    capture = _write(tmp_path, "codesys_v3_udp.pcap", [packet])

    result = analyze_codesys(capture, show_status=False)

    assert result.protocol_packets == 1
    assert result.commands["CODESYS Banner"] == 1


def test_codesys_v3_tcp_runtime_port_is_recognized(tmp_path) -> None:
    packet = _tcp("192.0.2.10", "192.0.2.20", 40000, 11740, b"CODESYS")
    packet.time = T0
    capture = _write(tmp_path, "codesys_v3_tcp.pcap", [packet])

    result = analyze_codesys(capture, show_status=False)

    assert result.protocol_packets == 1
    assert result.commands["CODESYS Banner"] == 1


def test_codesys_v3_udp_name_service_datagram_is_decoded() -> None:
    payload = b"\xc5\x0b\x40\x01\x00\x10\x00\x96"

    parsed = _parse_v3_datagram(payload)

    assert parsed is not None
    assert parsed["service_name"] == "AddressNotification Request"
    assert "CODESYS AddressNotification Request" in _parse_commands(payload)


def test_codesys_v3_udp_truncated_header_is_reported() -> None:
    parsed = _parse_v3_datagram(b"\xc5\x0b")

    assert parsed is not None
    assert parsed["issues"] == ["Truncated CoDeSys V3 datagram header."]


def test_codesys_v3_tcp_application_download_is_decoded_and_alerted() -> None:
    payload = _codesys_v3_download()

    commands = _parse_commands(payload)

    assert "CODESYS Application Download" in commands


def test_codesys_v3_tcp_analyzer_detects_download_operation(tmp_path) -> None:
    packet = _tcp("192.0.2.10", "192.0.2.20", 40000, 11740, _codesys_v3_download())
    packet.time = T0
    capture = _write(tmp_path, "codesys_v3_download.pcap", [packet])

    result = analyze_codesys(capture, show_status=False)

    assert result.commands["CODESYS Application Download"] == 1
    assert any(a.title == "CODESYS Program Transfer" for a in result.anomalies)


def test_codesys_v3_tcp_response_is_not_counted_as_a_download() -> None:
    assert "CODESYS Application Download" not in _parse_commands(
        _codesys_v3_download(response=True)
    )


def test_codesys_v3_tcp_frame_is_reassembled_across_segments() -> None:
    frame = _codesys_v3_download()
    reassembler = _CodesysTCPReassembler()
    match = SimpleNamespace(
        src="192.0.2.1",
        dst="192.0.2.2",
        sport=40000,
        dport=11740,
        payload=frame[:5],
    )
    first = IP(src=match.src, dst=match.dst) / TCP(
        sport=match.sport, dport=match.dport, seq=100, flags="PA"
    ) / Raw(load=frame[:5])
    assert reassembler(first, match) == b""

    match.payload = frame[5:]
    second = IP(src=match.src, dst=match.dst) / TCP(
        sport=match.sport, dport=match.dport, seq=105, flags="PA"
    ) / Raw(load=frame[5:])
    decoded = reassembler(second, match)

    assert _parse_commands(decoded).count("CODESYS Application Download") == 1
