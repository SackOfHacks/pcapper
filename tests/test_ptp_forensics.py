from __future__ import annotations

from scapy.all import Dot1Q, Ether, IP, Raw, UDP, wrpcap

from pcapper.ptp import _parse_ptp_header, analyze_ptp


def _ptp_message(
    message_type: int, sequence_id: int, *, domain: int = 0, message_length: int = 34
) -> bytes:
    payload = bytearray(34)
    payload[0] = message_type
    payload[1] = 2
    payload[2:4] = message_length.to_bytes(2, "big")
    payload[4] = domain
    payload[20:30] = bytes.fromhex("00112233445566778899")
    payload[30:32] = sequence_id.to_bytes(2, "big")
    return bytes(payload)


def test_ptp_header_requires_complete_v2_common_header_and_length() -> None:
    assert _parse_ptp_header(b"\x00" * 10) == "truncated PTP common header"
    assert _parse_ptp_header(_ptp_message(0, 1, message_length=33)) == (
        "invalid PTP message length below common header size"
    )
    assert _parse_ptp_header(_ptp_message(0, 1, message_length=40)) == (
        "truncated PTP message"
    )


def test_analyzer_recognizes_vlan_tagged_ptp(tmp_path) -> None:
    packet = (
        Ether(src="00:11:22:33:44:55", dst="01:1b:19:00:00:00")
        / Dot1Q(vlan=10, type=0x88F7)
        / Raw(load=_ptp_message(0xB, 42, domain=3))
    )
    capture = tmp_path / "tagged_ptp.pcap"
    wrpcap(str(capture), [packet])

    result = analyze_ptp(capture, show_status=False)

    assert result.ptp_packets == 1
    assert result.msg_types["Announce"] == 1
    assert result.domain_numbers[3] == 1
    assert result.sequence_ids[42] == 1


def test_sequence_tracking_is_per_message_type_and_handles_wrap(tmp_path) -> None:
    packets = [
        Ether(type=0x88F7) / Raw(load=_ptp_message(0, 0xFFFF)),
        Ether(type=0x88F7) / Raw(load=_ptp_message(8, 500)),
        Ether(type=0x88F7) / Raw(load=_ptp_message(0, 0)),
    ]
    capture = tmp_path / "ptp_sequence.pcap"
    wrpcap(str(capture), packets)

    result = analyze_ptp(capture, show_status=False)

    assert not any(d["summary"] == "PTP Sequence Decrease" for d in result.detections)


def test_analyzer_reports_malformed_ptp_port_payload(tmp_path) -> None:
    packet = (
        Ether()
        / IP(src="192.0.2.1", dst="192.0.2.2")
        / UDP(sport=319, dport=319)
        / Raw(load=b"\x00\x02")
    )
    capture = tmp_path / "malformed_ptp.pcap"
    wrpcap(str(capture), [packet])

    result = analyze_ptp(capture, show_status=False)

    assert result.ptp_packets == 1
    assert result.msg_types == {}
    assert result.errors == ["1 malformed PTP message(s): truncated PTP common header."]


def test_ptp_unicast_udp_destination_is_reported(tmp_path) -> None:
    packet = (
        Ether()
        / IP(src="192.0.2.1", dst="192.0.2.2")
        / UDP(sport=320, dport=320)
        / Raw(load=_ptp_message(0xB, 1))
    )
    capture = tmp_path / "unicast_ptp.pcap"
    wrpcap(str(capture), [packet])

    result = analyze_ptp(capture, show_status=False)

    assert any(d["summary"] == "PTP Unicast Destinations" for d in result.detections)
