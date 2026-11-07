from __future__ import annotations

from scapy.all import Ether, IP, Raw, UDP, wrpcap

from pcapper.hart import (
    _detect_anomalies,
    _is_hart_ip_message,
    _parse_commands,
    analyze_hart,
)


def _hart_ip_message(message_type: int, command: int) -> bytes:
    hart_pdu = bytes((0x02, 0x01, command, 0, 0))
    header = bytes((1, message_type, 3, 0, 0, 1))
    return header + (8 + len(hart_pdu)).to_bytes(2, "big") + hart_pdu


def test_hart_ip_validates_total_message_length_and_type() -> None:
    request = _hart_ip_message(0, 40)

    assert _is_hart_ip_message(request)
    assert not _is_hart_ip_message(request[:-1])
    assert not _is_hart_ip_message(request[:6] + b"\x00\x08" + request[8:])
    assert not _is_hart_ip_message(request[:1] + b"\x02" + request[2:])


def test_hart_ip_labels_responses_and_does_not_flag_them_as_anomalies() -> None:
    response = _hart_ip_message(1, 40)
    commands = _parse_commands(response)

    assert commands == ["Response: Enter/Exit Fixed Current Mode"]
    assert (
        _detect_anomalies(response, "10.0.0.2", "10.0.0.1", 1.0, commands)
        == []
    )


def test_hart_udp_handover_request_and_response_are_decoded_once(tmp_path) -> None:
    request = _hart_ip_message(0, 40)
    response = _hart_ip_message(1, 40)
    capture = tmp_path / "hart_handover.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=51820, dport=5095)
            / Raw(load=request),
            Ether()
            / IP(src="10.0.0.2", dst="10.0.0.1")
            / UDP(sport=5095, dport=51820)
            / Raw(load=response),
        ],
    )

    result = analyze_hart(capture, show_status=False)

    assert result.protocol_packets == 2
    assert result.requests == 1
    assert result.responses == 1
    assert result.commands["Request: Enter/Exit Fixed Current Mode"] == 1
    assert result.commands["Response: Enter/Exit Fixed Current Mode"] == 1
    assert [anomaly.title for anomaly in result.anomalies] == [
        "HART Fixed Current Mode"
    ]
