from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from pcapper.fins import _detect_anomalies, _parse_commands, analyze_fins


def _fins_frame(command: int, *, response: bool = False) -> bytes:
    header = bytes((0xC0 if response else 0x80, 0, 2, 0, 1, 0, 0, 10, 0, 1))
    return header + command.to_bytes(2, "big")


def _fins_tcp(frame: bytes) -> bytes:
    length = 8 + len(frame)
    return b"FINS" + length.to_bytes(4, "big") + (2).to_bytes(4, "big") + b"\x00" * 4 + frame


def test_fins_udp_and_tcp_decode_command_from_fins_header() -> None:
    frame = _fins_frame(0x0102)

    assert _parse_commands(frame) == ["Memory Area Write"]
    assert _parse_commands(_fins_tcp(frame)) == ["Memory Area Write"]


def test_fins_tcp_handshake_and_incomplete_frames_are_not_commands() -> None:
    frame = _fins_frame(0x0402)
    handshake = b"FINS" + (8).to_bytes(4, "big") + b"\x00" * 8
    truncated = _fins_tcp(frame)[:-1]

    assert _parse_commands(handshake) == []
    assert _parse_commands(truncated) == []


def test_fins_responses_are_labeled_but_not_reported_as_commands() -> None:
    response = _fins_frame(0x0402, response=True)

    commands = _parse_commands(response)

    assert commands == ["STOP (operating mode -> PROGRAM / halt) (response)"]
    assert _detect_anomalies(response, "10.0.0.2", "10.0.0.1", 1.0, commands) == []


def test_fins_tcp_analyzer_detects_write_request(tmp_path) -> None:
    capture = tmp_path / "fins_tcp.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=51820, dport=9600)
            / Raw(load=_fins_tcp(_fins_frame(0x0102)))
        ],
    )

    result = analyze_fins(capture, show_status=False)

    assert result.protocol_packets == 1
    assert result.commands["Memory Area Write"] == 1
    assert any(anomaly.title == "FINS Write Operation" for anomaly in result.anomalies)


def test_program_read_and_write_have_distinct_attack_mappings() -> None:
    read_frame = _fins_frame(0x0306)
    write_frame = _fins_frame(0x0307)
    read = _detect_anomalies(
        read_frame, "10.0.0.1", "10.0.0.2", 1.0, _parse_commands(read_frame)
    )
    write = _detect_anomalies(
        write_frame, "10.0.0.1", "10.0.0.2", 1.0, _parse_commands(write_frame)
    )

    assert [(anomaly.title, anomaly.attack) for anomaly in read] == [
        ("FINS Program Upload", "T0845 Program Upload")
    ]
    assert [(anomaly.title, anomaly.attack) for anomaly in write] == [
        ("FINS Program Download", "T0843 Program Download")
    ]
