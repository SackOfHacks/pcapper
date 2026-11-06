from __future__ import annotations

from scapy.all import Ether, IP, Raw, UDP, wrpcap

from pcapper.synchrophasor import (
    _iter_c37118_frames,
    _looks_like_c37118,
    analyze_synchrophasor,
)


def _frame(frame_type: int, command: int | None = None, *, size: int | None = None) -> bytes:
    frame_size = size or (18 if command is not None else 16)
    frame = bytearray(frame_size)
    frame[0] = 0xAA
    frame[1] = (frame_type << 4) | 1
    frame[2:4] = frame_size.to_bytes(2, "big")
    frame[4:6] = (7).to_bytes(2, "big")
    if command is not None and frame_size >= 16:
        frame[14:16] = command.to_bytes(2, "big")
    return bytes(frame)


def test_c37118_requires_full_declared_frame() -> None:
    truncated = _frame(4, 1)[:-2]

    assert _looks_like_c37118(truncated) is None
    assert _iter_c37118_frames(truncated) == []


def test_c37118_splits_coalesced_frames() -> None:
    frames = _iter_c37118_frames(_frame(0) + _frame(1))

    assert [(frame_type, len(frame)) for frame_type, frame in frames] == [
        (0, 16),
        (1, 16),
    ]


def test_analyzer_decodes_complete_command_frames(tmp_path) -> None:
    packet = (
        Ether()
        / IP(src="192.0.2.10", dst="192.0.2.20")
        / UDP(sport=4712, dport=4712)
        / Raw(load=_frame(4, 1))
    )
    capture = tmp_path / "c37118_command.pcap"
    wrpcap(str(capture), [packet])

    result = analyze_synchrophasor(capture, show_status=False)

    assert result.synchrophasor_packets == 1
    assert result.commands["Turn OFF data transmission"] == 1
    assert any("data-transmission disabled" in d["summary"] for d in result.detections)


def test_analyzer_ignores_truncated_command_frame(tmp_path) -> None:
    packet = (
        Ether()
        / IP(src="192.0.2.10", dst="192.0.2.20")
        / UDP(sport=4712, dport=4712)
        / Raw(load=_frame(4, 1)[:-2])
    )
    capture = tmp_path / "c37118_truncated.pcap"
    wrpcap(str(capture), [packet])

    result = analyze_synchrophasor(capture, show_status=False)

    assert result.synchrophasor_packets == 0
    assert result.commands == {}
