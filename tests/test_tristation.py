"""TriStation (Triconex, UDP 1502) is decoded, not just counted by port.

Backlog 1.4: ``--safety`` on Nozomi's TRITON capture reported 896 TriStation
packets and nothing about what they did. Frame layout and codes follow
Nozomi's tricotools dissector; the sequence below mirrors TRITON's.
"""

from __future__ import annotations

from scapy.all import Ether, IP, UDP, Raw, wrpcap  # type: ignore

from pcapper.safety import analyze_safety
from pcapper.tristation import parse_frame

EWS, SIS = "192.168.1.88", "192.168.1.2"


def _tcm(tcm_type: int, block: bytes = b"") -> bytes:
    return bytes([tcm_type, 0]) + len(block).to_bytes(2, "little") + block + b"\xbe\xef"


def _ts(direction: int, command: int, seq: int, payload: bytes = b"") -> bytes:
    header = bytes([direction, 1, command, seq]) + b"\x00\x00" + b"\x12\x34"
    return _tcm(0x05, header + (10 + len(payload)).to_bytes(2, "little") + payload)


def _cp_status_reply(seq: int, key: int) -> bytes:
    payload = bytearray(66)  # TS payload starts at frame offset 14
    payload[7] = key  # key switch (frame offset 21)
    payload[8] = 0  # program running (frame offset 22)
    payload += b"NOZOMI\x00\x00\x00\x00"  # project name (frame offset 80)
    return _ts(1, 0x6C, seq, bytes(payload))


def _capture(path, frames: list[tuple[bool, bytes]]) -> None:
    packets = []
    for index, (from_ews, data) in enumerate(frames):
        src, dst = (EWS, SIS) if from_ews else (SIS, EWS)
        sport, dport = (33279, 1502) if from_ews else (1502, 33279)
        pkt = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(data)
        pkt.time = 1_521_551_151 + index * 0.2
        packets.append(pkt)
    wrpcap(str(path), packets)


def test_frame_parsing() -> None:
    frame = parse_frame(_ts(0, 0x41, 7, b"\x00" * 8))
    assert frame is not None and (frame.direction, frame.command, frame.sequence) == (0, 0x41, 7)
    assert parse_frame(_tcm(0x01)).tcm_name == "CONNECT REQUEST"
    status = parse_frame(_cp_status_reply(3, 1))
    assert status.key_state == "PROGRAM" and status.run_state == "Running"
    assert status.project_name == "NOZOMI"
    assert parse_frame(b"\x05\x00\xff\x00garbage") is None  # length does not frame it


def test_triton_sequence_is_flagged(tmp_path) -> None:
    frames = [(True, _tcm(0x01)), (False, _tcm(0x02))]
    seq = 0
    for _ in range(3):
        seq += 1
        frames += [(True, _ts(0, 0x13, seq)), (False, _cp_status_reply(seq, 1))]
    for command in (0x41, 0x42, 0x01, 0x37, 0x0B, 0x14):
        seq += 1
        frames += [(True, _ts(0, command, seq, b"\x00" * 12)), (False, _ts(1, 0x67, seq))]
    frames.append((False, _ts(1, 0x64, seq + 1)))
    capture = tmp_path / "triton.pcap"
    _capture(capture, frames)

    summary = analyze_safety(capture, show_status=False)
    assert summary.tristation_frames == len(frames)
    assert summary.tristation_requests["Get CP status"] == 3
    assert summary.tristation_requests["Allocate program"] == 1
    assert summary.key_states == {"PROGRAM": 3}
    assert summary.tristation_rejects == {"Command rejected": 1}
    found = {d["summary"]: d for d in summary.detections}
    triton = found["TRITON-pattern safety controller reprogramming (TriStation)"]
    assert triton["severity"] == "critical" and "T0843" in triton["details"]
    assert "Triconex key switch in PROGRAM (accepts remote changes)" in found
    assert [name for _ts_, _s, _d, name in summary.tristation_timeline] == [
        "Upload program", "Upload function", "Start download change",
        "Allocate program", "End download change", "Run program",
    ]
    assert "Run program" in summary.commands


def test_status_polling_alone_is_not_an_attack(tmp_path) -> None:
    frames = []
    for seq in range(1, 6):
        frames += [(True, _ts(0, 0x13, seq)), (False, _cp_status_reply(seq, 2))]
    capture = tmp_path / "polling.pcap"
    _capture(capture, frames)
    summary = analyze_safety(capture, show_status=False)
    severities = {d["summary"]: d["severity"] for d in summary.detections}
    assert severities["TriStation status polling"] == "info"
    assert not any(s in ("critical", "high") for s in severities.values())
    assert summary.key_states == {"RUN": 5}
