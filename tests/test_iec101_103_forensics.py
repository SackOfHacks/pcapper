from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from pcapper.iec101_103 import (
    _extract_iec_apdus,
    _iec_apdu_candidate,
    _parse_asdu,
    analyze_iec101_103,
)


def _iec101_frame(type_id: int, cot: int) -> bytes:
    user_data = bytes((0x40, 0x01, type_id, 0x01, cot, 0x00))
    length = len(user_data)
    checksum = sum(user_data) & 0xFF
    return (
        b"\x68"
        + bytes((length, length, 0x68))
        + user_data
        + bytes((checksum, 0x16))
    )


def test_iec101_requires_complete_frame_and_valid_checksum() -> None:
    frame = _iec101_frame(45, 6)
    corrupt = frame[:-2] + bytes((frame[-2] ^ 0x01,)) + frame[-1:]

    assert _iec_apdu_candidate(frame)
    assert not _iec_apdu_candidate(frame[:-1])
    assert not _iec_apdu_candidate(corrupt)
    assert _parse_asdu(frame) == ("ASDU 45", "Activation", 45, 6)


def test_iec101_extracts_coalesced_frames_and_reports_each_command(tmp_path) -> None:
    frame = _iec101_frame(45, 6)
    assert len(_extract_iec_apdus(frame + frame)) == 2
    packet = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=24000, dport=2404, flags="PA")
        / Raw(load=frame + frame)
    )
    capture = tmp_path / "coalesced_iec101.pcap"
    wrpcap(str(capture), [packet])

    result = analyze_iec101_103(capture, show_status=False)

    assert result.candidate_packets == 1
    assert result.type_counts["ASDU 45"] == 2
    assert result.cause_counts["Activation"] == 2
    finding = next(
        item for item in result.detections
        if item["summary"] == "IEC 101/103 Control Command (Activation)"
    )
    assert "x2" in finding["evidence"][0]
