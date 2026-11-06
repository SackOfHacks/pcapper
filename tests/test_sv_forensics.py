from __future__ import annotations

from scapy.all import Dot1Q, Ether, Raw, wrpcap

from pcapper.sv import _decode_seq_of_data, _parse_sv_payload, analyze_sv


def _sv_payload(*, declared_length: int | None = None) -> bytes:
    sav_pdu = b"\x60\x08\x80\x03mu1\x82\x01\x07"
    length = 8 + len(sav_pdu) if declared_length is None else declared_length
    return b"\x40\x00" + length.to_bytes(2, "big") + b"\x00" * 4 + sav_pdu


def test_sv_payload_uses_declared_length_and_extracts_fields() -> None:
    payload = _sv_payload() + b"\x00" * 12

    parsed = _parse_sv_payload(payload)

    assert parsed["svID"] == "mu1"
    assert parsed["smpCnt"] == 7


def test_sv_sample_data_is_not_guessed_as_signed_integer_values() -> None:
    assert _decode_seq_of_data(b"\x00\x00\x03\xa6") == ("bytes", ["000003a6"])


def test_sv_payload_reports_invalid_and_truncated_lengths() -> None:
    assert "_parse_error" in _parse_sv_payload(_sv_payload(declared_length=7))
    assert _parse_sv_payload(_sv_payload(declared_length=100))["_parse_error"] == (
        "truncated SV payload"
    )


def test_analyzer_recognizes_vlan_tagged_sv_frames(tmp_path) -> None:
    packet = (
        Ether(src="00:11:22:33:44:55", dst="01:0c:cd:04:00:01")
        / Dot1Q(vlan=10, type=0x88BA)
        / Raw(load=_sv_payload())
    )
    capture = tmp_path / "tagged_sv.pcap"
    wrpcap(str(capture), [packet])

    result = analyze_sv(capture, show_status=False)

    assert result.sv_packets == 1
    assert result.sv_ids["mu1"] == 1
    assert result.smp_counts[7] == 1


def test_analyzer_reports_truncated_sv_payload(tmp_path) -> None:
    packet = (
        Ether(src="00:11:22:33:44:55", dst="01:0c:cd:04:00:01", type=0x88BA)
        / Raw(load=_sv_payload(declared_length=100))
    )
    capture = tmp_path / "truncated_sv.pcap"
    wrpcap(str(capture), [packet])

    result = analyze_sv(capture, show_status=False)

    assert result.sv_packets == 1
    assert result.errors == ["1 malformed SV frame(s): truncated SV payload."]
