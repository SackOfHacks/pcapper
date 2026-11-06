from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from pcapper.mms import _detect_mms_anomalies, _parse_commands, analyze_mms


def _tpkt(mms_pdu: bytes) -> bytes:
    cotp = b"\x02\xf0\x80" + mms_pdu
    return b"\x03\x00" + (len(cotp) + 4).to_bytes(2, "big") + cotp


def test_mms_finds_write_service_inside_presentation_wrappers() -> None:
    payload = bytes.fromhex(
        "01000100611d301b020103a016a014020100a50fa0083006a00480026d75a003850100"
    )

    commands = _parse_commands(payload)

    assert "MMS Confirmed-Request" in commands
    assert "MMS Service Write" in commands
    anomalies = _detect_mms_anomalies(payload, "10.0.0.1", "10.0.0.2", 1.0, commands)
    assert [finding.title for finding in anomalies] == ["MMS Write Operation"]


def test_mms_does_not_misclassify_association_a0_as_confirmed_request() -> None:
    commands = _parse_commands(bytes.fromhex("a0 03 80 01 01"))

    assert not any(command.startswith("MMS ") for command in commands)


def test_mms_maps_control_and_transfer_service_tags_correctly() -> None:
    take_control = _parse_commands(bytes.fromhex("a0 06 02 01 01 b3 01 00"))
    upload = _parse_commands(bytes.fromhex("a0 06 02 01 01 9d 01 00"))
    stop = _parse_commands(bytes.fromhex("a0 07 02 01 01 bf 29 01 00"))
    delete_program = _parse_commands(bytes.fromhex("a0 07 02 01 01 9f 27 01 00"))
    terminate_upload = _parse_commands(bytes.fromhex("a0 07 02 01 01 9f 1f 01 00"))

    assert "MMS Service TakeControl" in take_control
    assert "MMS Service InitiateUploadSequence" in upload
    assert "MMS Service Stop" in stop
    assert "MMS Service DeleteProgramInvocation" in delete_program
    assert "MMS Service TerminateUploadSequence" in terminate_upload


def test_mms_does_not_report_response_services_as_requests() -> None:
    response = _parse_commands(bytes.fromhex("a1 06 02 01 01 a5 01 00"))

    assert "MMS Confirmed-Response" in response
    assert not any(command.startswith("MMS Service ") for command in response)


def test_mms_parses_multiple_tpkt_frames_in_one_payload() -> None:
    read = _tpkt(bytes.fromhex("a0 06 02 01 01 a4 01 00"))
    write = _tpkt(bytes.fromhex("a0 06 02 01 02 a5 01 00"))

    commands = _parse_commands(read + write)

    assert commands.count("MMS Service Read") == 1
    assert commands.count("MMS Service Write") == 1
    assert commands.count("TPKT") == 2


def test_mms_analyzer_reassembles_tpkt_split_across_tcp_segments(tmp_path) -> None:
    frame = _tpkt(bytes.fromhex("a0 06 02 01 01 a5 01 00"))
    packets = [
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=41000, dport=102, seq=100, flags="PA")
        / Raw(load=frame[:6]),
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=41000, dport=102, seq=106, flags="PA")
        / Raw(load=frame[6:]),
    ]
    capture = tmp_path / "split_mms.pcap"
    wrpcap(str(capture), packets)

    result = analyze_mms(capture, show_status=False)

    assert result.commands["MMS Service Write"] == 1
    assert any(finding.title == "MMS Write Operation" for finding in result.anomalies)
    assert not result.errors
