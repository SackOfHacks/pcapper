from __future__ import annotations

from collections import Counter
from pathlib import Path

from pcapper.industrial_helpers import IndustrialAnalysis, IndustrialArtifact
from pcapper.reporting import render_s7_summary
from pcapper.s7 import _S7State, _parse_userdata_command, _parse_var_items


def _wrap_tpkt(cotp_payload: bytes) -> bytes:
    total = 4 + len(cotp_payload)
    return b"\x03\x00" + total.to_bytes(2, "big") + cotp_payload


def _build_cotp_dt(s7_payload: bytes) -> bytes:
    # COTP Data TPDU header: LI=2, PDU Type=DT, EOT=0x80.
    return b"\x02\xF0\x80" + s7_payload


def _build_s7_job(pdu_ref: int, func_code: int, param: bytes) -> bytes:
    header = b"\x32\x01\x00\x00" + pdu_ref.to_bytes(2, "big")
    header += len(param).to_bytes(2, "big") + b"\x00\x00"
    return header + param


def _build_s7_ackdata(
    pdu_ref: int,
    func_code: int,
    *,
    error_class: int = 0,
    error_code: int = 0,
) -> bytes:
    param = bytes([func_code, 0x01])
    header = b"\x32\x03\x00\x00" + pdu_ref.to_bytes(2, "big")
    header += len(param).to_bytes(2, "big") + b"\x00\x00"
    header += bytes([error_class, error_code])
    return header + param


def _build_s7_userdata(pdu_ref: int, param: bytes) -> bytes:
    header = b"\x32\x07\x00\x00" + pdu_ref.to_bytes(2, "big")
    header += len(param).to_bytes(2, "big") + b"\x00\x00"
    return header + param


def test_s7_parser_requires_valid_tpkt_cotp_framing() -> None:
    state = _S7State()

    # Contains 0x32 but does not contain a valid TPKT frame.
    noisy_payload = b"random-bytes\x32\x01\x00\x00"
    commands = state.parse_commands(noisy_payload)

    assert commands == []


def test_s7_parse_var_items_supports_dynamic_item_length() -> None:
    item_one = b"\x12\x0b\x10\x03\x00\x01\x00\x01\x84\x00\x00\x08\x00"
    item_two = b"\x12\x0a\x10\x04\x00\x01\x00\x01\x84\x00\x00\x00"
    param = b"\x04\x02" + item_one + item_two

    commands, targets = _parse_var_items("ReadVar", param)

    assert len(commands) == 2
    assert targets == ["DB1.DBX1.0", "DB1.DBB0"]


def test_s7_transaction_correlation_marks_confirmed_write() -> None:
    state = _S7State()

    write_param = b"\x05\x01\x12\x0a\x10\x04\x00\x01\x00\x01\x84\x00\x00\x00"
    request_payload = _wrap_tpkt(_build_cotp_dt(_build_s7_job(1, 0x05, write_param)))
    response_payload = _wrap_tpkt(_build_cotp_dt(_build_s7_ackdata(1, 0x05)))

    request_commands = state.parse_commands(request_payload)
    request_anomalies = state.detect_anomalies(
        request_payload,
        "10.0.0.10",
        "10.0.0.20",
        1000.0,
        request_commands,
    )
    response_commands = state.parse_commands(response_payload)
    response_anomalies = state.detect_anomalies(
        response_payload,
        "10.0.0.20",
        "10.0.0.10",
        1001.0,
        response_commands,
    )

    assert any(a.title == "S7 Write Operation Requested" for a in request_anomalies)
    assert any(a.title == "S7 Write Operation Confirmed" for a in response_anomalies)


def test_s7_parser_extracts_cotp_tsap_profile() -> None:
    state = _S7State()

    cotp_cr = bytes(
        [
            0x11,
            0xE0,
            0x00,
            0x00,
            0x00,
            0x01,
            0x00,
            0xC1,
            0x02,
            0x01,
            0x00,
            0xC2,
            0x02,
            0x01,
            0x02,
            0xC0,
            0x01,
            0x0A,
        ]
    )
    payload = _wrap_tpkt(cotp_cr)

    commands = state.parse_commands(payload)

    assert "COTP:CR" in commands
    assert any("SrcTSAP=" in cmd and "DstTSAP=" in cmd for cmd in commands)
    assert any("DstRef=0x0000:SrcRef=0x0001" in cmd for cmd in commands)
    assert "COTP:CR:TPDUSize=1024" in commands


def test_s7_parser_and_anomaly_support_cotp_disconnect() -> None:
    state = _S7State()

    # COTP DR: LI=6, PDU=DR, dst_ref=0x0001, src_ref=0x0002, reason=0x80 (Normal).
    cotp_dr = bytes([0x06, 0x80, 0x00, 0x01, 0x00, 0x02, 0x80])
    payload = _wrap_tpkt(cotp_dr)

    commands = state.parse_commands(payload)
    anomalies = state.detect_anomalies(
        payload,
        "10.0.0.10",
        "10.0.0.20",
        1000.0,
        commands,
    )

    assert "COTP:DR" in commands
    assert "COTP:DR:Reason=Normal" in commands
    assert any(a.title == "COTP Disconnect Request" for a in anomalies)


def test_s7_parse_userdata_extended_group_and_subfunction() -> None:
    # Extended coding observed in corpus: group=0x11, subfunction=0x47.
    param = bytes.fromhex("0001120411470100")

    command = _parse_userdata_command(param)

    assert command is not None
    assert command.startswith("UserData:Cpu:CpuStatus")
    assert "(g=0x11,s=0x47)" in command


def test_s7_parse_userdata_marker_search_not_fixed_offset() -> None:
    # Marker appears after 3-byte prefix; parser should still decode it.
    param = b"\x99\x88\x77" + bytes.fromhex("0001120411450100")

    command = _parse_userdata_command(param)

    assert command is not None
    assert command.startswith("UserData:Cpu:CpuPassword")


def test_s7_parse_userdata_vartab_read_format() -> None:
    # Captured in step7_s300_readVarTab.pcapng
    param = bytes.fromhex("0001120812410e0000000000")

    command = _parse_userdata_command(param)

    assert command is not None
    assert command.startswith("UserData:Cpu:VarTabRead")


def test_s7_parse_userdata_vartab_write_format() -> None:
    # Captured in step7_s300_readVarTab.pcapng / rwVarTab variants
    param = bytes.fromhex("0001120812810e0300000000")

    command = _parse_userdata_command(param)

    assert command is not None
    assert command.startswith("UserData:Cpu:VarTabWrite")


def test_s7_userdata_vartab_operations_create_enumeration_anomaly() -> None:
    state = _S7State()

    param = bytes.fromhex("0001120812410e0000000000")
    payload = _wrap_tpkt(_build_cotp_dt(_build_s7_userdata(11, param)))
    commands = state.parse_commands(payload)
    anomalies = state.detect_anomalies(
        payload,
        "10.0.0.10",
        "10.0.0.20",
        1000.0,
        commands,
    )

    assert any(cmd.startswith("UserData:Cpu:VarTabRead") for cmd in commands)
    assert any(a.title == "S7 Enumeration/Diagnostics" for a in anomalies)


def test_render_s7_summary_includes_detected_devices_information_section() -> None:
    summary = IndustrialAnalysis(path=Path("sample.pcap"))
    summary.commands = Counter({"COTP:CR:SrcTSAP=0x0100(PG,rack=0,slot=0):DstTSAP=0x0102(PG,rack=0,slot=2)": 1})
    summary.service_endpoints = {
        "COTP:CR:SrcTSAP=0x0100(PG,rack=0,slot=0):DstTSAP=0x0102(PG,rack=0,slot=2)": Counter({"10.0.0.10 -> 10.0.0.20": 1})
    }
    summary.artifacts = [
        IndustrialArtifact(
            kind="equipment",
            detail="Siemens: SIMATIC S7-300",
            src="10.0.0.10",
            dst="10.0.0.20",
            ts=1000.0,
        )
    ]

    rendered = render_s7_summary(summary)

    assert "Detected Devices Information" in rendered
    assert "Siemens: SIMATIC S7-300" in rendered


def test_s7_low_confidence_requires_semantic_signal() -> None:
    state = _S7State()
    analysis = IndustrialAnalysis(path=Path("sample.pcap"))
    analysis.protocol_packets = 5
    analysis.commands = Counter({"TPKT": 5})

    assert state.is_low_confidence(analysis)


def test_s7_low_confidence_accepts_cotp_session_signal() -> None:
    state = _S7State()
    analysis = IndustrialAnalysis(path=Path("sample.pcap"))
    analysis.protocol_packets = 3
    analysis.commands = Counter({"COTP:CR": 1, "COTP:CC": 1})

    assert not state.is_low_confidence(analysis)
