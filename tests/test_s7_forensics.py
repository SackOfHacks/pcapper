from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, wrpcap

import pcapper.s7 as s7_protocol
from pcapper.s7 import _S7State, analyze_s7


def _s7_pdu(
    param: bytes,
    *,
    rosctr: int = 0x01,
    data: bytes = b"",
    declared_param_len: int | None = None,
    pdu_ref: int = 1,
) -> bytes:
    param_len = len(param) if declared_param_len is None else declared_param_len
    header = (
        b"\x32"
        + bytes([rosctr])
        + b"\x00\x00"
        + pdu_ref.to_bytes(2, "big")
        + param_len.to_bytes(2, "big")
        + len(data).to_bytes(2, "big")
    )
    error = b"\x00\x00" if rosctr in {0x02, 0x03} else b""
    payload = header + error + param + data
    cotp = b"\x02\xf0\x80" + payload
    return b"\x03\x00" + (len(cotp) + 4).to_bytes(2, "big") + cotp


def test_s7_readvar_decodes_only_supported_s7any_items() -> None:
    s7any = bytes.fromhex("12 0a 10 04 00 01 00 01 84 00 00 00")
    commands = _S7State().parse_commands(_s7_pdu(b"\x04\x01" + s7any))

    assert "ReadVar" in commands
    assert "ReadVar DB1.DBB0 len=1 BYTE" in commands


def test_s7_readvar_does_not_decode_malformed_variable_specification() -> None:
    malformed_spec = bytes.fromhex(
        "12 0e b2 ff 00 00 00 52 ea 2d b0 d9 40 00 00 10"
    )
    commands = _S7State().parse_commands(
        _s7_pdu(b"\x04\x01" + malformed_spec)
    )

    assert "ReadVar" in commands
    assert not any(command.startswith("ReadVar AREA") for command in commands)


def test_s7_rejects_truncated_declared_parameter_length() -> None:
    commands = _S7State().parse_commands(
        _s7_pdu(b"\x04\x01", declared_param_len=4)
    )

    assert not any(command in {"Job", "ReadVar"} for command in commands)


def test_s7_analyzer_reassembles_tpkt_split_across_tcp_segments(tmp_path) -> None:
    s7any = bytes.fromhex("12 0a 10 04 00 01 00 01 84 00 00 00")
    frame = _s7_pdu(b"\x04\x01" + s7any)
    packets = [
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=41000, dport=102, seq=100, flags="PA")
        / Raw(load=frame[:5]),
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=41000, dport=102, seq=105, flags="PA")
        / Raw(load=frame[5:]),
    ]
    capture = tmp_path / "split_s7.pcap"
    wrpcap(str(capture), packets)

    result = analyze_s7(capture, show_status=False)

    assert result.commands["ReadVar"] == 1
    assert result.commands["ReadVar DB1.DBB0 len=1 BYTE"] == 1
    assert not result.errors


def test_s7_bounds_pending_transaction_state(monkeypatch) -> None:
    monkeypatch.setattr(s7_protocol, "_MAX_PENDING_TRANSACTIONS", 1)
    state = _S7State()

    for pdu_ref in (1, 2):
        state.detect_anomalies(
            _s7_pdu(b"\x05", pdu_ref=pdu_ref),
            "10.0.0.1",
            "10.0.0.2",
            1.0,
            [],
        )

    assert len(state.pending) == 1
    assert any("transaction limit reached" in error for error in state.errors)
