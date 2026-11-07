from __future__ import annotations

from scapy.all import Ether, IP, Raw, UDP, wrpcap

import pcapper.snmp as snmp
from pcapper.snmp import _decode_oid, _decode_value, _parse_snmp_message


def _tlv(tag: int, value: bytes) -> bytes:
    if len(value) >= 128:
        raise ValueError("test TLV helper supports short-form lengths only")
    return bytes((tag, len(value))) + value


def test_oid_decoder_handles_multibyte_first_subidentifier() -> None:
    assert _decode_oid(bytes((0x88, 0x37, 0x03))) == "2.999.3"


def test_snmp_integer_values_are_signed() -> None:
    assert _decode_value(0x02, b"\xff") == "-1"


def test_malformed_varbind_length_terminates_parser() -> None:
    varbinds = _tlv(0x30, b"\x30\x05\x06")
    pdu = _tlv(0xA0, _tlv(0x02, b"\x01") * 3 + varbinds)
    message = _tlv(0x30, _tlv(0x02, b"\x00") + _tlv(0x04, b"public") + pdu)

    parsed = _parse_snmp_message(message)

    assert parsed is not None
    assert parsed["varbinds"] == []


def test_snmp_flow_tracking_is_bounded_and_reported(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(snmp, "MAX_SNMP_FLOWS", 1)
    varbinds = _tlv(0x30, b"")
    pdu = _tlv(0xA0, _tlv(0x02, b"\x01") * 3 + varbinds)
    payload = _tlv(0x30, _tlv(0x02, b"\x00") + _tlv(0x04, b"public") + pdu)
    capture = tmp_path / "snmp_flow_limit.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src=f"10.0.0.{index + 1}", dst="10.0.0.100")
            / UDP(sport=50000 + index, dport=161)
            / Raw(load=payload)
            for index in range(2)
        ],
    )

    summary = snmp.analyze_snmp(capture, show_status=False)

    assert summary.snmp_packets == 2
    assert summary.total_messages == 1
    assert len(summary.conversations) == 1
    assert any("SNMP flow tracking cap reached" in error for error in summary.errors)
