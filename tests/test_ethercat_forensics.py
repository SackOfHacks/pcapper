from __future__ import annotations

from scapy.all import Dot1Q, Ether, Raw, wrpcap

from pcapper.ethercat import (
    ETHERCAT_ETHERTYPE,
    _detect_anomalies,
    _parse_commands,
    _parse_mailbox,
    analyze_ethercat,
)


def _ethercat_frame(command: int, data: bytes) -> bytes:
    datagram = (
        bytes((command, 0))
        + b"\x00" * 4
        + len(data).to_bytes(2, "little")
        + b"\x00\x00"
        + data
        + b"\x01\x00"
    )
    header = (0x1000 | len(datagram)).to_bytes(2, "little")
    return header + datagram


def _mailbox(mailbox_type: int, payload: bytes) -> bytes:
    return (
        len(payload).to_bytes(2, "little")
        + b"\x00" * 3
        + bytes((mailbox_type,))
        + payload
    )


def test_ethercat_mailbox_types_and_soe_opcodes_are_decoded() -> None:
    foe_commands = _parse_mailbox(_mailbox(0x04, b"\x02\x00\x00\x00\x00\x00"))
    soe_commands = _parse_mailbox(_mailbox(0x05, b"\x03"))

    assert "Mailbox FoE" in foe_commands
    assert "FoE WRQ" in foe_commands
    assert "Mailbox SoE" in soe_commands
    assert "SoE Write Request" in soe_commands


def test_ethercat_datagram_parser_respects_frame_header_and_lengths() -> None:
    payload = _ethercat_frame(0x05, b"\x00\x00")

    assert "FPWR" in _parse_commands(payload)
    assert _parse_commands(b"\x01\x00" + payload[2:]) == []
    assert _parse_commands(payload[:-1]) == []


def test_ethercat_foe_write_is_high_severity(tmp_path) -> None:
    packet = (
        Ether(type=ETHERCAT_ETHERTYPE)
        / Raw(load=_ethercat_frame(0x05, _mailbox(0x04, b"\x02\x00\x00\x00\x00\x00")))
    )
    capture = tmp_path / "ethercat_foe_write.pcap"
    wrpcap(str(capture), [packet])

    result = analyze_ethercat(capture, show_status=False)

    assert result.commands["Mailbox FoE"] == 1
    assert result.commands["FoE WRQ"] == 1
    finding = next(a for a in result.anomalies if a.title == "EtherCAT FoE Activity")
    assert finding.severity == "HIGH"


def test_ethercat_foe_read_is_not_reported_as_a_firmware_write() -> None:
    commands = _parse_commands(
        _ethercat_frame(0x05, _mailbox(0x04, b"\x01\x00\x00\x00\x00\x00"))
    )
    findings = _detect_anomalies(b"", "a", "b", 0.0, commands)

    assert "FoE RRQ" in commands
    assert findings[0].severity == "MEDIUM"


def test_ethercat_analyzer_recognizes_vlan_tagged_frames(tmp_path) -> None:
    packet = (
        Ether()
        / Dot1Q(vlan=22, type=ETHERCAT_ETHERTYPE)
        / Raw(load=_ethercat_frame(0x01, b"\x00"))
    )
    capture = tmp_path / "tagged_ethercat.pcap"
    wrpcap(str(capture), [packet])

    result = analyze_ethercat(capture, show_status=False)

    assert result.protocol_packets == 1
    assert result.commands["APRD"] == 1
