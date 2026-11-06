from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from pcapper.pccc import _match_signature, _parse_commands, analyze_pccc


def _pccc_frame(command: int, data: bytes = b"") -> bytes:
    body = bytes((1, 0, command, 0, 0x2A, 0)) + data
    checksum = (-sum(body)) & 0xFF
    return b"\x10\x02" + body + b"\x10\x03" + bytes((checksum,))


def test_pccc_only_matches_validated_command_frames() -> None:
    payload = _pccc_frame(0x0F)

    assert _match_signature(payload)
    assert _parse_commands(payload) == ["PCCC Protected Typed Logical Write"]
    assert not _match_signature(b"\x00" * 64)
    assert _parse_commands(b"\x00" * 64) == []


def test_pccc_analyzer_does_not_count_all_ethernet_ip_port_traffic(tmp_path) -> None:
    capture = tmp_path / "pccc_port_false_positive.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=51820, dport=44818)
            / Raw(load=b"\x00" * 64),
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=51820, dport=44818)
            / Raw(load=_pccc_frame(0x0F)),
        ],
    )

    result = analyze_pccc(capture, show_status=False)

    assert result.protocol_packets == 1
    assert result.commands["PCCC Protected Typed Logical Write"] == 1
