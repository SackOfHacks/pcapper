from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from pcapper.aim import analyze_aim


def test_aim_fields_are_counted_once_per_packet(tmp_path) -> None:
    capture = tmp_path / "aim_credentials.pcap"
    payload = b"OFT2 user=alice&pass=secret123&message=hello there"
    packet = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=50000, dport=5190)
        / Raw(load=payload)
    )
    wrpcap(str(capture), [packet])

    result = analyze_aim(capture, show_status=False)

    assert result.username_counts == {"alice": 1}
    assert result.password_counts == {"secret123": 1}
    assert result.secret_counts == {"secret123": 1}
    assert result.message_counts == {"hello there": 1}
