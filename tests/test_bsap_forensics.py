from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, UDP, wrpcap

from pcapper.bsap import analyze_bsap


def test_bsap_matches_only_documented_udp_service_port(tmp_path) -> None:
    capture = tmp_path / "bsap_ports.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=51820, dport=1234)
            / Raw(load=b"bsap"),
            Ether()
            / IP(src="10.0.0.2", dst="10.0.0.1")
            / UDP(sport=1234, dport=51820)
            / Raw(load=b"bsap"),
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=51820, dport=1235)
            / Raw(load=b"unidentified"),
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=51820, dport=1234)
            / Raw(load=b"unidentified"),
        ],
    )

    result = analyze_bsap(capture, show_status=False)

    assert result.protocol_packets == 2
    assert result.ports == {1234: 2, 51820: 2}
    assert result.commands == {}
