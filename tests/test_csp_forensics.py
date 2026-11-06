from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, UDP, wrpcap

from pcapper.csp import analyze_csp


def test_csp_matches_only_tcp_2222(tmp_path) -> None:
    payload = b"\x0f\x00\x00\x00\x67"
    capture = tmp_path / "csp_ports.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=51820, dport=2222)
            / Raw(load=payload),
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=51820, dport=2222)
            / Raw(load=payload),
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=51820, dport=44818)
            / Raw(load=payload),
        ],
    )

    result = analyze_csp(capture, show_status=False)

    assert result.protocol_packets == 1
    assert result.commands["PCCC Write (FNC 0x67)"] == 1
