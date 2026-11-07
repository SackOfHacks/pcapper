from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, UDP, wrpcap

from pcapper.honeywell import analyze_honeywell
from pcapper.ot_ports import OT_PORT_PROTOCOLS


def test_honeywell_cda_matches_documented_tcp_service_port(tmp_path) -> None:
    capture = tmp_path / "honeywell_cda.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=51820, dport=55565)
            / Raw(load=b"\x01\x02\x03"),
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=51820, dport=55566)
            / Raw(load=b"Honeywell CDA"),
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=51820, dport=55565)
            / Raw(load=b"Honeywell"),
        ],
    )

    result = analyze_honeywell(capture, show_status=False)

    assert result.protocol_packets == 1
    assert not result.commands
    assert [anomaly.title for anomaly in result.anomalies] == [
        "Honeywell CDA Traffic"
    ]
    assert OT_PORT_PROTOCOLS[55565] == "Honeywell CDA"
