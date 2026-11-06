from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, UDP, wrpcap

from pcapper.ot_ports import OT_PORT_PROTOCOLS
from pcapper.protocols import INDUSTRIAL_PORTS
from pcapper.services import COMMON_PORTS
from pcapper.yokogawa import analyze_yokogawa


def test_yokogawa_uses_vnet_ip_udp_port_and_does_not_infer_writes_from_text(
    tmp_path,
) -> None:
    capture = tmp_path / "yokogawa_ports.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=51820, dport=5313)
            / Raw(load=b"write"),
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=51820, dport=34378)
            / Raw(load=b"write"),
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=51820, dport=34378)
            / Raw(load=b"write"),
        ],
    )

    result = analyze_yokogawa(capture, show_status=False)

    assert result.protocol_packets == 1
    assert not result.commands
    assert not any(
        anomaly.title == "Yokogawa Write Operation" for anomaly in result.anomalies
    )
    assert OT_PORT_PROTOCOLS[5313] == "Yokogawa Vnet/IP"
    assert INDUSTRIAL_PORTS[34378] == "P-NET"
    assert COMMON_PORTS[34378] == "P-NET"
