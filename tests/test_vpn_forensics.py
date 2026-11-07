from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, UDP, wrpcap

from pcapper.vpn import _packet_ip_proto, analyze_vpn


def test_ipsec_protocol_is_read_from_ipv4_layer() -> None:
    packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2", proto=47) / Raw(load=b"\x00" * 8)

    assert _packet_ip_proto(packet) == 47


def test_generic_tls_on_tcp_443_is_not_mislabeled_as_vpn(tmp_path) -> None:
    capture = tmp_path / "ordinary_tls_443.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=50000, dport=443)
            / Raw(load=b"\x16\x03\x03\x00\x02\x01\x00"),
        ],
    )

    assert analyze_vpn(capture, show_status=False).vpn_packets == 0


def test_quic_on_udp_443_is_not_mislabeled_as_vpn(tmp_path) -> None:
    capture = tmp_path / "quic_443.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=50000, dport=443)
            / Raw(load=b"\xc0\x00\x00\x00\x01\x00\x00"),
        ],
    )

    assert analyze_vpn(capture, show_status=False).vpn_packets == 0
