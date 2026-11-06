from __future__ import annotations

from scapy.all import Ether, IP, Raw, UDP, wrpcap

from pcapper.ntp import analyze_ntp


def test_short_udp_payload_on_ntp_port_is_not_classified_as_ntp(tmp_path) -> None:
    capture = tmp_path / "short_ntp_payload.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=40000, dport=123)
            / Raw(load=b"\x1b\x02"),
        ],
    )

    summary = analyze_ntp(capture, show_status=False)

    assert summary.ntp_packets == 0
    assert not summary.mode_counts
