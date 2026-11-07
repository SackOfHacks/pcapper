from __future__ import annotations

from scapy.all import Ether, IP, UDP, wrpcap

import pcapper.udp as udp


def test_udp_flow_tracking_is_bounded_and_reported(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(udp, "MAX_UDP_FLOWS", 1)
    capture = tmp_path / "udp_flow_limit.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst=f"10.0.0.{index + 2}")
            / UDP(sport=51820 + index, dport=12345)
            for index in range(2)
        ],
    )

    summary = udp.analyze_udp(capture, show_status=False)

    assert summary.udp_packets == 2
    assert len(summary.conversations) == 1
    assert any("UDP flow tracking cap reached" in error for error in summary.errors)
