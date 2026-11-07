from __future__ import annotations

from scapy.all import Ether, IP, TCP, wrpcap

import pcapper.tcp as tcp


def test_tcp_flow_tracking_is_bounded_and_reported(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(tcp, "MAX_TCP_FLOWS", 1)
    capture = tmp_path / "tcp_flow_limit.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst=f"10.0.0.{index + 2}")
            / TCP(sport=51820 + index, dport=502, flags="S")
            for index in range(2)
        ],
    )

    summary = tcp.analyze_tcp(capture, show_status=False)

    assert summary.tcp_packets == 2
    assert len(summary.conversations) == 1
    assert any("TCP flow tracking cap reached" in error for error in summary.errors)
