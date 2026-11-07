from __future__ import annotations

from scapy.all import Ether, IP, Raw, UDP, wrpcap

import pcapper.quic as quic


def test_quic_flow_tracking_is_bounded_and_reported(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(quic, "MAX_QUIC_FLOWS", 1)
    capture = tmp_path / "quic_flow_limit.pcap"
    payload = b"\xc0\x00\x00\x00\x01\x00\x00"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src=f"10.0.0.{index + 1}", dst="10.0.0.100")
            / UDP(sport=50000 + index, dport=443)
            / Raw(load=payload)
            for index in range(2)
        ],
    )

    summary = quic.analyze_quic(capture, show_status=False)

    assert summary.quic_packets == 2
    assert len(summary.flow_counts) == 1
    assert any("QUIC flow tracking capped at 1" in error for error in summary.errors)
