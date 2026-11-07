from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, wrpcap

import pcapper.winrm as winrm


def test_winrm_session_tracking_is_bounded_and_reported(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(winrm, "MAX_WINRM_SESSIONS", 1)
    capture = tmp_path / "winrm_session_limit.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=51000 + index, dport=5985)
            / Raw(load=b"WSMAN")
            for index in range(2)
        ],
    )

    summary = winrm.analyze_winrm(capture, show_status=False)

    assert summary.winrm_packets == 2
    assert summary.total_sessions == 1
    assert any("WinRM session tracking capped at 1" in error for error in summary.errors)
