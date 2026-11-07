from __future__ import annotations

from scapy.all import Ether, IP, TCP, wrpcap

import pcapper.remote_access as remote_access


def test_remote_access_handshake_tracking_limit_is_reported(tmp_path, monkeypatch) -> None:
    capture = tmp_path / "remote_access.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=50000, dport=22, flags="S"),
        ],
    )
    monkeypatch.setattr(remote_access, "_MAX_HANDSHAKES", 0)

    result = remote_access.analyze_remote_access(capture, show_status=False)

    assert not result.sessions
    assert any("handshake limit reached" in error for error in result.errors)
