from __future__ import annotations

from collections import Counter

from scapy.all import Ether, IP, Raw, TCP, wrpcap

import pcapper.rdp as rdp


def test_rdp_session_tracking_is_bounded_and_reported(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(rdp, "MAX_RDP_SESSIONS", 1)
    capture = tmp_path / "rdp_session_limit.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=51000 + index, dport=3389)
            / Raw(load=b"RDP probe")
            for index in range(2)
        ],
    )

    summary = rdp.analyze_rdp(capture, show_status=False)

    assert summary.rdp_packets == 2
    assert summary.total_sessions == 1
    assert any("RDP session tracking capped at 1" in error for error in summary.errors)


def test_rdp_plaintext_value_counters_are_bounded(monkeypatch) -> None:
    monkeypatch.setattr(rdp, "MAX_RDP_UNIQUE_VALUES", 1)
    plaintext = Counter()
    suspicious = Counter()
    files = Counter()
    artifacts = []

    rdp._scan_plaintext(
        b"password=secret1 file1.exe file2.exe",
        plaintext,
        suspicious,
        files,
        artifacts,
        max_unique=1,
    )

    assert len(plaintext) <= 1
    assert len(suspicious) <= 1
    assert len(files) <= 1
