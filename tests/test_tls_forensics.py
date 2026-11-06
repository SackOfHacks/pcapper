from __future__ import annotations

from pathlib import Path

from scapy.all import Ether, IP, Raw, TCP, rdpcap, wrpcap

import pcapper.tls as tls


def test_tls_conversation_tracking_is_bounded_and_reported(tmp_path, monkeypatch) -> None:
    capture = tmp_path / "tls_conversations.pcap"
    payload = b"\x16\x03\x03\x00\x02\x01\x00"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=50000, dport=443)
            / Raw(load=payload),
            Ether()
            / IP(src="10.0.0.3", dst="10.0.0.2")
            / TCP(sport=50001, dport=443)
            / Raw(load=payload),
        ],
    )
    monkeypatch.setattr(tls, "MAX_TLS_CONVERSATIONS", 1)

    result = tls.analyze_tls(capture, show_status=False)

    assert len(result.conversations) == 1
    assert any("TLS conversation limit reached" in note for note in result.analysis_notes)


def test_tls_high_cardinality_values_are_bounded(tmp_path, monkeypatch) -> None:
    source = Path(__file__).parent / "data" / "tls.pcap"
    capture = tmp_path / "tls_unique_values.pcap"
    wrpcap(str(capture), rdpcap(str(source)))
    monkeypatch.setattr(tls, "MAX_TLS_UNIQUE_VALUES", 1)

    result = tls.analyze_tls(capture, show_status=False)

    assert len(result.sni_counts) <= 1
    assert any("TLS unique-value limit reached" in note for note in result.analysis_notes)
