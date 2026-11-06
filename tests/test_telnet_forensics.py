from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, wrpcap

import pcapper.telnet as telnet


def _packet(sport: int, payload: bytes) -> object:
    return (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=sport, dport=23)
        / Raw(load=payload)
    )


def test_telnet_session_state_is_bounded_and_limit_is_reported(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(telnet, "MAX_TELNET_SESSIONS", 1)
    capture = tmp_path / "telnet_session_limit.pcap"
    wrpcap(
        str(capture),
        [
            _packet(51820, b"login: user1\r\n"),
            _packet(51821, b"login: user2\r\n"),
        ],
    )

    result = telnet.analyze_telnet(capture, show_status=False)

    assert result.total_sessions == 1
    assert any("session tracking limit" in error for error in result.errors)


def test_telnet_transcript_retention_is_bounded_and_reported(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(telnet, "MAX_TELNET_TRANSCRIPT_PER_SESSION", 4)
    capture = tmp_path / "telnet_transcript_limit.pcap"
    wrpcap(str(capture), [_packet(51820, b"login: user1\r\n")])

    result = telnet.analyze_telnet(capture, show_status=False)

    assert result.total_sessions == 1
    assert any("transcript retention limit" in error for error in result.errors)


def test_telnet_credential_patterns_require_whole_keywords() -> None:
    assert telnet._extract_transcript_credentials("compass: secret") == (None, None)
