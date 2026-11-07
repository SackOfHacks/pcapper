from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, wrpcap

import pcapper.email as email


def _smtp_packet(payload: bytes, sport: int = 50000):
    return (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=sport, dport=25)
        / Raw(load=payload)
    )


def test_email_mime_buffer_limit_is_reported(tmp_path, monkeypatch) -> None:
    capture = tmp_path / "large_mime.pcap"
    payload = b"DATA\r\nSubject: sample\r\n" + b"A" * 1024 + b"\r\n.\r\n"
    wrpcap(str(capture), [_smtp_packet(payload)])
    monkeypatch.setattr(email, "MAX_EMAIL_MIME_BYTES_PER_MESSAGE", 128)
    monkeypatch.setattr(email, "MAX_EMAIL_TOTAL_MIME_BYTES", 128)

    result = email.analyze_email(capture, show_status=False)

    assert any("Email MIME data limits reached" in error for error in result.errors)


def test_email_stream_limit_is_reported(tmp_path, monkeypatch) -> None:
    capture = tmp_path / "email_streams.pcap"
    wrpcap(
        str(capture),
        [
            _smtp_packet(b"EHLO mail.example\r\n", 50000),
            _smtp_packet(b"EHLO mail.example\r\n", 50001),
        ],
    )
    monkeypatch.setattr(email, "MAX_EMAIL_STREAMS", 1)

    result = email.analyze_email(capture, show_status=False)

    assert any("Email stream limit reached" in error for error in result.errors)
