from __future__ import annotations

from scapy.all import Ether, IP, Raw, UDP, wrpcap

from pcapper.syslog import analyze_syslog


def _syslog_packet(timestamp: float, payload: bytes):
    packet = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=50000, dport=514)
        / Raw(load=payload)
    )
    packet.time = timestamp
    return packet


def test_syslog_conversation_times_use_minimum_and_maximum(tmp_path) -> None:
    capture = tmp_path / "out_of_order_syslog.pcap"
    wrpcap(
        str(capture),
        [
            _syslog_packet(10, b"<13>1 2024-01-01T00:00:00Z host app 1 id - first"),
            _syslog_packet(5, b"<13>1 2024-01-01T00:00:01Z host app 1 id - second"),
        ],
    )

    result = analyze_syslog(capture, show_status=False)

    assert result.conversations[0].first_seen == 5
    assert result.conversations[0].last_seen == 10


def test_invalid_syslog_pri_is_not_mapped_to_facility_or_severity(tmp_path) -> None:
    capture = tmp_path / "invalid_pri.pcap"
    wrpcap(
        str(capture),
        [_syslog_packet(1, b"<999>1 2024-01-01T00:00:00Z host app 1 id - invalid")],
    )

    result = analyze_syslog(capture, show_status=False)

    assert not result.facility_counts
    assert not result.severity_counts


def test_rfc3164_header_fields() -> None:
    from pcapper.syslog import _parse_syslog

    # HOSTNAME may be omitted: the token after the timestamp is then the TAG.
    parsed = _parse_syslog("<133>Apr  5 12:56:51 robin: Hello, syslog!")
    assert (parsed["hostname"], parsed["appname"]) == (None, "robin")
    parsed = _parse_syslog("<86>Mar  1 06:00:02 fw01 sshd[1234]: Accepted password for root from 10.0.0.5")
    assert (parsed["hostname"], parsed["appname"], parsed["procid"]) == ("fw01", "sshd", "1234")
    # rsyslog's high-precision template: RFC 3339 time, no version field.
    parsed = _parse_syslog("<13>2013-09-12T19:16:34.457849+04:00 localhost cron: job done")
    assert (parsed["hostname"], parsed["appname"]) == ("localhost", "cron")


def test_binary_payload_on_syslog_port_is_not_scanned_as_a_message(tmp_path) -> None:
    capture = tmp_path / "binary_on_514.pcap"
    noise = bytes(range(128, 256)) * 2
    wrpcap(
        str(capture),
        [
            # "C2" between random bytes matched \bc2\b: a malware indicator.
            _syslog_packet(1, b"<" + noise[:40] + b"\x00C2\x00" + noise[40:]),
            _syslog_packet(2, b"<13>Mar  1 06:00:02 host sshd[7]: Failed password for root from 10.0.0.9"),
        ],
    )

    result = analyze_syslog(capture, show_status=False)

    titles = {str(d.get("summary") or d.get("title")) for d in result.detections}
    assert "Malware indicator" not in titles
    assert "Authentication failure" in titles
    assert [m["appname"] for m in result.messages] == [None, "sshd"]
