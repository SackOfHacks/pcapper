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
