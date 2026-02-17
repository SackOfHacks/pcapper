from __future__ import annotations

from pcapper.udp import analyze_udp


def test_udp_fixture_counts(dns_query_pcap):
    summary = analyze_udp(dns_query_pcap, show_status=False)
    assert summary.udp_packets == 1
    assert summary.port_counts[53] == 1
