from __future__ import annotations

from pcapper.dns import analyze_dns


def test_dns_fixture_parses(dns_query_pcap):
    summary = analyze_dns(dns_query_pcap, show_status=False)
    assert summary.total_packets == 1
    assert summary.query_packets == 1
    assert summary.udp_packets == 1
    assert summary.qname_counts
    assert "example.com." in summary.qname_counts
