from __future__ import annotations

from pcapper.ips import analyze_ips


def test_ips_fixture_counts(dns_query_pcap):
    summary = analyze_ips(dns_query_pcap, show_status=False)
    assert summary.unique_ips == 2
    assert summary.src_counts["1.1.1.1"] == 1
    assert summary.dst_counts["2.2.2.2"] == 1
