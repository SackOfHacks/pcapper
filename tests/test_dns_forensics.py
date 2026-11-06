from __future__ import annotations

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, UDP

from pcapper.dns import analyze_dns


def test_dns_answer_names_are_case_insensitive(tmp_path) -> None:
    packets = [
        Ether()
        / IP(src="8.8.8.8", dst="10.0.0.1")
        / UDP(sport=53, dport=53000)
        / DNS(
            id=txid,
            qr=1,
            qd=DNSQR(qname=qname),
            an=DNSRR(rrname=qname, type="A", rdata=address),
        )
        for txid, qname, address in (
            (1, "PLC1.Example.net.", "192.0.2.10"),
            (2, "plc1.example.NET.", "192.0.2.11"),
        )
    ]

    summary = analyze_dns(
        tmp_path / "case-insensitive-dns.pcap",
        packets=packets,
        show_status=False,
    )

    assert summary.answers_by_qname["plc1.example.net"] == {
        "192.0.2.10",
        "192.0.2.11",
    }
