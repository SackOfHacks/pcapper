from __future__ import annotations

from scapy.all import Ether, IP, Raw, UDP, wrpcap

from pcapper.kerberos import analyze_kerberos


def test_malformed_etype_sequence_does_not_crash_analysis(tmp_path) -> None:
    capture = tmp_path / "malformed_kerberos.pcap"
    payload = b"\x6a\x08\xa8\x01\x30\x04\x02\x01\x11\x02"
    packet = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=50000, dport=88)
        / Raw(load=payload)
    )
    wrpcap(str(capture), [packet])

    result = analyze_kerberos(capture, show_status=False)

    assert result.request_types["AS-REQ"] == 1
    assert not result.etype_counts
