from __future__ import annotations

from scapy.all import Ether, IP, Raw, UDP

from pcapper.netbios import analyze_netbios
from pcapper.pcap_cache import PcapMeta


def test_packet_view_can_be_analyzed_without_a_capture_path(tmp_path) -> None:
    path = tmp_path / "capture_not_on_disk.pcap"
    packet = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=137, dport=137)
        / Raw(load=b"test")
    )
    meta = PcapMeta(path, "pcap", 0, None, None, None)

    summary = analyze_netbios(path, show_status=False, packets=[packet], meta=meta)

    assert summary.total_packets == 1
    assert summary.protocol_packets == {"UDP": 1}
