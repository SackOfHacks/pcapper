from __future__ import annotations

from scapy.all import Ether, wrpcap
from scapy.layers.l2 import ARP

from pcapper.arp import analyze_arp


def test_arp_replies_pair_to_requests_and_later_reply_is_unsolicited(tmp_path) -> None:
    capture = tmp_path / "arp_reply_pairing.pcap"
    client_mac = "02:00:00:00:00:01"
    server_mac = "02:00:00:00:00:02"
    request = (
        Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(
            op=1,
            hwsrc=client_mac,
            psrc="10.0.0.1",
            hwdst="00:00:00:00:00:00",
            pdst="10.0.0.2",
        )
    )
    reply = (
        Ether(src=server_mac, dst=client_mac)
        / ARP(
            op=2,
            hwsrc=server_mac,
            psrc="10.0.0.2",
            hwdst=client_mac,
            pdst="10.0.0.1",
        )
    )
    wrpcap(str(capture), [request, reply, reply.copy()])

    summary = analyze_arp(capture, show_status=False)

    assert summary.unsolicited_replies == 1
    assert len(summary.sessions) == 1
    assert summary.sessions[0].requests == 1
    assert summary.sessions[0].replies == 2
