from __future__ import annotations

from scapy.all import Ether, ICMP, IP, Raw, wrpcap
from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest, IPv6, IPv6ExtHdrDestOpt

from pcapper.icmp import analyze_icmp


def test_echo_sessions_pair_replies_and_walk_ipv6_extensions(tmp_path) -> None:
    capture = tmp_path / "icmp_sessions.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / ICMP(type=8, id=1, seq=1)
            / Raw(load=b"ping"),
            Ether()
            / IP(src="10.0.0.2", dst="10.0.0.1")
            / ICMP(type=0, id=1, seq=1)
            / Raw(load=b"ping"),
            Ether()
            / IPv6(src="2001:db8::1", dst="2001:db8::2")
            / IPv6ExtHdrDestOpt()
            / ICMPv6EchoRequest(id=2, seq=1, data=b"ping6"),
            Ether()
            / IPv6(src="2001:db8::2", dst="2001:db8::1")
            / IPv6ExtHdrDestOpt()
            / ICMPv6EchoReply(id=2, seq=1, data=b"ping6"),
        ],
    )

    summary = analyze_icmp(capture, show_status=False)

    assert summary.ipv6_packets == 2
    assert len(summary.sessions) == 2
    assert all(session["requests"] == 1 for session in summary.sessions)
    assert all(session["replies"] == 1 for session in summary.sessions)
