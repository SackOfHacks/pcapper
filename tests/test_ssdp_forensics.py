from __future__ import annotations

from scapy.all import Ether, IP, Raw, UDP, wrpcap

from pcapper.ssdp import analyze_ssdp


def _udp_packet(payload: bytes, *, dport: int = 1900):
    return (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=50000, dport=dport)
        / Raw(load=payload)
    )


def test_ssdp_port_alone_does_not_count_arbitrary_datagrams(tmp_path) -> None:
    capture = tmp_path / "udp1900_noise.pcap"
    wrpcap(str(capture), [_udp_packet(b"not an SSDP message")])

    result = analyze_ssdp(capture, show_status=False)

    assert result.ssdp_packets == 0


def test_http_1_0_ssdp_response_is_classified(tmp_path) -> None:
    capture = tmp_path / "ssdp_http10.pcap"
    response = (
        b"HTTP/1.0 200 OK\r\n"
        b"USN: uuid:device-1\r\n"
        b"ST: upnp:rootdevice\r\n\r\n"
    )
    wrpcap(str(capture), [_udp_packet(response, dport=50000)])

    result = analyze_ssdp(capture, show_status=False)

    assert result.ssdp_packets == 1
    assert result.response_count == 1
