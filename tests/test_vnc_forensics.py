from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from pcapper.vnc import _parse_rfb_security_types, _parse_rfb_version, analyze_vnc


def test_offered_none_auth_is_not_reported_when_client_selects_vnc_auth(
    tmp_path,
) -> None:
    capture = tmp_path / "vnc_security_selection.pcap"
    server, client = "10.0.0.2", "10.0.0.1"
    server_port, client_port = 5900, 50000
    version = b"RFB 003.008\n"
    packets = [
        Ether() / IP(src=server, dst=client) / TCP(sport=server_port, dport=client_port) / Raw(load=version),
        Ether() / IP(src=client, dst=server) / TCP(sport=client_port, dport=server_port) / Raw(load=version),
        Ether() / IP(src=server, dst=client) / TCP(sport=server_port, dport=client_port) / Raw(load=b"\x02\x01\x02"),
        Ether() / IP(src=client, dst=server) / TCP(sport=client_port, dport=server_port) / Raw(load=b"\x02"),
    ]
    wrpcap(str(capture), packets)

    summary = analyze_vnc(capture, show_status=False)

    assert summary.auth_types == {"VNC Authentication (DES challenge-response)": 1}
    assert not any("NO authentication" in d["summary"] for d in summary.detections)


def test_rfb_security_type_count_uses_full_one_byte_range() -> None:
    assert len(_parse_rfb_security_types(bytes([14, *range(1, 15)]), (3, 8))) == 14
    assert _parse_rfb_version(b"RFB 003.008X") is None
