from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from pcapper.opc_classic import UUID_MARKERS, analyze_opc_classic


def test_opc_classic_reports_interface_names_not_spec_versions(tmp_path) -> None:
    client_bind = b"\x05\x00\x0b\x03" + b"\x00" * 4 + UUID_MARKERS[
        "39c13a4d-011e-11d0-9675-0020afd8adb3"
    ]
    server_bind_ack = b"\x05\x00\x0c\x03" + b"\x00" * 4 + UUID_MARKERS[
        "f31dfde2-07b6-11d2-b2d8-0060083ba1fb"
    ]
    capture = tmp_path / "opc_classic.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=51820, dport=135)
            / Raw(load=client_bind),
            Ether()
            / IP(src="10.0.0.2", dst="10.0.0.1")
            / TCP(sport=135, dport=51820)
            / Raw(load=server_bind_ack),
        ],
    )

    result = analyze_opc_classic(capture, show_status=False)

    assert result.opc_packets == 2
    assert result.interface_counts["OPC DA IOPCServer"] == 1
    assert result.interface_counts["OPC Common IOPCCommon"] == 1
    assert result.client_counts["10.0.0.1"] == 2
    assert result.server_counts["10.0.0.2"] == 2
