from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, wrpcap

import pcapper.ftp as ftp


def test_ftp_active_mode_parsers_validate_addresses_ports_and_delimiters() -> None:
    assert ftp._parse_port_command("192,0,2,1,7,138") == ("192.0.2.1", 1930)
    assert ftp._parse_port_command("999,0,2,1,7,138") is None
    assert ftp._parse_port_command("192,0,2,1,0,0") is None
    assert ftp._parse_eprt_command("!2!2001:db8::1!1930!") == (
        "2001:db8::1",
        1930,
    )
    assert ftp._parse_eprt_command("|1|2001:db8::1|1930|") is None
    assert ftp._parse_eprt_command("|1|192.0.2.1|0|") is None


def test_ftp_caps_flow_state_and_data_flow_tracking(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(ftp, "MAX_FTP_UNIQUE", 1)
    capture = tmp_path / "ftp_flow_limits.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=51820, dport=21)
            / Raw(load=b"USER first\r\n"),
            Ether()
            / IP(src="10.0.0.3", dst="10.0.0.2")
            / TCP(sport=51821, dport=21)
            / Raw(load=b"USER second\r\n"),
        ],
    )

    result = ftp.analyze_ftp(capture, show_status=False)

    assert result.command_counts["USER"] == 1
    assert any("control-flow state limit" in error for error in result.errors)
    assert any("data-flow tracking limit" in error for error in result.errors)


def test_ftp_transfer_bytes_exclude_tcp_headers_and_empty_ack_packets(tmp_path) -> None:
    capture = tmp_path / "ftp_transfer_bytes.pcap"
    packets = [
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=51820, dport=21)
        / Raw(load=b"PASV\r\n"),
        Ether()
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=21, dport=51820)
        / Raw(load=b"227 Entering Passive Mode (10,0,0,2,195,80)\r\n"),
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=51820, dport=21)
        / Raw(load=b"RETR file.bin\r\n"),
        Ether()
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=21, dport=51820)
        / Raw(load=b"150 Opening data connection\r\n"),
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=51821, dport=50000)
        / Raw(load=b"abc"),
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=51821, dport=50000, flags="A"),
    ]
    wrpcap(str(capture), packets)

    result = ftp.analyze_ftp(capture, show_status=False)

    assert len(result.transfers) == 1
    assert result.transfers[0].bytes == 3
