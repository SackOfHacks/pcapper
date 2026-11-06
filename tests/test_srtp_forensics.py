from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from pcapper.srtp import analyze_srtp


def test_srtp_does_not_infer_write_commands_from_raw_payload_text(tmp_path) -> None:
    capture = tmp_path / "srtp_text_false_positive.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=51820, dport=18245)
            / Raw(load=b"write this value"),
        ],
    )

    result = analyze_srtp(capture, show_status=False)

    assert result.protocol_packets == 1
    assert not result.commands
    assert not any(
        anomaly.title == "GE SRTP Write Operation" for anomaly in result.anomalies
    )
