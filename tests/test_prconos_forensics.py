from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from pcapper.prconos import _detect_anomalies, _parse_commands, analyze_prconos


def test_proconos_cpu_start_and_stop_are_classified_as_mode_changes() -> None:
    start = bytes.fromhex("cc 01 00 04 40 0e 00 00 18 21")
    stop = bytes.fromhex("cc 01 00 01 40 0e 00 00 4c 07")

    assert _parse_commands(start) == ["Request: Start CPU"]
    assert _parse_commands(stop) == ["Request: Stop CPU"]
    assert [
        anomaly.title
        for anomaly in _detect_anomalies(
            start, "10.0.0.1", "10.0.0.2", 1.0, _parse_commands(start)
        )
    ] == ["ProConOS CPU Mode Change"]


def test_proconos_cpu_mode_response_is_not_reported_as_a_request(tmp_path) -> None:
    response = bytes.fromhex("cc 00 00 04 40 0e 00 00 18 21")
    capture = tmp_path / "proconos_response.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.2", dst="10.0.0.1")
            / TCP(sport=20547, dport=51820)
            / Raw(load=response),
        ],
    )

    result = analyze_prconos(capture, show_status=False)

    assert result.protocol_packets == 1
    assert result.commands["Response: Start CPU"] == 1
    assert not any(
        anomaly.title == "ProConOS CPU Mode Change" for anomaly in result.anomalies
    )
