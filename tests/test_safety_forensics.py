from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from pcapper.safety import analyze_safety


def test_safety_hit_details_are_bounded_without_losing_counts_or_public_alerts(
    tmp_path,
) -> None:
    packets = [
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=51820 + index % 100, dport=1502)
        / Raw(load=b"\x00")
        for index in range(200)
    ]
    packets.append(
        Ether()
        / IP(src="10.0.0.1", dst="8.8.8.8")
        / TCP(sport=51999, dport=1502)
        / Raw(load=b"\x00")
    )
    capture = tmp_path / "safety_many_hits.pcap"
    wrpcap(str(capture), packets)

    result = analyze_safety(capture, show_status=False)

    assert len(result.hits) == 200
    assert result.service_counts["Triconex/TriStation"] == 201
    assert any("detail limit reached" in error for error in result.errors)
    detection = result.detections[0]
    assert detection["severity"] == "high"
    assert "201 packet(s)" in str(detection["details"])
    assert "8.8.8.8" in str(detection["evidence"][0])
