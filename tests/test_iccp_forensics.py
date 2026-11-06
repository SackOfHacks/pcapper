from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from pcapper.iccp import _detect_anomalies, _parse_commands, analyze_iccp


_MMS_WRITE = bytes.fromhex(
    "01000100611d301b020103a016a014020100a50fa0083006a00480026d75a003850100"
)


def test_iccp_requires_both_tase2_marker_and_structural_mms_write() -> None:
    payload = _MMS_WRITE + b" TASE2_Version Operate"

    commands = _parse_commands(payload)

    assert "ICCP/TASE.2" in commands
    assert "MMS Write" in commands
    findings = _detect_anomalies(payload, "10.0.0.1", "10.0.0.2", 1.0, commands)
    assert [finding.title for finding in findings] == ["ICCP/TASE.2 Control Command"]


def test_raw_a5_byte_is_not_treated_as_an_mms_write() -> None:
    payload = b"TASE2_Version" + b"\xa5" + b" Operate"

    commands = _parse_commands(payload)

    assert "ICCP/TASE.2" in commands
    assert "MMS Write" not in commands
    assert _detect_anomalies(payload, "10.0.0.1", "10.0.0.2", 1.0, commands) == []


def test_iccp_analyzer_ignores_non_tase2_traffic_on_mms_port(tmp_path) -> None:
    capture = tmp_path / "non_iccp_mms.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="8.8.8.8")
            / TCP(sport=51820, dport=102)
            / Raw(load=b"\x03\x00\x00\x07\x02\xf0\x80"),
        ],
    )

    result = analyze_iccp(capture, show_status=False)

    assert result.protocol_packets == 0
    assert result.anomalies == []
