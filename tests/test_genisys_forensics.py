from __future__ import annotations

from scapy.all import Ether, IP, Raw, UDP, wrpcap

from pcapper.genisys import _match_signature, analyze_genisys


def test_genisys_signature_includes_control_functions_and_rejects_reserved_codes() -> None:
    assert _match_signature(b"\xfc\x01\x00\xf6")
    assert _match_signature(b"\xfe\x01\x00\xf6")
    assert not _match_signature(b"\xf4\x01\x00\xf6")
    assert not _match_signature(b"\xfc\x01\xf6\x00\xf6")


def test_genisys_control_frame_is_detected_on_nonstandard_port(tmp_path) -> None:
    capture = tmp_path / "genisys_control.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=51820, dport=60000)
            / Raw(load=b"\xfc\x01\x00\xf6"),
        ],
    )

    result = analyze_genisys(capture, show_status=False)

    assert result.protocol_packets == 1
