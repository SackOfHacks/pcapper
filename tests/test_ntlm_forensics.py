from __future__ import annotations

import base64

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from pcapper.ntlm import _extract_http_ntlm, analyze_ntlm


def _ntlm_message(message_type: int, size: int = 48) -> bytearray:
    message = bytearray(b"NTLMSSP\x00" + message_type.to_bytes(4, "little"))
    message.extend(b"\x00" * (size - len(message)))
    return message


def test_ntlm_capability_flag_does_not_count_as_ntlmv1(tmp_path) -> None:
    capture = tmp_path / "ntlm_capability.pcap"
    negotiate = _ntlm_message(1)
    negotiate[12:16] = (0x00000200).to_bytes(4, "little")
    challenge = _ntlm_message(2)
    challenge[20:24] = (0x00000200).to_bytes(4, "little")
    packets = [
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=50000, dport=445)
        / Raw(load=negotiate),
        Ether()
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=445, dport=50000)
        / Raw(load=challenge),
    ]
    wrpcap(str(capture), packets)

    result = analyze_ntlm(capture, show_status=False)

    assert not result.versions["NTLMv1"]
    assert not result.anomalies


def test_http_ntlm_header_and_scheme_are_case_insensitive() -> None:
    token = b"NTLMSSP\x00\x01\x00\x00\x00"
    header = b"authorization:\tntlm " + base64.b64encode(token) + b"\r\n"

    assert _extract_http_ntlm(header) == token
    assert _extract_http_ntlm(b"Authorization: NTLM ****\r\n") is None
