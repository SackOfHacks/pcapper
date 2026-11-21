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


def _md4(data: bytes) -> bytes:
    """RFC 1320 MD4 (hashlib's "md4" is gone from OpenSSL 3 builds)."""
    import struct

    def f(x, y, z): return (x & y) | (~x & z)
    def g(x, y, z): return (x & y) | (x & z) | (y & z)
    def h(x, y, z): return x ^ y ^ z
    def rol(v, s): return ((v << s) | (v >> (32 - s))) & 0xFFFFFFFF

    msg = data + b"\x80" + b"\x00" * ((55 - len(data)) % 64) + struct.pack("<Q", len(data) * 8)
    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for chunk in range(0, len(msg), 64):
        x = struct.unpack("<16I", msg[chunk:chunk + 64])
        a, b, c, d = a0, b0, c0, d0
        for i in range(16):
            k, s = i, (3, 7, 11, 19)[i % 4]
            a, b, c, d = d, rol((a + f(b, c, d) + x[k]) & 0xFFFFFFFF, s), b, c
        for i in range(16):
            k, s = (i % 4) * 4 + i // 4, (3, 5, 9, 13)[i % 4]
            a, b, c, d = d, rol((a + g(b, c, d) + x[k] + 0x5A827999) & 0xFFFFFFFF, s), b, c
        for i in range(16):
            k, s = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)[i], (3, 9, 11, 15)[i % 4]
            a, b, c, d = d, rol((a + h(b, c, d) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s), b, c
        a0, b0, c0, d0 = [(v + w) & 0xFFFFFFFF for v, w in zip((a0, b0, c0, d0), (a, b, c, d))]
    return struct.pack("<4I", a0, b0, c0, d0)


def test_netntlmv2_hash_line_verifies_with_the_password(tmp_path) -> None:
    """The emitted hashcat -m 5600 line must reproduce the NTProofStr from the
    password. NTLMv2 keys on Uppercase(user) + the domain *as sent*: a short
    NetBIOS domain ("3B") was dropped and longer ones were uppercased, and
    either way the line never cracked."""
    import hashlib
    import hmac
    import struct

    password, user, domain, ws = "Summer2024!", "alice", "lab", "WS01"
    challenge = bytes.fromhex("0123456789abcdef")
    blob = b"\x01\x01\x00\x00\x00\x00\x00\x00" + b"\x11" * 8 + b"\x22" * 8 + b"\x00" * 4 + b"\x00\x00\x00\x00"
    nt_hash = _md4(password.encode("utf-16le"))
    key = hmac.new(nt_hash, (user.upper() + domain).encode("utf-16le"), hashlib.md5).digest()
    proof = hmac.new(key, challenge + blob, hashlib.md5).digest()
    nt_resp = proof + blob

    challenge_msg = _ntlm_message(2)
    challenge_msg[20:24] = (0x00000201).to_bytes(4, "little")  # unicode
    challenge_msg[24:32] = challenge
    fields = [b"\x00" * 24, nt_resp, domain.encode("utf-16le"), user.encode("utf-16le"), ws.encode("utf-16le"), b""]
    auth = bytearray(b"NTLMSSP\x00" + (3).to_bytes(4, "little") + b"\x00" * 52)
    auth[60:64] = (0x00000201).to_bytes(4, "little")
    offset = len(auth)
    payload = b""
    for slot, data in zip((12, 20, 28, 36, 44, 52), fields):
        auth[slot:slot + 8] = struct.pack("<HHI", len(data), len(data), offset + len(payload))
        payload += data
    auth = bytes(auth) + payload

    capture = tmp_path / "ntlmv2.pcap"
    wrpcap(str(capture), [
        Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=445, dport=50000) / Raw(load=bytes(challenge_msg)),
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=445) / Raw(load=auth),
    ])

    result = analyze_ntlm(capture, show_status=False)

    [record] = result.crackable_hashes
    h_user, _, h_domain, h_chal, h_proof, h_blob = record["hash"].split(":")
    assert (h_user, h_domain) == ("alice", "lab")  # the domain as sent, not "LAB"
    key = hmac.new(nt_hash, (h_user.upper() + h_domain).encode("utf-16le"), hashlib.md5).digest()
    assert hmac.new(key, bytes.fromhex(h_chal) + bytes.fromhex(h_blob), hashlib.md5).hexdigest() == h_proof


def test_short_netbios_domain_is_kept() -> None:
    from pcapper.ntlm import _sanitize_ntlm_domain

    assert _sanitize_ntlm_domain("3B") == "3B"
    assert _sanitize_ntlm_domain("A") == "Unknown"
