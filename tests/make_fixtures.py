"""Regenerate the committed capture fixtures under ``tests/data``.

The ``.pcap`` files these tests run against are committed, so the suite needs
nothing but ``pytest`` and pcapper's own dependencies. This script is how they
were produced and how they are reproduced if one needs to change:

    python tests/make_fixtures.py

Everything here is deterministic — fixed addresses, fixed ports, fixed sequence
numbers and fixed packet timestamps — because the golden-output tests compare
rendered reports byte for byte. Do not introduce anything time- or
random-dependent, and regenerate the golden files (``pytest
--regenerate-golden``) after any change.
"""

from __future__ import annotations

import sys
from pathlib import Path

from scapy.all import wrpcap  # type: ignore
from scapy.layers.dns import DNS, DNSQR, DNSRR  # type: ignore
from scapy.layers.inet import IP, TCP, UDP  # type: ignore
from scapy.layers.l2 import Ether  # type: ignore
from scapy.packet import Raw  # type: ignore

DATA_DIR = Path(__file__).parent / "data"

# A fixed, obviously-synthetic base time (2021-01-01T00:00:00Z) so rendered
# reports that include timestamps stay byte-identical between runs.
BASE_TIME = 1609459200.0

CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
CLIENT_IP = "192.168.10.50"
SERVER_IP = "192.168.10.10"
# Deliberately NOT an RFC 5737 documentation range: Python's ipaddress reports
# 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 as private, so pcapper would
# not treat them as internet exposure and the fixture would exercise nothing.
# 93.184.216.34 is globally routable and is the long-standing example.com
# address, so it reads as external without pointing at anyone's live host.
EXTERNAL_IP = "93.184.216.34"

# 2**32 - 8: an initial sequence number high enough that an 8-byte payload wraps
# the 32-bit sequence space. Sorting raw sequence numbers puts the post-wrap
# segments first and mis-assembles the stream; see pcapper.reassembly.
WRAPPING_ISN = (1 << 32) - 8

# A minimal but genuinely-detectable PDF, large enough to survive carving.
PDF_BODY = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
    b"trailer<</Root 1 0 R>>\n"
    b"%%EOF\n"
)


def _stamp(packets: list, start: float = BASE_TIME, step: float = 0.01) -> list:
    """Pin each packet to a fixed timestamp, in order."""
    for index, pkt in enumerate(packets):
        pkt.time = start + index * step
    return packets


def _tcp_stream(
    payloads: list[bytes],
    isn: int,
    sport: int = 44300,
    dport: int = 8080,
    src: str = SERVER_IP,
    dst: str = CLIENT_IP,
    drop: set[int] | None = None,
) -> list:
    """One direction of a TCP conversation carrying ``payloads`` in order.

    ``isn`` is the sequence number of the first payload byte; subsequent
    segments advance modulo 2**32, exactly as a real stack would. Indices listed
    in ``drop`` are advanced over but not emitted, which is how a capture with a
    lost packet — or a capture that missed part of a stream — is simulated.
    """
    drop = drop or set()
    packets = []
    seq = isn
    for index, payload in enumerate(payloads):
        if index not in drop:
            packets.append(
                Ether(src=SERVER_MAC, dst=CLIENT_MAC)
                / IP(src=src, dst=dst)
                / TCP(sport=sport, dport=dport, seq=seq, flags="PA")
                / Raw(load=payload)
            )
        seq = (seq + len(payload)) % (1 << 32)
    return packets


def build_carve_wrap() -> list:
    """A PDF transferred over a stream whose sequence numbers wrap mid-transfer.

    Regression fixture for the carving sequence-wraparound bug: ordering by raw
    32-bit sequence number puts the post-wrap segments at the front, garbling
    the reassembled buffer so the PDF signature is never found and the artifact
    is silently not carved.
    """
    chunks = [PDF_BODY[i : i + 8] for i in range(0, len(PDF_BODY), 8)]
    return _stamp(_tcp_stream(chunks, isn=WRAPPING_ISN))


def build_carve_gap() -> list:
    """The same PDF, with one segment missing from the middle.

    Regression fixture for gap handling: the bytes are absent, so the carved
    blob is a partial reconstruction and its SHA-256 must not be presented as
    the hash of the original file.
    """
    chunks = [PDF_BODY[i : i + 16] for i in range(0, len(PDF_BODY), 16)]
    return _stamp(_tcp_stream(chunks, isn=1000, drop={2}))


def build_dns() -> list:
    """A handful of A lookups, one of them for an external name."""
    queries = [
        ("intranet.corp.example", "192.168.10.20"),
        ("updates.example.net", "203.0.113.80"),
        ("telemetry.example.org", "203.0.113.90"),
    ]
    packets = []
    for index, (name, answer) in enumerate(queries):
        txid = 0x1000 + index
        packets.append(
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src=CLIENT_IP, dst=SERVER_IP)
            / UDP(sport=50000 + index, dport=53)
            / DNS(id=txid, rd=1, qd=DNSQR(qname=name, qtype="A"))
        )
        packets.append(
            Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            / IP(src=SERVER_IP, dst=CLIENT_IP)
            / UDP(sport=53, dport=50000 + index)
            / DNS(
                id=txid,
                qr=1,
                rd=1,
                ra=1,
                qd=DNSQR(qname=name, qtype="A"),
                an=DNSRR(rrname=name, type="A", ttl=300, rdata=answer),
            )
        )
    return _stamp(packets)


def build_http() -> list:
    """A plaintext HTTP exchange, including a Basic-auth header.

    pcapper deliberately does not redact what it recovers, so this fixture
    carries an obviously-fake credential (``analyst:hunter2``) to exercise the
    credential path without putting anything real in the repository.
    """
    request = (
        b"GET /status HTTP/1.1\r\n"
        b"Host: intranet.corp.example\r\n"
        b"User-Agent: pcapper-tests/1.0\r\n"
        b"Authorization: Basic YW5hbHlzdDpodW50ZXIy\r\n"
        b"Accept: */*\r\n"
        b"\r\n"
    )
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: test-httpd/1.0\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: 2\r\n"
        b"\r\n"
        b"ok"
    )
    packets = [
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=EXTERNAL_IP)
        / TCP(sport=44310, dport=80, seq=1, flags="S"),
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=EXTERNAL_IP, dst=CLIENT_IP)
        / TCP(sport=80, dport=44310, seq=1, ack=2, flags="SA"),
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=EXTERNAL_IP)
        / TCP(sport=44310, dport=80, seq=2, ack=2, flags="A"),
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=EXTERNAL_IP)
        / TCP(sport=44310, dport=80, seq=2, ack=2, flags="PA")
        / Raw(load=request),
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=EXTERNAL_IP, dst=CLIENT_IP)
        / TCP(sport=80, dport=44310, seq=2, ack=2 + len(request), flags="PA")
        / Raw(load=response),
    ]
    return _stamp(packets)


def build_modbus() -> list:
    """Modbus/TCP: two reads and a single-coil write from an engineering host.

    The write is what makes this useful as a fixture — a control-plane
    operation is the thing an OT hunt is looking for, and it exercises the
    command-gating path rather than just the port match.
    """

    def frame(tid: int, unit: int, pdu: bytes) -> bytes:
        return (
            tid.to_bytes(2, "big")
            + b"\x00\x00"
            + (len(pdu) + 1).to_bytes(2, "big")
            + bytes([unit])
            + pdu
        )

    exchanges = [
        # function 0x03 read holding registers, addr 0, qty 2
        (frame(1, 1, b"\x03\x00\x00\x00\x02"), frame(1, 1, b"\x03\x04\x00\x0a\x00\x14")),
        # function 0x04 read input registers, addr 16, qty 1
        (frame(2, 1, b"\x04\x00\x10\x00\x01"), frame(2, 1, b"\x04\x02\x00\x64")),
        # function 0x05 write single coil, addr 3, value ON
        (frame(3, 1, b"\x05\x00\x03\xff\x00"), frame(3, 1, b"\x05\x00\x03\xff\x00")),
    ]
    packets = []
    seq_c, seq_s = 1, 1
    for request, response in exchanges:
        packets.append(
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src=CLIENT_IP, dst=SERVER_IP)
            / TCP(sport=44320, dport=502, seq=seq_c, ack=seq_s, flags="PA")
            / Raw(load=request)
        )
        seq_c += len(request)
        packets.append(
            Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            / IP(src=SERVER_IP, dst=CLIENT_IP)
            / TCP(sport=502, dport=44320, seq=seq_s, ack=seq_c, flags="PA")
            / Raw(load=response)
        )
        seq_s += len(response)
    return _stamp(packets)




# --- VoIP -------------------------------------------------------------------
# A synthetic PBX, phone and attacker. Everything is invented: the credentials
# are fake, the "SRTP key" is random base64, and the audio is a generated tone.
PBX_IP = "192.168.10.5"
PHONE_IP = "192.168.10.60"
ATTACKER_IP = "198.18.7.44"
PHONE_MAC = "02:00:00:00:00:03"
PBX_MAC = "02:00:00:00:00:04"

SDP_OFFER = (
    "v=0\r\n"
    f"o=phone 1 1 IN IP4 {PHONE_IP}\r\n"
    "s=call\r\n"
    f"c=IN IP4 {PHONE_IP}\r\n"
    "t=0 0\r\n"
    "m=audio 40000 RTP/AVP 0 101\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:101 telephone-event/8000\r\n"
    "a=fmtp:101 0-15\r\n"
    # SDES keying material in the clear over unencrypted signalling: the whole
    # point of the fixture's "encrypted" call being decryptable.
    "a=crypto:1 AES_CM_128_HMAC_SHA1_80 "
    "inline:PS1uQCVeeCFCanVT9oGZTsLu8HAxLGWMr7dmMLlq\r\n"
    "a=sendrecv\r\n"
)

SDP_ANSWER = (
    "v=0\r\n"
    f"o=pbx 1 1 IN IP4 {PBX_IP}\r\n"
    "s=call\r\n"
    f"c=IN IP4 {PBX_IP}\r\n"
    "t=0 0\r\n"
    "m=audio 40002 RTP/AVP 0 101\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:101 telephone-event/8000\r\n"
    "a=sendrecv\r\n"
)


def _sip(src_ip, dst_ip, sport, dport, text, src_mac=PHONE_MAC, dst_mac=PBX_MAC):
    return (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=sport, dport=dport)
        / Raw(load=text.encode())
    )


def _sip_message(start_line, headers, body=""):
    lines = [start_line]
    lines.extend(f"{name}: {value}" for name, value in headers)
    if body:
        lines.append("Content-Type: application/sdp")
        lines.append(f"Content-Length: {len(body)}")
    else:
        lines.append("Content-Length: 0")
    return "\r\n".join(lines) + "\r\n\r\n" + body


def _rtp(src_ip, dst_ip, sport, dport, seq, timestamp, ssrc, payload, pt=0, marker=False):
    header = bytes(
        [0x80, (0x80 if marker else 0) | pt]
    ) + seq.to_bytes(2, "big") + timestamp.to_bytes(4, "big") + ssrc.to_bytes(4, "big")
    src_mac, dst_mac = (
        (PHONE_MAC, PBX_MAC) if src_ip == PHONE_IP else (PBX_MAC, PHONE_MAC)
    )
    return (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=sport, dport=dport)
        / Raw(load=header + payload)
    )


def _tone_ulaw(count: int, phase: int) -> bytes:
    """A deterministic pseudo-tone encoded as mu-law, so the WAV is not silence."""
    import math

    out = bytearray()
    for index in range(count):
        value = int(60 * math.sin(2 * math.pi * (index + phase) / 20.0))
        out.append((value + 128) & 0xFF)
    return bytes(out)


def build_voip() -> list:
    """A complete SIP call: register, authenticate, invite, media, DTMF, hang up."""
    packets = []
    call_id = "a84b4c76e66710@phone"

    # 1. REGISTER, challenged, then answered with a Digest response.
    packets.append(
        _sip(PHONE_IP, PBX_IP, 5060, 5060, _sip_message(
            "REGISTER sip:pbx.example.com SIP/2.0",
            [
                ("Via", f"SIP/2.0/UDP {PHONE_IP}:5060;branch=z9hG4bKreg1"),
                ("From", "<sip:1001@pbx.example.com>;tag=reg1"),
                ("To", "<sip:1001@pbx.example.com>"),
                ("Call-ID", "reg-1@phone"),
                ("CSeq", "1 REGISTER"),
                ("Contact", f"<sip:1001@{PHONE_IP}:5060>"),
                ("User-Agent", "Grandstream GXP2170 1.0.11.28"),
                ("Expires", "3600"),
            ],
        ))
    )
    packets.append(
        _sip(PBX_IP, PHONE_IP, 5060, 5060, _sip_message(
            "SIP/2.0 401 Unauthorized",
            [
                ("Via", f"SIP/2.0/UDP {PHONE_IP}:5060;branch=z9hG4bKreg1"),
                ("From", "<sip:1001@pbx.example.com>;tag=reg1"),
                ("To", "<sip:1001@pbx.example.com>;tag=pbx1"),
                ("Call-ID", "reg-1@phone"),
                ("CSeq", "1 REGISTER"),
                ("WWW-Authenticate",
                 'Digest realm="asterisk", nonce="6f1e2d3c4b5a", algorithm=MD5, qop="auth"'),
                ("Server", "Asterisk PBX 18.10.0"),
            ],
        ), src_mac=PBX_MAC, dst_mac=PHONE_MAC)
    )
    packets.append(
        _sip(PHONE_IP, PBX_IP, 5060, 5060, _sip_message(
            "REGISTER sip:pbx.example.com SIP/2.0",
            [
                ("Via", f"SIP/2.0/UDP {PHONE_IP}:5060;branch=z9hG4bKreg2"),
                ("From", "<sip:1001@pbx.example.com>;tag=reg1"),
                ("To", "<sip:1001@pbx.example.com>"),
                ("Call-ID", "reg-1@phone"),
                ("CSeq", "2 REGISTER"),
                ("Contact", f"<sip:1001@{PHONE_IP}:5060>"),
                ("User-Agent", "Grandstream GXP2170 1.0.11.28"),
                ("Authorization",
                 'Digest username="1001", realm="asterisk", nonce="6f1e2d3c4b5a", '
                 'uri="sip:pbx.example.com", '
                 'response="7cf1d6f2a9b34e5c8d0a1b2c3d4e5f60", algorithm=MD5, '
                 'cnonce="3a7f9c2e", qop=auth, nc=00000001'),
                ("Expires", "3600"),
            ],
        ))
    )
    packets.append(
        _sip(PBX_IP, PHONE_IP, 5060, 5060, _sip_message(
            "SIP/2.0 200 OK",
            [
                ("Via", f"SIP/2.0/UDP {PHONE_IP}:5060;branch=z9hG4bKreg2"),
                ("From", "<sip:1001@pbx.example.com>;tag=reg1"),
                ("To", "<sip:1001@pbx.example.com>;tag=pbx1"),
                ("Call-ID", "reg-1@phone"),
                ("CSeq", "2 REGISTER"),
                ("Contact", f"<sip:1001@{PHONE_IP}:5060>;expires=3600"),
                ("Server", "Asterisk PBX 18.10.0"),
            ],
        ), src_mac=PBX_MAC, dst_mac=PHONE_MAC)
    )

    # 2. INVITE with SDP, ringing, answered.
    packets.append(
        _sip(PHONE_IP, PBX_IP, 5060, 5060, _sip_message(
            "INVITE sip:441134960000@pbx.example.com SIP/2.0",
            [
                ("Via", f"SIP/2.0/UDP {PHONE_IP}:5060;branch=z9hG4bKinv1"),
                ("From", "<sip:1001@pbx.example.com>;tag=inv1"),
                ("To", "<sip:441134960000@pbx.example.com>"),
                ("Call-ID", call_id),
                ("CSeq", "1 INVITE"),
                ("Contact", f"<sip:1001@{PHONE_IP}:5060>"),
                ("User-Agent", "Grandstream GXP2170 1.0.11.28"),
            ],
            SDP_OFFER,
        ))
    )
    for code, reason in ((100, "Trying"), (180, "Ringing")):
        packets.append(
            _sip(PBX_IP, PHONE_IP, 5060, 5060, _sip_message(
                f"SIP/2.0 {code} {reason}",
                [
                    ("Via", f"SIP/2.0/UDP {PHONE_IP}:5060;branch=z9hG4bKinv1"),
                    ("From", "<sip:1001@pbx.example.com>;tag=inv1"),
                    ("To", "<sip:441134960000@pbx.example.com>;tag=pbx2"),
                    ("Call-ID", call_id),
                    ("CSeq", "1 INVITE"),
                    ("Server", "Asterisk PBX 18.10.0"),
                ],
            ), src_mac=PBX_MAC, dst_mac=PHONE_MAC)
        )
    packets.append(
        _sip(PBX_IP, PHONE_IP, 5060, 5060, _sip_message(
            "SIP/2.0 200 OK",
            [
                ("Via", f"SIP/2.0/UDP {PHONE_IP}:5060;branch=z9hG4bKinv1"),
                ("From", "<sip:1001@pbx.example.com>;tag=inv1"),
                ("To", "<sip:441134960000@pbx.example.com>;tag=pbx2"),
                ("Call-ID", call_id),
                ("CSeq", "1 INVITE"),
                ("Contact", f"<sip:441134960000@{PBX_IP}:5060>"),
                ("Server", "Asterisk PBX 18.10.0"),
            ],
            SDP_ANSWER,
        ), src_mac=PBX_MAC, dst_mac=PHONE_MAC)
    )
    packets.append(
        _sip(PHONE_IP, PBX_IP, 5060, 5060, _sip_message(
            "ACK sip:441134960000@192.168.10.5:5060 SIP/2.0",
            [
                ("Via", f"SIP/2.0/UDP {PHONE_IP}:5060;branch=z9hG4bKack1"),
                ("From", "<sip:1001@pbx.example.com>;tag=inv1"),
                ("To", "<sip:441134960000@pbx.example.com>;tag=pbx2"),
                ("Call-ID", call_id),
                ("CSeq", "1 ACK"),
            ],
        ))
    )

    # 3. Bidirectional G.711 media.
    ssrc_a, ssrc_b = 0x11AA22BB, 0x33CC44DD
    for index in range(30):
        packets.append(
            _rtp(PHONE_IP, PBX_IP, 40000, 40002, 1000 + index, 160 * index,
                 ssrc_a, _tone_ulaw(160, index * 160))
        )
        packets.append(
            _rtp(PBX_IP, PHONE_IP, 40002, 40000, 5000 + index, 160 * index,
                 ssrc_b, _tone_ulaw(160, index * 160 + 7))
        )

    # 4. RFC 4733 DTMF: the caller keys 4-8-2-7 into an IVR.
    seq = 1030
    timestamp = 160 * 30
    for position, digit in enumerate((4, 8, 2, 7)):
        for repeat in range(3):
            payload = bytes([digit, 0x0A if repeat < 2 else 0x8A, 0x01, 0x40])
            packets.append(
                _rtp(PHONE_IP, PBX_IP, 40000, 40002, seq, timestamp,
                     ssrc_a, payload, pt=101, marker=(repeat == 0))
            )
            seq += 1
        timestamp += 800

    # 5. RTCP sender report with an SDES CNAME.
    sdes = b"\x81\xca\x00\x06" + ssrc_a.to_bytes(4, "big") + bytes([1, 18]) + \
        b"1001@192.168.10.60" + b"\x00\x00"
    packets.append(
        Ether(src=PHONE_MAC, dst=PBX_MAC)
        / IP(src=PHONE_IP, dst=PBX_IP)
        / UDP(sport=40001, dport=40003)
        / Raw(load=sdes)
    )

    # 6. Hang up.
    packets.append(
        _sip(PHONE_IP, PBX_IP, 5060, 5060, _sip_message(
            "BYE sip:441134960000@192.168.10.5:5060 SIP/2.0",
            [
                ("Via", f"SIP/2.0/UDP {PHONE_IP}:5060;branch=z9hG4bKbye1"),
                ("From", "<sip:1001@pbx.example.com>;tag=inv1"),
                ("To", "<sip:441134960000@pbx.example.com>;tag=pbx2"),
                ("Call-ID", call_id),
                ("CSeq", "2 BYE"),
            ],
        ))
    )
    packets.append(
        _sip(PBX_IP, PHONE_IP, 5060, 5060, _sip_message(
            "SIP/2.0 200 OK",
            [
                ("Via", f"SIP/2.0/UDP {PHONE_IP}:5060;branch=z9hG4bKbye1"),
                ("From", "<sip:1001@pbx.example.com>;tag=inv1"),
                ("To", "<sip:441134960000@pbx.example.com>;tag=pbx2"),
                ("Call-ID", call_id),
                ("CSeq", "2 BYE"),
            ],
        ), src_mac=PBX_MAC, dst_mac=PHONE_MAC)
    )

    # 7. The phone fetches its configuration over TFTP, unauthenticated.
    packets.append(
        Ether(src=PHONE_MAC, dst=PBX_MAC)
        / IP(src=PHONE_IP, dst=PBX_IP)
        / UDP(sport=52000, dport=69)
        / Raw(load=b"\x00\x01SEP020000000003.cnf.xml\x00octet\x00")
    )

    return _stamp(packets, step=0.02)


def build_voip_multiproto() -> list:
    """The same site's other call control: Skinny, MGCP, IAX2 and H.225."""
    packets = []

    def _tcp(src_ip, dst_ip, sport, dport, payload, seq=1):
        src_mac, dst_mac = (
            (PHONE_MAC, PBX_MAC) if src_ip == PHONE_IP else (PBX_MAC, PHONE_MAC)
        )
        return (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=sport, dport=dport, seq=seq, flags="PA")
            / Raw(load=payload)
        )

    def _skinny(message_id: int, body: bytes) -> bytes:
        return (
            (len(body) + 4).to_bytes(4, "little")
            + b"\x00\x00\x00\x00"
            + message_id.to_bytes(4, "little")
            + body
        )

    # Cisco Skinny: the handset registers, then keys 9-1-1-2-3.
    register_body = b"SEP020000000003".ljust(16, b"\x00") + b"\x00" * 8
    packets.append(_tcp(PHONE_IP, PBX_IP, 50100, 2000, _skinny(0x0001, register_body)))
    packets.append(_tcp(PBX_IP, PHONE_IP, 2000, 50100, _skinny(0x0081, b"\x00" * 8), seq=1))
    seq = len(_skinny(0x0001, register_body)) + 1
    for digit in (9, 1, 1, 2, 3):
        packets.append(
            _tcp(PHONE_IP, PBX_IP, 50100, 2000,
                 _skinny(0x0003, digit.to_bytes(4, "little") + b"\x00" * 8), seq=seq)
        )
        seq += len(_skinny(0x0003, b"\x00" * 12))

    # MGCP: the gateway notifies the call agent of collected digits.
    mgcp_ntfy = (
        "NTFY 1201 aaln/1@gw1.example.com MGCP 1.0\r\n"
        "N: ca@192.168.10.5:2727\r\n"
        "X: 3f2504e0\r\n"
        "O: D/5,D/5,D/5,D/1,D/2,D/1,D/2\r\n"
    )
    packets.append(
        Ether(src=PBX_MAC, dst=PHONE_MAC)
        / IP(src="192.168.10.7", dst=PBX_IP)
        / UDP(sport=2427, dport=2727)
        / Raw(load=mgcp_ntfy.encode())
    )
    packets.append(
        Ether(src=PBX_MAC, dst=PHONE_MAC)
        / IP(src=PBX_IP, dst="192.168.10.7")
        / UDP(sport=2727, dport=2427)
        / Raw(load=b"200 1201 OK\r\n")
    )

    # IAX2: an Asterisk trunk authenticates with an MD5 challenge/response.
    def _iax_full(src_call, dst_call, subclass, ies=b"", oseq=0, iseq=1):
        """A 12-byte IAX2 full-frame header: srccall, dstcall, timestamp,
        OSeqno, ISeqno, frametype, subclass — then the information elements."""
        return (
            (0x8000 | src_call).to_bytes(2, "big")
            + dst_call.to_bytes(2, "big")
            + (0).to_bytes(4, "big")
            + bytes([oseq, iseq, 0x06, subclass])
            + ies
        )

    def _ie(ident, value: bytes) -> bytes:
        return bytes([ident, len(value)]) + value

    new_ies = (
        _ie(0x06, b"trunk1") + _ie(0x02, b"1001") + _ie(0x01, b"442079460000")
    )
    packets.append(
        Ether(src=PBX_MAC, dst=PHONE_MAC)
        / IP(src=PBX_IP, dst="192.168.10.8")
        / UDP(sport=4569, dport=4569)
        / Raw(load=_iax_full(1, 0, 0x01, new_ies))
    )
    packets.append(
        Ether(src=PHONE_MAC, dst=PBX_MAC)
        / IP(src="192.168.10.8", dst=PBX_IP)
        / UDP(sport=4569, dport=4569)
        / Raw(load=_iax_full(2, 1, 0x08, _ie(0x0F, b"\x00\x02") + _ie(0x10, b"483920175")))
    )
    packets.append(
        Ether(src=PBX_MAC, dst=PHONE_MAC)
        / IP(src=PBX_IP, dst="192.168.10.8")
        / UDP(sport=4569, dport=4569)
        / Raw(load=_iax_full(1, 2, 0x09,
                             _ie(0x06, b"trunk1")
                             + _ie(0x11, b"5f4dcc3b5aa765d61d8327deb882cf99")))
    )

    # H.323: a Q.931 SETUP inside TPKT on 1720.
    q931_setup = (
        b"\x08\x02\x12\x34\x05"
        + b"\x04\x03\x80\x90\xa3"
        + b"\x6c\x06\x21\x83" + b"1001"
        + b"\x70\x0d\x80" + b"442079460000"
    )
    tpkt = b"\x03\x00" + (len(q931_setup) + 4).to_bytes(2, "big") + q931_setup
    packets.append(_tcp(PHONE_IP, PBX_IP, 50200, 1720, tpkt))

    return _stamp(packets, start=BASE_TIME + 100, step=0.02)


def build_voip_attack() -> list:
    """An internet-facing PBX being enumerated and brute-forced."""
    packets = []
    for index in range(24):
        extension = 1000 + index
        packets.append(
            _sip(ATTACKER_IP, PBX_IP, 5061 + index, 5060, _sip_message(
                f"OPTIONS sip:{extension}@{PBX_IP} SIP/2.0",
                [
                    ("Via", f"SIP/2.0/UDP {ATTACKER_IP}:5061;branch=z9hG4bKsc{index}"),
                    ("From", f'"sipvicious" <sip:100@1.1.1.1>;tag=sc{index}'),
                    ("To", f"<sip:{extension}@{PBX_IP}>"),
                    ("Call-ID", f"scan-{index}@attacker"),
                    ("CSeq", "1 OPTIONS"),
                    ("User-Agent", "friendly-scanner"),
                ],
            ), src_mac=PBX_MAC, dst_mac=PHONE_MAC)
        )
        packets.append(
            _sip(PBX_IP, ATTACKER_IP, 5060, 5061 + index, _sip_message(
                "SIP/2.0 404 Not Found",
                [
                    ("Via", f"SIP/2.0/UDP {ATTACKER_IP}:5061;branch=z9hG4bKsc{index}"),
                    ("From", f'"sipvicious" <sip:100@1.1.1.1>;tag=sc{index}'),
                    ("To", f"<sip:{extension}@{PBX_IP}>;tag=pbx"),
                    ("Call-ID", f"scan-{index}@attacker"),
                    ("CSeq", "1 OPTIONS"),
                    ("Server", "Asterisk PBX 18.10.0"),
                ],
            ), src_mac=PBX_MAC, dst_mac=PHONE_MAC)
        )

    # Registration brute force against one discovered extension.
    for index in range(14):
        packets.append(
            _sip(ATTACKER_IP, PBX_IP, 5200, 5060, _sip_message(
                "REGISTER sip:pbx.example.com SIP/2.0",
                [
                    ("Via", f"SIP/2.0/UDP {ATTACKER_IP}:5200;branch=z9hG4bKbf{index}"),
                    ("From", "<sip:1001@pbx.example.com>;tag=bf"),
                    ("To", "<sip:1001@pbx.example.com>"),
                    ("Call-ID", f"brute-{index}@attacker"),
                    ("CSeq", f"{index} REGISTER"),
                    ("User-Agent", "friendly-scanner"),
                    ("Authorization",
                     'Digest username="1001", realm="asterisk", nonce="6f1e2d3c4b5a", '
                     'uri="sip:pbx.example.com", '
                     f'response="{index:032x}", algorithm=MD5'),
                ],
            ), src_mac=PBX_MAC, dst_mac=PHONE_MAC)
        )
        packets.append(
            _sip(PBX_IP, ATTACKER_IP, 5060, 5200, _sip_message(
                "SIP/2.0 403 Forbidden",
                [
                    ("Via", f"SIP/2.0/UDP {ATTACKER_IP}:5200;branch=z9hG4bKbf{index}"),
                    ("From", "<sip:1001@pbx.example.com>;tag=bf"),
                    ("To", "<sip:1001@pbx.example.com>;tag=pbx"),
                    ("Call-ID", f"brute-{index}@attacker"),
                    ("CSeq", f"{index} REGISTER"),
                    ("Server", "Asterisk PBX 18.10.0"),
                ],
            ), src_mac=PBX_MAC, dst_mac=PHONE_MAC)
        )

    return _stamp(packets, start=BASE_TIME + 200, step=0.01)


# --- Mixed IT traffic ---------------------------------------------------------
# One small capture that touches the analyzers the other fixtures leave empty:
# VLAN tags, ICMPv4 and ICMPv6, ARP, DHCP, NTP, SNMP, a TCP retransmission and
# an HTTP download of a (fake, inert) PE. Everything is fixed and synthetic.
ROUTER_MAC = "02:00:00:00:00:fe"
ROUTER_IP = "192.168.10.1"
CLIENT_IP6 = "fd00:10::50"
SERVER_IP6 = "fd00:10::10"


def _fake_pe(section_bytes: int = 600) -> bytes:
    """A minimal PE: MZ stub, e_lfanew -> "PE\\0\\0", one section whose raw
    data ends the file. Not executable — the section body is 0xCC filler."""
    lfanew = 0x80
    image = bytearray(b"MZ" + b"\x00" * (lfanew - 2))
    image[0x3C:0x40] = lfanew.to_bytes(4, "little")
    coff = b"PE\x00\x00" + b"\x4c\x01" + (1).to_bytes(2, "little") + b"\x00" * 12
    opt_size = 0xE0
    coff += opt_size.to_bytes(2, "little") + b"\x00" * 2
    image += coff + b"\x00" * opt_size
    raw_ptr = len(image) + 40
    section = bytearray(40)
    section[0:6] = b".text\x00"
    section[16:20] = section_bytes.to_bytes(4, "little")
    section[20:24] = raw_ptr.to_bytes(4, "little")
    image += section
    image += bytes((i * 37) & 0xFF for i in range(section_bytes))
    return bytes(image)


def build_mixed() -> list:
    from scapy.layers.dhcp import BOOTP, DHCP  # type: ignore
    from scapy.layers.inet import ICMP  # type: ignore
    from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest, IPv6  # type: ignore
    from scapy.layers.l2 import ARP, Dot1Q  # type: ignore
    from scapy.layers.ntp import NTP  # type: ignore
    from scapy.layers.snmp import SNMP, SNMPget, SNMPvarbind  # type: ignore

    packets = []

    # ARP: who-has / is-at, then a gratuitous announcement from the router.
    packets.append(
        Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc=CLIENT_MAC, psrc=CLIENT_IP, hwdst="00:00:00:00:00:00", pdst=SERVER_IP)
    )
    packets.append(
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / ARP(op=2, hwsrc=SERVER_MAC, psrc=SERVER_IP, hwdst=CLIENT_MAC, pdst=CLIENT_IP)
    )
    packets.append(
        Ether(src=ROUTER_MAC, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2, hwsrc=ROUTER_MAC, psrc=ROUTER_IP, hwdst="ff:ff:ff:ff:ff:ff", pdst=ROUTER_IP)
    )

    # VLAN-tagged ICMPv4 echo pairs on VLAN 10.
    for seq in range(3):
        packets.append(
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / Dot1Q(vlan=10)
            / IP(src=CLIENT_IP, dst=SERVER_IP)
            / ICMP(type=8, id=0x1234, seq=seq)
            / Raw(load=bytes(range(56)))
        )
        packets.append(
            Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            / Dot1Q(vlan=10)
            / IP(src=SERVER_IP, dst=CLIENT_IP)
            / ICMP(type=0, id=0x1234, seq=seq)
            / Raw(load=bytes(range(56)))
        )
    # One oversized echo to an external host: boundary crossing + large payload.
    packets.append(
        Ether(src=CLIENT_MAC, dst=ROUTER_MAC)
        / IP(src=CLIENT_IP, dst=EXTERNAL_IP)
        / ICMP(type=8, id=0x4242, seq=1)
        / Raw(load=bytes((i * 131 + 7) & 0xFF for i in range(1400)))
    )

    # ICMPv6 echo pair.
    packets.append(
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IPv6(src=CLIENT_IP6, dst=SERVER_IP6)
        / ICMPv6EchoRequest(id=0x77, seq=1, data=b"ping6")
    )
    packets.append(
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IPv6(src=SERVER_IP6, dst=CLIENT_IP6)
        / ICMPv6EchoReply(id=0x77, seq=1, data=b"ping6")
    )

    # DHCP discover / offer.
    chaddr = bytes.fromhex(CLIENT_MAC.replace(":", ""))
    packets.append(
        Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=chaddr, xid=0x0BADF00D, flags=0x8000)
        / DHCP(options=[("message-type", "discover"), ("hostname", b"ws-analyst"), "end"])
    )
    packets.append(
        Ether(src=ROUTER_MAC, dst=CLIENT_MAC)
        / IP(src=ROUTER_IP, dst=CLIENT_IP)
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, yiaddr=CLIENT_IP, siaddr=ROUTER_IP, chaddr=chaddr, xid=0x0BADF00D)
        / DHCP(options=[("message-type", "offer"), ("server_id", ROUTER_IP),
                        ("lease_time", 86400), ("subnet_mask", "255.255.255.0"),
                        ("router", ROUTER_IP), ("name_server", SERVER_IP), "end"])
    )

    # NTP request (mode 3) and reply (mode 4). scapy fills an unset NTP
    # timestamp field with time.time() at build, so every stamp is pinned.
    ntp_stamps = {"ref": BASE_TIME, "orig": BASE_TIME, "recv": BASE_TIME, "sent": BASE_TIME}
    packets.append(
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / UDP(sport=123, dport=123)
        / NTP(mode=3, version=4, **ntp_stamps)
    )
    packets.append(
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP)
        / UDP(sport=123, dport=123)
        / NTP(mode=4, version=4, stratum=2, **ntp_stamps)
    )

    # SNMPv2c get with the default community — the classic finding.
    packets.append(
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / UDP(sport=50100, dport=161)
        / SNMP(version=1, community="public",
               PDU=SNMPget(id=7, varbindlist=[SNMPvarbind(oid="1.3.6.1.2.1.1.1.0")]))
    )

    # TCP: handshake, a data segment, the same segment retransmitted, then a
    # download of the fake PE over HTTP.
    request = b"GET /update.exe HTTP/1.1\r\nHost: updates.example.net\r\n\r\n"
    pe = _fake_pe()
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: test-httpd/1.0\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=\"update.exe\"\r\n"
        + f"Content-Length: {len(pe)}\r\n\r\n".encode()
        + pe
    )
    c, s = 5000, 9000
    flow = [
        Ether(src=CLIENT_MAC, dst=ROUTER_MAC) / IP(src=CLIENT_IP, dst=EXTERNAL_IP)
        / TCP(sport=44400, dport=80, seq=c, flags="S"),
        Ether(src=ROUTER_MAC, dst=CLIENT_MAC) / IP(src=EXTERNAL_IP, dst=CLIENT_IP)
        / TCP(sport=80, dport=44400, seq=s, ack=c + 1, flags="SA"),
        Ether(src=CLIENT_MAC, dst=ROUTER_MAC) / IP(src=CLIENT_IP, dst=EXTERNAL_IP)
        / TCP(sport=44400, dport=80, seq=c + 1, ack=s + 1, flags="A"),
        Ether(src=CLIENT_MAC, dst=ROUTER_MAC) / IP(src=CLIENT_IP, dst=EXTERNAL_IP)
        / TCP(sport=44400, dport=80, seq=c + 1, ack=s + 1, flags="PA") / Raw(load=request),
        # retransmission of the request: same seq, same payload
        Ether(src=CLIENT_MAC, dst=ROUTER_MAC) / IP(src=CLIENT_IP, dst=EXTERNAL_IP)
        / TCP(sport=44400, dport=80, seq=c + 1, ack=s + 1, flags="PA") / Raw(load=request),
    ]
    seq = s + 1
    for i in range(0, len(response), 400):
        chunk = response[i : i + 400]
        flow.append(
            Ether(src=ROUTER_MAC, dst=CLIENT_MAC) / IP(src=EXTERNAL_IP, dst=CLIENT_IP)
            / TCP(sport=80, dport=44400, seq=seq, ack=c + 1 + len(request), flags="PA")
            / Raw(load=chunk)
        )
        seq += len(chunk)
    packets.extend(flow)
    return _stamp(packets, start=BASE_TIME + 300, step=0.05)


def build_truncated() -> list:
    """The HTTP exchange written as if captured with a 96-byte snaplen.

    scapy's pcap writer records ``pkt.wirelen`` as the original length, so
    the file's headers say each frame was longer than the bytes stored —
    exactly what a snaplen-limited capture looks like to a reader.
    """
    packets = []
    for pkt in build_http():
        full = bytes(pkt)
        cut = full[:96]
        truncated = Ether(cut)
        truncated.time = pkt.time
        truncated.wirelen = len(full)
        packets.append(truncated)
    return packets


def _tls_record(content_type: int, body: bytes, version: int = 0x0303) -> bytes:
    return bytes([content_type]) + version.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body


def _tls_handshake(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + len(body).to_bytes(3, "big") + body


def _tls_ext(ext_type: int, data: bytes) -> bytes:
    return ext_type.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data


def _tls_u16_vector(values: list[int]) -> bytes:
    body = b"".join(value.to_bytes(2, "big") for value in values)
    return len(body).to_bytes(2, "big") + body


def _tls_random(seed: int) -> bytes:
    """32 fixed bytes standing in for the handshake random."""
    return bytes((seed * 37 + index * 11) & 0xFF for index in range(32))


def _client_hello(
    *,
    sni: str | None,
    alpn: list[str],
    ciphers: list[int],
    versions: list[int],
    seed: int,
) -> bytes:
    exts = []
    if sni:
        name = sni.encode("ascii")
        entry = b"\x00" + len(name).to_bytes(2, "big") + name
        exts.append(_tls_ext(0x0000, len(entry).to_bytes(2, "big") + entry))
    exts.append(_tls_ext(0x000A, _tls_u16_vector([0x001D, 0x0017])))  # groups
    exts.append(_tls_ext(0x000B, b"\x01\x00"))  # ec_point_formats
    exts.append(_tls_ext(0x000D, _tls_u16_vector([0x0403, 0x0804])))  # sig_algs
    if alpn:
        protos = b"".join(bytes([len(proto)]) + proto.encode("ascii") for proto in alpn)
        exts.append(_tls_ext(0x0010, len(protos).to_bytes(2, "big") + protos))
    if versions:
        listed = b"".join(version.to_bytes(2, "big") for version in versions)
        exts.append(_tls_ext(0x002B, bytes([len(listed)]) + listed))
    ext_blob = b"".join(exts)
    body = (
        b"\x03\x03"
        + _tls_random(seed)
        + b"\x00"  # empty session id
        + _tls_u16_vector(ciphers)
        + b"\x01\x00"  # null compression only
        + len(ext_blob).to_bytes(2, "big")
        + ext_blob
    )
    return _tls_record(22, _tls_handshake(1, body), version=0x0301)


def _server_hello(*, version: int, cipher: int, alpn: str | None, seed: int) -> bytes:
    exts = []
    if alpn:
        proto = bytes([len(alpn)]) + alpn.encode("ascii")
        exts.append(_tls_ext(0x0010, len(proto).to_bytes(2, "big") + proto))
    ext_blob = b"".join(exts)
    body = version.to_bytes(2, "big") + _tls_random(seed) + b"\x00" + cipher.to_bytes(2, "big") + b"\x00"
    if ext_blob:
        body += len(ext_blob).to_bytes(2, "big") + ext_blob
    return _tls_record(22, _tls_handshake(2, body), version=version)


def _certificate_record(der: bytes) -> bytes:
    entry = len(der).to_bytes(3, "big") + der
    return _tls_record(22, _tls_handshake(11, len(entry).to_bytes(3, "big") + entry))


def _fixture_certificate() -> bytes:
    """A self-signed, already-expired Ed25519 leaf for shop.example.net.

    Ed25519 is used because both the key (derived from fixed bytes) and the
    signature are deterministic, so the DER — and therefore the fixture and
    the fingerprints in the golden reports — never changes on regeneration.
    """
    from datetime import datetime, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "shop.example.net"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "pcapper fixtures"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x1001)
        .not_valid_before(datetime(2021, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2022, 1, 1, tzinfo=timezone.utc))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("shop.example.net")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, None)
    )
    return cert.public_bytes(Encoding.DER)


def build_tls() -> list:
    """Three TLS conversations covering the handshake shapes the analyzer keys on.

    * ``:443`` — ClientHello with SNI ``shop.example.net``, ALPN h2 + http/1.1
      and supported_versions; the server picks TLS 1.2 / ECDHE-RSA-AES128-GCM
      and sends a self-signed, expired Ed25519 certificate in the clear, then
      application data flows both ways.
    * ``EXTERNAL_IP:8443`` (twice) — SNI ``cdn-update.xyz``, no ALPN, and a
      server answering TLS 1.0 with 3DES: legacy version, weak cipher,
      suspicious TLD and a non-standard port in one flow.
    * ``:443`` — a ClientHello with no SNI at all.
    """
    der = _fixture_certificate()
    packets: list = []

    def _flow(sport: int, dst: str, dport: int, client: list[bytes], server: list[bytes]) -> None:
        c_seq, s_seq = 1, 1
        for index in range(max(len(client), len(server))):
            if index < len(client):
                packets.append(
                    Ether(src=CLIENT_MAC, dst=SERVER_MAC)
                    / IP(src=CLIENT_IP, dst=dst)
                    / TCP(sport=sport, dport=dport, seq=c_seq, ack=s_seq, flags="PA")
                    / Raw(load=client[index])
                )
                c_seq += len(client[index])
            if index < len(server):
                packets.append(
                    Ether(src=SERVER_MAC, dst=CLIENT_MAC)
                    / IP(src=dst, dst=CLIENT_IP)
                    / TCP(sport=dport, dport=sport, seq=s_seq, ack=c_seq, flags="PA")
                    / Raw(load=server[index])
                )
                s_seq += len(server[index])

    app_data = _tls_record(23, bytes(64))
    _flow(
        44330,
        SERVER_IP,
        443,
        [
            _client_hello(
                sni="shop.example.net",
                alpn=["h2", "http/1.1"],
                ciphers=[0x1301, 0x1302, 0xC02B, 0xC02F],
                versions=[0x0304, 0x0303],
                seed=1,
            ),
            app_data,
            app_data,
        ],
        [
            _server_hello(version=0x0303, cipher=0xC02F, alpn="h2", seed=2),
            _certificate_record(der),
            app_data,
        ],
    )
    for sport in (44331, 44332):
        _flow(
            sport,
            EXTERNAL_IP,
            8443,
            [_client_hello(sni="cdn-update.xyz", alpn=[], ciphers=[0x000A, 0x0004, 0xC02F], versions=[], seed=3)],
            [_server_hello(version=0x0301, cipher=0x000A, alpn=None, seed=4)],
        )
    _flow(
        44333,
        SERVER_IP,
        443,
        [_client_hello(sni=None, alpn=["http/1.1"], ciphers=[0xC02F], versions=[0x0303], seed=5)],
        [_server_hello(version=0x0303, cipher=0xC02F, alpn="http/1.1", seed=6)],
    )
    return _stamp(packets, start=BASE_TIME + 600, step=0.05)


SMB_CLIENT_GUID = bytes(range(0x10, 0x20))
SMB_SERVER_GUID = bytes(range(0xA0, 0xB0))
SMB_FILE_ID = bytes(range(0x30, 0x40))


FIXTURES = {
    "carve_wrap.pcap": build_carve_wrap,
    "carve_gap.pcap": build_carve_gap,
    "dns.pcap": build_dns,
    "http.pcap": build_http,
    "modbus.pcap": build_modbus,
    "voip.pcap": build_voip,
    "voip_multiproto.pcap": build_voip_multiproto,
    "voip_attack.pcap": build_voip_attack,
    "mixed.pcap": build_mixed,
    "truncated.pcap": build_truncated,
    "tls.pcap": build_tls,
}

# Written with the pcapng writer so the pcapng reader/metadata path is
# exercised by a fixture too.
PCAPNG_FIXTURES = {
    "mixed.pcapng": build_mixed,
}


def _write_pcapng(target: Path, packets: list) -> None:
    from scapy.utils import PcapNgWriter  # type: ignore

    with PcapNgWriter(str(target)) as writer:
        for pkt in packets:
            writer.write(pkt)


def main() -> int:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for name, builder in sorted(FIXTURES.items()):
        target = DATA_DIR / name
        wrpcap(str(target), builder())
        print(f"wrote {target} ({target.stat().st_size} bytes)")
    for name, builder in sorted(PCAPNG_FIXTURES.items()):
        target = DATA_DIR / name
        _write_pcapng(target, builder())
        print(f"wrote {target} ({target.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
