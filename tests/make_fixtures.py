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


FIXTURES = {
    "carve_wrap.pcap": build_carve_wrap,
    "carve_gap.pcap": build_carve_gap,
    "dns.pcap": build_dns,
    "http.pcap": build_http,
    "modbus.pcap": build_modbus,
}


def main() -> int:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for name, builder in sorted(FIXTURES.items()):
        target = DATA_DIR / name
        wrpcap(str(target), builder())
        print(f"wrote {target} ({target.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
