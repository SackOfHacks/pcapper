"""The credential, HTTP, telnet, NFS and AIM analyses read lite records from
disk and dissect only the packets they look at: their results must equal the
ones computed over scapy packets (in memory), record for record."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

pytest.importorskip("scapy")

from scapy.all import (  # noqa: E402
    ICMP,
    IP,
    LLC,
    SNAP,
    STP,
    TCP,
    UDP,
    Dot1Q,
    Dot3,
    Ether,
    IPOption_RR,
    IPv6,
    Raw,
    wrpcap,
)

from pcapper import creds, pcap_cache, telnet, utils  # noqa: E402
from pcapper.aim import analyze_aim  # noqa: E402
from pcapper.creds import analyze_creds  # noqa: E402
from pcapper.http import analyze_http  # noqa: E402
from pcapper.lite import UNSUPPORTED, LitePacket  # noqa: E402
from pcapper.nfs import analyze_nfs  # noqa: E402
from pcapper.telnet import analyze_telnet  # noqa: E402

DATA = Path(__file__).parent / "data"

A, B = "10.0.0.1", "10.0.0.2"


def _frames() -> list:
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    frames = [
        # A bare SYN padded to 60 bytes: no Raw layer, but padding behind TCP.
        eth / IP(src=A, dst=B) / TCP(sport=40000, dport=80, flags="S"),
        eth / IP(src=A, dst=B) / TCP(sport=40000, dport=80) / Raw(b"GET /login?user=bob&password=hunter2 HTTP/1.1\r\nHost: x\r\n\r\n"),
        eth / IP(src=A, dst=B) / TCP(sport=40001, dport=8081) / Raw(b"POST /a HTTP/1.1\r\nAuthorization: Basic Ym9iOnNlY3JldA==\r\n\r\n"),
        eth / IP(src=B, dst=A) / TCP(sport=80, dport=40000) / Raw(b"HTTP/1.1 200 OK\r\n\r\nusername=x"),
        # A short payload padded with non-zero bytes after the IP length.
        eth / IP(src=A, dst=B) / TCP(sport=40002, dport=21) / Raw(b"USER a\r\n"),
        eth / IP(src=A, dst=B) / TCP(sport=40002, dport=21) / Raw(b"PASS b\r\n"),
        # Telnet on its port, and option negotiation on another one.
        eth / IP(src=A, dst=B) / TCP(sport=40003, dport=23) / Raw(b"login: "),
        eth / IP(src=B, dst=A) / TCP(sport=40004, dport=4444) / Raw(b"\xff\xfb\x01\xff\xfd\x03"),
        eth / IP(src=A, dst=B) / TCP(sport=40005, dport=4445) / Raw(b"\xff"),
        # VLAN-tagged, IPv6 and IP-options TCP.
        eth / Dot1Q(vlan=5) / IP(src=A, dst=B) / TCP(sport=40006, dport=110) / Raw(b"USER v\r\nPASS w\r\n"),
        eth / IPv6(src="fe80::1", dst="fe80::2") / TCP(sport=40007, dport=143) / Raw(b"a1 LOGIN u p\r\n"),
        eth / IP(src=A, dst=B, options=[IPOption_RR()]) / TCP(sport=40008, dport=80) / Raw(b"GET /?pass=x HTTP/1.0\r\n\r\n"),
        # NFS over TCP and UDP, AIM, and AIM-looking bytes on 443.
        eth / IP(src=A, dst=B) / TCP(sport=900, dport=2049) / Raw(b"\x80\x00\x00\x28" + b"\x00" * 40),
        eth / IP(src=A, dst=B) / UDP(sport=901, dport=2049) / Raw(b"\x00\x00\x00\x01\x00\x00\x00\x00" + b"\x00" * 32),
        eth / IP(src=A, dst=B) / TCP(sport=40009, dport=5190) / Raw(b"*\x01\x00\x01\x00\x04\x00\x00\x00\x01"),
        eth / IP(src=A, dst=B) / TCP(sport=40010, dport=443) / Raw(b"*\x02\x00\x02\x00\x10" + b"\x00" * 16),
        # SNMP (scapy dissects it: no Raw), ICMP carrying a payload, STP.
        eth / IP(src=A, dst=B) / UDP(sport=40011, dport=161) / Raw(bytes.fromhex("302602010104067075626c6963a019020101020100020100300e300c06082b060102010101000500")),
        eth / IP(src=A, dst=B) / ICMP() / Raw(b"password=icmp"),
        Dot3(src="00:11:22:33:44:55", dst="01:80:c2:00:00:00") / LLC() / STP(),
        eth / Dot1Q(vlan=9, type=0x32) / LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(OUI=0x0C, code=0x10B) / STP() / Raw(b"\x00\x00\x00\x00\x02\x01\x0e"),
        # UDP with a short length field: the bytes past it are padding.
        eth / IP(src=A, dst=B) / UDP(sport=40012, dport=5000, len=12) / Raw(b"user=a pass=b"),
    ]
    out = []
    for frame in frames:
        data = bytes(frame)
        if len(data) < 60:
            data += bytes(range(1, 61 - len(data)))  # padding that is not zero
        out.append(Ether(data) if isinstance(frame, Ether) and not isinstance(frame, Dot3) else frame.__class__(data))
    return out


@pytest.fixture()
def capture(tmp_path: Path) -> Path:
    path = tmp_path / "edge.pcap"
    wrpcap(str(path), _frames())
    return path


@pytest.fixture(autouse=True)
def _fresh(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PCAPPER_CACHE_ENABLED", "0")
    utils.clear_analysis_memo()
    pcap_cache._PACKET_CACHE.clear()
    yield
    utils.clear_analysis_memo()
    pcap_cache._PACKET_CACHE.clear()


def _captures(tmp_path: Path, capture: Path) -> list[Path]:
    paths = [capture]
    for name in ("mixed.pcap", "mixed.pcapng", "http.pcap", "dns.pcap", "tls.pcap", "truncated.pcap", "voip_attack.pcap"):
        target = tmp_path / name
        shutil.copy(DATA / name, target)
        paths.append(target)
    return paths


@pytest.mark.parametrize(
    "analyze",
    [analyze_creds, analyze_http, analyze_telnet, analyze_nfs, analyze_aim],
    ids=["creds", "http", "telnet", "nfs", "aim"],
)
def test_from_disk_equals_scapy_packets(tmp_path: Path, capture: Path, analyze) -> None:  # type: ignore[no-untyped-def]
    for path in _captures(tmp_path, capture):
        utils.clear_analysis_memo()
        from_disk = analyze(path, show_status=False)
        packets, meta = pcap_cache.load_packets(path, show_status=False)
        assert packets and not isinstance(packets[0], LitePacket)
        utils.clear_analysis_memo()
        in_memory = analyze(path, show_status=False, packets=packets, meta=meta)
        assert repr(from_disk) == repr(in_memory), path.name  # same path: the whole summary


def test_the_edge_capture_reaches_every_path(capture: Path) -> None:
    """The fixture holds what the fast paths must get right: records the lite
    parser answers with a Raw payload, with padding behind it, and records
    only scapy can answer."""
    kinds = set()
    for record in pcap_cache.iter_packets(capture, show_status=False, lite=True):
        l4 = record.lite_l4()
        if l4 is UNSUPPORTED:
            kinds.add("unsupported")
        elif l4 is None:
            kinds.add("no-l4")
        elif l4[5] < 0:
            kinds.add("app-layer")
        else:
            kinds.add("raw+padding" if len(record.original) > l4[6] else "raw")
    assert {"unsupported", "no-l4", "app-layer", "raw", "raw+padding"} <= kinds


def test_lite_answers_match_scapy_record_for_record(tmp_path: Path, capture: Path) -> None:
    """creds' transport answer is scapy's, and telnet's skip never drops a
    record the scapy path would keep."""
    for path in _captures(tmp_path, capture):
        for record in pcap_cache.iter_packets(path, show_status=False, lite=True):
            pkt = record.materialize()
            assert creds._transport_and_payload(record) == creds._transport_and_payload(pkt)
            if telnet._lite_not_telnet(record):
                tcp = pkt.getlayer(TCP)
                if tcp is None:
                    continue
                payload = telnet._tcp_payload_bytes(pkt, tcp)[:16]
                assert not (
                    tcp.dport in telnet.TELNET_PORTS
                    or (tcp.sport in telnet.TELNET_PORTS and tcp.dport >= telnet._EPHEMERAL_MIN)
                    or payload.startswith((b"\xff\xfb", b"\xff\xfd"))
                )


class _Fake:
    __slots__ = ("sport", "dport", "proto", "payload", "time")

    def __init__(self, sport: int, dport: int, proto: str, payload: bytes) -> None:
        self.sport, self.dport, self.proto, self.payload, self.time = sport, dport, proto, payload, 1.0


def _scan(monkeypatch: pytest.MonkeyPatch, packets: list) -> object:
    """analyze_creds over ``packets`` with the padding skip off: the scan the
    skip stands in for, nested HTTP and telnet analyses left out."""

    class _Empty:
        url_counts: dict = {}
        first_seen = None
        conversations: list = []

    import pcapper.http as http_module

    monkeypatch.setattr(creds, "_padding_only", lambda payload: False)
    monkeypatch.setattr(creds, "_transport_and_payload", lambda p: (p.sport, p.dport, p.proto, p.payload))
    monkeypatch.setattr(creds, "_get_ip_pair", lambda p: ("10.0.0.1", "10.0.0.2"))
    monkeypatch.setattr(http_module, "analyze_http", lambda *a, **k: _Empty())
    monkeypatch.setattr(telnet, "analyze_telnet", lambda *a, **k: _Empty())
    return analyze_creds.__wrapped__(Path("/nonexistent.pcap"), show_status=False, packets=packets)


def test_padding_only_payloads_hold_no_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """What lets creds skip NUL-only payloads: scanned, they give no hit and no
    error on any port the scan tells apart (a sample here; the full grid of
    port pairs and 1-64 bytes was checked when the skip was added)."""
    from pcapper.services import COMMON_PORTS

    ports = set(COMMON_PORTS) | {161, 162, 389, 3268, 44818, 2222, 2221, 40000}
    for name in dir(creds):
        value = getattr(creds, name)
        if name.endswith("_PORTS") and isinstance(value, (set, frozenset)):
            ports |= set(value)
    packets = [
        _Fake(a, b, proto, b"\x00" * length)
        for proto in ("TCP", "UDP")
        for length in (1, 2, 6, 18, 46)
        for port in sorted(ports)
        for a, b in ((port, 40000), (40000, port), (port, port))
    ]
    summary = _scan(monkeypatch, packets)
    assert summary.total_packets == len(packets)
    assert not summary.hits and not summary.errors and not summary.kind_counts


def test_padding_inside_an_smtp_login_changes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    import base64

    def b64(text: str) -> str:
        return base64.b64encode(text.encode()).decode()

    flow = [
        (40000, 25, b"AUTH LOGIN\r\n"),
        (25, 40000, f"334 {b64('Username:')}\r\n".encode()),
        (40000, 25, f"{b64('alice.smith')}\r\n".encode()),
        (25, 40000, f"334 {b64('Password:')}\r\n".encode()),
        (40000, 25, f"{b64('S3cret!pass')}\r\n".encode()),
    ]

    def hits(segments: list) -> list:
        summary = _scan(monkeypatch, [_Fake(a, b, "TCP", p) for a, b, p in segments])
        return [(h.kind, h.username, h.secret) for h in summary.hits]

    plain = hits(flow)
    assert ("SMTP AUTH LOGIN Password", "alice.smith", "S3cret!pass") in plain
    for at in range(len(flow) + 1):
        for direction in ((40000, 25), (25, 40000)):
            padded = flow[:at] + [(*direction, b"\x00" * 6)] + flow[at:]
            assert hits(padded) == plain, (at, direction)


def test_tcp_options_scapy_cannot_parse_are_left_to_scapy(tmp_path: Path) -> None:
    """scapy keeps a TCP segment as Raw (no TCP layer) when a TCP-AO option
    (kind 29) carries a one-byte value: lite records must not claim a TCP
    layer there, and must keep claiming it for every other option block
    (a 0x1d byte inside another option's value included)."""
    import random
    import struct

    from scapy.all import Ether as _Ether
    from scapy.utils import PcapWriter

    rng = random.Random(29)
    pool = [0x00, 0x01, 0x1D, 0x1D, 0x02, 0x03, 0x04, 0x05, 0x08, 0x1E]

    def options() -> bytes:
        size = rng.choice((4, 8, 12, 16, 20, 40))
        out = bytearray()
        while len(out) < size:
            kind = rng.choice(pool)
            out.append(kind)
            if kind in (0, 1):
                continue
            olen = rng.choice((0, 1, 2, 3, 3, 4, 6, 10, 40))
            out.append(olen)
            out += bytes(rng.choice((0x1D, rng.randrange(256))) for _ in range(max(0, olen - 2)))
        return bytes(out[:size])

    frames = []
    for i in range(3000):
        opts = options()
        tcp = struct.pack("!HHIIBBHHH", 40000 + i % 100, 80, i, 0, (5 + len(opts) // 4) << 4, 0x18, 1024, 0, 0) + opts + b"x" * (i % 3)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), i & 0xFFFF, 0, 64, 6, 0, b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
        frames.append(b"\x66" * 6 + b"\x00\x11\x22\x33\x44\x55\x08\x00" + ip + tcp)
    path = tmp_path / "tcp_options.pcap"
    writer = PcapWriter(str(path), linktype=1, sync=True)
    for frame in frames:
        writer.write(_Ether(frame))
    writer.close()

    unsupported = 0
    for record in pcap_cache.iter_packets(path, show_status=False, lite=True):
        pkt = _Ether(record.original)
        tcp = pkt.getlayer(TCP)
        l4 = record.lite_l4()
        if tcp is None:
            assert l4 is UNSUPPORTED, record.original.hex()
            unsupported += 1
        else:
            assert l4 is not UNSUPPORTED and l4 is not None, record.original.hex()
            assert (l4[1], l4[2]) == (tcp.sport, tcp.dport)
    assert unsupported > 0  # the case the fix is about is in the sample
