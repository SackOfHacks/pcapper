"""The scan, TCP and UDP analyses read lite records from disk: a plain TCP/UDP
record is accounted from its bytes and never dissected. Their results must
equal the ones computed over scapy packets (in memory), and every value read
from the bytes must be the one scapy gives, record for record."""

from __future__ import annotations

import shutil
import struct
from pathlib import Path

import pytest

pytest.importorskip("scapy")

from scapy.all import (  # noqa: E402
    ARP,
    DNS,
    DNSQR,
    ICMP,
    IP,
    TCP,
    UDP,
    CookedLinux,
    Dot1Q,
    Ether,
    IPv6,
    Raw,
    wrpcap,
)
from scapy.fields import FlagValue  # noqa: E402
from test_lite_it_paths import _frames as _it_frames  # noqa: E402

from pcapper import lite, pcap_cache, scan, tcp, udp, utils  # noqa: E402
from pcapper.lite import UNSUPPORTED, LitePacket  # noqa: E402
from pcapper.scan import analyze_scan  # noqa: E402
from pcapper.tcp import analyze_tcp  # noqa: E402
from pcapper.udp import analyze_udp  # noqa: E402

DATA = Path(__file__).parent / "data"

A, B, C = "10.0.0.1", "10.0.0.2", "10.0.0.3"
A6, B6 = "fe80::1", "fe80::2"


def _tcp_header(sport: int, dport: int, doff: int, flags: int, options: bytes = b"") -> bytes:
    return (
        struct.pack("!HHIIBBHHH", sport, dport, 1, 0, (doff << 4) | (flags >> 8), flags & 0xFF, 1024, 0, 0)
        + options
    )


def _transport_frames() -> list:
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    back = Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55")
    frames = []
    # A vertical SYN scan, answered: SYN/ACK (zero window), RST/ACK (small
    # window), the scanner's bare RST.
    for port in range(20, 45):
        frames.append(eth / IP(src=A, dst=B) / TCP(sport=50000, dport=port, flags="S", options=[("MSS", 1460)]))
    frames.append(back / IP(src=B, dst=A, ttl=128) / TCP(sport=22, dport=50000, flags="SA", window=0))
    frames.append(back / IP(src=B, dst=A) / TCP(sport=23, dport=50000, flags="RA", window=512))
    frames.append(eth / IP(src=A, dst=B) / TCP(sport=50000, dport=22, flags="R"))
    # A completed handshake, a banner, a login attempt and its failure, a
    # retransmission, host and tool names in a payload.
    frames += [
        eth / IP(src=A, dst=B) / TCP(sport=50001, dport=21, flags="S", seq=1),
        back / IP(src=B, dst=A) / TCP(sport=21, dport=50001, flags="SA", seq=100, ack=2),
        eth / IP(src=A, dst=B) / TCP(sport=50001, dport=21, flags="A", seq=2, ack=101),
        back / IP(src=B, dst=A) / TCP(sport=21, dport=50001, flags="PA", seq=101) / Raw(b"220 ProFTPD ready\r\n"),
        eth / IP(src=A, dst=B) / TCP(sport=50001, dport=21, flags="PA", seq=2) / Raw(b"USER admin\r\n"),
        eth / IP(src=A, dst=B) / TCP(sport=50001, dport=21, flags="PA", seq=2) / Raw(b"USER admin\r\n"),
        back / IP(src=B, dst=A) / TCP(sport=21, dport=50001, flags="PA", seq=120) / Raw(b"530 Login incorrect\r\n"),
        eth / IP(src=A, dst=B) / TCP(sport=50001, dport=21, flags="PA", seq=14)
        / Raw(b"PASS hunter2 nmap\r\nHost: scanner.example.com\r\n"),
    ]
    # Stealth probes: FIN, NULL, XMAS, Maimon, ACK, six ports each.
    for i, flags in enumerate(("F", "", "FPU", "FA", "A")):
        for port in range(100 + 10 * i, 106 + 10 * i):
            frames.append(eth / IP(src=C, dst=B) / TCP(sport=40000 + i, dport=port, flags=flags))
    frames += [
        # LAND, TTL 0, IP total length 0 / short of the segment / past the record.
        eth / IP(src=B, dst=B) / TCP(sport=7000, dport=7000, flags="S"),
        eth / IP(src=A, dst=B, ttl=0) / TCP(sport=50002, dport=8080, flags="S"),
        eth / IP(src=A, dst=B, len=0) / TCP(sport=50003, dport=80, flags="PA") / Raw(b"GET / HTTP/1.0\r\n\r\n"),
        eth / IP(src=A, dst=B, len=44) / TCP(sport=50004, dport=80, flags="PA") / Raw(b"GET /x HTTP/1.0\r\n\r\n"),
        eth / IP(src=A, dst=B, len=1500) / TCP(sport=50005, dport=80, flags="PA") / Raw(b"GET /y HTTP/1.0\r\n\r\n"),
        # Ports scapy dissects further: empty SYNs (Kerberos: the lite parser
        # answers; SMB: it does not), NetBIOS/SMB and DNS data.
        eth / IP(src=A, dst=B) / TCP(sport=50012, dport=88, flags="S"),
        eth / IP(src=A, dst=B) / TCP(sport=50006, dport=445, flags="S"),
        eth / IP(src=A, dst=B) / TCP(sport=50006, dport=445, flags="PA") / Raw(b"\x00\x00\x00\x2f\xffSMBr" + b"\x00" * 39),
        eth / IP(src=A, dst=B) / TCP(sport=50007, dport=53, flags="PA")
        / Raw(b"\x00\x1d" + bytes(DNS(rd=1, qd=DNSQR(qname="example.com")))),
        # A TCP-AO option with a 1-byte value (scapy keeps the segment as
        # Raw), a timestamp holding the byte 0x1d, a data offset past the end.
        eth / IP(src=A, dst=B, proto=6) / Raw(_tcp_header(50008, 22, 6, 0x02, bytes([29, 3, 1, 0]))),
        eth / IP(src=A, dst=B) / TCP(sport=50009, dport=22, flags="S", options=[("Timestamp", (0x1D1D1D1D, 0))]),
        eth / IP(src=A, dst=B, proto=6) / Raw(_tcp_header(50010, 22, 15, 0x02)),
        # VLAN-tagged SYN.
        eth / Dot1Q(vlan=7) / IP(src=A, dst=C) / TCP(sport=50011, dport=3389, flags="S"),
    ]
    # IPv6: a SYN scan, VLAN-tagged SYN, data whose payload length stops short
    # (the rest pads), a banner back.
    for port in range(1, 22):
        frames.append(eth / IPv6(src=A6, dst=B6) / TCP(sport=50100, dport=port, flags="S"))
    frames += [
        eth / Dot1Q(vlan=7) / IPv6(src=A6, dst=B6) / TCP(sport=50101, dport=443, flags="S"),
        eth / IPv6(src=A6, dst=B6, plen=24) / TCP(sport=50102, dport=25, flags="PA") / Raw(b"EHLO mail.example.org\r\n"),
        eth / IPv6(src=B6, dst=A6) / TCP(sport=25, dport=50102, flags="PA") / Raw(b"220 mail.example.org ESMTP\r\n"),
        eth / IPv6(src=A6, dst=B6) / TCP(sport=50103, dport=445, flags="S"),
    ]
    # UDP: probes, a service's reply, broadcast, length fields short of and
    # past the datagram, an auth attempt, DNS, IPv6.
    for port in (7, 9, 13, 17, 19, 1000, 2000, 3000):
        frames.append(eth / IP(src=C, dst=B) / UDP(sport=40100, dport=port))
    frames += [
        back / IP(src=B, dst=C) / UDP(sport=7, dport=40100) / Raw(b"echo"),
        eth / IP(src=C, dst="10.0.0.255") / UDP(sport=40101, dport=9999) / Raw(b"hello"),
        eth / IP(src=C, dst=B) / UDP(sport=40102, dport=9999, len=4) / Raw(b"abcd"),
        eth / IP(src=C, dst=B) / UDP(sport=40103, dport=9999, len=200) / Raw(b"abcd"),
        eth / IP(src=C, dst=B) / UDP(sport=40104, dport=110) / Raw(b"user=bob password=x\r\n"),
        eth / IP(src=C, dst=B) / UDP(sport=40105, dport=53) / DNS(rd=1, qd=DNSQR(qname="a.example.com")),
        eth / IPv6(src=A6, dst=B6) / UDP(sport=40106, dport=5000) / Raw(b"v6 payload"),
        # ICMP echo and an unreachable quoting a probe, ARP request and reply.
        eth / IP(src=C, dst=B) / ICMP(type=8),
        back / IP(src=B, dst=C) / ICMP(type=3, code=3) / IP(src=C, dst=B) / UDP(sport=40100, dport=9),
        eth / ARP(op=1, psrc=A, pdst=B),
        back / ARP(op=2, psrc=B, pdst=A),
    ]
    out = []
    for frame in frames:
        data = bytes(frame)
        if len(data) < 60:
            data += bytes(range(1, 61 - len(data)))  # padding that is not zero
        out.append(Ether(data))
    return out


def _stamped(frames: list, start: float = 1_700_000_000.0) -> list:
    for i, frame in enumerate(frames):
        frame.time = start + i * 0.25
    return frames


def _cooked_frames() -> list:
    """Linux cooked capture: no Ethernet layer; one record with bytes behind
    the IP total length."""
    sll = CookedLinux(pkttype=0, lladdrtype=1, lladdrlen=6, src=b"\x00\x11\x22\x33\x44\x55\x00\x00")
    frames = [sll / IP(src=A, dst=B) / TCP(sport=50200, dport=port, flags="S") for port in range(1, 30)]
    frames += [
        sll / IPv6(src=A6, dst=B6) / TCP(sport=50201, dport=22, flags="S"),
        sll / IP(src=C, dst=B) / UDP(sport=40200, dport=7) / Raw(b"ping"),
        CookedLinux(bytes(sll / IP(src=A, dst=B) / TCP(sport=50202, dport=80, flags="PA") / Raw(b"GET /"))
                    + b"\x01\x02\x03"),
    ]
    return frames


@pytest.fixture()
def capture(tmp_path: Path) -> Path:
    path = tmp_path / "edge.pcap"
    wrpcap(str(path), _stamped(_it_frames() + _transport_frames()))
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
    cooked = tmp_path / "cooked.pcap"
    wrpcap(str(cooked), _stamped(_cooked_frames()))
    paths = [capture, cooked]
    for name in (
        "mixed.pcap", "mixed.pcapng", "http.pcap", "dns.pcap", "tls.pcap", "truncated.pcap",
        "voip_attack.pcap", "voip.pcap", "modbus.pcap",
    ):
        target = tmp_path / name
        shutil.copy(DATA / name, target)
        paths.append(target)
    return paths


@pytest.mark.parametrize(
    "analyze", [analyze_scan, analyze_tcp, analyze_udp], ids=["scan", "tcp", "udp"]
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


def test_the_edge_captures_reach_every_path(tmp_path: Path, capture: Path) -> None:
    """Records each fast path answers (TCP empty or with data, on a port
    scapy dissects further or not; UDP with a Raw payload), and records it
    hands to scapy (TCP data scapy dissects further, UDP DNS, a UDP length
    short of its header, ICMP, ARP, unsupported -- a TCP-AO option scapy
    cannot parse among them)."""
    kinds = set()
    for path in _captures(tmp_path, capture)[:2]:
        for record in pcap_cache.iter_packets(path, show_status=False, lite=True):
            l4, ports = record.lite_l4(), record.lite_ports()
            fast = scan._lite_scan_fields(record) is not None
            if ports is UNSUPPORTED or ports is None:
                kinds.add("unsupported" if ports is UNSUPPORTED else "no-l4")
            elif ports[0]:
                fields = tcp._lite_tcp_fields(record, ports)
                empty = fields is not None and fields[5] == 0
                kinds.add(("tcp", l4 is not UNSUPPORTED, ports[5] >= 0, empty, fast, fields is not None))
            else:
                kinds.add(("udp", l4[5] >= 0, fast, udp._lite_udp_fields(record, l4) is not None))
    assert {
        "unsupported",
        "no-l4",
        ("tcp", True, True, True, True, True),  # empty segment
        ("tcp", True, True, False, True, True),  # data
        ("tcp", True, False, True, True, True),  # empty, on a port scapy dissects further
        ("tcp", True, False, False, False, True),  # data scapy dissects further: scan asks scapy
        # A payload layer that may hide more layers (SMB): only TCP reads it.
        ("tcp", False, False, True, False, True),
        ("tcp", False, False, False, False, True),
        ("udp", True, True, True),
        ("udp", True, True, False),  # length field short of the header: UDP asks scapy
        ("udp", False, False, False),  # DNS
    } <= kinds, kinds


def _flag_packet(value: int) -> bytes:
    frame = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src=A, dst=B, proto=6)
    return bytes(frame / Raw(_tcp_header(1234, 4321, 5, value)))


def test_tcp_flags_are_rebuilt_as_scapy_dissects_them() -> None:
    """All 512 flag values: the lite record's flags, built into a FlagValue,
    are scapy's -- type, equality, text, letters, int -- and every scan flag
    predicate answers the same for both."""
    predicates = (
        scan._tcp_flags_int, scan._tcp_is_syn, scan._tcp_is_synack, scan._tcp_is_rst,
        scan._tcp_scan_flavor, scan._tcp_is_final_handshake_ack,
    )
    for value in range(512):
        data = _flag_packet(value)
        theirs = Ether(data)[TCP].flags
        record = LitePacket(data, 1, ("us", 0, 0), len(data))
        assert record.lite_l4()[4] == value
        ours = scan._lite_scan_fields(record)[5]
        assert type(ours) is type(theirs) is FlagValue
        assert ours == theirs and theirs == ours and ours == value
        assert int(ours) == int(theirs) == value
        assert str(ours) == str(theirs) and repr(ours) == repr(theirs)
        assert (ours.names, ours.multi) == (theirs.names, theirs.multi)
        for letter in "FSRPAUECN":
            assert (letter in ours) == (letter in theirs)
            assert getattr(ours, letter) == getattr(theirs, letter)
        for predicate in predicates:
            assert predicate(ours) == predicate(theirs), (value, predicate.__name__)
        fields = tcp._lite_tcp_fields(record, record.lite_ports())
        assert fields is not None and fields[2] == int(theirs)


def test_lite_fields_match_scapy_record_for_record(tmp_path: Path, capture: Path) -> None:
    """Each value a fast path reads from the bytes is the one the scapy path
    reads from the dissected packet, and each record a fast path drops has
    no layer the scapy path would use."""
    answered = {"scan": 0, "tcp": 0, "tcp-below": 0, "udp": 0}
    for path in _captures(tmp_path, capture):
        for record in pcap_cache.iter_packets(path, show_status=False, lite=True):
            pkt = record.materialize()
            l4, ports = record.lite_l4(), record.lite_ports()
            tcp_layer = pkt.getlayer(TCP)
            udp_layer = pkt.getlayer(UDP)
            # analyze_tcp / analyze_udp drop records without their layer.
            if ports is None or (ports is not UNSUPPORTED and not ports[0]):
                assert tcp_layer is None
            if l4 is None or (l4 is not UNSUPPORTED and l4[0]):
                assert udp_layer is None
            ours = tcp._lite_tcp_fields(record, ports)
            if ours is not None:
                # The first TCP and IP layers are the headers read, whatever
                # scapy builds from the payload behind them.
                answered["tcp" if l4 is not UNSUPPORTED else "tcp-below"] += 1
                assert ours == tcp._tcp_fields(pkt, tcp_layer)
                assert utils.extract_packet_endpoints(record) == utils._extract_packet_endpoints(pkt)
            if l4 is None or l4 is UNSUPPORTED:
                assert scan._lite_scan_fields(record) is None
                continue
            ours = udp._lite_udp_fields(record, l4) if not l4[0] else None
            if ours is not None:
                answered["udp"] += 1
                assert udp_layer is not None and udp_layer.getlayer(DNS) is None
                assert ours == udp._udp_fields(udp_layer)
            fields = scan._lite_scan_fields(record)
            if fields is None:
                continue
            answered["scan"] += 1
            # What scan's _process reads from a dissected packet.
            ether = pkt.getlayer(Ether)
            src_mac = str(getattr(ether, "src", "") or "").lower() if ether is not None else ""
            ip_layer = pkt.getlayer(IP)
            ttl = int(getattr(ip_layer, "ttl", 0) or 0) if ip_layer is not None else 0
            if ip_layer is None:
                ip_layer = pkt.getlayer(IPv6)
            transport = tcp_layer if tcp_layer is not None else udp_layer
            if tcp_layer is not None:
                udp_layer = None
            payload = scan._extract_payload(pkt, tcp_layer, ip_layer)
            flags = getattr(tcp_layer, "flags", None) if tcp_layer is not None else None
            assert fields[:2] == (src_mac, ttl)
            assert transport is not None and fields[2] == (tcp_layer is not None)
            assert fields[3:5] == (int(transport.sport), int(transport.dport))
            assert type(fields[5]) is type(flags) and fields[5] == flags
            assert fields[6] == payload
            assert pkt.getlayer(ICMP) is None and pkt.getlayer(ARP) is None
    assert all(answered.values()), answered


def test_plain_records_are_never_dissected(tmp_path: Path, capture: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """From disk, each analysis's own loop dissects exactly the records its
    fast path hands to scapy (the nested HTTP, file and service analyses of
    the TCP and UDP ones are replayed, not counted)."""
    records = list(pcap_cache.iter_packets(capture, show_status=False, lite=True))
    expected = {
        "scan": sum(scan._lite_scan_fields(r) is None for r in records),
        "tcp": sum(
            r.lite_ports() is UNSUPPORTED
            or (r.lite_ports() is not None and r.lite_ports()[0] and tcp._lite_tcp_fields(r, r.lite_ports()) is None)
            for r in records
        ),
        "udp": sum(
            r.lite_l4() is UNSUPPORTED
            or (r.lite_l4() is not None and not r.lite_l4()[0] and udp._lite_udp_fields(r, r.lite_l4()) is None)
            for r in records
        ),
    }
    for module in (tcp, udp):
        for name in ("analyze_http", "analyze_files", "analyze_services"):
            result = getattr(module, name)(capture, show_status=False)
            monkeypatch.setattr(module, name, lambda *a, _r=result, **k: _r)
    built: list[int] = []
    real_build = lite._build_scapy

    def _counting(record):  # type: ignore[no-untyped-def]
        built.append(1)
        return real_build(record)

    monkeypatch.setattr(lite, "_build_scapy", _counting)
    for name, analyze in (("scan", analyze_scan), ("tcp", analyze_tcp), ("udp", analyze_udp)):
        built.clear()
        utils.clear_analysis_memo()
        analyze(capture, show_status=False)
        assert len(built) == expected[name], name
        assert len(built) < len(records) // 4, name
