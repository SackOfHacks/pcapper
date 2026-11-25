"""The capture summary (analyzer.analyze_pcap) and the protocol hierarchy
(protocols.analyze_protocols) read lite records from disk and take TCP/UDP
over Ethernet from the record's bytes: their results must equal the ones
computed over scapy packets (in memory), and every answer read from the
bytes must be scapy's, record for record."""

from __future__ import annotations

import random
import shutil
import socket
import struct
from pathlib import Path

import pytest

pytest.importorskip("scapy")

from scapy.all import (  # noqa: E402
    ARP,
    ICMP,
    IP,
    TCP,
    UDP,
    Dot1Q,
    Ether,
    IPOption_RR,
    IPv6,
    PcapNgWriter,
    Raw,
    wrpcap,
)
from scapy.layers.l2 import CookedLinux, CookedLinuxV2, Dot1AD, Loopback, LoopbackOpenBSD  # noqa: E402
from scapy.packet import Padding  # noqa: E402

from pcapper import analyzer, pcap_cache, protocols, utils  # noqa: E402
from pcapper.analyzer import analyze_pcap  # noqa: E402
from pcapper.lite import UNSUPPORTED, LitePacket  # noqa: E402
from pcapper.protocols import analyze_protocols  # noqa: E402

from test_lite_it_paths import _frames as _it_frames  # noqa: E402

DATA = Path(__file__).parent / "data"

A, B = "10.0.0.1", "10.0.0.2"
MAC_A, MAC_B = "00:11:22:33:44:55", "66:77:88:99:aa:bb"


def _ip_tcp(**tcp) -> bytes:  # type: ignore[no-untyped-def]
    return bytes(Ether(src=MAC_A, dst=MAC_B) / IP(src=A, dst=B) / TCP(**tcp))


def _with_tcp_options(options: bytes, payload: bytes = b"") -> bytes:
    """An Ethernet/IPv4/TCP frame whose TCP header carries ``options`` as
    given (padded with EOLs to a whole number of words)."""
    options += b"\x00" * (-len(options) % 4)
    frame = bytearray(_ip_tcp(sport=40100, dport=80, flags="PA", dataofs=5 + len(options) // 4))
    frame += options + payload
    struct.pack_into("!H", frame, 16, len(frame) - 14)  # IP total length
    return bytes(frame)


def _summary_frames() -> list:
    """Frames for what the summary and the hierarchy read: VLAN and QinQ tags,
    IPv6, broadcast, IP and TCP flags, TCP options, OpenVPN-looking payloads
    and padding, retransmissions, EtherType protocols, and frames only scapy
    can answer."""
    eth = Ether(src=MAC_A, dst=MAC_B)
    bcast = Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff")
    data = b"\x16\x03\x01" + b"A" * 40
    frames = [
        # Tags: 802.1Q, priority tag (VLAN 0), two 802.1Q, QinQ (802.1ad
        # outside), 802.1ad alone, a 0x9100 tag scapy leaves as Raw.
        eth / Dot1Q(vlan=7) / IP(src=A, dst=B) / TCP(sport=40200, dport=502, flags="S"),
        eth / Dot1Q(vlan=0, prio=5) / IP(src=A, dst=B) / UDP(sport=40201, dport=47808) / Raw(b"\x81\x0b\x00\x0c"),
        eth / Dot1Q(vlan=10) / Dot1Q(vlan=20) / IP(src=A, dst=B) / TCP(sport=40202, dport=102, flags="A"),
        Ether(src=MAC_A, dst=MAC_B, type=0x88A8) / Dot1AD(vlan=100) / Dot1Q(vlan=200) / IP(src=A, dst=B) / TCP(sport=40203, dport=20000, flags="SA"),
        Ether(src=MAC_A, dst=MAC_B, type=0x88A8) / Dot1AD(vlan=300) / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=40204, dport=22, flags="R"),
        Ether(src=MAC_A, dst=MAC_B, type=0x88A8) / Dot1AD(vlan=301) / Dot1AD(vlan=302) / IP(src=A, dst=B) / UDP(sport=40205, dport=9999) / Raw(b"x"),
        Ether(src=MAC_A, dst=MAC_B, type=0x9100) / Raw(b"\x00\x05\x08\x00" + bytes(IP(src=A, dst=B) / TCP())),
        # IPv6 TCP/UDP, broadcast UDP and TCP.
        eth / IPv6(src="fe80::1", dst="ff02::1") / TCP(sport=40206, dport=445, flags="S"),
        eth / IPv6(src="2001:db8::5", dst="2001:db8::6") / UDP(sport=40207, dport=4840) / Raw(b"OPC"),
        bcast / IP(src=A, dst="255.255.255.255") / UDP(sport=40208, dport=9999) / Raw(b"hello"),
        bcast / IP(src=A, dst=B) / TCP(sport=40209, dport=80, flags="S"),
        # IP flags: MF on a first fragment, DF, evil, all three; a later
        # fragment (no TCP layer).
        eth / IP(src=A, dst=B, flags="MF") / TCP(sport=40210, dport=80, flags="A"),
        eth / IP(src=A, dst=B, flags="DF") / TCP(sport=40210, dport=80, flags="A"),
        eth / IP(src=A, dst=B, flags="evil") / UDP(sport=40211, dport=9999),
        eth / IP(src=A, dst=B, flags="MF+DF+evil") / UDP(sport=40211, dport=9999),
        eth / IP(src=A, dst=B, frag=10, proto=6) / Raw(b"\x00" * 24),
        # TCP flags: NULL, FIN, XMAS, ECE/CWR/NS, SYN with options.
        eth / IP(src=A, dst=B) / TCP(sport=40212, dport=21, flags=0),
        eth / IP(src=A, dst=B) / TCP(sport=40212, dport=23, flags="F"),
        eth / IP(src=A, dst=B) / TCP(sport=40212, dport=25, flags="FPU"),
        eth / IP(src=A, dst=B) / TCP(sport=40212, dport=8080, flags=0x1C2),
        eth / IP(src=A, dst=B) / TCP(sport=40213, dport=3389, flags="S", options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1, 0)), ("NOP", None), ("WScale", 7)]),
        # 443/8443 with no payload (no port name) and with one; OpenVPN on
        # 1194 over TCP and UDP.
        eth / IP(src=A, dst=B) / TCP(sport=40214, dport=8443, flags="A"),
        eth / IP(src=A, dst=B) / TCP(sport=40214, dport=8443, flags="PA") / Raw(b"\x17\x03\x03\x00\x01x"),
        eth / IP(src=A, dst=B) / TCP(sport=40215, dport=1194, flags="PA") / Raw(b"\x00\x0e\x38" + b"\x11" * 13),
        eth / IP(src=A, dst=B) / UDP(sport=40216, dport=1194) / Raw(b"\x38" + b"\x22" * 13),
        eth / IP(src=A, dst=B) / UDP(sport=40216, dport=4433) / Raw(b"\x30" + b"\x22" * 13),
        # Retransmissions: the same data segment twice (IPv4, VLAN, IPv6).
        eth / IP(src=A, dst=B) / TCP(sport=40217, dport=9000, seq=1000, flags="PA") / Raw(data),
        eth / IP(src=A, dst=B) / TCP(sport=40217, dport=9000, seq=1000, flags="PA") / Raw(data),
        eth / Dot1Q(vlan=3) / IP(src=A, dst=B) / TCP(sport=40218, dport=9000, seq=7, flags="PA") / Raw(b"abc"),
        eth / Dot1Q(vlan=3) / IP(src=A, dst=B) / TCP(sport=40218, dport=9000, seq=7, flags="PA") / Raw(b"abc"),
        eth / IPv6(src="2001:db8::5", dst="2001:db8::6") / TCP(sport=40219, dport=9000, seq=99, flags="PA") / Raw(b"zz"),
        eth / IPv6(src="2001:db8::5", dst="2001:db8::6") / TCP(sport=40219, dport=9000, seq=99, flags="PA") / Raw(b"zz"),
        # Credentials the hierarchy flags (a TCP payload: dissected).
        eth / IP(src=A, dst=B) / TCP(sport=40220, dport=21, flags="PA") / Raw(b"USER bob\r\n"),
        # EtherType protocols, ARP (gratuitous), ICMP with a large payload.
        Ether(src=MAC_A, dst="01:80:c2:00:00:0e", type=0x88CC) / Raw(b"\x02\x07\x04" + b"\x00" * 30),
        Ether(src=MAC_A, dst="01:1b:19:00:00:00", type=0x88F7) / Raw(b"\x00\x02" + b"\x00" * 40),
        eth / Dot1Q(vlan=8, type=0x88B8) / Raw(b"\x00\x01\x00\x10" + b"\x00" * 30),
        bcast / ARP(op=2, psrc=A, pdst=A, hwsrc=MAC_A),
        eth / IP(src=A, dst=B) / ICMP() / Raw(b"\x00" * 600),
        # UDP length fields shorter and longer than the datagram; an IP
        # total length under 20.
        eth / IP(src=A, dst=B) / UDP(sport=40221, dport=9999, len=4) / Raw(b"abcdef"),
        eth / IP(src=A, dst=B) / UDP(sport=40221, dport=9999, len=200) / Raw(b"abcdef"),
        eth / IP(src=A, dst=B, len=12) / TCP(sport=40222, dport=80, flags="S"),
    ]
    out = []
    for frame in frames:
        raw = bytes(frame)
        if len(raw) < 60:
            raw += bytes(range(1, 61 - len(raw)))  # padding that is not zero
        out.append(raw)
    # An empty segment whose (non-zero) padding reads as an OpenVPN control
    # frame, and one whose padding is all zero.
    syn = _ip_tcp(sport=40223, dport=9999, flags="A")
    out.append(syn + b"\x00\x03\x38\x00\x00\x00")
    out.append(syn + b"\x00" * 6)
    # TCP options scapy's dissector fails on (TCP-AO with a one-byte value:
    # the segment becomes Raw), a valid TCP-AO option, a truncated option
    # and options with lengths under 2.
    out.append(_with_tcp_options(b"\x1d\x03\x01\x00"))
    out.append(_with_tcp_options(b"\x1d\x04\x01\x02", b"data"))
    out.append(_with_tcp_options(b"\x01\x01\x08\x0a\x00\x00\x00\x01\x00\x00\x00\x02"))
    out.append(_with_tcp_options(b"\x02\x01\x1d\x03\x00"))
    out.append(_with_tcp_options(b"\x02\x00\x01\x00"))
    out.append(_with_tcp_options(b"\x00\x1d\x03\x01"))  # after EOL: not parsed
    return [Ether(raw) for raw in out]



def _v6_family(cls) -> int:  # type: ignore[no-untyped-def]
    """The loopback family value scapy dissects as IPv6 on this platform."""
    for fields, payload in cls.payload_guess:
        if payload is IPv6 and "type" in fields:
            return int(fields["type"])
    return int(socket.AF_INET6)


def _other_family(cls) -> int:  # type: ignore[no-untyped-def]
    """A BSD IPv6 family value scapy does not bind here (dissected as Raw)."""
    bound = {int(fields["type"]) for fields, _ in cls.payload_guess if "type" in fields}
    return next(v for v in (28, 30, 24) if v not in bound)


def _write_captures(tmp_path: Path) -> list[Path]:
    edge = tmp_path / "edge.pcap"
    frames = [*_it_frames(), *_summary_frames()]
    for index, frame in enumerate(frames):
        frame.time = 1_700_000_000 + index * 0.25
    frames[3].wirelen = len(bytes(frames[3])) + 100  # truncated by the snaplen
    wrpcap(str(edge), frames)

    # pcapng: two named interfaces and one without a name (sniffed_on).
    ng = tmp_path / "edge.pcapng"
    writer = PcapNgWriter(str(ng))
    for index, frame in enumerate(_summary_frames()[:20]):
        frame.sniffed_on = ("eth0", "wlan1", None)[index % 3]
        frame.time = 1_700_000_100 + index
        writer.write(frame)
    writer.close()

    # Other link types: Linux cooked v1/v2 (v2's ifindex field is the
    # interface key), BSD loopback, raw IPv4/IPv6 (each with TCP and UDP, an
    # ICMP and an IP-options packet left to scapy).
    def l3s(v6_ok: bool = True) -> list:
        ip = IP(src=A, dst=B)
        packets = [
            ip / TCP(sport=40300, dport=502, flags="S"),
            ip / TCP(sport=40300, dport=502, flags="S"),  # a repeat
            ip / UDP(sport=40301, dport=1194) / Raw(b"\x38" + b"\x01" * 13),
            ip / TCP(sport=40302, dport=80, flags="PA", seq=5) / Raw(b"GET /?pass=x HTTP/1.1\r\n\r\n"),
            ip / TCP(sport=40302, dport=80, flags="PA", seq=5) / Raw(b"GET /?pass=x HTTP/1.1\r\n\r\n"),
            ip / ICMP() / Raw(b"ping"),
            IP(src=A, dst=B, options=[IPOption_RR()]) / TCP(sport=40303, dport=23, flags="S"),
        ]
        if v6_ok:
            ip6 = IPv6(src="2001:db8::1", dst="2001:db8::2")
            packets += [ip6 / TCP(sport=40304, dport=443, flags="A"), ip6 / UDP(sport=40305, dport=9999) / Raw(b"v6")]
        return packets

    others = []
    for name, linktype, frames in (
        ("cooked.pcap", 113, [CookedLinux(proto=0x86DD if IPv6 in p else 0x0800) / p for p in l3s()]),
        ("cooked2.pcap", 276, [CookedLinuxV2(proto=0x86DD if IPv6 in p else 0x0800, ifindex=i) / p for i, p in zip((7, 0, 0x80000001, 7, 7, 7, 7, 9, 9), l3s())]),
        # scapy binds one loopback family value to IPv6 -- not always this
        # platform's AF_INET6 (Windows: AF_INET6 is 23, scapy binds 24) -- and
        # leaves any other BSD value as Raw.
        ("loopback.pcap", 0, [Loopback(type=_v6_family(Loopback) if IPv6 in p else 2) / p for p in l3s()]
         + [Loopback(type=_other_family(Loopback)) / l3s()[-1]]),
        ("loopback_openbsd.pcap", 108, [LoopbackOpenBSD(type=_v6_family(LoopbackOpenBSD) if IPv6 in p else 2) / p for p in l3s()]
         + [LoopbackOpenBSD(type=_other_family(LoopbackOpenBSD)) / l3s()[-1]]),
        ("rawip.pcap", 101, l3s()),
        ("rawip12.pcap", 12, l3s()),
        ("ipv4.pcap", 228, l3s(v6_ok=False)),
        ("ipv6.pcap", 229, [p for p in l3s() if IPv6 in p]),
    ):
        path = tmp_path / name
        wrpcap(str(path), frames, linktype=linktype)
        others.append(path)
    # pcapng: cooked v2 records on named interfaces (sniffed_on wins over
    # the ifindex field) and on one without a name.
    sll2 = tmp_path / "cooked2.pcapng"
    writer = PcapNgWriter(str(sll2))
    for index, packet in enumerate(l3s()):
        frame = CookedLinuxV2(proto=0x86DD if IPv6 in packet else 0x0800, ifindex=3) / packet
        frame.sniffed_on = ("any", None)[index % 2]
        writer.write(frame)
    writer.close()
    return [edge, ng, *others, sll2]


@pytest.fixture()
def captures(tmp_path: Path) -> list[Path]:
    paths = _write_captures(tmp_path)
    for name in ("mixed.pcap", "mixed.pcapng", "http.pcap", "dns.pcap", "tls.pcap", "truncated.pcap", "voip_attack.pcap", "modbus.pcap", "voip_multiproto.pcap"):
        target = tmp_path / name
        shutil.copy(DATA / name, target)
        paths.append(target)
    return paths


@pytest.fixture(autouse=True)
def _fresh(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PCAPPER_CACHE_ENABLED", "0")
    utils.clear_analysis_memo()
    pcap_cache._PACKET_CACHE.clear()
    yield
    utils.clear_analysis_memo()
    pcap_cache._PACKET_CACHE.clear()


@pytest.mark.parametrize(
    "analyze", [analyze_pcap, analyze_protocols], ids=["summary", "protocols"]
)
def test_from_disk_equals_scapy_packets(captures: list[Path], analyze) -> None:  # type: ignore[no-untyped-def]
    for path in captures:
        utils.clear_analysis_memo()
        from_disk = analyze(path, show_status=False)
        packets, meta = pcap_cache.load_packets(path, show_status=False)
        assert packets and not isinstance(packets[0], LitePacket)
        utils.clear_analysis_memo()
        in_memory = analyze(path, show_status=False, packets=packets, meta=meta)
        assert repr(from_disk) == repr(in_memory), path.name  # the whole summary


def test_the_edge_captures_reach_every_path(captures: list[Path]) -> None:
    """The fixtures hold records read from their bytes (TCP with and without
    a payload, UDP, under tags, over IPv6, behind every link layer read) and
    records left to scapy."""
    kinds = set()
    for path in captures:
        for record in pcap_cache.iter_packets(path, show_status=False, lite=True):
            chain = analyzer._lite_layer_chain(record)
            if chain is None:
                l4 = record.lite_l4()
                kinds.add("scapy:" + ("unsupported" if l4 is UNSUPPORTED else "no-l4" if l4 is None else "other"))
                continue
            classes, l4, _ = chain
            names = [cls.__name__ for cls in classes]
            kinds.add(("tcp" if l4[0] else "udp") + (":payload" if l4[6] > l4[5] else ":empty"))
            kinds.add("tags:" + "/".join(name for name in names if name.startswith("Dot1")))
            kinds.add(f"link{record.linktype}:{names[0]}/{names[-2]}")
            if record.sniffed_on:
                kinds.add(f"named:{names[0]}")
    assert {
        "tcp:payload", "tcp:empty", "udp:payload", "udp:empty",
        "tags:", "tags:Dot1Q", "tags:Dot1Q/Dot1Q", "tags:Dot1AD/Dot1Q", "tags:Dot1AD",
        "link1:Ether/IP", "link1:Ether/IPv6",
        "link113:CookedLinux/IP", "link113:CookedLinux/IPv6",
        "link276:CookedLinuxV2/IP", "link276:CookedLinuxV2/IPv6",
        "link0:Loopback/IP", "link0:Loopback/IPv6",
        "link108:LoopbackOpenBSD/IP", "link108:LoopbackOpenBSD/IPv6",
        "link101:IP/IP", "link101:IPv6/IPv6", "link12:IP/IP", "link12:IPv6/IPv6",
        "link228:IP/IP", "link229:IPv6/IPv6",
        "named:Ether", "named:CookedLinuxV2",
        "scapy:unsupported", "scapy:no-l4", "scapy:other",
    } <= kinds


def _scapy_layers(pkt) -> list:  # type: ignore[no-untyped-def]
    layers = []
    layer = pkt
    while layer:
        layers.append(layer)
        layer = layer.payload
    return layers


def check_record(record: LitePacket) -> list[str]:
    """Every answer the lite paths read from ``record``, against scapy's; the
    names of those that differ (empty when all agree)."""
    pkt = record.materialize()
    bad = []
    chain = analyzer._lite_layer_chain(record)
    if chain is None:
        return bad
    classes, l4, l3 = chain
    data = record.original
    layers = _scapy_layers(pkt)
    # The layer chain: the classes, then a Raw payload iff the lite tuple has
    # one, then only Padding.
    tail = [type(layer) for layer in layers[len(classes):]]
    has_raw = l4[6] > l4[5]
    if [type(layer) for layer in layers[: len(classes)]] != classes:
        bad.append("classes")
    if tail[: int(has_raw)] != [Raw] * int(has_raw) or any(cls is not Padding for cls in tail[int(has_raw):]):
        bad.append("tail")
    if [cls.__name__ for cls in pkt.layers()] != [cls.__name__ for cls in classes] + [cls.__name__ for cls in tail]:
        bad.append("layers()")
    if [protocols._layer_name(cls) for cls in classes] != [layer.name for layer in layers[: len(classes)]]:
        bad.append("names")
    # analyze_pcap's answers.
    iface_key = analyzer._get_iface_key(pkt)
    if analyzer._lite_iface_key(record, classes) != ("unknown" if iface_key is None else iface_key):
        bad.append("iface")
    vlan = int(getattr(pkt[Dot1Q], "vlan", 0) or 0) if pkt.haslayer(Dot1Q) else 0
    if analyzer._lite_first_vlan(data, classes) != vlan:
        bad.append("vlan")
    if analyzer._lite_port_protocol_name(data, l4) != analyzer._port_protocol_name(pkt):
        bad.append("port name")
    if analyzer.ETHERTYPE_PROTOCOLS.get((data[12] << 8) | data[13]) != analyzer._ethertype_protocol_name(pkt):
        bad.append("ethertype name")
    if utils.extract_packet_endpoints(record) != utils.extract_packet_endpoints(pkt):
        bad.append("endpoints")
    transport = pkt.getlayer(TCP) or pkt.getlayer(UDP)
    if transport is None or (type(transport) is TCP) != l4[0]:
        bad.append("transport")
    elif bytes(transport.payload) != data[l4[7]:]:
        bad.append("transport payload bytes")
    tcp = pkt.getlayer(TCP)
    if tcp is not None:
        raw = tcp.getlayer(Raw)
        if (len(raw.load) if raw is not None else 0) != l4[6] - l4[5]:
            bad.append("payload length")
        if (int(tcp.seq), int(tcp.sport), int(tcp.dport)) != (l4[3], l4[1], l4[2]):
            bad.append("seq/ports")
        if int(tcp.flags) != l4[4]:
            bad.append("tcp flags")
    # analyze_protocols' answers.
    ip = pkt.getlayer(IP)
    ip6 = None if ip is not None else pkt.getlayer(IPv6)
    if (ip is not None) != (classes[-2] is IP) or (ip6 is not None) != (classes[-2] is IPv6):
        bad.append("ip version")
    layer = ip if ip is not None else ip6
    if layer is not None and record.lite_endpoints() != (layer.src, layer.dst):
        bad.append("ip src/dst")
    if ip is not None:
        flags_frag = (data[l3 + 6] << 8) | data[l3 + 7]
        if (int(ip.proto), int(ip.flags), int(ip.frag)) != (data[l3 + 9], flags_frag >> 13, flags_frag & 0x1FFF):
            bad.append("ip proto/flags/frag")
        if protocols._ip_flag_answers()[flags_frag >> 13] != (bool(ip.flags), str(ip.flags).lower().find("mf") >= 0):
            bad.append("ip flag answers")
    ether = pkt.getlayer(Ether)
    if (ether is not None) != (classes[0] is Ether):
        bad.append("ether layer")
    elif ether is not None:
        if int(ether.type) != (data[12] << 8) | data[13]:
            bad.append("ether type")
        if (str(ether.dst).lower() == "ff:ff:ff:ff:ff:ff") != (data[:6] == b"\xff" * 6):
            bad.append("broadcast")
    if pkt.getlayer(ICMP) is not None or pkt.getlayer(ARP) is not None:
        bad.append("icmp/arp")
    if (pkt.getlayer(Raw) is not None) != has_raw:
        bad.append("raw layer")
    return bad


def test_lite_answers_match_scapy_record_for_record(captures: list[Path]) -> None:
    claimed = 0
    for path in captures:
        for index, record in enumerate(pcap_cache.iter_packets(path, show_status=False, lite=True), start=1):
            bad = check_record(record)
            assert not bad, (path.name, index, bad)
            claimed += analyzer._lite_layer_chain(record) is not None
    assert claimed > 50


def test_tcp_ao_options_are_left_to_scapy() -> None:
    """scapy's TCP dissector fails on a TCP-AO option with a one-byte value
    (the segment becomes Raw): the lite parser answers UNSUPPORTED there, so
    no layer chain is read from the bytes; for every other options block the
    chain read from the bytes is scapy's."""
    failing = Ether(_with_tcp_options(b"\x1d\x03\x01\x00"))
    assert TCP not in failing  # scapy: Ether / IP / Raw
    rng = random.Random(7)
    alphabet = [0, 1, 2, 3, 29, 29, 29, 4, 8, 255]
    seen_failure = seen_ao = 0
    for _ in range(4000):
        options = bytes(
            rng.choice(alphabet) if rng.random() < 0.8 else rng.randrange(256)
            for _ in range(rng.randrange(1, 40))
        )
        frame = _with_tcp_options(options)
        pkt = Ether(frame)
        record = LitePacket(frame, 1, ("us", 0, 0), len(frame))
        chain = analyzer._lite_layer_chain(record)
        tcp = pkt.getlayer(TCP)
        if tcp is None:
            seen_failure += 1
            assert record.lite_l4() is UNSUPPORTED and chain is None, options.hex()
            continue
        seen_ao += any(name == "AO" for name, _ in tcp.options)
        if record.lite_l4()[5] >= 0:  # a Raw payload, or none
            assert chain is not None, options.hex()
            names = [cls.__name__ for cls in chain[0]]
            assert names == [c.__name__ for c in pkt.layers() if c.__name__ not in ("Raw", "Padding")]
    assert seen_failure and seen_ao


def test_tcp_flags_are_scapys_for_all_512_values(tmp_path: Path) -> None:
    path = tmp_path / "flags.pcap"
    wrpcap(str(path), [Ether(src=MAC_A, dst=MAC_B) / IP(src=A, dst=B) / TCP(flags=value) for value in range(512)])
    for value, record in enumerate(pcap_cache.iter_packets(path, show_status=False, lite=True)):
        assert record.lite_l4()[4] == int(record.materialize()[TCP].flags) == value


def test_ip_flag_answers_are_scapys(tmp_path: Path) -> None:
    path = tmp_path / "ipflags.pcap"
    wrpcap(str(path), [Ether(src=MAC_A, dst=MAC_B) / IP(src=A, dst=B, flags=value) / TCP() for value in range(8)])
    for value, record in enumerate(pcap_cache.iter_packets(path, show_status=False, lite=True)):
        ip = record.materialize()[IP]
        assert protocols._ip_flag_answers()[value] == (bool(ip.flags), str(ip.flags).lower().find("mf") >= 0)
        assert check_record(record) == []
