"""The services, routing, ICMP and ARP analyses read lite records from disk:
they dissect only the packets they look at (services also counts plain TCP/UDP
records from their bytes), and their results must equal the ones computed
over scapy packets in memory, record for record."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

pytest.importorskip("scapy")

from scapy.all import (  # noqa: E402
    ARP,
    HSRP,
    ICMP,
    IGMP,
    IP,
    LLC,
    NTP,
    SNAP,
    STP,
    TCP,
    UDP,
    VRRP,
    CookedLinux,
    Dot1Q,
    Dot3,
    Ether,
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    ICMPv6MLQuery,
    ICMPv6ND_NS,
    ICMPv6NDOptRedirectedHdr,
    IPerror,
    IPOption_RR,
    IPv6,
    IPv6ExtHdrHopByHop,
    Padding,
    Raw,
    UDPerror,
    wrpcap,
)
from scapy.fields import FlagValue  # noqa: E402

from pcapper import arp, icmp, pcap_cache, routing, services, utils  # noqa: E402
from pcapper.arp import analyze_arp  # noqa: E402
from pcapper.icmp import analyze_icmp  # noqa: E402
from pcapper.lite import UNSUPPORTED, LitePacket  # noqa: E402
from pcapper.routing import analyze_routing  # noqa: E402
from pcapper.services import analyze_services  # noqa: E402

DATA = Path(__file__).parent / "data"

A, B = "10.0.0.1", "10.0.0.2"
PUB1, PUB2 = "8.8.4.4", "1.1.1.1"
MAC_A, MAC_B = "00:11:22:33:44:55", "66:77:88:99:aa:bb"
V6A, V6B = "fe80::1", "fe80::2"


def _bgp(msg_type: int, body: bytes) -> bytes:
    return b"\xff" * 16 + (19 + len(body)).to_bytes(2, "big") + bytes([msg_type]) + body


def _ospf_hello(router_id: bytes, auth_type: int, auth: bytes) -> bytes:
    hello = b"\xff\xff\xff\x00" + b"\x00\x0a\x02\x01" + b"\x00\x00\x00\x28" + b"\x00" * 8
    return b"\x02\x01" + (24 + len(hello)).to_bytes(2, "big") + router_id + b"\x00" * 4 + b"\x00\x00" + auth_type.to_bytes(2, "big") + auth + hello


# An IS-IS LAN hello: the 0x83 discriminator, then a header scapy leaves raw.
_ISIS = bytes.fromhex("831b0100100100000001") + bytes.fromhex("0100000000010021") + b"\x00" * 40


def _ip_frames() -> list:
    """IP traffic for services, routing and ICMP (link-layer independent)."""
    syn_opts = [("MSS", 1460), ("NOP", None), ("WScale", 7)]
    ovpn_reset = bytes([8 << 3]) + b"\x11" * 8 + b"\x00" * 5
    return [
        # A full handshake then banners both ways, FIN and RST: services'
        # established path (SYN/SYN-ACK/ACK tracking, banner guessing).
        IP(src=A, dst=B) / TCP(sport=40100, dport=22, flags="S", options=syn_opts),
        IP(src=B, dst=A) / TCP(sport=22, dport=40100, flags="SA", options=syn_opts),
        IP(src=A, dst=B) / TCP(sport=40100, dport=22, flags="A"),
        IP(src=B, dst=A) / TCP(sport=22, dport=40100, flags="PA") / Raw(b"SSH-2.0-OpenSSH_7.4\r\n"),
        IP(src=A, dst=B) / TCP(sport=40100, dport=22, flags="PA") / Raw(b"SSH-2.0-PuTTY_0.70\r\n"),
        IP(src=A, dst=B) / TCP(sport=40100, dport=22, flags="FA"),
        IP(src=B, dst=A) / TCP(sport=22, dport=40100, flags="R"),
        # OpenVPN over TCP: the server's first payload is a hard reset.
        IP(src=A, dst=B) / TCP(sport=40103, dport=1194, flags="S"),
        IP(src=B, dst=A) / TCP(sport=1194, dport=40103, flags="SA"),
        IP(src=A, dst=B) / TCP(sport=40103, dport=1194, flags="A"),
        IP(src=B, dst=A) / TCP(sport=1194, dport=40103, flags="PA") / Raw(len(ovpn_reset).to_bytes(2, "big") + ovpn_reset),
        # A flow seen without its handshake: inferred from both directions.
        IP(src=A, dst=B) / TCP(sport=40102, dport=21, flags="PA") / Raw(b"USER x\r\n"),
        IP(src=B, dst=A) / TCP(sport=21, dport=40102, flags="PA") / Raw(b"220 (vsFTPd 2.3.4)\r\n"),
        # One whose server sends only empty (padded) segments: the padding is
        # no server payload, so no service is inferred.
        IP(src=A, dst=B) / TCP(sport=40140, dport=3306, flags="PA") / Raw(b"\x0a\x00\x00\x01"),
        IP(src=B, dst=A) / TCP(sport=3306, dport=40140, flags="A"),
        # IP length fields scapy's payload length reads: 0, under the header,
        # past the captured bytes; TCP options; every flag bit incl. NS.
        IP(src=A, dst=B, len=0) / TCP(sport=40104, dport=5000, flags="PA") / Raw(b"abc"),
        IP(src=A, dst=B, len=10) / TCP(sport=40104, dport=5000, flags="PA") / Raw(b"abcdef"),
        IP(src=B, dst=A, len=400) / TCP(sport=5000, dport=40104, flags="PA") / Raw(b"0123456789"),
        IP(src=A, dst=B) / TCP(sport=40104, dport=5000, flags=0x1FF, options=syn_opts) / Raw(b"opts"),
        IP(src=A, dst=B) / TCP(sport=40104, dport=5000, flags=0x110),
        # Ports scapy dissects further: Kerberos (a terminal layer: lite
        # answers -1), TLS and NBT session (UNSUPPORTED), an empty 445 one.
        IP(src=A, dst=B) / TCP(sport=40105, dport=88, flags="S"),
        IP(src=A, dst=B) / TCP(sport=40105, dport=443, flags="S"),
        IP(src=A, dst=B) / TCP(sport=40105, dport=139, flags="S"),
        IP(src=B, dst=A) / TCP(sport=445, dport=40105, flags="RA"),
        IP(src=A, dst=B) / UDP(sport=40113, dport=53) / Raw(bytes.fromhex("12340100000100000000000003777777076578616d706c6503636f6d0000010001")),
        IP(src=A, dst=B) / UDP(sport=40114, dport=161) / Raw(bytes.fromhex("302602010104067075626c6963a019020101020100020100300e300c06082b060102010101000500")),
        # UDP: NTP (dissected), OpenVPN control, a group address, both ports
        # well known, one well-known side, none.
        IP(src=A, dst=B) / UDP(sport=123, dport=123) / NTP(mode=3),
        IP(src=A, dst=B) / UDP(sport=40106, dport=1194) / Raw(bytes([7 << 3]) + b"\x22" * 8 + b"\x00" * 5),
        IP(src=A, dst="239.255.255.250") / UDP(sport=40107, dport=1900) / Raw(b"M-SEARCH * HTTP/1.1\r\n"),
        IP(src=A, dst=B) / UDP(sport=514, dport=514) / Raw(b"<13>hello"),
        IP(src=B, dst=A) / UDP(sport=502, dport=40108) / Raw(b"\x00\x01\x00\x00\x00\x06"),
        IP(src=A, dst=B) / UDP(sport=40108, dport=40109) / Raw(b"x"),
        IP(src=A, dst=B) / UDP(sport=40110, dport=4433, len=8),
        # Routing: protocol numbers (OSPF with and without auth, EIGRP, VRRP,
        # PIM, IGMP, IGRP from a public IP, IS-IS over IP), BGP and the ports.
        IP(src=PUB1, dst="224.0.0.5", proto=89) / Raw(_ospf_hello(b"\x01\x01\x01\x01", 1, b"secret12")),
        IP(src=A, dst="224.0.0.5", proto=89) / Raw(_ospf_hello(b"\x02\x02\x02\x02", 0, b"\x00" * 8)),
        IP(src=A, dst="224.0.0.10", proto=88) / Raw(b"\x02\x05\xee\xc3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x64"),
        IP(src=A, dst="224.0.0.18", proto=112) / VRRP(vrid=7, priority=200, addrlist=["10.0.0.254"]),
        IP(src=A, dst="224.0.0.13", proto=103) / Raw(b"\x20\x00\x00\x00\x00\x01\x00\x02\x00\x69"),
        IP(src=A, dst="224.0.0.1") / IGMP(),
        IP(src=PUB2, dst=B, proto=9) / Raw(b"\x11" * 20),
        IP(src=A, dst=B, proto=124) / Raw(_ISIS),
        IP(src=A, dst=B) / TCP(sport=40111, dport=179, flags="PA") / Raw(_bgp(1, b"\x04\xfd\xe9\x00\xb4\x0a\x00\x00\x01\x00")),
        IP(src=B, dst=A) / TCP(sport=179, dport=40111, flags="PA") / Raw(_bgp(4, b"")),
        IP(src=B, dst=A) / TCP(sport=179, dport=80, flags="S"),
        IP(src=A, dst=B) / TCP(sport=40112, dport=520, flags="S"),
        IP(src=A, dst="224.0.0.9") / UDP(sport=520, dport=520) / Raw(b"\x02\x02\x00\x00\xff\xff\x00\x02" + b"pass" + b"\x00" * 12 + b"\x00\x02\x00\x00" + b"\x0a\x00\x00\x00" + b"\x00" * 8 + b"\x00\x00\x00\x10"),
        IP(src=A, dst="224.0.0.2") / UDP(sport=1985, dport=1985) / HSRP(group=3, auth=b"cisco"),
        IP(src=A, dst="224.0.0.102") / UDP(sport=3222, dport=3222) / Raw(b"\x01\x00\x00\x00"),
        # ICMP: a redirect (quotes a header: dissected), echo with artefacts,
        # a fragment whose first byte reads like a redirect, a 1-byte ICMP,
        # an empty IP payload, an unreachable.
        IP(src=B, dst=A) / ICMP(type=5, code=1, gw="10.0.0.254") / IPerror(src=A, dst=PUB1) / UDPerror(sport=1, dport=2),
        IP(src=A, dst=B) / ICMP(type=8, id=7, seq=1) / Raw(b"user=bob secret.exe padding!"),
        IP(src=B, dst=A) / ICMP(type=0, id=7, seq=1) / Raw(b"user=bob secret.exe padding!"),
        IP(src=A, dst=B, proto=1, frag=100) / Raw(b"\x05\x00rest-of-a-fragment"),
        IP(src=A, dst=B, proto=1, frag=200) / Raw(b"\x08\x00rest-of-a-fragment"),
        IP(src=A, dst=B, proto=1) / Raw(b"\x08"),
        IP(src=B, dst=A) / ICMP(type=3, code=3) / IPerror(src=A, dst=B) / UDPerror(sport=40108, dport=40109),
        # IPv6: a handshake and an HTTP banner, RIPng, ICMPv6 echo, MLD
        # behind a hop-by-hop header, no next header, and ND messages whose
        # Redirected Header option carries whole packets scapy finds TCP,
        # IPv4 and ICMP layers in (the lite parser does not look inside).
        IPv6(src=V6A, dst=V6B) / TCP(sport=40120, dport=8080, flags="S"),
        IPv6(src=V6B, dst=V6A) / TCP(sport=8080, dport=40120, flags="SA"),
        IPv6(src=V6A, dst=V6B) / TCP(sport=40120, dport=8080, flags="A"),
        IPv6(src=V6B, dst=V6A) / TCP(sport=8080, dport=40120, flags="PA") / Raw(b"HTTP/1.1 200 OK\r\nServer: Apache/2.2.3\r\n\r\n"),
        IPv6(src=V6A, dst="ff02::9") / UDP(sport=521, dport=521) / Raw(b"\x02\x01\x00\x00" + b"\x00" * 16 + b"\x00\x00\x40\x10"),
        IPv6(src=V6A, dst=V6B) / ICMPv6EchoRequest(id=9) / Raw(b"ping6 payload.txt"),
        IPv6(src=V6B, dst=V6A) / ICMPv6EchoReply(id=9) / Raw(b"ping6 payload.txt"),
        IPv6(src=V6A, dst="ff02::1") / IPv6ExtHdrHopByHop() / ICMPv6MLQuery(),
        IPv6(src=V6A, dst=V6B, nh=59) / Raw(b"nothing next"),
        IPv6(src=V6A, dst=V6B) / ICMPv6ND_NS(tgt=V6B) / ICMPv6NDOptRedirectedHdr(pkt=IPv6(src="2001:db8::9", dst="2001:db8::8") / TCP(sport=1, dport=2) / b"abcd"),
        IPv6(src=V6A, dst=V6B) / ICMPv6ND_NS(tgt=V6B) / ICMPv6NDOptRedirectedHdr(pkt=IPv6(src="2001:db8::9", dst="2001:db8::8", nh=4) / IP(src=PUB1, dst=PUB2) / TCP(sport=179, dport=40000) / b"abcd"),
        IPv6(src=V6A, dst=V6B) / ICMPv6ND_NS(tgt=V6B) / ICMPv6NDOptRedirectedHdr(pkt=IPv6(src="2001:db8::9", dst="2001:db8::8", nh=4) / IP(src=PUB1, dst=PUB2, proto=1) / b"\x08\x00\x00\x00"),
    ] + [
        # A whole handshake and banner hidden that way: scapy confirms a
        # service from them.
        IPv6(src=V6A, dst=V6B) / ICMPv6ND_NS(tgt=V6B) / ICMPv6NDOptRedirectedHdr(pkt=IPv6(src="2001:db8::9", dst="2001:db8::8", nh=4) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags) / payload)
        for src, dst, sport, dport, flags, payload in (
            (PUB1, PUB2, 40130, 2323, "S", b""),
            (PUB2, PUB1, 2323, 40130, "SA", b""),
            (PUB1, PUB2, 40130, 2323, "A", b""),
            (PUB2, PUB1, 2323, 40130, "PA", b"SSH-2.0-dropbear_2012.55\r\n"),
        )
    ]


def _frames() -> list:
    eth = Ether(src=MAC_A, dst=MAC_B)
    frames = [eth / frame for frame in _ip_frames()]
    frames += [
        # The edge frames of tests/test_lite_it_paths.py: padding, VLAN,
        # IPv6, IP options, NFS/AIM, SNMP, ICMP with a payload, STP over
        # LLC/SNAP, a UDP length shorter than the datagram.
        eth / IP(src=A, dst=B) / TCP(sport=40000, dport=80, flags="S"),
        eth / IP(src=A, dst=B) / TCP(sport=40000, dport=80) / Raw(b"GET /login?user=bob&password=hunter2 HTTP/1.1\r\nHost: x\r\n\r\n"),
        eth / IP(src=A, dst=B) / TCP(sport=40001, dport=8081) / Raw(b"POST /a HTTP/1.1\r\nAuthorization: Basic Ym9iOnNlY3JldA==\r\n\r\n"),
        eth / IP(src=B, dst=A) / TCP(sport=80, dport=40000) / Raw(b"HTTP/1.1 200 OK\r\n\r\nusername=x"),
        eth / IP(src=A, dst=B) / TCP(sport=40002, dport=21) / Raw(b"USER a\r\n"),
        eth / IP(src=A, dst=B) / TCP(sport=40002, dport=21) / Raw(b"PASS b\r\n"),
        eth / IP(src=A, dst=B) / TCP(sport=40003, dport=23) / Raw(b"login: "),
        eth / IP(src=B, dst=A) / TCP(sport=40004, dport=4444) / Raw(b"\xff\xfb\x01\xff\xfd\x03"),
        eth / IP(src=A, dst=B) / TCP(sport=40005, dport=4445) / Raw(b"\xff"),
        eth / Dot1Q(vlan=5) / IP(src=A, dst=B) / TCP(sport=40006, dport=110) / Raw(b"USER v\r\nPASS w\r\n"),
        eth / IPv6(src=V6A, dst=V6B) / TCP(sport=40007, dport=143) / Raw(b"a1 LOGIN u p\r\n"),
        eth / IP(src=A, dst=B, options=[IPOption_RR()]) / TCP(sport=40008, dport=80) / Raw(b"GET /?pass=x HTTP/1.0\r\n\r\n"),
        eth / IP(src=A, dst=B) / TCP(sport=900, dport=2049) / Raw(b"\x80\x00\x00\x28" + b"\x00" * 40),
        eth / IP(src=A, dst=B) / UDP(sport=901, dport=2049) / Raw(b"\x00\x00\x00\x01\x00\x00\x00\x00" + b"\x00" * 32),
        eth / IP(src=A, dst=B) / TCP(sport=40009, dport=5190) / Raw(b"*\x01\x00\x01\x00\x04\x00\x00\x00\x01"),
        eth / IP(src=A, dst=B) / TCP(sport=40010, dport=443) / Raw(b"*\x02\x00\x02\x00\x10" + b"\x00" * 16),
        eth / IP(src=A, dst=B) / UDP(sport=40011, dport=161) / Raw(bytes.fromhex("302602010104067075626c6963a019020101020100020100300e300c06082b060102010101000500")),
        eth / IP(src=A, dst=B) / ICMP() / Raw(b"password=icmp"),
        Dot3(src=MAC_A, dst="01:80:c2:00:00:00") / LLC() / STP(),
        eth / Dot1Q(vlan=9, type=0x32) / LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(OUI=0x0C, code=0x10B) / STP() / Raw(b"\x00\x00\x00\x00\x02\x01\x0e"),
        eth / IP(src=A, dst=B) / UDP(sport=40012, dport=5000, len=12) / Raw(b"user=a pass=b"),
        # IS-IS as routing reads it: over LLC, with its own EtherType, and as
        # the raw payload of an unknown EtherType.
        Dot3(src=MAC_A, dst="01:80:c2:00:00:14") / LLC(dsap=0xFE, ssap=0xFE, ctrl=3) / Raw(_ISIS),
        Ether(src=MAC_A, dst=MAC_B, type=0xFEFE) / Raw(_ISIS),
        Ether(src=MAC_A, dst=MAC_B, type=0x88B5) / Raw(_ISIS),
        # ARP: request, reply, gratuitous, probe, unsolicited broadcast reply,
        # a printable trailer, VLAN-tagged, IPv6 protocol type, truncated.
        Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=MAC_A, psrc=A, pdst=B),
        Ether(src=MAC_B, dst=MAC_A) / ARP(op=2, hwsrc=MAC_B, psrc=B, hwdst=MAC_A, pdst=A),
        Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=MAC_A, psrc=A, pdst=A),
        Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=MAC_A, psrc="0.0.0.0", pdst=B),
        Ether(src=MAC_B, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=MAC_B, psrc=B, hwdst="ff:ff:ff:ff:ff:ff", pdst=B),
        Ether(src=MAC_B, dst=MAC_A) / ARP(op=2, hwsrc=MAC_B, psrc=B, hwdst=MAC_A, pdst=A) / Padding(b"leak: notes.txt secret"),
        Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff") / Dot1Q(vlan=7) / ARP(op=1, hwsrc=MAC_A, psrc=A, pdst=B),
        Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, ptype=0x86DD, plen=16, hwsrc=MAC_A, psrc=V6A, pdst=V6B),
        Ether(bytes(Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc=A, pdst=B))[:34]),
    ]
    out = []
    for frame in frames:
        data = bytes(frame)
        if len(data) < 60:
            data += bytes(range(1, 61 - len(data)))  # padding that is not zero
        out.append(Ether(data) if isinstance(frame, Ether) and not isinstance(frame, Dot3) else frame.__class__(data))
    # An empty IP payload whose padding starts like an ICMP redirect.
    empty = bytes(Ether(src=MAC_A, dst=MAC_B) / IP(src=A, dst=B, proto=1, len=20))
    out.append(Ether(empty + b"\x05" + bytes(range(1, 60 - len(empty)))))
    return out


def _cooked_frames() -> list:
    """The IP traffic again behind a Linux cooked header (other offsets)."""
    head = CookedLinux(pkttype=0, lladdrtype=1, lladdrlen=6, src=b"\x00\x11\x22\x33\x44\x55\x00\x00")
    out = []
    for frame in _ip_frames():
        head.proto = 0x86DD if isinstance(frame, IPv6) else 0x0800
        out.append(CookedLinux(bytes(head / frame)))
    return out


def _raw_ip_frames() -> list:
    """Raw IP (linktype 101), with bytes past the IP length as padding."""
    return [IP(bytes(f) + b"\x00pad\x01") if isinstance(f, IP) else IPv6(bytes(f) + b"pad") for f in _ip_frames()]


def write_edge_captures(directory: Path) -> list[Path]:
    """The edge captures (Ethernet, Linux cooked, raw IP) written to ``directory``."""
    paths = [directory / "edge_eth.pcap", directory / "edge_sll.pcap", directory / "edge_rawip.pcap"]
    wrpcap(str(paths[0]), _frames())
    wrpcap(str(paths[1]), _cooked_frames(), linktype=113)
    wrpcap(str(paths[2]), _raw_ip_frames(), linktype=101)
    return paths


@pytest.fixture()
def edge(tmp_path: Path) -> list[Path]:
    return write_edge_captures(tmp_path)


@pytest.fixture(autouse=True)
def _fresh(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PCAPPER_CACHE_ENABLED", "0")
    utils.clear_analysis_memo()
    pcap_cache._PACKET_CACHE.clear()
    yield
    utils.clear_analysis_memo()
    pcap_cache._PACKET_CACHE.clear()


def _captures(tmp_path: Path, edge: list[Path]) -> list[Path]:
    paths = list(edge)
    for source in sorted(DATA.glob("*.pcap*")):
        target = tmp_path / source.name
        shutil.copy(source, target)
        paths.append(target)
    return paths


ANALYSES = [analyze_services, analyze_routing, analyze_icmp, analyze_arp]


@pytest.mark.parametrize("analyze", ANALYSES, ids=["services", "routing", "icmp", "arp"])
def test_from_disk_equals_scapy_packets(tmp_path: Path, edge: list[Path], analyze) -> None:  # type: ignore[no-untyped-def]
    for path in _captures(tmp_path, edge):
        utils.clear_analysis_memo()
        from_disk = analyze(path, show_status=False)
        packets, meta = pcap_cache.load_packets(path, show_status=False)
        assert packets and not isinstance(packets[0], LitePacket)
        utils.clear_analysis_memo()
        in_memory = analyze(path, show_status=False, packets=packets, meta=meta)
        assert repr(from_disk) == repr(in_memory), path.name  # the whole summary


def test_the_edge_captures_reach_every_path(edge: list[Path]) -> None:
    """The fixtures hold what the fast paths must get right."""
    kinds = set()
    for path in edge:
        for record in pcap_cache.iter_packets(path, show_status=False, lite=True):
            l3 = record.headers()[1]
            l4 = record.lite_l4()
            mine = services._lite_l4(record)
            if l4 is UNSUPPORTED:
                kinds.add("unsupported")
            elif l4 is None:
                kinds.add("icmpv6" if mine is UNSUPPORTED else "no-l4")
                if l3 is not None and l3 is not UNSUPPORTED:
                    kinds.add({4: "ipv4-no-l4", 6: "ipv6-no-l4", 1: "arp"}[l3[0]])
            elif l4[5] < 0:
                kinds.add("app-layer")
            else:
                kind = "tcp" if l4[0] else "udp"
                kinds.add(kind + ("+padding" if len(record.original) > l4[6] else ""))
                if l4[0] and l3[0] == 4:
                    start = l3[1] - 12
                    total = int.from_bytes(record.original[start + 2 : start + 4], "big")
                    if total == 0:
                        kinds.add("ip-len-0")
                    elif total < 20:
                        kinds.add("ip-len-short")
                    elif start + total > len(record.original):
                        kinds.add("ip-len-past-capture")
                if l4[0] and l3[0] == 6 and len(record.original) > l4[6]:
                    kinds.add("ipv6-tcp+padding")
            if not routing._lite_not_routing(record):
                kinds.add("routing-dissected")
    assert {
        "unsupported", "no-l4", "icmpv6", "ipv4-no-l4", "ipv6-no-l4", "arp", "app-layer",
        "tcp", "tcp+padding", "udp", "udp+padding", "ip-len-0", "ip-len-short",
        "ip-len-past-capture", "ipv6-tcp+padding", "routing-dissected",
    } <= kinds, kinds


def _tcp_flags_field_value(value: int) -> object:
    return TCP(bytes(TCP(sport=1, dport=2, flags=value))).flags


def test_flags_rebuilt_from_the_int_are_scapys() -> None:
    """services hands the four handshake tests a FlagValue built from the
    record's 9-bit flags: for every value it is the one scapy dissects."""
    letters = "FSRPAUECN"
    for value in range(512):
        theirs = _tcp_flags_field_value(value)
        mine = FlagValue(value, services._TCP_FLAG_NAMES)
        assert type(mine) is type(theirs)
        assert mine == theirs and int(mine) == int(theirs) == value
        assert str(mine) == str(theirs) and repr(mine) == repr(theirs)
        assert mine.names == theirs.names
        assert [c in mine for c in letters] == [c in theirs for c in letters]
        assert utils.tcp_flags_int(mine) == utils.tcp_flags_int(theirs) == value
        for test in (
            services._tcp_is_syn,
            services._tcp_is_synack,
            services._tcp_is_rst,
            services._tcp_is_final_handshake_ack,
        ):
            assert test(mine) == test(theirs), (value, test.__name__)


def _services_view(pkt: object) -> object:
    """What analyze_services' loop reads off a scapy packet, its own way."""
    if IP in pkt:
        ip_layer = pkt[IP]
    elif IPv6 in pkt:
        ip_layer = pkt[IPv6]
    else:
        return None
    if TCP in pkt:
        tcp = pkt[TCP]
        payload = services._tcp_payload_bytes(ip_layer, tcp)
        return (True, int(tcp.sport or 0), int(tcp.dport or 0), tcp.flags, payload)
    if UDP in pkt:
        udp = pkt[UDP]
        return (False, udp.sport, udp.dport, None, bytes(udp.payload))
    return None


def _routing_may_record(pkt: object) -> bool:
    """Every test analyze_routing's loop records something behind."""
    ip = pkt.getlayer(IP)
    ip6 = pkt.getlayer(IPv6) if ip is None else None
    proto = int(ip.proto) if ip is not None else int(ip6.nh) if ip6 is not None else None
    if proto in routing.ROUTING_IP_PROTOS or proto in routing._ROUTING_IGP_PROTOS:
        return True
    if pkt.haslayer(ICMP) and int(pkt[ICMP].type) == 5:
        return True
    if pkt.haslayer(Ether) and int(pkt[Ether].type or 0) == 0xFEFE:
        return True
    if pkt.haslayer(LLC) and (int(pkt[LLC].dsap), int(pkt[LLC].ssap)) == (0xFE, 0xFE):
        return True
    if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)) and pkt.haslayer(Raw):
        if bytes(pkt[Raw])[:1] == b"\x83":
            return True
    if pkt.haslayer(TCP):
        sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
        if dport in routing.ROUTING_PORTS or (sport in routing.ROUTING_PORTS and dport >= 1024):
            return True
    if pkt.haslayer(UDP):
        sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
        if sport in routing.ROUTING_PORTS or dport in routing.ROUTING_PORTS:
            return True
    return False


def _icmp_reads(pkt: object) -> bool:
    """analyze_icmp's own test for an ICMP/ICMPv6 packet."""
    ip = pkt.getlayer(IP)
    if ip is not None and getattr(ip, "proto", None) == 1:
        return True
    ip6 = pkt.getlayer(IPv6)
    return ip6 is not None and (getattr(ip6, "nh", None) == 58 or icmp._icmpv6_layer(ip6) is not None)


def test_lite_answers_match_scapy_record_for_record(tmp_path: Path, edge: list[Path]) -> None:
    """Every value services reads from a record's bytes is scapy's (ports,
    flags, endpoints, the header lengths and payloads), and a record the
    routing, ICMP or ARP analysis skips is one its scapy path ignores."""
    names = services._TCP_FLAG_NAMES
    counts = {"bytes": 0, "routing": 0, "icmp": 0, "arp": 0}
    for path in _captures(tmp_path, edge):
        for record in pcap_cache.iter_packets(path, show_status=False, lite=True):
            pkt = record.materialize()
            l4 = services._lite_l4(record)
            if l4 is None:
                assert TCP not in pkt and UDP not in pkt, path.name
            elif l4 is not UNSUPPORTED:
                counts["bytes"] += 1
                assert l4[5] >= 0
                if l4[0]:
                    view = (True, l4[1], l4[2], FlagValue(l4[4], names), services._lite_tcp_payload(record, l4))
                else:
                    view = (False, l4[1], l4[2], None, record.original[l4[7] :])
                theirs = _services_view(pkt)
                assert view == theirs, path.name
                assert [type(v) for v in view] == [type(v) for v in theirs]
                assert str(view[3]) == str(theirs[3])
                assert utils.extract_packet_endpoints(record, include_arp=False) == utils.extract_packet_endpoints(
                    pkt, include_arp=False
                )
                # The header fields _lite_tcp_payload reads are scapy's.
                kind, off = record.headers()[1]
                data = record.original
                if kind == 4:
                    assert IP in pkt and pkt[IP].ihl == 5
                    assert pkt[IP].len == int.from_bytes(data[off - 10 : off - 8], "big")
                    tcp_start = off + 8
                else:
                    assert IP not in pkt and IPv6 in pkt
                    assert pkt[IPv6].plen == int.from_bytes(data[off - 4 : off - 2], "big")
                    tcp_start = off + 32
                if l4[0]:
                    assert pkt[TCP].dataofs * 4 == l4[7] - tcp_start
            if routing._lite_not_routing(record):
                counts["routing"] += 1
                assert not _routing_may_record(pkt), path.name
            if icmp._lite_not_icmp(record):
                counts["icmp"] += 1
                assert not _icmp_reads(pkt), path.name
            if arp._lite_no_arp(record):
                counts["arp"] += 1
                assert pkt.getlayer(ARP) is None, path.name
    assert all(counts.values()), counts


def test_icmpv6_records_are_dissected_whatever_lite_says(edge: list[Path]) -> None:
    """An ND message's Redirected Header option carries a whole packet that
    scapy finds TCP, IPv4 and ICMP layers in while the lite parser reports no
    TCP/UDP layer: every analysis here dissects ICMPv6 records itself."""
    hidden = 0
    for record in pcap_cache.iter_packets(edge[0], show_status=False, lite=True):
        pkt = record.materialize()
        if pkt.haslayer(ICMPv6NDOptRedirectedHdr):
            hidden += 1
            assert services._lite_l4(record) is UNSUPPORTED
            assert not routing._lite_not_routing(record)
            assert not icmp._lite_not_icmp(record)
            assert not arp._lite_no_arp(record)
    assert hidden == 7
