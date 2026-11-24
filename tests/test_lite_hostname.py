"""The hostname analysis reads lite records from disk and dissects only the
packets an extractor could find a name in: its result must equal the one
computed over scapy packets (in memory), record for record, with every filter
it takes."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

pytest.importorskip("scapy")

from scapy.all import (  # noqa: E402
    ARP,
    BOOTP,
    DHCP,
    DNS,
    DNSQR,
    DNSRR,
    ICMP,
    IP,
    LLC,
    SNAP,
    STP,
    TCP,
    UDP,
    CookedLinux,
    Dot1Q,
    Dot3,
    Ether,
    IPOption_RR,
    IPv6,
    Raw,
    wrpcap,
)

from pcapper import hostname, pcap_cache, utils  # noqa: E402
from pcapper.hostname import analyze_hostname  # noqa: E402
from pcapper.lite import UNSUPPORTED, LitePacket  # noqa: E402
from pcapper.ot_ports import OT_PORT_PROTOCOLS  # noqa: E402

DATA = Path(__file__).parent / "data"

A, B = "10.0.0.1", "10.0.0.2"
MAC_A, MAC_B, MAC_A2 = "00:11:22:33:44:55", "66:77:88:99:aa:bb", "00:11:22:33:44:66"


def _client_hello(name: bytes) -> bytes:
    """A TLS ClientHello carrying ``name`` in its SNI extension."""
    entry = b"\x00" + len(name).to_bytes(2, "big") + name
    names = len(entry).to_bytes(2, "big") + entry
    ext = b"\x00\x00" + len(names).to_bytes(2, "big") + names
    body = b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x00\x2f" + b"\x01\x00"
    body += len(ext).to_bytes(2, "big") + ext
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def _pad(frame, fill: bytes = b"") -> bytes:  # type: ignore[no-untyped-def]
    """The frame's bytes padded to 60 (``fill`` NUL bytes, or a non-zero run),
    or with ``fill`` appended as is when it is longer."""
    data = bytes(frame)
    if fill and fill.strip(b"\x00"):
        return data + fill
    if len(data) < 60:
        data += (b"\x00" * 60 if fill else bytes(range(1, 61)))[: 60 - len(data)]
    return data


def _frames() -> list:
    eth = Ether(src=MAC_A, dst=MAC_B)
    back = Ether(src=MAC_B, dst=MAC_A)
    nul = b"\x00"
    frames: list[bytes] = [
        # Empty segments: unpadded, NUL padding, non-zero padding, IPv6, VLAN.
        bytes(eth / IP(src=A, dst=B) / TCP(sport=40000, dport=80, flags="S")),
        _pad(back / IP(src=B, dst=A) / TCP(sport=80, dport=40000, flags="SA"), nul),
        _pad(eth / IP(src=A, dst=B) / TCP(sport=40000, dport=81, flags="S")),
        bytes(eth / IPv6(src="fe80::1", dst="fe80::2") / TCP(sport=40001, dport=22, flags="S")),
        _pad(eth / Dot1Q(vlan=7) / IP(src=A, dst=B) / TCP(sport=40002, dport=445, flags="R"), nul),
        _pad(eth / IP(src=A, dst=B) / UDP(sport=40003, dport=9999), nul),
        # The same IP from a second MAC; unspecified and multicast addresses.
        _pad(Ether(src=MAC_A2, dst=MAC_B) / IP(src=A, dst=B) / TCP(sport=40004, dport=81, flags="S"), nul),
        _pad(eth / IP(src="0.0.0.0", dst="224.0.0.251") / UDP(sport=40005, dport=40006), nul),
        # NUL-only payloads on ports with an extractor of their own.
        *[
            bytes(eth / IP(src=A, dst=B) / TCP(sport=40010, dport=port) / Raw(nul * size))
            for port, size in (
                (25, 8), (21, 48), (22, 12), (161, 64), (389, 9), (88, 20), (5060, 30),
                (3389, 46), (4840, 64), (34962, 12), (502, 16), (1900, 50), (80, 70),
                (8443, 100), (20000, 32), (2404, 3),
            )
        ],
        *[
            _pad(eth / IP(src=A, dst=B) / UDP(sport=40011, dport=port) / Raw(nul * size), nul)
            for port, size in ((1900, 60), (5060, 8), (4840, 1), (34964, 40), (47808, 13))
        ],
        # A name in the padding behind an empty segment: the payload read is
        # everything behind the TCP header, so it is found.
        _pad(eth / IP(src=A, dst=B) / TCP(sport=40020, dport=25, flags="A"), b"EHLO pad.example.com\r\n"),
        # An IP packet to CDP's multicast MAC (CDP reads the frame itself).
        _pad(Ether(src=MAC_A, dst="01:00:0c:cc:cc:cc") / IP(src=A, dst=B) / TCP(sport=40021, dport=82), nul),
        # Names the extractors find.
        bytes(eth / IP(src=A, dst=B) / TCP(sport=40030, dport=80) / Raw(b"GET / HTTP/1.1\r\nHost: web.example.com\r\n\r\n")),
        bytes(eth / IP(src=A, dst=B) / TCP(sport=40031, dport=8443) / Raw(_client_hello(b"sni.example.com"))),
        bytes(back / IP(src=B, dst=A) / TCP(sport=22, dport=40001) / Raw(b"SSH-2.0-OpenSSH_8.9 build.host.example\r\n")),
        bytes(eth / IP(src=A, dst=B) / TCP(sport=40032, dport=25) / Raw(b"EHLO mail.client.example\r\n")),
        bytes(
            back / IP(src=B, dst=A) / UDP(sport=53, dport=40033)
            / DNS(qr=1, qd=DNSQR(qname="dns.example.com"), an=DNSRR(rrname="dns.example.com", rdata="10.0.0.5"))
        ),
        bytes(
            Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67) / BOOTP(chaddr=bytes.fromhex("001122334455"))
            / DHCP(options=[("message-type", "request"), ("hostname", b"dhcp-host1"), "end"])
        ),
        bytes(Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=MAC_A, psrc=A, pdst=B)),
        _pad(back / ARP(op=2, hwsrc=MAC_B, psrc=B, hwdst=MAC_A, pdst=A), nul),
        bytes(eth / IP(src=A, dst=B) / ICMP() / Raw(b"GET / HTTP/1.1\r\nHost: icmp.example.com\r\n\r\n")),
        # What only scapy answers: IP options, an ICMP error, 802.3/LLC.
        _pad(eth / IP(src=A, dst=B, options=[IPOption_RR()]) / TCP(sport=40040, dport=80, flags="S"), nul),
        bytes(back / IP(src=B, dst=A) / ICMP(type=3, code=3) / IP(src=A, dst=B) / UDP(sport=40041, dport=9)),
        _pad(Dot3(src=MAC_A, dst="01:80:c2:00:00:00") / LLC() / STP(), nul),
        _pad(eth / Dot1Q(vlan=9, type=0x32) / LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(OUI=0x0C, code=0x10B) / STP(), nul),
        # UDP with a short length field: the bytes past it are padding.
        _pad(eth / IP(src=A, dst=B) / UDP(sport=40042, dport=5000, len=8) / Raw(b"host=udp.example"), nul),
        _pad(eth / IP(src=A, dst=B) / UDP(sport=40043, dport=5000, len=10) / Raw(nul * 9), nul),
    ]
    return [Ether(data) for data in frames]


def _cooked_frames() -> list:
    """Linux cooked capture: no Ethernet layer, so no MAC to learn."""
    sll = CookedLinux(pkttype=0, lladdrtype=1, lladdrlen=6, src=bytes.fromhex("001122334455") + b"\x00\x00")
    frames = [
        sll / IP(src=A, dst=B) / TCP(sport=40050, dport=80, flags="S"),
        sll / IP(src=A, dst=B) / TCP(sport=40050, dport=80) / Raw(b"GET / HTTP/1.1\r\nHost: sll.example.com\r\n\r\n"),
        sll / IP(src=A, dst=B) / UDP(sport=40051, dport=9999) / Raw(b"\x00" * 4),
    ]
    return [CookedLinux(bytes(frame)) for frame in frames]


@pytest.fixture()
def captures(tmp_path: Path) -> list[Path]:
    edge = tmp_path / "edge.pcap"
    wrpcap(str(edge), _frames())
    cooked = tmp_path / "cooked.pcap"
    wrpcap(str(cooked), _cooked_frames(), linktype=113)
    paths = [edge, cooked]
    for name in ("mixed.pcap", "mixed.pcapng", "http.pcap", "dns.pcap", "tls.pcap", "truncated.pcap", "voip_attack.pcap"):
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


_CALLS = {
    "all": (None, {}),
    "target": (A, {}),
    "target-related": (A, {"include_related": True}),
    "target-v6": ("fe80::2", {}),
    "port": (None, {"port_filter": 81}),
    "target-port-query": (B, {"port_filter": 25, "hostname_query": "example"}),
    "search-unfiltered": (A, {"search_query": "example", "apply_filters": False}),
}


@pytest.mark.parametrize("call", sorted(_CALLS))
def test_from_disk_equals_scapy_packets(captures: list[Path], call: str) -> None:
    target_ip, kwargs = _CALLS[call]
    for path in captures:
        utils.clear_analysis_memo()
        from_disk = analyze_hostname(path, target_ip, show_status=False, **kwargs)
        packets, meta = pcap_cache.load_packets(path, show_status=False)
        assert packets and not isinstance(packets[0], LitePacket)
        utils.clear_analysis_memo()
        in_memory = analyze_hostname(path, target_ip, show_status=False, packets=packets, meta=meta, **kwargs)
        assert repr(from_disk) == repr(in_memory), path.name  # the whole summary
        assert not from_disk.errors, path.name


def test_memo_bounds_change_nothing(captures: list[Path], monkeypatch: pytest.MonkeyPatch) -> None:
    """The lite path's memos (Ethernet answers, learnt IP<->MAC pairs) only
    save repeated work: emptied every few records, the result is the same."""
    monkeypatch.setattr(hostname, "_LITE_MEMO_MAX", 2)
    monkeypatch.setattr(hostname, "_LITE_LEARNT_MAX", 3)
    test_from_disk_equals_scapy_packets(captures, "all")
    test_from_disk_equals_scapy_packets(captures, "target")


def test_the_edge_capture_reaches_every_path(captures: list[Path]) -> None:
    """The edge capture holds records taken from their bytes -- with and
    without an Ethernet layer, padding NUL or absent, a NUL-only load -- and
    every kind that is dissected instead."""
    kinds = set()
    for path in captures[:2]:
        for record in pcap_cache.iter_packets(path, show_status=False, lite=True):
            quiet = hostname._lite_quiet_packet(record, {})
            l4 = record.lite_l4()
            if quiet is not None:
                data = record.original
                if l4[6] > l4[5]:
                    kinds.add("quiet:nul-load")
                else:
                    kinds.add("quiet:nul-padding" if len(data) > l4[7] else "quiet:bare")
                kinds.add("quiet:ether" if quiet[4] is not None else "quiet:no-ether")
            elif l4 is UNSUPPORTED:
                kinds.add("dissected:unsupported")
            elif l4 is None:
                kinds.add("dissected:no-l4")
            elif l4[5] < 0:
                kinds.add("dissected:app-layer")
            elif record.lite_first_ether() not in (None, UNSUPPORTED) and record.lite_first_ether()[2] == hostname.CDP_MULTICAST_MAC:
                kinds.add("dissected:cdp-mac")
            elif l4[6] > l4[5]:
                kinds.add("dissected:load")
            else:
                kinds.add("dissected:padding")
    assert kinds == {
        "quiet:nul-load", "quiet:nul-padding", "quiet:bare", "quiet:ether", "quiet:no-ether",
        "dissected:unsupported", "dissected:no-l4", "dissected:app-layer", "dissected:cdp-mac",
        "dissected:load", "dissected:padding",
    }


def test_quiet_records_read_like_scapy(captures: list[Path]) -> None:
    """For every record answered from its bytes: the addresses, ports and
    Ethernet MACs are scapy's (same text, also when the Ethernet answer comes
    from the memo), the payload the loop reads is empty or NUL bytes, and
    scapy built no layer an extractor reads."""
    from scapy.layers.dhcp6 import DHCP6OptClientFQDN
    from scapy.layers.tls.handshake import TLSCertificate, TLSClientHello

    checked = 0
    for path in captures:
        memo: dict = {}
        for record in pcap_cache.iter_packets(path, show_status=False, lite=True):
            quiet = hostname._lite_quiet_packet(record, memo)
            if quiet is None:
                continue
            checked += 1
            src_ip, dst_ip, sport, dport, ether = quiet
            pkt = record.materialize()
            ip_layer = pkt.getlayer(IP)
            ipv6_layer = pkt.getlayer(IPv6) if ip_layer is None else None
            arp_layer = pkt.getlayer(ARP)
            assert arp_layer is None
            assert hostname._extract_ip_pair(ip_layer, ipv6_layer, arp_layer) == (src_ip, dst_ip)
            assert utils.get_packet_ports(pkt)[:2] == (sport, dport)
            ether_layer = pkt.getlayer(Ether)
            if ether is None:
                assert ether_layer is None
            else:
                src_mac, dst_mac = getattr(ether_layer, "src", ""), getattr(ether_layer, "dst", "")
                assert type(src_mac) is str and type(dst_mac) is str
                assert (ether[1], ether[2]) == (src_mac, dst_mac)
                assert int(ether_layer.type) == ether[0] != hostname.LLDP_ETHERTYPE
                assert dst_mac != hostname.CDP_MULTICAST_MAC
            payload = hostname._extract_payload(pkt.getlayer(Raw), pkt.getlayer(TCP), pkt.getlayer(UDP))
            assert not payload.strip(b"\x00")
            assert utils.dns_message(pkt) is None
            for layer in (DHCP, "DHCP", BOOTP, DHCP6OptClientFQDN, TLSClientHello, TLSCertificate, "TLSCertificate", "NBNSHeader"):
                assert pkt.getlayer(layer) is None
    assert checked > 20


def test_addresses_and_macs_are_scapys_text(tmp_path: Path) -> None:
    """The MAC and address strings taken from the bytes equal scapy's
    ``Ether.src``/``.dst`` and ``IP``/``IPv6`` ``src``/``dst``: every byte
    value in every MAC position, IPv4 octets 0-255, and IPv6 zero runs,
    mapped and compatible forms."""
    v6 = [
        "::", "::1", "::ffff:10.0.0.1", "::10.0.0.1", "fe80::1:0:0:1", "2001:db8::",
        "1:0:0:1:0:0:0:1", "1:0:1:0:1:0:1:0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "64:ff9b::192.0.2.33", "0:0:0:0:0:1:0:0", "2001:db8:0:0:1::1",
    ]
    frames = []
    for value in range(256):
        src = ":".join("%02x" % ((value + i * 37) % 256) for i in range(6))
        dst = ":".join("%02x" % ((value * 7 + i) % 256) for i in range(6))
        octets = ".".join(str((value + i * 85) % 256) for i in range(4))
        frames.append(Ether(src=src, dst=dst) / IP(src=octets, dst=f"{value}.{255 - value}.0.{value}") / TCP(sport=40000 + value, dport=50000 + value, flags="S"))
    for addr in v6:
        frames.append(Ether(src=MAC_A, dst=MAC_B) / IPv6(src=addr, dst=v6[0] if addr != v6[0] else v6[1]) / UDP(sport=40000, dport=9999))
    path = tmp_path / "addresses.pcap"
    wrpcap(str(path), [Ether(bytes(frame)) for frame in frames])
    checked = 0
    memo: dict = {}
    for record in pcap_cache.iter_packets(path, show_status=False, lite=True):
        quiet = hostname._lite_quiet_packet(record, memo)
        assert quiet is not None
        assert quiet[4] == record.lite_first_ether()  # the memo's answer is lite's
        pkt = record.materialize()
        ether_layer = pkt.getlayer(Ether)
        assert quiet[4][1:3] == (ether_layer.src, ether_layer.dst)
        layer = pkt.getlayer(IP)
        if layer is None:
            layer = pkt.getlayer(IPv6)
        assert quiet[:2] == (str(layer.src), str(layer.dst))
        checked += 1
    assert checked == len(frames)


def _nul_capture(path: Path, ports: list[int], sizes: list[int]) -> Path:
    """TCP and UDP to and from ``ports`` carrying NUL-only loads of ``sizes``
    bytes, and empty segments with NUL padding of those sizes."""
    eth = Ether(src=MAC_A, dst=MAC_B)
    frames = []
    for port in ports:
        for sport, dport in ((port, 40000), (40000, port), (port, port)):
            for size in sizes:
                for transport in (TCP(sport=sport, dport=dport, flags="PA"), UDP(sport=sport, dport=dport)):
                    frames.append(eth / IP(src=A, dst=B) / transport / Raw(b"\x00" * size))
                    frames.append(Ether(bytes(eth / IP(src=A, dst=B) / transport) + b"\x00" * size))
    wrpcap(str(path), [Ether(bytes(frame)) for frame in frames])
    return path


def _gated_ports() -> list[int]:
    ports = {80, 443, 8443, 1194, 137, 5000, 40000}
    for name in dir(hostname):
        value = getattr(hostname, name)
        if name.endswith("_PORTS") and isinstance(value, (set, frozenset)):
            ports |= set(value)
    ports |= {4840, 34962, 34963, 34964, 502} | set(OT_PORT_PROTOCOLS)
    return sorted(ports)


def test_nul_payloads_hold_no_hostname(tmp_path: Path) -> None:
    """What lets the lite path skip a record: the unchanged loop, over the
    scapy packets of every record the lite path skips, finds nothing and
    raises nothing -- an empty or NUL-only payload, load or padding, on any
    port an extractor looks at, at the lengths the parsers branch on (a
    sample here; the full grid of 1-64, 128, 512, 1460, 2049 and 4100 bytes
    was checked when the skip was added) -- and learns only the MACs."""
    path = _nul_capture(tmp_path / "nul.pcap", _gated_ports(), [1, 3, 8, 12, 46, 64])
    records = list(pcap_cache.iter_packets(path, show_status=False, lite=True))
    memo: dict = {}
    quiet = [record.materialize() for record in records if hostname._lite_quiet_packet(record, memo) is not None]
    assert len(quiet) > len(records) * 0.8  # bound app layers (DNS, NBNS, SNMP ...) are dissected
    summary = analyze_hostname.__wrapped__(path, None, show_status=False, packets=quiet)
    assert summary.total_packets == len(quiet)
    assert not summary.findings and not summary.errors
    assert not summary.protocol_counts and not summary.method_counts and not summary.relevant_packets
    assert summary.ip_to_macs == {A: [MAC_A], B: [MAC_B]}
    # The whole capture, bound app layers included, from disk and in memory.
    packets, meta = pcap_cache.load_packets(path, show_status=False)
    utils.clear_analysis_memo()
    from_disk = analyze_hostname.__wrapped__(path, None, show_status=False)
    utils.clear_analysis_memo()
    in_memory = analyze_hostname.__wrapped__(path, None, show_status=False, packets=packets, meta=meta)
    assert repr(from_disk) == repr(in_memory)
