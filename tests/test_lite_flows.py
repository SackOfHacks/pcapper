"""The beacon, exfil and IP analyses read lite records from disk and account
plain TCP/UDP packets from their bytes: their results, and the state their
packet loops build, must equal the ones computed over scapy packets (in
memory), and every value they read from a record must be scapy's."""

from __future__ import annotations

import shutil
import struct
import sys
from collections import defaultdict
from pathlib import Path

import pytest

pytest.importorskip("scapy")

from scapy.all import (  # noqa: E402
    ARP,
    DNS,
    DNSQR,
    GRE,
    ICMP,
    IP,
    TCP,
    UDP,
    CookedLinux,
    Dot1AD,
    Dot1Q,
    Ether,
    ICMPv6DestUnreach,
    ICMPv6EchoRequest,
    ICMPv6ND_NS,
    IPv6,
    IPv6ExtHdrHopByHop,
    Raw,
    wrpcap,
)
from test_lite_it_paths import _frames as _it_frames  # noqa: E402

from pcapper import beacon, exfil, ips, pcap_cache, utils  # noqa: E402
from pcapper.lite import UNSUPPORTED, LitePacket  # noqa: E402
from pcapper.openvpn import is_openvpn_tcp_control  # noqa: E402

DATA = Path(__file__).parent / "data"

T0 = 1_700_000_000.0
MAC_A, MAC_B, MAC_GW = "00:11:22:33:44:55", "66:77:88:99:aa:bb", "02:00:00:00:00:01"
A, B, DNS_HOST = "10.0.0.1", "10.0.0.2", "10.0.0.53"
P, P2 = "8.8.8.8", "93.184.216.34"
A6, B6, P6 = "fd00::1", "fd00::2", "2001:4860:4860::8888"
# An OpenVPN-over-TCP control frame: u16 length, P_CONTROL_HARD_RESET_CLIENT_V2.
OPENVPN_RESET = struct.pack(">H", 14) + b"\x38" + b"\x11" * 8 + b"\x00" + b"\x00" * 4


def _patch_ip(frame: bytes, total: int, at: int = 14) -> bytes:
    """``frame`` with its IPv4 total length (header at ``at``) set to ``total``."""
    return frame[: at + 2] + struct.pack(">H", total) + frame[at + 4 :]


class _Flows:
    """Ethernet frames with increasing timestamps; short ones padded to 60
    bytes, with zeros or (to catch a payload read into it) with bytes that
    are not zero."""

    def __init__(self) -> None:
        self.frames: list = []
        self.t = T0

    def add(self, frame, dt: float = 1.0, zero_pad: bool = False) -> None:  # type: ignore[no-untyped-def]
        data = frame if isinstance(frame, bytes) else bytes(frame)
        if len(data) < 60:
            data += bytes(60 - len(data)) if zero_pad else bytes(range(1, 61 - len(data)))
        self.t += dt
        pkt = Ether(data)
        pkt.time = self.t
        self.frames.append(pkt)


def _flow_frames() -> list:
    f = _Flows()
    ab, ba = Ether(src=MAC_A, dst=MAC_GW), Ether(src=MAC_GW, dst=MAC_A)
    # A reconnect-per-check-in beacon to a public host: handshake, request,
    # reply and close, a minute apart (scored as one periodic session).
    for i in range(22):
        cport = 50000 + i
        f.add(ab / IP(src=A, dst=P) / TCP(sport=cport, dport=8080, flags="S"), 60.0 + (i % 3) * 0.2, True)
        f.add(ba / IP(src=P, dst=A) / TCP(sport=8080, dport=cport, flags="SA"), 0.01)
        f.add(ab / IP(src=A, dst=P) / TCP(sport=cport, dport=8080, flags="A"), 0.01)
        f.add(ab / IP(src=A, dst=P) / TCP(sport=cport, dport=8080, flags="PA") / Raw(b"POST /gate HTTP/1.1\r\nHost: c2\r\n\r\nid=1"), 0.01)
        f.add(ba / IP(src=P, dst=A) / TCP(sport=8080, dport=cport, flags="PA") / Raw(b"HTTP/1.1 200 OK\r\n\r\nok"), 0.01)
        f.add(ab / IP(src=A, dst=P) / TCP(sport=cport, dport=8080, flags="FA"), 0.01, i % 2 == 0)
    # Heartbeats over one persistent IPv6 connection (request basis), and
    # periodic datagrams to a public host.
    f.add(Ether(src=MAC_A, dst=MAC_GW) / IPv6(src=A6, dst=P6) / TCP(sport=40100, dport=9001, flags="S"))
    f.add(Ether(src=MAC_GW, dst=MAC_A) / IPv6(src=P6, dst=A6) / TCP(sport=9001, dport=40100, flags="SA"), 0.01)
    for i in range(30):
        f.add(Ether(src=MAC_A, dst=MAC_GW) / IPv6(src=A6, dst=P6) / TCP(sport=40100, dport=9001, flags="PA") / Raw(b"ping %d" % i), 30.0)
        f.add(Ether(src=MAC_GW, dst=MAC_A) / IPv6(src=P6, dst=A6) / TCP(sport=9001, dport=40100, flags="A"), 0.01)
    for i in range(25):
        f.add(ab / IP(src=A, dst=P2) / UDP(sport=40001, dport=9999) / Raw(b"beat"), 30.0, i % 2 == 0)
        f.add(ab / IP(src=A, dst=P2) / UDP(sport=123, dport=40002) / Raw(b"\x00" * 48), 0.5)
    # NTP (scapy dissects it), DNS out and in, DNS and Kerberos over TCP
    # (an app layer behind the only TCP header), empty and with data.
    f.add(ab / IP(src=A, dst=P) / UDP(sport=40003, dport=123) / Raw(b"\x1b" + b"\x00" * 47))
    f.add(ab / IP(src=A, dst=P) / UDP(sport=40004, dport=53) / DNS(rd=1, qd=DNSQR(qname="a" * 40 + ".example.com")))
    f.add(ab / IP(src=A, dst=DNS_HOST) / UDP(sport=40005, dport=53) / DNS(rd=1, qd=DNSQR(qname="intranet.local")))
    f.add(ab / IP(src=DNS_HOST, dst=A) / UDP(sport=53, dport=40005) / DNS(qr=1, qd=DNSQR(qname="intranet.local")))
    for dst in (P, B):
        f.add(ab / IP(src=A, dst=dst) / TCP(sport=40006, dport=53, flags="S"), zero_pad=True)
        f.add(ab / IP(src=A, dst=dst) / TCP(sport=40007, dport=88, flags="PA") / Raw(b"\x00\x00\x00\x10" + b"\x6a" * 16))
        f.add(ab / IP(src=A, dst=dst) / TCP(sport=40008, dport=2000, flags="PA") / Raw(b"\x04\x00\x00\x00" * 3))
    f.add(ab / IPv6(src=A6, dst=P6) / TCP(sport=40009, dport=88, flags="S"))
    f.add(ab / IPv6(src=A6, dst=P6) / UDP(sport=40010, dport=53) / DNS(rd=1, qd=DNSQR(qname="v6.example.com")))
    # WebSocket upgrades leaving the network, on unbound ports and on 80.
    for port, text in (
        (8081, b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"),
        (80, b"GET /chat HTTP/1.1\r\nSec-WebSocket-Key: dGhlIHNhbXBsZQ==\r\n\r\n"),
        (8082, b"Upgrade"),  # short: the padding behind it is read as well
    ):
        f.add(ab / IP(src=A, dst=P2) / TCP(sport=40011, dport=port, flags="PA") / Raw(text))
    f.add(ab / IPv6(src=A6, dst=P6) / TCP(sport=40012, dport=8081, flags="PA") / Raw(b"upgrade: WebSocket\r\n"))
    # OpenVPN over TCP, leaving and inside the network.
    f.add(ab / IP(src=A, dst=P) / TCP(sport=40013, dport=1194, flags="PA") / Raw(OPENVPN_RESET))
    f.add(ab / IP(src=A, dst=B) / TCP(sport=40014, dport=1194, flags="PA") / Raw(OPENVPN_RESET))
    # OT and management ports, a port 0 and equal ports.
    for port in (502, 44818, 2404, 20000, 102, 22, 3389, 5985, 5900):
        f.add(ab / IP(src=A, dst=B) / TCP(sport=40015, dport=port, flags="PA") / Raw(b"\x00\x01\x00\x00\x00\x06\x01\x03"))
        f.add(Ether(src=MAC_B, dst=MAC_A) / IP(src=B, dst=A) / TCP(sport=port, dport=40015, flags="A"))
    f.add(ab / IP(src=A, dst=B) / UDP(sport=47808, dport=47808) / Raw(b"\x81\x0b\x00\x0c"))
    f.add(ab / IP(src=A, dst=P) / TCP(sport=22, dport=0, flags="RA"))
    f.add(ab / IP(src=A, dst=B) / TCP(sport=5000, dport=5000, flags="PA") / Raw(b"same ports"))
    f.add(ab / IP(src=A, dst=A) / TCP(sport=40016, dport=80, flags="S"))
    f.add(Ether(src="00:00:00:00:00:00", dst=MAC_B) / IP(src=A, dst=B) / TCP(sport=40017, dport=80, flags="S"))
    # Broadcast and multicast destinations.
    f.add(ab / IP(src=A, dst="10.0.0.255") / UDP(sport=40018, dport=9) / Raw(b"wake"))
    f.add(Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / Raw(b"\x01" * 40))
    f.add(Ether(src=MAC_A, dst="01:00:5e:00:00:fb") / IP(src=A, dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(qd=DNSQR(qname="printer.local")))
    f.add(Ether(src=MAC_A, dst="33:33:00:00:00:fb") / IPv6(src=A6, dst="ff02::fb") / UDP(sport=5353, dport=5353) / Raw(b"\x00" * 12))
    # Header arithmetic: an IPv4 total length of 0 (segmentation offload),
    # below the header size, beyond the captured bytes; TCP options; NS.
    seg = bytes(ab / IP(src=A, dst=P) / TCP(sport=40019, dport=8080, flags="PA") / Raw(b"offloaded" * 30))
    f.add(_patch_ip(seg, 0))
    f.add(_patch_ip(bytes(ab / IP(src=A, dst=B) / TCP(sport=40020, dport=8080, flags="PA") / Raw(b"short")), 10))
    f.add(_patch_ip(bytes(ab / IP(src=A, dst=B) / TCP(sport=40021, dport=8080, flags="PA") / Raw(b"cut")), 1500))
    f.add(ab / IP(src=A, dst=B) / TCP(sport=40022, dport=8080, flags="PA", options=[("MSS", 1460), ("NOP", None), ("WScale", 7)]) / Raw(b"opts"))
    f.add(ab / IP(src=A, dst=B) / TCP(sport=40023, dport=8080, flags=0x1C2))
    f.add(ab / IP(src=A, dst=B, flags="MF") / TCP(sport=40024, dport=8080, flags="PA") / Raw(b"first fragment"))
    f.add(ab / IPv6(src=A6, dst=B6, plen=20) / TCP(sport=40025, dport=8080, flags="A") / Raw(b"tail"))
    f.add(bytes(ab / IPv6(src=A6, dst=B6, plen=200) / TCP(sport=40026, dport=8080, flags="PA") / Raw(b"cut v6")))
    f.add(bytes(ab / IP(src=A, dst=B) / TCP(sport=40027, dport=8080, dataofs=15) / Raw(b"x" * 8)))
    # VLAN and QinQ tags.
    f.add(Ether(src=MAC_A, dst=MAC_B) / Dot1Q(vlan=10) / IP(src=A, dst=B) / TCP(sport=40028, dport=502, flags="PA") / Raw(b"\x00\x01"))
    f.add(Ether(src=MAC_A, dst=MAC_B) / Dot1AD(vlan=20) / Dot1Q(vlan=30) / IP(src=A, dst=P) / UDP(sport=40029, dport=9999) / Raw(b"qinq"))
    # Neither TCP nor UDP: ICMP out and in, a fragment, IGMP, a GRE tunnel,
    # ICMPv6, an IPv6 extension header.
    f.add(ab / IP(src=A, dst=P) / ICMP() / Raw(b"\x00" * 200))
    f.add(ab / IP(src=A, dst=P) / ICMP(type=13))
    f.add(ab / IP(src=A, dst=B) / ICMP() / Raw(b"ping"))
    f.add(ab / IP(src=B, dst=A) / ICMP(type=3, code=3) / IP(src=A, dst=B) / UDP(sport=40030, dport=9))
    f.add(ab / IP(src=A, dst=B, frag=185, proto=6) / Raw(b"\x00" * 40))
    f.add(ab / IP(src=A, dst=P, frag=185, proto=6) / Raw(b"\x00" * 40))
    f.add(Ether(src=MAC_A, dst="01:00:5e:00:00:16") / IP(src=A, dst="224.0.0.22", proto=2) / Raw(b"\x22\x00\xfa\x02"))
    f.add(ab / IP(src=A, dst=B) / GRE() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=40031, dport=80, flags="S"))
    f.add(ab / IPv6(src=A6, dst=P6) / ICMPv6EchoRequest(data=b"x" * 20))
    f.add(Ether(src=MAC_A, dst="33:33:ff:00:00:02") / IPv6(src=A6, dst="ff02::1:ff00:2") / ICMPv6ND_NS(tgt=B6))
    f.add(ab / IPv6(src=B6, dst=A6) / ICMPv6DestUnreach() / IPv6(src=A6, dst=B6) / UDP(sport=40032, dport=9))
    f.add(ab / IPv6(src=A6, dst=B6) / IPv6ExtHdrHopByHop() / TCP(sport=40033, dport=80, flags="S"))
    # ARP, and frames with no IP layer at all.
    f.add(Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=MAC_A, psrc=A, pdst=B))
    f.add(Ether(src=MAC_B, dst=MAC_A) / ARP(op=2, hwsrc=MAC_B, psrc=B, hwdst=MAC_A, pdst=A))
    f.add(Ether(src=MAC_A, dst=MAC_B) / ARP(op=2, hwsrc=MAC_A, psrc=A, hwdst=MAC_B, pdst=P))
    for i in range(3):
        f.add(Ether(src=MAC_A, dst=MAC_B, type=0x8892) / Raw(b"\x80\x00" + bytes(40)), 2.0)
        f.add(Ether(src=MAC_A, dst="01:80:c2:00:00:0e", type=0x88CC) / Raw(bytes(30)))
        f.add(Ether(src=MAC_A, dst="01:0c:cd:01:00:01", type=0x88B8) / Raw(bytes(30)))
        f.add(Ether(src=MAC_A, dst=MAC_B, type=0x9000) / Raw(bytes(30)))
    return f.frames


def _edge_frames() -> list:
    frames = _it_frames()
    for i, frame in enumerate(frames):
        frame.time = T0 - 1000 + i
    return frames + _flow_frames()


def _sll_frames() -> list:
    """Linux cooked capture: no Ethernet layer to read MACs from."""
    head = dict(pkttype=0, lladdrtype=1, lladdrlen=6, src=b"\x00\x11\x22\x33\x44\x55\x00\x00")
    frames = [
        CookedLinux(proto=0x0800, **head) / IP(src=A, dst=P) / TCP(sport=40100, dport=8080, flags="S"),
        CookedLinux(proto=0x0800, **head) / IP(src=P, dst=A) / TCP(sport=8080, dport=40100, flags="SA"),
        CookedLinux(proto=0x0800, **head) / IP(src=A, dst=P) / TCP(sport=40100, dport=8080, flags="PA") / Raw(b"Upgrade: websocket"),
        CookedLinux(proto=0x86DD, **head) / IPv6(src=A6, dst=B6) / UDP(sport=40101, dport=9999) / Raw(b"v6"),
        CookedLinux(proto=0x0800, **head) / IP(src=A, dst=B) / UDP(sport=40102, dport=53) / DNS(qd=DNSQR(qname="sll.local")),
        CookedLinux(proto=0x0800, **head) / IP(src=A, dst=P) / ICMP() / Raw(b"\x00" * 150),
        CookedLinux(proto=0x0806, **head) / ARP(op=1, hwsrc=MAC_A, psrc=A, pdst=B),
        CookedLinux(proto=0x88CC, **head) / Raw(bytes(20)),
    ]
    for i, frame in enumerate(frames):
        frame.time = T0 + i
    return frames


def _raw_ip_frames() -> list:
    frames = [
        IP(src=A, dst=P) / TCP(sport=40200, dport=8080, flags="S"),
        IP(src=A, dst=P) / TCP(sport=40200, dport=8080, flags="PA") / Raw(b"GET / HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"),
        IPv6(src=A6, dst=P6) / TCP(sport=40201, dport=22, flags="PA") / Raw(b"SSH-2.0-x\r\n"),
        IP(src=A, dst=B) / UDP(sport=40202, dport=502) / Raw(b"\x00\x01"),
        IP(src=A, dst=B) / ICMP(),
    ]
    for i, frame in enumerate(frames):
        frame.time = T0 + i
    return frames


@pytest.fixture()
def captures(tmp_path: Path) -> list[Path]:
    edge = tmp_path / "edge.pcap"
    wrpcap(str(edge), _edge_frames())
    sll = tmp_path / "sll.pcap"
    wrpcap(str(sll), _sll_frames(), linktype=113)
    raw_ip = tmp_path / "raw_ip.pcap"
    wrpcap(str(raw_ip), _raw_ip_frames(), linktype=101)
    paths = [edge, sll, raw_ip]
    for source in sorted(DATA.glob("*.pcap*")):
        target = tmp_path / source.name
        shutil.copy(source, target)
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


# What each packet loop builds: the locals initialised before it.
_LOOPS = {
    "beacon": (
        beacon,
        "analyze_beacons",
        (
            "udp_session_times", "udp_session_sizes", "udp_session_packets",
            "icmp_session_times", "icmp_session_sizes", "icmp_session_packets",
            "l2_session_times", "l2_session_sizes", "l2_session_packets",
            "conn_first_ts", "conn_syn_ts", "conn_first_idx", "conn_syn_idx",
            "conn_bytes", "conn_data_bytes", "conn_established", "conn_request_times",
            "conn_request_sizes", "conn_request_packets", "openvpn_conn_keys",
            "untracked_connections", "total_packets", "skipped_packets", "first_skip_error",
        ),
    ),
    "exfil": (
        exfil,
        "analyze_exfil",
        (
            "total_packets", "total_bytes", "outbound_bytes", "outbound_flow_bytes",
            "outbound_flow_packets", "outbound_flow_first", "outbound_flow_last",
            "outbound_port_bytes", "external_dsts", "internal_flow_bytes",
            "internal_flow_packets", "internal_flow_first", "internal_flow_last",
            "ot_flow_bytes", "ot_flow_packets", "ot_flow_first", "ot_flow_last",
            "remote_mgmt_bytes", "dns_query_counts", "dns_unique_queries", "dns_long_queries",
            "dns_entropy_total_by_src", "dns_max_label_by_src", "icmp_outbound_packets",
            "icmp_outbound_bytes", "icmp_large_payload_packets", "icmp_dst_counts",
            "ntp_outbound_packets", "ntp_outbound_bytes", "ntp_dst_counts",
            "websocket_handshakes", "first_seen", "last_seen", "skipped_packets",
            "first_skip_error",
        ),
    ),
    "ips": (
        ips,
        "analyze_ips",
        (
            "total_packets", "total_bytes", "protocol_counts", "src_counts", "dst_counts",
            "ip_category_counts", "ip_mac_counts", "ip_hostnames", "endpoints", "conversations",
            "unique_ips", "src_ips", "dst_ips", "ipv4_set", "ipv6_set", "src_to_ports",
            "src_to_dsts", "dst_to_ports", "dst_to_srcs", "syn_seen", "syn_ack_seen",
            "handshake_complete", "confirmed_tcp_service_ports", "tls_client_hellos",
            "ja3_counts", "ja4_counts", "ja4s_counts", "sni_counts", "sni_entropy",
            "tls_cert_risks", "cert_seen", "first_seen", "last_seen", "skipped_endpoints",
            "skipped_conversations", "skipped_packets", "first_skip_error",
        ),
    ),
}


def _loop_state(monkeypatch: pytest.MonkeyPatch, name: str, path: Path, **kwargs) -> dict:  # type: ignore[no-untyped-def]
    """The state ``name``'s packet loop built, read from the analysis' frame
    the moment its iter_packets() is exhausted (every value as its repr)."""
    module, func_name, names = _LOOPS[name]
    func = getattr(module, func_name).__wrapped__
    real = pcap_cache.iter_packets
    state: dict = {}

    def spy(*args, **kw):  # type: ignore[no-untyped-def]
        yield from real(*args, **kw)
        frame = sys._getframe(1)
        assert frame.f_code is func.__code__
        local = frame.f_locals
        for local_name in names:
            value = local[local_name]
            state[local_name] = repr(dict(value) if isinstance(value, defaultdict) else value)

    with monkeypatch.context() as patch:
        patch.setattr(module, "iter_packets", spy)
        utils.clear_analysis_memo()
        func(path, show_status=False, **kwargs)
    assert set(state) == set(names), path.name
    return state


_ANALYSES = [
    (beacon.analyze_beacons, {}),
    (beacon.analyze_beacons, {"min_events": 3}),
    (exfil.analyze_exfil, {}),
    (ips.analyze_ips, {}),
]


@pytest.mark.parametrize(
    "analyze,kwargs", _ANALYSES, ids=["beacon", "beacon-min3", "exfil", "ips"]
)
def test_from_disk_equals_scapy_packets(captures: list[Path], analyze, kwargs) -> None:  # type: ignore[no-untyped-def]
    for path in captures:
        utils.clear_analysis_memo()
        from_disk = analyze(path, show_status=False, **kwargs)
        packets, meta = pcap_cache.load_packets(path, show_status=False)
        assert packets and not isinstance(packets[0], LitePacket)
        utils.clear_analysis_memo()
        in_memory = analyze(path, show_status=False, packets=packets, meta=meta, **kwargs)
        assert repr(from_disk) == repr(in_memory), path.name  # same path: the whole summary


@pytest.mark.parametrize("name", sorted(_LOOPS))
def test_loop_state_from_disk_equals_scapy_packets(
    monkeypatch: pytest.MonkeyPatch, captures: list[Path], name: str
) -> None:
    """Summaries keep only part of what the loops count (beacon reports the
    flows that score, exfil the 15 largest): compare all of it."""
    for path in captures:
        from_disk = _loop_state(monkeypatch, name, path)
        packets, meta = pcap_cache.load_packets(path, show_status=False)
        in_memory = _loop_state(monkeypatch, name, path, packets=packets, meta=meta)
        for key in from_disk:
            assert from_disk[key] == in_memory[key], (path.name, key)


_SMALL_CAPS = {
    "beacon": {"MAX_TRACKED_CONNECTIONS": 5, "MAX_SESSION_SAMPLES": 3, "MAX_BEACON_PACKET_SAMPLES": 2},
    "exfil": {"_MAX_WEBSOCKET_HANDSHAKES": 1},
    "ips": {"MAX_ENDPOINTS": 4, "MAX_CONVERSATIONS": 6, "MAX_UNIQUE_IPS": 5, "MAX_SET_VALUES": 2},
}
_CAP_REACHED = {
    "beacon": lambda state: state["untracked_connections"] != "0",
    "exfil": lambda state: state["websocket_handshakes"].count("'marker'") == 1,
    "ips": lambda state: state["skipped_endpoints"] != "0" and state["skipped_conversations"] != "0",
}


@pytest.mark.parametrize("name", sorted(_LOOPS))
def test_loop_state_with_small_caps(
    monkeypatch: pytest.MonkeyPatch, captures: list[Path], name: str
) -> None:
    """The branches taken once a cap is reached (untracked connections,
    skipped endpoints, no more WebSocket payload reads ...) are the same."""
    module = _LOOPS[name][0]
    for attr, value in _SMALL_CAPS[name].items():
        assert hasattr(module, attr), attr
        monkeypatch.setattr(module, attr, value)
    for path in captures[:3]:
        from_disk = _loop_state(monkeypatch, name, path)
        packets, meta = pcap_cache.load_packets(path, show_status=False)
        in_memory = _loop_state(monkeypatch, name, path, packets=packets, meta=meta)
        for key in from_disk:
            assert from_disk[key] == in_memory[key], (path.name, key)
        if path is captures[0]:
            assert _CAP_REACHED[name](from_disk)


def test_the_edge_captures_reach_every_path(captures: list[Path]) -> None:
    """Records each fast path answers (Raw and app-layer payloads, padding,
    both IP versions) and records it hands to scapy."""
    kinds = set()
    openvpn = False
    for path in captures[:3]:
        for record in pcap_cache.iter_packets(path, show_status=False, lite=True):
            l3, l4 = record.headers()[1], record.lite_l4()
            src, dst = utils.extract_packet_endpoints(record)
            if src and dst and utils.is_valid_ip(dst) and not utils.is_unicast_host_ip(dst):
                kinds.add("beacon-skips-" + ("tcp/udp" if isinstance(l4, tuple) else "other"))
            if l4 is UNSUPPORTED:
                kinds.add("unsupported")
            elif l4 is None:
                kinds.add("no-l3" if l3 is None else f"no-l4/{l3 if l3 is UNSUPPORTED else l3[0]}")
            else:
                kind = f"{'tcp' if l4[0] else 'udp'}/v{l3[0]}"
                if l4[5] < 0:
                    kinds.add(kind + "/app")
                else:
                    kinds.add(kind + ("/raw" if l4[6] > l4[5] else "/empty"))
                    if len(record.original) > l4[6]:
                        kinds.add(kind + "/padded")
                flow = beacon._lite_flow(record)
                if flow is None:
                    kinds.add("beacon-dissects-" + kind)
                elif flow[2] and flow[6] and is_openvpn_tcp_control(record.original[flow[7] :][: flow[6]]):
                    openvpn = True
            if record.lite_first_ether() is None:
                kinds.add("no-ether")
    assert openvpn
    assert {
        "unsupported", "no-l3", "no-l4/4", "no-l4/6", "no-l4/1", "no-ether",
        "tcp/v4/raw", "tcp/v4/empty", "tcp/v4/padded", "tcp/v6/raw", "tcp/v6/empty",
        "udp/v4/raw", "udp/v6/raw", "udp/v4/app", "udp/v6/app", "tcp/v4/app", "tcp/v6/app",
        "beacon-dissects-tcp/v4", "beacon-skips-tcp/udp", "beacon-skips-other",
    } <= kinds, kinds


def _check_record(record: LitePacket) -> None:
    """Every answer the three fast paths take from ``record`` is the one the
    scapy path reads from the dissected packet."""
    pkt = record.materialize()
    l3, l4 = record.headers()[1], record.lite_l4()
    tcp, udp = pkt.getlayer(TCP), pkt.getlayer(UDP)
    src, dst = utils.extract_packet_endpoints(record)
    if src and dst and utils.is_valid_ip(dst) and not utils.is_unicast_host_ip(dst):
        # beacon skips it: _flow_key gives it no key, whatever it carries.
        icmp = pkt.getlayer(ICMP) if tcp is None and udp is None else None
        layer = None if tcp is not None else udp
        assert beacon._flow_key(pkt, pkt.getlayer(Ether), tcp, layer, icmp) is None
    if l3 is None:  # ips skips it: no IP, IPv6 or ARP layer
        assert pkt.getlayer(IP) is None and pkt.getlayer(IPv6) is None and pkt.getlayer(ARP) is None
    if l4 is None:  # exfil: neither layer, so proto "IP" and no ports
        assert tcp is None and udp is None
    if l4 is None or l4 is UNSUPPORTED:
        return
    # The record's only TCP/UDP layer, right behind its first IPv4/IPv6 one.
    layer, other = (tcp, udp) if l4[0] else (udp, tcp)
    assert layer is not None and other is None
    assert (layer.sport, layer.dport) == (l4[1], l4[2])
    ip4, ip6 = pkt.getlayer(IP), pkt.getlayer(IPv6)
    if l3[0] == 4:
        assert ip4 is not None and (str(ip4.src), str(ip4.dst)) == record.lite_endpoints()
    else:
        assert ip4 is None and ip6 is not None
        assert (str(ip6.src), str(ip6.dst)) == record.lite_endpoints()
    assert utils.extract_packet_endpoints(pkt) == utils.extract_packet_endpoints(record)
    ether, eth = record.lite_first_ether(), pkt.getlayer(Ether)
    if ether is None:
        assert eth is None
    elif ether is not UNSUPPORTED:
        assert (str(eth.src), str(eth.dst)) == (ether[1], ether[2])
    if l4[0]:
        assert utils.tcp_flags_int(tcp.flags) == l4[4]
        if l4[5] >= 0:
            # exfil's WebSocket check reads it; ips looks for TLS layers.
            assert bytes(tcp.payload) == record.original[l4[7] :]
            for cls in (ips.TLSClientHello, ips.TLSServerHello, ips.TLSCertificate):
                assert pkt.getlayer(cls) is None
    elif l4[5] >= 0:
        assert udp.getlayer(exfil.DNS) is None  # exfil's DNS check
    flow = beacon._lite_flow(record)
    if flow is None:
        return
    # beacon: _flow_key's answer, the flags, the segment length and payload.
    src, dst = utils.extract_packet_endpoints(pkt)
    assert flow[:5] == (src, dst, l4[0], l4[1], l4[2])
    key = beacon._flow_key(pkt, eth, tcp, None if tcp is not None else udp, None)
    unicast = not (utils.is_valid_ip(dst) and not utils.is_unicast_host_ip(dst))
    if not unicast:
        assert key is None
    elif l4[0]:
        assert key == (src, dst, "TCP", l4[1], l4[2])
    else:  # the lower port alone: the fast path keys the session on min()
        lower = (None, l4[2]) if l4[1] > l4[2] else (l4[1], None)
        assert key == (src, dst, "UDP", *lower)
        assert [port for port in lower if port is not None] == [min(l4[1], l4[2])]
    if flow[2]:
        assert utils.tcp_flags_int(getattr(tcp, "flags", None)) == flow[5]
        seg_len = utils.tcp_segment_length(tcp, ip4 if ip4 is not None else ip6)
        assert seg_len is not None and seg_len == flow[6]
        if seg_len:
            payload = bytes(getattr(tcp, "payload", b"") or b"")[: int(seg_len)]
            assert payload == record.original[flow[7] : flow[7] + flow[6]]


def test_lite_answers_match_scapy_record_for_record(captures: list[Path]) -> None:
    checked = 0
    for path in captures:
        for record in pcap_cache.iter_packets(path, show_status=False, lite=True):
            _check_record(record)
            checked += 1
    assert checked > 500


def test_tcp_flags_of_every_value(tmp_path: Path) -> None:
    """The 9-bit flags value the lite parser reads is tcp_flags_int() of
    scapy's FlagValue, for every value, over IPv4 and IPv6, and the SYN /
    SYN-ACK / final-ACK tests ips makes on it agree."""
    eth = Ether(src=MAC_A, dst=MAC_B)
    frames = []
    for value in range(512):
        frames.append(eth / IP(src=A, dst=B) / TCP(sport=40000, dport=8080, flags=value))
        frames.append(eth / IPv6(src=A6, dst=B6) / TCP(sport=40000, dport=8080, flags=value) / Raw(b"x"))
    path = tmp_path / "flags.pcap"
    wrpcap(str(path), frames)
    seen = []
    for record in pcap_cache.iter_packets(path, show_status=False, lite=True):
        l4 = record.lite_l4()
        flags = record.materialize()[TCP].flags
        assert l4[4] == utils.tcp_flags_int(flags) == int(flags)
        for test in (ips._tcp_is_syn, ips._tcp_is_synack, ips._tcp_is_final_handshake_ack):
            assert test(l4[4]) == test(flags)
        flow = beacon._lite_flow(record)
        assert flow is not None and flow[5] == l4[4]
        seen.append(l4[4])
    assert sorted(seen) == sorted(list(range(512)) * 2)
