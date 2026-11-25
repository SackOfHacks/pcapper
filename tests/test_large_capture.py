"""Large-capture paths: lite records, windows, prefilters, shared passes, --jobs/--split.

Every fast path here promises the *same answer* as the scapy path it
replaces, so most tests compare the two directly on captures built to hit the
edge cases (VLAN stacks, IPv6 extension headers, IP options, fragments,
Ethernet padding, tunnels, ICMP errors, 802.3 frames, bound application
layers, pcapng interfaces and options, nanosecond and cooked captures).
"""

from __future__ import annotations

import contextlib
import importlib
import io
import os
import re
import sys
from pathlib import Path

import pytest
from scapy.all import (  # type: ignore
    ARP,
    DNS,
    DNSQR,
    GRE,
    ICMP,
    IP,
    LLC,
    SNAP,
    TCP,
    UDP,
    CookedLinux,
    Dot1AD,
    Dot1Q,
    Ether,
    IPv6,
    IPv6ExtHdrHopByHop,
    PcapNgWriter,
    PcapWriter,
    Raw,
    rdpcap,
    wrpcap,
)
from scapy.layers.vxlan import VXLAN  # type: ignore

from pcapper import cli, pcap_cache, sharedpass, utils
from pcapper.industrial_helpers import (
    _match_ethertype,
    _scapy_transport_record,
    _strip_padding,
)
from pcapper.lite import UNSUPPORTED
from pcapper.rawcap import LiteStream, estimate_packets, plan_windows
from pcapper.utils import _extract_packet_endpoints

MBAP_READ = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x02"
ETHERTYPES = (0x88AB, 0x8892, 0x88A4, 0x88B8, 0x88BA, 0x8100)


@pytest.fixture(autouse=True)
def _reset_large_capture_state():
    yield
    utils._FAN_OUT_HOOK = None
    sharedpass.set_jobs(1)
    pcap_cache._CAPTURE_WINDOWS.clear()
    pcap_cache._ESTIMATES.clear()
    pcap_cache._PACKET_CACHE.clear()
    utils.clear_analysis_memo()


def _edge_packets() -> list:
    base = 1_700_000_000
    pkts = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000, dport=502, flags="PA", seq=7) / MBAP_READ,
        Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=502, dport=40000, flags="A"),
        # 5-byte payload ending in 0x00 plus one byte of Ethernet padding
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40001, dport=502) / b"\x01\x00\x00\x00\x00",
        Ether() / Dot1Q(vlan=10) / IP(src="10.0.1.1", dst="10.0.1.2") / UDP(sport=40002, dport=20000) / b"\x05\x64\x05\xc0\x01\x00\x00\x04\xe9\x21",
        Ether() / Dot1AD(vlan=5) / Dot1Q(vlan=10) / IP(src="10.0.2.1", dst="10.0.2.2") / TCP(sport=40003, dport=102) / b"\x03\x00\x00\x07\x02\xf0\x80",
        Ether() / IPv6(src="fe80::1", dst="2001:db8::2") / TCP(sport=40004, dport=443) / b"\x16\x03\x01\x00\x05hello",
        Ether() / IPv6(src="fe80::1", dst="::ffff:1.2.3.4") / IPv6ExtHdrHopByHop() / UDP(sport=1, dport=53) / b"x",
        Ether() / IP(src="10.0.3.1", dst="10.0.3.2", options=b"\x94\x04\x00\x00") / TCP(dport=502) / MBAP_READ,
        Ether() / IP(src="10.0.4.1", dst="10.0.4.2", flags="MF", proto=6) / bytes(TCP(sport=40005, dport=502) / MBAP_READ)[:24],
        Ether() / IP(src="10.0.4.1", dst="10.0.4.2", frag=3, proto=6) / Raw(b"\x9c\x45\x01\xf6" + b"\x00" * 20),
        Ether() / ARP(psrc="10.0.5.1", pdst="10.0.5.2"),
        Ether() / IP(src="10.0.6.1", dst="10.0.6.2") / ICMP(type=3, code=3) / IP(src="10.0.6.2", dst="10.0.6.1") / TCP(sport=502, dport=40006),
        Ether() / IP(src="10.0.6.1", dst="10.0.6.2") / ICMP(type=8) / b"ping",
        Ether() / IP(src="10.0.7.1", dst="10.0.7.2") / GRE() / IP(src="192.168.0.1", dst="192.168.0.2") / TCP(dport=502) / MBAP_READ,
        Ether() / IP(src="10.0.8.1", dst="10.0.8.2") / UDP(sport=40007, dport=4789) / VXLAN() / Ether() / IP() / TCP(dport=502) / MBAP_READ,
        Ether(type=0x88B8) / Raw(b"\x00\x01\x00\x10" + b"\x61" * 12),
        Ether(type=0x8892) / Raw(b"\xfe\xfe\x05\x00" + b"\x00" * 30),
        Ether(type=0x88AB) / Raw(b"\x01\x02\x03\x04"),
        Ether(type=0x9100) / Raw(b"\x00\x0a\x88\xb8" + b"\x00" * 30),
        Ether() / LLC() / SNAP() / IP() / TCP(dport=502),
        Ether() / IP(src="10.0.9.1", dst="10.0.9.2") / UDP(sport=40008, dport=40009, len=4) / b"abcdefghijkl",
        Ether() / IP(src="10.0.9.1", dst="10.0.9.2", len=10) / TCP(dport=502) / b"x",
        Ether() / IP(src="10.0.9.1", dst="10.0.9.2") / TCP(dport=502, dataofs=15) / b"short",
        Ether() / IP(src="10.0.10.1", dst="10.0.10.2") / UDP(sport=40010, dport=53) / DNS(qd=DNSQR(qname="plc.example")),
        Ether() / IP(src="10.0.11.1", dst="10.0.11.2") / TCP(sport=40011, dport=1883, flags="PA") / b"\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\x00\x00",
    ]
    for index, pkt in enumerate(pkts):
        pkt.time = base + index + 0.000123
    return pkts


def _scapy_reference(packets_path: Path) -> list:
    reader = pcap_cache._open_single_capture(packets_path)
    try:
        return list(reader)
    finally:
        reader.close()


def _assert_lite_matches(packets_path: Path) -> int:
    reference = _scapy_reference(packets_path)
    lite = list(LiteStream(packets_path))
    assert len(lite) == len(reference)
    for index, (record, pkt) in enumerate(zip(lite, reference)):
        built = record.materialize()
        where = f"packet {index}: {pkt.summary()}"
        assert type(built) is type(pkt), where
        assert built.original == pkt.original, where
        assert built.time == pkt.time and type(built.time) is type(pkt.time), where
        for attr in ("wirelen", "comments", "direction", "process_information", "sniffed_on"):
            assert getattr(built, attr, None) == getattr(pkt, attr, None), f"{where}: {attr}"
        assert [layer.__name__ for layer in built.layers()] == [layer.__name__ for layer in pkt.layers()], where
        rec = _scapy_transport_record(pkt)
        lite_tr = record.lite_transport()
        if lite_tr is not UNSUPPORTED:
            if rec is None:
                assert lite_tr is None, where
            else:
                assert lite_tr is not None and lite_tr[:3] == tuple(rec[:3]), where
                if lite_tr[5] is not None:
                    assert lite_tr[5] == _strip_padding(rec[3].payload), where
                if rec[0]:
                    tcp = pkt.getlayer(TCP)
                    assert (lite_tr[3], lite_tr[4]) == (int(tcp.seq), int(tcp.flags)), where
        for include_arp in (True, False):
            lite_ep = record.lite_endpoints(include_arp)
            if lite_ep is not UNSUPPORTED:
                got = (lite_ep[0] or None, lite_ep[1] or None)
                assert got == _extract_packet_endpoints(pkt, include_arp=include_arp), where
        for ethertype in ETHERTYPES:
            lite_eth = record.lite_ether(ethertype)
            if lite_eth is UNSUPPORTED:
                continue
            match = _match_ethertype(pkt, ethertype)
            want = None if match is None else (match.src, match.dst, match.payload)
            assert lite_eth == want, f"{where}: ethertype {ethertype:#x}"
        # The only-transport answer: getlayer(TCP) and getlayer(UDP) agree
        # with it, and its bytes are what the own-loop analyzers read.
        l4 = record.lite_l4()
        if l4 is not UNSUPPORTED:
            tcp, udp = pkt.getlayer(TCP), pkt.getlayer(UDP)
            if l4 is None:
                assert tcp is None and udp is None, where
            else:
                layer, other = (tcp, udp) if l4[0] else (udp, tcp)
                assert layer is not None and other is None, where
                assert (int(layer.sport), int(layer.dport)) == (l4[1], l4[2]), where
                if l4[5] >= 0:
                    assert record.original[l4[7] :] == bytes(layer.payload), where
                    raw = pkt.getlayer(Raw)
                    assert (raw.load if raw is not None else b"") == record.original[l4[5] : l4[6]], where
        first = record.lite_first_ether()
        if first is not UNSUPPORTED:
            eth = pkt.getlayer(Ether)
            if first is None:
                assert eth is None, where
            else:
                assert first[:3] == (int(eth.type), eth.src, eth.dst), where
                if first[3] >= 0:
                    assert record.original[first[3] :] == bytes(eth.payload), where
    return len(lite)


def test_lite_records_match_scapy_on_edge_cases(tmp_path: Path) -> None:
    path = tmp_path / "edge.pcap"
    wrpcap(str(path), _edge_packets())
    assert _assert_lite_matches(path) == len(_edge_packets())


def test_lite_records_match_scapy_nanosecond_and_cooked(tmp_path: Path) -> None:
    nano = tmp_path / "nano.pcap"
    writer = PcapWriter(str(nano), nano=True)
    for pkt in _edge_packets():
        pkt.time = pkt.time + 0.000000789
        writer.write(pkt)
    writer.close()
    _assert_lite_matches(nano)
    cooked = tmp_path / "sll.pcap"
    wrpcap(
        str(cooked),
        [CookedLinux(proto=0x0800) / IP(src="10.1.0.1", dst="10.1.0.2") / TCP(dport=502) / MBAP_READ,
         CookedLinux(proto=0x86DD) / IPv6() / UDP(dport=20000) / b"\x05\x64"],
        linktype=113,
    )
    _assert_lite_matches(cooked)
    raw_ip = tmp_path / "raw.pcap"
    wrpcap(str(raw_ip), [IP(src="10.2.0.1", dst="10.2.0.2") / TCP(dport=502) / MBAP_READ], linktype=101)
    _assert_lite_matches(raw_ip)


def test_lite_records_match_scapy_pcapng_interfaces_and_options(tmp_path: Path) -> None:
    path = tmp_path / "multi.pcapng"
    writer = PcapNgWriter(str(path))
    for index, pkt in enumerate(_edge_packets()):
        pkt.sniffed_on = "eth0" if index < 10 else "eth1"
        pkt.comments = [b"analyst note"] if index == 12 else None
        writer.write(pkt)
    writer.close()
    _assert_lite_matches(path)


def _numbered_capture(path: Path, count: int, *, pcapng: bool = False) -> None:
    writer = PcapNgWriter(str(path)) if pcapng else PcapWriter(str(path))
    for index in range(count):
        pkt = Ether() / IP(src="10.9.0.1", dst="10.9.0.2") / UDP(sport=1024 + index % 50, dport=20000) / index.to_bytes(4, "big")
        pkt.time = 1_700_000_000 + index * 0.01
        if pcapng:
            pkt.sniffed_on = "eth0" if index < count // 2 else "eth1"
        writer.write(pkt)
    writer.close()


@pytest.mark.parametrize("pcapng", [False, True])
def test_windows_cover_every_record_exactly_once(tmp_path: Path, pcapng: bool) -> None:
    path = tmp_path / ("windows.pcapng" if pcapng else "windows.pcap")
    _numbered_capture(path, 3000, pcapng=pcapng)
    full = [(r.original, r.sniffed_on, r.time) for r in LiteStream(path)]
    windows = plan_windows(path, 5, min_packets=100)
    assert windows is not None and len(windows) == 5
    pieces = []
    for window in windows:
        pieces.extend((r.original, r.sniffed_on, r.time) for r in LiteStream(path, window))
    assert pieces == full  # interfaces declared mid-file are replayed per window
    assert sum(w.packets for w in windows) == len(full)


def test_estimate_packets_exact_for_small_capture(tmp_path: Path) -> None:
    path = tmp_path / "small.pcap"
    _numbered_capture(path, 500)
    assert estimate_packets(path) == 500


def test_prefilter_stats_report_every_record(tmp_path: Path) -> None:
    path = tmp_path / "edge.pcap"
    wrpcap(str(path), _edge_packets())
    stats = pcap_cache.PassStats()
    kept = list(pcap_cache.iter_packets(path, show_status=False, lite=True, prefilter=lambda r: False, stats=stats))
    reference = _scapy_reference(path)
    assert kept == []
    assert stats.active and stats.packets == len(reference)
    assert stats.bytes == sum(len(p.original) for p in reference)
    times = [p.time for p in reference]
    assert stats.first.time == times[0] and stats.last.time == times[-1]
    assert stats.earliest.time == min(times) and stats.latest.time == max(times)


def _render_steps(path: Path, flags: list[str], monkeypatch: pytest.MonkeyPatch, **env: str) -> str:
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(sys, "argv", ["pcapper", str(path), *flags, "--quiet", "--no-status"])
    utils.clear_analysis_memo()
    pcap_cache._PACKET_CACHE.clear()
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        cli.main()
    return buffer.getvalue()


def test_ot_analyzers_same_from_disk_and_memory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "edge.pcap"
    wrpcap(str(path), _edge_packets() * 3)
    flags = ["--modbus", "--dnp3", "--mqtt", "--s7", "--goose", "--profinet", "--powerlink"]
    memory = _render_steps(path, flags, monkeypatch)
    disk = _render_steps(path, flags, monkeypatch, PCAPPER_CACHE_ENABLED="0", PCAPPER_SHARED_PASS="0")
    shared = _render_steps(path, flags, monkeypatch, PCAPPER_CACHE_ENABLED="0", PCAPPER_SHARED_PASS="1")
    assert memory == disk == shared
    assert "MODBUS" in memory


def test_fan_out_shared_pass_matches_separate_reads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "edge.pcap"
    wrpcap(str(path), _edge_packets() * 4)
    separate = _render_steps(path, ["--ot-commands"], monkeypatch, PCAPPER_CACHE_ENABLED="0", PCAPPER_SHARED_PASS="0")
    opened = []
    real = LiteStream.__init__

    def _counting(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        opened.append(1)
        real(self, *args, **kwargs)

    monkeypatch.setattr(LiteStream, "__init__", _counting)
    shared = _render_steps(path, ["--ot-commands"], monkeypatch, PCAPPER_CACHE_ENABLED="0", PCAPPER_SHARED_PASS="1")
    assert shared == separate
    assert 0 < len(opened) <= 6  # a handful of shared reads, not one per analyzer


def test_planning_reads_nothing_from_the_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A shared pass plans by running each orchestrator over an empty packet
    view. The --files dpkt export read the capture from disk instead, once per
    call: 15 full reads on one core before a --threats run of a 6 GB capture
    started any analysis (21 for --compromised)."""
    import builtins

    from pcapper import compromised, overview, threats

    path = tmp_path / "web.pcap"
    body = b"GET /a.bin HTTP/1.1\r\nHost: example.test\r\n\r\n" + b"x" * 1400
    frames = [
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=40000 + i % 50, dport=80, flags="PA") / Raw(body)
        for i in range(2000)
    ]
    wrpcap(str(path), frames)
    roots = [(threats.analyze_threats, (), {}), (overview.analyze_overview, (), {}), (compromised.analyze_compromised, (), {})]
    sharedpass.discover(path, roots)  # also hashes the capture once (kept for the real run)

    target = os.path.realpath(path)
    read = [0]
    real_open = builtins.open

    class _Counting:
        def __init__(self, handle) -> None:  # type: ignore[no-untyped-def]
            self._handle = handle

        def read(self, *args):  # type: ignore[no-untyped-def]
            data = self._handle.read(*args)
            read[0] += len(data or b"")
            return data

        def readinto(self, buffer):  # type: ignore[no-untyped-def]
            count = self._handle.readinto(buffer) or 0
            read[0] += count
            return count

        def __iter__(self):  # type: ignore[no-untyped-def]
            for chunk in self._handle:
                read[0] += len(chunk)
                yield chunk

        def __enter__(self):  # type: ignore[no-untyped-def]
            self._handle.__enter__()
            return self

        def __exit__(self, *exc):  # type: ignore[no-untyped-def]
            return self._handle.__exit__(*exc)

        def __getattr__(self, name):  # type: ignore[no-untyped-def]
            return getattr(self._handle, name)

    def _open(file, *args, **kwargs):  # type: ignore[no-untyped-def]
        handle = real_open(file, *args, **kwargs)
        if isinstance(file, (str, os.PathLike)) and os.path.realpath(file) == target:
            return _Counting(handle)
        return handle

    monkeypatch.setattr(builtins, "open", _open)
    monkeypatch.setattr(io, "open", _open)
    plan = sharedpass.discover(path, roots)
    monkeypatch.undo()
    assert len(plan) > 50
    assert read[0] < 64 * 1024  # file-type checks only, not a read per call


def _build_in_shared_pass(path: Path, consumers: int, build) -> dict[str, list]:  # type: ignore[no-untyped-def]
    """Run ``consumers`` analyses in one shared pass over ``path``; each calls
    ``build`` on every (shared) scapy packet. Returns what each one got."""
    results: dict[str, list] = {}

    def _consumer(name: str):  # type: ignore[no-untyped-def]
        def _run(capture: Path) -> None:
            got = []
            for pkt in pcap_cache.iter_packets(capture, show_status=False):
                try:
                    got.append(build(pkt))
                except Exception as exc:  # noqa: BLE001 - the failure under test
                    got.append(repr(exc))
            results[name] = got

        _run.__qualname__ = name
        return _run

    session = sharedpass.prefetch(path, [(_consumer(f"consumer{i}"), (), {}) for i in range(consumers)])
    assert session is not None and session.rounds == 1  # one read, packets shared
    assert len(results) == consumers
    return results


def test_shared_pass_consumers_can_build_the_same_tls_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Building a scapy TLS/SSLv2 record clears and restores its byte cache and
    rewrites a field, so two consumers building one shared record at once got
    an exception ("DNP3: AttributeError: While building field 'msg': 'bytes'
    object has no attribute 'fields'" in a --threats report) or other bytes."""
    pytest.importorskip("cryptography")
    import scapy.layers.tls.record  # noqa: F401  (binds TCP/443 to TLS)
    from scapy.layers.tls.handshake_sslv2 import SSLv2ClientCertificate  # type: ignore

    cert, response = b"CERT", b"RESPONSE"
    message = bytes([8, 1]) + len(cert).to_bytes(2, "big") + len(response).to_bytes(2, "big") + cert + response
    payload = bytes([0x80, len(message)]) + message  # SSLv2 record: client certificate
    frame = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="10.0.0.1", dst="10.0.0.2")
    frame = frame / TCP(sport=50000, dport=443, flags="PA") / payload
    assert Ether(bytes(frame)).haslayer(SSLv2ClientCertificate)
    path = tmp_path / "sslv2.pcap"
    wrpcap(str(path), [frame] * 200)
    monkeypatch.setenv("PCAPPER_CACHE_ENABLED", "0")
    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)  # interleave the consumer threads as often as possible
    try:
        results = _build_in_shared_pass(path, 6, lambda pkt: bytes(pkt[TCP].payload))
    finally:
        sys.setswitchinterval(previous)
    assert all(got == [payload] * 200 for got in results.values())


def test_shared_pass_consumers_can_build_the_same_fcs_frame(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A trailer field (here an 802.15.4 FCS) swaps its layer's post_build
    method while the layer builds, so two overlapping builds of one shared
    frame (len(pkt), bytes(pkt)) returned 23 and 19 bytes for a 21-byte frame.
    The window is normally tiny, so the overlap is forced: two builds meet
    mid-build unless the lock keeps the second one out."""
    import threading

    from scapy.config import conf  # type: ignore
    from scapy.layers.dot15d4 import Dot15d4Data, Dot15d4FCS  # type: ignore

    monkeypatch.setattr(conf, "dot15d4_protocol", "sixlowpan")
    frame = Dot15d4FCS(fcf_frametype=1, seqnum=7) / Dot15d4Data(dest_panid=0x1234, dest_addr=1, src_addr=2)
    wire = bytes(frame / Raw(b"hello zigbee"))
    assert bytes(Dot15d4FCS(wire)) == wire
    path = tmp_path / "zigbee.pcap"
    wrpcap(str(path), [Dot15d4FCS(wire)] * 10)
    real = Dot15d4FCS.do_build_payload
    meet = threading.Barrier(2, timeout=0.2)

    def _meet_mid_build(self):  # type: ignore[no-untyped-def]
        try:
            meet.wait()  # between the FCS field and post_build
        except threading.BrokenBarrierError:
            pass  # builds of this frame take turns: no second one can get here
        return real(self)

    monkeypatch.setattr(Dot15d4FCS, "do_build_payload", _meet_mid_build)
    monkeypatch.setenv("PCAPPER_CACHE_ENABLED", "0")
    results = _build_in_shared_pass(path, 2, lambda pkt: (len(pkt), bytes(pkt)))
    assert all(got == [(len(wire), wire)] * 10 for got in results.values())


def test_build_guard_covers_the_changing_layers_during_a_shared_pass_only() -> None:
    """The lock goes on every TLS-family layer and every layer class with a
    trailer field, nowhere else, and is taken only while a shared pass runs."""
    pytest.importorskip("cryptography")
    from scapy.layers.dcerpc import DceRpc5  # type: ignore
    from scapy.layers.dot11 import Dot11FCS  # type: ignore
    from scapy.layers.dot15d4 import Dot15d4FCS  # type: ignore
    from scapy.layers.inet6 import ICMPv6DestUnreach  # type: ignore
    from scapy.layers.tls.session import _GenericTLSSessionInheritance  # type: ignore
    from scapy.packet import Packet  # type: ignore

    sharedpass._guard_scapy_builds()

    def guarded(method) -> bool:  # type: ignore[no-untyped-def]
        return bool(getattr(method, sharedpass._GUARD_MARK, False))

    for cls in (DceRpc5, Dot11FCS, Dot15d4FCS, ICMP, ICMPv6DestUnreach):
        assert guarded(cls.do_build), cls.__name__
    assert guarded(_GenericTLSSessionInheritance.__bytes__) and guarded(_GenericTLSSessionInheritance.do_build)
    assert not any(guarded(m) for m in (Packet.__bytes__, Packet.do_build, Ether.do_build, TCP.do_build))
    pkt = Ether(bytes(Ether() / IP() / ICMP(type=3, code=3) / IP() / UDP()))
    assert bytes(pkt) and sharedpass._BUILD_LOCK_KEY not in vars(pkt)  # no shared pass: no lock


_TLS_APP_DATA = bytes.fromhex("170303000a") + b"0123456789"  # TLS 1.2 application data record


def test_shared_pass_rebuilds_each_tls_record_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """scapy rebuilds a TLS record from its fields on every bytes() call, and
    ~30 analyzers call bytes() on each TCP payload. The consumers of a shared
    pass get the record's first rebuild instead of rebuilding it again."""
    pytest.importorskip("cryptography")
    from scapy.layers.tls.record import TLS  # type: ignore

    frame = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="10.0.0.1", dst="10.0.0.2")
    frame = frame / TCP(sport=50000, dport=443, flags="PA") / _TLS_APP_DATA
    assert type(Ether(bytes(frame))[TCP].payload) is TLS
    path = tmp_path / "tls.pcap"
    wrpcap(str(path), [frame] * 50)
    builds = []
    real = TLS.post_build

    def _counting(self, pkt, pay):  # type: ignore[no-untyped-def]
        builds.append(1)
        return real(self, pkt, pay)

    monkeypatch.setattr(TLS, "post_build", _counting)
    monkeypatch.setenv("PCAPPER_CACHE_ENABLED", "0")
    results = _build_in_shared_pass(path, 6, lambda pkt: bytes(pkt[TCP].payload))
    assert all(got == [_TLS_APP_DATA] * 50 for got in results.values())
    assert len(builds) == 50  # once per record, not once per consumer


def test_tls_rebuild_is_kept_only_for_an_unchanged_record(monkeypatch: pytest.MonkeyPatch) -> None:
    """The kept rebuild serves every later bytes() of a record dissected from
    a capture -- in a shared pass (under its lock) and between analyzers
    taking turns over packets in memory -- and not after the record changes."""
    pytest.importorskip("cryptography")
    from scapy.layers.tls.record import TLS, TLSApplicationData  # type: ignore

    sharedpass._guard_scapy_builds()
    record = TLS(_TLS_APP_DATA)
    assert bytes(record) == _TLS_APP_DATA and sharedpass._BUILT_KEY in vars(record)  # in memory, no shared pass
    assert bytes(record) == _TLS_APP_DATA
    record = TLS(_TLS_APP_DATA)
    monkeypatch.setattr(sharedpass, "_guarded_passes", 1)  # as while a shared pass runs
    assert bytes(record) == _TLS_APP_DATA and sharedpass._BUILT_KEY in vars(record)
    assert bytes(record) == _TLS_APP_DATA
    assert sharedpass._BUILT_KEY not in vars(record.copy())
    record.version = 0x0301
    assert bytes(record) == bytes.fromhex("170301000a") + b"0123456789"  # built again
    made = TLS(version=0x0303, msg=[TLSApplicationData(data=b"0123456789")])  # not from a capture
    assert bytes(made) == _TLS_APP_DATA and sharedpass._BUILT_KEY not in vars(made)


@pytest.mark.skipif(not sharedpass.parallel_available(), reason="needs fork()")
def test_jobs_output_identical(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "edge.pcap"
    wrpcap(str(path), _edge_packets() * 4)
    one = _render_steps(path, ["--ot-commands", "--modbus", "--dnp3"], monkeypatch, PCAPPER_CACHE_ENABLED="0")
    many = _render_steps(path, ["--ot-commands", "--modbus", "--dnp3", "--jobs", "3"], monkeypatch, PCAPPER_CACHE_ENABLED="0")
    assert many == one


@pytest.mark.skipif(not sharedpass.parallel_available(), reason="needs fork()")
def test_split_reports_each_window(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "numbered.pcap"
    _numbered_capture(path, 3000)  # window cuts snap to every 256th record
    monkeypatch.setattr(cli, "_MIN_WINDOW_PACKETS", 100)
    out = _render_steps(path, ["--dnp3", "--split", "3"], monkeypatch)
    plain = re.sub(r"\x1b\[[0-9;]*m", "", out)
    headers = re.findall(r"WINDOW (\d)/3\s+numbered\.pcap · packets ~([\d,]+)–([\d,]+)", plain)
    assert [h[0] for h in headers] == ["1", "2", "3"]
    assert headers[0][1] == "1" and headers[-1][2].rstrip(",") == "3,000"
    totals = [int(n) for n in re.findall(r"(\d+) DNP3 packets", out.replace(",", ""))]
    assert sum(totals) == 3000


def test_cache_respects_packet_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "small.pcap"
    _numbered_capture(path, 500)
    monkeypatch.setenv("PCAPPER_CACHE_MAX_PACKETS", "100")
    assert not pcap_cache.fits_in_memory(path)
    assert pcap_cache.load_packets_if_allowed(path, show_status=False) == (None, None)
    monkeypatch.setenv("PCAPPER_CACHE_MAX_PACKETS", "1000")
    assert pcap_cache.fits_in_memory(path)


def test_large_capture_note(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "small.pcap"
    _numbered_capture(path, 500)
    monkeypatch.setenv("PCAPPER_LARGE_CAPTURE_PACKETS", "100")
    monkeypatch.setenv("PCAPPER_CACHE_MAX_PACKETS", "100")
    cli._note_large_capture(path, jobs=1, multi_analyzer=True)
    assert capsys.readouterr().err == ""  # guidance is detail: -v only
    from pcapper import progress

    progress.set_verbose_progress(True)
    cli._note_large_capture(path, jobs=1, multi_analyzer=True)
    err = capsys.readouterr().err
    assert "Large capture: small.pcap" in err and "Too large to keep in memory" in err and "--jobs N" in err
    cli._note_large_capture(path, jobs=8, multi_analyzer=True)
    err = capsys.readouterr().err
    assert "Its analyses run in 8 processes" in err and "--jobs N" not in err and "--split N" in err
    # Kept in memory, a run never forks: the note must not claim processes.
    monkeypatch.setenv("PCAPPER_CACHE_MAX_PACKETS", "1000")
    cli._note_large_capture(path, jobs=8, multi_analyzer=True)
    err = capsys.readouterr().err
    assert "processes" not in err and "Too large" not in err
    # One dissection's time is what the run costs -- unless its analyses all
    # read lightweight records, which dissect only the packets they look at.
    assert "Dissecting it once takes" in err
    cli._note_large_capture(path, jobs=1, multi_analyzer=True, lite_only=True)
    err = capsys.readouterr().err
    assert "Dissecting it once would take" in err
    assert "this run's analyses dissect only the packets they look at." in err


def test_jobs_default_is_automatic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert cli.build_parser().parse_args(["x.pcap"]).jobs is None
    assert cli._resolve_jobs(None) is None
    assert cli._resolve_jobs(0) == (os.cpu_count() or 1)
    assert cli._resolve_jobs(-2) == 1 and cli._resolve_jobs(3) == 3
    path = tmp_path / "small.pcap"
    _numbered_capture(path, 500)
    sharedpass.set_jobs(None)
    assert sharedpass.jobs_for(path) == 1  # below the automatic threshold
    monkeypatch.setattr(sharedpass, "AUTO_JOBS_MIN_PACKETS", 100)
    assert 1 <= sharedpass.auto_jobs() <= sharedpass.AUTO_JOBS_MAX
    assert sharedpass.jobs_for(path) == (sharedpass.auto_jobs() if sharedpass.parallel_available() else 1)
    sharedpass.set_jobs(3)
    # An explicit --jobs always wins -- where processes can fork at all
    # (Windows has no fork: every plan runs in one process).
    assert sharedpass.jobs_for(path) == (3 if sharedpass.parallel_available() else 1)


def test_simple_step_table_matches_step_loop() -> None:
    """The steps a shared pass prefetches must call exactly
    analyze_x(path, show_status=..., packets=..., meta=...) in the step loop."""
    src = Path(cli.__file__).read_text()
    start = src.index("        for step in ordered_steps:")
    end = src.index("        if forced_view_for_path:", start)
    loop = src[start:end]
    marks = [(m.start(), m.group(1)) for m in re.finditer(r'step == "([a-z0-9_]+)"', loop)]
    simple = {}
    for index, (pos, step) in enumerate(marks):
        body = loop[pos : marks[index + 1][0] if index + 1 < len(marks) else len(loop)]
        calls = []
        for call in re.finditer(r"\b(analyze_[a-z0-9_]+)\(\s*((?:[^()]|\([^()]*\))*)\)", body, re.S):
            args = " ".join(call.group(2).split())
            positional = [a.strip() for a in args.split(",") if a.strip() and "=" not in a]
            keywords = set(re.findall(r"([a-z_]+)=", args))
            calls.append((call.group(1), positional == ["path"] and keywords <= {"show_status", "packets", "meta"}))
        if calls and all(ok for _name, ok in calls):
            simple.setdefault(step, tuple(name for name, _ok in calls))
    assert simple == cli._SIMPLE_STEP_ANALYZERS


def test_overview_from_disk_keeps_capture_metadata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """--overview of a capture read from disk handed its deep dives a dict as
    capture metadata (a shadowed variable): every one failed on .file_type."""
    path = tmp_path / "edge.pcap"
    wrpcap(str(path), _edge_packets() * 2)
    out = _render_steps(path, ["--overview"], monkeypatch, PCAPPER_CACHE_ENABLED="0", PCAPPER_SHARED_PASS="0")
    assert "file_type" not in out
    assert "Deep Dive Errors        : 0" in out or "Deep Dive Errors" not in out


# -- OT analyzers with their own packet loops ---------------------------------

_OWN_LOOP_ANALYZERS = (
    ("sv", "analyze_sv", "sv_packets"),
    ("goose", "analyze_goose", "goose_packets"),
    ("synchrophasor", "analyze_synchrophasor", "synchrophasor_packets"),
    ("safety", "analyze_safety", "tristation_frames"),
    ("opc_classic", "analyze_opc_classic", "opc_packets"),
    ("cip", "analyze_cip", "cip_packets"),
    ("enip", "analyze_enip", "enip_packets"),
    ("iec101_103", "analyze_iec101_103", "candidate_packets"),
    ("ptp", "analyze_ptp", "ptp_packets"),
    ("lldp_dcp", "analyze_lldp_dcp", "lldp_packets"),
)
_OWN_LOOP_FLAGS = [
    "--sv", "--goose", "--synchrophasor", "--safety", "--opc-classic",
    "--cip", "--enip", "--iec101-103", "--ptp", "--lldp",
]


def _lldp_payload() -> bytes:
    def tlv(kind: int, value: bytes) -> bytes:
        return ((kind << 9) | len(value)).to_bytes(2, "big") + value

    return (
        tlv(1, b"\x04" + bytes.fromhex("001122334455"))
        + tlv(2, b"\x05eth1")
        + tlv(3, b"\x00\x78")
        + tlv(5, b"SIMATIC S7-1500")
        + tlv(0, b"")
    )


def _ot_ip_packets() -> list:
    """IP-borne traffic for the own-loop OT analyzers, with the variants their
    lite paths must hand to scapy: a session on a port scapy dissects,
    Ethernet tunnelled inside IP, coalesced frames."""
    from test_cip_forensics import _request as _cip_request
    from test_enip_forensics import _encapsulation, _identity_cpf
    from test_iec101_103_forensics import _iec101_frame
    from test_ptp_forensics import _ptp_message
    from test_rgoose import _goose_pdu, _session
    from test_sv_forensics import _sv_payload
    from test_synchrophasor_forensics import _frame as _c37118
    from test_tristation import _cp_status_reply, _tcm, _ts

    from pcapper.goose import _l2_goose_payload

    plc, hmi, ews, sis = "10.20.0.10", "10.20.0.20", "192.168.1.88", "192.168.1.2"
    send_rr = b"\x00" * 6 + b"\x02\x00" + b"\x00\x00\x00\x00" + b"\xb2\x00"
    cip = _cip_request(b"\x20\x01\x24\x01\x30\x01")
    send_rr += len(cip).to_bytes(2, "little") + cip
    return [
        IP(src=hmi, dst=plc) / TCP(sport=40100, dport=4712, flags="PA") / (_c37118(0) + _c37118(4, command=1)),
        IP(src=plc, dst=hmi) / UDP(sport=4713, dport=40101) / _c37118(3),
        IPv6(src="fd00::1", dst="2001:db8::5") / TCP(sport=40102, dport=4712, flags="PA") / _c37118(4, command=2),
        IP(src=ews, dst=sis) / TCP(sport=33280, dport=1502, flags="PA") / _tcm(0x01),
        IP(src=ews, dst=sis) / UDP(sport=33279, dport=1502) / _ts(0, 0x41, 1, b"\x00" * 12),
        IP(src=sis, dst=ews) / UDP(sport=1502, dport=33279) / _cp_status_reply(1, 1),
        IP(src=hmi, dst=plc) / TCP(sport=40103, dport=44818, flags="PA") / _encapsulation(0x0065, b"\x01\x00\x00\x00"),
        IP(src=plc, dst=hmi) / TCP(sport=44818, dport=40103, flags="PA") / _encapsulation(0x0063, _identity_cpf()),
        IP(src=hmi, dst=plc) / TCP(sport=40103, dport=44818, flags="PA") / _encapsulation(0x006F, send_rr),
        IP(src=hmi, dst=plc) / TCP(sport=40104, dport=5555, flags="PA") / _encapsulation(0x0004),
        IP(src=hmi, dst=plc) / UDP(sport=2222, dport=2222) / (b"\x02\x00\x02\x80\x08\x00" + b"\x00" * 10),
        IP(src=hmi, dst=plc) / TCP(sport=40105, dport=2404, flags="PA") / (_iec101_frame(45, 6) + _iec101_frame(100, 6)),
        IP(src="10.30.0.1", dst="224.0.1.129") / UDP(sport=319, dport=319) / _ptp_message(0, 7),
        IP(src="10.30.0.1", dst="10.30.0.9") / UDP(sport=320, dport=320) / _ptp_message(0xD, 8),
        IP(src="10.100.3.30", dst="232.0.2.3") / UDP(sport=45477, dport=102) / _session(5, _goose_pdu(1, 0, True)),
        # scapy dissects port 53 as DNS: only the scapy packet has this payload
        IP(src="10.100.3.31", dst="232.0.2.3") / UDP(sport=53, dport=53) / _session(6, _goose_pdu(2, 0, False)),
        # Ethernet tunnelled in IP: getlayer(Ether) finds it even in a cooked
        # or raw-IP capture, which has no Ethernet header of its own
        IP(src="10.40.0.1", dst="10.40.0.2") / UDP(sport=40106, dport=4789) / VXLAN()
        / Ether(dst="01:0c:cd:01:00:09", type=0x88B8) / _l2_goose_payload(9, _goose_pdu(3, 0, True)),
        IP(src="10.40.0.1", dst="10.40.0.2") / GRE(proto=0x6558) / Ether(dst="01:0c:cd:04:00:09", type=0x88BA) / _sv_payload(),
        IP(src="10.40.0.1", dst="10.40.0.2") / GRE(proto=0x6558) / Ether(type=0x88CC) / _lldp_payload(),
    ]


def _ot_ether_packets(tmp_path: Path) -> list:
    from test_opc_classic_dcom import _build_capture
    from test_ptp_forensics import _ptp_message
    from test_rgoose import _goose_pdu
    from test_sv_forensics import _sv_payload

    from pcapper.goose import _l2_goose_payload

    goose = _l2_goose_payload(1, _goose_pdu(1, 0, True))
    dcp = b"\xfe\xfe\x05\x00\x00\x00\x00\x01\x00\x01\x00\x04\xff\xff\x00\x00"
    pkts = [Ether() / pkt for pkt in _ot_ip_packets()]
    pkts[0] = Ether() / Dot1Q(vlan=7) / pkts[0].payload
    pkts += [
        Ether(dst="01:0c:cd:04:00:01", type=0x88BA) / _sv_payload(),
        Ether(dst="01:0c:cd:04:00:01") / Dot1Q(vlan=4, type=0x88BA) / _sv_payload(),
        Ether(dst="01:0c:cd:04:00:01") / Dot1AD(vlan=3) / Dot1Q(vlan=4, type=0x88BA) / _sv_payload(),
        Ether(dst="00:11:22:33:44:55", type=0x88BA) / _sv_payload(declared_length=200),
        Ether(type=0x9100) / Raw(b"\x00\x04\x88\xba" + _sv_payload()),
        Ether(dst="01:0c:cd:01:00:01", type=0x88B8) / goose,
        Ether(dst="01:0c:cd:01:00:01") / Dot1Q(vlan=9, type=0x88B8) / goose,
        Ether(dst="01:1b:19:00:00:00", type=0x88F7) / _ptp_message(0, 9),
        Ether(dst="01:1b:19:00:00:00") / Dot1Q(vlan=2, type=0x88F7) / _ptp_message(8, 9),
        Ether(dst="01:80:c2:00:00:0e", type=0x88CC) / _lldp_payload(),
        Ether(dst="01:80:c2:00:00:0e") / Dot1Q(vlan=2, type=0x88CC) / _lldp_payload(),
        Ether(dst="01:0e:cf:00:00:00", type=0x8892) / dcp,
        # short frames a NIC padded to 60 bytes
        Ether(bytes(Ether() / IP(src="10.30.0.2", dst="224.0.1.129") / UDP(sport=319, dport=319) / _ptp_message(1, 3)) + b"\x00" * 6),
        Ether(bytes(Ether() / IP(src="10.20.0.20", dst="10.20.0.10") / TCP(sport=40107, dport=4712, flags="A")) + b"\x00" * 6),
    ]
    opc = tmp_path / "opc_part.pcap"
    _build_capture(opc)
    pkts += list(rdpcap(str(opc)))
    return pkts + _edge_packets()


def _write_ot_capture(tmp_path: Path, variant: str) -> Path:
    path = tmp_path / f"ot_{variant}.pcap"
    if variant == "ether":
        pkts, linktype = _ot_ether_packets(tmp_path), None
    elif variant == "cooked":
        pkts = [CookedLinux(proto=0x86DD if pkt.version == 6 else 0x0800) / pkt for pkt in _ot_ip_packets()]
        linktype = 113
    else:
        pkts, linktype = _ot_ip_packets(), 101
    for index, pkt in enumerate(pkts):
        pkt.time = 1_700_000_100 + index * 0.25
    if linktype is None:
        wrpcap(str(path), pkts)
    else:
        wrpcap(str(path), pkts, linktype=linktype)
    return path


@pytest.mark.parametrize("variant", ["ether", "cooked", "raw"])
def test_own_loop_ot_analyzers_same_from_disk_and_memory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str
) -> None:
    """Each analyzer reads lite records from disk (prefiltered, the totals from
    the pass) and scapy packets from memory: the summaries must be equal."""
    path = _write_ot_capture(tmp_path, variant)
    _assert_lite_matches(path)
    monkeypatch.setenv("PCAPPER_CACHE_ENABLED", "0")
    reference = _scapy_reference(path)
    seen = {}
    for module_name, func_name, counter in _OWN_LOOP_ANALYZERS:
        func = getattr(importlib.import_module(f"pcapper.{module_name}"), func_name)
        utils.clear_analysis_memo()
        disk = func(path, show_status=False)
        utils.clear_analysis_memo()
        memory = func(path, show_status=False, packets=reference)
        assert repr(disk) == repr(memory), module_name
        assert disk.total_packets == len(reference), module_name
        seen[module_name] = getattr(disk, counter)
    if variant == "ether":
        assert all(seen.values()), seen  # every analyzer had traffic to decode
    else:
        assert seen["goose"] and seen["sv"] and seen["synchrophasor"] and seen["cip"], seen


def test_own_loop_ot_flags_same_from_disk_memory_and_shared_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_ot_capture(tmp_path, "ether")
    memory = _render_steps(path, _OWN_LOOP_FLAGS, monkeypatch)
    disk = _render_steps(path, _OWN_LOOP_FLAGS, monkeypatch, PCAPPER_CACHE_ENABLED="0", PCAPPER_SHARED_PASS="0")
    shared = _render_steps(path, _OWN_LOOP_FLAGS, monkeypatch, PCAPPER_CACHE_ENABLED="0", PCAPPER_SHARED_PASS="1")
    assert memory == disk == shared


def _epl_pn_packets() -> list:
    def epl(mtype: int, dst: int, src: int, rest: bytes = b"") -> bytes:
        return bytes([mtype, dst, src]) + rest

    def nmt(cmd: int) -> bytes:
        return epl(0x06, 1, 240, bytes([4, cmd]) + b"\x00" * 10)

    pkts = []
    for i in range(24):
        pkts.append(Ether(src="02:00:00:00:00:f0", dst="01:11:1e:00:00:01", type=0x88AB) / epl(0x01, 255, 240))
        if i % 7 == 0:  # L2 and UDP NMT commands tie in count: first-seen order decides
            pkts.append(Ether(src="02:00:00:00:00:f0", type=0x88AB) / nmt(0x22 if i % 2 else 0x28))
        if i % 5 == 0:
            pkts.append(Ether() / IP(src="10.9.9.1", dst="10.9.9.2") / UDP(sport=3819, dport=3819) / nmt(0x28 if i % 2 else 0x22))
        if i % 9 == 0:
            pkts.append(Ether(src="02:00:00:00:00:aa", type=0x88AB) / epl(0x01, 255, 240))
            pkts.append(Ether(type=0x3E3F) / Raw(b"\x01\x02\x03\x04"))
        pkts.append(Ether(type=0x8892) / Raw(b"\x80\x00" + bytes(40)))
        if i % 6 == 0:
            pkts.append(Ether() / IP(src="10.8.8.1", dst="10.8.8.2") / UDP(sport=50000, dport=34964) / Raw(b"\x04\x00" + bytes(78)))
    for index, pkt in enumerate(pkts):
        pkt.time = 1_700_000_200 + index * 0.01
    return pkts


@pytest.mark.parametrize("module_name,func_name", [("powerlink", "analyze_powerlink"), ("profinet", "analyze_profinet")])
def test_multi_protocol_analyzers_read_once_and_match_memory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, module_name: str, func_name: str
) -> None:
    """POWERLINK (EtherType, UDP 3819, v1) and PROFINET (PNIO-CM ports, RT
    EtherType) analyse their protocols in one read instead of one each."""
    path = tmp_path / "epl_pn.pcap"
    wrpcap(str(path), _epl_pn_packets())
    func = getattr(importlib.import_module(f"pcapper.{module_name}"), func_name)
    monkeypatch.setenv("PCAPPER_CACHE_ENABLED", "0")
    opened = []
    real = LiteStream.__init__

    def _counting(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        opened.append(1)
        real(self, *args, **kwargs)

    monkeypatch.setattr(LiteStream, "__init__", _counting)
    utils.clear_analysis_memo()
    disk = func(path, show_status=False)
    assert len(opened) == 1
    monkeypatch.setattr(LiteStream, "__init__", real)
    # These take no packet list: give them the scapy packets as a forced view.
    pcap_cache.set_forced_packet_view(path, _scapy_reference(path))
    try:
        utils.clear_analysis_memo()
        memory = func(path, show_status=False)
    finally:
        pcap_cache.clear_forced_packet_view(path)
    assert repr(disk) == repr(memory)
    assert disk.protocol_packets > 0


def test_epl_state_absorb_matches_one_state_fed_in_order() -> None:
    from pcapper.powerlink import _EplState

    frames = [
        (bytes([0x06, 1, 240, 4, 0x28]), "a"), (bytes([0x06, 1, 240, 4, 0x22]), "b"),
        (bytes([0x06, 2, 240, 4, 0x22]), "a"), (bytes([0x01, 255, 240]), "mn1"),
    ]
    later = [
        (bytes([0x06, 1, 240, 4, 0x2B]), "c"), (bytes([0x06, 1, 240, 4, 0x28]), "c"),
        (bytes([0x01, 255, 240]), "mn2"), (bytes([0x06, 3, 240, 4, 0x22]), "d"),
    ]
    one = _EplState()
    for payload, src in frames + later:
        one.feed(payload, src, "x", 0.0, [])
    first, second = _EplState(), _EplState()
    for payload, src in frames:
        first.feed(payload, src, "x", 0.0, [])
    for payload, src in later:
        second.feed(payload, src, "x", 0.0, [])
    first.absorb(second)
    assert repr(first.findings()) == repr(one.findings())
    assert list(first.nmt.items()) == list(one.nmt.items())
    assert {k: list(v.items()) for k, v in first.nmt_src.items()} == {k: list(v.items()) for k, v in one.nmt_src.items()}


def test_lite_records_match_scapy_bsd_loopback(tmp_path: Path) -> None:
    """Loopback captures (linktype 0 and OpenBSD's 108) take the fast path;
    the family is read by scapy's own field, so on Linux only the first byte
    counts and only Linux's AF_INET6 (10) builds IPv6 (BSD's 24 stays Raw)."""
    from scapy.layers.l2 import Loopback, LoopbackOpenBSD  # type: ignore

    ip = IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=40000, dport=502, flags="PA") / MBAP_READ
    ip6 = IPv6(src="::1", dst="::1") / UDP(sport=40001, dport=20000) / b"\x05\x64"
    null = tmp_path / "null.pcap"
    wrpcap(
        str(null),
        [Loopback(type=2) / ip, Loopback(b"\x18\x00\x00\x00" + bytes(ip6)), Loopback(b"\x0a\x00\x00\x00" + bytes(ip6)),
         Loopback(b"\x00\x00\x00\x02" + bytes(ip)), Raw(b"\x02\x00")],  # a truncated frame
        linktype=0,
    )
    assert _assert_lite_matches(null) == 5
    loop = tmp_path / "loop.pcap"
    wrpcap(str(loop), [LoopbackOpenBSD(type=2) / ip, LoopbackOpenBSD(b"\x00\x00\x00\x18" + bytes(ip6))], linktype=108)
    assert _assert_lite_matches(loop) == 2
    records = list(LiteStream(null))
    assert records[0].lite_ports() is not UNSUPPORTED and records[0].lite_ports()[2] == 502


def _gzip_copy(src: Path, dst: Path) -> Path:
    import gzip
    import shutil

    with src.open("rb") as plain, gzip.open(dst, "wb") as packed:
        shutil.copyfileobj(plain, packed)
    return dst


@pytest.mark.parametrize("pcapng", [False, True])
def test_gzip_capture_is_read_like_its_contents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pcapng: bool
) -> None:
    """A gzip-compressed capture was refused as "not a pcap/pcapng capture";
    it is now read decompressed, with the same report as the capture inside
    it (apart from the file's own name, size and hashes)."""
    from pcapper.discovery import is_capture_file
    from pcapper.rawcap import estimate_packets
    from pcapper.utils import detect_file_type

    plain = tmp_path / ("ot.pcapng" if pcapng else "ot.pcap")
    if pcapng:
        writer = PcapNgWriter(str(plain))
        for pkt in _edge_packets() * 2:
            writer.write(pkt)
        writer.close()
    else:
        wrpcap(str(plain), _edge_packets() * 2)
    packed = _gzip_copy(plain, tmp_path / (plain.name + ".gz"))
    assert detect_file_type(packed) == ("pcapng" if pcapng else "pcap")
    assert is_capture_file(packed)
    assert estimate_packets(packed) == len(_edge_packets()) * 2

    def masked(text: str, path: Path) -> list[str]:
        # File size and hashes legitimately differ (compressed vs. plain):
        # the capture summary's hash lines and the size in its headline.
        text = text.replace(str(path), "PATH").replace(path.name, "NAME").replace(" (gzip)", "")
        return [
            re.sub(r"(packets · )[\d.,]+ (?:B|KB|MB|GB)( · )", r"\1SIZE\2", line)
            for line in text.splitlines()
            if not re.match(r"^\s+(SHA-256|SHA-1):", line)
        ]

    flags = ["--base", "--modbus", "--dnp3", "--files"]
    for env in ({}, {"PCAPPER_CACHE_ENABLED": "0"}):
        got = masked(_render_steps(packed, flags, monkeypatch, **env), packed)
        want = masked(_render_steps(plain, flags, monkeypatch, **env), plain)
        assert got == want
    assert "(gzip)" in _render_steps(packed, ["--base"], monkeypatch)


def test_gzip_of_something_else_is_not_a_capture(tmp_path: Path) -> None:
    import gzip

    from pcapper.discovery import is_capture_file

    junk = tmp_path / "notes.txt.gz"
    with gzip.open(junk, "wb") as handle:
        handle.write(b"just some text, no capture here")
    assert not is_capture_file(junk)


def test_layer_lookups_kept_for_packets_in_memory(tmp_path: Path) -> None:
    """A packet of an in-memory view answers getlayer/haslayer from its own
    table once asked; a copy, a filtered lookup and an unmarked packet ask
    scapy, with the same answers."""
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether

    pcap_cache.install_layer_memo()
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2)
    path = tmp_path / "memo.pcap"
    wrpcap(str(path), [pkt])
    packets, meta = pcap_cache.load_packets(path, show_status=False)
    pcap_cache.set_forced_packet_view(path, packets, meta)
    try:
        first = packets[0]
        assert first.getlayer(TCP) is first[TCP] and first.haslayer(TCP) and not first.haslayer(UDP)
        table = vars(first)[pcap_cache._LAYER_MEMO_KEY][1]
        assert table[TCP] is first.getlayer(TCP) and table[("has", UDP)] == 0  # scapy answers 0, kept as is
        assert first.getlayer(IP, src="10.0.0.1") is first[IP]  # filtered: asked of scapy
        copy = first.copy()
        assert copy.getlayer(TCP) is not first.getlayer(TCP) and copy.getlayer(TCP).dport == 2
    finally:
        pcap_cache.clear_forced_packet_view(path)
