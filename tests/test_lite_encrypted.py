"""The TLS, certificate, QUIC, encrypted-DNS, VPN, SSH, FTP and email analyses
read lite records from disk and dissect only the packets they look at: their
results must equal the ones computed over scapy packets (in memory), record
for record."""

from __future__ import annotations

import datetime
import shutil
from pathlib import Path

import pytest

pytest.importorskip("scapy")
pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from scapy.all import (  # noqa: E402
    ARP,
    IP,
    TCP,
    UDP,
    CookedLinux,
    Dot1Q,
    Ether,
    IPOption_RR,
    IPv6,
    Raw,
    rdpcap,
    wrpcap,
)
from scapy.config import conf  # noqa: E402
from scapy.layers.inet import TCPerror  # noqa: E402
from scapy.layers.tls.handshake import TLSCertificate, TLSClientHello, TLSServerHello  # noqa: E402
from scapy.layers.tls.record import TLS  # noqa: E402
from scapy.layers.tls.record_sslv2 import SSLv2  # noqa: E402
from scapy.layers.tls.record_tls13 import TLS13  # noqa: E402
from test_lite_it_paths import _frames as _it_frames  # noqa: E402

from pcapper import certificates, email, ftp, pcap_cache, ssh, utils, vpn  # noqa: E402
from pcapper.certificates import analyze_certificates  # noqa: E402
from pcapper.email import analyze_email  # noqa: E402
from pcapper.encrypted_dns import analyze_encrypted_dns  # noqa: E402
from pcapper.ftp import analyze_ftp  # noqa: E402
from pcapper.lite import UNSUPPORTED, LitePacket  # noqa: E402
from pcapper.quic import analyze_quic  # noqa: E402
from pcapper.ssh import analyze_ssh  # noqa: E402
from pcapper.tls import analyze_tls  # noqa: E402
from pcapper.vpn import analyze_vpn  # noqa: E402

DATA = Path(__file__).parent / "data"

A, B, C = "10.0.0.1", "10.0.0.2", "10.0.0.3"
ETH = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
TLS_FAMILY = (TLS, TLS13, SSLv2, TLSCertificate, TLSClientHello, TLSServerHello)


def _padded(frame, padding: bytes):  # type: ignore[no-untyped-def]
    """``frame`` with ``padding`` behind its IP datagram: scapy hangs it under
    the transport layer as Padding, and the scapy path reads it as payload."""
    return frame.__class__(bytes(frame) + padding)


def _cert_record(common_name: str = "tls.example.test", serial: int = 4242) -> bytes:
    """A TLS record carrying a Certificate message: one deterministic
    (Ed25519) self-signed certificate."""
    key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .sign(key, None)
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    certs = len(der).to_bytes(3, "big") + der
    body = len(certs).to_bytes(3, "big") + certs
    handshake = b"\x0b" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def _openvpn_control(packet_id: int, data: bytes, opcode: int = 4) -> bytes:
    """One OpenVPN-over-TCP control frame (length-prefixed, no acks)."""
    frame = bytes([opcode << 3]) + b"\x11" * 8 + b"\x00" + packet_id.to_bytes(4, "big") + data
    return len(frame).to_bytes(2, "big") + frame


def _split_without_record_start(record: bytes) -> int:
    """Where to cut ``record`` so that the second part holds no TLS record
    start: only the buffered first part makes the second one worth reading."""
    cut = 16
    for idx in range(len(record) - 4):
        if certificates._is_tls_record_start(record[idx:]):
            cut = max(cut, idx + 1)
    assert cut < len(record) - 8
    return cut


def _tcp(sport: int, dport: int, **kw):  # type: ignore[no-untyped-def]
    return ETH / IP(src=A, dst=B) / TCP(sport=sport, dport=dport, **kw)


def _rtcp(sport: int, dport: int, **kw):  # type: ignore[no-untyped-def]
    return ETH / IP(src=B, dst=A) / TCP(sport=sport, dport=dport, **kw)


def _udp(sport: int, dport: int, **kw):  # type: ignore[no-untyped-def]
    return ETH / IP(src=A, dst=B) / UDP(sport=sport, dport=dport, **kw)


def _frames() -> list:
    tcp, rtcp, udp = _tcp, _rtcp, _udp
    hello = bytes(rdpcap(str(DATA / "tls.pcap"))[0][TCP].payload)  # a real ClientHello
    assert hello[:1] == b"\x16" and hello[5:6] == b"\x01"
    record = _cert_record()
    vpn_record = _cert_record("vpn.example.test", 4343)
    cut = _split_without_record_start(vpn_record)
    frames = [
        # TLS: a ClientHello and a certificate off the TLS ports (raw paths),
        # SSLv2, a record that only the padding behind its first byte
        # completes, and a bare ACK whose padding opens like an alert.
        tcp(40020, 4443) / Raw(hello),
        rtcp(8443, 40021) / Raw(record),
        tcp(40022, 5000) / Raw(b"\x80\x2e\x01\x00\x02\x00\x15\x00\x00\x00\x10" + b"\x07\x00\xc0" * 7),
        _padded(tcp(40023, 7001) / Raw(b"\x16"), b"\x03\x01\x00\x05\x00"),
        _padded(tcp(40024, 7002, flags="A"), b"\x15\x03\x03\x00\x02\x02"),
        _padded(tcp(40025, 7003) / Raw(b"\x15\x03\x03\x00\x02\x02\x28"), bytes(range(1, 8))),
        ETH / IPv6(src="fe80::1", dst="fe80::2") / TCP(sport=40026, dport=443) / Raw(hello),
        ETH / IPv6(src="fe80::1", dst="fe80::2") / TCP(sport=40027, dport=9443) / Raw(hello),
        # An OpenVPN control channel (tcp/1194) carrying a certificate in two
        # frames: the second holds no record start and is read only because
        # the first left TLS bytes buffered for its flow.
        rtcp(1194, 40100) / Raw(_openvpn_control(1, vpn_record[:cut])),
        _padded(tcp(40100, 1194, flags="A"), b"\x00" * 6),
        _padded(rtcp(1194, 40100, flags="A"), b"\x00" * 6),
        rtcp(1194, 40100) / Raw(_openvpn_control(2, vpn_record[cut:])),
        # A second control flow whose ACK padding parses as a control frame
        # with data: buffered behind the first frame's TLS bytes.
        rtcp(1194, 40101) / Raw(_openvpn_control(1, vpn_record[:cut])),
        _padded(rtcp(1194, 40101, flags="A"), b"\x00\x10\x20" + b"\x11" * 8 + b"\x00\x00\x00\x00\x09\x41\x42"),
        # QUIC and DNS over QUIC/TLS/HTTPS, padding that opens like QUIC
        # behind a datagram without payload, padding behind DoT's port.
        udp(50000, 443) / Raw(b"\xc3\x00\x00\x00\x01\x08" + b"\x01" * 24),
        ETH / IP(src=B, dst=A) / UDP(sport=443, dport=50000) / Raw(b"\x40" + b"\x02" * 24),
        udp(50001, 443) / Raw(b"\x00\x01\x02\x03\x04\x05"),
        _padded(udp(50002, 443, len=8), b"\xc0\x00\x00\x00\x01\x00"),
        udp(50003, 853) / Raw(b"\xc0\x00\x00\x00\x01" + b"\x03" * 16),
        _padded(udp(50005, 853, len=8), b"\xc0\x00\x00\x00\x01\x00"),
        ETH / IP(src=B, dst=A) / UDP(sport=784, dport=80) / Raw(b"\xc0\x00\x00\x00\x01" + b"\x03" * 16),
        ETH / IPv6(src="fe80::1", dst="fe80::2") / UDP(sport=50004, dport=443) / Raw(b"\xc3\x00\x00\x00\x01"),
        tcp(40030, 853) / Raw(b"\x17\x03\x03\x00\x10" + b"\x04" * 16),
        rtcp(853, 40030) / Raw(b"\x17\x03\x03\x00\x10" + b"\x05" * 16),
        tcp(40031, 853) / Raw(b"hello"),
        _padded(tcp(40032, 853, flags="A"), b"\x17\x03\x03\x00\x10\x00"),
        tcp(40033, 80) / Raw(b"GET /dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB HTTP/1.1\r\nHost: dns.example\r\n\r\n"),
        tcp(40034, 8080) / Raw(b"POST /q HTTP/1.1\r\nContent-Type: application/dns-message\r\n\r\n"),
        ETH / IPv6(src="fe80::1", dst="fe80::2") / TCP(sport=40035, dport=853) / Raw(b"\x17\x03\x03\x00\x10" + b"\x06" * 16),
        # VPN: tunnel protocols (also as a fragment), OpenVPN/WireGuard on
        # their ports, OpenVPN opcodes on UDP/443 and on another TCP port,
        # padding that parses as an OpenVPN frame, SoftEther, PPTP, SSTP.
        ETH / IP(src=A, dst=B, proto=50) / Raw(b"\x00\x00\x10\x01" + b"\x00" * 12),
        ETH / IP(src=A, dst=B, proto=51) / Raw(b"\x32\x04\x00\x00" + b"\x00" * 20),
        ETH / IP(src=A, dst=B, proto=47) / Raw(b"\x00\x00\x08\x00" + b"\x00" * 20),
        ETH / IP(src=A, dst=B, proto=50, frag=10) / Raw(b"\x00" * 16),
        ETH / IP(src=A, dst=B, proto=6, frag=10) / Raw(b"\x00" * 16),
        udp(40040, 1194) / Raw(b"\x38" + b"\x22" * 8 + b"\x00" + b"\x00\x00\x00\x00"),
        udp(40041, 51820) / Raw(b"\x01\x00\x00\x00" + b"\x00" * 144),
        udp(40042, 443) / Raw(b"\x38" + b"\x22" * 8 + b"\x00" + b"\x00\x00\x00\x00"),
        udp(40043, 4500) / Raw(b"\x00\x00\x00\x00" + b"\x00" * 28),
        udp(40044, 500) / Raw(b"\x00" * 28),
        tcp(40045, 5555, flags="S"),
        tcp(40046, 1723, flags="S"),
        tcp(40047, 9999) / Raw(_openvpn_control(1, b"", opcode=7)),
        _padded(tcp(40048, 9998, flags="A"), b"\x00\x02\x38\x00\x00\x00"),
        tcp(40049, 443) / Raw(b"SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n\r\n"),
        tcp(40050, 1194) / Raw(b"not openvpn at all"),
        # SSH: a banner on its port and off it, "SSH-" at the edge of the
        # 32-byte window, in padding only, and across payload and padding.
        tcp(40060, 22) / Raw(b"SSH-2.0-OpenSSH_9.6\r\n"),
        rtcp(22, 40060) / Raw(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"),
        tcp(40061, 2022) / Raw(b"SSH-2.0-dropbear_2022.83\r\n"),
        tcp(40062, 2023) / Raw(b"x" * 28 + b"SSH-2.0-a\r\n"),
        tcp(40063, 2024) / Raw(b"x" * 29 + b"SSH-2.0-b\r\n"),
        _padded(tcp(40064, 2025, flags="S"), b"\x00SSH-2"),
        _padded(tcp(40065, 2026) / Raw(b"xxSS"), b"H-2.0-c"),
        udp(40066, 22) / Raw(b"SSH-2.0-udp\r\n"),
        ETH / IPv6(src="fe80::1", dst="fe80::2") / TCP(sport=40067, dport=22) / Raw(b"SSH-2.0-v6\r\n"),
        # FTP: control on its ports and off them, PASV, data, an IP length
        # of 0 (TSO: the whole frame is payload) and one shorter than the
        # header (no payload), MAC bookkeeping over VLAN, IPv6 and ARP.
        rtcp(21, 40070) / Raw(b"220 ProFTPD 1.3.5 Server ready\r\n"),
        tcp(40070, 21) / Raw(b"USER alice\r\nPASS s3cret\r\n"),
        tcp(40070, 21) / Raw(b"PASV\r\n"),
        rtcp(21, 40070) / Raw(b"227 Entering Passive Mode (10,0,0,2,19,137)\r\n"),
        tcp(40070, 21) / Raw(b"RETR evil.exe\r\n"),
        rtcp(21, 40070) / Raw(b"150 Opening BINARY mode data connection\r\n"),
        rtcp(5001, 40071) / Raw(b"MZ\x90\x00binary"),
        tcp(40072, 5021) / Raw(b"USER bob\r\n"),
        ETH / IP(src=B, dst=A) / TCP(sport=5021, dport=40072) / Raw(b"331 Password required\r\n"),
        tcp(40072, 5021) / Raw(b"PASS hunter2\r\n"),
        ETH / IP(src=A, dst=B, len=0) / TCP(sport=40073, dport=21) / Raw(b"USER tso\r\n"),
        ETH / IP(src=A, dst=B, len=10) / TCP(sport=40074, dport=21) / Raw(b"USER short\r\n"),
        rtcp(20, 40075) / Raw(b"data channel bytes"),
        _padded(Ether(src="00:aa:bb:cc:dd:01", dst="66:77:88:99:aa:bb") / Dot1Q(vlan=7) / IP(src=C, dst=B) / TCP(sport=40076, dport=21, flags="S"), bytes(range(1, 3))),
        Ether(src="00:aa:bb:cc:dd:02", dst="66:77:88:99:aa:bb") / IP(src=A, dst=B) / TCP(sport=40077, dport=80, flags="A"),
        Ether(src="00:aa:bb:cc:dd:03", dst="66:77:88:99:aa:bb") / IPv6(src="fe80::1", dst="fe80::2") / TCP(sport=40078, dport=21, flags="S"),
        Ether(src="00:aa:bb:cc:dd:04", dst="ff:ff:ff:ff:ff:ff") / ARP(hwsrc="00:aa:bb:cc:dd:04", psrc=C, hwdst="00:00:00:00:00:00", pdst=A),
        Ether(src="00:aa:bb:cc:dd:05", dst="66:77:88:99:aa:bb") / IP(src=A, dst=B, options=[IPOption_RR()]) / TCP(sport=40079, dport=21, flags="S"),
        # Email: SMTP, an ACK on its port (its padding is the payload),
        # mail text off the mail ports (in a payload, then in padding only),
        # webmail, and an ordinary web request.
        tcp(40080, 25) / Raw(b"EHLO client.example\r\nMAIL FROM:<a@example.com>\r\n"),
        rtcp(25, 40080) / Raw(b"250 OK\r\n"),
        _padded(tcp(40080, 25, flags="A"), b"\x00" * 6),
        tcp(40081, 2526) / Raw(b"MAIL FROM:<x@example.org>\r\nRCPT TO:<y@example.org>\r\n"),
        _padded(tcp(40082, 2527, flags="A"), b"smtp\r\n"),
        tcp(40083, 80) / Raw(b"GET /owa/ HTTP/1.1\r\nHost: mail.example.com\r\nUser-Agent: Outlook\r\n\r\n"),
        tcp(40084, 80) / Raw(b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n"),
        tcp(40085, 993) / Raw(b"\x17\x03\x03\x00\x05abcde"),
    ]
    out = []
    for frame in frames:
        data = bytes(frame)
        if len(data) < 60:
            data += bytes(range(1, 61 - len(data)))  # padding that is not zero
        out.append(Ether(data))
    return _it_frames() + out


def _cooked_frames() -> list:
    """Linux cooked capture: no Ethernet layer, so no MAC bookkeeping."""
    sll = CookedLinux(pkttype=0, lladdrtype=1, lladdrlen=6, src=b"\x00\x11\x22\x33\x44\x55\x00\x00", proto=0x0800)
    return [
        sll / IP(src=A, dst=B) / TCP(sport=40090, dport=21) / Raw(b"USER cooked\r\n"),
        sll / IP(src=B, dst=A) / TCP(sport=21, dport=40090, flags="A"),
        sll / IP(src=A, dst=B) / TCP(sport=40091, dport=22) / Raw(b"SSH-2.0-cooked\r\n"),
        sll / IP(src=A, dst=B) / TCP(sport=40092, dport=8443) / Raw(_cert_record()),
        sll / IP(src=A, dst=B) / UDP(sport=40093, dport=443) / Raw(b"\xc3\x00\x00\x00\x01\x08"),
        sll / IP(src=A, dst=B) / TCP(sport=40094, dport=25) / Raw(b"HELO cooked\r\n"),
    ]


@pytest.fixture()
def capture(tmp_path: Path) -> Path:
    path = tmp_path / "edge.pcap"
    wrpcap(str(path), _frames())
    return path


@pytest.fixture()
def cooked(tmp_path: Path) -> Path:
    path = tmp_path / "cooked.pcap"
    wrpcap(str(path), _cooked_frames())
    return path


@pytest.fixture(autouse=True)
def _fresh(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PCAPPER_CACHE_ENABLED", "0")
    utils.clear_analysis_memo()
    pcap_cache._PACKET_CACHE.clear()
    yield
    utils.clear_analysis_memo()
    pcap_cache._PACKET_CACHE.clear()


def _captures(tmp_path: Path, *edge: Path) -> list[Path]:
    paths = list(edge)
    for name in ("mixed.pcap", "mixed.pcapng", "http.pcap", "dns.pcap", "tls.pcap", "truncated.pcap", "voip_attack.pcap"):
        target = tmp_path / name
        shutil.copy(DATA / name, target)
        paths.append(target)
    return paths


def _records(paths: list[Path]):  # type: ignore[no-untyped-def]
    for path in paths:
        yield from pcap_cache.iter_packets(path, show_status=False, lite=True)


ANALYSES = [
    analyze_tls,
    analyze_certificates,
    analyze_quic,
    analyze_encrypted_dns,
    analyze_vpn,
    analyze_ssh,
    analyze_ftp,
    analyze_email,
]


@pytest.mark.parametrize(
    "analyze",
    ANALYSES,
    ids=["tls", "certificates", "quic", "encrypted_dns", "vpn", "ssh", "ftp", "email"],
)
def test_from_disk_equals_scapy_packets(tmp_path: Path, capture: Path, cooked: Path, analyze) -> None:  # type: ignore[no-untyped-def]
    for path in _captures(tmp_path, capture, cooked):
        utils.clear_analysis_memo()
        from_disk = analyze(path, show_status=False)
        packets, meta = pcap_cache.load_packets(path, show_status=False)
        assert packets and not isinstance(packets[0], LitePacket)
        utils.clear_analysis_memo()
        in_memory = analyze(path, show_status=False, packets=packets, meta=meta)
        assert repr(from_disk) == repr(in_memory), path.name  # the whole summary


def test_the_edge_capture_reaches_every_path(capture: Path) -> None:
    """The fixture holds what the fast paths must get right, and what each
    analysis must find in it (so a skip that drops it shows)."""
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
            proto = "tcp" if l4[0] else "udp"
            kinds.add(f"{proto}-raw+padding" if len(record.original) > l4[6] else f"{proto}-raw")
            if l4[6] == l4[5]:
                kinds.add(f"{proto}-empty")
    assert {
        "unsupported", "no-l4", "app-layer", "tcp-raw", "tcp-raw+padding", "tcp-empty",
        "udp-raw", "udp-raw+padding", "udp-empty",
    } <= kinds
    utils.clear_analysis_memo()
    cert = analyze_certificates(capture, show_status=False)
    assert {c.transport for c in cert.artifacts} == {"TLS", "OpenVPN control-channel TLS"}
    tls_summary = analyze_tls(capture, show_status=False)
    assert tls_summary.nonstandard_tls_clients and tls_summary.tls_like_packets >= 6
    assert analyze_quic(capture, show_status=False).quic_packets >= 4
    edns = analyze_encrypted_dns(capture, show_status=False)
    assert edns.dot_packets >= 3 and edns.doh_packets >= 2 and edns.doq_packets >= 2
    vpn_summary = analyze_vpn(capture, show_status=False)
    assert {"OpenVPN", "WireGuard", "SoftEther VPN", "PPTP", "IPsec ESP"} <= set(vpn_summary.service_counts)
    ssh_summary = analyze_ssh(capture, show_status=False)
    assert ssh_summary.ssh_packets >= 7
    ftp_summary = analyze_ftp(capture, show_status=False)
    assert ftp_summary.password_counts and len(ftp_summary.mac_addresses) >= 3
    assert "tso" in ftp_summary.user_counts and "short" not in ftp_summary.user_counts
    assert analyze_email(capture, show_status=False).protocol_counts["WEBMAIL"] >= 1


def test_payload_views_match_scapy(tmp_path: Path, capture: Path, cooked: Path) -> None:
    """What the skips read from a record's bytes is what the scapy path
    reads: bytes(transport.payload) (payload and padding), the Raw layer and
    its load; no TCP, UDP or TLS layer at all without a transport header."""
    for record in _records(_captures(tmp_path, capture, cooked)):
        l4 = record.lite_l4()
        if l4 is UNSUPPORTED:
            continue
        pkt = record.materialize()
        if l4 is None:
            assert pkt.getlayer(TCP) is None and pkt.getlayer(UDP) is None
            assert all(pkt.getlayer(cls) is None for cls in TLS_FAMILY)
            continue
        transport = pkt.getlayer(TCP if l4[0] else UDP)
        assert (transport.sport, transport.dport) == (l4[1], l4[2])
        assert pkt.getlayer(UDP if l4[0] else TCP) is None
        if l4[5] < 0:
            continue
        assert all(pkt.getlayer(cls) is None for cls in TLS_FAMILY)
        assert bytes(transport.payload) == record.original[l4[7] :]
        raw = pkt.getlayer(Raw)
        assert transport.getlayer(Raw) is raw  # the first Raw is the payload's
        assert (raw is not None) == (l4[6] > l4[5])
        if raw is not None:
            assert raw.load == record.original[l4[5] : l4[6]]
            assert bytes(raw) == record.original[l4[5] :]


def test_tls_is_bound_under_tcp_only() -> None:
    """Why a record without a TCP/UDP header has no TLS layer: scapy builds
    TLS only on a transport header -- TCP, and the TCP header an ICMP error
    quotes, which the lite parser leaves to scapy -- and no other layer
    holds one in a field."""
    parents = {
        cls
        for cls in conf.layers
        for _fields, child in (getattr(cls, "payload_guess", ()) or ())
        if isinstance(child, type) and issubclass(child, TLS_FAMILY)
    }
    assert TCP in parents and all(issubclass(cls, (TCP, UDP)) for cls in parents)
    assert TCPerror in parents  # quoted by ICMP errors: UNSUPPORTED in lite
    holders = {
        cls
        for cls in conf.layers
        if not cls.__module__.startswith("scapy.layers.tls")
        for fld in getattr(cls, "fields_desc", ())
        if isinstance(getattr(fld, "cls", None), type) and issubclass(fld.cls, TLS_FAMILY)
    }
    assert not holders


def test_vpn_reads_the_ip_protocol_scapy_reads(tmp_path: Path, capture: Path, cooked: Path) -> None:
    for record in _records(_captures(tmp_path, capture, cooked)):
        l3 = record.headers()[1]
        if l3 is UNSUPPORTED:
            continue
        proto = vpn._packet_ip_proto(record.materialize())
        if l3 is None or l3[0] == 1:
            assert proto is None
        elif l3[0] == 4:
            assert proto == record.original[l3[1] - 3]
        else:
            assert proto not in vpn.VPN_IP_PROTOCOLS


def test_ftp_mac_bookkeeping_matches_scapy(tmp_path: Path, capture: Path, cooked: Path) -> None:
    """The (IP, MAC) pairs added for a skipped record are _record_mac's, and a
    record skipped for want of a payload has none on the scapy path either."""
    seen = 0
    for record in _records(_captures(tmp_path, capture, cooked)):
        src_ip, dst_ip = utils.extract_packet_endpoints(record)
        if not src_ip or not dst_ip:
            continue
        pkt = record.materialize()
        expected = []
        if Ether in pkt:
            if IP in pkt:
                expected = [(str(pkt[IP].src), str(pkt[Ether].src)), (str(pkt[IP].dst), str(pkt[Ether].dst))]
        lite = ftp._lite_macs(record, src_ip, dst_ip)
        if lite is not None:
            assert list(lite) == expected
            seen += bool(expected)
        if ftp._lite_no_tcp_payload(record):
            tcp = pkt.getlayer(TCP)
            if tcp is not None:
                ip_layer = pkt.getlayer(IP)
                if ip_layer is None:
                    ip_layer = pkt.getlayer(IPv6)
                assert ftp._tcp_payload_bytes(ip_layer, tcp) == b""
    assert seen


def test_skips_drop_only_what_scapy_drops(tmp_path: Path, capture: Path, cooked: Path) -> None:
    """Record by record: what a skip drops, the scapy path drops too."""
    for record in _records(_captures(tmp_path, capture, cooked)):
        pkt = record.materialize()
        tcp, udp = pkt.getlayer(TCP), pkt.getlayer(UDP)
        payload = bytes(tcp.payload) if tcp is not None else None
        if ssh._lite_not_ssh(record) and tcp is not None:
            assert tcp.sport not in ssh.SSH_PORTS and tcp.dport not in ssh.SSH_PORTS
            assert b"SSH-" not in payload[:32]
        if email._lite_not_email(record) and tcp is not None and payload:
            text = email._readable_text(payload)
            known = tcp.sport in email.MAIL_PORTS or tcp.dport in email.MAIL_PORTS
            assert not known and not email._looks_like_mail_text(text)
            assert email._detect_webmail_context(text) is None
        if certificates._lite_no_certificate(record, {}):
            assert all(pkt.getlayer(cls) is None for cls in TLS_FAMILY)
            if tcp is not None:
                assert not certificates._is_tls_record_start(payload)
        if vpn._lite_not_vpn(record):
            assert vpn._packet_ip_proto(pkt) not in vpn.VPN_IP_PROTOCOLS
            if udp is not None:
                assert not vpn._vpn_port_match(udp.sport, udp.dport) or 443 in {udp.sport, udp.dport}


def test_ssh_decrypted_payloads_keep_every_record(tmp_path: Path, capture: Path) -> None:
    """A decrypted payload may belong to any packet index: with one, every
    record goes down the scapy path."""
    utils.clear_analysis_memo()
    from_disk = analyze_ssh(capture, show_status=False, decrypted_payloads={3: b"\x05" * 8})
    packets, meta = pcap_cache.load_packets(capture, show_status=False)
    utils.clear_analysis_memo()
    in_memory = analyze_ssh(capture, show_status=False, packets=packets, meta=meta, decrypted_payloads={3: b"\x05" * 8})
    assert repr(from_disk) == repr(in_memory)
    assert ssh._meta_decrypted({"ssh_decrypted": {1: b"x"}}) == {1: b"x"}
    assert ssh._meta_decrypted(meta) is None
