"""The DNS, LDAP, Kerberos, NetBIOS, DHCP, syslog, SNMP and NTLM analyses read
lite records from disk and dissect only the packets they look at: their
results must equal the ones computed over scapy packets (in memory), record
for record."""

from __future__ import annotations

import base64
import shutil
import struct
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
    TCP,
    UDP,
    Dot1Q,
    Ether,
    IPerror,
    IPOption_RR,
    IPv6,
    Raw,
    UDPerror,
)
from scapy.layers.llmnr import LLMNRQuery  # noqa: E402
from scapy.layers.netbios import (  # noqa: E402
    NBNSHeader,
    NBNSQueryRequest,
    NBNSQueryResponse,
    NBTDatagram,
)
from scapy.utils import wrpcap  # noqa: E402
from test_lite_it_paths import _frames as _it_frames  # noqa: E402

from pcapper import ldap, ntlm, pcap_cache, sharedpass, syslog, utils  # noqa: E402
from pcapper.dhcp import analyze_dhcp  # noqa: E402
from pcapper.dns import analyze_dns  # noqa: E402
from pcapper.kerberos import analyze_kerberos  # noqa: E402
from pcapper.ldap import analyze_ldap  # noqa: E402
from pcapper.lite import UNSUPPORTED, LitePacket  # noqa: E402
from pcapper.netbios import analyze_netbios  # noqa: E402
from pcapper.ntlm import analyze_ntlm  # noqa: E402
from pcapper.snmp import analyze_snmp  # noqa: E402
from pcapper.syslog import analyze_syslog  # noqa: E402

DATA = Path(__file__).parent / "data"

A, B = "10.0.0.1", "10.0.0.2"
_MAILSLOT_BROWSE = b"\\MAILSLOT\\BROWSE\x00"
ANALYSES = [
    analyze_dns,
    analyze_ldap,
    analyze_kerberos,
    analyze_netbios,
    analyze_dhcp,
    analyze_syslog,
    analyze_snmp,
    analyze_ntlm,
]
IDS = ["dns", "ldap", "kerberos", "netbios", "dhcp", "syslog", "snmp", "ntlm"]


def _ber(tag: int, body: bytes) -> bytes:
    size = len(body)
    return bytes([tag, size] if size < 0x80 else [tag, 0x81, size]) + body


def _ldap_message(msg_id: int, op: bytes) -> bytes:
    return _ber(0x30, _ber(0x02, bytes([msg_id])) + op)


def _ntlm(msg_type: int, user: str = "alice", domain: str = "CORP", host: str = "WS01") -> bytes:
    """An NTLMSSP Negotiate (1), Challenge (2) or Authenticate (3) message."""
    head = b"NTLMSSP\x00" + struct.pack("<I", msg_type)
    if msg_type == 1:
        return head + struct.pack("<I", 0xA2088207) + b"\x00" * 16
    if msg_type == 2:
        target = domain.encode("utf-16-le")
        return (
            head
            + struct.pack("<HHI", len(target), len(target), 48)
            + struct.pack("<I", 0xA2898205)
            + b"\x01\x23\x45\x67\x89\xab\xcd\xef"
            + b"\x00" * 8
            + struct.pack("<HHI", 0, 0, 48 + len(target))
            + target
        )
    fields = [
        b"\x00" * 24,
        b"\x11" * 16 + b"\x01\x01\x00\x00" + b"\x00" * 28,  # NTLMv2 response
        domain.encode("utf-16-le"),
        user.encode("utf-16-le"),
        host.encode("utf-16-le"),
        b"",
    ]
    offset, body, buffers = 64, b"", b""
    for value in fields:
        buffers += struct.pack("<HHI", len(value), len(value), offset)
        offset += len(value)
        body += value
    return head + buffers + struct.pack("<I", 0x00088201) + body


def _with_padding(frame, padding: bytes) -> Ether:
    """``frame`` (an IPv4 packet in Ethernet) followed by Ethernet padding:
    bytes past the IP total length, which scapy hangs behind the payload."""
    return Ether(bytes(frame) + padding)


def _names_frames() -> list:
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    bcast = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")
    query = DNS(id=7, rd=1, qd=DNSQR(qname="plc1.example.local"))
    answer = DNS(
        id=7, qr=1, qd=DNSQR(qname="plc1.example.local"),
        an=DNSRR(rrname="plc1.example.local", rdata="10.0.0.9"),
    )
    bind = _ldap_message(1, _ber(0x60, _ber(0x02, b"\x03") + _ber(0x04, b"cn=admin,dc=example,dc=com") + _ber(0x80, b"S3cret!")))
    bind_failed = _ldap_message(1, _ber(0x61, _ber(0x0A, b"\x31") + _ber(0x04, b"") + _ber(0x04, b"80090308: LdapErr")))
    search = _ldap_message(2, _ber(0x63, (
        _ber(0x04, b"dc=example,dc=com") + _ber(0x0A, b"\x02") + _ber(0x0A, b"\x00")
        + _ber(0x02, b"\x00") + _ber(0x02, b"\x00") + _ber(0x01, b"\x00")
        + _ber(0x87, b"objectClass") + _ber(0x30, _ber(0x04, b"sAMAccountName") + _ber(0x04, b"userPassword"))
    )))
    as_req = (
        b"\x6a\x08\xa8\x01\x30\x04\x02\x01\x17\x02"
        + b" alice@EXAMPLE.LOCAL krbtgt/EXAMPLE.LOCAL KDC_ERR_PREAUTH_REQUIRED"
    )
    announcement = (
        b"\xffSMB\x25" + b"\x00" * 27 + _MAILSLOT_BROWSE + b"\x01\x00"
        + b"\x80\xfc\x0a\x00" + b"PLC-HMI-7".ljust(16, b"\x00") + b"\x06\x01"
        + b"\x03\x10\x00\x00" + b"\x0f\x01\x55\xaa" + b"engineering station\x00"
    )
    sam_logon = (
        b"\xffSMB\x25" + b"\x00" * 27 + b"\\MAILSLOT\\NET\\NETLOGON\x00" + b"\x12\x00\x01\x00"
        + "WS01".encode("utf-16-le") + b"\x00\x00" + "alice".encode("utf-16-le") + b"\x00\x00"
    )
    smb2_ntlm = b"\x00\x00\x00\x80\xfeSMB" + b"\x40\x00" + b"\x00" * 54 + _ntlm(1)
    frames = [
        # DNS over UDP and TCP, a bare segment on the DNS port, VLAN-tagged,
        # mDNS (IPv4 and IPv6), LLMNR, DNS quoted in an ICMP error, and DNS
        # bytes on a port scapy leaves Raw.
        eth / IP(src=A, dst=B) / UDP(sport=40020, dport=53) / query,
        eth / IP(src=B, dst=A) / UDP(sport=53, dport=40020) / answer,
        eth / IP(src=A, dst=B) / TCP(sport=40021, dport=53, flags="PA") / query,
        eth / IP(src=A, dst=B) / TCP(sport=40021, dport=53, flags="S"),
        eth / Dot1Q(vlan=7) / IP(src=A, dst=B) / UDP(sport=40024, dport=53) / query,
        eth / IP(src=A, dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(qr=1, an=DNSRR(rrname="printer.local", rdata=A)),
        eth / IPv6(src="fe80::1", dst="ff02::fb") / UDP(sport=5353, dport=5353) / DNS(qd=DNSQR(qname="_ipp._tcp.local", qtype="PTR")),
        eth / IP(src=A, dst="224.0.0.252") / UDP(sport=40022, dport=5355) / LLMNRQuery(qd=DNSQR(qname="wpad")),
        eth / IP(src=B, dst=A) / ICMP(type=3, code=3) / IPerror(src=A, dst=B) / UDPerror(sport=40020, dport=53) / query,
        eth / IP(src=A, dst=B) / UDP(sport=40023, dport=5000) / Raw(bytes(query)),
        # LDAP: bind with a password and a failed bind response, a search,
        # CLDAP, a bare SYN to the GC port, the LDAP port as the source of a
        # connection to a service port (not LDAP), HTTP on another port.
        eth / IP(src=A, dst=B) / TCP(sport=40030, dport=389, flags="PA") / Raw(bind),
        eth / IP(src=B, dst=A) / TCP(sport=389, dport=40030, flags="PA") / Raw(bind_failed),
        eth / IP(src=A, dst=B) / TCP(sport=40030, dport=389, flags="PA") / Raw(search),
        eth / IP(src=A, dst=B) / UDP(sport=40032, dport=389) / Raw(search),
        eth / IP(src=A, dst=B) / TCP(sport=40031, dport=3268, flags="S"),
        eth / IP(src=B, dst=A) / TCP(sport=389, dport=80, flags="SA"),
        eth / IP(src=A, dst=B) / TCP(sport=40033, dport=8081, flags="PA") / Raw(b"GET /ldap?q=x HTTP/1.1\r\nUser-Agent: probe\r\n\r\n"),
        # Kerberos over UDP and TCP, kpasswd over TCP (scapy dissects it
        # further), SMB with a payload on 445 (likewise), and the KDC port as
        # the source of a connection to a service port (not Kerberos).
        eth / IP(src=A, dst=B) / UDP(sport=40040, dport=88) / Raw(as_req),
        eth / IP(src=A, dst=B) / TCP(sport=40041, dport=88, flags="PA") / Raw(struct.pack("!I", len(as_req)) + as_req),
        eth / IP(src=A, dst=B) / TCP(sport=40042, dport=464, flags="PA") / Raw(b"\x00\x00\x00\x0c\x00\x0c\xff\x80" + b"\x00" * 4),
        eth / IP(src=A, dst=B) / TCP(sport=40051, dport=445, flags="PA") / Raw(smb2_ntlm),
        eth / IP(src=A, dst=B) / TCP(sport=40051, dport=445, flags="S"),
        eth / IP(src=B, dst=A) / TCP(sport=88, dport=443, flags="SA"),
        # NetBIOS: NBNS query and response, a browser announcement and a
        # NETLOGON request over the datagram service, a session request.
        bcast / IP(src=A, dst="10.0.0.255") / UDP(sport=137, dport=137) / NBNSHeader() / NBNSQueryRequest(QUESTION_NAME="FILESRV"),
        eth / IP(src=B, dst=A) / UDP(sport=137, dport=137) / NBNSHeader(RESPONSE=1, ANCOUNT=1) / NBNSQueryResponse(RR_NAME="FILESRV"),
        bcast / IP(src=A, dst="10.0.0.255") / UDP(sport=138, dport=138) / NBTDatagram(SourceIP=A, SourceName="PLC-HMI-7", DestinationName="WORKGROUP") / Raw(announcement),
        bcast / IP(src=A, dst="10.0.0.255") / UDP(sport=138, dport=138) / NBTDatagram(SourceIP=A, SourceName="WS01", DestinationName="CORP") / Raw(sam_logon),
        eth / IP(src=A, dst=B) / TCP(sport=40050, dport=139, flags="PA") / Raw(b"\x81\x00\x00\x44" + b" " * 68),
        # DHCP and DHCPv6, and TCP on a DHCP port (not DHCP).
        bcast / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67)
        / BOOTP(op=1, xid=0x1234, chaddr=b"\x00\x11\x22\x33\x44\x55" + b"\x00" * 10)
        / DHCP(options=[("message-type", "discover"), ("hostname", b"plc7"), ("vendor_class_id", b"MSFT 5.0"), "end"]),
        eth / IPv6(src="fe80::1", dst="ff02::1:2") / UDP(sport=546, dport=547) / Raw(b"\x01\x01\x02\x03" + b"\x00\x08\x00\x02\x00\x00"),
        eth / IP(src=A, dst=B) / TCP(sport=40060, dport=67, flags="S"),
        # Syslog on its ports, a PRI on another port, and text that is not one.
        eth / IP(src=A, dst=B) / UDP(sport=40070, dport=514) / Raw(b"<34>Oct 11 22:14:15 plc7 su: 'su root' failed for lonvick"),
        eth / IP(src=A, dst=B) / TCP(sport=40071, dport=601, flags="PA") / Raw(b"<165>1 2003-10-11T22:14:15.003Z hmi.example.com evntslog - ID47 - event"),
        eth / IP(src=A, dst=B) / UDP(sport=40072, dport=6000) / Raw(b"<13>Nov 24 10:00:00 plc7 app: password=hunter2"),
        eth / IP(src=A, dst=B) / UDP(sport=40073, dport=6001) / Raw(b"<html>not syslog</html>"),
        # SNMP: a set, a trap, and SNMP over TCP.
        eth / IP(src=A, dst=B) / UDP(sport=40080, dport=161) / Raw(bytes.fromhex("302c020101040770726976617465a31e0201000201000201003013301106082b060102010105000405706c632d37")),
        eth / IP(src=B, dst=A) / UDP(sport=40081, dport=162) / Raw(bytes.fromhex("303902010104067075626c6963a72c0201000201000201003021301f06082b06010201010100041357696e646f7773205365727665722032303139")),
        eth / IP(src=A, dst=B) / TCP(sport=40082, dport=161, flags="PA") / Raw(bytes.fromhex("302c020101040770726976617465a31e0201000201000201003013301106082b060102010105000405706c632d37")),
        # NTLM over HTTP headers (any case), raw on a port scapy leaves Raw,
        # over UDP, and inside ICMP (no TCP/UDP: the Raw layer is searched).
        eth / IP(src=A, dst=B) / TCP(sport=40090, dport=80, flags="PA") / Raw(b"GET / HTTP/1.1\r\nAuthorization: NTLM " + base64.b64encode(_ntlm(1)) + b"\r\n\r\n"),
        eth / IP(src=B, dst=A) / TCP(sport=80, dport=40090, flags="PA") / Raw(b"HTTP/1.1 401 Unauthorized\r\nwww-authenticate: nTlM " + base64.b64encode(_ntlm(2)) + b"\r\n\r\n"),
        eth / IP(src=A, dst=B) / TCP(sport=40090, dport=80, flags="PA") / Raw(b"GET / HTTP/1.1\r\nAuthorization: NTLM " + base64.b64encode(_ntlm(3)) + b"\r\n\r\n"),
        eth / IP(src=A, dst=B) / TCP(sport=40091, dport=8080, flags="PA") / Raw(_ntlm(3, user="bob")),
        eth / IP(src=A, dst=B) / UDP(sport=40092, dport=7000) / Raw(_ntlm(1)),
        eth / IP(src=A, dst=B) / ICMP() / Raw(_ntlm(3, user="carol")),
        # Records with no TCP/UDP layer: an unknown EtherType carrying NTLM (a
        # Raw layer), and IGMP with NTLM in its padding (scapy matches Padding
        # as Raw below IGMP).
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb", type=0x88B5) / Raw(_ntlm(3, user="dave")),
        _with_padding(eth / IP(src=A, dst="224.0.0.22", proto=2) / Raw(b"\x22\x00\xf9\x01\x00\x00\x00\x00"), _ntlm(1)),
    ]
    # Each protocol once more behind IP options, which only scapy reads.
    frames += [
        eth / IP(src=A, dst=B, options=[IPOption_RR()]) / layers
        for layers in (
            UDP(sport=40110, dport=53) / query,
            TCP(sport=40111, dport=389, flags="PA") / Raw(bind),
            UDP(sport=40112, dport=88) / Raw(as_req),
            UDP(sport=137, dport=137) / NBNSHeader() / NBNSQueryRequest(QUESTION_NAME="OPTSRV"),
            UDP(sport=68, dport=67) / BOOTP(op=1, xid=0x99) / DHCP(options=[("message-type", "request"), "end"]),
            UDP(sport=40113, dport=514) / Raw(b"<11>Nov 24 10:00:01 opt app: behind options"),
            UDP(sport=40114, dport=161) / Raw(bytes.fromhex("302c020101040770726976617465a31e0201000201000201003013301106082b060102010105000405706c632d37")),
            TCP(sport=40115, dport=8085, flags="PA") / Raw(_ntlm(3, user="frank")),
        )
    ]
    out = []
    for frame in frames:
        data = bytes(frame)
        if len(data) < 60:
            data += bytes(range(1, 61 - len(data)))  # padding that is not zero
        out.append(Ether(data))
    # Payloads that only the Ethernet padding carries: an empty segment whose
    # padding opens an HTTP request, holds an NTLMSSP message or a PRI, a UDP
    # length field that leaves a PRI in the padding, and an ARP frame whose
    # trailing bytes (Padding, never Raw) hold an NTLM message.
    out += [
        _with_padding(eth / IP(src=A, dst=B) / TCP(sport=40100, dport=8082, flags="A"), b"GET /pad HTTP/1.0\r\n\r\n"),
        _with_padding(eth / IP(src=A, dst=B) / TCP(sport=40101, dport=8083, flags="A"), _ntlm(3, user="erin")),
        _with_padding(eth / IP(src=A, dst=B) / TCP(sport=40102, dport=8084, flags="A"), b"<14>padded syslog line"),
        _with_padding(eth / IP(src=A, dst=B) / UDP(sport=40103, dport=6002, len=8), b"<15>udp padding line"),
        Ether(bytes(bcast / ARP(psrc=A, pdst=B)) + _ntlm(1)),
    ]
    return out


def _all_frames() -> list:
    return _it_frames() + _names_frames()


@pytest.fixture()
def capture(tmp_path: Path) -> Path:
    path = tmp_path / "edge_names.pcap"
    wrpcap(str(path), _all_frames())
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
    for source in sorted(DATA.glob("*.pcap*")):
        target = tmp_path / source.name
        shutil.copy(source, target)
        paths.append(target)
    return paths


@pytest.mark.parametrize("analyze", ANALYSES, ids=IDS)
def test_from_disk_equals_scapy_packets(tmp_path: Path, capture: Path, analyze) -> None:  # type: ignore[no-untyped-def]
    for path in _captures(tmp_path, capture):
        utils.clear_analysis_memo()
        from_disk = analyze(path, show_status=False)
        packets, meta = pcap_cache.load_packets(path, show_status=False)
        assert packets and not isinstance(packets[0], LitePacket)
        utils.clear_analysis_memo()
        in_memory = analyze(path, show_status=False, packets=packets, meta=meta)
        assert repr(from_disk) == repr(in_memory), path.name  # same path: the whole summary


def test_from_disk_equals_scapy_packets_with_app_layers_unbound(tmp_path: Path, capture: Path) -> None:
    """scapy dissects most of these protocols' ports further, so the records
    on them always reach the scapy path and the port checks for tcp/139,
    udp/137-138, udp/67-68, udp/546-547 ... are never put to the test. With
    those bindings removed the ports carry Raw payloads the lite checks
    decide from the bytes, and the results must still agree."""
    from pcapper import lite

    ports = {53, 67, 68, 88, 137, 138, 139, 161, 162, 389, 445, 464, 546, 547, 3268, 5353, 5355}
    saved = {cls: list(cls.payload_guess) for cls in (TCP, UDP)}
    try:
        for cls in saved:
            cls.payload_guess[:] = [
                (fields, child) for fields, child in cls.payload_guess
                if not ports & {value for value in fields.values() if isinstance(value, int)}
            ]
        lite.refresh_bindings()
        assert lite._TCP_PORTS is not None and not ports & lite._TCP_PORTS
        assert lite._UDP_PORTS is not None and not ports & lite._UDP_PORTS
        for analyze in ANALYSES:
            utils.clear_analysis_memo()
            pcap_cache._PACKET_CACHE.clear()
            from_disk = analyze(capture, show_status=False)
            packets, meta = pcap_cache.load_packets(capture, show_status=False)
            utils.clear_analysis_memo()
            in_memory = analyze(capture, show_status=False, packets=packets, meta=meta)
            assert repr(from_disk) == repr(in_memory), analyze.__name__
    finally:
        for cls, guess in saved.items():
            cls.payload_guess[:] = guess
        lite.refresh_bindings()
        utils.clear_analysis_memo()
        pcap_cache._PACKET_CACHE.clear()


@pytest.mark.parametrize("analyze", ANALYSES, ids=IDS)
def test_the_edge_capture_feeds_every_analysis(capture: Path, analyze) -> None:  # type: ignore[no-untyped-def]
    """The edge frames are not ignored by the analyses they target: each one
    finds traffic of its protocol (so the equality above compares results,
    not two empty summaries)."""
    summary = analyze(capture, show_status=False)
    counts = {
        "analyze_dns": lambda s: s.total_packets,
        "analyze_ldap": lambda s: sum(s.service_counts.values()),
        "analyze_kerberos": lambda s: sum(s.service_counts.values()),
        "analyze_netbios": lambda s: s.total_packets,
        "analyze_dhcp": lambda s: s.dhcp_packets,
        "analyze_syslog": lambda s: s.syslog_packets,
        "analyze_snmp": lambda s: s.snmp_packets,
        "analyze_ntlm": lambda s: s.ntlm_packets,
    }
    assert counts[analyze.__name__](summary) > 0


def test_the_edge_capture_reaches_every_path(capture: Path) -> None:
    """Records the lite parser answers with a Raw payload (with and without
    padding behind it), with a payload scapy dissects further, with no
    TCP/UDP (ARP among them), and records only scapy can answer."""
    kinds = set()
    for record in pcap_cache.iter_packets(capture, show_status=False, lite=True):
        l4 = record.lite_l4()
        if l4 is UNSUPPORTED:
            kinds.add("unsupported")
        elif l4 is None:
            l3 = record.headers()[1]
            kinds.add("arp" if l3 not in (None, UNSUPPORTED) and l3[0] == 1 else "no-l4")
        elif l4[5] < 0:
            kinds.add("app-layer")
        else:
            kinds.add("raw+padding" if len(record.original) > l4[6] else "raw")
    assert {"unsupported", "no-l4", "arp", "app-layer", "raw", "raw+padding"} <= kinds


# -- the skips, record by record ------------------------------------------------


def _ldap_keeps(pkt, src_ip: str, dst_ip: str) -> bool:  # type: ignore[no-untyped-def]
    """Whether analyze_ldap's loop does anything at all with a scapy packet."""
    tcp = pkt.getlayer(TCP)
    if tcp is not None:
        if ldap._ldap_roles(src_ip, dst_ip, int(tcp.sport), int(tcp.dport)) is not None:
            return True
        payload = bytes(getattr(tcp, "payload", b""))
        if payload and payload.startswith(ldap._HTTP_REQUEST_STARTS):
            return True
    udp = pkt.getlayer(UDP)
    return udp is not None and ldap._ldap_roles(src_ip, dst_ip, int(udp.sport), int(udp.dport)) is not None


def _syslog_keeps(pkt) -> bool:  # type: ignore[no-untyped-def]
    """Whether analyze_syslog's loop gets past its last ``continue``."""
    tcp, udp = pkt.getlayer(TCP), pkt.getlayer(UDP)
    layer = tcp if tcp is not None else udp
    if layer is None:
        return False
    payload = bytes(layer.payload)
    if pkt.haslayer(Raw):
        payload = bytes(pkt[Raw])
    if not payload:
        return False
    sport, dport = int(layer.sport), int(layer.dport)
    is_syslog = dport in syslog.SYSLOG_PORTS or (sport in syslog.SYSLOG_PORTS and dport >= 1024)
    if not is_syslog and not syslog._PRI_RE.match(payload):
        return False
    return bool(payload.decode("latin-1", errors="ignore").strip())


def _ntlm_keeps(pkt) -> bool:  # type: ignore[no-untyped-def]
    """Whether analyze_ntlm's loop finds an NTLM message in the packet."""
    if pkt.haslayer(TCP):
        payload = bytes(pkt[TCP].payload)
    elif pkt.haslayer(UDP):
        payload = bytes(pkt[UDP].payload)
    elif pkt.haslayer(Raw):
        payload = bytes(pkt[Raw])
    else:
        return False
    return bool(payload) and (
        payload.find(ntlm.NTLM_SIG) != -1 or ntlm._extract_http_ntlm(payload) is not None
    )


def test_lite_skips_match_scapy_record_for_record(tmp_path: Path, capture: Path) -> None:
    """A record the lite checks drop is one the scapy path does nothing with,
    and the checks do drop records (they are not always False)."""
    dropped = {"ldap": 0, "syslog": 0, "ntlm": 0}
    for path in _captures(tmp_path, capture):
        for record in pcap_cache.iter_packets(path, show_status=False, lite=True):
            pkt = record.materialize()
            src_ip, dst_ip = utils.extract_packet_endpoints(pkt)
            if src_ip and dst_ip and ldap._lite_not_ldap(record, src_ip, dst_ip):
                dropped["ldap"] += 1
                assert not _ldap_keeps(pkt, src_ip, dst_ip), (path.name, pkt.summary())
            if syslog._lite_not_syslog(record):
                dropped["syslog"] += 1
                assert not _syslog_keeps(pkt), (path.name, pkt.summary())
            if ntlm._lite_not_ntlm(record):
                dropped["ntlm"] += 1
                assert not _ntlm_keeps(pkt), (path.name, pkt.summary())
    assert all(dropped.values()), dropped


def test_dns_layers_are_bound_under_tcp_and_udp_only() -> None:
    """What lets DNS drop every record with no TCP/UDP layer: with all that a
    pcapper run imports loaded, scapy binds its DNS and LLMNR layers under
    TCP and UDP only (and the ICMP-quoted copies of those, which the lite
    parser leaves to scapy). A class choosing its payload at run time is
    never one the lite parser looks past."""
    import pcapper.cli  # noqa: F401 - every binding a run makes
    from scapy.config import conf

    names = {"DNS", "DNSTCP", "LLMNRQuery", "LLMNRResponse", "_LLMNR"}
    owners = {
        cls.__name__
        for cls in conf.layers
        for _fields, child in getattr(cls, "payload_guess", None) or ()
        if any(getattr(base, "__name__", "") in names for base in getattr(child, "__mro__", ()))
    }
    assert owners == {"TCP", "UDP", "TCPerror", "UDPerror"}


def test_arp_frames_have_no_raw_layer(tmp_path: Path, capture: Path) -> None:
    """What lets NTLM drop ARP records: scapy hangs whatever follows the ARP
    header on as Padding, so there is no Raw layer (nor TCP/UDP) to search."""
    trailing = 0
    for path in _captures(tmp_path, capture):
        for record in pcap_cache.iter_packets(path, show_status=False, lite=True):
            l3 = record.headers()[1]
            if record.lite_l4() is not None or l3 in (None, UNSUPPORTED) or l3[0] != 1:
                continue
            pkt = record.materialize()
            assert pkt.haslayer(ARP)
            assert not pkt.haslayer(Raw) and not pkt.haslayer(TCP) and not pkt.haslayer(UDP)
            trailing += len(record.original) > l3[1] + 14  # bytes past the ARP header
    assert trailing  # the edge capture's ARP frame carries an NTLM message there


def test_kerberos_ports_come_from_the_first_tcp_header(tmp_path: Path, capture: Path) -> None:
    """Kerberos reads ``lite_ports()``: a TCP header there is the packet's
    first TCP layer (what ``pkt[TCP]`` returns, whatever scapy builds behind
    it), a UDP header the only TCP/UDP layer."""
    tcp_beyond_l4 = 0
    for path in _captures(tmp_path, capture):
        for record in pcap_cache.iter_packets(path, show_status=False, lite=True):
            ports = record.lite_ports()
            if ports is None or ports is UNSUPPORTED:
                continue
            pkt = record.materialize()
            if ports[0]:
                tcp = pkt.getlayer(TCP)
                assert tcp is not None and (int(tcp.sport), int(tcp.dport)) == ports[1:3]
                tcp_beyond_l4 += record.lite_l4() is UNSUPPORTED
            else:
                udp = pkt.getlayer(UDP)
                assert pkt.getlayer(TCP) is None
                assert udp is not None and (int(udp.sport), int(udp.dport)) == ports[1:3]
    assert tcp_beyond_l4  # records lite_l4 leaves to scapy are among them


@pytest.mark.parametrize("analyze", ANALYSES, ids=IDS)
def test_shared_pass_plan_reads_lite_records(capture: Path, analyze) -> None:  # type: ignore[no-untyped-def]
    """In a shared pass the analysis asks for lite records, so it does not make
    the pass dissect every record."""
    plan = sharedpass.discover(capture, [(analyze, (), {})])
    reads = {call[0].__name__: read for call, read in zip(plan.calls, plan.reads)}
    assert reads[analyze.__name__] == "lite"
