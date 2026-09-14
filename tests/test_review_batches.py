"""Regression tests for the second day of the 2026-09 production-readiness
review: the per-protocol analyzers outside the core set. Each test names the
failure it pins; the failures were wrong reports, not errors.
"""

from __future__ import annotations

import dataclasses
from collections import Counter
from pathlib import Path

import pytest

from pcapper import utils

DATA = Path(__file__).parent / "data"
T0 = 1609459200.0


def _write(tmp_path: Path, name: str, packets: list) -> Path:
    from scapy.all import wrpcap  # type: ignore

    for index, pkt in enumerate(packets):
        if getattr(pkt, "time", None) in (None, 0):
            pkt.time = T0 + index * 0.01
    target = tmp_path / name
    wrpcap(str(target), packets)
    return target


def _udp(src: str, dst: str, sport: int, dport: int, payload: bytes):
    from scapy.layers.inet import IP, UDP  # type: ignore
    from scapy.layers.l2 import Ether  # type: ignore
    from scapy.packet import Raw  # type: ignore

    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(load=payload)


def _tcp(src: str, dst: str, sport: int, dport: int, payload: bytes = b"", *, seq: int = 1000, flags: str = "PA", pad: int = 0):
    """A TCP segment; ``pad`` appends Ethernet padding the way a NIC does on
    short frames, which scapy then dissects as ``Padding`` under TCP."""
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.layers.l2 import Ether  # type: ignore
    from scapy.packet import Raw  # type: ignore

    pkt = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=seq, flags=flags)
    if payload:
        pkt = pkt / Raw(load=payload)
    if pad:
        pkt = Ether(bytes(pkt) + b"\x00" * pad)
    return pkt


# --- QUIC ------------------------------------------------------------------------

_QUIC_INITIAL = b"\xc0\x00\x00\x00\x01" + b"\x08" + b"\x11" * 8 + b"\x00" + b"\x00" * 40


class TestQuicRoles:
    def test_server_reply_keeps_the_server_role(self, tmp_path) -> None:
        """A packet *from* 443 to an ephemeral port is the server's; the
        roles used to be assigned from the packet's dport alone and the
        flow was keyed on the client's ephemeral port."""
        from pcapper.quic import analyze_quic

        client, server = "192.168.10.50", "203.0.113.10"
        pcap = _write(tmp_path, "quic.pcap", [
            _udp(client, server, 51000, 443, _QUIC_INITIAL),
            _udp(server, client, 443, 51000, _QUIC_INITIAL),
        ])
        summary = analyze_quic(pcap, show_status=False)
        assert summary.quic_packets == 2
        assert summary.clients == {client: 2}
        assert summary.servers == {server: 2}
        assert summary.flow_counts == {f"{client}->{server}:443": 2}

    def test_ephemeral_source_port_443_is_not_a_quic_server(self, tmp_path) -> None:
        from pcapper.quic import analyze_quic

        pcap = _write(tmp_path, "quic_ephemeral.pcap", [
            _udp("192.168.10.50", "8.8.8.8", 443, 53, _QUIC_INITIAL),
        ])
        summary = analyze_quic(pcap, show_status=False)
        assert summary.quic_packets == 0 and not summary.servers


# --- Encrypted DNS ---------------------------------------------------------------


class TestEncryptedDns:
    def test_dot_reply_keeps_the_resolver_role(self, tmp_path) -> None:
        """The resolver's reply from 853 used to be counted as a new client."""
        from pcapper.encrypted_dns import analyze_encrypted_dns

        client, resolver = "192.168.10.50", "1.1.1.1"
        pcap = _write(tmp_path, "dot.pcap", [
            _tcp(client, resolver, 51000, 853, b"\x16\x03\x01\x00\x10" + b"\x00" * 16),
            _tcp(resolver, client, 853, 51000, b"\x16\x03\x03\x00\x10" + b"\x00" * 16),
        ])
        summary = analyze_encrypted_dns(pcap, show_status=False)
        assert summary.dot_packets == 2
        assert summary.clients == {client: 2}
        assert summary.servers == {resolver: 2}

    def test_doh_is_recognised_from_the_request_line_only(self) -> None:
        """``b"/resolve" in payload`` matched /resolver, /resolve-ticket and
        any body mentioning the word."""
        from pcapper.encrypted_dns import _is_doh_request

        assert _is_doh_request(b"POST /dns-query HTTP/1.1\r\nHost: dns.example\r\n\r\n")
        assert _is_doh_request(b"GET /resolve?name=example.com&type=A HTTP/1.1\r\n\r\n")
        assert _is_doh_request(b"GET /custom HTTP/1.1\r\nContent-Type: application/dns-message\r\n\r\n")
        assert not _is_doh_request(b"GET /resolver-status HTTP/1.1\r\nHost: x\r\n\r\n")
        assert not _is_doh_request(b"GET /tickets HTTP/1.1\r\n\r\n{\"path\": \"/resolve\"}")
        assert not _is_doh_request(b"\x16\x03\x01/dns-query")


# --- HTTP/2 --------------------------------------------------------------------------


class TestHttp2:
    def test_connection_is_tracked_after_the_preface(self, tmp_path) -> None:
        """Only segments containing the literal preface were counted, so the
        server side of an h2c connection never appeared and every binary
        frame after the preface was invisible."""
        from pcapper.http2 import HTTP2_PREFACE, analyze_http2

        client, server = "192.168.10.50", "192.168.10.10"
        settings = b"\x00\x00\x12\x04\x00\x00\x00\x00\x00" + b"\x00" * 18
        pcap = _write(tmp_path, "h2c.pcap", [
            _tcp(client, server, 51000, 8080, HTTP2_PREFACE + settings),
            _tcp(server, client, 8080, 51000, settings),
            _tcp(client, server, 51000, 8080, b"\x00\x00\x00\x04\x01\x00\x00\x00\x00", seq=2000),
        ])
        summary = analyze_http2(pcap, show_status=False)
        assert summary.http2_packets == 3
        assert summary.client_counts == {client: 3}
        assert summary.server_counts == {server: 3}

    def test_h2c_in_a_body_is_not_http2(self, tmp_path) -> None:
        from pcapper.http2 import analyze_http2

        pcap = _write(tmp_path, "not_h2c.pcap", [
            _tcp("192.168.10.50", "192.168.10.10", 51000, 80, b"POST /notes HTTP/1.1\r\nHost: a\r\n\r\nplanning the h2c rollout"),
        ])
        assert analyze_http2(pcap, show_status=False).http2_packets == 0

    def test_upgrade_request_and_switching_response_assign_roles(self) -> None:
        from pcapper.http2 import _h2c_upgrade

        assert _h2c_upgrade(b"GET / HTTP/1.1\r\nHost: a\r\nUpgrade: h2c\r\n\r\n") == "request"
        assert _h2c_upgrade(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n") == "response"
        assert _h2c_upgrade(b"GET / HTTP/1.1\r\nHost: a\r\n\r\nUpgrade: h2c") is None


# --- packet sizes -------------------------------------------------------------------


class TestSizes:
    def test_offloaded_super_packets_land_in_the_last_bucket(self) -> None:
        """The top bucket ended at 65535, so GRO/TSO "packets" above that fell
        through every bucket and vanished from the table."""
        from pcapper.sizes import _bucket_label

        assert _bucket_label(70000) == "5120+"
        assert _bucket_label(5120) == "5120+"
        assert _bucket_label(0) == "0-19"

    def test_sizes_are_wire_lengths_not_captured_lengths(self, tmp_path) -> None:
        from pcapper.sizes import analyze_sizes

        pcap = _write(tmp_path, "sizes.pcap", [_udp("192.168.10.50", "192.168.10.10", 40000, 53, b"x" * 100)])
        from scapy.all import rdpcap, wrpcap  # type: ignore

        pkts = rdpcap(str(pcap))
        pkts[0].wirelen = 1514
        wrpcap(str(pcap), pkts)
        summary = analyze_sizes(pcap, show_status=False)
        assert summary.total_bytes == 1514
        assert [b.label for b in summary.buckets if b.count] == ["1280-2559"]


# --- Kerberos --------------------------------------------------------------------------


def _krb_principal(name_type: int, *components: str) -> bytes:
    seq = b"".join(b"\x1b" + bytes([len(c)]) + c.encode() for c in components)
    seq = b"\x30" + bytes([len(seq)]) + seq
    return b"\xa0\x03\x02\x01" + bytes([name_type]) + b"\xa1" + bytes([len(seq)]) + seq


def _krb_realm(tag: int, realm: str) -> bytes:
    return bytes([tag, len(realm) + 2, 0x1B, len(realm)]) + realm.encode()


def _as_req(preauth: bool) -> bytes:
    body = b"\xa1\x03\x02\x01\x05\xa2\x03\x02\x01\x0a"  # pvno 5, msg-type 10
    if preauth:
        body += b"\xa3\x0b\x30\x09\x30\x07\xa1\x03\x02\x01\x02\xa2\x00"  # PA-ENC-TIMESTAMP
    body += _krb_principal(1, "svc_backup") + _krb_realm(0xA2, "CORP.EXAMPLE") + _krb_principal(2, "krbtgt", "CORP.EXAMPLE")
    return b"\x6a" + bytes([len(body) + 2]) + b"\x30" + bytes([len(body)]) + body


def _as_rep() -> bytes:
    body = b"\xa0\x03\x02\x01\x05\xa1\x03\x02\x01\x0b" + _krb_realm(0xA3, "CORP.EXAMPLE") + _krb_principal(1, "svc_backup")
    return b"\x6b" + bytes([len(body) + 2]) + b"\x30" + bytes([len(body)]) + body


class TestKerberos:
    def test_asrep_without_preauth_is_flagged_with_the_account(self, tmp_path) -> None:
        """AS-REP roasting used to be inferred from 'five AS-REPs and no
        PREAUTH_REQUIRED error', which every healthy domain logon satisfies.
        The evidence is an AS-REP answering an AS-REQ that carried no
        pre-authentication data."""
        from pcapper.kerberos import analyze_kerberos

        client, kdc = "192.168.10.50", "192.168.10.10"
        pcap = _write(tmp_path, "asrep.pcap", [
            _udp(client, kdc, 50088, 88, _as_req(preauth=False)),
            _udp(kdc, client, 88, 50088, _as_rep()),
        ])
        summary = analyze_kerberos(pcap, show_status=False)
        assert summary.request_types == {"AS-REQ": 1, "AS-REP": 1}
        hits = [d for d in summary.detections if "AS-REP roastable" in str(d["summary"])]
        assert len(hits) == 1 and "svc_backup@CORP.EXAMPLE" in str(hits[0]["details"])
        assert summary.principals.get("svc_backup@CORP.EXAMPLE")
        assert summary.spns.get("krbtgt")

    def test_preauthenticated_logon_is_not_roastable(self, tmp_path) -> None:
        from pcapper.kerberos import analyze_kerberos

        client, kdc = "192.168.10.50", "192.168.10.10"
        pcap = _write(tmp_path, "preauth.pcap", [
            _udp(client, kdc, 50088, 88, _as_req(preauth=True)),
            _udp(kdc, client, 88, 50088, _as_rep()),
        ])
        summary = analyze_kerberos(pcap, show_status=False)
        assert not any("roastable" in str(d["summary"]) for d in summary.detections)

    def test_kdc_reply_is_attributed_to_the_client(self, tmp_path) -> None:
        """The KDC's reply used to make the KDC a 'client' and the workstation
        a 'server', so every per-client heuristic named the wrong host."""
        from pcapper.kerberos import analyze_kerberos

        client, kdc = "192.168.10.50", "192.168.10.10"
        pcap = _write(tmp_path, "roles.pcap", [
            _udp(client, kdc, 50088, 88, _as_req(preauth=True)),
            _udp(kdc, client, 88, 50088, _as_rep()),
            _udp("192.168.10.51", "8.8.8.8", 88, 53, _as_req(preauth=True)),  # ephemeral 88, not Kerberos
        ])
        summary = analyze_kerberos(pcap, show_status=False)
        assert summary.clients == {client: 2}
        assert summary.servers == {kdc: 2}
        assert summary.service_counts == {"UDP/88": 2}


# --- FTP ---------------------------------------------------------------------------------


class TestFtp:
    def test_smtp_on_port_25_is_not_ftp(self, tmp_path) -> None:
        """Any 'NNN text' line or USER/PASS/QUIT on any port was parsed as FTP,
        so every SMTP and POP3 session appeared in the FTP report."""
        from pcapper.ftp import analyze_ftp

        client, server = "192.168.10.50", "192.168.10.25"
        pcap = _write(tmp_path, "smtp.pcap", [
            _tcp(server, client, 25, 51000, b"220 mail.example ESMTP Postfix\r\n"),
            _tcp(client, server, 51000, 25, b"EHLO ws01\r\n"),
            _tcp(server, client, 25, 51000, b"250 OK\r\n"),
            _tcp(client, server, 51000, 25, b"QUIT\r\n"),
            _tcp(server, client, 25, 51000, b"221 Bye\r\n"),
        ])
        summary = analyze_ftp(pcap, show_status=False)
        assert summary.ftp_packets == 0
        assert not summary.banner_counts and not summary.server_counts

    def test_ftp_on_a_non_standard_port_is_confirmed_and_replayed(self, tmp_path) -> None:
        from pcapper.ftp import analyze_ftp

        client, server = "192.168.10.50", "192.168.10.30"
        pcap = _write(tmp_path, "ftp3000.pcap", [
            _tcp(server, client, 3000, 51000, b"220 Welcome\r\n"),
            _tcp(client, server, 51000, 3000, b"USER bob\r\n", pad=18),
            _tcp(server, client, 3000, 51000, b"331 Password required for bob\r\n"),
            _tcp(client, server, 51000, 3000, b"PASS hunter2\r\n", pad=14),
            _tcp(server, client, 3000, 51000, b"230 Logged in\r\n"),
        ])
        summary = analyze_ftp(pcap, show_status=False)
        assert summary.ftp_packets == 5
        assert summary.user_counts == {"bob": 1}
        assert summary.password_counts == {"hunter2": 1}
        assert summary.banner_counts and summary.server_ports == {3000: 3}
        assert not any("\x00" in cmd for cmd in summary.command_counts), summary.command_counts
        assert [c.username for c in summary.credential_hits] == ["bob"]


# --- threats ----------------------------------------------------------------------------


class TestThreatsRates:
    def test_brute_force_needs_concentration(self) -> None:
        """20 SMB sessions over a working day were reported as brute force."""
        from pcapper.threats import _brute_force_candidates

        key = ("192.168.10.50", "192.168.10.10", "SMB")
        attempts = Counter({key: 20})
        assert _brute_force_candidates(attempts, {key: (T0, T0 + 8 * 3600)}) == []
        assert _brute_force_candidates(attempts, {key: (T0, T0 + 120)}) == [(*key, 20)]
        assert _brute_force_candidates(attempts, {}) == [(*key, 20)]  # no timestamps: keep the count rule

    def test_udp_flood_is_a_rate(self) -> None:
        """A resolver receiving 6000 datagrams over an hour is not a flood."""
        from pcapper.threats import _udp_flood_target

        counts = Counter({"192.168.10.10": 6000})
        assert _udp_flood_target(counts, 3600.0) is None
        assert _udp_flood_target(counts, 0.5) is None
        assert _udp_flood_target(counts, None) is None
        assert _udp_flood_target(counts, 10.0) == ("192.168.10.10", 6000)

    def test_crown_jewel_credit_is_deterministic(self) -> None:
        """The credited asset used to be picked from a set of IPs, so the
        report text depended on hash order."""
        from pcapper.threats import _elevate_crown_jewel_detections

        facts = {
            "10.0.0.1": {"is_dc": True, "hostname": "DC01", "roles": ["Domain Controller"]},
            "10.0.0.2": {"is_dc": False, "hostname": "SQL01", "roles": ["SQL Server"]},
        }
        for _ in range(20):
            det = {"severity": "warning", "details": "x", "top_sources": [("10.0.0.2", 5), ("10.0.0.1", 3)]}
            _elevate_crown_jewel_detections([det], facts)
            assert "ASSET: 10.0.0.2 (SQL01)" in det["details"]
            assert det["severity"] == "high"


# --- domain -----------------------------------------------------------------------------


class TestDomainExposure:
    def test_internet_dns_is_not_domain_control_exposure(self, tmp_path) -> None:
        """A query to a public resolver was reported as a public
        domain-service endpoint; only Kerberos/LDAP/SMB/RPC to a public
        address is."""
        from pcapper.domain import analyze_domain

        client = "192.168.10.50"
        pcap = _write(tmp_path, "domain.pcap", [
            _tcp(client, "8.8.8.8", 51000, 53, b"\x00\x1c" + b"\x00" * 28),
            # 203.0.113.0/24 is TEST-NET-3, which ipaddress reports as not
            # global; use a routable address for the exposed LDAP server.
            _tcp(client, "93.184.216.34", 51001, 389, b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"),
        ])
        summary = analyze_domain(pcap, show_status=False)
        exposure = summary.deterministic_checks.get("public_domain_service_exposure", [])
        assert len(exposure) == 1
        assert "93.184.216.34" in exposure[0] and "services=LDAP" in exposure[0]


# --- hostname ---------------------------------------------------------------------------


def _nbns_encode(name: str, suffix: int) -> str:
    raw = name.encode("ascii").ljust(15, b" ") + bytes([suffix])
    return "".join(chr((b >> 4) + 0x41) + chr((b & 0xF) + 0x41) for b in raw)


def _nbns_registration(name: str, suffix: int, *, group: bool) -> bytes:
    encoded = _nbns_encode(name, suffix).encode("ascii")
    header = b"\x12\x34" + b"\x29\x10" + b"\x00\x01\x00\x00\x00\x00\x00\x01"
    question = b"\x20" + encoded + b"\x00" + b"\x00\x20\x00\x01"
    nb_flags = b"\x80\x00" if group else b"\x00\x00"
    rr = b"\xc0\x0c" + b"\x00\x20\x00\x01" + b"\x00\x04\x93\xe0" + b"\x00\x06" + nb_flags + bytes([192, 168, 10, 50])
    return header + question + rr


class TestHostnameNbns:
    def test_suffix_is_decoded(self) -> None:
        from pcapper.hostname import _decode_nbns_level1_name_suffix

        assert _decode_nbns_level1_name_suffix(_nbns_encode("WS01", 0x20)) == ("WS01", 0x20)
        assert _decode_nbns_level1_name_suffix(_nbns_encode("CORP", 0x1C)) == ("CORP", 0x1C)

    def test_group_and_domain_role_names_are_not_hostnames(self, tmp_path) -> None:
        """A workstation registering the CORP<1C>/<1E> group names got
        'corp' recorded as its hostname."""
        from scapy.all import rdpcap  # type: ignore

        from pcapper.hostname import _extract_nbns_hostnames

        pcap = _write(tmp_path, "nbns.pcap", [
            _udp("192.168.10.50", "192.168.10.255", 137, 137, _nbns_registration("CORP", 0x1E, group=True)),
            _udp("192.168.10.50", "192.168.10.255", 137, 137, _nbns_registration("CORP", 0x1C, group=True)),
            _udp("192.168.10.50", "192.168.10.255", 137, 137, _nbns_registration("WS01", 0x00, group=False)),
        ])
        names = []
        for pkt in rdpcap(str(pcap)):
            payload = bytes(pkt["UDP"].payload)
            names.extend(_extract_nbns_hostnames(pkt, payload))
        assert [n.lower() for n in names] == ["ws01"]


class TestHostnameSsdp:
    def test_location_names_the_sender_not_the_multicast_group(self, tmp_path) -> None:
        from pcapper.hostname import analyze_hostname

        notify = (
            b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
            b"LOCATION: http://nas-01.local:8080/desc.xml\r\nNT: upnp:rootdevice\r\n\r\n"
        )
        pcap = _write(tmp_path, "ssdp.pcap", [_udp("192.168.10.20", "239.255.255.250", 49152, 1900, notify)])
        summary = analyze_hostname(pcap, None, show_status=False)
        ssdp = [f for f in summary.findings if f.protocol == "SSDP/UPnP"]
        assert ssdp and {f.mapped_ip for f in ssdp} == {"192.168.10.20"}
        assert {f.hostname for f in ssdp} == {"nas-01.local"}

    def test_ip_literal_is_not_a_hostname(self, tmp_path) -> None:
        from pcapper.hostname import analyze_hostname

        notify = b"NOTIFY * HTTP/1.1\r\nLOCATION: http://192.168.10.20:8080/desc.xml\r\nNT: upnp:rootdevice\r\n\r\n"
        pcap = _write(tmp_path, "ssdp_ip.pcap", [_udp("192.168.10.20", "239.255.255.250", 49152, 1900, notify)])
        summary = analyze_hostname(pcap, None, show_status=False)
        assert not [f for f in summary.findings if f.hostname == "192.168.10.20"]


# --- health -----------------------------------------------------------------------------


class TestHealthRetransmissions:
    def test_padded_pure_acks_are_not_retransmissions(self, tmp_path) -> None:
        """bytes(tcp.payload) includes the Ethernet pad, so repeated pure ACKs
        looked like repeated 6-byte data segments."""
        from pcapper.health import analyze_health

        client, server = "192.168.10.50", "192.168.10.10"
        pcap = _write(tmp_path, "acks.pcap", [
            _tcp(client, server, 51000, 445, flags="A", seq=5000, pad=6),
            _tcp(client, server, 51000, 445, flags="A", seq=5000, pad=6),
            _tcp(client, server, 51000, 445, flags="A", seq=5000, pad=6),
            _tcp(client, server, 51000, 445, b"REALDATA", seq=5000),
            _tcp(client, server, 51000, 445, b"REALDATA", seq=5000),
        ])
        summary = analyze_health(pcap, show_status=False)
        assert summary.tcp_packets == 5
        assert summary.retransmissions == 1


# --- malware ----------------------------------------------------------------------------


class TestMalwareRollup:
    def test_merged_verdict_is_the_worst_capture_not_a_sum(self) -> None:
        """Three captures each scoring 2 ("SUSPICIOUS") merged to a verdict
        with no score at all; the roll-up now carries the worst single
        capture's score and wording, with its reasons and evidence lists."""
        from pcapper.malware import _verdict_for_score, analyze_malware, merge_malware_summaries

        utils.clear_analysis_memo()
        base = analyze_malware(DATA / "dns.pcap", show_status=False)
        a = dataclasses.replace(base, malware_score=2, verdict_reasons=["two"])
        b = dataclasses.replace(base, malware_score=7, verdict_reasons=["seven"])
        merged = merge_malware_summaries([a, b, a])
        assert merged.malware_score == 7
        assert merged.malware_verdict.startswith("MALWARE PRESENT")
        assert merged.malware_confidence == "high"
        assert "dns.pcap: seven" in merged.verdict_reasons and "dns.pcap: two" in merged.verdict_reasons
        assert _verdict_for_score(0)[0].startswith("NO STRONG SIGNAL")


# --- memoization of the migrated analyzers ----------------------------------------------


@pytest.mark.parametrize(
    "module, func",
    [
        ("pcapper.quic", "analyze_quic"),
        ("pcapper.encrypted_dns", "analyze_encrypted_dns"),
        ("pcapper.http2", "analyze_http2"),
        ("pcapper.sizes", "analyze_sizes"),
        ("pcapper.kerberos", "analyze_kerberos"),
        ("pcapper.ftp", "analyze_ftp"),
        ("pcapper.health", "analyze_health"),
        ("pcapper.malware", "analyze_malware"),
        ("pcapper.domain", "analyze_domain"),
    ],
)
def test_migrated_analyzers_are_memoized_and_accept_a_packet_view(module: str, func: str) -> None:
    import importlib

    from scapy.all import rdpcap  # type: ignore

    from pcapper.pcap_cache import load_capture_meta

    fn = getattr(importlib.import_module(module), func)
    path = DATA / "mixed.pcap"
    utils.clear_analysis_memo()
    first = fn(path, show_status=False)
    assert fn(path, show_status=False) is first
    packets = list(rdpcap(str(path)))
    meta = load_capture_meta(path)
    view = fn(path, show_status=False, packets=packets, meta=meta)
    assert view.total_packets == first.total_packets == len(packets)
