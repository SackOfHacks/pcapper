"""Regression tests for the remaining analyzers reviewed on the second day of
the 2026-09 production-readiness review (Windows/AD, remote access, OT and
the small IT views). Each test names the failure it pins.
"""

from __future__ import annotations

import importlib
import zlib
from pathlib import Path

import pytest

from pcapper import utils
from test_review_batches import T0, _tcp, _udp, _write

DATA = Path(__file__).parent / "data"


def _dns_query(src: str, dst: str):
    from scapy.layers.dns import DNS, DNSQR  # type: ignore
    from scapy.layers.inet import IP, UDP  # type: ignore
    from scapy.layers.l2 import Ether  # type: ignore

    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=src, dst=dst) / UDP(sport=40000, dport=53) / DNS(id=1, rd=1, qd=DNSQR(qname="www.example.net"))


def _at(pkt, ts: float):
    pkt.time = ts
    return pkt


# --- LDAP ----------------------------------------------------------------------


class TestLdapRoles:
    def test_server_reply_keeps_the_server_role_and_the_window_is_ldap_only(self, tmp_path) -> None:
        """Every packet's destination was the "server", so a directory
        server's replies made each workstation a server and the server its
        own busiest client; the report window also spanned the whole capture."""
        from pcapper.ldap import analyze_ldap

        client, server = "192.168.10.50", "192.168.10.10"
        bind = b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"
        bind_resp = b"\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00"
        pcap = _write(tmp_path, "ldap.pcap", [
            _at(_dns_query(client, server), T0),
            _at(_tcp(client, server, 51000, 389, bind), T0 + 100),
            _at(_tcp(server, client, 389, 51000, bind_resp), T0 + 100.05),
        ])
        summary = analyze_ldap(pcap, show_status=False)
        assert summary.clients == {client: 2}
        assert summary.servers == {server: 2}
        assert summary.service_counts == {"TCP/389": 2}
        assert [(c.src_ip, c.dst_ip, c.dst_port) for c in summary.conversations] == [(client, server, 389)]
        assert summary.duration == pytest.approx(0.05)  # LDAP window, not the capture

    def test_ephemeral_source_port_389_is_not_a_directory_server(self, tmp_path) -> None:
        from pcapper.ldap import analyze_ldap

        pcap = _write(tmp_path, "ldap_eph.pcap", [_tcp("192.168.10.50", "93.184.216.34", 389, 443, b"\x16\x03\x01")])
        summary = analyze_ldap(pcap, show_status=False)
        assert not summary.servers and not summary.clients


# --- NTLM ---------------------------------------------------------------------------


def _ntlm(msg_type: int, size: int = 48) -> bytes:
    body = b"NTLMSSP\x00" + msg_type.to_bytes(4, "little")
    return body + b"\x00" * (size - len(body))


class TestNtlm:
    def test_challenge_from_the_server_counts_the_carrier_service(self, tmp_path) -> None:
        """The carrier service was read from the packet's dport only, so the
        server's Type-2 challenge (dport = client's ephemeral port) counted
        no service, and the report window spanned the whole capture."""
        from pcapper.ntlm import analyze_ntlm

        client, server = "192.168.10.50", "192.168.10.10"
        pcap = _write(tmp_path, "ntlm.pcap", [
            _at(_dns_query(client, server), T0),
            _at(_tcp(client, server, 51000, 445, _ntlm(1)), T0 + 100),
            _at(_tcp(server, client, 445, 51000, _ntlm(2)), T0 + 100.02),
        ])
        summary = analyze_ntlm(pcap, show_status=False)
        assert summary.ntlm_packets == 2
        assert summary.services == {"SMB": 2}
        assert summary.duration == pytest.approx(0.02)


# --- remote administration ports on the wrong side ---------------------------------


@pytest.mark.parametrize(
    "module, func, port, count_field",
    [
        ("pcapper.winrm", "analyze_winrm", 5985, "winrm_packets"),
        ("pcapper.rdp", "analyze_rdp", 3389, "rdp_packets"),
        ("pcapper.telnet", "analyze_telnet", 23, "telnet_packets"),
        ("pcapper.vnc", "analyze_vnc", 5900, "vnc_packets"),
        ("pcapper.teamviewer", "analyze_teamviewer", 5938, "tv_packets"),
    ],
)
def test_ephemeral_source_port_equal_to_a_service_port_is_not_that_service(tmp_path, module, func, port, count_field) -> None:
    """A flow from ephemeral port N to 443 was reported as service N with
    the roles inverted."""
    fn = getattr(importlib.import_module(module), func)
    pcap = _write(tmp_path, f"eph_{port}.pcap", [_tcp("192.168.10.50", "93.184.216.34", port, 443, b"\x16\x03\x01\x00\x10" + b"\x00" * 16)])
    summary = fn(pcap, show_status=False)
    assert getattr(summary, count_field) == 0
    assert not summary.server_counts


@pytest.mark.parametrize(
    "module, func, port",
    [("pcapper.winrm", "analyze_winrm", 5985), ("pcapper.rdp", "analyze_rdp", 3389), ("pcapper.vnc", "analyze_vnc", 5900)],
)
def test_server_reply_keeps_the_server_role(tmp_path, module, func, port) -> None:
    fn = getattr(importlib.import_module(module), func)
    client, server = "192.168.10.50", "192.168.10.10"
    pcap = _write(tmp_path, f"roles_{port}.pcap", [
        _tcp(client, server, 51000, port, b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"),
        _tcp(server, client, port, 51000, b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x00\x08\x00\x02\x00\x00\x00"),
    ])
    summary = fn(pcap, show_status=False)
    assert summary.client_counts == {client: 2}
    assert summary.server_counts == {server: 2}


# --- telnet / remote-access padding --------------------------------------------------


class TestPaddingIsNotPayload:
    def test_telnet_keystroke_segment_has_no_pad_bytes(self, tmp_path) -> None:
        """Character-mode telnet sends one keystroke per segment, always in a
        padded minimum frame; the transcript carried five NULs per key."""
        from scapy.all import rdpcap  # type: ignore

        from pcapper.telnet import _tcp_payload_bytes

        pcap = _write(tmp_path, "key.pcap", [_tcp("192.168.10.50", "192.168.10.10", 51000, 23, b"b", pad=5)])
        pkt = rdpcap(str(pcap))[0]
        assert bytes(pkt["TCP"].payload) == b"b" + b"\x00" * 5  # scapy's view
        assert _tcp_payload_bytes(pkt, pkt["TCP"]) == b"b"

    def test_pure_ack_to_a_plc_port_is_not_an_ot_command(self, tmp_path) -> None:
        from scapy.all import rdpcap  # type: ignore

        from pcapper.remote_access import _payload_len

        pcap = _write(tmp_path, "ack.pcap", [
            _tcp("192.168.10.50", "192.168.10.20", 51000, 502, flags="A", pad=6),
            _tcp("192.168.10.50", "192.168.10.20", 51000, 502, b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a"),
        ])
        pkts = rdpcap(str(pcap))
        assert _payload_len(pkts[0], pkts[0]["TCP"]) == 0
        assert _payload_len(pkts[1], pkts[1]["TCP"]) == 12


# --- syslog --------------------------------------------------------------------------


class TestSyslog:
    def test_html_is_not_syslog_but_a_pri_on_any_port_is(self, tmp_path) -> None:
        """Any TCP segment whose first bytes contained "<" was counted as a
        syslog message, so HTML and XML responses filled the syslog report."""
        from pcapper.syslog import analyze_syslog

        client, server = "192.168.10.50", "192.168.10.10"
        pcap = _write(tmp_path, "syslog.pcap", [
            _tcp(server, client, 80, 51000, b"<html><body>hello</body></html>"),
            _tcp(client, "192.168.10.11", 51001, 5000, b"<13>Sep 14 12:00:00 ws01 sshd[100]: Accepted password for bob\n"),
        ])
        summary = analyze_syslog(pcap, show_status=False)
        assert summary.syslog_packets == 1
        assert summary.client_counts == {client: 1}
        assert summary.server_counts == {"192.168.10.11": 1}


# --- VPN -----------------------------------------------------------------------------


class TestVpn:
    def test_port_match_needs_the_vpn_port_on_the_server_side(self) -> None:
        from pcapper.vpn import _vpn_port_match

        assert _vpn_port_match(50000, 1194)
        assert _vpn_port_match(1194, 50000)
        assert not _vpn_port_match(1194, 25)

    def test_window_spans_vpn_traffic_only(self, tmp_path) -> None:
        from pcapper.vpn import analyze_vpn

        pcap = _write(tmp_path, "vpn.pcap", [
            _at(_dns_query("192.168.10.50", "192.168.10.10"), T0),
            _at(_udp("192.168.10.50", "93.184.216.34", 50000, 1194, b"\x38" + b"\x00" * 40), T0 + 100),
        ])
        summary = analyze_vpn(pcap, show_status=False)
        assert summary.vpn_packets == 1
        assert summary.first_seen == pytest.approx(T0 + 100)


# --- SSDP / NetBIOS / GOOSE windows ---------------------------------------------------


class TestProtocolWindows:
    def test_ssdp_window(self, tmp_path) -> None:
        from pcapper.ssdp import analyze_ssdp

        notify = b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\nUSN: uuid:1\r\n\r\n"
        pcap = _write(tmp_path, "ssdp_w.pcap", [
            _at(_dns_query("192.168.10.50", "192.168.10.10"), T0),
            _at(_udp("192.168.10.20", "239.255.255.250", 49152, 1900, notify), T0 + 50),
        ])
        summary = analyze_ssdp(pcap, show_status=False)
        assert summary.ssdp_packets == 1 and summary.first_seen == pytest.approx(T0 + 50)

    def test_netbios_window(self, tmp_path) -> None:
        from test_review_batches import _nbns_registration

        from pcapper.netbios import analyze_netbios

        reg = _nbns_registration("WS01", 0x00, group=False)
        pcap = _write(tmp_path, "nb_w.pcap", [
            _at(_dns_query("192.168.10.50", "192.168.10.10"), T0),
            _at(_udp("192.168.10.50", "192.168.10.255", 137, 137, reg), T0 + 50),
            _at(_udp("192.168.10.50", "192.168.10.255", 137, 137, reg), T0 + 50.5),
        ])
        summary = analyze_netbios(pcap, show_status=False)
        assert summary.total_packets == 2
        assert summary.duration == pytest.approx(0.5)

    def test_goose_window(self, tmp_path) -> None:
        from scapy.layers.l2 import Ether  # type: ignore
        from scapy.packet import Raw  # type: ignore

        from pcapper.goose import analyze_goose

        goose = Ether(src="02:00:00:00:00:10", dst="01:0c:cd:01:00:01", type=0x88B8) / Raw(load=b"\x00\x01\x00\x30" + b"\x00" * 44)
        pcap = _write(tmp_path, "goose_w.pcap", [_at(_dns_query("192.168.10.50", "192.168.10.10"), T0), _at(goose, T0 + 10)])
        summary = analyze_goose(pcap, show_status=False)
        assert summary.goose_packets == 1 and summary.first_seen == pytest.approx(T0 + 10)


# --- PTP ------------------------------------------------------------------------------


def _ptp_frame(src: str, msg_type: int, seq: int):
    from scapy.layers.l2 import Ether  # type: ignore
    from scapy.packet import Raw  # type: ignore

    body = bytearray(44)
    body[0] = msg_type
    body[4] = 0  # domain
    body[30:32] = seq.to_bytes(2, "big")
    return Ether(src=src, dst="01:1b:19:00:00:00", type=0x88F7) / Raw(load=bytes(body))


class TestPtpSourceAttribution:
    def test_message_types_are_credited_to_the_sending_mac(self, tmp_path) -> None:
        """Every message type was credited to the first MAC ever seen, so the
        per-source Management finding named the wrong device."""
        from pcapper.ptp import analyze_ptp

        quiet, manager = "02:00:00:00:00:aa", "02:00:00:00:00:bb"
        pcap = _write(tmp_path, "ptp.pcap", [
            _ptp_frame(quiet, 0, 1),
            _ptp_frame(manager, 0, 1), _ptp_frame(manager, 1, 2), _ptp_frame(manager, 8, 3), _ptp_frame(manager, 13, 4),
        ])
        summary = analyze_ptp(pcap, show_status=False)
        hits = [d for d in summary.detections if d["summary"] == "PTP Management Activity"]
        assert len(hits) == 1
        assert manager in str(hits[0]["details"]) and quiet not in str(hits[0]["details"])


# --- IEC 60870-5-101/103 --------------------------------------------------------------


def _ft12(control: int) -> bytes:
    user = bytes([control, 0x01, 0x2D, 0x01, 0x06, 0x00, 0x01, 0x00, 0x05])  # C A TYPE VSQ COT CA IOA
    return b"\x68\x09\x09\x68" + user + bytes([sum(user) & 0xFF]) + b"\x16"


class TestIecRoles:
    def test_outstation_reply_does_not_become_a_master(self, tmp_path) -> None:
        """The sender of every frame was the "client"; the PRM bit says which
        end is the primary station."""
        from pcapper.iec101_103 import analyze_iec101_103

        master, outstation = "192.168.10.50", "192.168.10.60"
        pcap = _write(tmp_path, "iec.pcap", [
            _tcp(master, outstation, 51000, 2404, _ft12(0x73)),      # PRM=1
            _tcp(outstation, master, 2404, 51000, _ft12(0x08)),      # PRM=0
        ])
        summary = analyze_iec101_103(pcap, show_status=False)
        assert summary.candidate_packets == 2
        assert summary.client_counts == {master: 2}
        assert summary.server_counts == {outstation: 2}


# --- OPC Classic ----------------------------------------------------------------------


class TestOpcClassicRoles:
    def test_bind_ack_from_the_server_is_not_a_client(self, tmp_path) -> None:
        from pcapper.opc_classic import OPC_UUIDS, _uuid_to_le_bytes, analyze_opc_classic

        marker = _uuid_to_le_bytes(next(iter(OPC_UUIDS)))
        client, server = "192.168.10.50", "192.168.10.70"
        bind = b"\x05\x00\x0b\x03" + b"\x00" * 20 + marker
        bind_ack = b"\x05\x00\x0c\x03" + b"\x00" * 20 + marker
        pcap = _write(tmp_path, "opc.pcap", [
            _tcp(client, server, 51000, 135, bind),
            _tcp(server, client, 135, 51000, bind_ack),
        ])
        summary = analyze_opc_classic(pcap, show_status=False)
        assert summary.opc_packets == 2
        assert summary.client_counts == {client: 2}
        assert summary.server_counts == {server: 2}


# --- safety systems -------------------------------------------------------------------


class TestSafetyPorts:
    def test_service_port_must_be_on_the_server_side(self, tmp_path) -> None:
        from pcapper.safety import analyze_safety

        pcap = _write(tmp_path, "safety.pcap", [
            _tcp("192.168.10.50", "192.168.10.80", 50000, 1502, b"\x01\x00"),
            _tcp("192.168.10.80", "192.168.10.50", 1502, 50000, b"\x01\x00"),
            _tcp("192.168.10.50", "93.184.216.34", 1502, 443, b"\x16\x03\x01"),
        ])
        summary = analyze_safety(pcap, show_status=False)
        assert len(summary.hits) == 2
        assert summary.service_counts == {"Triconex/TriStation": 2}


# --- Modbus / AIM ephemeral ports -----------------------------------------------------


class TestEphemeralOtPorts:
    def test_modbus_port_on_the_source_side_only(self, tmp_path) -> None:
        from pcapper.modbus import analyze_modbus

        pcap = _write(tmp_path, "mb.pcap", [
            _tcp("192.168.10.50", "93.184.216.34", 502, 80, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
            _tcp("192.168.10.50", "192.168.10.20", 50000, 502, b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a"),
        ])
        summary = analyze_modbus(pcap, show_status=False)
        assert summary.modbus_packets == 1

    def test_aim_port_on_the_source_side_only(self, tmp_path) -> None:
        from pcapper.aim import analyze_aim

        pcap = _write(tmp_path, "aim.pcap", [_tcp("192.168.10.50", "93.184.216.34", 5190, 443, b"\x16\x03\x01")])
        assert analyze_aim(pcap, show_status=False).aim_packets == 0


# --- decode ---------------------------------------------------------------------------


class TestDecodeBounds:
    def test_decompression_is_bounded(self) -> None:
        from pcapper.decode import MAX_DECOMPRESSED_BYTES, _bounded_zlib

        small = zlib.compress(b"hello world" * 100)
        assert _bounded_zlib(small, zlib.MAX_WBITS) == b"hello world" * 100
        bomb = zlib.compress(b"\x00" * (MAX_DECOMPRESSED_BYTES + 1024))
        with pytest.raises(ValueError):
            _bounded_zlib(bomb, zlib.MAX_WBITS)


# --- DNS question helper --------------------------------------------------------------


class TestDnsQuestions:
    def test_every_question_is_returned_without_the_shim(self, recwarn) -> None:
        from scapy.layers.dns import DNS, DNSQR  # type: ignore

        dns = DNS(id=1, rd=1, qd=[DNSQR(qname="a.example.net"), DNSQR(qname="b.example.net", qtype="TXT")])
        assert utils.dns_questions(dns) == [("a.example.net", 1), ("b.example.net", 16)]
        assert utils.dns_questions(DNS(id=2, qd=[])) == []
        assert not [w for w in recwarn if "PacketListField" in str(w.message)]


# --- memoization and the packet view across every migrated analyzer --------------------


@pytest.mark.parametrize(
    "module, func, args",
    [
        ("pcapper.ldap", "analyze_ldap", ()),
        ("pcapper.ntlm", "analyze_ntlm", ()),
        ("pcapper.rpc", "analyze_rpc", ()),
        ("pcapper.winrm", "analyze_winrm", ()),
        ("pcapper.wmic", "analyze_wmic", ()),
        ("pcapper.powershell", "analyze_powershell", ()),
        ("pcapper.rdp", "analyze_rdp", ()),
        ("pcapper.telnet", "analyze_telnet", ()),
        ("pcapper.vnc", "analyze_vnc", ()),
        ("pcapper.teamviewer", "analyze_teamviewer", ()),
        ("pcapper.vpn", "analyze_vpn", ()),
        ("pcapper.remote_access", "analyze_remote_access", ()),
        ("pcapper.nfs", "analyze_nfs", ()),
        ("pcapper.syslog", "analyze_syslog", ()),
        ("pcapper.ssdp", "analyze_ssdp", ()),
        ("pcapper.netbios", "analyze_netbios", ()),
        ("pcapper.services", "analyze_services", ()),
        ("pcapper.protocols", "analyze_protocols", ()),
        ("pcapper.goose", "analyze_goose", ()),
        ("pcapper.sv", "analyze_sv", ()),
        ("pcapper.lldp_dcp", "analyze_lldp_dcp", ()),
        ("pcapper.ptp", "analyze_ptp", ()),
        ("pcapper.opc_classic", "analyze_opc_classic", ()),
        ("pcapper.iec101_103", "analyze_iec101_103", ()),
        ("pcapper.safety", "analyze_safety", ()),
        ("pcapper.synchrophasor", "analyze_synchrophasor", ()),
        ("pcapper.strings", "analyze_strings", ()),
        ("pcapper.search", "analyze_search", ("example",)),
        ("pcapper.qos", "analyze_qos", ()),
        ("pcapper.aim", "analyze_aim", ()),
        ("pcapper.ctf", "analyze_ctf", ()),
        ("pcapper.voip", "analyze_voip", ()),
        ("pcapper.obfuscation", "analyze_obfuscation", ()),
        ("pcapper.routing", "analyze_routing", ()),
        ("pcapper.wlan", "analyze_wlan", ()),
        ("pcapper.modbus", "analyze_modbus", ()),
        ("pcapper.dnp3", "analyze_dnp3", ()),
        ("pcapper.enip", "analyze_enip", ()),
        ("pcapper.cip", "analyze_cip", ()),
        ("pcapper.timeline", "analyze_timeline", ("192.168.10.50",)),
    ],
)
def test_migrated_analyzer_memoizes_and_honours_the_packet_view(module, func, args) -> None:
    from scapy.all import rdpcap  # type: ignore

    from pcapper.pcap_cache import load_capture_meta

    fn = getattr(importlib.import_module(module), func)
    path = DATA / "mixed.pcap"
    utils.clear_analysis_memo()
    first = fn(path, *args, show_status=False)
    assert fn(path, *args, show_status=False) is first
    packets = list(rdpcap(str(path)))
    view = fn(path, *args, show_status=False, packets=packets, meta=load_capture_meta(path))
    assert view == first


# --- routing -------------------------------------------------------------------------


class TestRouting:
    def test_window_spans_routing_traffic_only(self, tmp_path) -> None:
        from scapy.layers.inet import IP  # type: ignore
        from scapy.layers.l2 import Ether  # type: ignore
        from scapy.packet import Raw  # type: ignore

        from pcapper.routing import analyze_routing

        hello = b"\x02\x01\x00\x2c" + bytes([10, 0, 0, 1]) + b"\x00" * 4 + b"\x00" * 2 + b"\x00\x00" + b"\x00" * 8 + b"\x00" * 20
        ospf = Ether(src="02:00:00:00:00:01", dst="01:00:5e:00:00:05") / IP(src="10.0.0.1", dst="224.0.0.5", proto=89) / Raw(load=hello)
        pcap = _write(tmp_path, "ospf.pcap", [_at(_dns_query("192.168.10.50", "192.168.10.10"), T0), _at(ospf, T0 + 10)])
        summary = analyze_routing(pcap, show_status=False)
        assert summary.routing_packets == 1
        assert summary.first_seen == pytest.approx(T0 + 10)

    def test_bgp_port_on_the_source_side_only(self, tmp_path) -> None:
        from pcapper.routing import analyze_routing

        marker = b"\xff" * 16 + b"\x00\x13\x04"  # BGP KEEPALIVE
        pcap = _write(tmp_path, "bgp.pcap", [
            _tcp("10.0.0.1", "93.184.216.34", 179, 443, b"\x16\x03\x01"),
            _tcp("10.0.0.1", "10.0.0.2", 50000, 179, marker),
        ])
        summary = analyze_routing(pcap, show_status=False)
        assert summary.routing_packets == 1
        assert summary.protocol_counts == {"BGP": 1}
