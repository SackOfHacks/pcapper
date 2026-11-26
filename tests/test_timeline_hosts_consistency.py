"""The host reports agree with the protocol reports.

* --timeline shows the server side of an OT flow (a PLC, an outstation) from
  that side, and reads commands only in the request direction;
* --timeline lists every kind of credential exposure, never the secret;
* the table-driven OT protocols (KNXnet/IP, ADS/AMS ...) are OT on the timeline;
* the name an ADS discovery reply gives (--ads) is a --hostnames name, and an
  EtherNet/IP ListIdentity product (--enip) is the --hostdetails device;
* --overview names hosts from DHCP, ADS and ENIP, and calls a capture with
  FINS in it an OT/ICS capture (but not one whose client port is 9600).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from pcapper import timeline
from pcapper.hostdetails import analyze_hostdetails
from pcapper.hostname import analyze_hostname
from pcapper.ot_extra import OT_EXTRA
from pcapper.ot_ports import OT_PORT_PROTOCOLS
from pcapper.overview import analyze_overview
from pcapper.reporting import render_overview_summary
from pcapper.timeline import analyze_timeline
from pcapper.utils import redact_sensitive_text
from test_review_batches import T0, _tcp, _udp, _write

CLIENT = "192.0.2.10"
PLC = "192.0.2.20"


def _timed(packets: list) -> list:
    for index, pkt in enumerate(packets):
        pkt.time = T0 + index * 0.1
    return packets


def _handshake(client: str, server: str, cport: int, sport: int) -> list:
    return [
        _tcp(client, server, cport, sport, seq=100, flags="S"),
        _tcp(server, client, sport, cport, seq=500, flags="SA"),
        _tcp(client, server, cport, sport, seq=101, flags="A"),
    ]


def _texts(summary) -> list[str]:
    return [f"{event.category} | {event.summary} | {event.details}" for event in summary.events]


# --- D1: the server side of an OT flow ---------------------------------------------


def _s7(param: bytes, rosctr: int) -> bytes:
    header = b"\x32" + bytes([rosctr]) + b"\x00\x00\x00\x01" + len(param).to_bytes(2, "big") + b"\x00\x00"
    error = b"\x00\x00" if rosctr in (0x02, 0x03) else b""
    cotp = b"\x02\xf0\x80" + header + error + param
    return b"\x03\x00" + (len(cotp) + 4).to_bytes(2, "big") + cotp


def test_s7_stop_is_on_the_plc_timeline_worded_from_the_plc(tmp_path: Path) -> None:
    stop = b"\x29\x00\x00\x00\x00\x00\x09P_PROGRAM"
    capture = _write(tmp_path, "s7_stop.pcap", _timed(_handshake(CLIENT, PLC, 50000, 102) + [
        _tcp(CLIENT, PLC, 50000, 102, _s7(stop, 0x01), seq=101),
        _tcp(PLC, CLIENT, 102, 50000, _s7(b"\x29", 0x03), seq=501),
    ]))

    plc = analyze_timeline(capture, PLC, show_status=False)
    assert plc.ot_protocol_counts.get("S7")
    texts = _texts(plc)
    assert any(t.startswith(f"S7 | Received S7 PLCStop from {CLIENT} | {CLIENT} -> {PLC}") for t in texts), texts
    assert any(t.startswith(f"S7 | Inbound S7 flow | {CLIENT} -> {PLC}:102") for t in texts), texts

    client = analyze_timeline(capture, CLIENT, show_status=False)
    summaries = [event.summary for event in client.events if event.category == "S7"]
    assert "S7 PLCStop" in summaries
    assert not any(summary.startswith("Received") for summary in summaries)
    # The PLC's acknowledgement is a reply, not a command the client sent.
    assert "S7 AckData" not in summaries and summaries.count("S7 PLCStop") == 1


def _dnp3(user_data: bytes, *, src: int, dst: int, control: int) -> bytes:
    from pcapper.dnp3 import _crc16_dnp

    header = b"\x05\x64" + bytes((5 + len(user_data), control)) + dst.to_bytes(2, "little") + src.to_bytes(2, "little")
    frame = header + _crc16_dnp(header).to_bytes(2, "little")
    for offset in range(0, len(user_data), 16):
        block = user_data[offset : offset + 16]
        frame += block + _crc16_dnp(block).to_bytes(2, "little")
    return frame


def test_dnp3_outstation_sees_the_operate_it_received(tmp_path: Path) -> None:
    operate = _dnp3(b"\xc0\xc0\x05", src=3, dst=1, control=0xC4)
    response = _dnp3(b"\xc0\xc0\x81\x00\x00", src=1, dst=3, control=0x44)
    capture = _write(tmp_path, "dnp3_operate.pcap", _timed(_handshake(CLIENT, PLC, 40000, 20000) + [
        _tcp(CLIENT, PLC, 40000, 20000, operate, seq=101),
        _tcp(PLC, CLIENT, 20000, 40000, response, seq=501),
    ]))

    outstation = _texts(analyze_timeline(capture, PLC, show_status=False))
    assert any(f"DNP3 | Received DNP3 Direct Operate from {CLIENT} |" in t for t in outstation), outstation
    master = _texts(analyze_timeline(capture, CLIENT, show_status=False))
    assert any("DNP3 | DNP3 Direct Operate |" in t for t in master), master
    # A response is not a command, on either side.
    assert not any("DNP3 Response" in t for t in outstation + master)


def _mbap(pdu: bytes, unit: int = 1) -> bytes:
    return b"\x00\x01\x00\x00" + (len(pdu) + 1).to_bytes(2, "big") + bytes([unit]) + pdu


def test_modbus_commands_are_read_from_requests_only(tmp_path: Path) -> None:
    capture = _write(tmp_path, "modbus_write.pcap", _timed(_handshake(CLIENT, PLC, 50001, 502) + [
        _tcp(CLIENT, PLC, 50001, 502, _mbap(b"\x06\x00\x10\x00\x2a"), seq=101),
        _tcp(PLC, CLIENT, 502, 50001, _mbap(b"\x06\x00\x10\x00\x2a"), seq=501),
        _tcp(CLIENT, PLC, 50001, 502, _mbap(b"\x03\x10\x00\x00\x01"), seq=113),
        _tcp(PLC, CLIENT, 502, 50001, _mbap(b"\x83\x02"), seq=513),
    ]))

    client = analyze_timeline(capture, CLIENT, show_status=False)
    writes = [e for e in client.events if e.summary == "Modbus Write Single Register"]
    assert len(writes) == 1 and writes[0].details.startswith(f"{CLIENT} -> {PLC}:502")
    exceptions = [e for e in client.events if e.summary == "Modbus exception Read Holding Registers"]
    assert len(exceptions) == 1 and exceptions[0].details.startswith(f"{PLC}:502 -> {CLIENT}")

    plc = _texts(analyze_timeline(capture, PLC, show_status=False))
    assert any(f"Received Modbus Write Single Register from {CLIENT}" in t for t in plc), plc
    assert any(f"Sent Modbus exception Read Holding Registers to {CLIENT}" in t for t in plc), plc


def test_a_client_source_port_that_is_an_ot_port_is_not_ot(tmp_path: Path) -> None:
    """DNS/53 and STUN/3478 replying to client ports 44818 and 55565, and a
    TCP server on 9000 answering a client whose source port is 44818: the
    handshake shows 9000 is the service, so its replies are not ENIP requests
    to the client."""
    capture = _write(tmp_path, "coincidence.pcap", _timed([
        _udp(CLIENT, "192.0.2.53", 44818, 53, b"\x00\x01query"),
        _udp("192.0.2.53", CLIENT, 53, 44818, b"\x00\x01reply"),
        _udp("192.0.2.54", CLIENT, 3478, 55565, b"\x01\x01stun"),
        *_handshake(CLIENT, "192.0.2.90", 44818, 9000),
        _tcp(CLIENT, "192.0.2.90", 44818, 9000, b"hello", seq=101),
        _tcp("192.0.2.90", CLIENT, 9000, 44818, b"\x65\x00world", seq=501),
    ]))

    summary = analyze_timeline(capture, CLIENT, show_status=False)
    assert not summary.ot_protocol_counts
    assert not [e for e in summary.events if e.category in timeline.OT_CATEGORIES]


def test_ot_service_port_rule() -> None:
    assert timeline._ot_service_port(50000, 102) == (102, True)
    assert timeline._ot_service_port(102, 50000) == (102, False)
    assert timeline._ot_service_port(2222, 502) == (502, True)  # master sourcing from 2222
    assert timeline._ot_service_port(502, 2222) == (502, False)
    assert timeline._ot_service_port(44818, 20000) == (20000, True)  # a Linux client port
    assert timeline._ot_service_port(20000, 44818) == (20000, False)
    assert timeline._ot_service_port(47808, 47808) == (47808, True)  # peer to peer
    for sport, dport in ((53, 44818), (44818, 53), (3478, 55565), (8080, 44818)):
        assert timeline._ot_service_port(sport, dport) is None


# --- D2: every credential exposure, never the secret -------------------------------


def test_every_credential_kind_is_listed_capped_and_never_its_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(timeline, "_TIMELINE_CREDS_PER_KIND", 2)
    server = "192.0.2.21"
    passwords = ["hunter2x", "letmein9", "s3cretpw", "tr0ub4dor"]
    packets = []
    for index, password in enumerate(passwords):
        cport = 51000 + index
        packets += _handshake(CLIENT, server, cport, 21)
        packets.append(_tcp(CLIENT, server, cport, 21, b"USER operator\r\n", seq=101))
        packets.append(_tcp(CLIENT, server, cport, 21, f"PASS {password}\r\n".encode(), seq=116))
    packets += _handshake(CLIENT, server, 52000, 80)
    packets.append(_tcp(CLIENT, server, 52000, 80, (
        b"GET /admin HTTP/1.1\r\nHost: plc-web\r\nAuthorization: Basic b3BlcmF0b3I6d2ViUGFzczE=\r\n\r\n"
    ), seq=101))
    capture = _write(tmp_path, "creds.pcap", _timed(packets))

    summary = analyze_timeline(capture, CLIENT, show_status=False)
    creds = [e for e in summary.events if e.category == "Credentials"]
    kinds = {e.summary for e in creds}
    assert "Credential exposed (FTP USER)" in kinds
    assert "Credential exposed (HTTP Basic Auth)" in kinds  # not only SMTP
    users = [e for e in creds if e.summary == "Credential exposed (FTP USER)"]
    assert len(users) == 1 and "(seen 4×, last 2021-01-01T00:00:01.800000Z)" in users[0].details
    passes = [e for e in creds if e.summary == "Credential exposed (FTP PASS)"]
    assert len(passes) == 2  # the cap, then one row says how many more
    assert any(e.summary == "2 more credential exposures not listed (FTP PASS)" for e in creds)
    text = "\n".join(_texts(summary))
    for secret in passwords + ["webPass1", "b3BlcmF0b3I6d2ViUGFzczE="]:
        assert secret not in text
    assert re.search(r"secret=\[len=8#[0-9a-f]{4}\]", passes[0].details)
    assert "secret=[REDACTED]" in redact_sensitive_text(passes[0].details)


def test_the_credential_analysis_cap_is_said(tmp_path: Path, monkeypatch) -> None:
    """When the credential analysis keeps only its first N hits, a host's
    timeline says so, at the last hit kept. The real cap is high, so the test
    lowers it to 200 to reach it with a small capture."""
    from pcapper import creds as creds_module

    monkeypatch.setattr(creds_module, "MAX_STORED_HITS", 200)
    server = "192.0.2.21"
    packets = _handshake(CLIENT, server, 53000, 21)
    packets += [_tcp(CLIENT, server, 53000, 21, f"PASS guess{n:04d}\r\n".encode(), seq=101 + 15 * n) for n in range(210)]
    capture = _write(tmp_path, "many_creds.pcap", _timed(packets))

    summary = analyze_timeline(capture, CLIENT, show_status=False)
    capped = [e for e in summary.events if e.summary == "Credential analysis capped"]
    assert len(capped) == 1 and capped[0].ts is not None
    assert capped[0].details.startswith("it kept 200 of 210 credential hits")
    assert any(e.summary.endswith("credential exposures not listed (FTP PASS)") for e in summary.events)


def test_secret_preview_tells_secrets_apart_without_showing_them() -> None:
    first, second = timeline._secret_preview("password1"), timeline._secret_preview("password2")
    assert first != second and first == timeline._secret_preview("password1")
    assert "pass" not in first and first.startswith("[len=9#")
    assert timeline._secret_preview("") == "-"


# --- D3: the table-driven OT protocols are OT ---------------------------------------


def test_every_registry_protocol_is_an_ot_timeline_category() -> None:
    assert set(OT_PORT_PROTOCOLS.values()) <= timeline.OT_CATEGORIES
    for spec in OT_EXTRA:
        assert OT_PORT_PROTOCOLS[spec.ports[0]] in timeline.OT_CATEGORIES, spec.label
    assert {"Credentials", "Remote IN"} <= timeline.NON_OT_CATEGORIES
    assert {"KNXnet/IP", "ADS/AMS", "POWERLINK", "Credentials"} <= set(timeline.TIMELINE_CATEGORIES)


def _twincat(service: int, tags: list[tuple[int, bytes]], netid: bytes = bytes((192, 0, 2, 10, 1, 1))) -> bytes:
    body = b"".join(tag.to_bytes(2, "little") + len(value).to_bytes(2, "little") + value for tag, value in tags)
    return (
        b"\x03\x66\x14\x71" + b"\x00\x00\x00\x00" + service.to_bytes(4, "little")
        + netid + (10000).to_bytes(2, "little") + len(tags).to_bytes(4, "little") + body
    )


def _twincat_capture(tmp_path: Path) -> Path:
    netid = bytes((192, 0, 2, 10, 1, 1))
    return _write(tmp_path, "twincat.pcap", _timed([
        _udp(CLIENT, PLC, 48899, 48899, _twincat(1, [])),
        _udp(PLC, CLIENT, 48899, 48899, _twincat(0x80000001, [(5, b"CX_TEST01\x00")], bytes((192, 0, 2, 20, 1, 1)))),
        _udp(CLIENT, PLC, 48899, 48899, _twincat(6, [
            (12, b"ENG-WS01\x00"), (7, netid), (13, b"Administrator\x00"), (2, b"Sup3rS3cret\x00"), (5, b"192.0.2.10\x00"),
        ])),
        _udp(PLC, CLIENT, 48899, 48899, _twincat(0x80000006, [(1, b"\x00\x00\x00\x00")])),
    ]))


def test_ads_findings_reach_the_plc_timeline_as_ot(tmp_path: Path) -> None:
    capture = _twincat_capture(tmp_path)
    summary = analyze_timeline(capture, PLC, show_status=False)
    assert summary.ot_protocol_counts.get("ADS/AMS")
    findings = [e for e in summary.events if e.category == "ADS/AMS" and e.source == "ads"]
    assert any(e.summary == "ADS AddRoute with cleartext Windows credentials" for e in findings), _texts(summary)
    assert "ADS/AMS" in summary.ot_activity_bins  # counted as OT activity


# --- E1/E2: ADS and ENIP names reach the host reports ------------------------------


def test_ads_discovery_name_is_a_hostname(tmp_path: Path) -> None:
    capture = _twincat_capture(tmp_path)
    findings = analyze_hostname(capture, None, show_status=False).findings
    named = {(f.hostname, f.mapped_ip, f.method, f.confidence) for f in findings}
    assert ("cx_test01", PLC, "TwinCAT ADS discovery reply", "HIGH") in named
    assert ("eng-ws01", CLIENT, "TwinCAT AddRoute route name", "LOW") in named
    assert not any("Sup3rS3cret" in f.details for f in findings)
    scoped = analyze_hostname(capture, PLC, show_status=False).findings
    assert {f.hostname for f in scoped} == {"cx_test01"}


def _enip(command: int, data: bytes = b"") -> bytes:
    return command.to_bytes(2, "little") + len(data).to_bytes(2, "little") + b"\x00" * 20 + data


def _list_identity(product: bytes) -> bytes:
    identity = (
        b"\x01\x00" + b"\x00" * 16
        + (1).to_bytes(2, "little") + (12).to_bytes(2, "little") + (58).to_bytes(2, "little")
        + bytes((4, 3)) + b"\x00\x00" + (5393806).to_bytes(4, "little")
        + bytes((len(product),)) + product + b"\x03"
    )
    return b"\x01\x00" + b"\x0c\x00" + len(identity).to_bytes(2, "little") + identity


def test_enip_list_identity_is_the_device_in_host_details_and_overview(tmp_path: Path) -> None:
    capture = _write(tmp_path, "enip_identity.pcap", _timed([
        _udp(CLIENT, PLC, 50000, 44818, _enip(0x0063)),
        _udp(PLC, CLIENT, 44818, 50000, _enip(0x0063, _list_identity(b"1756-ENBT/A"))),
    ]))

    details = analyze_hostdetails(capture, PLC, show_status=False)
    assert details.operating_system.startswith("1756-ENBT/A ("), details.operating_system
    assert any(e.startswith("EtherNet/IP ListIdentity:") and "serial=5393806" in e for e in details.os_evidence)

    overview = analyze_overview(capture, show_status=False)
    rows = [row for row in overview.ip_activity if row.get("ip") == PLC]
    assert rows and str(rows[0].get("os", "")).startswith("1756-ENBT/A")


# --- E3/F3: the overview's names and capture type -----------------------------------


def _dhcp(message: str, src: str, dst: str, yiaddr: str, options: list) -> object:
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether

    client = message in ("discover", "request")
    return (
        Ether(src="02:00:00:00:00:aa" if client else "02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")
        / IP(src=src, dst=dst)
        / UDP(sport=68 if client else 67, dport=67 if client else 68)
        / BOOTP(op=1 if client else 2, chaddr=bytes.fromhex("0200000000aa"), xid=0x1234, yiaddr=yiaddr)
        / DHCP(options=[("message-type", message), *options, "end"])
    )


def test_overview_names_dhcp_clients_and_ads_devices(tmp_path: Path) -> None:
    leased = "192.0.2.77"
    server = [("server_id", "192.0.2.1"), ("lease_time", 3600)]
    packets = [
        _dhcp("discover", "0.0.0.0", "255.255.255.255", "0.0.0.0", [("hostname", b"eng-ws07")]),
        _dhcp("offer", "192.0.2.1", leased, leased, server),
        _dhcp("request", "0.0.0.0", "255.255.255.255", "0.0.0.0",
              [("requested_addr", leased), ("server_id", "192.0.2.1"), ("hostname", b"eng-ws07")]),
        _dhcp("ack", "192.0.2.1", leased, leased, server),
        *_handshake(leased, "192.0.2.80", 50000, 443),
    ]
    twincat = _twincat_capture(tmp_path)
    from scapy.all import rdpcap  # type: ignore

    capture = _write(tmp_path, "names.pcap", _timed(packets + list(rdpcap(str(twincat)))))

    overview = analyze_overview(capture, show_status=False)
    names = {row.get("ip"): row.get("hostname") for row in overview.ip_activity}
    assert names.get(leased) == "eng-ws07", names
    assert names.get(PLC) == "CX_TEST01", names


def _fins(icf: int, command: int, data: bytes) -> bytes:
    return bytes((icf, 0x00, 0x02, 0x00, 0x14, 0x00, 0x00, 0x0A, 0x00, 0x01)) + command.to_bytes(2, "big") + data


def test_a_fins_capture_is_an_ot_capture(tmp_path: Path) -> None:
    capture = _write(tmp_path, "fins_read.pcap", _timed([
        _udp(CLIENT, PLC, 50002, 9600, _fins(0x80, 0x0101, b"\x82\x00\x64\x00\x00\x01")),
        _udp(PLC, CLIENT, 9600, 50002, _fins(0xC0, 0x0101, b"\x00\x00\x12\x34")),
    ]))

    overview = analyze_overview(capture, show_status=False)
    assert "FINS" in overview.ot_protocols, overview.ot_protocols
    assert "OT/ICS capture" in render_overview_summary(overview)


def test_a_goose_capture_is_an_ot_capture_and_lldp_alone_is_not(tmp_path: Path) -> None:
    """GOOSE is Layer 2: no port or service label names it, but the GOOSE
    analyzer the threat correlation ran found it. LLDP, which every managed
    switch sends, is counted with the OT protocols but is not OT by itself."""
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw

    from test_goose_forensics import _goose_packet, _goose_payload

    goose = _write(tmp_path, "goose.pcap", _timed([_goose_packet(_goose_payload(sq_num=n)) for n in range(4)]))
    overview = analyze_overview(goose, show_status=False)
    assert "goose" in overview.modules_run and "GOOSE" in overview.ot_protocols, overview.ot_protocols

    tlvs = (
        (1 << 9 | 7).to_bytes(2, "big") + b"\x04\x02\x00\x00\x00\x00\x99"
        + (2 << 9 | 5).to_bytes(2, "big") + b"\x05eth0"
        + (3 << 9 | 2).to_bytes(2, "big") + (120).to_bytes(2, "big")
        + b"\x00\x00"
    )
    lldp = _write(tmp_path, "lldp.pcap", _timed([
        Ether(src="02:00:00:00:00:99", dst="01:80:c2:00:00:0e", type=0x88CC) / Raw(load=tlvs) for _ in range(3)
    ]))
    overview = analyze_overview(lldp, show_status=False)
    assert not overview.ot_protocols, overview.ot_protocols


def test_an_ot_port_number_on_a_client_does_not_make_an_ot_capture(tmp_path: Path) -> None:
    """DNS replies to client source ports 9600 (FINS), 18245 (SRTP) and 55565
    (Honeywell CDA): the services inventory files each as a UDP service and
    the threat correlation counts each by port, but no analyzer finds the
    protocol and no host accepted a connection there."""
    resolver = "192.0.2.53"
    packets = []
    for port in (9600, 18245, 55565):
        packets.append(_udp(CLIENT, resolver, port, 53, b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"))
        packets.append(_udp(resolver, CLIENT, 53, port, b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"))
    capture = _write(tmp_path, "dns_coincidence.pcap", _timed(packets))

    overview = analyze_overview(capture, show_status=False)
    assert not overview.ot_protocols, overview.ot_protocols
    assert "IT/enterprise capture" in render_overview_summary(overview)
