"""The table-driven OT analyzers (backlog 1.6): KNXnet/IP, XGT FEnet, ROC Plus,
Beckhoff ADS/AMS, DLMS/COSEM, ANSI C12.22, LonTalk/CN-IP and POWERLINK.

Frames are built byte for byte in the shapes seen in the reference captures
(KNX IDS dataset, Zhejiang 2026 XGT CTF, CISA ICSNPP ROC Plus / C12.22
traces, ITI Beckhoff captures, emreekin LonTalk, automayt POWERLINK).
"""

from __future__ import annotations

import sys

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap  # type: ignore

from pcapper import cli
from pcapper.ads import analyze_ads
from pcapper.c1222 import analyze_c1222
from pcapper.dlms import analyze_dlms
from pcapper.knx import analyze_knx, parse_knx
from pcapper.lontalk import analyze_lontalk, parse_cnip
from pcapper.overview import analyze_overview
from pcapper.powerlink import analyze_powerlink
from pcapper.rocplus import analyze_rocplus, crc16_modbus
from pcapper.xgt import analyze_xgt

A, B = "192.168.21.220", "192.168.21.250"


def _udp(path, frames, sport=40000, dport=3671):
    pkts = []
    for i, (reply, data) in enumerate(frames):
        s, d, sp, dp = (B, A, dport, sport) if reply else (A, B, sport, dport)
        pkt = Ether() / IP(src=s, dst=d) / UDP(sport=sp, dport=dp) / Raw(data)
        pkt.time = 1_700_000_000 + i * 0.01
        pkts.append(pkt)
    wrpcap(str(path), pkts)


def _tcp(path, frames, dport, sport=50000):
    pkts, cseq, sseq = [], 1, 1
    for i, (reply, data) in enumerate(frames):
        if reply:
            pkt = Ether() / IP(src=B, dst=A) / TCP(sport=dport, dport=sport, seq=sseq, flags="PA") / Raw(data)
            sseq += len(data)
        else:
            pkt = Ether() / IP(src=A, dst=B) / TCP(sport=sport, dport=dport, seq=cseq, flags="PA") / Raw(data)
            cseq += len(data)
        pkt.time = 1_700_000_000 + i * 0.01
        pkts.append(pkt)
    wrpcap(str(path), pkts)


# --- KNXnet/IP --------------------------------------------------------------------


def _knx_tunnel(cemi: bytes, seq: int = 0) -> bytes:
    body = bytes([4, 0x65, seq & 0xFF, 0]) + cemi
    return b"\x06\x10\x04\x20" + (6 + len(body)).to_bytes(2, "big") + body


def _group_write(group: int, value: int, code: int = 0x11) -> bytes:
    return bytes([code, 0, 0xBC, 0xE0, 0x11, 0x06]) + group.to_bytes(2, "big") + bytes([1, 0, 0x80 | value])


def test_knx_parsing_and_fuzzing(tmp_path) -> None:
    telegram = parse_knx(_knx_tunnel(_group_write(0x0002, 1, code=0x29)))
    assert (telegram.cemi, telegram.apci, telegram.source, telegram.destination, telegram.value) == (
        "L_Data.ind", "GroupValueWrite", "1.1.6", "0/0/2", "1",
    )
    frames = [(False, _knx_tunnel(_group_write(g, g % 64, code=0x11), g)) for g in range(1, 130)]
    frames += [(False, _knx_tunnel(bytes([0xF1, 0])))]  # M_Reset.req
    # the KNX/IP interface relaying the bus (L_Data.ind) is not the writer
    frames += [(True, _knx_tunnel(_group_write(2, 1, code=0x29)))] * 5
    capture = tmp_path / "knx.pcap"
    _udp(capture, frames, dport=20100)  # the dataset also tunnels on 20100
    result = analyze_knx(capture, show_status=False)
    titles = {a.title: a for a in result.anomalies}
    fuzz = titles["KNX GroupValueWrite fuzzing (many groups/values)"]
    assert fuzz.src == A and fuzz.severity == "HIGH"
    assert titles["KNX device reset"].src == A
    assert not any(a.src == B for a in result.anomalies)


# --- XGT FEnet ---------------------------------------------------------------------


def _xgt(command: int, body: bytes, from_plc: bool = False) -> bytes:
    inst = command.to_bytes(2, "little") + b"\x14\x00" + body
    header = b"LSIS-XGT\x00\x00" + b"\x00\x00" + b"\xa0" + (b"\x11" if from_plc else b"\x33")
    return header + b"\x00\x00" + len(inst).to_bytes(2, "little") + b"\x03\x00" + inst


def test_xgt_writes_spell_text(tmp_path) -> None:
    frames = []
    for ch in "flag{x}":
        body = b"\x00\x00\x01\x00" + b"\x06\x00%MB200" + b"\x04\x00" + bytes([ord(ch), 0, 0, 0])
        frames += [(False, _xgt(0x58, body)), (True, _xgt(0x59, b"\x08\x01\x00\x00\x01\x00", True))]
    capture = tmp_path / "xgt.pcap"
    _tcp(capture, frames, dport=2004)
    result = analyze_xgt(capture, show_status=False)
    assert result.commands["Write request"] == 7
    writes = next(a for a in result.anomalies if a.title == "XGT memory writes")
    assert "flag{x}" in writes.evidence[0]


# --- ROC Plus --------------------------------------------------------------------------


def _roc(opcode: int, data: bytes) -> bytes:
    body = bytes([1, 2, 3, 4, opcode, len(data)]) + data
    return body + crc16_modbus(body).to_bytes(2, "little")


def test_roc_plus_login_and_custom_port(tmp_path) -> None:
    assert crc16_modbus(bytes.fromhex("010203040600")).to_bytes(2, "little") == bytes.fromhex("3a2f")
    frames = [(False, _roc(17, b"OP1" + (13330).to_bytes(2, "little") + b"\x01")), (True, _roc(17, b""))]
    frames += [(False, _roc(181, b"\x01\x02\x03")), (True, _roc(6, b"\x00" * 10))]
    capture = tmp_path / "roc.pcap"
    _udp(capture, frames, dport=12345)
    result = analyze_rocplus(capture, show_status=False)
    login = next(a for a in result.anomalies if a.title == "ROC Plus cleartext login credentials")
    assert "operator 'OP1' password '13330'" in login.evidence[0]


# --- Beckhoff ADS -------------------------------------------------------------------------


def test_ads_addroute_credentials(tmp_path) -> None:
    def tag(tid, value):
        return tid.to_bytes(2, "little") + len(value).to_bytes(2, "little") + value
    tags = tag(12, b"EWS-PC\x00") + tag(7, bytes([192, 168, 1, 99, 1, 1])) + tag(13, b"Administrator\x00") + tag(2, b"1\x00")
    route = b"\x03\x66\x14\x71" + b"\x00" * 4 + (6).to_bytes(4, "little") + bytes([192, 168, 1, 99, 1, 1]) + (10000).to_bytes(2, "little") + (4).to_bytes(4, "little") + tags
    capture = tmp_path / "ads.pcap"
    _udp(capture, [(False, route)], dport=48899)
    found = analyze_ads(capture, show_status=False).anomalies
    cred = next(a for a in found if a.title == "ADS AddRoute with cleartext Windows credentials")
    assert "user 'Administrator' password '1'" in cred.evidence[0]


# --- DLMS/COSEM ----------------------------------------------------------------------------


def _dlms(apdu: bytes) -> bytes:
    return b"\x00\x01\x00\x10\x00\x01" + len(apdu).to_bytes(2, "big") + apdu


def test_dlms_password_and_disconnect(tmp_path) -> None:
    aarq = bytes([0x60, 0x0C, 0xAC, 0x0A, 0x80, 0x08]) + b"12345678"
    action = bytes([0xC3, 0x01, 0xC1, 0x00, 0x46, 0, 0, 96, 3, 10, 255, 0x01, 0x01, 0x0F, 0x00])
    capture = tmp_path / "dlms.pcap"
    _tcp(capture, [(False, _dlms(aarq)), (False, _dlms(action))], dport=4059)
    titles = {a.title: a for a in analyze_dlms(capture, show_status=False).anomalies}
    assert "LLS password '12345678'" in titles["DLMS low-level-security password in clear"].evidence[0]
    assert "DLMS remote disconnect/reconnect" in titles


# --- ANSI C12.22 ------------------------------------------------------------------------------


def _c1222(service: bytes, control: int = 0x80) -> bytes:
    epsem = bytes([control, len(service)]) + service
    user = bytes([0x28, len(epsem) + 2, 0x81, len(epsem)]) + epsem
    body = bytes([0xBE, len(user)]) + user
    return bytes([0x60, len(body)]) + body


def test_c1222_cleartext_security(tmp_path) -> None:
    capture = tmp_path / "c1222.pcap"
    _tcp(capture, [(False, _c1222(b"\x51" + b"password1234".ljust(20, b"\x00"))), (True, _c1222(b"\x00"))], dport=1153)
    result = analyze_c1222(capture, show_status=False)
    assert result.commands["Security"] == 1
    cred = next(a for a in result.anomalies if "credentials" in a.title)
    assert "password 'password1234'" in cred.evidence[0]


# --- LonTalk / CN-IP --------------------------------------------------------------------------


def _cnip(lon: bytes, seq: int) -> bytes:
    body = b"\x01\x01\x00\x00\x00\x00" + (0x6B8B4567).to_bytes(4, "big") + seq.to_bytes(4, "big") + b"\x00" * 4 + lon
    return (len(body) + 2).to_bytes(2, "big") + body


def test_lontalk_nv_update_and_management(tmp_path) -> None:
    nv = bytes.fromhex("010901aa01a901038120ca")
    packet = parse_cnip(_cnip(nv, 0))
    assert packet.message == "NV Update" and packet.source == "1/42" and packet.destination == "1/41"
    set_mode = bytes.fromhex("010901aa01a901036b00")
    capture = tmp_path / "lon.pcap"
    _udp(capture, [(False, _cnip(nv, 1)), (False, _cnip(set_mode, 2))], dport=1628)
    titles = {a.title: a for a in analyze_lontalk(capture, show_status=False).anomalies}
    assert titles["LonWorks network management writes"].severity == "HIGH"


# --- POWERLINK ----------------------------------------------------------------------------------


def test_powerlink_nmt_reset_and_rogue_mn(tmp_path) -> None:
    pkts = []
    for i, mac in enumerate(("00:50:c2:31:3f:dd", "02:00:00:00:00:66")):
        soc = Ether(src=mac, dst="01:11:1e:00:00:01", type=0x88AB) / Raw(bytes([0x01, 0xFF, 240]) + b"\x00" * 43)
        soc.time = 1_700_000_000 + i
        pkts.append(soc)
    reset = Ether(src="02:00:00:00:00:66", dst="01:11:1e:00:00:03", type=0x88AB) / Raw(bytes([0x06, 0xFF, 240, 4, 0x28]) + b"\x00" * 41)
    reset.time = 1_700_000_005
    pkts.append(reset)
    capture = tmp_path / "epl.pcap"
    wrpcap(str(capture), pkts)
    titles = {a.title for a in analyze_powerlink(capture, show_status=False).anomalies}
    assert {"Multiple POWERLINK Managing Nodes", "POWERLINK NMT stop/reset commands"} <= titles


# --- wiring ----------------------------------------------------------------------------------------


def test_flag_and_overview_wiring(tmp_path, monkeypatch, capfd) -> None:
    capture = tmp_path / "roc.pcap"
    _udp(capture, [(False, _roc(17, b"OP1\x12\x34\x01")), (True, _roc(17, b""))] * 2, dport=4000)
    monkeypatch.setattr(sys, "argv", ["pcapper", str(capture), "--rocplus"])
    assert cli.main() == 0
    assert "ROC PLUS · roc.pcap" in capfd.readouterr().out
    overview = analyze_overview(capture, show_status=False)
    assert "rocplus" in overview.modules_run
