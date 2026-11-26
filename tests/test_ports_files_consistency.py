"""Port tables agree with the OT port registry, --files no longer carves
HTTP/2 out of OT streams, and --files reports OT protocol file transfers.

- services.COMMON_PORTS named only some of the ports pcapper's OT analyzers
  decode: --services printed "TCP/48898" where --protocols said ADS/AMS.
- services/hosts/exfil/beacon each kept a hand-written OT port set that
  drifted from ot_ports.OT_PORT_PROTOCOLS (4000 was "OPC / various", not ROC
  Plus).
- _looks_like_http2 took any 9 bytes that parse as a frame header for HTTP/2,
  so ADS/AMS and Modbus/TCP streams became http2_stream_*.bin "downloads".
- DNP3 Group 70, MMS and BACnet atomic file transfers were not reported.
"""

from __future__ import annotations

import hashlib

import pytest

from pcapper import beacon, exfil, hosts, scan, services
from pcapper.ot_ports import COAP_PORTS, OT_PORT_PROTOCOLS, PTP_PORTS
from test_review_batches import _tcp, _udp, _write

pytest.importorskip("scapy.all")
pytest.importorskip("dpkt")

MASTER, OUTSTATION = "10.20.0.10", "10.20.0.20"


# --- port tables --------------------------------------------------------------


def test_every_registry_port_is_named_in_common_ports() -> None:
    labelled = {102, 502, 2222, 18245, 18246, 44818, 47808}
    for port, label in OT_PORT_PROTOCOLS.items():
        assert port in services.COMMON_PORTS, port
        if port not in labelled:
            assert services.COMMON_PORTS[port] == label, port
    # The fuller service names reports and the overview inventory match on.
    assert services.COMMON_PORTS[102] == "S7/MMS/ICCP"
    assert services.COMMON_PORTS[502] == "Modbus/TCP"
    assert services.COMMON_PORTS[2222] == "ENIP-IO"
    assert services.COMMON_PORTS[48898] == services.COMMON_PORTS[48899] == "ADS/AMS"
    assert services.COMMON_PORTS[4000] == "ROC Plus"


def test_registry_covers_the_ports_ot_analyzers_decode() -> None:
    from pcapper import codesys, hart, melsec, synchrophasor
    from pcapper.ot_extra import OT_EXTRA

    decoded = (
        set(codesys.CODESYS_TCP_PORTS)
        | set(codesys.CODESYS_UDP_PORTS)
        | set(synchrophasor.SYNCHROPHASOR_PORTS)
        | {hart.HART_PORT, hart.HART_UDP_HANDOVER_PORT}
        | {melsec.MELSEC_TCP_PORT, melsec.MELSEC_UDP_PORT}
        | {melsec.MELSOFT_TCP_PORT, melsec.MELSOFT_UDP_PORT}
        | {port for spec in OT_EXTRA for port in spec.ports}
    )
    assert decoded <= set(OT_PORT_PROTOCOLS), sorted(decoded - set(OT_PORT_PROTOCOLS))
    assert OT_PORT_PROTOCOLS[11740] == OT_PORT_PROTOCOLS[1740] == "CODESYS"
    assert OT_PORT_PROTOCOLS[5562] == OT_PORT_PROTOCOLS[5006] == "MELSEC"
    # Claimed by port alone with no frame check, or not port-bound at all.
    assert not {1234, 10001, 1500, 1501, 1883, 8883} & set(OT_PORT_PROTOCOLS)


def test_ot_port_sets_are_derived_from_the_registry() -> None:
    registry = frozenset(OT_PORT_PROTOCOLS)
    assert services._OT_SERVICE_PORTS == registry - PTP_PORTS - COAP_PORTS
    assert hosts._HOST_OT_PORTS == services._OT_SERVICE_PORTS
    assert scan._OT_SERVICE_PORTS is services._OT_SERVICE_PORTS
    assert exfil.OT_PORTS == beacon.OT_PORTS == registry - PTP_PORTS
    assert 4000 in services._OT_SERVICE_PORTS and 48898 in beacon.OT_PORTS


def test_services_names_the_ads_port_like_protocols_does(tmp_path) -> None:
    from pcapper.protocols import KNOWN_PORTS
    from pcapper.services import analyze_services

    client, plc = "192.168.1.99", "192.168.1.8"
    packets = [
        _tcp(client, plc, 49179, 48898, flags="S", seq=100),
        _tcp(plc, client, 48898, 49179, flags="SA", seq=500),
        _tcp(client, plc, 49179, 48898, flags="A", seq=101),
        _tcp(client, plc, 49179, 48898, b"\x00\x00\x20\x00\x00\x00" + b"\x01" * 32, seq=101),
        _tcp(plc, client, 48898, 49179, b"\x00\x00\x28\x00\x00\x00" + b"\x02" * 40, seq=501),
        _udp(client, plc, 48899, 48899, b"\x03\x66\x14\x71" + b"\x00" * 20),
    ]
    summary = analyze_services(_write(tmp_path, "ads.pcap", packets), show_status=False)
    names = {(a.port, a.protocol): a.service_name for a in summary.assets}
    assert names[(48898, "TCP")] == KNOWN_PORTS[48898] == "ADS/AMS"
    assert names[(48899, "UDP")] == "ADS/AMS"


def test_netbios_broadcasts_are_not_listed_as_services(tmp_path) -> None:
    from pcapper.services import analyze_services

    packets = [_udp("192.168.1.5", "192.168.1.255", 137, 137, b"\x80\x01" + b"\x00" * 48)]
    summary = analyze_services(_write(tmp_path, "nbns.pcap", packets), show_status=False)
    assert not [a for a in summary.assets if a.ip == "192.168.1.255"]


# --- HTTP/2 detection ---------------------------------------------------------

ADS_REQUEST = b"\x00\x00\x20\x00\x00\x00" + bytes(range(32))
ADS_REPLY = b"\x00\x00\x28\x00\x00\x00" + bytes(range(40))
MODBUS_REQUEST = b"\x00\x00\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a" * 3
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def _h2_frame(kind: int, flags: int, stream: int, payload: bytes) -> bytes:
    return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + stream.to_bytes(4, "big") + payload


SERVER_SETTINGS = _h2_frame(4, 0, 0, b"\x00\x03\x00\x00\x00\x64" + b"\x00\x04\x00\x10\x00\x00")


def test_ot_headers_are_not_http2() -> None:
    from pcapper.files import _detect_app_protocol_from_stream, _looks_like_http2

    for stream in (ADS_REQUEST, ADS_REPLY, MODBUS_REQUEST):
        assert not _looks_like_http2(stream)
        assert _detect_app_protocol_from_stream(stream, 49192, 48898) != "HTTP2"
    # A DATA/HEADERS frame header alone is no evidence either.
    assert not _looks_like_http2(_h2_frame(0, 1, 1, b"hello"))


def test_http2_needs_a_preface() -> None:
    from pcapper.files import _looks_like_http2

    assert _looks_like_http2(PREFACE + SERVER_SETTINGS)
    assert _looks_like_http2(SERVER_SETTINGS, reverse=PREFACE)
    assert _looks_like_http2(SERVER_SETTINGS)  # one-sided capture: the server preface decides
    assert not _looks_like_http2(SERVER_SETTINGS, reverse=MODBUS_REQUEST)
    # SETTINGS must be well formed: length a multiple of 6, known ids, stream 0.
    assert not _looks_like_http2(_h2_frame(4, 0, 0, b"\x00\x03\x00\x00\x00"))
    assert not _looks_like_http2(_h2_frame(4, 0, 0, b"\x00\x77\x00\x00\x00\x01"))
    assert not _looks_like_http2(_h2_frame(4, 0, 5, b"\x00\x03\x00\x00\x00\x64"))
    assert not _looks_like_http2(_h2_frame(4, 0, 0, b"\x00\x02\x00\x00\x00\x07"))


def test_files_carves_no_http2_from_ads_or_modbus(tmp_path) -> None:
    from pcapper.files import analyze_files

    packets = [
        _tcp("192.168.1.199", "192.168.1.8", 49192, 48898, ADS_REQUEST, seq=100),
        _tcp("192.168.1.8", "192.168.1.199", 48898, 49192, ADS_REPLY, seq=900),
        _tcp("10.0.0.57", "10.0.0.8", 2585, 502, MODBUS_REQUEST, seq=100),
    ]
    summary = analyze_files(_write(tmp_path, "ot.pcap", packets), show_status=False)
    assert not [a for a in summary.artifacts if a.protocol == "HTTP2"]


def test_files_still_carves_real_h2c(tmp_path) -> None:
    from pcapper.files import analyze_files

    body = b"cleartext http/2 body " * 8
    client = PREFACE + _h2_frame(4, 0, 0, b"") + _h2_frame(1, 5, 1, b"\x82\x86\x84")
    server = (
        SERVER_SETTINGS
        + _h2_frame(4, 1, 0, b"")
        + _h2_frame(1, 4, 1, b"\x88")
        + _h2_frame(0, 1, 1, body)
    )
    packets = [
        _tcp("10.0.0.1", "10.0.0.2", 50000, 80, client, seq=100),
        _tcp("10.0.0.2", "10.0.0.1", 80, 50000, server, seq=700),
    ]
    summary = analyze_files(_write(tmp_path, "h2c.pcap", packets), show_status=False)
    h2 = [a for a in summary.artifacts if a.protocol == "HTTP2"]
    assert [a.filename for a in h2] == ["http2_stream_1_2.bin"]
    assert h2[0].size_bytes == len(body)
    assert h2[0].sha256 == hashlib.sha256(body).hexdigest()


# --- DNP3 file transfer ------------------------------------------------------


def _dnp3_frames(fragment: bytes, src: int, dst: int) -> bytes:
    from pcapper.dnp3 import _crc16_dnp

    def frame(user: bytes) -> bytes:
        header = b"\x05\x64" + bytes([len(user) + 5, 0x44]) + dst.to_bytes(2, "little") + src.to_bytes(2, "little")
        out = header + _crc16_dnp(header).to_bytes(2, "little")
        for off in range(0, len(user), 16):
            block = user[off : off + 16]
            out += block + _crc16_dnp(block).to_bytes(2, "little")
        return out

    pieces = [fragment[off : off + 249] for off in range(0, len(fragment), 249)]
    out = b""
    for n, piece in enumerate(pieces):
        header = n & 0x3F
        header |= 0x40 if n == 0 else 0
        header |= 0x80 if n == len(pieces) - 1 else 0
        out += frame(bytes([header]) + piece)
    return out


def _g70(variation: int, obj: bytes) -> bytes:
    return bytes([70, variation, 0x5B, 1]) + len(obj).to_bytes(2, "little") + obj


def _file_command(name: str, mode: int, size: int, request_id: int) -> bytes:
    raw = name.encode()
    return (
        (26).to_bytes(2, "little") + len(raw).to_bytes(2, "little") + b"\x00" * 6 + b"\xff\x01"
        + b"\x00" * 4 + size.to_bytes(4, "little") + mode.to_bytes(2, "little")
        + (1024).to_bytes(2, "little") + request_id.to_bytes(2, "little") + raw
    )


def _file_status(handle: int, size: int, request_id: int, status: int = 0) -> bytes:
    return (
        handle.to_bytes(4, "little") + size.to_bytes(4, "little") + (1024).to_bytes(2, "little")
        + request_id.to_bytes(2, "little") + bytes([status])
    )


def _file_block(handle: int, block: int, last: bool, data: bytes = b"") -> bytes:
    return handle.to_bytes(4, "little") + (block | (0x80000000 if last else 0)).to_bytes(4, "little") + data


def _dnp3_session(tmp_path, exchanges: list[tuple[str, int, bytes]], name: str = "dnp3.pcap"):
    """``exchanges``: (sender "m"/"o", function code, objects) in order."""
    seq = {"m": 1000, "o": 50000}
    packets = []
    for n, (sender, fc, objects) in enumerate(exchanges):
        ac = 0xC0 | (n & 0x0F)
        fragment = bytes([ac, fc]) + (b"\x00\x00" if fc >= 129 else b"") + objects
        if sender == "m":
            data = _dnp3_frames(fragment, 3, 4)
            packets.append(_tcp(MASTER, OUTSTATION, 49178, 20000, data, seq=seq["m"]))
        else:
            data = _dnp3_frames(fragment, 4, 3)
            packets.append(_tcp(OUTSTATION, MASTER, 20000, 49178, data, seq=seq["o"]))
        seq[sender] += len(data)
    return _write(tmp_path, name, packets)


def _ot_artifacts(path, protocol: str):
    from pcapper.files import analyze_files

    summary = analyze_files(path, show_status=False, extract_name=None)
    return [a for a in summary.artifacts if a.protocol == protocol], summary


def test_dnp3_file_read_is_carved(tmp_path) -> None:
    content = b"[config]\nsetpoint=42\n" * 30  # two blocks
    handle = 0x1234
    capture = _dnp3_session(
        tmp_path,
        [
            ("m", 25, _g70(3, _file_command("/etc/rtu/config.ini", 1, 0, 7))),
            ("o", 129, _g70(4, _file_status(handle, len(content), 7))),
            ("m", 1, _g70(5, _file_block(handle, 0, False))),
            ("o", 129, _g70(5, _file_block(handle, 0, False, content[:400]))),
            ("m", 1, _g70(5, _file_block(handle, 1, False))),
            ("o", 129, _g70(5, _file_block(handle, 1, True, content[400:]))),
            ("m", 26, _g70(4, _file_status(handle, 0, 8))),
            ("o", 129, _g70(4, _file_status(handle, 0, 8))),
        ],
    )
    arts, summary = _ot_artifacts(capture, "DNP3")
    assert len(arts) == 1
    art = arts[0]
    assert art.filename == "config.ini"
    assert (art.src_ip, art.dst_ip, art.src_port, art.dst_port) == (OUTSTATION, MASTER, 20000, 49178)
    assert art.size_bytes == len(content)
    assert art.sha256 == hashlib.sha256(content).hexdigest()
    assert art.packet_index == 1
    assert art.note == (
        "DNP3 file read (upload from outstation) /etc/rtu/config.ini; 2 block(s), "
        f"{len(content)} B carved; packets 1,2,3,4,5,6,7,8"
    )
    assert any(d["summary"] == "OT protocol file transfers observed" for d in summary.detections)


def test_dnp3_file_write_and_extract(tmp_path) -> None:
    from pcapper.files import analyze_files

    content = b"\x7fELF firmware image" + bytes(range(200))
    handle = 0x99
    capture = _dnp3_session(
        tmp_path,
        [
            ("m", 25, _g70(3, _file_command("C:\\fw\\update.bin", 2, len(content), 3))),
            ("o", 129, _g70(4, _file_status(handle, 0, 3))),
            ("m", 2, _g70(5, _file_block(handle, 0, True, content))),
            ("o", 129, _g70(6, _file_block(handle, 0, True, b"\x00"))),
            ("m", 26, _g70(4, _file_status(handle, 0, 4))),
            ("o", 129, _g70(4, _file_status(handle, 0, 4))),
        ],
    )
    out_dir = tmp_path / "out"
    summary = analyze_files(capture, show_status=False, extract_name="update.bin", output_dir=out_dir)
    arts = [a for a in summary.artifacts if a.protocol == "DNP3"]
    assert [(a.filename, a.src_ip, a.dst_ip) for a in arts] == [("update.bin", MASTER, OUTSTATION)]
    assert "download to outstation" in arts[0].note
    assert (out_dir / "update.bin").read_bytes() == content


def test_dnp3_missing_block_is_reported_without_content(tmp_path) -> None:
    handle = 0x55
    capture = _dnp3_session(
        tmp_path,
        [
            ("m", 25, _g70(3, _file_command("log.txt", 1, 0, 1))),
            ("o", 129, _g70(4, _file_status(handle, 600, 1))),
            # block 0 never captured
            ("o", 129, _g70(5, _file_block(handle, 1, True, b"x" * 100))),
            ("m", 26, _g70(4, _file_status(handle, 0, 2))),
            ("o", 129, _g70(4, _file_status(handle, 0, 2))),
            ("m", 27, _g70(3, _file_command("./old.cfg", 0, 0, 9))),
            ("o", 129, _g70(4, _file_status(0, 0, 9))),
        ],
    )
    arts, _summary = _ot_artifacts(capture, "DNP3")
    by_name = {a.filename: a for a in arts}
    read = by_name["log.txt"]
    assert read.sha256 is None and read.payload is None
    assert read.size_bytes == 600  # announced size
    assert read.note.startswith("[not carved] DNP3 file read (upload from outstation) log.txt; ")
    assert "1 of 2 blocks not captured; 600 B announced" in read.note
    delete = by_name["old.cfg"]
    assert delete.sha256 is None
    assert (delete.src_ip, delete.dst_ip) == (MASTER, OUTSTATION)
    assert delete.note == "[no content] DNP3 file delete ./old.cfg (success); packets 6,7"


def test_dnp3_retransmitted_segment_is_read_once(tmp_path) -> None:
    from pcapper.files import analyze_files

    content = b"retransmitted block" * 4
    handle = 7
    exchanges = [
        ("m", 25, _g70(3, _file_command("a.txt", 1, 0, 1))),
        ("o", 129, _g70(4, _file_status(handle, len(content), 1))),
        ("o", 129, _g70(5, _file_block(handle, 0, True, content))),
        ("m", 26, _g70(4, _file_status(handle, 0, 2))),
    ]
    capture = _dnp3_session(tmp_path, exchanges)
    from scapy.all import rdpcap, wrpcap  # type: ignore

    packets = list(rdpcap(str(capture)))
    packets.insert(3, packets[2].copy())  # the data segment, sent twice
    wrpcap(str(capture), packets)
    summary = analyze_files(capture, show_status=False)
    arts = [a for a in summary.artifacts if a.protocol == "DNP3"]
    assert len(arts) == 1 and arts[0].sha256 == hashlib.sha256(content).hexdigest()


# --- MMS file services --------------------------------------------------------


def _ber(tag: int, value: bytes) -> bytes:
    tag_bytes = tag.to_bytes(2, "big") if tag > 0xFF else bytes([tag])
    n = len(value)
    if n < 0x80:
        length = bytes([n])
    elif n < 0x100:
        length = b"\x81" + bytes([n])
    else:
        length = b"\x82" + n.to_bytes(2, "big")
    return tag_bytes + length + value


def _tpkt_mms(pdu: bytes, segment: int = 0) -> list[bytes]:
    """The MMS PDU in session/presentation framing, over one TPKT/COTP DT
    TPDU or (``segment`` bytes each) several, the last with EOT."""
    tsdu = b"\x01\x00\x01\x00" + _ber(0x61, _ber(0x30, _ber(0x02, b"\x03") + _ber(0xA0, pdu)))
    parts = [tsdu[off : off + segment] for off in range(0, len(tsdu), segment)] if segment else [tsdu]
    out = []
    for n, part in enumerate(parts):
        cotp = b"\x02\xf0" + (b"\x80" if n == len(parts) - 1 else b"\x00") + part
        out.append(b"\x03\x00" + (len(cotp) + 4).to_bytes(2, "big") + cotp)
    return out


def _mms_name(name: str) -> bytes:
    return _ber(0x19, name.encode())


def _mms_session(tmp_path, messages: list[tuple[str, bytes]], segment: int = 0):
    client, server = "10.30.0.5", "10.30.0.6"
    seq = {"c": 1000, "s": 9000}
    packets = []
    for sender, pdu in messages:
        for tpdu in _tpkt_mms(pdu, segment if sender == "s" else 0):
            if sender == "c":
                packets.append(_tcp(client, server, 51000, 102, tpdu, seq=seq["c"]))
            else:
                packets.append(_tcp(server, client, 102, 51000, tpdu, seq=seq["s"]))
            seq[sender] += len(tpdu)
    return _write(tmp_path, "mms.pcap", packets), client, server


def _req(invoke: int, service: bytes) -> bytes:
    return _ber(0xA0, _ber(0x02, bytes([invoke])) + service)


def _rsp(invoke: int, service: bytes) -> bytes:
    return _ber(0xA1, _ber(0x02, bytes([invoke])) + service)


def test_mms_file_read_is_carved_across_cotp_segments(tmp_path) -> None:
    content = b"COMTRADE,1999\r\n" + bytes(range(256)) * 3
    first, second = content[:500], content[500:]
    capture, client, server = _mms_session(
        tmp_path,
        [
            ("c", _req(1, _ber(0xBF48, _ber(0xA0, _mms_name("/COMTRADE/fault1.cfg")) + _ber(0x81, b"\x00")))),
            ("s", _rsp(1, _ber(0xBF48, _ber(0x80, b"\x05") + _ber(0xA1, _ber(0x80, len(content).to_bytes(2, "big")))))),
            ("c", _req(2, _ber(0x9F49, b"\x05"))),
            ("s", _rsp(2, _ber(0xBF49, _ber(0x80, first)))),  # moreFollows defaults to TRUE
            ("c", _req(3, _ber(0x9F49, b"\x05"))),
            ("s", _rsp(3, _ber(0xBF49, _ber(0x80, second) + _ber(0x81, b"\x00")))),
            ("c", _req(4, _ber(0x9F4A, b"\x05"))),
            ("s", _rsp(4, _ber(0x9F4A, b""))),
        ],
        segment=200,
    )
    arts, _summary = _ot_artifacts(capture, "MMS")
    assert len(arts) == 1
    art = arts[0]
    assert art.filename == "fault1.cfg"
    assert (art.src_ip, art.dst_ip) == (server, client)
    assert art.size_bytes == len(content)
    assert art.sha256 == hashlib.sha256(content).hexdigest()
    assert "2 FileRead(s)" in art.note


def test_mms_directory_delete_and_unfinished_read(tmp_path) -> None:
    entry = _ber(0x30, _ber(0xA0, _mms_name("/LOGS/events.log")) + _ber(0xA1, _ber(0x80, b"\x10\x00")))
    capture, client, server = _mms_session(
        tmp_path,
        [
            ("c", _req(1, _ber(0xBF4D, _ber(0xA0, _mms_name("/LOGS/"))))),
            ("s", _rsp(1, _ber(0xBF4D, _ber(0xA0, _ber(0x30, entry))))),
            ("c", _req(2, _ber(0xBF4C, _mms_name("/LOGS/events.log")))),
            ("s", _rsp(2, _ber(0x9F4C, b""))),
            ("c", _req(3, _ber(0xBF48, _ber(0xA0, _mms_name("/CFG/ied.cid")) + _ber(0x81, b"\x00")))),
            ("s", _rsp(3, _ber(0xBF48, _ber(0x80, b"\x07") + _ber(0xA1, _ber(0x80, b"\x20\x00"))))),
            ("c", _req(4, _ber(0x9F49, b"\x07"))),
            ("s", _rsp(4, _ber(0xBF49, _ber(0x80, b"partial")))),  # more follows, never read
        ],
    )
    arts, _summary = _ot_artifacts(capture, "MMS")
    notes = {a.note.split(";")[0]: a for a in arts}
    listing = notes["[no content] MMS file directory /LOGS/: 1 entries (/LOGS/events.log (4096 B))"]
    assert listing.sha256 is None and (listing.src_ip, listing.dst_ip) == (client, server)
    assert "[no content] MMS file delete /LOGS/events.log" in notes
    read = notes["[not carved] MMS file read /CFG/ied.cid"]
    assert read.payload is None and read.sha256 is None and read.size_bytes == 8192
    assert "last FileRead (moreFollows false) not captured" in read.note


def test_mms_refused_open_and_non_file_services(tmp_path) -> None:
    error = _ber(0xA2, _ber(0x80, b"\x01") + _ber(0xA2, _ber(0x80, b"\x0b")))  # file-problem
    capture, client, server = _mms_session(
        tmp_path,
        [
            ("c", _req(1, _ber(0xBF48, _ber(0xA0, _mms_name("/secret.cfg")) + _ber(0x81, b"\x00")))),
            ("s", error),
            ("c", _req(2, _ber(0xA4, _ber(0xA1, b"")))),  # Read: not a file service
            ("s", _rsp(2, _ber(0xA4, _ber(0xA1, b"")))),
        ],
    )
    arts, _summary = _ot_artifacts(capture, "MMS")
    assert [a.note.split(";")[0] for a in arts] == ["[no content] MMS file open /secret.cfg (refused)"]
    assert (arts[0].src_ip, arts[0].dst_ip) == (client, server)


# --- BACnet atomic file services ----------------------------------------------


def _bacnet(apdu: bytes, request: bool) -> bytes:
    npdu = b"\x01" + (b"\x04" if request else b"\x00") + apdu
    return b"\x81\x0a" + (len(npdu) + 4).to_bytes(2, "big") + npdu


def _octets(data: bytes) -> bytes:
    if len(data) < 5:
        return bytes([0x60 | len(data)]) + data
    if len(data) < 254:
        return b"\x65" + bytes([len(data)]) + data
    return b"\x65\xfe" + len(data).to_bytes(2, "big") + data


def _signed(value: int) -> bytes:
    raw = value.to_bytes(2, "big", signed=True).lstrip(b"\x00") or b"\x00"
    return bytes([0x30 | len(raw)]) + raw


def _file_oid(instance: int) -> bytes:
    return b"\xc4" + ((10 << 22) | instance).to_bytes(4, "big")


def test_bacnet_atomic_read_and_write_are_carved(tmp_path) -> None:
    trend = bytes(range(256)) * 2 + b"tail"
    workstation, controller = "10.40.0.2", "10.40.0.3"
    packets = []
    for invoke, start in ((1, 0), (2, 300)):
        chunk = trend[start : start + 300]
        request = b"\x00\x05" + bytes([invoke, 6]) + _file_oid(7) + b"\x0e" + _signed(start) + b"\x22\x01\x2c\x0f"
        eof = b"\x11" if start + 300 >= len(trend) else b"\x10"
        ack = b"\x30" + bytes([invoke, 6]) + eof + b"\x0e" + _signed(start) + _octets(chunk) + b"\x0f"
        packets.append(_udp(workstation, controller, 47808, 47808, _bacnet(request, True)))
        packets.append(_udp(controller, workstation, 47808, 47808, _bacnet(ack, False)))
    program = b"PROGRAM main\r\nEND\r\n"
    write = b"\x00\x05\x09\x07" + _file_oid(2) + b"\x0e" + _signed(0) + _octets(program) + b"\x0f"
    packets.append(_udp(workstation, controller, 47808, 47808, _bacnet(write, True)))
    packets.append(_udp(controller, workstation, 47808, 47808, _bacnet(b"\x30\x09\x07\x09\x00", False)))
    arts, _summary = _ot_artifacts(_write(tmp_path, "bacnet.pcap", packets), "BACnet")
    by_op = {a.filename.split("_")[3]: a for a in arts}
    read, written = by_op["read"], by_op["write"]
    assert read.filename == "bacnet_file_7_read_1.bin"
    assert (read.src_ip, read.dst_ip) == (controller, workstation)
    assert read.sha256 == hashlib.sha256(trend).hexdigest()
    assert written.filename == "bacnet_file_2_write_5.bin"
    assert (written.src_ip, written.dst_ip) == (workstation, controller)
    assert written.sha256 == hashlib.sha256(program).hexdigest()


def test_bacnet_read_without_end_of_file_is_not_carved(tmp_path) -> None:
    request = b"\x00\x05\x01\x06" + _file_oid(3) + b"\x0e" + _signed(0) + b"\x22\x01\x2c\x0f"
    ack = b"\x30\x01\x06\x10\x0e" + _signed(0) + _octets(b"z" * 300) + b"\x0f"
    packets = [
        _udp("10.40.0.2", "10.40.0.3", 47808, 47808, _bacnet(request, True)),
        _udp("10.40.0.3", "10.40.0.2", 47808, 47808, _bacnet(ack, False)),
    ]
    arts, _summary = _ot_artifacts(_write(tmp_path, "bacnet_partial.pcap", packets), "BACnet")
    assert len(arts) == 1 and arts[0].payload is None and arts[0].sha256 is None
    assert arts[0].note.startswith("[not carved] BACnet AtomicReadFile")
    assert "end of file not reached" in arts[0].note
