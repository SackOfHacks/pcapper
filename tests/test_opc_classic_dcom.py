"""OPC DA over DCOM is decoded statefully: binds, items, writes, callbacks.

Backlog 1.3: ``--opc-classic`` reported zero packets on the ICSC 2021 OPC
capture because it only knew five IIDs and searched raw payloads for them.
The capture binds IOPCSyncIO/IOPCItemMgt/IOPCAsyncIO2/IOPCDataCallback with
``alter_context`` and then names them only by context id. These tests rebuild
that conversation shape byte for byte (layouts taken from the capture).
"""

from __future__ import annotations

import struct
import uuid

from scapy.all import Ether, IP, TCP, wrpcap  # type: ignore
from scapy.packet import Padding  # type: ignore

from pcapper.opc_classic import (
    _ascii_from_values,
    analyze_opc_classic,
    scan_variants,
    scan_wstrings,
)

CLIENT, SERVER = "192.168.1.21", "192.168.1.11"
NDR = uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860").bytes_le + struct.pack("<I", 2)
IID_ITEMMGT = "39c13a54-011e-11d0-9675-0020afd8adb3"
IID_SYNCIO = "39c13a52-011e-11d0-9675-0020afd8adb3"
IID_CALLBACK = "39c13a70-011e-11d0-9675-0020afd8adb3"
ORPCTHIS = struct.pack("<HHII", 5, 7, 0, 0) + b"\x11" * 16 + struct.pack("<I", 0)
ORPCTHAT = struct.pack("<II", 0, 0)


def _pdu(ptype: int, call_id: int, body: bytes, flags: int = 0x03) -> bytes:
    return (
        struct.pack("<BBBB", 5, 0, ptype, flags)
        + b"\x10\x00\x00\x00"
        + struct.pack("<HHI", 16 + len(body), 0, call_id)
        + body
    )


def _alter(call_id: int, ctx_id: int, iid: str) -> bytes:
    body = struct.pack("<HHI", 5840, 5840, 0) + struct.pack("<BBH", 1, 0, 0)
    body += struct.pack("<HBB", ctx_id, 1, 0) + uuid.UUID(iid).bytes_le
    body += struct.pack("<HH", 0, 0) + NDR
    return _pdu(14, call_id, body)


def _alter_resp(call_id: int) -> bytes:
    body = struct.pack("<HHI", 5840, 5840, 0) + struct.pack("<H", 0) + b"\x00\x00"
    body += struct.pack("<BBH", 1, 0, 0) + struct.pack("<HH", 0, 0) + NDR
    return _pdu(15, call_id, body)


def _request(call_id: int, ctx_id: int, opnum: int, stub: bytes) -> bytes:
    return _pdu(0, call_id, struct.pack("<IHH", len(stub), ctx_id, opnum) + stub)


def _response(call_id: int, ctx_id: int, stub: bytes) -> bytes:
    return _pdu(2, call_id, struct.pack("<IHBB", len(stub), ctx_id, 0, 0) + stub)


def _wstr(text: str) -> bytes:
    count = len(text) + 1
    out = struct.pack("<III", count, 0, count) + (text + "\x00").encode("utf-16-le")
    return out + b"\x00" * ((-len(out)) % 4)


def _variant_i4(value: int) -> bytes:
    return struct.pack("<IIHHHHI", 3, 0, 3, 0, 0, 0, 3) + struct.pack("<i", value)


def _variant_r8(value: float) -> bytes:
    return struct.pack("<IIHHHHI", 4, 0, 5, 0, 0, 0, 5) + b"\x00" * 4 + struct.pack("<d", value)


def _variant_bstr(text: str) -> bytes:
    data = text.encode("utf-16-le")
    return (
        struct.pack("<IIHHHHI", 6, 0, 8, 0, 0x5C, 0x50, 8)  # garbage reserved words
        + struct.pack("<I", 0x0020_0008)
        + struct.pack("<III", len(text), len(data), len(text))
        + data
    )


def _pad8(stub: bytes) -> bytes:
    return stub + b"\x00" * ((-len(stub)) % 8)


def _variants(values: list[bytes]) -> bytes:
    """``[size_is(n)] VARIANT*`` as ole32 marshals it: conformance, one
    'User' marker per element, then each wireVARIANT 8-byte aligned."""
    out = struct.pack("<I", len(values)) + b"User" * len(values)
    for value in values:
        out = _pad8(out) if (len(out) % 8) else out
        out += value
        out += b"\x00" * ((-len(out)) % 4)
    return out


def _add_items_request(items: list[tuple[str, int]]) -> bytes:
    stub = ORPCTHIS + struct.pack("<II", len(items), len(items))
    for index, (_name, h_client) in enumerate(items):
        stub += struct.pack(
            "<IIIIIIHH", 0x20000 + 8 * index, 0x20004 + 8 * index, 1, h_client, 0, 0, 0, 0
        )
    for name, _h in items:
        stub += _wstr("") + _wstr(name)
    return stub


def _add_items_response(results: list[tuple[int, int]]) -> bytes:
    stub = ORPCTHAT + struct.pack("<II", 0x20000, len(results))
    for h_server, vt in results:
        stub += struct.pack("<IHHIII", h_server, vt, 0, 3, 0, 0)
    stub += struct.pack("<II", 0x20004, len(results)) + b"\x00\x00\x00\x00" * len(results)
    return stub + struct.pack("<I", 0)


def _segments(src, sport, dst, dport, seq, chunks):
    packets = []
    for chunk in chunks:
        packets.append(
            Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=seq, flags="PA") / chunk
        )
        seq += len(chunk)
    return packets, seq


def _build_capture(path) -> None:
    c2s, s2c = [], []
    cseq, sseq = 1000, 5000
    conn = (CLIENT, 1042, SERVER, 1249)
    back = (SERVER, 1249, CLIENT, 1042)

    def client(*chunks):
        nonlocal cseq
        pkts, cseq = _segments(*conn, cseq, list(chunks))
        c2s.extend(pkts)
        return pkts

    def server(*chunks):
        nonlocal sseq
        pkts, sseq = _segments(*back, sseq, list(chunks))
        c2s.extend(pkts)
        return pkts

    client(_alter(1, 7, IID_ITEMMGT))
    server(_alter_resp(1))
    client(_alter(2, 8, IID_SYNCIO))
    server(_alter_resp(2))
    # AddItems split across two TCP segments (reassembly).
    add_req = _request(3, 7, 3, _add_items_request([("Plant.Valve1.Cmd", 0xA1), ("Plant.Label", 0xA2), ("Plant.Tank1.Level", 0xA3)]))
    client(add_req[:40])
    client(add_req[40:])
    server(_response(3, 7, _add_items_response([(10, 3), (11, 8), (12, 5)])))
    # A bare ACK in the *same* direction at the next data sequence number,
    # between two PDUs: scapy reports its Ethernet padding as six payload
    # bytes, which used to be spliced into the stream ahead of the next PDU
    # (the Write below) and cost every PDU after it on the connection.
    c2s.append(
        Ether() / IP(src=CLIENT, dst=SERVER) / TCP(sport=1042, dport=1249, seq=cseq, flags="A") / Padding(b"\x00" * 6)
    )
    # IOPCSyncIO::Write of two items (I4 and BSTR)
    write_stub = ORPCTHIS + struct.pack("<II", 2, 2) + struct.pack("<II", 10, 11)
    write_stub += _variants([_variant_i4(1111), _variant_bstr("hello")])
    client(_request(4, 8, 4, write_stub))
    server(_response(4, 8, ORPCTHAT + struct.pack("<III", 0x20000, 2, 0) + b"\x00" * 8))
    # IOPCSyncIO::Read of the level (OPCDATASOURCE, count, handles)
    read_stub = ORPCTHIS + struct.pack("<HHI", 1, 0, 1) + struct.pack("<II", 1, 12)
    client(_request(5, 8, 3, read_stub))
    read_resp = ORPCTHAT + struct.pack("<II", 0x20000, 1)
    read_resp += struct.pack("<IIIHH", 0xA3, 0, 0, 0xC0, 0) + b"User" + b"\x00" * 4
    read_resp = _pad8(read_resp) + _variant_r8(42.5)
    server(_response(5, 8, read_resp))
    # a request on a context bound before the capture started
    client(_request(6, 5, 4, ORPCTHIS + b"\x00" * 8))

    # Callback connection: the OPC server calls the client's IOPCDataCallback.
    cb = (SERVER, 1252, CLIENT, 1043)
    cb_back = (CLIENT, 1043, SERVER, 1252)
    pkts, _ = _segments(*cb, 7000, [_alter(1, 1, IID_CALLBACK)])
    c2s.extend(pkts)
    pkts, _ = _segments(*cb_back, 9000, [_alter_resp(1)])
    c2s.extend(pkts)
    cb_stub = ORPCTHIS + struct.pack("<IIIII", 0, 1, 0, 0, 2) + struct.pack("<III", 2, 0xA3, 0xA1)
    cb_stub += _variants([_variant_r8(43.25), _variant_i4(0)])
    pkts, _ = _segments(*cb, 7000 + len(_alter(1, 1, IID_CALLBACK)), [_request(2, 1, 3, cb_stub)])
    c2s.extend(pkts)

    for index, pkt in enumerate(c2s):
        pkt.time = 1_600_000_000 + index * 0.01
    wrpcap(str(path), c2s)


def test_dcom_conversation_is_decoded(tmp_path) -> None:
    capture = tmp_path / "opc_da.pcap"
    _build_capture(capture)
    summary = analyze_opc_classic(capture, show_status=False)

    assert summary.operation_counts["IOPCItemMgt::AddItems"] == 1
    assert summary.operation_counts["IOPCSyncIO::Write"] == 1
    assert summary.operation_counts["IOPCSyncIO::Read"] == 1
    assert summary.operation_counts["IOPCDataCallback::OnDataChange"] == 1

    level = summary.items["Plant.Tank1.Level"]
    assert (level.server_handle, level.client_handle) == (12, 0xA3)
    assert level.canonical_type == "R8" and level.access_rights == "RW"

    assert [(w.item, w.value, w.vartype) for w in summary.writes] == [
        ("Plant.Valve1.Cmd", "1111", "I4"),
        ("Plant.Label", "'hello'", "BSTR"),
    ]
    assert [(r.item, r.value) for r in summary.reads] == [("Plant.Tank1.Level", "42.5")]
    # Callbacks name items by *client* handle, and run server -> client.
    assert [(u.item, u.value) for u in summary.updates] == [
        ("Plant.Tank1.Level", "43.25"),
        ("Plant.Valve1.Cmd", "0"),
    ]
    assert summary.updates[0].client == CLIENT and summary.updates[0].server == SERVER
    assert summary.client_counts[CLIENT] >= 4 and summary.server_counts[SERVER] >= 4

    assert summary.unattributed_requests["context 5 opnum 4"] == 1
    writes = [d for d in summary.detections if "item writes" in str(d["summary"])]
    assert writes and writes[0]["severity"] == "high"
    assert "T0855" in str(writes[0]["details"])


def test_variant_and_string_scanners() -> None:
    stub = b"\x00" * 8 + _variant_i4(-7) + _variant_bstr("Tag") + b"\x00" * 4
    assert scan_variants(stub) == [(3, "-7"), (8, "'Tag'")]
    assert scan_wstrings(_wstr("Random.Int4") + _wstr("")) == ["Random.Int4", ""]


def test_written_ascii_codes_are_reassembled() -> None:
    assert _ascii_from_values(["102", "108", "97", "103", "123", "125"]) == "flag{}"
    assert _ascii_from_values(["1111", "123"]) == ""
    assert _ascii_from_values(["65", "66"]) == ""  # too short to mean anything
