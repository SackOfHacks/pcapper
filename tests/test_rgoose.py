"""R-GOOSE (IEC 61850-90-5 routable GOOSE over CLTP/UDP) is analysed as GOOSE.

Backlog 1.1: ``--goose`` reported 0 packets on the IEEE 24-bus SDN lab
captures, which carry GOOSE inside 90-5 session PDUs on UDP (port 8694 there;
the standard is 102). Layout follows Wireshark's R-GOOSE dissector; note the
APDU length there counts its own two bytes.
"""

from __future__ import annotations

from scapy.all import Ether, IP, UDP, Raw, wrpcap  # type: ignore

from pcapper.goose import analyze_goose, parse_rgoose
from pcapper.overview import analyze_overview

PUBLISHER, GROUP = "10.100.3.30", "232.0.2.3"


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag, len(value)]) + value


def _goose_pdu(st: int, sq: int, trip: bool) -> bytes:
    body = (
        _tlv(0x80, b"IED03/LLN0$GO$gcb01")
        + _tlv(0x81, (4000).to_bytes(2, "big"))
        + _tlv(0x82, b"IED03/LLN0$Trip")
        + _tlv(0x83, b"protection_from_ied3")
        + _tlv(0x84, b"\x6a\x0c\xc0\x8c\x76\x04\x18\x0a")
        + _tlv(0x85, st.to_bytes(1, "big"))
        + _tlv(0x86, sq.to_bytes(2, "big"))
        + _tlv(0x87, b"\x00")
        + _tlv(0x88, b"\x01")
        + _tlv(0x89, b"\x00")
        + _tlv(0x8A, b"\x01")
        + _tlv(0xAB, _tlv(0x83, b"\x01" if trip else b"\x00"))
    )
    return _tlv(0x61, body)


def _session(spdu: int, pdu: bytes, signed: bool = True) -> bytes:
    entry = bytes([0x81, 0x00]) + (0).to_bytes(2, "big") + (len(pdu) + 2).to_bytes(2, "big") + pdu
    security = (0).to_bytes(4, "big") + (0).to_bytes(2, "big") + (1).to_bytes(4, "big") + b"\x00"
    common = (
        bytes([0x80, 0x12])
        + (128).to_bytes(4, "big")
        + spdu.to_bytes(4, "big")
        + (2).to_bytes(2, "big")
        + security
    )
    out = b"\x01\x40\xa1\x18" + common + len(entry).to_bytes(4, "big") + entry
    if signed:
        out += b"\x85\x10" + bytes(range(16))
    return out


def _capture(path, sessions: list[tuple[float, bytes]], port: int = 8694) -> None:
    packets = []
    for ts, payload in sessions:
        pkt = Ether() / IP(src=PUBLISHER, dst=GROUP) / UDP(sport=45477, dport=port) / Raw(payload)
        pkt.time = 1_700_000_000 + ts
        packets.append(pkt)
    wrpcap(str(path), packets)


def test_session_is_parsed() -> None:
    session = parse_rgoose(_session(98, _goose_pdu(11, 98, False)))
    assert session is not None
    assert (session.session_id, session.spdu_number, session.key_id) == (0xA1, 98, 1)
    assert len(session.apdus) == 1 and session.apdus[0].apdu[0] == 0x61
    assert len(session.signature) == 16 and session.payload_parsed
    assert parse_rgoose(b"\x01\x40\xa1" + b"\x00" * 40) is None


def test_goose_inside_rgoose_is_analysed(tmp_path) -> None:
    capture = tmp_path / "rgoose.pcap"
    _capture(capture, [(i * 1.0, _session(98 + i, _goose_pdu(11, 98 + i, False))) for i in range(5)])
    summary = analyze_goose(capture, show_status=False)
    assert summary.goose_packets == summary.rgoose_packets == 5
    assert summary.gocb_refs["IED03/LLN0$GO$gcb01"] == 5
    assert summary.rgoose_publishers == {PUBLISHER: 5}
    assert summary.rgoose_ports == {8694: 5} and summary.rgoose_signed == 5
    summaries = [d["summary"] for d in summary.detections]
    assert "GOOSE routed beyond the substation LAN (R-GOOSE, IEC 61850-90-5)" in summaries
    assert "R-GOOSE on a non-standard UDP port" in summaries
    assert not any("replay" in s.lower() for s in summaries)


def test_reordering_is_not_replay_but_reuse_is(tmp_path) -> None:
    reordered = tmp_path / "reordered.pcap"
    _capture(reordered, [
        (0.0, _session(150, _goose_pdu(16, 150, False))),
        (0.001, _session(152, _goose_pdu(16, 152, False))),
        (0.002, _session(151, _goose_pdu(16, 151, False))),
        (0.003, _session(153, _goose_pdu(16, 153, False))),
    ])
    found = analyze_goose(reordered, show_status=False).detections
    assert not [d for d in found if d["severity"] in ("warning", "high")]
    assert any("reordering" in str(d["summary"]) for d in found)

    replayed = tmp_path / "replayed.pcap"
    _capture(replayed, [
        (0.0, _session(150, _goose_pdu(16, 150, False))),
        (1.0, _session(151, _goose_pdu(17, 0, True))),
        (5.0, _session(150, _goose_pdu(16, 150, False))),  # old PDU re-sent later
    ])
    found = analyze_goose(replayed, show_status=False).detections
    assert any(d["summary"].startswith("R-GOOSE session PDU replayed") for d in found)


def test_unsigned_rgoose_is_high(tmp_path) -> None:
    capture = tmp_path / "unsigned.pcap"
    _capture(capture, [(i * 1.0, _session(10 + i, _goose_pdu(1, i, False), signed=False)) for i in range(3)], port=102)
    summary = analyze_goose(capture, show_status=False)
    found = {d["summary"]: d["severity"] for d in summary.detections}
    assert found["R-GOOSE without message authentication"] == "high"
    assert "R-GOOSE on a non-standard UDP port" not in found


def test_overview_finds_rgoose_on_any_port(tmp_path) -> None:
    capture = tmp_path / "rgoose.pcap"
    _capture(capture, [(i * 1.0, _session(98 + i, _goose_pdu(11, 98 + i, False))) for i in range(5)])
    overview = analyze_overview(capture, show_status=False)
    assert "goose" in overview.modules_run
