"""Defects found by running the ICS-PCAP-Challenges walkthroughs (2.9.0 review)."""

from __future__ import annotations

from scapy.all import Ether, IP, TCP, Raw, wrpcap  # type: ignore

from pcapper.goose import analyze_goose
from pcapper.mitre import _fallback_from_explicit_ids
from pcapper.modbus import _register_text, analyze_modbus
from pcapper.ot_commands import _is_write_command
from pcapper.reporting._common import _ot_command_risk
from pcapper.utils import format_ts


def test_garbage_timestamps_render() -> None:
    # ICSC 2021 FINS/S7 captures carry pcapng timestamps in year 31969.
    assert format_ts(946_684_800.0).startswith("2000-01-01")
    assert "out-of-range" in format_ts(1_0000_000_000_000.0)


def test_ics_techniques_get_their_own_tactic() -> None:
    tactic, tactic_id, _t, technique_id = _fallback_from_explicit_ids([], ["T0858"], "ics", "x")
    assert (tactic, tactic_id, technique_id) == ("Execution", "TA0104", "T0858")
    assert _fallback_from_explicit_ids([], ["T0804"], "ics", "x")[1] == "TA0107"


def test_responses_are_not_writes() -> None:
    assert not _is_write_command("Write response")
    assert _is_write_command("Write request")
    assert _ot_command_risk("Write response") == "Normal"


def test_register_values_spell_text(tmp_path) -> None:
    assert _register_text({0: ord("f"), 1: ord("l"), 2: ord("a"), 3: ord("g"), 4: ord("{"), 5: ord("}")}) == "flag{}"
    assert _register_text({0: 0x6865, 1: 0x6C6C, 2: 0x6F21}) == "hello!"
    pkts = []
    for i, ch in enumerate("flag{ok}"):
        req = (1000).to_bytes(2, "big") + b"\x00\x00\x00\x06\x64\x03" + i.to_bytes(2, "big") + b"\x00\x01"
        resp = (1000).to_bytes(2, "big") + b"\x00\x00\x00\x05\x64\x03\x02" + ord(ch).to_bytes(2, "big")
        pkts.append(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000, dport=502, seq=1 + 12 * i, flags="PA") / Raw(req))
        pkts.append(Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=502, dport=40000, seq=1 + 11 * i, flags="PA") / Raw(resp))
    capture = tmp_path / "m.pcap"
    wrpcap(str(capture), pkts)
    titles = [a.title for a in analyze_modbus(capture, show_status=False).anomalies]
    assert any("flag{ok}" in t for t in titles)


def _goose(st: int, sq: int) -> bytes:
    def tlv(tag, value):
        return bytes([tag, len(value)]) + value
    body = (tlv(0x80, b"IED/LLN0$GO$g") + tlv(0x81, b"\x07\xd0") + tlv(0x82, b"IED/LLN0$DS")
            + tlv(0x85, st.to_bytes(2, "big")) + tlv(0x86, sq.to_bytes(2, "big"))
            + tlv(0xAB, tlv(0x83, b"\x00")))
    pdu = tlv(0x61, body)
    return (1).to_bytes(2, "big") + (8 + len(pdu)).to_bytes(2, "big") + b"\x00" * 4 + pdu


def test_inflated_stnum_injection_is_suppression(tmp_path) -> None:
    frames = [(5, 0), (5, 1), (9999, 0), (5, 2), (5, 3)]
    pkts = []
    for i, (st, sq) in enumerate(frames):
        pkt = Ether(src="00:09:8e:21:73:33", dst="01:0c:cd:01:00:01", type=0x88B8) / Raw(_goose(st, sq))
        pkt.time = 1_700_000_000 + i * 0.5
        pkts.append(pkt)
    capture = tmp_path / "g.pcap"
    wrpcap(str(capture), pkts)
    found = {d["summary"]: d["severity"] for d in analyze_goose(capture, show_status=False).detections}
    assert found["GOOSE message suppression (inflated stNum injected)"] == "high"
