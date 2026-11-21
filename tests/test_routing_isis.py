"""IS-IS over IEEE 802.3/LLC: frames are read, PDU types and TLVs follow ISO 10589."""

from __future__ import annotations

import struct

from scapy.layers.l2 import LLC, Dot3
from scapy.packet import Raw

from pcapper.routing import _parse_isis_pdu, analyze_routing
from test_review_batches import T0, _write

SYSID = bytes.fromhex("444444444444")


def _hello(tlvs: bytes) -> bytes:
    fixed = bytes([0x02]) + SYSID + struct.pack(">HH", 30, 27 + len(tlvs)) + bytes([0x40]) + SYSID + b"\x01"
    return bytes([0x83, 27, 1, 0, 16, 1, 0, 0]) + fixed + tlvs


def _lsp(tlvs: bytes, seq: int = 10) -> bytes:
    fixed = struct.pack(">HH", 27 + len(tlvs), 1199) + SYSID + b"\x00\x00" + struct.pack(">IHB", seq, 0x1234, 0x03)
    return bytes([0x83, 27, 1, 0, 20, 1, 0, 0]) + fixed + tlvs


def _frame(isis: bytes, ts: float):
    pkt = Dot3(dst="01:80:c2:00:00:15", src="c2:03:29:a9:00:00") / LLC(dsap=0xFE, ssap=0xFE, ctrl=3) / Raw(isis)
    pkt.time = ts
    return pkt


def test_isis_pdu_types_and_offsets() -> None:
    hello = _parse_isis_pdu(_hello(b"\x01\x04\x03\x49\x00\x14"))
    assert hello["pdu_type"] == 16 and hello["source_id"] == "4444.4444.4444" and hello["hold_time"] == 30
    lsp = _parse_isis_pdu(_lsp(b"\x89\x02R9", seq=10))
    assert lsp["pdu_type"] == 20 and lsp["lsp_seq"] == 10 and lsp["lsp_id"] == "4444.4444.4444.00-00"
    assert lsp["tlvs"]["hostnames"] == ["R9"]


def test_lsp_entries_tlv_is_not_authentication() -> None:
    # TLV 9 is LSP Entries (CSNP/PSNP), not authentication.
    csnp = bytes([0x83, 33, 1, 0, 25, 1, 0, 0]) + struct.pack(">H", 49) + SYSID + b"\x00" + b"\x00" * 16
    parsed = _parse_isis_pdu(csnp + b"\x09\x10" + b"\x04\xb1" + b"\x44" * 8 + b"\x00\x00\x00\x0a" + b"\x12\x34")
    assert parsed["tlvs"]["auth_types"] == [] and parsed["tlvs"]["auth_values"] == []


def test_isis_over_llc_is_analyzed_with_cleartext_password(tmp_path) -> None:
    pcap = _write(tmp_path, "isis.pcap", [
        _frame(_hello(b"\x01\x04\x03\x49\x00\x14" + b"\x0a\x07\x01s3cret"), T0),
        _frame(_lsp(b"\x89\x02R9"), T0 + 1),
    ])
    summary = analyze_routing(pcap, show_status=False)
    assert summary.protocol_counts["IS-IS"] == 2
    assert summary.message_counts["IS-IS L2 LAN Hello"] == 1 and summary.message_counts["IS-IS L2 LSP"] == 1
    assert "R9" in summary.isis_hostname_counts
    titles = [str(d.get("summary")) for d in summary.detections]
    assert any("plaintext authentication" in t for t in titles)
    assert any("s3cret" in str(d.get("details")) for d in summary.detections)
    assert "IS-IS without authentication" not in titles
