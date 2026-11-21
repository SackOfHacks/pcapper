"""DCSync (DRSUAPI DRSGetNCChanges): recognised with or without the bind."""

from __future__ import annotations

import struct
import uuid as uuidlib

from pcapper.rpc import DRSUAPI_UUID, _dcsync_opnum_shape, analyze_rpc
from test_review_batches import T0, _tcp, _write

CLIENT, SERVER, PORT = "10.0.0.50", "10.0.0.10", 49667


def _request(call_id: int, opnum: int, stub: bytes = b"\x00" * 24) -> bytes:
    body = struct.pack("<IHH", len(stub), 0, opnum) + stub
    return struct.pack("<BBBB4sHHI", 5, 0, 0, 3, b"\x10\x00\x00\x00", 16 + len(body), 0, call_id) + body


def _bind(call_id: int) -> bytes:
    abstract = uuidlib.UUID(DRSUAPI_UUID).bytes_le + struct.pack("<HH", 4, 0)
    ndr = uuidlib.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860").bytes_le + struct.pack("<I", 2)
    ctx = struct.pack("<HBB", 0, 1, 0) + abstract + ndr
    body = struct.pack("<HHIB3x", 5840, 5840, 0, 1) + ctx
    return struct.pack("<BBBB4sHHI", 5, 0, 11, 3, b"\x10\x00\x00\x00", 16 + len(body), 0, call_id) + body


def _session(tmp_path, name: str, payloads: list[bytes]):
    packets, seq = [], 1000
    for i, payload in enumerate(payloads):
        pkt = _tcp(CLIENT, SERVER, 52036, PORT, payload, seq=seq)
        pkt.time = T0 + i
        packets.append(pkt)
        seq += len(payload)
    return analyze_rpc(_write(tmp_path, name, packets), show_status=False)


def test_dcsync_opnum_shape() -> None:
    assert _dcsync_opnum_shape([0, 16, 12, 0, 3, 1])  # secretsdump
    assert _dcsync_opnum_shape([0, 12, 3, 1])
    assert not _dcsync_opnum_shape([0, 3, 1])  # no name lookup: too generic
    assert not _dcsync_opnum_shape([3, 0, 12, 1])  # no DRSBind first
    assert not _dcsync_opnum_shape([0, 16, 12, 3, 5])  # outside the DCSync working set


def test_dcsync_without_bind_is_inferred(tmp_path) -> None:
    summary = _session(tmp_path, "dcsync_nobind.pcap", [_request(8 + i, op) for i, op in enumerate([0, 16, 12, 0, 3, 1])])
    [session] = summary.dcsync_sessions
    assert session["replication"] and session["inferred"]
    assert session["operations"][4] == "IDL_DRSGetNCChanges"
    assert any(d.get("mitre") == "T1003.006" and "DCSync" in str(d.get("summary")) for d in summary.detections)
    assert not any(k.startswith("opnum ") for k in summary.command_counts)


def test_dcsync_with_bind_is_not_inferred(tmp_path) -> None:
    summary = _session(tmp_path, "dcsync_bind.pcap", [_bind(1)] + [_request(2 + i, op) for i, op in enumerate([0, 3, 1])])
    [session] = summary.dcsync_sessions
    assert session["replication"] and not session["inferred"]
    assert summary.command_counts["DRSUAPI (Directory Replication)::IDL_DRSGetNCChanges"] == 1


def test_unrelated_unbound_rpc_is_not_dcsync(tmp_path) -> None:
    summary = _session(tmp_path, "other_rpc.pcap", [_request(1 + i, op) for i, op in enumerate([0, 5, 3, 7])])
    assert summary.dcsync_sessions == []
    assert not any("DCSync" in str(d.get("summary")) for d in summary.detections)
