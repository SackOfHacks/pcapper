"""A reply from another service whose destination (the peer's ephemeral
port) happens to equal an OT port is not that OT protocol."""

from __future__ import annotations

from pcapper.dnp3 import analyze_dnp3
from pcapper.enip import analyze_enip
from pcapper.knx import analyze_knx
from pcapper.ot_ports import foreign_service_reply
from test_review_batches import T0, _tcp, _write

# A Modbus/TCP response: MBAP, unit 1, Read Holding Registers, 2 bytes of data.
MODBUS_REPLY = bytes.fromhex("000100000005010302002a")


def _reply_to(port: int, tmp_path, name: str):
    pkt = _tcp("192.168.1.105", "192.168.1.100", 502, port, MODBUS_REPLY)
    pkt.time = T0
    return _write(tmp_path, name, [pkt])


def test_foreign_service_reply_rule() -> None:
    assert foreign_service_reply(502, {44818, 2222})  # Modbus reply to an ephemeral 2222
    assert foreign_service_reply(53, {3671})
    assert not foreign_service_reply(51000, {44818})  # an ordinary client port
    assert not foreign_service_reply(2222, {2222})  # the protocol's own port


def test_modbus_reply_to_ephemeral_2222_is_not_enip(tmp_path) -> None:
    assert analyze_enip(_reply_to(2222, tmp_path, "enip.pcap"), show_status=False).enip_packets == 0


def test_modbus_reply_to_ephemeral_3671_is_not_knx(tmp_path) -> None:
    assert analyze_knx(_reply_to(3671, tmp_path, "knx.pcap"), show_status=False).protocol_packets == 0


def test_modbus_reply_to_ephemeral_20000_is_not_dnp3(tmp_path) -> None:
    summary = analyze_dnp3(_reply_to(20000, tmp_path, "dnp3.pcap"), show_status=False)
    assert summary.dnp3_packets == 0 and not summary.errors


def test_modbus_write_is_one_command_not_two(tmp_path) -> None:
    # A Modbus write is echoed in its response: two frames, one command.
    from pcapper.modbus import analyze_modbus

    write = bytes.fromhex("000700000006010500020000")  # Write Single Coil, coil 2, 0x0000
    request = _tcp("192.168.1.100", "192.168.1.101", 50000, 502, write)
    request.time = T0
    echo = _tcp("192.168.1.101", "192.168.1.100", 502, 50000, write)
    echo.time = T0 + 0.01
    summary = analyze_modbus(_write(tmp_path, "modbus_write.pcap", [request, echo]), show_status=False)
    assert summary.func_counts["Write Single Coil"] == 2
    assert summary.request_func_counts["Write Single Coil"] == 1
