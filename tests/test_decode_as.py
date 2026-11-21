"""OT protocols on non-standard ports: --decode-as and payload-structure detection.

Backlog 1.2: MAPNA CTF 2024 "PLC I" carries S7comm over TPKT on tcp/10203;
``--overview`` listed ``TCP/10203`` and ``--s7`` found 0 packets. The S7 frames
below are the first ones of that capture.
"""

from __future__ import annotations

import struct
import sys

import pytest
from scapy.all import Ether, IP, TCP, Raw, wrpcap  # type: ignore

from pcapper import cli
from pcapper.modbus import analyze_modbus
from pcapper.port_heuristics import auto_decode, detect_nonstandard_ports
from pcapper.port_overrides import (
    DecodeAsError,
    extra_ports,
    parse_decode_as,
    register,
    register_spec,
)
from pcapper.s7 import analyze_s7

PLC, CLIENT = "10.19.31.85", "192.168.110.40"
MAPNA_S7 = [
    (False, "0300001611e00000000600c1020100c2020102c0010a"),
    (True, "0300001611d00006000300c0010ac1020100c2020102"),
    (False, "0300001902f08032010000020000080000f0000001000101e0"),
    (True, "0300001b02f080320300000200000800000000f0000001000100f0"),
    (False, "0300000702f000"),
    (False, "0300002102f080320700000300000800080001120411440100ff09000400110001"),
    (True, "0300002102f080320700000300000c0004000112081284000000000000ff09000400110001"[:66]),
    (False, "0300002102f080320700000400000800080001120411440100ff09000400110001"),
]


def _tcp_flow(path, server_port: int, payloads: list[tuple[bool, bytes]]) -> None:
    packets, cseq, sseq = [], 1000, 9000
    for index, (from_server, payload) in enumerate(payloads):
        if from_server:
            pkt = Ether() / IP(src=PLC, dst=CLIENT) / TCP(sport=server_port, dport=34979, seq=sseq, flags="PA") / Raw(payload)
            sseq += len(payload)
        else:
            pkt = Ether() / IP(src=CLIENT, dst=PLC) / TCP(sport=34979, dport=server_port, seq=cseq, flags="PA") / Raw(payload)
            cseq += len(payload)
        pkt.time = 1_408_528_771 + index * 0.05
        packets.append(pkt)
    wrpcap(str(path), packets)


def _mapna(path, port: int = 10203) -> None:
    payloads = [(srv, bytes.fromhex(hexdata)) for srv, hexdata in MAPNA_S7]
    # fix the truncated server frame's TPKT length to its real size
    payloads = [
        (srv, data[:2] + struct.pack(">H", len(data)) + data[4:]) for srv, data in payloads
    ]
    _tcp_flow(path, port, payloads)


class TestSpecs:
    @pytest.mark.parametrize(
        "spec,expected",
        [
            ("tcp/10203=s7", [("tcp", 10203, ("s7",))]),
            ("tcp.port==10203,tpkt", [("tcp", 10203, ("s7", "mms", "iccp"))]),
            ("tcp.port=10203:s7comm", [("tcp", 10203, ("s7",))]),
            ("udp/4000=roc", [("udp", 4000, ("rocplus",))]),
            ("1502=tristation", [("tcp", 1502, ("safety",)), ("udp", 1502, ("safety",))]),
        ],
    )
    def test_accepted_forms(self, spec, expected) -> None:
        assert parse_decode_as(spec) == expected

    @pytest.mark.parametrize("spec", ["tcp/99999=s7", "tcp/102=nosuch", "s7 on 102", ""])
    def test_rejected_forms(self, spec) -> None:
        with pytest.raises(DecodeAsError):
            parse_decode_as(spec)

    def test_auto_overrides_are_scoped_to_their_capture(self, tmp_path) -> None:
        a, b = tmp_path / "a.pcap", tmp_path / "b.pcap"
        register("tcp", 10203, "s7", origin="auto: test", scope=a)
        register_spec("tcp/5678=s7")
        assert extra_ports("s7", "tcp", a) == {10203, 5678}
        assert extra_ports("s7", "tcp", b) == {5678}


class TestDetection:
    def test_s7_on_moved_port_is_detected_and_decoded(self, tmp_path) -> None:
        capture = tmp_path / "plc.pcap"
        _mapna(capture)
        assert analyze_s7(capture, show_status=False).protocol_packets == 0
        detections = auto_decode(capture)
        assert [(d.transport, d.port, d.step) for d in detections] == [("tcp", 10203, "s7")]
        assert detections[0].clean == detections[0].total == len(MAPNA_S7)
        s7 = analyze_s7(capture, show_status=False)
        assert s7.protocol_packets == len(MAPNA_S7)
        assert any("SetupCommunication" in str(cmd) for cmd in s7.commands)

    def test_ratio_rule_rejects_a_few_lucky_frames(self, tmp_path) -> None:
        capture = tmp_path / "mixed.pcap"
        good = [(False, bytes.fromhex(MAPNA_S7[2][1]))] * 3
        junk = [(True, b"SSH-2.0-OpenSSH_8.9\r\n")] + [(i % 2 == 0, bytes(range(40, 120))) for i in range(6)]
        _tcp_flow(capture, 2022, good + junk)
        assert detect_nonstandard_ports(capture) == []

    def test_weak_modbus_lookalikes_are_not_modbus(self, tmp_path) -> None:
        # Bytes 2-3 are zero (the MBAP protocol id) but the length field does
        # not frame the payload: the old per-packet heuristic counted these.
        capture = tmp_path / "lookalike.pcap"
        payloads = [(i % 2 == 1, b"\x12\x34\x00\x00\x00\x80" + bytes(range(70))) for i in range(12)]
        _tcp_flow(capture, 7000, payloads)
        assert detect_nonstandard_ports(capture) == []
        assert analyze_modbus(capture, show_status=False).modbus_packets == 0

    def test_clients_of_a_registered_port_are_not_servers(self, tmp_path) -> None:
        # Old Windows/odd stacks use client ports like 1054 or even 1/3/5, and
        # a stray SYN *to* that client port (scan, reset) must not make it the
        # "server" of the Modbus flow to 502 (Cyber4OT, S4x15 Modicon).
        capture = tmp_path / "clients.pcap"
        request = bytes.fromhex("000100000006010300000002")
        response = bytes.fromhex("0001000000070103040001000a")
        pkts = [Ether() / IP(src=PLC, dst=CLIENT) / TCP(sport=40000, dport=5, flags="S")]
        for i in range(4):
            pkts.append(Ether() / IP(src=CLIENT, dst=PLC) / TCP(sport=5, dport=502, flags="PA") / Raw(request))
            pkts.append(Ether() / IP(src=PLC, dst=CLIENT) / TCP(sport=502, dport=5, flags="PA") / Raw(response))
        wrpcap(str(capture), pkts)
        assert detect_nonstandard_ports(capture) == []

    def test_framed_modbus_on_moved_port(self, tmp_path) -> None:
        capture = tmp_path / "modbus5020.pcap"
        request = bytes.fromhex("000100000006010300000002")
        response = bytes.fromhex("0001000000070103040001000a")
        _tcp_flow(capture, 5020, [(False, request), (True, response)] * 3)
        detections = auto_decode(capture)
        assert [(d.port, d.step) for d in detections] == [(5020, "modbus")]
        assert analyze_modbus(capture, show_status=False).modbus_packets == 6


class TestCli:
    def _run(self, monkeypatch, *args, errors=None) -> int:
        monkeypatch.setattr(sys, "argv", ["pcapper", *args])
        if errors is not None:
            monkeypatch.setattr(cli, "_print_error", errors.append)
        return cli.main()

    def test_auto_detection_is_announced(self, tmp_path, monkeypatch, capfd) -> None:
        """The decode-as notice is detail: announced with -v, silent without
        (the report still decodes the port either way)."""
        capture = tmp_path / "plc.pcap"
        _mapna(capture)
        errors: list[str] = []
        assert self._run(monkeypatch, str(capture), "--s7", errors=errors) == 0
        assert not any("Auto decode-as" in e for e in errors)
        assert f"{len(MAPNA_S7)} S7 packets" in capfd.readouterr().out
        assert self._run(monkeypatch, str(capture), "--s7", "-v", errors=errors) == 0
        assert any("Auto decode-as" in e and "tcp/10203" in e for e in errors)
        assert f"{len(MAPNA_S7)} S7 packets" in capfd.readouterr().out

    def test_no_auto_decode_and_explicit_spec(self, tmp_path, monkeypatch, capfd) -> None:
        capture = tmp_path / "plc.pcap"
        _mapna(capture)
        assert self._run(monkeypatch, str(capture), "--s7", "--no-auto-decode") == 0
        assert "no S7 traffic in this capture" in capfd.readouterr().out
        errors: list[str] = []
        assert (
            self._run(
                monkeypatch, str(capture), "--s7", "--no-auto-decode",
                "--decode-as", "tcp.port==10203,s7comm", errors=errors,
            )
            == 0
        )
        assert any("Decode-as: tcp/10203 as s7 (user)" in e for e in errors)
        assert f"{len(MAPNA_S7)} S7 packets" in capfd.readouterr().out

    def test_bad_spec_exits_2(self, tmp_path, monkeypatch) -> None:
        capture = tmp_path / "plc.pcap"
        _mapna(capture)
        errors: list[str] = []
        assert self._run(monkeypatch, str(capture), "--s7", "--decode-as", "tcp/1=nosuch", errors=errors) == 2
        assert any("unknown protocol" in e for e in errors)
