from __future__ import annotations

from pathlib import Path

from pcapper.reporting import render_timeline_summary
from pcapper.timeline import (
    TimelineEvent,
    TimelineSummary,
    _format_s7_timeline_command,
    _is_interesting_s7_command,
    _tls_handshake_label,
)


def test_tls_handshake_label_detects_common_records() -> None:
    client_hello = b"\x16\x03\x03\x00\x31\x01" + b"\x00" * 8
    server_hello = b"\x16\x03\x03\x00\x31\x02" + b"\x00" * 8

    assert _tls_handshake_label(client_hello) == "TLS ClientHello"
    assert _tls_handshake_label(server_hello) == "TLS ServerHello"
    assert _tls_handshake_label(b"\x17\x03\x03\x00\x10\x01") is None


def test_s7_command_filter_removes_transport_noise() -> None:
    assert not _is_interesting_s7_command("TPKT")
    assert not _is_interesting_s7_command("COTP:DT")
    assert not _is_interesting_s7_command("UserData")

    assert _is_interesting_s7_command("COTP:CR")
    assert _is_interesting_s7_command("WriteVar")
    assert _is_interesting_s7_command(
        "UserData:Cpu:VarTabWrite(sel=0x81,item=0x08,mode=0x02)"
    )


def test_s7_timeline_command_formatter_splits_metadata() -> None:
    summary, meta = _format_s7_timeline_command(
        "UserData:Cpu:VarTabWrite(sel=0x81,item=0x08,mode=0x02)"
    )
    assert summary == "S7 UserData:Cpu:VarTabWrite"
    assert meta is not None
    assert "sel=0x81" in meta

    cotp_summary, cotp_meta = _format_s7_timeline_command(
        "COTP:CR:SrcTSAP=0x0100:DstTSAP=0x0102"
    )
    assert cotp_summary == "S7 COTP CR"
    assert cotp_meta == "SrcTSAP=0x0100:DstTSAP=0x0102"


def test_render_timeline_surfaces_high_value_ot_actions_and_event_metadata() -> None:
    events = [
        TimelineEvent(
            ts=1.0,
            category="S7",
            summary="S7 CPU State Change Confirmed",
            details="PLCStop transaction succeeded. (10.0.0.10 -> 10.0.0.20)",
            packet_index=42,
            source="s7",
        ),
        TimelineEvent(
            ts=2.0,
            category="S7",
            summary="S7 UserData:Cpu:VarTabWrite",
            details="10.0.0.10 -> 10.0.0.20 sel=0x81,item=0x08,mode=0x02",
            packet_index=43,
            source="s7",
        ),
    ]

    summary = TimelineSummary(
        path=Path("sample.pcap"),
        target_ip="10.0.0.10",
        total_packets=10,
        events=events,
        errors=[],
        first_seen=1.0,
        last_seen=2.0,
        duration=1.0,
        category_counts={"S7": 2},
        peer_counts={"10.0.0.20": 2},
        port_counts={102: 2},
        ot_protocol_counts={"S7": 2},
    )

    rendered = render_timeline_summary(summary, limit=20)

    assert "High-Value OT Actions" in rendered
    assert "S7 CPU State Change Confirmed" in rendered
    assert "source=s7" in rendered
    assert "pkt=42" in rendered
