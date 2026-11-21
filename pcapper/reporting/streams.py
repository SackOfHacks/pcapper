"""Rendered output for --streams: TCP streams with their connection state
(did it connect) and reassembly completeness (is the payload whole), and,
on request, one stream followed packet by packet or its content."""

from __future__ import annotations

from collections import Counter

from ..services import COMMON_PORTS
from ..streams import StreamSummary
from ..utils import format_bytes_as_mb, hexdump
from . import _style as st

_STATE_LABELS = [
    ("syn-only", "SYN-only/unanswered"), ("refused", "refused (RST)"), ("half-open", "half-open (no final ACK)"),
    ("reset", "reset"), ("no-handshake", "no handshake captured"), ("unknown", "unknown"),
]


def _reassembly(rec) -> str:  # type: ignore[no-untyped-def]
    if rec.client_gaps or rec.server_gaps:
        return st.caution(f"gaps c={len(rec.client_gaps)} s={len(rec.server_gaps)}")
    if not rec.client_payload_preview and not rec.server_payload_preview:
        return "no data"  # a SYN-only flow: "complete" would be vacuous
    return "complete"


def _content(title: str, client: bytes, server: bytes) -> list[str]:
    return [f"  {st.strong(title)}", f"  {st.dim(f'client -> server ({len(client)} bytes)')}",
            hexdump(client) if client else "  -", f"  {st.dim(f'server -> client ({len(server)} bytes)')}",
            hexdump(server) if server else "  -"]


def render_streams_summary(summary: StreamSummary, verbose: bool = False) -> str:
    rep = st.Report("TCP streams", summary.path)
    states = Counter(getattr(r, "conn_state", "unknown") for r in summary.streams)
    established, active = states.get("established", 0), states.get("active", 0)
    not_established = sum(n for s, n in states.items() if s not in ("established", "active"))
    gaps = [r for r in summary.streams if r.client_gaps or r.server_gaps]
    rep.headline(False, st.join([
        st.plural(summary.total_streams, "stream"), f"{st.count(established)} established",
        f"{st.count(active)} mid-capture" if active else "",
        f"{st.count(not_established)} not established" if not_established else "",
        st.caution(f"{len(gaps)} with reassembly gaps") if gaps else "",
    ]), st.join([
        f"of {st.count(summary.observed_streams)} observed (-established)" if summary.established_only and summary.observed_streams else "",
        f"search {summary.stream_search!r}" if summary.stream_search else "",
    ]))
    if not_established:
        parts = [f"{label}={states[s]}" for s, label in _STATE_LABELS if states.get(s)]
        rep.scope("not established: " + ", ".join(parts))
    if not_established and not established and not active:
        rep.note("NOTE", "no TCP connection completed a 3-way handshake: these are connection attempts, not sessions")
    if summary.established_only and summary.total_streams == 0 and summary.observed_streams > 0:
        rep.note("NOTE", "no stream completed a 3-way handshake; run without -established to see the attempts")
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])

    selected = None
    if summary.followed_stream_id:
        selected = next((r for r in summary.streams if r.stream_id == summary.followed_stream_id), None)
        if selected is None:
            rep.note("MISSING", f"stream ID not found: {summary.followed_stream_id}")
    ordered = sorted(summary.streams, key=lambda r: (r.first_seen is None, r.first_seen or 0.0, r.last_seen or 0.0, r.stream_id))
    shown = [selected] if selected else ordered

    def _row(r) -> list:  # type: ignore[no-untyped-def]
        dur = max(0.0, r.last_seen - r.first_seen) if r.first_seen is not None and r.last_seen is not None else None
        return [r.stream_id, f"{r.client_ip}:{r.client_port} -> {r.server_ip}:{r.server_port}", st.ts(r.first_seen)] + (
            [st.ts(r.last_seen)] if st.verbose() else []) + [
                st.duration(dur) if dur is not None else "-",
                f"{r.packets} pkt / {format_bytes_as_mb(r.bytes)}",
                COMMON_PORTS.get(int(r.server_port), f"TCP/{int(r.server_port)}"), getattr(r, "conn_state", "unknown"), _reassembly(r)]

    rep.section("Selected stream" if selected else "Streams", st.table(
        ["Stream ID", "Flow", "Start"] + (["Stop"] if st.verbose() else []) + ["Duration", "Traffic", "Service", "State", "Reassembly"],
        [_row(r) for r in shown], max_rows=20, noun="stream",
    ))

    if getattr(summary, "view_content", False) and shown:
        blocks: list[str] = []
        cap = None if (st.verbose() or verbose) else 10
        count = 0
        for r in shown:
            if summary.followed_stream_id and r.stream_id == summary.followed_stream_id:
                continue
            client, server = bytes(r.client_payload_preview or b""), bytes(r.server_payload_preview or b"")
            if not client and not server:
                continue
            if cap is not None and count >= cap:
                blocks.append(st.dim(f"  … content capped at {cap} streams; narrow with -ip/-port/-search/-id or use -v"))
                break
            blocks += _content(f"{r.stream_id}  {r.client_ip}:{r.client_port} -> {r.server_ip}:{r.server_port}", client, server)
            count += 1
        rep.section("Content", blocks or [f"  {st.dim('no reassembled payload to view')}"])

    if selected:
        dur = (max(0.0, selected.last_seen - selected.first_seen)
               if selected.first_seen is not None and selected.last_seen is not None else None)
        rep.section("Stream metadata", st.kv([
            ("Endpoints", f"{selected.src}:{selected.src_port} <-> {selected.dst}:{selected.dst_port}"),
            ("Client -> server", f"{selected.client_ip}:{selected.client_port} -> {selected.server_ip}:{selected.server_port}"),
            ("Connection state", getattr(selected, "conn_state", "unknown")),
            ("First / last seen", f"{st.ts(selected.first_seen)} / {st.ts(selected.last_seen)}"),
            ("Duration", st.duration(dur) if dur is not None else "-"),
            ("Packets / bytes", f"{selected.packets} / {selected.bytes}"),
            ("First / SYN packet", f"{selected.first_packet_number if selected.first_packet_number is not None else '-'} / "
                                   f"{selected.syn_packet_number if selected.syn_packet_number is not None else '-'}"),
        ]))
    if summary.followed_packets is not None:
        rep.section("Stream packets", st.table(
            ["Pkt", "Time", "Dir", "Source", "Destination", "Flags", "Seq", "Ack", "Win", "Frame", "Payload"],
            [[p.packet_number, st.ts(p.ts), p.direction, f"{p.src}:{p.src_port}", f"{p.dst}:{p.dst_port}", p.flags,
              p.seq, p.ack, p.window, p.packet_bytes, p.payload_bytes] for p in summary.followed_packets],
            align="rllllllrrrr", max_rows=None,
        ) or [f"  {st.dim('no packets matched the selected stream ID')}"])
    if summary.followed_stream_id:
        def _gaps(g: list) -> str:
            return ", ".join(f"seq {x.get('at_seq', 0)} (+{x.get('gap_bytes', 0)})" for x in g)
        rep.section("Stream reassembly", st.kv([
            ("Client gaps", _gaps(summary.followed_client_gaps or [])),
            ("Server gaps", _gaps(summary.followed_server_gaps or [])),
        ]) + _content("payload", summary.followed_client_payload or b"", summary.followed_server_payload or b""))
    return rep.render()
