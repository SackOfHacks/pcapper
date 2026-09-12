"""Rendered output for streams analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from collections import Counter
from ..coloring import (
    header,
    muted,
)
from ..services import COMMON_PORTS
from ..streams import StreamSummary
from ..utils import (
    format_bytes_as_mb,
    format_duration,
    format_ts,
    hexdump,
)

from ._common import (
    SUBSECTION_BAR,
    _finalize_output,
    _format_kv,
    _format_table,
)


def render_streams_summary(summary: StreamSummary, verbose: bool = False) -> str:
    lines = [header("STREAM ANALYSIS")]
    selected_stream = None
    if summary.followed_stream_id:
        selected_stream = next(
            (
                rec
                for rec in summary.streams
                if rec.stream_id == summary.followed_stream_id
            ),
            None,
        )
    # Reassembly completeness: does the captured payload have byte gaps? This is
    # independent of whether the TCP connection ever came up. A SYN-only flow has
    # no payload and therefore no gaps -- so do NOT read "reassembled cleanly" as
    # "connection established"; see the connection-state breakdown below.
    reassembled_clean = [
        rec for rec in summary.streams if not rec.client_gaps and not rec.server_gaps
    ]
    reassembly_gaps = [
        rec for rec in summary.streams if rec.client_gaps or rec.server_gaps
    ]
    # Connection state derived from the TCP handshake (streams.py:_conn_state).
    conn_state_counts: "Counter[str]" = Counter(
        getattr(rec, "conn_state", "unknown") for rec in summary.streams
    )
    established_count = conn_state_counts.get("established", 0)
    active_count = conn_state_counts.get("active", 0)
    not_established = sum(
        count
        for state, count in conn_state_counts.items()
        if state not in ("established", "active")
    )
    all_ordered = sorted(
        summary.streams,
        key=lambda item: (
            item.first_seen is None,
            item.first_seen if item.first_seen is not None else 0.0,
            item.last_seen if item.last_seen is not None else 0.0,
            item.stream_id,
        ),
    )
    lines.append(_format_kv("Total Streams", str(summary.total_streams)))
    if summary.established_only and summary.observed_streams:
        lines.append(_format_kv("Observed Streams", str(summary.observed_streams)))
    if summary.stream_search:
        lines.append(_format_kv("Search Term", summary.stream_search))
    # Connection state first -- this is what analysts usually mean by "did it
    # connect". Keep reassembly completeness as a clearly separate metric.
    lines.append(_format_kv("Established (3-way handshake)", str(established_count)))
    if active_count:
        lines.append(
            _format_kv("Active (mid-capture, no SYN)", str(active_count))
        )
    if not_established:
        breakdown_order = [
            ("syn-only", "SYN-only/unanswered"),
            ("refused", "refused (RST)"),
            ("half-open", "half-open (no final ACK)"),
            ("reset", "reset"),
            ("no-handshake", "no handshake captured"),
            ("unknown", "unknown"),
        ]
        parts = [
            f"{label}={conn_state_counts[state]}"
            for state, label in breakdown_order
            if conn_state_counts.get(state)
        ]
        detail = f" ({', '.join(parts)})" if parts else ""
        lines.append(_format_kv("Not Established", f"{not_established}{detail}"))
        if established_count == 0 and active_count == 0:
            lines.append(
                muted(
                    "No TCP connection in this capture completed a 3-way handshake; "
                    "the flows below are connection attempts, not sessions."
                )
            )
    lines.append(_format_kv("Reassembled Cleanly", str(len(reassembled_clean))))
    lines.append(_format_kv("Reassembly Gaps", str(len(reassembly_gaps))))
    if (
        summary.established_only
        and summary.total_streams == 0
        and summary.observed_streams > 0
    ):
        lines.append(
            muted(
                "No streams met -established (completed 3-way handshake). Run without -established to review attempted TCP connections."
            )
        )
    if summary.followed_stream_id:
        lines.append(_format_kv("Selected Stream ID", summary.followed_stream_id))
        lines.append(_format_kv("Selected 5-Tuple", summary.lookup_tuple or "Not found"))
    if selected_stream:
        lines.append(header("Selected Stream"))
        top = [selected_stream]
    elif summary.streams:
        lines.append(header("All Streams"))
        top = all_ordered
    else:
        top = []

    if top:
        rows = [
            [
                "Stream ID",
                "Flow",
                "Start",
                "Stop",
                "Duration",
                "Traffic",
                "Hostnames",
                "Service",
                "State",
                "Reassembly",
            ]
        ]

        for rec in top:
            flow = f"{rec.client_ip}:{rec.client_port} -> {rec.server_ip}:{rec.server_port}"
            duration = None
            if rec.first_seen is not None and rec.last_seen is not None:
                duration = max(0.0, rec.last_seen - rec.first_seen)
            traffic_text = f"{rec.packets} pkt / {format_bytes_as_mb(rec.bytes)}"
            hostnames_text = f"{rec.client_ip} -> {rec.server_ip}"
            service_text = COMMON_PORTS.get(
                int(rec.server_port), f"TCP/{int(rec.server_port)}"
            )
            reassembly_text = "complete"
            if rec.client_gaps or rec.server_gaps:
                reassembly_text = (
                    f"gaps c={len(rec.client_gaps)} s={len(rec.server_gaps)}"
                )
            elif not rec.client_payload_preview and not rec.server_payload_preview:
                # No application payload at all (e.g. SYN-only) -- "complete"
                # reassembly is vacuous here, so say so plainly.
                reassembly_text = "no-data"
            conn_state_text = getattr(rec, "conn_state", "unknown")
            rows.append(
                [
                    rec.stream_id,
                    flow,
                    format_ts(rec.first_seen),
                    format_ts(rec.last_seen),
                    format_duration(duration),
                    traffic_text,
                    hostnames_text,
                    service_text,
                    conn_state_text,
                    reassembly_text,
                ]
            )
        lines.append(_format_table(rows))

    # `-view`: dump the reassembled HEX/ASCII content of the displayed streams.
    # The single followed stream (-id) already prints its full payload below, so
    # skip it here to avoid duplication.
    if getattr(summary, "view_content", False) and top:
        followed_id = summary.followed_stream_id
        stream_cap = None if verbose else 10
        shown = 0
        for rec in top:
            if followed_id and rec.stream_id == followed_id:
                continue
            client = bytes(rec.client_payload_preview or b"")
            server = bytes(rec.server_payload_preview or b"")
            if not client and not server:
                continue
            if stream_cap is not None and shown >= stream_cap:
                lines.append(
                    muted(
                        f"... content view capped at {stream_cap} streams; narrow with "
                        "-ip/-port/-search/-id or use -v for all."
                    )
                )
                break
            lines.append(SUBSECTION_BAR)
            lines.append(
                header(
                    f"Stream Content {rec.stream_id} :: "
                    f"{rec.client_ip}:{rec.client_port} -> {rec.server_ip}:{rec.server_port}"
                )
            )
            lines.append(f"Client -> Server ({len(client)} bytes):")
            lines.append(hexdump(client) if client else "-")
            lines.append(f"Server -> Client ({len(server)} bytes):")
            lines.append(hexdump(server) if server else "-")
            shown += 1
        if shown == 0:
            lines.append(
                muted("No reassembled stream payload available to view.")
            )

    if summary.followed_stream_id and not selected_stream:
        lines.append(
            muted(f"Selected stream ID not found: {summary.followed_stream_id}")
        )
    if selected_stream:
        duration = None
        if (
            selected_stream.first_seen is not None
            and selected_stream.last_seen is not None
        ):
            duration = max(0.0, selected_stream.last_seen - selected_stream.first_seen)
        lines.append(header("Selected Stream Metadata"))
        lines.append(
            _format_kv(
                "Endpoints",
                f"{selected_stream.src}:{selected_stream.src_port} <-> {selected_stream.dst}:{selected_stream.dst_port}",
            )
        )
        lines.append(
            _format_kv(
                "Client -> Server",
                f"{selected_stream.client_ip}:{selected_stream.client_port} -> {selected_stream.server_ip}:{selected_stream.server_port}",
            )
        )
        lines.append(
            _format_kv(
                "Connection State", getattr(selected_stream, "conn_state", "unknown")
            )
        )
        lines.append(
            _format_kv("First Seen", format_ts(selected_stream.first_seen))
        )
        lines.append(_format_kv("Last Seen", format_ts(selected_stream.last_seen)))
        lines.append(_format_kv("Duration", format_duration(duration)))
        lines.append(_format_kv("Packets", str(selected_stream.packets)))
        lines.append(_format_kv("Bytes", str(selected_stream.bytes)))
        lines.append(
            _format_kv(
                "First Packet Number",
                str(selected_stream.first_packet_number)
                if selected_stream.first_packet_number is not None
                else "-",
            )
        )
        lines.append(
            _format_kv(
                "SYN Packet Number",
                str(selected_stream.syn_packet_number)
                if selected_stream.syn_packet_number is not None
                else "-",
            )
        )
    if summary.followed_packets is not None:
        lines.append(header("Selected Stream Packets"))
        if summary.followed_packets:
            rows = [
                [
                    "Pkt #",
                    "Time",
                    "Dir",
                    "Source",
                    "Destination",
                    "Flags",
                    "Seq",
                    "Ack",
                    "Win",
                    "Frame Bytes",
                    "Payload Bytes",
                ]
            ]
            for item in summary.followed_packets:
                rows.append(
                    [
                        str(item.packet_number),
                        format_ts(item.ts),
                        item.direction,
                        f"{item.src}:{item.src_port}",
                        f"{item.dst}:{item.dst_port}",
                        item.flags,
                        str(item.seq),
                        str(item.ack),
                        str(item.window),
                        str(item.packet_bytes),
                        str(item.payload_bytes),
                    ]
                )
            lines.append(_format_table(rows))
        else:
            lines.append(muted("No packets matched the selected stream ID."))
    if summary.followed_stream_id:
        lines.append(header("Selected Stream Reassembly"))
        lines.append(_format_kv("Stream ID", summary.followed_stream_id))
        if summary.followed_client_gaps:
            lines.append(
                _format_kv(
                    "Client Gaps",
                    ", ".join(
                        f"seq {gap.get('at_seq', 0)} (+{gap.get('gap_bytes', 0)})"
                        for gap in summary.followed_client_gaps
                    ),
                )
            )
        if summary.followed_server_gaps:
            lines.append(
                _format_kv(
                    "Server Gaps",
                    ", ".join(
                        f"seq {gap.get('at_seq', 0)} (+{gap.get('gap_bytes', 0)})"
                        for gap in summary.followed_server_gaps
                    ),
                )
            )
        client_payload = summary.followed_client_payload or b""
        server_payload = summary.followed_server_payload or b""
        lines.append(f"Client Payload ({len(client_payload)} bytes):")
        lines.append(hexdump(client_payload) if client_payload else "-")
        lines.append(f"Server Payload ({len(server_payload)} bytes):")
        lines.append(hexdump(server_payload) if server_payload else "-")
    return _finalize_output(lines, show_truncation_note=False)
