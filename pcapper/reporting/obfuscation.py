"""Rendered output for obfuscation analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    danger,
    header,
    muted,
    ok,
    warn,
)
from ..utils import (
    format_duration,
    format_speed_bps,
    format_ts,
)

from ._common import (
    _finalize_output,
    _format_counter,
    _format_kv,
    _format_table,
    _limit_value,
    _truncate_text,
)


def render_obfuscation_summary(summary) -> str:
    if not summary:
        return ""
    lines = [header("OBFUSCATION / TUNNELING")]

    # ---- Analyst Verdict + Detections -----------------------------------
    # The computed `detections` (with severity) were never rendered — only a
    # wall of stats. Lead with the triage call. Note: base64/hex blobs are
    # LOW severity on purpose (TLS, cookies, images encode constantly), so they
    # must not escalate the verdict; only IOC/attack/covert-channel signals do.
    detections = list(getattr(summary, "detections", []) or [])
    sev_rank = {"high": 3, "warning": 2, "medium": 2, "low": 1, "info": 0}
    worst = max((sev_rank.get(str(d.get("severity", "info")).lower(), 0) for d in detections), default=0)
    if worst >= 3:
        v_text, v_fn = "COVERT CHANNEL / ENCODED ATTACK CONTENT", danger
    elif worst == 2:
        v_text, v_fn = "OBFUSCATED CONTENT OF INTEREST", warn
    elif worst == 1:
        v_text, v_fn = "ENCODED CONTENT PRESENT (likely benign encoding)", muted
    else:
        v_text, v_fn = "NO OBFUSCATION / TUNNELING SIGNALS", ok
    lines.append(v_fn(f"[VERDICT] {v_text}"))
    if detections:
        ordered = sorted(
            detections,
            key=lambda d: -sev_rank.get(str(d.get("severity", "info")).lower(), 0),
        )
        lines.append(header("Detections"))
        for d in ordered[: _limit_value(8)]:
            sev = str(d.get("severity", "info")).upper()
            title = str(d.get("summary") or d.get("title") or "Detection")
            sev_fn = danger if sev == "HIGH" else (warn if sev in ("WARNING", "MEDIUM") else muted)
            lines.append(sev_fn(f"[{sev}] {title}"))
            details = str(d.get("details", "")).strip()
            if details:
                lines.append(muted(f"  {details}"))
            evidence = d.get("evidence") or []
            if isinstance(evidence, list):
                for ev in evidence[: _limit_value(4)]:
                    lines.append(muted(f"  - {_truncate_text(str(ev), 140)}"))

    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("Payload Bytes", str(summary.total_payload_bytes)))
    lines.append(
        _format_kv("Suspicious Packets", str(getattr(summary, "suspicious_packets", 0)))
    )
    lines.append(
        _format_kv(
            "Suspicious Bytes", str(getattr(summary, "suspicious_payload_bytes", 0))
        )
    )
    if getattr(summary, "total_payload_bytes", 0):
        suspicious_share = (
            getattr(summary, "suspicious_payload_bytes", 0)
            / summary.total_payload_bytes
        ) * 100.0
        lines.append(_format_kv("Suspicious Byte Share", f"{suspicious_share:.1f}%"))
    lines.append(_format_kv("Start", format_ts(getattr(summary, "first_seen", None))))
    lines.append(_format_kv("End", format_ts(getattr(summary, "last_seen", None))))
    lines.append(
        _format_kv(
            "Duration", format_duration(getattr(summary, "duration_seconds", None))
        )
    )
    duration = getattr(summary, "duration_seconds", None)
    if (
        isinstance(duration, (int, float))
        and duration > 0
        and summary.total_payload_bytes
    ):
        lines.append(
            _format_kv(
                "Observed Throughput",
                format_speed_bps(int((summary.total_payload_bytes * 8) / duration)),
            )
        )
    if (
        isinstance(duration, (int, float))
        and duration > 0
        and getattr(summary, "suspicious_payload_bytes", 0)
    ):
        lines.append(
            _format_kv(
                "Suspicious Throughput",
                format_speed_bps(
                    int((summary.suspicious_payload_bytes * 8) / duration)
                ),
            )
        )
    lines.append(
        _format_kv(
            "Sessions (Susp/Total)",
            f"{getattr(summary, 'suspicious_sessions', 0)}/{getattr(summary, 'total_sessions', 0)}",
        )
    )
    lines.append(_format_kv("High Entropy Hits", str(len(summary.high_entropy_hits))))
    lines.append(_format_kv("Base64 Hits", str(len(summary.base64_hits))))
    lines.append(_format_kv("Hex Hits", str(len(summary.hex_hits))))
    if getattr(summary, "hit_kind_counts", None):
        if summary.hit_kind_counts:
            lines.append(
                _format_kv("Hit Kinds", _format_counter(summary.hit_kind_counts, 6))
            )
    if summary.source_counts:
        lines.append(
            _format_kv("Top Sources", _format_counter(summary.source_counts, 6))
        )
    if summary.destination_counts:
        lines.append(
            _format_kv(
                "Top Destinations", _format_counter(summary.destination_counts, 6)
            )
        )
    if getattr(summary, "protocol_counts", None):
        if summary.protocol_counts:
            lines.append(
                _format_kv(
                    "Suspicious Protocols", _format_counter(summary.protocol_counts, 6)
                )
            )
    if getattr(summary, "port_counts", None):
        if summary.port_counts:
            lines.append(
                _format_kv("Suspicious Ports", _format_counter(summary.port_counts, 6))
            )
    if getattr(summary, "ioc_counts", None):
        if summary.ioc_counts:
            lines.append(
                _format_kv("Recovered IOCs", _format_counter(summary.ioc_counts, 8))
            )
    if getattr(summary, "attack_counts", None):
        if summary.attack_counts:
            lines.append(
                _format_kv("Attack Signals", _format_counter(summary.attack_counts, 8))
            )

    session_lookup: dict[str, object] = {}
    if getattr(summary, "session_stats", None):
        session_lookup = {str(item.flow_id): item for item in summary.session_stats}

    if getattr(summary, "session_stats", None):
        suspicious_sessions = [
            item
            for item in summary.session_stats
            if getattr(item, "suspicious_packets", 0)
        ]
        if suspicious_sessions:
            lines.append(header("Suspicious Sessions"))
            rows = [
                [
                    "Session",
                    "Hits(H/B/X)",
                    "Packets",
                    "Payload",
                    "Susp Bytes",
                    "Timerange",
                    "Duration",
                ]
            ]
            for item in suspicious_sessions[: _limit_value(8)]:
                timerange = f"{format_ts(getattr(item, 'first_seen', None))} -> {format_ts(getattr(item, 'last_seen', None))}"
                rows.append(
                    [
                        getattr(item, "flow_id", "-"),
                        f"{getattr(item, 'high_entropy_hits', 0)}/{getattr(item, 'base64_hits', 0)}/{getattr(item, 'hex_hits', 0)}",
                        str(getattr(item, "packets", 0)),
                        str(getattr(item, "payload_bytes", 0)),
                        str(getattr(item, "suspicious_payload_bytes", 0)),
                        timerange,
                        format_duration(getattr(item, "duration_seconds", None)),
                    ]
                )
            lines.append(_format_table(rows))

    if summary.high_entropy_hits:
        lines.append(header("High-Entropy Samples"))
        rows = [
            [
                "Time",
                "Session",
                "Len",
                "Entropy",
                "Print",
                "Timerange",
                "Session Stats",
                "Traffic",
                "Reasoning",
            ]
        ]
        for hit in summary.high_entropy_hits[: _limit_value(8)]:
            session = session_lookup.get(str(getattr(hit, "flow_id", "")))
            timerange = "-"
            session_stats = "-"
            traffic = "-"
            if session is not None:
                timerange = f"{format_ts(getattr(session, 'first_seen', None))} -> {format_ts(getattr(session, 'last_seen', None))}"
                session_stats = (
                    f"pkts={getattr(session, 'packets', 0)} "
                    f"susp={getattr(session, 'suspicious_packets', 0)} "
                    f"hits={getattr(session, 'high_entropy_hits', 0)}/{getattr(session, 'base64_hits', 0)}/{getattr(session, 'hex_hits', 0)}"
                )
                payload_bytes = int(getattr(session, "payload_bytes", 0) or 0)
                suspicious_bytes = int(
                    getattr(session, "suspicious_payload_bytes", 0) or 0
                )
                if payload_bytes > 0:
                    traffic = f"{suspicious_bytes}/{payload_bytes} ({(suspicious_bytes / payload_bytes) * 100.0:.1f}%)"
                else:
                    traffic = f"{suspicious_bytes}/0"
            rows.append(
                [
                    format_ts(getattr(hit, "ts", None)),
                    getattr(
                        hit,
                        "flow_id",
                        f"{hit.src}:{hit.src_port}->{hit.dst}:{hit.dst_port}",
                    ),
                    str(hit.length),
                    f"{hit.entropy:.2f}",
                    f"{getattr(hit, 'printable_ratio', 0.0):.2f}",
                    timerange,
                    session_stats,
                    traffic,
                    _truncate_text(getattr(hit, "reasoning", "-"), 96),
                ]
            )
        lines.append(_format_table(rows))
        lines.append(muted("Evidence:"))
        for hit in summary.high_entropy_hits[: _limit_value(6)]:
            lines.append(
                muted(
                    f"pkt={getattr(hit, 'packet_index', '-')} "
                    f"time={format_ts(getattr(hit, 'ts', None))} "
                    f"session={getattr(hit, 'flow_id', '-')} "
                    f"sample={_truncate_text(getattr(hit, 'sample', '-'), 96)}"
                )
            )

    if getattr(summary, "artifacts", None):
        if summary.artifacts:
            lines.append(header("Recovered Artifacts"))
            rows = [
                [
                    "Type",
                    "Value",
                    "Source",
                    "Session",
                    "Time",
                    "Confidence",
                    "Reasoning",
                ]
            ]
            for item in summary.artifacts[: _limit_value(12)]:
                rows.append(
                    [
                        getattr(item, "kind", "-"),
                        _truncate_text(str(getattr(item, "value", "-")), 56),
                        getattr(item, "source_kind", "-"),
                        _truncate_text(getattr(item, "flow_id", "-"), 44),
                        format_ts(getattr(item, "ts", None)),
                        getattr(item, "confidence", "-"),
                        _truncate_text(getattr(item, "reasoning", "-"), 84),
                    ]
                )
            lines.append(_format_table(rows))

    if summary.base64_hits:
        lines.append(header("Base64 Samples"))
        for hit in summary.base64_hits[: _limit_value(4)]:
            lines.append(
                muted(
                    f"{format_ts(getattr(hit, 'ts', None))} "
                    f"{hit.src}:{hit.src_port} -> {hit.dst}:{hit.dst_port} "
                    f"len={hit.length} entropy={hit.entropy:.2f} "
                    f"reason={_truncate_text(getattr(hit, 'reasoning', '-'), 72)} "
                    f"sample={_truncate_text(getattr(hit, 'sample', '-'), 72)}"
                )
            )
    if summary.hex_hits:
        lines.append(header("Hex Samples"))
        for hit in summary.hex_hits[: _limit_value(4)]:
            lines.append(
                muted(
                    f"{format_ts(getattr(hit, 'ts', None))} "
                    f"{hit.src}:{hit.src_port} -> {hit.dst}:{hit.dst_port} "
                    f"len={hit.length} entropy={hit.entropy:.2f} "
                    f"reason={_truncate_text(getattr(hit, 'reasoning', '-'), 72)} "
                    f"sample={_truncate_text(getattr(hit, 'sample', '-'), 72)}"
                )
            )
    return _finalize_output(lines)
