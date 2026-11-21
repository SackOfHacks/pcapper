"""Rendered output for --obfuscation: encoded and high-entropy payloads, the
IOCs recovered by decoding them, and the sessions that carried them.

Base64 and hex blobs are low severity by design (TLS, cookies and images
encode constantly); only recovered IOCs, attack content and covert-channel
signals raise the verdict."""

from __future__ import annotations

from ..utils import format_duration, format_speed_bps, format_ts
from . import _style as st
from ._kv import counter_line, findings_for


def _flow(item: object) -> str:
    flow_id = getattr(item, "flow_id", None)
    if flow_id:
        return str(flow_id)
    return f"{getattr(item, 'src', '?')}:{getattr(item, 'src_port', '?')} -> {getattr(item, 'dst', '?')}:{getattr(item, 'dst_port', '?')}"


def render_obfuscation_summary(summary) -> str:  # type: ignore[no-untyped-def]
    if not summary:
        return ""
    rep = st.Report("Obfuscation", getattr(summary, "path", "") or "")
    findings = findings_for(summary, ot=False)
    severity, text = st.verdict(findings, high="covert channel or encoded attack content: investigate",
                                medium="obfuscated content of interest",
                                low="encoded content present (likely benign encoding)",
                                clean="no obfuscation or tunneling signals")
    payload = int(getattr(summary, "total_payload_bytes", 0) or 0)
    susp_bytes = int(getattr(summary, "suspicious_payload_bytes", 0) or 0)
    rep.headline(severity, text, st.join([
        f"{st.count(summary.total_packets)} packets · {st.size(payload)} payload",
        f"{st.size(susp_bytes)} suspicious ({susp_bytes / payload * 100:.1f}%)" if payload and susp_bytes else "",
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
    ]))
    rep.scope(st.join([
        f"{st.count(getattr(summary, 'suspicious_sessions', 0))} of {st.plural(getattr(summary, 'total_sessions', 0), 'session')} suspicious",
        f"{len(summary.high_entropy_hits)} high-entropy · {len(summary.base64_hits)} base64 · {len(summary.hex_hits)} hex hits",
    ]))
    if getattr(summary, "errors", None):
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    verbose = st.verbose()
    rep.section("Recovered IOCs", st.table(
        ["Type", "Value", "Source", "Session", "Time", "Confidence"] + (["Reasoning"] if verbose else []),
        [[a.kind, a.value, a.source_kind, a.flow_id or "-", st.ts(a.ts), a.confidence] + ([a.reasoning] if verbose else [])
         for a in (getattr(summary, "artifacts", None) or [])],
        widths=(None, 64, None, 48), noun="IOC",
    ))
    rep.section("Signals", st.kv([counter_line("IOCs", getattr(summary, "ioc_counts", None), 8),
                                  counter_line("Attack content", getattr(summary, "attack_counts", None), 8)]))
    stats = [s for s in (getattr(summary, "session_stats", None) or []) if getattr(s, "suspicious_packets", 0)]
    rep.section("Suspicious sessions", st.table(
        ["Session", "Hits H/B/X", "Packets", "Payload", "Suspicious", "Start"] + (["End"] if verbose else []) + ["Duration"]
        + (["Entropy avg/max"] if verbose else []),
        [[s.flow_id, f"{s.high_entropy_hits}/{s.base64_hits}/{s.hex_hits}", st.count(s.packets), st.size(s.payload_bytes),
          st.size(s.suspicious_payload_bytes), st.ts(s.first_seen)] + ([st.ts(s.last_seen)] if verbose else [])
         + [st.duration(s.duration_seconds) if s.duration_seconds is not None else "-"]
         + ([f"{s.avg_entropy:.2f}/{s.max_entropy:.2f}"] if verbose else []) for s in stats],
        align="llrrrll" + ("l" if verbose else "") + ("l" if verbose else ""), max_rows=8, noun="session",
    ))

    sessions = {str(s.flow_id): s for s in (getattr(summary, "session_stats", None) or [])}

    def _session_share(hit: object) -> str:
        s = sessions.get(str(getattr(hit, "flow_id", "")))
        if s is None:
            return "-"
        total, susp = int(s.payload_bytes or 0), int(s.suspicious_payload_bytes or 0)
        return f"{susp}/{total} ({susp / total * 100:.1f}%)" if total else f"{susp}/0"

    rep.section("High-entropy payloads", st.table(
        ["Time", "Session", "Len", "Entropy", "Printable", "Reasoning"] + (["Packet", "Session share", "Sample"] if verbose else []),
        [[st.ts(h.ts), _flow(h), h.length, f"{h.entropy:.2f}", f"{h.printable_ratio:.2f}", h.reasoning or "-"]
         + ([h.packet_index, _session_share(h), h.sample] if verbose else []) for h in summary.high_entropy_hits],
        align="llrrrl", widths=(None, 48, None, None, None, 60), max_rows=5, noun="payload",
    ))

    def _samples(hits: list) -> list[str]:
        return st.table(
            ["Time", "Flow", "Len", "Entropy", "Reasoning", "Sample"],
            [[st.ts(h.ts), f"{h.src}:{h.src_port} -> {h.dst}:{h.dst_port}", h.length, f"{h.entropy:.2f}", h.reasoning or "-",
              h.sample] for h in hits],
            align="llrrll", max_rows=None, noun="sample",
        )

    rep.section("Base64 samples", _samples(summary.base64_hits), detail=True)
    rep.section("Hex samples", _samples(summary.hex_hits), detail=True)
    rep.section("Counters", st.kv([
        counter_line("Hit kinds", getattr(summary, "hit_kind_counts", None), None),
        counter_line("Sources", summary.source_counts, None),
        counter_line("Destinations", summary.destination_counts, None),
        counter_line("Protocols", getattr(summary, "protocol_counts", None), None),
        counter_line("Ports", getattr(summary, "port_counts", None), None),
    ]), detail=True)
    dur = summary.duration_seconds
    rep.section("Traffic", st.kv([
        ("Packets", str(summary.total_packets)),
        ("Payload bytes", str(payload)),
        ("Suspicious packets", str(getattr(summary, "suspicious_packets", 0))),
        ("Suspicious bytes", f"{susp_bytes}" + (f" ({susp_bytes / payload * 100:.1f}%)" if payload else "")),
        ("Start / end", f"{format_ts(summary.first_seen)} / {format_ts(summary.last_seen)}"),
        ("Duration", format_duration(dur)),
        ("Throughput", format_speed_bps(int(payload * 8 / dur)) if isinstance(dur, (int, float)) and dur > 0 and payload else ""),
        ("Suspicious throughput",
         format_speed_bps(int(susp_bytes * 8 / dur)) if isinstance(dur, (int, float)) and dur > 0 and susp_bytes else ""),
        ("Sessions (suspicious/total)", f"{getattr(summary, 'suspicious_sessions', 0)}/{getattr(summary, 'total_sessions', 0)}"),
    ]), detail=True)
    return rep.render()
