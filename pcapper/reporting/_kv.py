"""Shared pieces of the compact protocol reports (GOOSE, Sampled Values,
IEC 101/103, PTP, LLDP/DCP, C37.118 ...): findings from detection dicts and
anomalies, counter lines and capture windows."""

from __future__ import annotations

from typing import Callable, Iterable, Optional, Sequence

from . import _style as st
from ._common import _filtered_detections, _ot_attack_for_title


def findings_for(summary: object, *, ot: bool = True) -> list[st.Finding]:
    """Detections as findings (informational ones only with -v) plus any
    anomaly objects, with the OT ATT&CK technique where the analyzer did not
    name one."""
    attack = _ot_attack_for_title if ot else None
    items = [st.finding(d, attack) for d in _filtered_detections(summary, st.verbose())]
    items += [st.finding(a, attack) for a in (getattr(summary, "anomalies", None) or [])]
    return items


def counter_line(label_text: str, counter: object, n: int = 5) -> tuple[str, str]:
    return (label_text, st.top(counter, n) if counter else "")


def int_range(values: Iterable[object]) -> str:
    nums = [v for v in values if isinstance(v, int)]
    return f"{len(nums)} distinct, {min(nums)}..{max(nums)}" if nums else ""


def window(summary: object) -> str:
    first, last = getattr(summary, "first_seen", None), getattr(summary, "last_seen", None)
    return st.ts_range(first, last) if first else ""


def sessions(
    conversations: Iterable[object],
    *,
    value_label: str = "Packets",
    value_fn: Callable[[object], object] | None = None,
    extra_cols: Sequence[tuple[str, Callable[[object], object]]] = (),
    max_rows: Optional[int] = st.DEFAULT_ROWS,
) -> list[str]:
    """Client -> server sessions, largest first (bytes, then packets): start,
    end, duration, a count column and protocol-specific extras."""
    from ._common import _conv_value
    from ..utils import format_bytes_as_mb, safe_float

    def val(conv: object, *names: str) -> object:
        for name in names:
            value = _conv_value(conv, name)
            if value not in (None, ""):
                return value
        return None

    def sort_key(conv: object) -> tuple[float, float]:
        try:
            return float(val(conv, "bytes") or 0), float(val(conv, "packets") or 0)
        except (TypeError, ValueError):
            return 0.0, 0.0

    rows = []
    for conv in sorted(conversations, key=sort_key, reverse=True):
        c_ip, s_ip = val(conv, "client_ip", "src_ip", "src") or "-", val(conv, "server_ip", "dst_ip", "dst") or "-"
        c_port, s_port = val(conv, "client_port", "src_port"), val(conv, "server_port", "dst_port")
        first, last = safe_float(val(conv, "first_seen")), safe_float(val(conv, "last_seen"))
        dur = max(0.0, last - first) if first is not None and last is not None else None
        value = value_fn(conv) if value_fn else (val(conv, "packets") or val(conv, "requests") or 0)
        rows.append([
            f"{c_ip}:{c_port}" if c_port is not None else str(c_ip),
            f"{s_ip}:{s_port}" if s_port is not None else str(s_ip),
            st.ts(first), st.ts(last), st.duration(dur) if dur is not None else "-",
            st.count(value), format_bytes_as_mb(int(val(conv, "bytes") or 0)),
        ] + [str(fn(conv)) for _, fn in extra_cols])
    return st.table(
        ["Client", "Server", "Start", "End", "Duration", value_label, "Size"] + [label for label, _ in extra_cols],
        rows, align="lllllrr" + "l" * len(extra_cols), max_rows=max_rows, noun="session",
    )


def simple_report(
    name: str,
    summary: object,
    *,
    packets: int,
    unit: str,
    clients: object = None,
    servers: object = None,
    facts_title: str = "Activity",
    facts: Sequence[tuple[str, object]] = (),
    details: Sequence[tuple[str, object]] = (),
    high: str = "high-severity activity to investigate",
    medium: str = "activity to review",
    absent: Optional[str] = None,
    ot: bool = False,
) -> str:
    """The report for a protocol summarised by counters: headline (findings,
    packet count, window, roles), errors, findings, a facts block, and -v
    details. Used by the small analyzers (NTP, QUIC, HTTP/2, encrypted DNS ...)."""
    rep = st.Report(name, getattr(summary, "path", "") or "")
    findings = findings_for(summary, ot=ot)
    errors = list(getattr(summary, "errors", None) or [])
    if not packets and not st.material(findings):
        return rep.absent(absent or f"{name} traffic", errors)
    severity, text = st.verdict(findings, high=high, medium=medium)
    dur = getattr(summary, "duration_seconds", None)
    rep.headline(severity, text, st.join([
        f"{st.count(packets)} {unit}", st.duration(dur) if dur else "", window(summary),
    ]))
    if clients is not None or servers is not None:
        rep.scope(f"{st.plural(len(clients or {}), 'client')} -> {st.plural(len(servers or {}), 'server')}")
    if errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in errors])
    rep.section("Findings", st.findings_block(findings))
    rep.section(facts_title, st.kv(list(facts)))
    total = getattr(summary, "total_packets", None)
    rep.section("Details", st.kv(list(details) + ([("Total packets", st.count(total))] if total is not None else [])),
                detail=True)
    return rep.render()
