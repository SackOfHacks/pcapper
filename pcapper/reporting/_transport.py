"""The shared report for the TCP and UDP transport analyses.

Default view: findings, then the analyzer's hunting profiles that point at
an actor (recon, lateral movement, egress outliers, cadence, amplification,
tunneling, OT boundary crossings, corroborated hosts), the top conversations,
destination ports and services. Health profiles (session integrity,
teardown, reliability), size distributions, endpoint roles, HTTP-over-the-
transport counters and the analyzer's own assessment are -v detail.
"""

from __future__ import annotations

from collections import Counter
from typing import Callable, Optional, Sequence

from ..utils import format_duration
from . import _style as st
from ._common import _render_deterministic_checks
from ._kv import counter_line, findings_for

# (title, summary field, [(header, key, formatter)], default view?)
Column = tuple[str, str, Optional[Callable[[object], object]]]
Profile = tuple[str, str, Sequence[Column], bool]

_BUCKETS = ["<=64", "65-128", "129-256", "257-512", "513-1024", "1025-1500", "1501-9000", ">9000"]


def _size(value: object) -> str:
    try:
        return st.size(int(value or 0))
    except (TypeError, ValueError):
        return str(value)


SIZE = _size


def _profiles(rep: st.Report, summary: object, profiles: Sequence[Profile]) -> None:
    for title, field, columns, default in profiles:
        items = [p for p in (getattr(summary, field, None) or []) if isinstance(p, dict)]
        rows = []
        for item in items:
            row = []
            for _header, key, fmt in columns:
                value = item.get(key, "-")
                if isinstance(value, (list, tuple, set)):
                    value = ", ".join(str(v) for v in value) or "-"
                row.append(fmt(value) if fmt else value)
            rows.append(row)
        rep.section(title, st.table([c[0] for c in columns], rows, max_rows=8, noun="row"), detail=not default)


def _orient(c: object, flags: bool) -> tuple[str, int, str, int]:
    """(client, client port, server, server port) for one direction of a
    conversation: the SYN sender is the client and the SYN-ACK sender the
    server; otherwise the side on a well-known (or the lower) port serves."""
    from ..services import COMMON_PORTS

    src, sport, dst, dport = c.src_ip, int(c.src_port), c.dst_ip, int(c.dst_port)
    if flags:
        if int(getattr(c, "syn_ack", 0) or 0) and not int(getattr(c, "syn", 0) or 0):
            return dst, dport, src, sport
        if int(getattr(c, "syn", 0) or 0):
            return src, sport, dst, dport
    src_known, dst_known = sport in COMMON_PORTS, dport in COMMON_PORTS
    if src_known != dst_known:
        return (dst, dport, src, sport) if src_known else (src, sport, dst, dport)
    return (dst, dport, src, sport) if sport < dport else (src, sport, dst, dport)


def _grouped(conversations: Sequence[object], flags: bool) -> list[dict]:
    """Both directions of each conversation merged and grouped by (client,
    server, server port): flows (client ports), packets, bytes, TCP flags
    and the window."""
    groups: dict[tuple, dict] = {}
    for c in conversations:
        client, cport, server, sport = _orient(c, flags)
        key = (client, server, sport)
        g = groups.setdefault(key, {"src": client, "dst": server, "port": sport, "packets": 0, "bytes": 0,
                                    "syn": 0, "syn_ack": 0, "rst": 0, "fin": 0, "sports": set(), "first": None, "last": None})
        g["packets"] += int(c.packets)
        g["bytes"] += int(c.bytes)
        if flags:
            for f in ("syn", "syn_ack", "rst", "fin"):
                g[f] += int(getattr(c, f, 0) or 0)
        g["sports"].add(cport)
        if c.first_seen is not None:
            g["first"] = c.first_seen if g["first"] is None else min(g["first"], c.first_seen)
        if c.last_seen is not None:
            g["last"] = c.last_seen if g["last"] is None else max(g["last"], c.last_seen)
    return sorted(groups.values(), key=lambda g: (-g["bytes"], -g["packets"], g["src"], g["dst"], g["port"]))


def _service(port: int, services: dict[int, str]) -> str:
    name = services.get(port)
    return f"{port} ({name})" if name else str(port)


def transport_report(
    name: str,
    summary: object,
    *,
    packets: int,
    total_bytes: int,
    payload_bytes: int,
    profiles: Sequence[Profile],
    flags: bool,
    deterministic: tuple[str, list[tuple[str, str]]],
    counters: Sequence[tuple[str, object]] = (),
) -> str:
    from ..services import COMMON_PORTS

    rep = st.Report(name, getattr(summary, "path", "") or "")
    findings = findings_for(summary, ot=False)
    if not packets and not st.material(findings):
        return rep.absent(f"{name} traffic", getattr(summary, "errors", None))
    severity, text = st.verdict(findings, high=f"high-severity {name} activity: investigate", medium=f"{name} activity to review")
    capture_packets = int(getattr(summary, "total_packets", 0) or 0)
    capture_bytes = int(getattr(summary, "total_bytes", 0) or 0)
    dur = getattr(summary, "duration_seconds", None)
    first, last = getattr(summary, "first_seen", None), getattr(summary, "last_seen", None)
    rep.headline(severity, text, st.join([
        f"{st.count(packets)} {name} packets" + (f" ({packets / capture_packets:.0%} of capture)" if capture_packets else ""),
        st.size(total_bytes),
        st.duration(dur) if dur else "",
        st.ts_range(first, last) if first else "",
    ]))
    conversations = list(getattr(summary, "conversations", None) or [])
    rep.scope(st.join([
        f"{st.plural(len(getattr(summary, 'client_counts', {}) or {}), 'client')} -> "
        f"{st.plural(len(getattr(summary, 'server_counts', {}) or {}), 'server')}",
        st.plural(len(conversations), "flow"),
    ]))
    errors = list(getattr(summary, "errors", None) or [])
    if errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in errors])
    rep.section("Findings", st.findings_block(findings))
    _profiles(rep, summary, [p for p in profiles if p[3]])

    groups = _grouped(conversations, flags)
    verbose = st.verbose()

    def _conv_row(g: dict) -> list:
        dur_g = max(0.0, g["last"] - g["first"]) if g["first"] is not None and g["last"] is not None else None
        row = [g["src"], f"{g['dst']}:{g['port']}", st.count(len(g["sports"])), st.count(g["packets"]), st.size(g["bytes"]),
               st.duration(dur_g) if dur_g is not None else "-"]
        if flags:
            row.append(f"{g['syn']}/{g['syn_ack']}/{g['rst']}/{g['fin']}")
        if verbose:
            row += [st.ts(g["first"]), st.ts(g["last"])]
        return row

    rep.section("Top conversations", st.table(
        ["Client", "Server", "Flows", "Packets", "Bytes", "Duration"] + (["SYN/SYN-ACK/RST/FIN"] if flags else [])
        + (["First", "Last"] if verbose else []),
        [_conv_row(g) for g in groups], align="llrrrr" + ("l" if flags else "") + ("ll" if verbose else ""),
        max_rows=st.TOP_ROWS, tail=st.TOP_ROWS, noun="conversation",
    ))
    port_counts = getattr(summary, "port_counts", None) or Counter()
    port_dsts = getattr(summary, "port_destinations", None) or {}
    rep.section("Destination ports", st.table(
        ["Port", "Packets", "Destinations", "Top destinations"],
        [[_service(int(p), COMMON_PORTS), st.count(n), st.count(len(port_dsts.get(p, {}) or {})),
          st.top(port_dsts.get(p, Counter()) or Counter(), 4)] for p, n in port_counts.most_common()],
        align="lrrl", max_rows=st.TOP_ROWS, tail=st.TOP_ROWS, noun="port",
    ))
    # Busiest first, as a capture's and a rollup's are ranked alike.
    services = sorted(
        list(getattr(summary, "services", None) or []),
        key=lambda s: (-int(s.get("count", 0) or 0), str(s.get("endpoint", "")), str(s.get("port", "")),
                       str(s.get("service", ""))),
    )
    rep.section("Services", st.table(
        ["Service", "Endpoint", "Port", "Clients", "Count"],
        [[s.get("service", "-"), s.get("endpoint", "-"), s.get("port", "-"),
          (f"{s.get('client_count')}: " if s.get("client_count") else "") + str(s.get("clients", "-")), s.get("count", "-")]
         for s in services], align="lllll", widths=(None, None, None, 60), max_rows=10, noun="service",
    ))
    files = getattr(summary, "file_artifacts", None)
    rep.section("Files", st.ranked(["File", "Count"], [[f, st.count(n)] for f, n in (files or Counter()).most_common()],
                                   align="lr", noun="file"))

    # ---- reference (-v) --------------------------------------------------
    rep.section("Assessment", st.kv([
        ("Verdict", str(getattr(summary, "analyst_verdict", "") or "")),
        ("Confidence", str(getattr(summary, "analyst_confidence", "") or "")),
    ]) + st.bullets([str(r) for r in (getattr(summary, "analyst_reasons", None) or [])], max_items=None), detail=True)
    _profiles(rep, summary, [p for p in profiles if not p[3]])
    rep.section("False-positive context", st.bullets(
        [str(v) for v in (getattr(summary, "false_positive_context", None) or []) if str(v).strip()], max_items=None), detail=True)
    size_lines: list[tuple[str, str]] = []
    for label_text, hist_name, stats_name in (("Packet sizes", "packet_size_hist", "packet_size_stats"),
                                              ("Payload sizes", "payload_size_hist", "payload_size_stats")):
        hist = getattr(summary, hist_name, None) or {}
        stats = getattr(summary, stats_name, None) or {}
        if hist:
            size_lines.append((label_text, f"{st.sparkline_of([hist.get(b, 0) for b in _BUCKETS])}  {', '.join(_BUCKETS)}"))
            size_lines.append((f"{label_text} (min/p50/p95/max)",
                               f"{st.stat(stats, 'min')} / {st.stat(stats, 'p50')} / {st.stat(stats, 'p95')} / {st.stat(stats, 'max')}"))
    zero = getattr(summary, "zero_payload_packets", 0)
    rep.section("Traffic", st.kv([
        ("Packets", f"{packets} {name} of {capture_packets} ({packets / capture_packets:.1%})" if capture_packets else str(packets)),
        ("Bytes", f"{st.size(total_bytes)} of {st.size(capture_bytes)} ({total_bytes / capture_bytes:.1%})" if capture_bytes else st.size(total_bytes)),
        ("Payload bytes", st.size(payload_bytes)),
        ("Avg packet / payload", f"{total_bytes / packets:.1f} / {payload_bytes / packets:.1f} bytes" if packets else ""),
        ("Rate", f"{packets / dur:.2f} pkt/s · {total_bytes / dur:.2f} B/s" if dur else ""),
        ("Start / end", f"{st.ts(first)} / {st.ts(last)}"),
        ("Duration", format_duration(dur) if dur is not None else ""),
        ("Zero-payload packets", str(zero) if zero else ""),
    ] + size_lines), detail=True)
    client_counts = getattr(summary, "client_counts", None) or Counter()
    server_counts = getattr(summary, "server_counts", None) or Counter()
    # TCP keeps bytes per endpoint; UDP keeps one total per direction.
    client_bytes = getattr(summary, "client_bytes", None)
    server_bytes = getattr(summary, "server_bytes", None)
    client_bytes = client_bytes if isinstance(client_bytes, dict) else Counter()
    server_bytes = server_bytes if isinstance(server_bytes, dict) else Counter()
    endpoint_rows = []
    for ep in set(client_counts) | set(server_counts):
        cp, sp = int(client_counts.get(ep, 0)), int(server_counts.get(ep, 0))
        role = "mostly client" if cp > sp else "mostly server" if sp > cp else "balanced"
        endpoint_rows.append([ep, st.count(cp), st.size(client_bytes.get(ep, 0)), st.count(sp), st.size(server_bytes.get(ep, 0)),
                              st.count(cp + sp), role, cp + sp])
    endpoint_rows.sort(key=lambda r: (-r[-1], str(r[0])))
    endpoint_bytes = getattr(summary, "endpoint_bytes", None)
    endpoint_bytes = endpoint_bytes if isinstance(endpoint_bytes, dict) else Counter()
    rep.section("Endpoints", st.table(
        ["Endpoint", "As client", "Client bytes", "As server", "Server bytes", "Packets", "Role"],
        [r[:-1] for r in endpoint_rows], align="lrrrrrl", max_rows=None,
    ) + st.kv([("Endpoint bytes", st.top(endpoint_bytes, None, fmt=lambda k, v: f"{k} ({st.size(v)})"))]), detail=True)
    rep.section("Flows", st.table(
        ["Source", "Destination", "Packets", "Bytes"] + (["SYN", "SYN-ACK", "RST", "FIN"] if flags else []) + ["First", "Last"],
        [[f"{c.src_ip}:{c.src_port}", f"{c.dst_ip}:{c.dst_port}", st.count(c.packets), st.size(c.bytes)]
         + ([c.syn, c.syn_ack, c.rst, c.fin] if flags else []) + [st.ts(c.first_seen), st.ts(c.last_seen)]
         for c in sorted(conversations, key=lambda c: (c.first_seen or 0.0))],
        align="llrr" + ("rrrr" if flags else "") + "ll", max_rows=None, noun="flow",
    ), detail=True)
    rep.section("Counters", st.kv(list(counters)), detail=True)
    artifacts = [str(a) for a in (getattr(summary, "artifacts", None) or [])]
    rep.section("Artifacts", st.bullets(artifacts, max_items=None), detail=True)

    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, deterministic[0], deterministic[1])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()


def http_counters(summary: object) -> list[tuple[str, str]]:
    return [
        ("HTTP requests / responses", f"{getattr(summary, 'http_requests', 0)} / {getattr(summary, 'http_responses', 0)}"
         if getattr(summary, "http_requests", 0) or getattr(summary, "http_responses", 0) else ""),
        counter_line("HTTP methods", getattr(summary, "http_methods", None), None),
        counter_line("HTTP statuses", getattr(summary, "http_statuses", None), None),
        counter_line("HTTP URLs", getattr(summary, "http_urls", None), None),
        counter_line("HTTP user agents", getattr(summary, "http_user_agents", None), None),
        counter_line("HTTP files", getattr(summary, "http_files", None), None),
    ]
