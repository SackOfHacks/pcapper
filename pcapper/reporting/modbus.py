"""Rendered output for modbus analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
import re
from collections import Counter, defaultdict
from typing import TYPE_CHECKING, Iterable
from ..utils import (
    format_bytes_as_mb,
    format_speed_bps,
    sparkline,
)
if TYPE_CHECKING:
    from ..modbus import ModbusAnalysis

from . import _style as st
from ._common import (
    _ot_attack_for_title,
)


def _identity_text(value: str) -> str:
    return value


_SIZE_BUCKETS = ["<=64", "65-128", "129-256", "257-512", "513-1024", "1025-1500", "1501-9000", ">9000"]
_DURATION_BUCKETS = ["<=1s", "1-10s", "10-60s", "1-5m", "5-30m", ">30m"]
_TARGET_RE = re.compile(r"[a-z_]+\[[^\]]*\]")
_VALUES_RE = re.compile(r"values=(\[[^\]]*\])")
_WRITE_TARGET_RE = re.compile(r"^(?P<func>.*?)\s+(?P<target>[a-z_]+\[[^\]]*\])\s*(?P<rest>.*)$")


def _function_class(name: str) -> str:
    lowered = name.lower()
    if "write" in lowered:
        return "write"
    if any(token in lowered for token in ("diagnostic", "encapsulated", "report server", "file")):
        return "diagnostic"
    if "read" in lowered:
        return "read"
    return "other"


def _modbus_headline(rep: "st.Report", summary: "ModbusAnalysis", findings: list) -> None:
    masters = list(getattr(summary, "masters", []) or [])
    servers = list(getattr(summary, "dst_ips", {}) or {})
    units = sorted(getattr(summary, "unit_ids", {}) or {})
    reads = sum(cnt for name, cnt in summary.func_counts.items() if "read" in name.lower())
    writes = int(getattr(summary, "write_count", 0))
    excs = int(getattr(summary, "exception_count", 0))
    severity, text = st.verdict(
        findings,
        high=("destructive or broadcast control activity: treat as active process manipulation"
              if st.worst(findings) >= 4 else
              "state-changing commands: confirm an authorized master and change window"),
        medium="activity outside a read-only polling baseline",
        clean="read-only polling baseline: no writes, exceptions or anomalies",
    )
    unit_text = ", ".join(str(u) for u in units[:8]) + (f" +{len(units) - 8}" if len(units) > 8 else "")
    rep.headline(
        severity,
        text,
        st.join([
            f"{st.count(summary.modbus_packets)} Modbus packets",
            st.size(summary.modbus_bytes),
            st.duration(summary.duration),
        ]),
    )
    rep.scope(st.join([
        f"{st.plural(len(masters), 'master')} -> {st.plural(len(servers), 'server')}",
        f"unit {unit_text}" if len(units) == 1 else (f"units {unit_text}" if units else ""),
        f"{st.count(reads)} reads / {st.count(writes)} writes / {st.count(excs)} exceptions",
    ]))
    if len(masters) > 1:
        rep.note("NOTE", st.plural(len(masters), "master") + " present: validate any that is not a known SCADA/HMI/EWS")


def _write_targets(summary: "ModbusAnalysis") -> list[str]:
    """Each write stream (function, unit, master, server): how often, when,
    what target and the last values written."""
    distinct: Counter[tuple[str, str, str, str]] = Counter()
    for art in summary.artifacts:
        if str(getattr(art, "kind", "")) != "write":
            continue
        m = _WRITE_TARGET_RE.match(str(getattr(art, "detail", "")))
        func, target = (m.group("func"), m.group("target")) if m else (str(art.detail), "")
        distinct[(str(art.src), str(art.dst), func, target)] += 1
    records = list(getattr(summary, "write_targets", []) or [])
    if not records:  # a summary without write_targets: one line per artifact group
        records = [
            {"func": func, "unit": "", "src": src, "dst": dst, "count": 0, "first": None, "last": None,
             "detail": target, "distinct": n}
            for (src, dst, func, target), n in distinct.most_common()
        ]
    shown = records if st.verbose() else records[: st.DEFAULT_ROWS]
    lines: list[str] = []
    for rec in shown:
        detail = str(rec.get("detail") or "")
        tm = _TARGET_RE.search(detail)
        target = tm.group(0) if tm else ""
        vm = _VALUES_RE.search(detail)
        values = vm.group(1) if vm else ""
        func = str(rec.get("func", ""))
        n_distinct = rec.get("distinct") or distinct.get((str(rec.get("src")), str(rec.get("dst")), func, target), 0)
        unit = rec.get("unit")
        lines.append("  " + st.join([
            st.flow(rec.get("src"), rec.get("dst")),
            f"unit {unit}" if unit not in (None, "") else "",
            st.bad(func),
            target,
        ], "  "))
        lines.append(st.INDENT + st.dim(st.join([
            st.plural(int(rec.get("count") or 0), "write") if rec.get("count") else "",
            st.plural(int(n_distinct), "distinct value set") if n_distinct else "",
            st.ts_range(rec.get("first"), rec.get("last")) if rec.get("first") else "",
            f"last {st.cut(values, 48)}" if values else "",
        ])))
    if len(records) > len(shown):
        lines.append(st.more(len(records) - len(shown), "write stream"))
    return lines


def _write_log(summary: "ModbusAnalysis") -> list[str]:
    writes = sorted(
        (a for a in summary.artifacts if str(getattr(a, "kind", "")) == "write"),
        key=lambda a: float(getattr(a, "ts", 0.0) or 0.0),
    )
    return st.table(
        ["Time", "Flow", "Write"],
        [[st.ts(a.ts), st.flow(a.src, a.dst), a.detail] for a in writes],
        max_rows=None,
    )


def _artifact_table(summary: "ModbusAnalysis", kind: str, label_text: str) -> list[str]:
    hits = [a for a in summary.artifacts if str(getattr(a, "kind", "")) == kind]
    if not hits:
        return []
    counts = Counter(str(getattr(a, "detail", "")) for a in hits)
    endpoints: dict[str, Counter[str]] = defaultdict(Counter)
    for a in hits:
        endpoints[str(getattr(a, "detail", ""))][st.flow(a.src, a.dst)] += 1
    rows = []
    for detail, cnt in counts.most_common():
        rows.append([detail, st.count(cnt), st.top(endpoints[detail], 2)])
    return st.table([label_text, "Seen", "Endpoints"], rows, align="lr", widths=(70,))


def render_modbus_summary(summary: "ModbusAnalysis", verbose: bool = False) -> str:
    """Render Modbus analysis results."""
    if not summary:
        return ""
    findings = [st.finding(a, _ot_attack_for_title) for a in summary.anomalies]
    rep = st.Report("Modbus", summary.path)
    if not summary.modbus_packets and not st.material(findings):
        return rep.absent("Modbus traffic", summary.errors)
    _modbus_headline(rep, summary, findings)

    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {err}" for err in summary.errors])

    rep.section("Findings", st.findings_block(findings))
    rep.section("Writes", _write_targets(summary))

    if getattr(summary, "value_changes", None):
        rep.section("Value changes", st.table(
            ["Time", "Target", "Old", "New", "From"],
            [[st.ts(c.get("ts")), c.get("target", ""), c.get("old", ""), c.get("new", ""), c.get("src", "")]
             for c in summary.value_changes],
            align="llrrl",
        ))

    if summary.func_counts:
        rows = []
        for func, cnt in summary.func_counts.most_common():
            klass = _function_class(func)
            style = st.bad if klass == "write" else (st.caution if klass == "diagnostic" else _identity_text)
            rows.append([style(func), st.count(cnt), klass])
        rep.section("Commands", st.table(["Function", "Count", "Class"], rows, align="lrl", max_rows=None))

    if summary.messages:
        exceptions = Counter(f"{m.exception_desc or 'Exception'}" for m in summary.messages if m.is_exception)
        if exceptions:
            rep.section("Exceptions", st.table(
                ["Exception", "Count"], [[k, st.count(v)] for k, v in exceptions.most_common()], align="lr",
                max_rows=st.TOP_ROWS, tail=st.TOP_ROWS
            ))

    units_by_server: dict[str, set] = defaultdict(set)
    for rec in (getattr(summary, "register_map", {}) or {}).values():
        units_by_server[str(rec.get("dst", ""))].add(rec.get("unit"))
    # Packets/bytes: everything to and from the address. With -v also what it
    # sent in its role (requests for a master, responses for a server).
    endpoint_rows = []
    roles = [("master", ip, cnt, summary.client_bytes.get(ip, 0)) for ip, cnt in summary.src_ips.most_common()]
    roles += [("server", ip, cnt, summary.server_bytes.get(ip, 0)) for ip, cnt in summary.dst_ips.most_common()]
    for role, ip, sent, sent_bytes in roles:
        units = ", ".join(str(u) for u in sorted(units_by_server.get(ip, ()))) if role == "server" else ""
        row = [role, ip, st.count(summary.endpoint_packets.get(ip, 0)), st.size(summary.endpoint_bytes.get(ip, 0)), units]
        if st.verbose():
            row[4:4] = [st.count(sent), st.size(sent_bytes)]
        endpoint_rows.append(row)
    header_row = ["Role", "Address", "Packets", "Bytes", "Units"]
    if st.verbose():
        header_row[4:4] = ["Sent", "Sent bytes"]
    rep.section("Endpoints", st.table(header_row, endpoint_rows, align="llrr" + ("rr" if st.verbose() else "") + "l"))

    devices = _artifact_table(summary, "device", "Device")
    equipment = _artifact_table(summary, "equipment", "Equipment")
    rep.section("Devices", devices + ([""] if devices and equipment else []) + equipment)

    # ---- reference material (-v) ----------------------------------------
    total_packets, total_bytes = summary.total_packets, summary.total_bytes
    pkt_ratio = summary.modbus_packets / total_packets if total_packets else 0.0
    byte_ratio = summary.modbus_bytes / total_bytes if total_bytes else 0.0
    avg_pkt = summary.modbus_bytes / summary.modbus_packets if summary.modbus_packets else 0.0
    avg_payload = summary.modbus_payload_bytes / summary.modbus_packets if summary.modbus_packets else 0.0
    traffic = [
        ("Duration", f"{summary.duration:.2f}s"),
        ("Packets", f"{total_packets} total · {summary.modbus_packets} Modbus ({pkt_ratio:.1%})"),
        ("Bytes", f"{format_bytes_as_mb(total_bytes)} total · {format_bytes_as_mb(summary.modbus_bytes)} Modbus ({byte_ratio:.1%})"),
        ("Payload", f"{format_bytes_as_mb(summary.modbus_payload_bytes)} · avg {avg_payload:.1f} bytes"),
        ("Avg packet", f"{avg_pkt:.1f} bytes"),
    ]
    if summary.duration:
        traffic.append(("Rate", f"{total_packets / summary.duration:.2f} pkt/s · {format_speed_bps(int(total_bytes / summary.duration * 8))}"))
    traffic += [
        ("Clients", str(summary.unique_clients)),
        ("Servers", str(summary.unique_servers)),
        ("Error rate", f"{summary.error_rate:.2f}%"),
    ]
    rep.section("Traffic", st.kv(traffic), detail=True)

    register_map = getattr(summary, "register_map", {}) or {}
    if register_map:
        rows = []
        for rec in sorted(register_map.values(), key=lambda r: -(int(r.get("read_count", 0)) + int(r.get("write_count", 0)))):
            rmin, rmax = rec.get("read_min"), rec.get("read_max")
            wmin, wmax = rec.get("write_min"), rec.get("write_max")
            hot_src = rec.get("write_hot") or rec.get("read_hot") or []
            wcount = int(rec.get("write_count", 0))
            rows.append([
                f"{rec.get('dst', '?')} U{rec.get('unit', '?')}",
                st.count(rec.get("read_count", 0)),
                f"{rmin}-{rmax}" if rmin is not None else "-",
                st.bad(str(wcount)) if wcount else "0",
                f"{wmin}-{wmax}" if wmin is not None else "-",
                ", ".join(f"{a}:{c}" for a, c in hot_src[:3]) or "-",
            ])
        rep.section("Register map", st.table(
            ["Server/unit", "Reads", "Read range", "Writes", "Write range", "Hot addr:count"], rows,
            align="lrlrll", max_rows=None,
        ), detail=True)

    cadence = [c for c in (getattr(summary, "session_cadence", []) or [])
               if str(c.get("session", "")).split(" -> ", 1)[-1].endswith(":502")]
    rep.section("Polling cadence", st.table(
        ["Session", "Requests", "Avg s", "Median s", "Regular"],
        [[c.get("session", ""), st.count(c.get("count", 0)), f"{float(c.get('avg', 0.0)):.3f}",
          f"{float(c.get('median', 0.0)):.3f}", "yes" if c.get("regular") else "no"] for c in cadence],
        align="lrrrl", max_rows=None,
    ), detail=True)

    rtt = getattr(summary, "rtt_by_server", {}) or {}
    rep.section("Response times", st.table(
        ["Server", "Min ms", "p50 ms", "p95 ms", "Max ms"],
        [[ip, st.stat(v, "min"), st.stat(v, "p50"), st.stat(v, "p95"), st.stat(v, "max")]
         for ip, v in sorted(rtt.items(), key=lambda kv: (-kv[1].get("p95", 0), kv[0]))],
        align="lrrrr", max_rows=None,
    ), detail=True)

    pairing = getattr(summary, "pairing", {}) or {}
    if pairing:
        def _flag(value: object) -> str:
            n = int(value or 0)
            return st.bad(str(n)) if n else "0"
        rep.section("Transaction pairing", st.kv([
            ("Matched req/resp", st.count(pairing.get("matched", 0))),
            ("Orphan requests", _flag(pairing.get("orphan_requests", 0))),
            ("Unsolicited responses", _flag(pairing.get("phantom_responses", 0))),
            ("Static transaction-id connections", _flag(pairing.get("static_transid_conns", 0))),
        ]) + [st.dim("  Normal near the capture edges; a sustained imbalance suggests DoS or injection.")], detail=True)

    if summary.service_endpoints:
        totals = Counter({name: sum(c.values()) for name, c in summary.service_endpoints.items()})
        rep.section("Function endpoints", st.table(
            ["Function", "Requests", "Endpoints"],
            [[name, st.count(total), st.top(summary.service_endpoints.get(name, Counter()), 3)]
             for name, total in totals.most_common()],
            align="lrl", max_rows=None,
        ), detail=True)

    size_pairs: list[tuple[str, str]] = []
    for label_text, hist, stats in (
        ("Packet", summary.packet_size_hist, summary.packet_size_stats),
        ("Payload", summary.payload_size_hist, summary.payload_size_stats),
    ):
        if hist:
            series = [hist.get(b, 0) for b in _SIZE_BUCKETS]
            size_pairs.append((f"{label_text} sizes",
                               f"{sparkline(series)}  " + ", ".join(f"{b}:{hist.get(b, 0)}" for b in _SIZE_BUCKETS)))
            if stats:
                size_pairs.append((f"{label_text} stats",
                                   f"min {st.stat(stats, 'min')} / p50 {st.stat(stats, 'p50')} / "
                                   f"p95 {st.stat(stats, 'p95')} / max {st.stat(stats, 'max')}"))
    rep.section("Sizes", st.kv(size_pairs), detail=True)

    durations: list[tuple[str, str]] = []
    for key, label_text in (("all", "All flows"), ("requests", "Request flows"), ("responses", "Response flows")):
        buckets = (summary.flow_duration_buckets or {}).get(key, Counter())
        if buckets:
            durations.append((label_text, ", ".join(f"{b}:{int(buckets.get(b, 0))}" for b in _DURATION_BUCKETS)))
    rep.section("Flow durations", st.kv(durations), detail=True)

    rep.section("Write log", _write_log(summary), detail=True)
    return rep.render()


def merge_modbus_rollup(summaries: Iterable["ModbusAnalysis"]) -> "ModbusAnalysis | None":
    """Modbus across several captures (-summarize): the per-capture data merged
    into one summary and rendered exactly like a single capture."""
    from dataclasses import replace
    from pathlib import Path

    from ..rollup import earliest_per_key, merge_sample_stats, merge_stats_by_key

    from ..rollup import merge_records

    summary_list = [s for s in summaries if s]
    if not summary_list:
        return None

    def _merged_counter(name: str) -> Counter:
        total: Counter = Counter()
        for item in summary_list:
            total.update(getattr(item, name, None) or {})
        return total

    service_endpoints: dict[str, Counter[str]] = defaultdict(Counter)
    flow_duration_buckets: dict[str, Counter[str]] = defaultdict(Counter)
    register_map: dict[str, dict[str, object]] = {}
    pairing: Counter = Counter()
    errors: list[str] = []
    for item in summary_list:
        for name, counter in (item.service_endpoints or {}).items():
            service_endpoints[name].update(counter)
        for key, counter in (item.flow_duration_buckets or {}).items():
            flow_duration_buckets[key].update(counter)
        for key, rec in (getattr(item, "register_map", {}) or {}).items():
            register_map[key] = _merge_register_record(register_map.get(key), rec)
        pairing.update(getattr(item, "pairing", {}) or {})
        errors += [e for e in item.errors if e not in errors]

    first = summary_list[0]
    merged = replace(
        first,
        path=Path(f"ALL_PCAPS_{len(summary_list)}"),
        duration=sum(s.duration for s in summary_list),
        total_packets=sum(s.total_packets for s in summary_list),
        modbus_packets=sum(s.modbus_packets for s in summary_list),
        total_bytes=sum(s.total_bytes for s in summary_list),
        modbus_bytes=sum(s.modbus_bytes for s in summary_list),
        modbus_payload_bytes=sum(s.modbus_payload_bytes for s in summary_list),
        func_counts=_merged_counter("func_counts"),
        request_func_counts=_merged_counter("request_func_counts"),
        unit_ids=_merged_counter("unit_ids"),
        src_ips=_merged_counter("src_ips"),
        dst_ips=_merged_counter("dst_ips"),
        client_bytes=_merged_counter("client_bytes"),
        server_bytes=_merged_counter("server_bytes"),
        endpoint_packets=_merged_counter("endpoint_packets"),
        endpoint_bytes=_merged_counter("endpoint_bytes"),
        service_endpoints=dict(service_endpoints),
        packet_size_hist=_merged_counter("packet_size_hist"),
        payload_size_hist=_merged_counter("payload_size_hist"),
        packet_size_stats=merge_sample_stats([s.packet_size_stats for s in summary_list],
                                             [s.modbus_packets for s in summary_list]),
        payload_size_stats=merge_sample_stats([s.payload_size_stats for s in summary_list],
                                              [s.modbus_packets for s in summary_list]),
        flow_duration_buckets=dict(flow_duration_buckets),
        register_map=register_map,
        session_cadence=merge_records([list(s.session_cadence or []) for s in summary_list]),
        rtt_by_server=merge_stats_by_key(s.rtt_by_server for s in summary_list),
        pairing=dict(pairing),
        messages=merge_records([list(s.messages) for s in summary_list]),
        artifacts=merge_records([list(s.artifacts) for s in summary_list]),
        anomalies=merge_records([list(s.anomalies) for s in summary_list]),
        value_changes=merge_records([list(s.value_changes or []) for s in summary_list]),
        write_targets=merge_records([list(getattr(s, "write_targets", None) or []) for s in summary_list]),
        errors=errors,
        first_seen=earliest_per_key(s.first_seen for s in summary_list),
        register_ranges=_merge_register_ranges(summary_list),
    )
    from ..rollup import merge_window

    merge_window(merged, summary_list)
    return merged


def _merge_register_record(current: dict | None, rec: dict) -> dict:
    """One server/unit's register activity in two captures as one row: reads
    and writes added, ranges widened, hot addresses added up. A distinct
    address count is at least each capture's and the hot addresses seen."""
    if current is None:
        return dict(rec)
    out = dict(current)
    for name in ("read_count", "write_count"):
        out[name] = int(current.get(name, 0) or 0) + int(rec.get(name, 0) or 0)
    for name, pick in (("read_min", min), ("write_min", min), ("read_max", max), ("write_max", max)):
        values = [v for v in (current.get(name), rec.get(name)) if v is not None]
        out[name] = pick(values) if values else None
    for hot, distinct in (("read_hot", "distinct_read_addrs"), ("write_hot", "distinct_write_addrs")):
        counts: Counter = Counter()
        for entries in (current.get(hot) or [], rec.get(hot) or []):
            for address, count in entries:
                counts[address] += int(count)
        out[hot] = counts.most_common(5)
        out[distinct] = max(int(current.get(distinct, 0) or 0), int(rec.get(distinct, 0) or 0), len(counts))
    return out


def _merge_register_ranges(summary_list: list) -> dict:
    """Register value ranges of several captures: min and max with the
    time each was first seen, sample counts summed."""
    merged: dict = {}
    for item in summary_list:
        for key, entry in (getattr(item, "register_ranges", None) or {}).items():
            low, high, count = entry[0], entry[1], entry[2]
            low_ts = entry[3] if len(entry) > 3 else 0.0
            high_ts = entry[4] if len(entry) > 4 else 0.0
            current = merged.get(key)
            if current is None:
                merged[key] = [low, high, count, low_ts, high_ts]
                continue
            if low < current[0] or (low == current[0] and low_ts and (not current[3] or low_ts < current[3])):
                current[0], current[3] = low, low_ts
            if high > current[1] or (high == current[1] and high_ts and (not current[4] or high_ts < current[4])):
                current[1], current[4] = high, high_ts
            current[2] += count
    return merged


def render_modbus_rollup(summaries: Iterable["ModbusAnalysis"]) -> str:
    """Modbus across several captures (-summarize), rendered like one capture."""
    merged = merge_modbus_rollup(summaries)
    return render_modbus_summary(merged) if merged is not None else ""
