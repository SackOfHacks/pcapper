"""Rendered output for modbus analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from collections import Counter, defaultdict
from typing import TYPE_CHECKING, Iterable
from ..coloring import (
    danger,
    header,
    highlight,
    muted,
    ok,
    warn,
)
from ..utils import (
    format_bytes_as_mb,
    format_speed_bps,
    sparkline,
)
if TYPE_CHECKING:
    from ..modbus import ModbusAnalysis

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _PROTO_SEV_RANK,
    _counter_table,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
    _normalize_finding,
    _ot_attack_for_title,
    _ot_full_render,
    _truncate_text,
)


def _identity_text(value: str) -> str:
    return value


@_ot_full_render
def _render_modbus_verdict(lines: list[str], summary: "ModbusAnalysis") -> None:
    """Always-on triage disposition for Modbus — unlike the shared
    ``_render_ot_verdict`` (silent on benign captures), this states a verdict on
    every capture, including a benign polling baseline, so a triager never has
    to re-derive "is this normal?" from the raw statistics. Anomalies, when
    present, still drive a Focus-Here-First + ATT&CK-for-ICS block.
    """
    anoms = list(getattr(summary, "anomalies", []) or [])
    norm = [(_normalize_finding(a), a) for a in anoms]
    worst = max((_PROTO_SEV_RANK.get(n[0][0], 0) for n in norm), default=0)

    masters = list(getattr(summary, "masters", []) or [])
    servers = list(getattr(summary, "dst_ips", {}) or {})
    units = list(getattr(summary, "unit_ids", {}) or {})
    reads = sum(
        cnt for name, cnt in getattr(summary, "func_counts", {}).items()
        if "read" in name.lower()
    )
    writes = int(getattr(summary, "write_count", 0))
    excs = int(getattr(summary, "exception_count", 0))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if worst >= 4:
        lines.append(danger(
            "CRITICAL - Modbus: broadcast/destructive control activity observed; "
            "treat as a potential active manipulation of the process."
        ))
    elif worst >= 3:
        lines.append(danger(
            "HIGH - Modbus: state-changing command or control-plane abuse observed; "
            "confirm it originates from an authorized master within a change window."
        ))
    elif worst >= 2:
        lines.append(warn(
            "REVIEW - Modbus: notable activity that deviates from a clean read-only "
            "polling baseline; triage the findings below."
        ))
    else:
        lines.append(ok(
            "BENIGN BASELINE - Modbus: read-only polling with no writes, exceptions, "
            "or protocol anomalies. Consistent with routine SCADA/HMI acquisition."
        ))

    unit_str = ", ".join(str(u) for u in sorted(units)[:8]) if units else "none"
    if units and len(units) > 8:
        unit_str += f", +{len(units) - 8}"
    lines.append(muted(
        f"  Baseline: {len(masters)} master(s) -> {len(servers)} server(s); "
        f"unit id(s) {unit_str}; {reads} reads / {writes} writes / {excs} exceptions "
        f"over {getattr(summary, 'duration', 0.0):.0f}s."
    ))
    if masters:
        lines.append(muted(f"  Master(s): {', '.join(masters[:6])}"))
    if len(masters) > 1:
        lines.append(warn(
            "  Note: >1 Modbus master present — validate any that is not a known "
            "SCADA/HMI/EWS (new-master hunt hypothesis)."
        ))

    if worst >= 2:
        ranked = sorted(
            norm, key=lambda n: _PROTO_SEV_RANK.get(n[0][0], 0), reverse=True
        )
        lines.append(muted("Focus Here First:"))
        attack_ids: list[str] = []
        for (sev, title, detail), orig in ranked[: _limit_value(6)]:
            if _PROTO_SEV_RANK.get(sev, 0) < 2:
                continue
            mark = (
                danger(f"[{sev.upper()}]")
                if _PROTO_SEV_RANK.get(sev, 0) >= 3
                else warn(f"[{sev.upper()}]")
            )
            src = str(getattr(orig, "src", "") or "")
            dst = str(getattr(orig, "dst", "") or "")
            ev = f"{src} -> {dst}" if (src or dst) else _truncate_text(detail, 80)
            lines.append(f"  {mark} {title}" + (f" — {_truncate_text(ev, 90)}" if ev else ""))
        for (_sev, title, _detail), _orig in ranked:
            tech = _ot_attack_for_title(title)
            if tech and tech not in attack_ids:
                attack_ids.append(tech)
        if attack_ids:
            lines.append(SUBSECTION_BAR)
            lines.append(header("ATT&CK for ICS Mapping"))
            for tid in attack_ids[: _limit_value(12)]:
                lines.append(muted(f"- {tid}"))


def _render_modbus_baseline_sections(
    lines: list[str], summary: "ModbusAnalysis"
) -> None:
    """Forensic baseline sections: register/coil map (process fingerprint),
    polling cadence, per-server response time, and transaction pairing."""
    # --- Register / Coil Map (process fingerprint) ---
    register_map = getattr(summary, "register_map", {}) or {}
    if register_map:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Register / Coil Map (process fingerprint)"))
        rows = [["Server / Unit", "Reads", "Read Range", "Writes", "Write Range", "Hot (addr:count)"]]
        ordered = sorted(
            register_map.values(),
            key=lambda r: -(int(r.get("read_count", 0)) + int(r.get("write_count", 0))),
        )
        for rec in ordered[: _limit_value(12)]:
            rmin, rmax = rec.get("read_min"), rec.get("read_max")
            wmin, wmax = rec.get("write_min"), rec.get("write_max")
            read_rng = f"{rmin}-{rmax}" if rmin is not None else "-"
            write_rng = f"{wmin}-{wmax}" if wmin is not None else "-"
            hot_src = rec.get("write_hot") or rec.get("read_hot") or []
            hot = ", ".join(f"{a}:{c}" for a, c in hot_src[:3]) or "-"
            wcount = int(rec.get("write_count", 0))
            wcell = danger(str(wcount)) if wcount else "0"
            rows.append([
                f"{rec.get('dst','?')} U{rec.get('unit','?')}",
                str(rec.get("read_count", 0)),
                read_rng,
                wcell,
                write_rng,
                hot,
            ])
        lines.append(_format_table(rows))

    # --- Polling Cadence (request direction only) ---
    cadence = getattr(summary, "session_cadence", []) or []
    req_cadence = [c for c in cadence if str(c.get("session", "")).split(" -> ", 1)[-1].endswith(":502")]
    if req_cadence:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Polling Cadence (per master -> server)"))
        rows = [["Session", "Reqs", "Avg (s)", "Median (s)", "Regular?"]]
        for c in req_cadence[: _limit_value(10)]:
            rows.append([
                _truncate_text(str(c.get("session", "")), 46),
                str(c.get("count", 0)),
                f"{float(c.get('avg', 0.0)):.3f}",
                f"{float(c.get('median', 0.0)):.3f}",
                "yes" if c.get("regular") else "no",
            ])
        lines.append(_format_table(rows))

    # --- Response Time by Server ---
    rtt = getattr(summary, "rtt_by_server", {}) or {}
    if rtt:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Response Time by Server (paired req->resp)"))
        rows = [["Server", "min ms", "p50 ms", "p95 ms", "max ms"]]
        for ip, st in sorted(rtt.items(), key=lambda kv: -kv[1].get("p95", 0)):
            rows.append([
                ip,
                f"{st.get('min', 0):.0f}",
                f"{st.get('p50', 0):.0f}",
                f"{st.get('p95', 0):.0f}",
                f"{st.get('max', 0):.0f}",
            ])
        lines.append(_format_table(rows))

    # --- Transaction Pairing ---
    pairing = getattr(summary, "pairing", {}) or {}
    if pairing:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Transaction Pairing"))
        matched = int(pairing.get("matched", 0))
        orphans = int(pairing.get("orphan_requests", 0))
        phantom = int(pairing.get("phantom_responses", 0))
        static = int(pairing.get("static_transid_conns", 0))
        lines.append(_format_kv("Matched req/resp", str(matched)))
        lines.append(_format_kv(
            "Orphan requests (no response)",
            danger(str(orphans)) if orphans else "0",
        ))
        lines.append(_format_kv(
            "Unsolicited responses",
            danger(str(phantom)) if phantom else "0",
        ))
        lines.append(_format_kv(
            "Static transaction-id connections",
            danger(str(static)) if static else "0",
        ))
        lines.append(muted(
            "  Orphans/unsolicited near capture edges are expected (pre-existing "
            "sessions, cut-off); sustained imbalance = DoS or injection."
        ))


def render_modbus_summary(summary: "ModbusAnalysis", verbose: bool = False) -> str:
    """
    Render Modbus analysis results.
    """
    from ..utils import format_ts

    if not summary:
        return ""

    lines = []
    lines.append(SECTION_BAR)
    lines.append(header(f"MODBUS ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)
    _render_modbus_verdict(lines, summary)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    # 1. Overview
    total_packets = summary.total_packets
    total_bytes = summary.total_bytes
    modbus_packets = summary.modbus_packets
    modbus_bytes = summary.modbus_bytes
    modbus_payload_bytes = summary.modbus_payload_bytes
    modbus_packet_ratio = (modbus_packets / total_packets) if total_packets else 0.0
    modbus_byte_ratio = (modbus_bytes / total_bytes) if total_bytes else 0.0
    avg_modbus_pkt = (modbus_bytes / modbus_packets) if modbus_packets else 0.0
    avg_modbus_payload = (
        (modbus_payload_bytes / modbus_packets) if modbus_packets else 0.0
    )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Overall Traffic Statistics"))
    lines.append(_format_kv("Scan Duration", f"{summary.duration:.2f}s"))
    lines.append(_format_kv("Total Packets", str(total_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(total_bytes)))
    if summary.duration:
        pps = total_packets / summary.duration
        bps = (total_bytes / summary.duration) * 8
        lines.append(_format_kv("Packets/sec", f"{pps:.2f}"))
        lines.append(_format_kv("Bits/sec", format_speed_bps(int(bps))))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Modbus Protocol Statistics"))
    lines.append(
        _format_kv("Modbus Packets", f"{modbus_packets} ({modbus_packet_ratio:.1%})")
    )
    lines.append(
        _format_kv(
            "Modbus Bytes",
            f"{format_bytes_as_mb(modbus_bytes)} ({modbus_byte_ratio:.1%})",
        )
    )
    lines.append(
        _format_kv("Modbus Payload Bytes", format_bytes_as_mb(modbus_payload_bytes))
    )
    lines.append(_format_kv("Avg Modbus Packet Size", f"{avg_modbus_pkt:.1f} bytes"))
    lines.append(
        _format_kv("Avg Modbus Payload Size", f"{avg_modbus_payload:.1f} bytes")
    )
    lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))
    lines.append(_format_kv("Error Rate", f"{summary.error_rate:.2f}%"))

    # 2. Function Codes
    lines.append(SUBSECTION_BAR)
    lines.append(header("Observed Commands"))
    if not summary.func_counts:
        lines.append(muted("No Modbus functions detected."))
    else:
        for func, count in summary.func_counts.most_common():
            lowered = func.lower()
            is_write = "write" in lowered
            is_diag = any(
                token in lowered
                for token in ("diagnostic", "encapsulated", "report server", "file")
            )
            if is_write:
                color = danger
            elif is_diag:
                color = warn
            else:
                color = _identity_text
            lines.append(color(f"{func:<40} : {count}"))

    # 3. Unit IDs
    lines.append(SUBSECTION_BAR)
    lines.append(header("Active Unit IDs"))
    if not summary.unit_ids:
        lines.append(muted("No Unit IDs found."))
    else:
        # Show top 10
        top_units = summary.unit_ids.most_common(_limit_value(10))
        u_strs = [f"ID {uid} ({cnt})" for uid, cnt in top_units]
        lines.append("  " + ", ".join(u_strs))
        if len(summary.unit_ids) > 10:
            lines.append(muted(f"  ... and {len(summary.unit_ids) - 10} more"))

    # 4. Endpoints
    lines.append(SUBSECTION_BAR)
    lines.append(header("Endpoint Statistics"))
    if summary.endpoint_packets:
        rows = [["Endpoint", "Packets", "Bytes"]]
        for ip, count in summary.endpoint_packets.most_common(_limit_value(10)):
            rows.append(
                [
                    ip,
                    str(count),
                    format_bytes_as_mb(summary.endpoint_bytes.get(ip, 0)),
                ]
            )
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No Modbus endpoints detected."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Client/Server Statistics"))
    col_width = 45
    lines.append(
        highlight(
            f"{'Clients (Controllers)':<{col_width}} | {'Servers (PLCs/Sensors)'}"
        )
    )
    lines.append(muted("-" * 90))
    clients = summary.src_ips.most_common(_limit_value(10))
    servers = summary.dst_ips.most_common(_limit_value(10))
    max_rows = max(len(clients), len(servers))
    for i in range(max_rows):
        c_str = ""
        s_str = ""
        if i < len(clients):
            ip, cnt = clients[i]
            c_bytes = format_bytes_as_mb(summary.client_bytes.get(ip, 0))
            c_str = f"{ip} ({cnt}/{c_bytes})"
        if i < len(servers):
            ip, cnt = servers[i]
            s_bytes = format_bytes_as_mb(summary.server_bytes.get(ip, 0))
            s_str = f"{ip} ({cnt}/{s_bytes})"
        lines.append(f"{c_str:<{col_width}} | {s_str}")

    _render_modbus_baseline_sections(lines, summary)

    if summary.service_endpoints:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Modbus Services (Endpoints)"))
        rows = [["Service", "Top Endpoints"]]
        for func_name, counter in Counter(
            {name: sum(cnt.values()) for name, cnt in summary.service_endpoints.items()}
        ).most_common(_limit_value(10)):
            endpoints = summary.service_endpoints.get(func_name, Counter())
            top_eps = ", ".join(
                f"{ep} ({cnt})" for ep, cnt in endpoints.most_common(_limit_value(3))
            )
            rows.append([func_name, top_eps or "-"])
        lines.append(_format_table(rows))

    if summary.artifacts:
        equipment_hits = [
            artifact
            for artifact in summary.artifacts
            if str(getattr(artifact, "kind", "")) == "equipment"
        ]
        if equipment_hits:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Equipment Inventory"))
            counts = Counter(
                str(getattr(artifact, "detail", "")) for artifact in equipment_hits
            )
            endpoints: dict[str, Counter[str]] = defaultdict(Counter)
            for artifact in equipment_hits:
                detail = str(getattr(artifact, "detail", ""))
                src = str(getattr(artifact, "src", "?"))
                dst = str(getattr(artifact, "dst", "?"))
                endpoints[detail][f"{src} -> {dst}"] += 1
            rows = [["Equipment", "Count", "Top Endpoints"]]
            for detail, count in counts.most_common(_limit_value(12)):
                top_eps = ", ".join(
                    f"{ep} ({cnt})"
                    for ep, cnt in endpoints[detail].most_common(_limit_value(3))
                )
                rows.append([detail, str(count), top_eps or "-"])
            lines.append(_format_table(rows))

        device_hits = [
            artifact
            for artifact in summary.artifacts
            if str(getattr(artifact, "kind", "")) == "device"
        ]
        if device_hits:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Device Fingerprints"))
            counts = Counter(
                str(getattr(artifact, "detail", "")) for artifact in device_hits
            )
            endpoints: dict[str, Counter[str]] = defaultdict(Counter)
            for artifact in device_hits:
                detail = str(getattr(artifact, "detail", ""))
                src = str(getattr(artifact, "src", "?"))
                dst = str(getattr(artifact, "dst", "?"))
                endpoints[detail][f"{src} -> {dst}"] += 1
            rows = [["Fingerprint", "Count", "Top Endpoints"]]
            for detail, count in counts.most_common(_limit_value(12)):
                top_eps = ", ".join(
                    f"{ep} ({cnt})"
                    for ep, cnt in endpoints[detail].most_common(_limit_value(3))
                )
                rows.append([_truncate_text(detail, 90), str(count), top_eps or "-"])
            lines.append(_format_table(rows))

    if summary.packet_size_hist or summary.payload_size_hist:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Packet & Payload Size Distribution"))
        bucket_labels = [
            "<=64",
            "65-128",
            "129-256",
            "257-512",
            "513-1024",
            "1025-1500",
            "1501-9000",
            ">9000",
        ]
        if summary.packet_size_hist:
            packet_series = [
                summary.packet_size_hist.get(label, 0) for label in bucket_labels
            ]
            lines.append(_format_kv("Packet Size Buckets", ", ".join(bucket_labels)))
            lines.append(_format_kv("Packet Size Spark", sparkline(packet_series)))
            stats = summary.packet_size_stats
            lines.append(
                _format_kv(
                    "Packet Size Stats",
                    f"min {stats.get('min', 0):.0f} / p50 {stats.get('p50', 0):.0f} / p95 {stats.get('p95', 0):.0f} / max {stats.get('max', 0):.0f}",
                )
            )
        if summary.payload_size_hist:
            payload_series = [
                summary.payload_size_hist.get(label, 0) for label in bucket_labels
            ]
            lines.append(_format_kv("Payload Size Buckets", ", ".join(bucket_labels)))
            lines.append(_format_kv("Payload Size Spark", sparkline(payload_series)))
            stats = summary.payload_size_stats
            lines.append(
                _format_kv(
                    "Payload Size Stats",
                    f"min {stats.get('min', 0):.0f} / p50 {stats.get('p50', 0):.0f} / p95 {stats.get('p95', 0):.0f} / max {stats.get('max', 0):.0f}",
                )
            )

    if summary.flow_duration_buckets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Flow Duration Distribution"))
        bucket_order = ["<=1s", "1-10s", "10-60s", "1-5m", "5-30m", ">30m"]
        for key, label_text in (
            ("all", "All"),
            ("requests", "Requests"),
            ("responses", "Responses"),
        ):
            buckets = summary.flow_duration_buckets.get(key, Counter())
            if not buckets:
                continue
            counts = [int(buckets.get(bucket, 0)) for bucket in bucket_order]
            lines.append(_format_kv(f"{label_text} Buckets", ", ".join(bucket_order)))
            lines.append(
                _format_kv(
                    f"{label_text} Counts", ", ".join(str(val) for val in counts)
                )
            )

    if summary.messages:
        exception_counts = Counter(
            f"{msg.exception_desc or 'Exception'}"
            for msg in summary.messages
            if msg.is_exception
        )
        if exception_counts:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Exception Responses"))
            lines.append(_counter_table(exception_counts, "Exception", limit=_limit_value(10)))

    if getattr(summary, "value_changes", None):
        if summary.value_changes:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Write Value Changes (Preview)"))
            rows = [["Target", "Old", "New", "Src", "Dst", "TS"]]
            for item in summary.value_changes[: _limit_value(8)]:
                rows.append(
                    [
                        str(item.get("target", "")),
                        str(item.get("old", "")),
                        str(item.get("new", "")),
                        str(item.get("src", "")),
                        str(item.get("dst", "")),
                        format_ts(item.get("ts")),
                    ]
                )
            lines.append(_format_table(rows))

    # 5. Anomalies
    if summary.anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Threats"))

        if not verbose:
            lines.append(_format_kv("Total Anomalies", str(len(summary.anomalies))))
            sev_counts = Counter(a.severity for a in summary.anomalies)
            sev_rows = [["Severity", "Count"]]
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if sev_counts.get(severity):
                    sev_rows.append([severity, str(sev_counts[severity])])
            if len(sev_rows) > 1:
                lines.append(_format_table(sev_rows))
            title_counts = Counter(a.title for a in summary.anomalies)
            if title_counts:
                lines.append(SUBSECTION_BAR)
                lines.append(header("Top Anomaly Types"))
                lines.append(_counter_table(title_counts, "Type", limit=_limit_value(10)))
            lines.append(muted("Use -v for detailed anomaly listings."))
        else:
            # Sort by severity
            sev_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            sorted_anoms = sorted(
                summary.anomalies, key=lambda x: sev_map.get(x.severity, 99)
            )

            for a in sorted_anoms:
                sev_color = danger if a.severity in ("CRITICAL", "HIGH") else warn
                if a.severity == "LOW":
                    sev_color = muted

                lines.append(sev_color(f"[{a.severity}] {a.title}"))
                lines.append(f"  {a.description}")
                lines.append(muted(f"  Src: {a.src} -> Dst: {a.dst}"))
                lines.append("")

    lines.append(SECTION_BAR)
    return _finalize_output(lines)


def render_modbus_rollup(summaries: Iterable["ModbusAnalysis"]) -> str:
    """
    Render Modbus rollup results across multiple pcaps.
    """

    summary_list = list(summaries)
    if not summary_list:
        return ""

    total_pcaps = len(summary_list)
    total_duration = 0.0
    total_modbus_packets = 0
    total_packets = 0
    total_bytes = 0
    total_modbus_bytes = 0
    total_modbus_payload_bytes = 0
    total_messages = 0
    total_exceptions = 0
    func_counts = Counter()
    unit_ids = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    client_bytes = Counter()
    server_bytes = Counter()
    endpoint_packets = Counter()
    endpoint_bytes = Counter()
    service_endpoints: dict[str, Counter[str]] = defaultdict(Counter)
    packet_size_hist = Counter()
    payload_size_hist = Counter()
    flow_duration_buckets: dict[str, Counter[str]] = {
        "all": Counter(),
        "requests": Counter(),
        "responses": Counter(),
    }
    equipment_counts: Counter[str] = Counter()
    equipment_endpoints: dict[str, Counter[str]] = defaultdict(Counter)
    device_counts: Counter[str] = Counter()
    device_endpoints: dict[str, Counter[str]] = defaultdict(Counter)
    all_anomalies = []
    errors = Counter()

    for summary in summary_list:
        total_duration += summary.duration
        total_packets += summary.total_packets
        total_bytes += summary.total_bytes
        total_modbus_packets += summary.modbus_packets
        total_modbus_bytes += summary.modbus_bytes
        total_modbus_payload_bytes += summary.modbus_payload_bytes
        func_counts.update(summary.func_counts)
        unit_ids.update(summary.unit_ids)
        src_ips.update(summary.src_ips)
        dst_ips.update(summary.dst_ips)
        client_bytes.update(summary.client_bytes)
        server_bytes.update(summary.server_bytes)
        endpoint_packets.update(summary.endpoint_packets)
        endpoint_bytes.update(summary.endpoint_bytes)
        packet_size_hist.update(summary.packet_size_hist)
        payload_size_hist.update(summary.payload_size_hist)
        for name, counter in summary.service_endpoints.items():
            service_endpoints[name].update(counter)
        for artifact in summary.artifacts:
            if str(getattr(artifact, "kind", "")) != "equipment":
                continue
            detail = str(getattr(artifact, "detail", ""))
            equipment_counts[detail] += 1
            src = str(getattr(artifact, "src", "?"))
            dst = str(getattr(artifact, "dst", "?"))
            equipment_endpoints[detail][f"{src} -> {dst}"] += 1
        for artifact in summary.artifacts:
            if str(getattr(artifact, "kind", "")) != "device":
                continue
            detail = str(getattr(artifact, "detail", ""))
            device_counts[detail] += 1
            src = str(getattr(artifact, "src", "?"))
            dst = str(getattr(artifact, "dst", "?"))
            device_endpoints[detail][f"{src} -> {dst}"] += 1
        for key in ("all", "requests", "responses"):
            flow_duration_buckets[key].update(
                summary.flow_duration_buckets.get(key, Counter())
            )
        total_messages += len(summary.messages)
        total_exceptions += sum(1 for msg in summary.messages if msg.is_exception)
        all_anomalies.extend(summary.anomalies)
        for err in summary.errors:
            errors[err] += 1

    error_rate = (total_exceptions / total_messages) * 100 if total_messages else 0.0

    lines = []
    lines.append(SECTION_BAR)
    lines.append(header(f"MODBUS ANALYSIS :: ALL PCAPS ({total_pcaps})"))
    lines.append(SECTION_BAR)

    if errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err, count in errors.most_common(_limit_value(10)):
            suffix = f" (x{count})" if count > 1 else ""
            lines.append(danger(f"- {err}{suffix}"))

    lines.append(_format_kv("PCAPs Analyzed", str(total_pcaps)))
    lines.append(_format_kv("Combined Duration", f"{total_duration:.2f}s"))
    lines.append(_format_kv("Total Packets", str(total_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(total_bytes)))
    lines.append(_format_kv("Modbus Packets", str(total_modbus_packets)))
    lines.append(_format_kv("Modbus Bytes", format_bytes_as_mb(total_modbus_bytes)))
    lines.append(
        _format_kv(
            "Modbus Payload Bytes", format_bytes_as_mb(total_modbus_payload_bytes)
        )
    )
    lines.append(_format_kv("Total Messages", str(total_messages)))
    lines.append(_format_kv("Unique Clients", str(len(src_ips))))
    lines.append(_format_kv("Unique Servers", str(len(dst_ips))))
    lines.append(_format_kv("Error Rate", f"{error_rate:.2f}%"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Function Code Usage"))
    if not func_counts:
        lines.append(muted("No Modbus functions detected."))
    else:
        for func, count in func_counts.most_common():
            is_write = "Write" in func
            c = danger if is_write else lambda x: x
            lines.append(c(f"{func:<40} : {count}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Active Unit IDs"))
    if not unit_ids:
        lines.append(muted("No Unit IDs found."))
    else:
        top_units = unit_ids.most_common(_limit_value(10))
        u_strs = [f"ID {uid} ({cnt})" for uid, cnt in top_units]
        lines.append("  " + ", ".join(u_strs))
        if len(unit_ids) > 10:
            lines.append(muted(f"  ... and {len(unit_ids) - 10} more"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Modbus Endpoints"))
    col_width = 45
    lines.append(
        highlight(
            f"{'Clients (Controllers)':<{col_width}} | {'Servers (PLCs/Sensors)'}"
        )
    )
    lines.append(muted("-" * 90))
    clients = src_ips.most_common(_limit_value(10))
    servers = dst_ips.most_common(_limit_value(10))
    max_rows = max(len(clients), len(servers))
    for i in range(max_rows):
        c_str = ""
        s_str = ""
        if i < len(clients):
            ip, cnt = clients[i]
            c_str = f"{ip} ({cnt}/{format_bytes_as_mb(client_bytes.get(ip, 0))})"
        if i < len(servers):
            ip, cnt = servers[i]
            s_str = f"{ip} ({cnt}/{format_bytes_as_mb(server_bytes.get(ip, 0))})"
        lines.append(f"{c_str:<{col_width}} | {s_str}")

    if endpoint_packets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Endpoints"))
        rows = [["Endpoint", "Packets", "Bytes"]]
        for ip, count in endpoint_packets.most_common(_limit_value(10)):
            rows.append(
                [
                    ip,
                    str(count),
                    format_bytes_as_mb(endpoint_bytes.get(ip, 0)),
                ]
            )
        lines.append(_format_table(rows))

    if service_endpoints:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Modbus Services (Endpoints)"))
        rows = [["Service", "Top Endpoints"]]
        for func_name, counter in Counter(
            {name: sum(cnt.values()) for name, cnt in service_endpoints.items()}
        ).most_common(_limit_value(10)):
            endpoints = service_endpoints.get(func_name, Counter())
            top_eps = ", ".join(
                f"{ep} ({cnt})" for ep, cnt in endpoints.most_common(_limit_value(3))
            )
            rows.append([func_name, top_eps or "-"])
        lines.append(_format_table(rows))

    if equipment_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Equipment Inventory"))
        rows = [["Equipment", "Count", "Top Endpoints"]]
        for detail, count in equipment_counts.most_common(_limit_value(12)):
            top_eps = ", ".join(
                f"{ep} ({cnt})"
                for ep, cnt in equipment_endpoints[detail].most_common(_limit_value(3))
            )
            rows.append([detail, str(count), top_eps or "-"])
        lines.append(_format_table(rows))

    if device_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Device Fingerprints"))
        rows = [["Fingerprint", "Count", "Top Endpoints"]]
        for detail, count in device_counts.most_common(_limit_value(12)):
            top_eps = ", ".join(
                f"{ep} ({cnt})"
                for ep, cnt in device_endpoints[detail].most_common(_limit_value(3))
            )
            rows.append([_truncate_text(detail, 90), str(count), top_eps or "-"])
        lines.append(_format_table(rows))

    if packet_size_hist or payload_size_hist:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Packet & Payload Size Distribution"))
        bucket_labels = [
            "<=64",
            "65-128",
            "129-256",
            "257-512",
            "513-1024",
            "1025-1500",
            "1501-9000",
            ">9000",
        ]
        if packet_size_hist:
            packet_series = [packet_size_hist.get(label, 0) for label in bucket_labels]
            lines.append(_format_kv("Packet Size Buckets", ", ".join(bucket_labels)))
            lines.append(_format_kv("Packet Size Spark", sparkline(packet_series)))
        if payload_size_hist:
            payload_series = [
                payload_size_hist.get(label, 0) for label in bucket_labels
            ]
            lines.append(_format_kv("Payload Size Buckets", ", ".join(bucket_labels)))
            lines.append(_format_kv("Payload Size Spark", sparkline(payload_series)))

    if flow_duration_buckets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Flow Duration Distribution"))
        bucket_order = ["<=1s", "1-10s", "10-60s", "1-5m", "5-30m", ">30m"]
        for key, label_text in (
            ("all", "All"),
            ("requests", "Requests"),
            ("responses", "Responses"),
        ):
            buckets = flow_duration_buckets.get(key, Counter())
            if not buckets:
                continue
            counts = [int(buckets.get(bucket, 0)) for bucket in bucket_order]
            lines.append(_format_kv(f"{label_text} Buckets", ", ".join(bucket_order)))
            lines.append(
                _format_kv(
                    f"{label_text} Counts", ", ".join(str(val) for val in counts)
                )
            )

    if all_anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Threats (Aggregated)"))
        lines.append(_format_kv("Total Anomalies", str(len(all_anomalies))))
        sev_counts = Counter(a.severity for a in all_anomalies)
        sev_rows = [["Severity", "Count"]]
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if sev_counts.get(severity):
                sev_rows.append([severity, str(sev_counts[severity])])
        if len(sev_rows) > 1:
            lines.append(_format_table(sev_rows))
        title_counts = Counter(a.title for a in all_anomalies)
        if title_counts:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Top Anomaly Types"))
            lines.append(_counter_table(title_counts, "Type", limit=_limit_value(10)))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
