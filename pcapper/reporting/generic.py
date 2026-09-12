"""Rendered output for generic analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from collections import Counter, defaultdict
from typing import Iterable
from ..coloring import (
    header,
    highlight,
    label,
    muted,
)
from ..utils import (
    format_bytes_as_mb,
    format_duration,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _counter_table,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
)


def render_generic_rollup(title: str, summaries: Iterable[object]) -> str:
    summary_list = list(summaries)
    if not summary_list:
        return ""

    totals: dict[str, float] = {}
    counters: dict[str, Counter[str]] = {}
    unions: dict[str, set[object]] = {}
    service_endpoints: dict[str, Counter[str]] = defaultdict(Counter)
    packet_buckets: dict[str, dict[str, float]] = {}
    payload_buckets: dict[str, dict[str, float]] = {}
    artifact_counts: Counter[str] = Counter()
    anomaly_counts: Counter[str] = Counter()

    preferred_numeric = {
        "total_packets": "Total Packets",
        "total_bytes": "Total Bytes",
        "packet_count": "Total Packets",
        "packets": "Total Packets",
        "protocol_packets": "Protocol Packets",
        "protocol_bytes": "Protocol Bytes",
        "duration_seconds": "Combined Duration",
        "duration": "Combined Duration",
        "modbus_packets": "Modbus Packets",
        "dnp3_packets": "DNP3 Packets",
        "total_requests": "Total Requests",
        "total_responses": "Total Responses",
        "requests": "Total Requests",
        "responses": "Total Responses",
        "total_tagged_packets": "Tagged Packets",
        "total_tagged_bytes": "Tagged Bytes",
    }

    preferred_sets = {
        "src_ips": "Unique Source IPs",
        "dst_ips": "Unique Destination IPs",
        "client_ips": "Unique Clients",
        "server_ips": "Unique Servers",
        "clients": "Unique Clients",
        "servers": "Unique Servers",
    }

    for summary in summary_list:
        for name, value in vars(summary).items():
            if isinstance(value, Counter):
                counters.setdefault(name, Counter()).update(value)
            elif isinstance(value, set):
                unions.setdefault(name, set()).update(value)
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                if name in preferred_numeric:
                    totals[name] = totals.get(name, 0.0) + float(value)

        summary_service_endpoints = getattr(summary, "service_endpoints", None)
        if isinstance(summary_service_endpoints, dict):
            for service, endpoints in summary_service_endpoints.items():
                if isinstance(endpoints, Counter):
                    service_endpoints[str(service)].update(endpoints)

        for bucket_name, bucket_store in (
            ("packet_size_buckets", packet_buckets),
            ("payload_size_buckets", payload_buckets),
        ):
            buckets = getattr(summary, bucket_name, None)
            if not buckets:
                continue
            for bucket in buckets:
                bucket_label = getattr(bucket, "label", None)
                if bucket_label is None:
                    continue
                entry = bucket_store.setdefault(
                    str(bucket_label),
                    {"count": 0.0, "sum": 0.0, "min": 0.0, "max": 0.0},
                )
                count = float(getattr(bucket, "count", 0) or 0)
                avg = float(getattr(bucket, "avg", 0.0) or 0.0)
                min_val = float(getattr(bucket, "min", 0) or 0)
                max_val = float(getattr(bucket, "max", 0) or 0)
                if entry["count"] == 0:
                    entry["min"] = min_val
                    entry["max"] = max_val
                else:
                    entry["min"] = min(entry["min"], min_val)
                    entry["max"] = max(entry["max"], max_val)
                entry["count"] += count
                entry["sum"] += avg * count

        artifacts = getattr(summary, "artifacts", None)
        if isinstance(artifacts, list):
            for artifact in artifacts:
                kind = str(getattr(artifact, "kind", "artifact"))
                detail = str(getattr(artifact, "detail", ""))
                artifact_counts[f"{kind}: {detail}"] += 1

        anomalies = getattr(summary, "anomalies", None)
        if isinstance(anomalies, list):
            for anomaly in anomalies:
                title = str(getattr(anomaly, "title", "Event"))
                anomaly_counts[title] += 1

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"{title} :: ALL PCAPS ({len(summary_list)})"))
    lines.append(SECTION_BAR)
    lines.append(_format_kv("PCAPs Analyzed", str(len(summary_list))))

    for key, label_text in preferred_numeric.items():
        if key in totals:
            value = totals[key]
            if key.endswith("bytes"):
                lines.append(_format_kv(label_text, format_bytes_as_mb(int(value))))
            elif "duration" in key:
                lines.append(_format_kv(label_text, format_duration(value)))
            else:
                lines.append(_format_kv(label_text, str(int(value))))

    for key, label_text in preferred_sets.items():
        if key in unions:
            lines.append(_format_kv(label_text, str(len(unions[key]))))

    client_counter = (
        counters.get("client_ips") or counters.get("clients") or counters.get("src_ips")
    )
    server_counter = (
        counters.get("server_ips") or counters.get("servers") or counters.get("dst_ips")
    )
    if client_counter or server_counter:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Endpoint Statistics"))
        col_width = 45
        lines.append(highlight(f"{'Clients':<{col_width}} | {'Servers'}"))
        lines.append(muted("-" * 90))
        clients = client_counter.most_common(_limit_value(10)) if client_counter else []
        servers = server_counter.most_common(_limit_value(10)) if server_counter else []
        max_rows = max(len(clients), len(servers))
        for i in range(max_rows):
            c_str = ""
            s_str = ""
            if i < len(clients):
                ip, cnt = clients[i]
                c_str = f"{ip} ({cnt})"
            if i < len(servers):
                ip, cnt = servers[i]
                s_str = f"{ip} ({cnt})"
            lines.append(f"{c_str:<{col_width}} | {s_str}")

    if counters:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Aggregated Counters"))
        ordered_counters = sorted(
            counters.items(), key=lambda item: sum(item[1].values()), reverse=True
        )
        for name, counter in ordered_counters[: _limit_value(4)]:
            lines.append(label(name.replace("_", " ").title()))
            lines.append(_counter_table(counter, "Item", limit=_limit_value(10)))

    if service_endpoints:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Service Endpoints"))
        rows = [["Service", "Top Endpoints"]]
        for service, counter in Counter(
            {svc: sum(cnt.values()) for svc, cnt in service_endpoints.items()}
        ).most_common(_limit_value(10)):
            endpoints = service_endpoints.get(service, Counter())
            top_eps = ", ".join(
                f"{ep} ({cnt})" for ep, cnt in endpoints.most_common(_limit_value(3))
            )
            rows.append([service, top_eps or "-"])
        lines.append(_format_table(rows))

    if packet_buckets or payload_buckets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Packet/Payload Size Analysis"))

        def _render_bucket_table(
            bucket_store: dict[str, dict[str, float]], label_text: str
        ) -> None:
            if not bucket_store:
                return
            total = sum(entry["count"] for entry in bucket_store.values())
            if not total:
                return
            rows = [["Bucket", "Count", "Pct", "Min", "Avg", "Max"]]
            for bucket_label, entry in bucket_store.items():
                avg = (entry["sum"] / entry["count"]) if entry["count"] else 0.0
                pct = (entry["count"] / total) * 100
                rows.append(
                    [
                        bucket_label,
                        str(int(entry["count"])),
                        f"{pct:.1f}%",
                        str(int(entry["min"])) if entry["min"] else "0",
                        f"{avg:.1f}",
                        str(int(entry["max"])) if entry["max"] else "0",
                    ]
                )
            lines.append(label(label_text))
            lines.append(_format_table(rows))

        _render_bucket_table(packet_buckets, "Packet Buckets")
        _render_bucket_table(payload_buckets, "Payload Buckets")

    if artifact_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts & Observations"))
        lines.append(_counter_table(artifact_counts, "Artifact", limit=_limit_value(12)))

    if anomaly_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Threat Indicators"))
        lines.append(_counter_table(anomaly_counts, "Title", limit=_limit_value(12)))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
