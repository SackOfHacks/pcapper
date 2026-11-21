"""Rendered output for the generic -summarize rollup (analyzers without
their own merge): findings aggregated across captures with how many
captures each appeared in, endpoint and counter tallies, and service
endpoints; totals, size buckets and artifacts are -v detail."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Iterable

from . import _style as st


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
    finding_seen: dict[tuple[str, str], tuple[str, set[int]]] = {}

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

    for index, summary in enumerate(summary_list):
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

        for item in list(getattr(summary, "detections", None) or []) + list(getattr(summary, "anomalies", None) or []):
            f = st.finding(item)
            entry = finding_seen.setdefault((f.title, f.severity), (f.detail, set()))
            entry[1].add(index)

    n = len(summary_list)
    rep = st.Report(f"{title.replace(' ANALYSIS', '').strip()} rollup", f"all captures ({n})")
    findings = []
    for (_title, _sev), (detail, seen) in sorted(finding_seen.items(), key=lambda kv: (-st.sev_rank(kv[0][1]), kv[0][0])):
        findings.append(st.finding({"severity": _sev, "title": _title,
                                    "details": st.join([f"in {len(seen)} of {st.plural(n, 'capture')}", detail])}))
    severity, text = st.verdict(findings, high="high-severity findings across captures", medium="findings to review across captures")
    totals_kv: dict[str, str] = {}
    for key, label_text in preferred_numeric.items():
        if key in totals and label_text not in totals_kv:
            value = totals[key]
            totals_kv[label_text] = (st.size(int(value)) if key.endswith("bytes") else
                                     st.duration(value) if "duration" in key else st.count(int(value)))
    rep.headline(severity, text, st.join([st.plural(n, "capture")]
                                         + [f"{v} {k.lower().removeprefix('total ')}" for k, v in list(totals_kv.items())[:3]]))
    rep.section("Findings", st.findings_block(findings))
    client_counter = counters.get("client_ips") or counters.get("clients") or counters.get("src_ips")
    server_counter = counters.get("server_ips") or counters.get("servers") or counters.get("dst_ips")
    rep.section("Endpoints", st.kv([("Clients", st.top(client_counter, 8)), ("Servers", st.top(server_counter, 8))]
                                   + [(label_text, st.count(len(unions[key]))) for key, label_text in preferred_sets.items() if key in unions]))
    shown = {id(client_counter), id(server_counter)}
    ordered = sorted(((k, c) for k, c in counters.items() if id(c) not in shown), key=lambda item: sum(item[1].values()), reverse=True)
    rep.section("Counters", st.kv([(name.replace("_", " ").capitalize(), st.top(c, 6)) for name, c in
                                   (ordered if st.verbose() else ordered[:4])]))
    rep.section("Services", st.table(
        ["Service", "Top endpoints"],
        [[svc, st.top(service_endpoints.get(svc, Counter()), 3)] for svc, _ in
         Counter({svc: sum(c.values()) for svc, c in service_endpoints.items()}).most_common()],
        max_rows=st.TOP_ROWS, tail=st.TOP_ROWS, noun="service",
    ))
    rep.section("Totals", st.kv(list(totals_kv.items())), detail=True)

    def _buckets(store: dict[str, dict[str, float]]) -> list[str]:
        total = sum(e["count"] for e in store.values())
        return st.table(["Bucket", "Count", "Share", "Min", "Avg", "Max"],
                        [[b, int(e["count"]), f"{e['count'] / total:.1%}", int(e["min"]), f"{e['sum'] / e['count']:.1f}" if e["count"] else "0.0",
                          int(e["max"])] for b, e in store.items()], align="lrrrrr", max_rows=None) if total else []

    rep.section("Packet sizes", _buckets(packet_buckets), detail=True)
    rep.section("Payload sizes", _buckets(payload_buckets), detail=True)
    rep.section("Artifacts", st.table(["Artifact", "Count"], [[a, c] for a, c in artifact_counts.most_common()], align="lr", max_rows=None),
                detail=True)
    return rep.render()
