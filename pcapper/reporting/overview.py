"""Rendered output for --overview: the triage entry point. It leads with
the posture verdict and why, the critical/high detections by name, and the
immediate leads -- each with the pcapper command that scopes it and what to
confirm -- then what the auto-run deep dives found, the threat-hunt /
forensics / OT / CTF highlights (each line once), recommended actions and
what not to chase, and the inventory (hosts, devices, protocols, services,
notable flows). The capture counters and per-module extra highlights are
-v detail."""

from __future__ import annotations

from ..overview import OverviewSummary
from ..utils import format_bytes_as_mb, format_duration, format_speed_bps, format_ts
from . import _style as st
from ._common import _redact_in_text, _short_browser_role


def _overview_metrics_text(metrics: dict[str, object]) -> str:
    if not metrics:
        return "-"
    preferred = [
        "detections",
        "high_severity",
        "packets",
        "requests",
        "responses",
        "commands",
        "anomalies",
        "artifacts",
        "hits",
        "findings",
        "pcaps",
    ]
    parts: list[str] = []
    for key in preferred:
        if key not in metrics:
            continue
        value = metrics[key]
        if value is None:
            continue
        parts.append(f"{key}={value}")
    if not parts:
        for key, value in metrics.items():
            if value is None:
                continue
            parts.append(f"{key}={value}")
            if len(parts) >= 5:
                break
    return ", ".join(parts) if parts else "-"


def _overview_ts(value: object) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        ts = float(value)
    except Exception:
        return None
    return ts if ts > 0 else None


def _overview_window_text(start: object, end: object) -> str:
    start_ts = _overview_ts(start)
    end_ts = _overview_ts(end) or start_ts
    if start_ts is None and end_ts is None:
        return "-"
    if start_ts is None:
        return format_ts(end_ts)
    if end_ts is None or end_ts == start_ts:
        return format_ts(start_ts)
    return f"{format_ts(start_ts)} -> {format_ts(end_ts)}"


def _overview_list_preview(value: object, limit: int = 3) -> str:
    if isinstance(value, list):
        items = [str(item).strip() for item in value if str(item).strip()]
        if not items:
            return "-"
        text = ", ".join(items[:limit])
        if len(items) > limit:
            text = f"{text} (+{len(items) - limit})"
        return text
    return "-"


def _overview_activity_text(item: dict[str, object]) -> str:
    activity = str(item.get("activity", "") or "").strip()
    if activity and activity != "-":
        return activity
    services_hosted = _overview_list_preview(item.get("services_hosted"), limit=2)
    services_used = _overview_list_preview(item.get("services_used"), limit=2)
    protocols = _overview_list_preview(
        item.get("top_protocols", item.get("protocols")), limit=3
    )
    parts: list[str] = []
    if services_hosted != "-":
        parts.append(f"hosts {services_hosted}")
    if services_used != "-":
        parts.append(f"uses {services_used}")
    if not parts and protocols != "-":
        parts.append(f"speaks {protocols}")
    return "; ".join(parts) if parts else "-"


def _overview_rate_text(item: dict[str, object]) -> str:
    bits_per_sec = int(item.get("bits_per_sec", 0) or 0)
    packets_per_sec = float(item.get("packets_per_sec", 0.0) or 0.0)
    parts: list[str] = []
    if bits_per_sec > 0:
        parts.append(format_speed_bps(bits_per_sec))
    if packets_per_sec > 0:
        parts.append(f"{packets_per_sec:.2f} pps")
    return " / ".join(parts) if parts else "-"


def _overview_priority_style(priority: str):
    if priority == "HIGH":
        return st.bad
    if priority == "MEDIUM":
        return st.caution
    return st.dim


_OVERVIEW_OT_SIGNAL_TOKENS = (
    "modbus",
    "dnp3",
    "iec-104",
    "iec104",
    "s7",
    "s7comm",
    "enip",
    "cip",
    "profinet",
    "bacnet",
    "opc",
    "mms",
    "goose",
    "sv",
    "ptp",
    "hart",
    "niagara",
    "codesys",
)


_OVERVIEW_IOT_SIGNAL_TOKENS = ("mqtt", "coap")


def _overview_detected_devices(
    ip_activity_rows: list[dict[str, object]],
    limit: int = 12,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    seen_ips: set[str] = set()

    for item in ip_activity_rows:
        if not isinstance(item, dict):
            continue
        ip_text = str(item.get("ip", "") or "").strip()
        if not ip_text or ip_text in seen_ips:
            continue

        role = str(item.get("role", "mixed") or "mixed").strip()
        scope = str(item.get("scope", "unknown") or "unknown").strip()
        protocols = [str(v).strip() for v in list(item.get("top_protocols", []) or []) if str(v).strip()]
        services_hosted = [
            str(v).strip()
            for v in list(item.get("services_hosted", []) or [])
            if str(v).strip()
        ]
        services_used = [
            str(v).strip()
            for v in list(item.get("services_used", []) or [])
            if str(v).strip()
        ]
        ports: list[int] = []
        for raw in list(item.get("top_ports", []) or [])[:6]:
            try:
                ports.append(int(raw))
            except Exception:
                continue

        signal_blob = " ".join(protocols + services_hosted + services_used).lower()
        ot_signals = [
            token
            for token in _OVERVIEW_OT_SIGNAL_TOKENS
            if token in signal_blob
        ]
        iot_signals = [
            token
            for token in _OVERVIEW_IOT_SIGNAL_TOKENS
            if token in signal_blob
        ]

        # Browser (MS-BRWS) announced identity makes a host a device by itself
        # (it self-identifies its name/OS/roles).
        nb_host = str(item.get("hostname", "") or "")
        nb_roles = list(item.get("browser_roles", []) or [])
        nb_os = str(item.get("os", "") or "")
        nb_is_dc = bool(item.get("is_dc"))

        is_device_candidate = (
            role in {"service-host", "mixed"}
            or bool(services_hosted)
            or bool(ot_signals)
            or bool(iot_signals)
            or bool(nb_roles)
        )
        if not is_device_candidate:
            continue

        profile = "Network Service Node"
        if ot_signals:
            profile = "OT/ICS Device"
        elif iot_signals:
            profile = "IoT Endpoint/Gateway"
        elif nb_is_dc:
            profile = "Domain Controller"
        elif any("SQL Server" in r for r in nb_roles):
            profile = "SQL Server"
        elif any("Print Queue Server" in r for r in nb_roles):
            profile = "Print Server"
        elif any("Master Browser" in r for r in nb_roles):
            profile = "Master Browser"
        elif role == "service-host":
            profile = "Service Host"

        role_short = _short_browser_role(nb_roles)
        role_text = f"{scope}/{role_short or role}" if scope else (role_short or role)
        device_cell = f"{ip_text} ({nb_host})" if nb_host else ip_text
        when_text = _overview_window_text(item.get("first_seen"), item.get("last_seen"))
        signal_items = protocols[:3] + services_hosted[:2] + services_used[:1]
        signal_text = _overview_list_preview(list(dict.fromkeys(signal_items)), limit=3)
        if nb_os:
            signal_text = f"{nb_os.split(' (')[0]}; {signal_text}" if signal_text != "-" else nb_os.split(" (")[0]
        hosted_text = _overview_list_preview(services_hosted, limit=2)
        if hosted_text == "-":
            hosted_text = _overview_list_preview(services_used, limit=2)

        rows.append(
            {
                "ip": device_cell,
                "role": role_text,
                "profile": profile,
                "signals": signal_text,
                "services": hosted_text,
                "ports": ", ".join(str(v) for v in ports[:4]) if ports else "-",
                "when": when_text,
                "first_seen": item.get("first_seen"),
                "last_seen": item.get("last_seen"),
            }
        )
        seen_ips.add(ip_text)
        if len(rows) >= limit:
            break

    return rows


def _overview_next_command(entity: str) -> str:
    """Map a hunt-lead entity to the concrete pcapper command that scopes it."""
    text = str(entity or "").strip()
    if not text:
        return ""
    module_cmds = {
        "threat-correlation": "--threats -v   (then --threats --mitre to map ATT&CK)",
        "scan-analysis": "--scan",
        "ot-command-activity": "--ot-commands",
        "modbus-analysis": "--modbus",
        "dnp3-analysis": "--dnp3",
    }
    if text in module_cmds:
        return module_cmds[text]
    if "->" in text:
        src = text.split("->", 1)[0].strip()
        return f"--streams -ip {src}   (pull the conversation; --files -ip {src} if transfers)"
    # Bare IP / host entity.
    return f"--hostdetails -ip {text}   (then --streams -ip {text})"


def _overview_lead_lookfor(finding: str) -> str:
    """One-line 'what to confirm' guidance for a lead, by finding type."""
    lowered = str(finding or "").lower()
    if "egress-heavy" in lowered or "large cross-zone" in lowered or "exfil" in lowered:
        return "Confirm destination reputation and whether the volume/timing matches a sanctioned backup or sync."
    if "scan-like" in lowered or "scanner" in lowered or "recon" in lowered:
        return "Identify whether the source is an approved vuln scanner/asset-discovery tool; if not, scope it as recon."
    if "boundary" in lowered or "cross-zone" in lowered:
        return "Validate segmentation/jump-host policy; OT should not speak directly across the IT/OT or public boundary."
    if "low-and-slow" in lowered or "persistent flow" in lowered:
        return "Rule out a legitimate keepalive/monitoring session before treating as covert C2."
    if "control" in lowered or "write" in lowered or "modbus" in lowered or "dnp3" in lowered:
        return "Correlate with a change ticket / maintenance window and confirm the source is an authorized engineering workstation."
    if "service node" in lowered:
        return "Establish the asset's role and owner; confirm the exposed services are expected for that host."
    if "critical/high detections" in lowered:
        return "Triage the underlying detections in --threats; verify before escalating."
    return "Scope the entity, establish whether the behavior is sanctioned, and corroborate with endpoint/AD telemetry."


_METRIC_LABELS = {  # most telling first: the Result column is cut at its width
    "detections": "detections", "high_severity": "critical/high", "ot_risk_score": "OT risk", "anomalies": "anomalies",
    "findings": "findings", "candidates": "candidates", "hits": "hits", "decoded_hits": "decoded", "artifacts": "artifacts",
    "executable_artifacts": "executable", "scanners": "scanners", "high_risk_ops": "high-risk operations",
    "write_ops": "writes", "control_ops": "control operations", "total_changes": "value changes", "commands": "commands",
    "requests": "requests", "responses": "responses",
}


def _metrics_result(metrics: dict) -> str:
    """A deep dive's result in words: ``10 detections · 3 critical/high``."""
    parts = []
    for key, label_text in _METRIC_LABELS.items():
        value = metrics.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value:
            parts.append(f"{st.count(value)} {label_text}" if key != "ot_risk_score" else f"OT risk {value}/100")
    return st.join(parts) or "nothing found"


def _posture(summary: OverviewSummary) -> tuple[object, str, list[str]]:
    """The hunt posture: (severity, verdict, reasons)."""
    detail = dict(summary.summary_details or {})
    modules = {r.module: r for r in summary.module_results or []}
    threats = modules.get("threats")
    high_sev = int(threats.metrics.get("high_severity", 0) or 0) if threats else 0
    ot_risk = int(threats.metrics.get("ot_risk_score", 0) or 0) if threats else 0
    scanners = int(modules["scan"].metrics.get("scanners", 0) or 0) if "scan" in modules else 0
    leads = list(summary.hunt_leads or [])
    high_leads = [lead for lead in leads if str(lead.get("priority", "")).lower() == "high"]
    medium_leads = [lead for lead in leads if str(lead.get("priority", "")).lower() == "medium"]
    cross_zone_ot = int(detail.get("cross_zone_ot_iot_flows", 0) or 0)
    reasons = [text for cond, text in (
        (high_sev, f"{st.plural(high_sev, 'critical/high threat detection')}"),
        (high_leads, f"{st.plural(len(high_leads), 'high-priority lead')}"),
        (scanners, f"{st.plural(scanners, 'scanning source')}"),
        (cross_zone_ot, f"{st.plural(cross_zone_ot, 'OT/IoT cross-boundary flow')}"),
        (ot_risk >= 60, f"OT risk posture {ot_risk}/100"),
    ) if cond]
    if high_sev >= 2 or (high_sev >= 1 and high_leads):
        return "high", "active threat indicators: prioritize investigation now", reasons
    if high_sev >= 1 or high_leads:
        return "medium", "suspicious: corroborate the leads before escalating", reasons
    if scanners or cross_zone_ot or medium_leads:
        return "medium", "elevated exposure or reconnaissance: review boundary and scan activity", reasons
    return None, "baseline: no strong attack signal (scoping / triage pass)", reasons


def _key(text: object) -> str:
    return str(text or "").strip().lower().rstrip(".")


def _window(start: object, end: object) -> str:
    """A compact first..last time (exact with -v)."""
    first, last = _overview_ts(start), _overview_ts(end)
    if first is None and last is None:
        return "-"
    return st.ts_range(first if first is not None else last, last if last is not None else first)


def render_overview_summary(summary: OverviewSummary, verbose: bool = False) -> str:
    rep = st.Report("Overview", summary.path)
    detail = dict(summary.summary_details or {})
    modules = {r.module: r for r in summary.module_results or []}
    severity, verdict, reasons = _posture(summary)
    ot_families = list(summary.ot_protocols or [])
    # The capture window to the tenth of a second, as the other reports give
    # it (capture_span_seconds is whole seconds: 1m 17.0s beside 1m 17.2s).
    if summary.capture_start is not None and summary.capture_end is not None:
        span = max(0.0, float(summary.capture_end) - float(summary.capture_start))
    else:
        span = int(detail.get("capture_span_seconds", 0) or 0) or summary.duration_seconds
    rep.headline(severity, verdict, st.join([
        f"{'OT/ICS' if ot_families else 'IT/enterprise'} capture",
        f"{st.count(summary.total_packets)} packets",
        st.duration(span) if span else "",
        f"{st.plural(int(detail.get('unique_ips', 0) or 0), 'host')} ({int(detail.get('internal_ips', 0) or 0)} internal, "
        f"{int(detail.get('public_ips', 0) or 0)} public)",
        st.ts_range(summary.capture_start, summary.capture_end) if summary.capture_start else "",
    ]))
    if reasons:
        rep.scope("why: " + "; ".join(reasons))
    if ot_families:
        rep.scope("OT/ICS families: " + ", ".join(ot_families[:10]))
    shown: set[str] = {_key(verdict), _key("Detected OT/ICS protocol families: " + ", ".join(ot_families[:10]))}

    threats = modules.get("threats")
    high_sev = int(threats.metrics.get("high_severity", 0) or 0) if threats else 0
    named = [h for h in (threats.highlights if threats else []) if h and not _key(h).startswith(("detections:", "ot risk score"))
             and "no threat detections" not in _key(h)]
    shown.update(_key(h) for h in named)
    rep.section("Critical/high detections", (st.bullets([_redact_in_text(str(h)) for h in named], max_items=6)
                                             + ([st.dim(f"  +{high_sev - len(named)} more: pcapper <capture> --threats")]
                                                if high_sev > len(named) else [])) if high_sev else [])

    queue: list[dict] = []
    seen_entities: set[str] = set()
    rank = {"high": 0, "medium": 1, "low": 2}
    for lead in sorted(summary.hunt_leads or [], key=lambda lead: (rank.get(str(lead.get("priority", "")).lower(), 3), -int(lead.get("score", 0) or 0))):
        entity = str(lead.get("entity", "")).strip()
        if entity and entity not in seen_entities:
            seen_entities.add(entity)
            queue.append(lead)
    lead_lines: list[str] = []
    pad = " " * (5 + st.BADGE_W + 1)
    for idx, lead in enumerate(queue if st.verbose() else queue[:5], start=1):
        priority = str(lead.get("priority", "medium")).lower()
        entity = str(lead.get("entity", "-")).strip()
        finding = str(lead.get("finding", "")).strip()
        evidence = _redact_in_text(str(lead.get("evidence", "") or "").strip())
        when = _window(lead.get("first_seen"), lead.get("last_seen"))
        lead_lines.append(f"  {idx}. {st.badge(priority)} {st.strong(entity)}  {finding}")
        if evidence and _key(evidence) not in shown:
            lead_lines.append(pad + st.dim(st.cut("evidence: " + evidence, 140)))
        if when != "-":
            lead_lines.append(pad + st.dim(f"when: {when}"))
        command = _overview_next_command(entity)
        if command:
            lead_lines.append(pad + st.dim(f"next: pcapper <capture> {command}"))
        lead_lines.append(pad + st.dim(f"check: {_overview_lead_lookfor(finding)}"))
        shown.update({_key(finding), _key(evidence), _key(f"{entity}: {finding}")})
    if not st.verbose() and len(queue) > 5:
        lead_lines.append(st.more(len(queue) - 5, "lead"))
    rep.section("Immediate leads", lead_lines)

    deep_rows = []
    for result in summary.module_results or []:
        top = next((h for h in result.highlights if _key(h) not in shown and not _key(h).startswith("no ")), "")
        deep_rows.append([result.module, _metrics_result(result.metrics), _redact_in_text(str(top)) or "-", result.reason])
        shown.add(_key(top))
    rep.section("Deep dives (auto-run)", st.table(
        ["Module", "Result", "Top finding"] + (["Why it ran"] if st.verbose() else []),
        [row if st.verbose() else row[:3] for row in deep_rows], widths=(None, 50, 70), max_rows=None,
    ))

    for title, items in (("Threat hunt", summary.hunt_highlights), ("Forensics", summary.forensics_highlights),
                         ("OT/ICS", summary.ot_highlights), ("CTF", summary.ctf_highlights)):
        fresh = []
        for item in items or []:
            if _key(item) not in shown:
                shown.add(_key(item))
                fresh.append(_redact_in_text(str(item)))
        rep.section(f"{title} highlights", st.bullets(fresh, max_items=6))

    rep.section("Recommended actions", st.bullets([_redact_in_text(str(r)) for r in (summary.recommendations or [])], max_items=4))
    benign = []
    if ot_families:
        benign.append("OT is deterministic: steady internal HMI<->PLC polling and cyclic I/O are baseline, not C2 -- check a process "
                      "baseline before chasing periodicity")
    if int(detail.get("public_ips", 0) or 0) and not high_sev:
        benign.append("public peers without a high-severity detection are often CDN / cloud / update / NTP -- confirm reputation "
                      "before treating egress as exfiltration")
    benign.append("activity inside a documented maintenance window with an open change ticket is a false positive by default")
    rep.section("Likely benign", st.bullets(benign, max_items=None))

    ip_rows = list(summary.ip_activity or summary.observed_ips or [])
    # Ranked by volume: the top 10 and the bottom 10 (the analyzer keeps the
    # tail of each ranking beyond its top 24).
    host_items = ip_rows + (list(getattr(summary, "ip_activity_tail", None) or []) if summary.ip_activity else [])
    host_table = []
    for item in host_items:
        if not isinstance(item, dict):
            continue
        role = _short_browser_role(item.get("browser_roles", []) or []) or str(item.get("role", "mixed") or "mixed")
        scope = str(item.get("scope", "") or "")
        peers = _overview_list_preview(item.get("top_peers"), limit=2)
        peer_count = int(item.get("peer_count", 0) or 0)
        host_table.append([
            f"{item.get('ip', '-')}" + (f" ({item.get('hostname')})" if item.get("hostname") else ""), f"{scope}/{role}" if scope else role,
            _overview_activity_text(item), _window(item.get("first_seen"), item.get("last_seen")),
            f"{st.count(int(item.get('packets_total', 0) or 0))} pkts / {st.size(int(item.get('bytes_total', 0) or 0))}",
            (f"{peers} (of {peer_count})" if peers != "-" else str(peer_count)) if peer_count else peers,
        ])
    rep.section("Hosts", st.ranked(["Host", "Role", "What", "When", "Volume", "Top peers"], host_table,
                                   widths=(32, 26, 48, None, None, 44), noun="host",
                                   total=int(getattr(summary, "ip_activity_total", 0) or 0) if summary.ip_activity else None))
    devices = _overview_detected_devices(ip_rows, limit=10**6)
    rep.section("Devices", st.table(
        ["Device", "Role", "Likely type", "Signals", "Services", "Ports", "When"],
        [[d["ip"], d["role"], d["profile"], d["signals"], d["services"], d["ports"], _window(d.get("first_seen"), d.get("last_seen"))
          if d.get("first_seen") is not None else d["when"]] for d in devices],
        widths=(32, 22, None, 44, 38, 20), max_rows=6, noun="device",
    ))
    protocols = [p for p in (summary.protocol_activity or []) if isinstance(p, dict)]
    if protocols:
        protocols += [p for p in (getattr(summary, "protocol_activity_tail", None) or []) if isinstance(p, dict)]
        proto_table = st.ranked(
            ["Protocol", "Packets", "Bytes", "Flows", "Hosts", "When", "Ports"],
            [[p.get("protocol", "-"), st.count(int(p.get("packets", 0) or 0))]
             # Link/transport layers carry packet counts only: "-" rather than 0 B / 0 flows.
             + ([st.size(int(p.get("bytes", 0) or 0)), st.count(int(p.get("flow_count", 0) or 0)), int(p.get("host_count", 0) or 0)]
                if int(p.get("flow_count", 0) or 0) or int(p.get("bytes", 0) or 0) else ["-", "-", "-"])
             + [_window(p.get("first_seen"), p.get("last_seen")), _overview_list_preview(p.get("top_ports"), 3)]
             for p in protocols], align="lrrrrll", noun="protocol",
            total=int(getattr(summary, "protocol_activity_total", 0) or 0) or None)
    else:
        total = sum(int(c) for _n, c in summary.observed_protocols or []) or 1
        proto_table = st.ranked(["Protocol", "Packets", "Share"], [[n, st.count(int(c)), f"{int(c) / total:.1%}"]
                                                                  for n, c in summary.observed_protocols or []],
                                align="lrr", noun="protocol")
    rep.section("Protocols", proto_table)
    services = [x for x in (summary.service_activity or []) if isinstance(x, dict)]
    if services:
        services += [x for x in (getattr(summary, "service_activity_tail", None) or []) if isinstance(x, dict)]
        svc_table = st.ranked(
            ["Service", "Assets", "Hosts/clients", "When", "Traffic", "Top hosts"],
            [[x.get("service", "-"), int(x.get("asset_count", 0) or 0), f"{int(x.get('host_count', 0) or 0)}/{int(x.get('client_count', 0) or 0)}",
              _window(x.get("first_seen"), x.get("last_seen")),
              f"{st.count(int(x.get('packets', 0) or 0))} pkts / {st.size(int(x.get('bytes', 0) or 0))}", _overview_list_preview(x.get("top_hosts"), 2)]
             for x in services], align="lrrlll", noun="service",
            total=int(getattr(summary, "service_activity_total", 0) or 0) or None)
    else:
        total = sum(int(c) for _n, c in summary.observed_services or []) or 1
        svc_table = st.ranked(["Service", "Count", "Share"], [[n, st.count(int(c)), f"{int(c) / total:.1%}"] for n, c in summary.observed_services or []],
                              align="lrr", noun="service")
    rep.section("Services", svc_table)
    flows = [f for f in (summary.notable_flows or []) if isinstance(f, dict)]
    rep.section("Notable flows", st.table(
        ["Flow", "Protocol / ports", "When", "Packets", "Bytes", "Rate"],
        [[st.flow(f.get("src", "-"), f.get("dst", "-")),
          st.join([f.get("protocol", "-"), f"[{f.get('scope_pair')}]" if f.get("scope_pair") else "",
                   _overview_list_preview(f.get("ports"), 3) if _overview_list_preview(f.get("ports"), 3) != "-" else ""], " "),
          _window(f.get("start_ts"), f.get("end_ts")), st.count(int(f.get("packets", 0) or 0)), st.size(int(f.get("bytes", 0) or 0)),
          _overview_rate_text(f)] for f in flows],
        align="lllrrl", max_rows=6, noun="flow",
    ))
    gaps = list(summary.errors or [])
    module_errors = int(detail.get("module_errors", 0) or 0)
    rep.section("Errors and gaps", ([st.dim(f"  coverage gaps ({module_errors} deep-dive errors): findings are a lower bound")] if gaps or module_errors else [])
                + [f"  {st.caution('!')} {_redact_in_text(str(g))}" for g in (gaps if st.verbose() else gaps[:8])])

    top_talker = ip_rows[0] if ip_rows and isinstance(ip_rows[0], dict) else None
    iot = [label_text for label_text in ot_families if any(t in str(label_text).lower() for t in ("mqtt", "coap"))]
    rep.section("Capture", st.kv([
        st.path_field(summary),
        ("Window", f"{format_ts(summary.capture_start)} / {format_ts(summary.capture_end)}" if summary.capture_start else ""),
        ("Duration", format_duration(summary.duration_seconds)),
        ("Top protocols", st.top(dict(summary.top_protocols or []), None)),
        ("Top services", st.top(dict(summary.top_services or []), None)),
        ("Top talker", f"{top_talker.get('ip', '-')} ({int(top_talker.get('packets_total', 0) or 0)} packets, "
                       f"{format_bytes_as_mb(int(top_talker.get('bytes_total', 0) or 0))})" if top_talker else ""),
        ("Counts", st.join([f"{k.replace('_', ' ')} {v}" for k, v in detail.items() if isinstance(v, (int, float)) and not isinstance(v, bool)])),
        ("IoT families", ", ".join(iot)),
        ("Deep dives run", ", ".join(summary.modules_run or [])),
    ]), detail=True)
    extra = []
    for result in summary.module_results or []:
        more = [h for h in result.highlights[1:] if _key(h) not in shown]
        if more:
            extra.append(f"  {st.strong(result.module)}")
            extra += st.bullets([_redact_in_text(str(h)) for h in more], max_items=None, indent=4)
        extra += [f"    {st.caution('!')} {e}" for e in (result.errors or [])]
    rep.section("Deep-dive detail", extra, detail=True)
    return rep.render()
