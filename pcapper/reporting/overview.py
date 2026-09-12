"""Rendered output for overview analysis.

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
from ..overview import OverviewSummary
from ..utils import (
    format_bytes_as_mb,
    format_duration,
    format_speed_bps,
    format_ts,
)

from ._common import (
    SUBSECTION_BAR,
    _always_full_render,
    _finalize_output,
    _format_counter,
    _format_kv,
    _format_table,
    _highlight_public_ips,
    _limit_value,
    _redact_in_text,
    _short_browser_role,
    _truncate_text,
)


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
        return danger
    if priority == "MEDIUM":
        return warn
    return muted


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


def _overview_hunt_lead_section(summary: OverviewSummary, verbose: bool) -> list[str]:
    """Front-load the overview with a hunt-lead briefing: posture verdict,
    capture characterization, a prioritized triage queue with the exact command
    to run for each lead, hunt hypotheses, and likely-benign guidance."""
    lines: list[str] = []
    detail = dict(getattr(summary, "summary_details", {}) or {})
    module_lookup = {
        result.module: result for result in getattr(summary, "module_results", []) or []
    }
    threats = module_lookup.get("threats")
    high_sev = int(threats.metrics.get("high_severity", 0) or 0) if threats else 0
    ot_risk = int(threats.metrics.get("ot_risk_score", 0) or 0) if threats else 0
    scanners = 0
    scan_result = module_lookup.get("scan")
    if scan_result:
        scanners = int(scan_result.metrics.get("scanners", 0) or 0)
    leads = list(getattr(summary, "hunt_leads", []) or [])
    high_leads = [l for l in leads if str(l.get("priority", "")).lower() == "high"]
    med_leads = [l for l in leads if str(l.get("priority", "")).lower() == "medium"]
    cross_zone_ot = int(detail.get("cross_zone_ot_iot_flows", 0) or 0)

    # --- Posture verdict -------------------------------------------------
    reasons: list[str] = []
    if high_sev:
        reasons.append(f"{high_sev} critical/high threat detection(s)")
    if high_leads:
        reasons.append(f"{len(high_leads)} high-priority lead(s)")
    if scanners:
        reasons.append(f"{scanners} scanning source(s)")
    if cross_zone_ot:
        reasons.append(f"{cross_zone_ot} OT/IoT cross-boundary flow(s)")
    if ot_risk >= 60:
        reasons.append(f"OT risk posture {ot_risk}/100")

    if high_sev >= 2 or (high_sev >= 1 and high_leads):
        verdict = "ACTIVE THREAT INDICATORS - prioritize investigation now."
        style = danger
    elif high_sev >= 1 or high_leads:
        verdict = "SUSPICIOUS - corroborate the leads below before escalating."
        style = warn
    elif scanners or cross_zone_ot or med_leads:
        verdict = "ELEVATED EXPOSURE/RECON - review boundary and scan activity."
        style = warn
    else:
        verdict = "BASELINE - no strong attack signal; treat as scoping/triage pass."
        style = ok

    lines.append(SUBSECTION_BAR)
    lines.append(header("Hunt Lead Assessment"))
    lines.append(style(verdict))
    if reasons:
        lines.append(muted("Why: " + "; ".join(reasons[: _limit_value(5)])))

    # --- Capture characterization ---------------------------------------
    ot_families = list(getattr(summary, "ot_protocols", []) or [])
    env = "OT/ICS" if ot_families else "IT/enterprise"
    internal_ips = int(detail.get("internal_ips", 0) or 0)
    public_ips = int(detail.get("public_ips", 0) or 0)
    span = int(detail.get("capture_span_seconds", 0) or 0)
    char_bits = [
        f"{env} capture",
        f"{int(summary.total_packets)} pkts",
    ]
    if span > 0:
        char_bits.append(format_duration(float(span)))
    char_bits.append(f"{int(detail.get('unique_ips', 0) or 0)} hosts ({internal_ips} internal / {public_ips} public)")
    if ot_families:
        char_bits.append("families: " + ", ".join(ot_families[: _limit_value(6)]))
    lines.append(muted("Capture: " + "; ".join(char_bits) + "."))

    # --- Name the high/critical detections behind the count -------------
    # Otherwise "N critical/high threat detection(s)" is an unexplained number
    # the analyst cannot find anywhere else in the report.
    if threats and high_sev > 0:
        shown = [
            h
            for h in (getattr(threats, "highlights", []) or [])
            if h
            and not str(h).lower().startswith(("detections:", "ot risk score"))
            and "no threat detections" not in str(h).lower()
        ][: _limit_value(4)]
        if shown:
            lines.append(muted(f"Critical/high detections ({high_sev}):"))
            for h in shown:
                lines.append(
                    muted(f"  - {_redact_in_text(_truncate_text(str(h), 150))}")
                )

    # --- Triage queue: where to focus first -----------------------------
    queue = (high_leads + med_leads + leads)
    seen_entities: set[str] = set()
    ordered_queue: list[dict] = []
    for lead in queue:
        ent = str(lead.get("entity", "")).strip()
        if ent in seen_entities:
            continue
        seen_entities.add(ent)
        ordered_queue.append(lead)
    if ordered_queue:
        lines.append(header("Focus Here First"))
        for idx, lead in enumerate(ordered_queue[: _limit_value(5)], start=1):
            priority = str(lead.get("priority", "medium")).upper()
            entity = str(lead.get("entity", "-")).strip()
            finding = str(lead.get("finding", "")).strip()
            pstyle = _overview_priority_style(priority)
            lines.append(
                pstyle(f"{idx}. [{priority}] {_highlight_public_ips(entity)} - {finding}")
            )
            cmd = _overview_next_command(entity)
            if cmd:
                lines.append(muted(f"   run:  pcapper <capture> {cmd}"))
            lines.append(muted(f"   check: {_overview_lead_lookfor(finding)}"))

    # --- Hunt hypotheses / recommended actions --------------------------
    recs = list(getattr(summary, "recommendations", []) or [])
    if recs:
        lines.append(header("Recommended Hunt Actions"))
        for rec in recs[: _limit_value(6)]:
            lines.append(muted(f"- {_redact_in_text(_truncate_text(str(rec), 200))}"))

    # --- Likely benign / don't chase ------------------------------------
    benign: list[str] = []
    if ot_families:
        benign.append(
            "OT is deterministic: steady internal HMI<->PLC polling and cyclic I/O are "
            "baseline, not C2 - confirm against a process baseline before chasing periodicity."
        )
    if public_ips and not high_sev:
        benign.append(
            "Public peers without a high-severity detection are often CDN/cloud/update/NTP - "
            "confirm reputation before treating egress as exfil."
        )
    benign.append(
        "Anything inside a documented maintenance/change window with an open ticket is "
        "false-positive by default - calendar the activity first."
    )
    lines.append(header("Likely Benign / Don't Chase"))
    for item in benign[: _limit_value(4)]:
        lines.append(muted(f"- {item}"))

    gaps = list(getattr(summary, "errors", []) or [])
    module_errors = int(detail.get("module_errors", 0) or 0)
    if gaps or module_errors:
        note = "Coverage gaps present"
        if module_errors:
            note += f" ({module_errors} deep-dive error(s))"
        note += " - findings are lower-bound; see Errors/Gaps below."
        lines.append(muted(f"Caveat: {note}"))

    return lines


@_always_full_render
def render_overview_summary(summary: OverviewSummary, verbose: bool = False) -> str:
    verbose = True  # --overview always shows the complete picture
    lines = [header(f"THREAT HUNT LEAD :: {summary.path.name}")]
    lines.append(_format_kv("Capture", str(summary.path)))
    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))
    capture_window = _overview_window_text(
        getattr(summary, "capture_start", None), getattr(summary, "capture_end", None)
    )
    if capture_window != "-":
        lines.append(_format_kv("Capture Window", capture_window))
    lines.append(_format_kv("Top Protocols", _format_counter(dict(summary.top_protocols), 8)))
    lines.append(_format_kv("Top Services", _format_counter(dict(summary.top_services), 8)))
    ip_activity_rows = list(getattr(summary, "ip_activity", []) or summary.observed_ips or [])
    if ip_activity_rows:
        top_talker = ip_activity_rows[0]
        lines.append(
            _format_kv(
                "Top Talker",
                (
                    f"{top_talker.get('ip', '-')} "
                    f"({int(top_talker.get('packets_total', 0) or 0)} pkts, "
                    f"{format_bytes_as_mb(int(top_talker.get('bytes_total', 0) or 0))})"
                ),
            )
        )
    detail = dict(getattr(summary, "summary_details", {}) or {})
    if detail:
        lines.append(_format_kv("Unique IPs", str(int(detail.get("unique_ips", 0) or 0))))
        lines.append(
            _format_kv(
                "Unique Protocols",
                str(int(detail.get("unique_protocols", 0) or 0)),
            )
        )
        lines.append(
            _format_kv(
                "Unique Services",
                str(int(detail.get("unique_services", 0) or 0)),
            )
        )
        lines.append(
            _format_kv("Internal IPs", str(int(detail.get("internal_ips", 0) or 0)))
        )
        lines.append(
            _format_kv("Public IPs", str(int(detail.get("public_ips", 0) or 0)))
        )
        lines.append(
            _format_kv("Observed Flows", str(int(detail.get("flow_count", 0) or 0)))
        )
        lines.append(
            _format_kv(
                "Cross-Zone Flows",
                str(int(detail.get("cross_zone_flows", 0) or 0)),
            )
        )
        lines.append(
            _format_kv(
                "Cross-Zone OT/IoT Flows",
                str(int(detail.get("cross_zone_ot_iot_flows", 0) or 0)),
            )
        )
        lines.append(
            _format_kv("Leads", str(int(detail.get("hunt_leads", 0) or 0)))
        )
        capture_span_seconds = int(detail.get("capture_span_seconds", 0) or 0)
        if capture_span_seconds > 0:
            lines.append(
                _format_kv("Capture Span", format_duration(float(capture_span_seconds)))
            )
        lines.append(
            _format_kv(
                "Deep Dives Run",
                str(int(detail.get("module_count", len(summary.modules_run)) or 0)),
            )
        )
        lines.append(
            _format_kv(
                "Deep Dive Errors",
                str(int(detail.get("module_errors", 0) or 0)),
            )
        )
        lines.append(
            _format_kv(
                "Protocol Anomalies",
                str(int(detail.get("protocol_anomalies", 0) or 0)),
            )
        )
        lines.append(
            _format_kv("Service Risks", str(int(detail.get("service_risks", 0) or 0)))
        )
    lines.append(
        _format_kv(
            "OT/ICS Families",
            ", ".join(summary.ot_protocols[:10]) if summary.ot_protocols else "-",
        )
    )
    iot_labels = [
        str(label).strip()
        for label in summary.ot_protocols
        if str(label).strip()
        and (
            "mqtt" in str(label).lower()
            or "coap" in str(label).lower()
        )
    ]
    lines.append(
        _format_kv(
            "IoT Families",
            ", ".join(iot_labels[:8]) if iot_labels else "-",
        )
    )

    # Lead the report with the analyst-facing hunt briefing (verdict, triage
    # queue with commands, hypotheses, benign guidance); the inventory tables
    # below are the supporting evidence.
    lines.extend(_overview_hunt_lead_section(summary, verbose))

    if ip_activity_rows:
        lines.append(header("Supporting Detail :: Observed IPs"))
        rows = [["IP", "Role", "What", "When", "How Much", "Top Peers"]]
        for item in ip_activity_rows[: _limit_value(15)]:
            if not isinstance(item, dict):
                continue
            scope = str(item.get("scope", "") or "").strip()
            role = str(item.get("role", "mixed") or "mixed").strip()
            # Prefer the Browser-announced role (DC/SQL/master browser) when known.
            nb_role = _short_browser_role(item.get("browser_roles", []) or [])
            if nb_role:
                role = nb_role
            role_text = f"{scope}/{role}" if scope else role
            ip_cell = str(item.get("ip", "-"))
            nb_host = str(item.get("hostname", "") or "")
            if nb_host:
                ip_cell = f"{ip_cell} ({nb_host})"
            when_text = _overview_window_text(item.get("first_seen"), item.get("last_seen"))
            peer_text = _overview_list_preview(item.get("top_peers"), limit=2)
            peer_count = int(item.get("peer_count", 0) or 0)
            if peer_count > 0 and peer_text != "-":
                peer_text = f"{peer_text} (total={peer_count})"
            elif peer_count > 0:
                peer_text = f"total={peer_count}"
            volume = (
                f"{int(item.get('packets_total', 0) or 0)} pkts / "
                f"{format_bytes_as_mb(int(item.get('bytes_total', 0) or 0))} "
                f"(s/r {int(item.get('packets_sent', 0) or 0)}/{int(item.get('packets_recv', 0) or 0)})"
            )
            rows.append(
                [
                    _truncate_text(ip_cell, 30),
                    _truncate_text(role_text, 18),
                    _truncate_text(_overview_activity_text(item), 54),
                    _truncate_text(when_text, 54),
                    _truncate_text(volume, 54),
                    _truncate_text(peer_text, 50),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

        detected_devices = _overview_detected_devices(ip_activity_rows)
        if detected_devices:
            lines.append(header("Detected Devices Information"))
            device_rows = [["Device", "Role", "Likely Type", "Signals", "Services", "Ports", "When"]]
            for item in detected_devices:
                device_rows.append(
                    [
                        _truncate_text(str(item.get("ip", "-")), 24),
                        _truncate_text(str(item.get("role", "-")), 22),
                        _truncate_text(str(item.get("profile", "-")), 24),
                        _truncate_text(str(item.get("signals", "-")), 44),
                        _truncate_text(str(item.get("services", "-")), 38),
                        _truncate_text(str(item.get("ports", "-")), 20),
                        _truncate_text(str(item.get("when", "-")), 42),
                    ]
                )
            lines.append(_format_table(device_rows))

    protocol_activity_rows = list(getattr(summary, "protocol_activity", []) or [])
    observed_protocols = list(getattr(summary, "observed_protocols", []) or [])
    if protocol_activity_rows:
        lines.append(header("Observed Protocols"))
        rows = [["Protocol", "Pkts", "Bytes", "Flows", "Hosts", "When", "Ports"]]
        for item in protocol_activity_rows[: _limit_value(15)]:
            if not isinstance(item, dict):
                continue
            rows.append(
                [
                    _truncate_text(str(item.get("protocol", "-")), 26),
                    str(int(item.get("packets", 0) or 0)),
                    format_bytes_as_mb(int(item.get("bytes", 0) or 0)),
                    str(int(item.get("flow_count", 0) or 0)),
                    str(int(item.get("host_count", 0) or 0)),
                    _truncate_text(
                        _overview_window_text(
                            item.get("first_seen"), item.get("last_seen")
                        ),
                        52,
                    ),
                    _truncate_text(_overview_list_preview(item.get("top_ports"), 3), 24),
                ]
            )
        lines.append(_format_table(rows))
    elif observed_protocols:
        lines.append(header("Observed Protocols"))
        proto_total = sum(int(count) for _name, count in observed_protocols) or 1
        rows = [["Protocol", "Packets", "% Traffic"]]
        for name, count in observed_protocols[: _limit_value(15)]:
            pct = (int(count) / proto_total) * 100 if proto_total else 0.0
            rows.append([str(name), str(int(count)), f"{pct:.1f}%"])
        lines.append(_format_table(rows))

    service_activity_rows = list(getattr(summary, "service_activity", []) or [])
    observed_services = list(getattr(summary, "observed_services", []) or [])
    if service_activity_rows:
        lines.append(header("Observed Services"))
        rows = [["Service", "Assets", "Hosts/Clients", "When", "Traffic", "Top Hosts"]]
        for item in service_activity_rows[: _limit_value(15)]:
            if not isinstance(item, dict):
                continue
            rows.append(
                [
                    _truncate_text(str(item.get("service", "-")), 26),
                    str(int(item.get("asset_count", 0) or 0)),
                    (
                        f"{int(item.get('host_count', 0) or 0)}/"
                        f"{int(item.get('client_count', 0) or 0)}"
                    ),
                    _truncate_text(
                        _overview_window_text(
                            item.get("first_seen"), item.get("last_seen")
                        ),
                        52,
                    ),
                    _truncate_text(
                        (
                            f"{int(item.get('packets', 0) or 0)} pkts / "
                            f"{format_bytes_as_mb(int(item.get('bytes', 0) or 0))}"
                        ),
                        42,
                    ),
                    _truncate_text(_overview_list_preview(item.get("top_hosts"), 2), 44),
                ]
            )
        lines.append(_format_table(rows))
    elif observed_services:
        lines.append(header("Observed Services"))
        svc_total = sum(int(count) for _name, count in observed_services) or 1
        rows = [["Service", "Count", "% Service Share"]]
        for name, count in observed_services[: _limit_value(15)]:
            pct = (int(count) / svc_total) * 100 if svc_total else 0.0
            rows.append([str(name), str(int(count)), f"{pct:.1f}%"])
        lines.append(_format_table(rows))

    notable_flows = list(getattr(summary, "notable_flows", []) or [])
    if notable_flows:
        lines.append(header("Notable Flows"))
        rows = [["Flow", "Protocol/Ports", "When", "Packets", "Bytes", "Rate"]]
        for item in notable_flows[: _limit_value(12)]:
            if not isinstance(item, dict):
                continue
            flow_text = f"{item.get('src', '-')} -> {item.get('dst', '-')}"
            proto_text = str(item.get("protocol", "-"))
            scope_pair = str(item.get("scope_pair", "") or "").strip()
            if scope_pair:
                proto_text = f"{proto_text} [{scope_pair}]"
            ports = _overview_list_preview(item.get("ports"), 3)
            if ports != "-":
                proto_text = f"{proto_text} {ports}"
            rows.append(
                [
                    _truncate_text(flow_text, 40),
                    _truncate_text(proto_text, 46),
                    _truncate_text(
                        _overview_window_text(item.get("start_ts"), item.get("end_ts")),
                        52,
                    ),
                    str(int(item.get("packets", 0) or 0)),
                    format_bytes_as_mb(int(item.get("bytes", 0) or 0)),
                    _truncate_text(_overview_rate_text(item), 32),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    hunt_leads = list(getattr(summary, "hunt_leads", []) or [])
    if hunt_leads:
        lines.append(header("Immediate Leads"))
        for lead in hunt_leads[: _limit_value(10)]:
            if not isinstance(lead, dict):
                continue
            priority = str(lead.get("priority", "medium") or "medium").upper()
            entity = _truncate_text(str(lead.get("entity", "-")), 48)
            finding = _truncate_text(str(lead.get("finding", "")), 120)
            evidence = _truncate_text(str(lead.get("evidence", "")), 180)
            when_text = _overview_window_text(
                lead.get("first_seen"), lead.get("last_seen")
            )
            style = _overview_priority_style(priority)
            lines.append(style(f"[{priority}] {entity} - {finding}"))
            if when_text != "-":
                lines.append(muted(f"  when: {when_text}"))
            if evidence:
                lines.append(muted(f"  evidence: {evidence}"))

    if summary.module_results:
        lines.append(header("Auto-Run Deep Dives"))
        rows = [["Module", "Reason", "Metrics", "Top Highlight"]]
        for result in summary.module_results[: _limit_value(14)]:
            rows.append(
                [
                    _truncate_text(result.module, 18),
                    _truncate_text(result.reason, 56),
                    _truncate_text(_overview_metrics_text(result.metrics), 42),
                    _truncate_text(result.highlights[0] if result.highlights else "-", 64),
                ]
            )
        lines.append(_format_table(rows))
        if verbose:
            for result in summary.module_results[: _limit_value(8)]:
                extra = list(result.highlights[1:3])
                if not extra:
                    continue
                lines.append(muted(f"{result.module}:"))
                for item in extra:
                    lines.append(muted(f"  - {_truncate_text(item, 140)}"))

    if summary.ot_highlights:
        lines.append(header("OT/ICS Highlights"))
        for item in summary.ot_highlights[: _limit_value(8)]:
            lines.append(f"- {_truncate_text(item, 160)}")

    if summary.hunt_highlights:
        lines.append(header("Threat Hunt Highlights"))
        for item in summary.hunt_highlights[: _limit_value(10)]:
            lines.append(f"- {_truncate_text(item, 160)}")

    if summary.forensics_highlights:
        lines.append(header("Forensics Highlights"))
        for item in summary.forensics_highlights[: _limit_value(10)]:
            lines.append(f"- {_truncate_text(item, 160)}")

    if summary.ctf_highlights:
        lines.append(header("CTF Highlights"))
        for item in summary.ctf_highlights[: _limit_value(8)]:
            lines.append(f"- {_truncate_text(item, 160)}")

    # Recommendations are surfaced in the Hunt Lead Assessment at the top
    # (Recommended Hunt Actions); not repeated here to keep the briefing tight.

    if summary.errors:
        lines.append(header("Errors / Gaps"))
        for item in summary.errors[: _limit_value(8)]:
            lines.append(muted(f"- {_truncate_text(item, 180)}"))

    return _finalize_output(lines)
