"""Rendered output for hosts analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    danger,
    header,
    label,
    muted,
    ok,
    warn,
)
from ..hosts import HostSummary
from ..utils import (
    format_bytes_as_mb,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _apply_verbose_limit,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
    _redact_in_text,
    _truncate_text,
)


def render_hosts_summary(
    summary: HostSummary, limit: int = 30, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit)
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"HOST INVENTORY :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors if verbose else summary.errors[: _limit_value(20)]:
            lines.append(danger(f"- {err}"))
        if not verbose and len(summary.errors) > 20:
            lines.append(muted(f"... {len(summary.errors) - 20} more errors"))

    total_hosts = summary.total_hosts or len(summary.hosts)
    with_macs = sum(1 for host in summary.hosts if host.mac_addresses)
    with_hostnames = sum(1 for host in summary.hosts if host.hostnames)
    with_os = sum(
        1
        for host in summary.hosts
        if host.operating_system and host.operating_system.lower() != "unknown"
    )
    total_bytes = sum(host.bytes_sent + host.bytes_recv for host in summary.hosts)

    lines.append(_format_kv("Total Hosts", str(total_hosts)))
    lines.append(_format_kv("Hosts w/ MAC", str(with_macs)))
    lines.append(_format_kv("Hosts w/ Hostname", str(with_hostnames)))
    lines.append(_format_kv("Hosts w/ OS Guess", str(with_os)))
    lines.append(_format_kv("Total Host Traffic", format_bytes_as_mb(total_bytes)))

    # Host-risk assessment (verdict / deterministic checks / risk matrix) is
    # sourced from a disabled enrichment builder, so it was emitting a fixed
    # "NO STRONG SIGNAL" verdict, nine "no evidence" check lines, and an empty
    # risk matrix on every capture. Render only when actually populated.
    checks = getattr(summary, "deterministic_checks", {}) or {}
    check_labels = [
        ("service_exposure_risk", "Service Exposure Risk"),
        ("identity_drift_or_collision", "Identity Drift or Collision"),
        ("boundary_cross_zone_exposure", "Boundary Cross-Zone Exposure"),
        ("ot_it_boundary_crossing", "OT/IT Boundary Crossing"),
        ("evidence_provenance", "Evidence Provenance"),
    ]
    _has_checks = any(
        [str(v) for v in list(checks.get(key, []) or []) if str(v).strip()]
        for key, _ in check_labels
    )

    if summary.analyst_verdict:
        verdict = str(summary.analyst_verdict)
        confidence = str(
            getattr(summary, "analyst_confidence", "low") or "low"
        ).capitalize()
        reasons = [
            str(v)
            for v in list(getattr(summary, "analyst_reasons", []) or [])
            if str(v).strip()
        ]
        lines.append(SUBSECTION_BAR)
        lines.append(header("Analyst Verdict"))
        if verdict.startswith("YES"):
            lines.append(danger(verdict))
        elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
            lines.append(warn(verdict))
        else:
            lines.append(ok(verdict))
        lines.append(_format_kv("Confidence", confidence))
        if reasons:
            lines.append(muted("Why confidence:"))
            for reason in reasons[: _limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(reason)}"))

    if _has_checks:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Deterministic Host Security Checks"))
        for key, label_text in check_labels:
            values = [
                str(v) for v in list(checks.get(key, []) or []) if str(v).strip()
            ]
            if not values:
                continue
            lines.append(label(label_text))
            lines.append(
                warn(
                    f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"
                )
            )
            for value in values[: _limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(value)}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Host Table"))
    if not summary.hosts:
        lines.append(muted("No host entries discovered in the capture."))
    else:
        rows = [["IP", "MAC", "Hostname", "OS", "Sent", "Recv", "Open Ports"]]

        def _join_limited(values: list[str], max_items: int, max_len: int) -> str:
            if not values:
                return "-"
            display = ", ".join(values[:max_items])
            if len(values) > max_items:
                display += "..."
            return _truncate_text(display, max_len)

        def _format_ports(ports: list[object]) -> str:
            if not ports:
                return "-"
            entries: list[str] = []
            for port in ports:
                proto = str(getattr(port, "protocol", "") or "").lower() or "-"
                service = str(getattr(port, "service", "") or "-")
                label_text = f"{int(getattr(port, 'port', 0) or 0)}/{proto} {service}"
                if verbose:
                    software = str(getattr(port, "software", "") or "")
                    if software:
                        label_text = f"{label_text} ({software})"
                entries.append(label_text)
            port_limit = _limit_value(6)
            display = ", ".join(
                _truncate_text(item, 48) for item in entries[:port_limit]
            )
            if len(entries) > port_limit:
                display += "..."
            return display or "-"

        row_hosts = summary.hosts if verbose else summary.hosts[:limit]
        for host in row_hosts:
            mac_display = _join_limited(host.mac_addresses, _limit_value(3), 48)
            host_display = _join_limited(host.hostnames, _limit_value(3), 48)
            os_display = _truncate_text(host.operating_system or "Unknown", 28)
            sent_display = (
                f"{format_bytes_as_mb(host.bytes_sent)} ({host.packets_sent})"
            )
            recv_display = (
                f"{format_bytes_as_mb(host.bytes_recv)} ({host.packets_recv})"
            )
            ports_display = _format_ports(host.open_ports)
            rows.append(
                [
                    host.ip,
                    mac_display,
                    host_display,
                    os_display,
                    sent_display,
                    recv_display,
                    ports_display,
                ]
            )
        lines.append(_format_table(rows))
        if not verbose and len(summary.hosts) > limit:
            lines.append(muted(f"... {len(summary.hosts) - limit} additional hosts"))

    host_risks = list(getattr(summary, "host_risk_profiles", []) or [])
    if host_risks:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Priority Host Queue"))
        rows = [["Host", "Score", "Severity", "Confidence", "OS", "Reasons"]]
        for item in host_risks[: _limit_value(limit if verbose else 15)]:
            reasons_val = item.get("reasons", [])
            rows.append(
                [
                    str(item.get("host", "-")),
                    str(item.get("score", "-")),
                    str(item.get("severity", "-")),
                    str(item.get("confidence", "-")),
                    _truncate_text(str(item.get("os", "-")), 32),
                    _truncate_text(
                        ", ".join(
                            str(v)
                            for v in (
                                reasons_val[:3] if isinstance(reasons_val, list) else []
                            )
                        )
                        or "-",
                        90,
                    ),
                ]
            )
        lines.append(_format_table(rows))

    lateral_profiles = list(getattr(summary, "lateral_movement_profiles", []) or [])
    if lateral_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Lateral Movement Analytics"))
        rows = [["Host", "Admin Ports", "Port Count", "Confidence"]]
        for item in lateral_profiles[: _limit_value(limit if verbose else 12)]:
            ports = item.get("admin_ports", [])
            rows.append(
                [
                    str(item.get("host", "-")),
                    ", ".join(
                        str(v) for v in (ports[:8] if isinstance(ports, list) else [])
                    )
                    or "-",
                    str(item.get("admin_port_count", "-")),
                    str(item.get("confidence", "-")),
                ]
            )
        lines.append(_format_table(rows))

    role_drift = list(getattr(summary, "role_drift_profiles", []) or [])
    if role_drift:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Role Drift Profiles"))
        rows = [["Host", "Roles", "Hostnames", "Admin Ports", "OS"]]
        for item in role_drift[: _limit_value(limit if verbose else 12)]:
            roles = item.get("roles", [])
            hostnames = item.get("hostnames", [])
            admin_ports = item.get("admin_ports", [])
            rows.append(
                [
                    str(item.get("host", "-")),
                    _truncate_text(
                        ", ".join(
                            str(v)
                            for v in (roles[:4] if isinstance(roles, list) else [])
                        )
                        or "-",
                        50,
                    ),
                    _truncate_text(
                        ", ".join(
                            str(v)
                            for v in (
                                hostnames[:3] if isinstance(hostnames, list) else []
                            )
                        )
                        or "-",
                        70,
                    ),
                    _truncate_text(
                        ", ".join(
                            str(v)
                            for v in (
                                admin_ports[:8] if isinstance(admin_ports, list) else []
                            )
                        )
                        or "-",
                        40,
                    ),
                    _truncate_text(str(item.get("os", "-")), 28),
                ]
            )
        lines.append(_format_table(rows))

    identity_drift = list(getattr(summary, "identity_drift_profiles", []) or [])
    if identity_drift:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Identity Drift Profiles"))
        rows = [["Hostname", "Host Count", "Hosts"]]
        for item in identity_drift[: _limit_value(limit if verbose else 12)]:
            hosts = item.get("hosts", [])
            rows.append(
                [
                    _truncate_text(str(item.get("hostname", "-")), 50),
                    str(item.get("host_count", "-")),
                    _truncate_text(
                        ", ".join(
                            str(v)
                            for v in (hosts[:6] if isinstance(hosts, list) else [])
                        )
                        or "-",
                        90,
                    ),
                ]
            )
        lines.append(_format_table(rows))

    clusters = list(getattr(summary, "incident_clusters", []) or [])
    if clusters:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Incident Clusters"))
        rows = [["Cluster", "Host", "Indicators", "Targets", "Confidence"]]
        for item in clusters[: _limit_value(limit if verbose else 12)]:
            indicators = item.get("indicators", [])
            rows.append(
                [
                    str(item.get("cluster", "-")),
                    str(item.get("host", "-")),
                    str(len(indicators) if isinstance(indicators, list) else 0),
                    str(item.get("target_count", "-")),
                    str(item.get("confidence", "-")),
                ]
            )
        lines.append(_format_table(rows))

    false_positive = [
        str(v)
        for v in list(getattr(summary, "false_positive_context", []) or [])
        if str(v).strip()
    ]
    if false_positive:
        lines.append(SUBSECTION_BAR)
        lines.append(header("False-Positive Context"))
        for note in false_positive[: _limit_value(8)]:
            lines.append(muted(f"- {_redact_in_text(note)}"))

    if verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OS Evidence"))
        evidence_rows = [["IP", "OS Guess", "Evidence"]]
        for host in summary.hosts:
            if not host.os_evidence:
                continue
            evidence_rows.append(
                [
                    host.ip,
                    host.operating_system or "Unknown",
                    _truncate_text(" | ".join(host.os_evidence), 120),
                ]
            )
        if len(evidence_rows) == 1:
            lines.append(muted("No OS fingerprinting evidence captured for hosts."))
        else:
            lines.append(_format_table(evidence_rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Forensics Notes"))
    lines.append(
        muted(
            "- OS guesses are passive and should be confirmed with endpoint telemetry."
        )
    )
    lines.append(
        muted(
            "- Open ports are inferred from server-side responses or banners; absence does not imply closed."
        )
    )
    lines.append(
        muted(
            "- MACs are derived from IP/Ethernet/ARP mapping and can change across segments."
        )
    )

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
