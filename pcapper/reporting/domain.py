"""Rendered output for domain analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from typing import TYPE_CHECKING
from ..coloring import (
    danger,
    header,
    label,
    muted,
    ok,
    warn,
)
from ..services import COMMON_PORTS
if TYPE_CHECKING:
    from ..domain import DomainAnalysis

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _apply_verbose_limit,
    _counter_table,
    _filtered_detections,
    _finalize_output,
    _format_kv,
    _format_table,
    _highlight_public_ips,
    _limit_value,
    _redact_in_text,
    _truncate_text,
)


def render_domain_summary(
    summary: "DomainAnalysis", limit: int = 25, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit)

    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"MS AD & DOMAIN ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Duration", f"{summary.duration:.2f}s"))
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))

    def _domain_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        checks = getattr(summary, "deterministic_checks", {}) or {}

        def _count_check(key: str) -> int:
            items = checks.get(key, []) if isinstance(checks, dict) else []
            return len([v for v in (items or []) if str(v).strip()])

        high_impact = {
            "dcsync_replication_activity": 4,
            "kerberos_ticket_abuse": 3,
            "ntlm_downgrade_or_relay_exposure": 3,
            "ldap_bind_risk": 2,
            "auth_sequence_plausibility": 2,
            "dc_role_consistency": 2,
            "name_resolution_poisoning_context": 1,
            "privileged_account_spread": 1,
        }

        for key, weight in high_impact.items():
            count = _count_check(key)
            if not count:
                continue
            score += min(4, weight + min(2, count - 1))
            reasons.append(f"{key.replace('_', ' ')} evidence ({count})")

        high_count = sum(
            1
            for item in (summary.detections or [])
            if str(item.get("severity", "")).lower() in {"high", "critical"}
        )
        warning_count = sum(
            1
            for item in (summary.detections or [])
            if str(item.get("severity", "")).lower() == "warning"
        )
        if high_count:
            score += min(3, high_count)
            reasons.append(f"High-severity domain detections observed ({high_count})")
        if warning_count >= 2:
            score += 1
            reasons.append(
                f"Multiple warning-level domain detections observed ({warning_count})"
            )

        if score >= 8:
            verdict = "YES - high-confidence malicious or compromised domain activity is present."
            confidence = "High"
        elif score >= 5:
            verdict = "LIKELY - suspicious domain activity with compromise indicators is present."
            confidence = "Medium"
        elif score >= 2:
            verdict = "POSSIBLE - risky domain behavior is present; corroboration recommended."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing malicious domain pattern from current heuristics."
            confidence = "Low"

        if not reasons:
            reasons.append(
                "No high-confidence domain threat heuristic crossed threshold"
            )
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _domain_verdict()
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", f"{confidence} (score={verdict_score})"))
    lines.append(muted("Why confidence:"))
    for reason in verdict_reasons[: _limit_value(8)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    if summary.clients:
        lines.append(muted("Who:"))
        lines.append(muted("- Top initiating hosts"))
        for ip, count in summary.clients.most_common(_limit_value(8)):
            lines.append(muted(f"- {_highlight_public_ips(str(ip))}: {int(count)}"))
    if summary.servers:
        lines.append(muted("Where:"))
        lines.append(muted("- Top domain infrastructure targets"))
        for ip, count in summary.servers.most_common(_limit_value(8)):
            lines.append(muted(f"- {_highlight_public_ips(str(ip))}: {int(count)}"))
    if summary.detections:
        lines.append(muted("What:"))
        lines.append(muted("- Top domain detections"))
        for item in summary.detections[: _limit_value(6)]:
            lines.append(
                muted(
                    f"- [{str(item.get('severity', 'info')).upper()}] {_redact_in_text(str(item.get('summary', '-')))}"
                )
            )
    if getattr(summary, "incident_clusters", None):
        lines.append(muted("When:"))
        lines.append(muted("- Incident cluster context"))
        for item in list(summary.incident_clusters or [])[: _limit_value(4)]:
            lines.append(
                muted(
                    f"- {_redact_in_text(str(item.get('cluster', '-')))} host={_highlight_public_ips(str(item.get('host', '-')))} "
                    f"signals={len(item.get('indicators', []) if isinstance(item.get('indicators', []), list) else [])}"
                )
            )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Domain Security Checks"))
    checks = getattr(summary, "deterministic_checks", {}) or {}
    check_labels = [
        ("dc_role_consistency", "DC Role Consistency"),
        ("kerberos_ticket_abuse", "Kerberos Ticket Abuse"),
        ("kerberos_roast_or_cipher_risk", "Kerberoasting / Weak Cipher Risk"),
        ("dcsync_replication_activity", "DCSync/Replication-like Activity"),
        ("dcsync_fingerprint_evidence", "DCSync Fingerprint Evidence"),
        ("adcs_or_certificate_abuse_context", "AD CS / Certificate Abuse Context"),
        ("ldap_bind_risk", "LDAP Bind Risk"),
        ("ldap_directory_abuse_context", "LDAP Directory Abuse Context"),
        ("ntlm_downgrade_or_relay_exposure", "NTLM Downgrade/Relay Exposure"),
        ("relay_coercion_chain_context", "Relay/Coercion Chain Context"),
        ("credential_material_in_domain_flows", "Credential Material in Domain Flows"),
        ("auth_sequence_plausibility", "Authentication Sequence Plausibility"),
        ("name_resolution_poisoning_context", "Name Resolution Poisoning Context"),
        ("privileged_account_spread", "Privileged Account Spread"),
        ("identity_attack_path_correlation", "Identity Attack-Path Correlation"),
        ("public_domain_service_exposure", "Public Domain Service Exposure"),
        ("baseline_service_deviation", "Baseline Service Deviation"),
        ("ot_identity_attack_surface_overlap", "OT Identity Attack-Surface Overlap"),
    ]
    for key, label_text in check_labels:
        evidence_items = checks.get(key, []) if isinstance(checks, dict) else []
        evidence_items = [str(v) for v in (evidence_items or []) if str(v).strip()]
        lines.append(label(label_text))
        if evidence_items:
            lines.append(
                warn(
                    f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"
                )
            )
            for item in evidence_items[: _limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))
        else:
            lines.append(
                ok(
                    f"No, there is no strong evidence for {label_text.lower()} in this capture."
                )
            )

    if summary.domains:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Domain Names"))
        lines.append(_counter_table(summary.domains, "Domain", limit=limit))

    if summary.dc_hosts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Domain Controllers (NetBIOS/DNS)"))
        lines.append(_counter_table(summary.dc_hosts, "IP", limit=limit))

    # Passive domain intelligence from Browser (MS-BRWS) announcements.
    nb_domains = getattr(summary, "netbios_domains", None)
    browser_roles = getattr(summary, "browser_roles", None) or {}
    if nb_domains or browser_roles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Browser-Announced Domain Intelligence (MS-BRWS)"))
        if nb_domains:
            lines.append(
                _format_kv(
                    "Announced Workgroup/Domain",
                    ", ".join(
                        f"{d} ({c} announcements)" for d, c in nb_domains.most_common(limit)
                    ),
                )
            )
        if browser_roles:
            rows = [["Host IP", "Announced Server Roles"]]
            for ip, roles in list(browser_roles.items())[:limit]:
                role_txt = ", ".join(roles)
                is_infra = any(
                    r in role_txt
                    for r in ("Domain Controller", "Master Browser", "SQL Server")
                )
                rows.append([ip, danger(role_txt) if is_infra else role_txt])
            lines.append(_format_table(rows))

    if summary.service_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Domain Services"))
        rows = [["Service", "Name", "Count"]]
        for svc, count in summary.service_counts.most_common(limit):
            svc_name = "-"
            try:
                _proto, port_str = svc.split("/", 1)
                port = int(port_str)
                svc_name = COMMON_PORTS.get(port, "-")
            except Exception:
                svc_name = "-"
            rows.append([svc, svc_name, str(count)])
        lines.append(_format_table(rows))

    if summary.servers or summary.clients:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Domain Servers & Clients"))
        rows = [["Servers", "Clients"]]
        server_text = (
            ", ".join(
                f"{ip}({count})"
                for ip, count in summary.servers.most_common(_limit_value(10))
            )
            or "-"
        )
        client_text = (
            ", ".join(
                f"{ip}({count})"
                for ip, count in summary.clients.most_common(_limit_value(10))
            )
            or "-"
        )
        rows.append([server_text, client_text])
        lines.append(_format_table(rows))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Domain Conversations"))
        rows = [["Src", "Dst", "Port", "Proto", "Packets"]]
        for convo in summary.conversations[:limit]:
            rows.append(
                [
                    convo.src_ip,
                    convo.dst_ip,
                    str(convo.dst_port),
                    convo.proto,
                    str(convo.packets),
                ]
            )
        lines.append(_format_table(rows))

    if getattr(summary, "host_attack_paths", None):
        paths = list(summary.host_attack_paths or [])
        if paths:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Host-Centric Attack Paths"))
            rows = [["Host", "Confidence", "Targets", "Steps"]]
            for item in paths[:limit]:
                targets = item.get("targets", [])
                step_values = item.get("steps", [])
                target_text = (
                    ", ".join(str(v) for v in targets[:3])
                    if isinstance(targets, list) and targets
                    else "-"
                )
                steps_text = (
                    "; ".join(str(v) for v in step_values[:3])
                    if isinstance(step_values, list) and step_values
                    else "-"
                )
                rows.append(
                    [
                        _highlight_public_ips(str(item.get("host", "-"))),
                        str(item.get("confidence", "-")),
                        _truncate_text(target_text, 40),
                        _truncate_text(steps_text, 80),
                    ]
                )
            lines.append(_format_table(rows))

    if getattr(summary, "incident_clusters", None):
        clusters = list(summary.incident_clusters or [])
        if clusters:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Incident Clusters"))
            rows = [["Cluster", "Host", "Signals", "Targets", "Confidence"]]
            for item in clusters[:limit]:
                signals = item.get("indicators", [])
                rows.append(
                    [
                        str(item.get("cluster", "-")),
                        _highlight_public_ips(str(item.get("host", "-"))),
                        str(len(signals) if isinstance(signals, list) else 0),
                        str(item.get("target_count", "-")),
                        str(item.get("confidence", "-")),
                    ]
                )
            lines.append(_format_table(rows))

    if getattr(summary, "campaign_indicators", None):
        campaigns = list(summary.campaign_indicators or [])
        if campaigns:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Shared Campaign Indicators"))
            rows = [["Indicator", "Value", "Hosts"]]
            for item in campaigns[:limit]:
                hosts = item.get("hosts", [])
                host_text = (
                    ", ".join(_highlight_public_ips(str(v)) for v in hosts[:4])
                    if isinstance(hosts, list)
                    else "-"
                )
                rows.append(
                    [
                        _truncate_text(str(item.get("indicator", "-")), 40),
                        _truncate_text(str(item.get("value", "-")), 40),
                        _truncate_text(host_text or "-", 60),
                    ]
                )
            lines.append(_format_table(rows))

    if getattr(summary, "dc_role_drift", None):
        drift = list(summary.dc_role_drift or [])
        if drift:
            lines.append(SUBSECTION_BAR)
            lines.append(header("DC Role Drift Signals"))
            rows = [["Server", "Service Mix", "Packets"]]
            for item in drift[:limit]:
                services = item.get("services", [])
                svc_text = (
                    ", ".join(str(v) for v in services)
                    if isinstance(services, list)
                    else "-"
                )
                rows.append(
                    [
                        _highlight_public_ips(str(item.get("server", "-"))),
                        _truncate_text(svc_text, 60),
                        str(item.get("packets", "-")),
                    ]
                )
            lines.append(_format_table(rows))

    if getattr(summary, "sequence_violations", None):
        seq = list(summary.sequence_violations or [])
        if seq:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Sequence Plausibility Violations"))
            rows = [["Source", "Reason", "Lateral Hits", "Auth Signals"]]
            for item in seq[:limit]:
                rows.append(
                    [
                        _highlight_public_ips(str(item.get("src", "-"))),
                        _truncate_text(str(item.get("reason", "-")), 56),
                        str(item.get("lateral_hits", "-")),
                        str(item.get("auth_signals", "-")),
                    ]
                )
            lines.append(_format_table(rows))

    if summary.urls:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed URLs"))
        lines.append(_counter_table(summary.urls, "URL", limit=limit))

    if summary.user_agents:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed User Agents"))
        lines.append(_counter_table(summary.user_agents, "User Agent", limit=limit))

    if summary.users:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Users"))
        lines.append(_counter_table(summary.users, "User", limit=limit))

    if summary.credentials:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Credentials"))
        rows = [["Credential", "Count"]]
        for cred, count in summary.credentials.most_common(limit):
            rows.append([_redact_in_text(str(cred)), str(count)])
        lines.append(_format_table(rows))

    if summary.computer_names:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Computer Names"))
        lines.append(_counter_table(summary.computer_names, "Computer", limit=limit))

    if summary.response_codes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Response Codes"))
        lines.append(_counter_table(summary.response_codes, "Code", limit=limit))

    if summary.request_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Request Summary"))
        lines.append(_counter_table(summary.request_counts, "Request", limit=limit))

    if summary.files:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files Discovered"))
        for name in summary.files[:limit]:
            lines.append(f"- {name}")

    if summary.anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies"))
        for item in summary.anomalies[:limit]:
            lines.append(warn(f"- {item}"))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = _redact_in_text(str(item.get("details", "")))
            summary_lower = summary_text.lower()
            if "extension/type mismatch" in summary_lower:
                marker = danger("[HIGH]")
                summary_text = danger(summary_text)
            elif severity == "warning":
                marker = warn("[WARN]")
            elif severity == "critical":
                marker = danger("[CRIT]")
            elif severity == "high":
                marker = danger("[HIGH]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

    if getattr(summary, "benign_context", None):
        benign_notes = [
            str(v) for v in (summary.benign_context or []) if str(v).strip()
        ]
        if benign_notes:
            lines.append(SUBSECTION_BAR)
            lines.append(header("False-Positive Context"))
            for note in benign_notes[: _limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(note)}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
