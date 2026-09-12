"""Rendered output for kerberos analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from collections import Counter
from typing import TYPE_CHECKING
from ..coloring import (
    danger,
    header,
    muted,
    ok,
    severity_color,
    severity_label,
    warn,
)
from ..services import COMMON_PORTS
from ..utils import (
    format_ts,
)
if TYPE_CHECKING:
    from ..kerberos import KerberosAnalysis

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _apply_verbose_limit,
    _counter_table,
    _filtered_detections,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
    _redact_in_text,
    _render_protocol_verdict,
    _truncate_text,
)


def render_kerberos_summary(
    summary: "KerberosAnalysis", limit: int = 25, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit)

    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"KERBEROS ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)
    _render_protocol_verdict(
        lines,
        label="Kerberos",
        detections=getattr(summary, "detections", None),
        anomalies=getattr(summary, "anomalies", None),
    )

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Protocol Statistics"))
    lines.append(_format_kv("Start", format_ts(getattr(summary, "first_seen", None))))
    lines.append(_format_kv("End", format_ts(getattr(summary, "last_seen", None))))
    lines.append(_format_kv("Duration", f"{summary.duration:.2f}s"))
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("TCP Packets", str(getattr(summary, "tcp_packets", 0))))
    lines.append(_format_kv("UDP Packets", str(getattr(summary, "udp_packets", 0))))
    if summary.session_stats:
        lines.append(
            _format_kv(
                "Kerberos Sessions", str(summary.session_stats.get("total_sessions", 0))
            )
        )
        lines.append(
            _format_kv(
                "Unique Clients", str(summary.session_stats.get("unique_clients", 0))
            )
        )
        lines.append(
            _format_kv(
                "Unique Servers", str(summary.session_stats.get("unique_servers", 0))
            )
        )

    attack_matrix = list(getattr(summary, "attack_matrix", []) or [])
    if attack_matrix:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Deterministic Kerberos Attack Overview"))
        rows = [["Attack Technique", "Status", "Severity", "Evidence"]]
        for item in attack_matrix[: _limit_value(30)]:
            if not isinstance(item, dict):
                continue
            status = str(item.get("status", "-"))
            severity = str(item.get("severity", "info")).lower()
            evidence = str(item.get("evidence", "-"))
            if status == "suspicious":
                status_text = danger("SUSPICIOUS")
            elif status == "watch":
                status_text = warn("WATCH")
            else:
                status_text = ok("NOT OBSERVED")
            sev_text = severity_color(severity_label(severity), severity)
            rows.append(
                [
                    str(item.get("attack", "-")),
                    status_text,
                    sev_text,
                    _truncate_text(_redact_in_text(evidence), 120),
                ]
            )
        lines.append(_format_table(rows))

    deterministic_checks = dict(getattr(summary, "deterministic_checks", {}) or {})
    if deterministic_checks:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Deterministic Check Evidence"))
        order = [
            ("kerberoasting", "Kerberoasting"),
            ("asrep_roasting", "AS-REP roasting"),
            ("password_spray_bruteforce", "Password spray/brute-force"),
            ("delegation_abuse", "Delegation abuse"),
            ("ticket_forgery_ptt", "Ticket forgery/pass-the-ticket"),
            ("user_enumeration", "Principal enumeration"),
            ("public_kdc_exposure", "Public Kerberos exposure"),
            ("cross_realm_or_realm_spray", "Cross-realm spray"),
        ]
        for key, label_text in order:
            values = [str(v) for v in list(deterministic_checks.get(key, []) or [])]
            if values:
                lines.append(warn(f"[!] {label_text}: {len(values)}"))
                for entry in values[: _limit_value(5)]:
                    lines.append(muted(f"  - {_redact_in_text(entry)}"))
            else:
                lines.append(ok(f"[ ] {label_text}: none"))

    if summary.servers or summary.clients:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Kerberos Servers & Clients"))
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

    if summary.service_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Kerberos Service Ports"))
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

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Kerberos Conversations"))
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

    if summary.request_types:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Kerberos Commands / Requests"))
        lines.append(_counter_table(summary.request_types, "Command", limit=limit))

    etype_counts = getattr(summary, "etype_counts", None)
    if etype_counts:
        from ..kerberos import (
            _KRB_ETYPE_NAMES,
            _KRB_STRONG_ETYPES,
            _KRB_WEAK_ETYPES,
        )

        lines.append(SUBSECTION_BAR)
        lines.append(header("Kerberos Encryption Types Requested"))
        rows = [["EType", "Algorithm", "Strength", "Count"]]
        for etype, count in etype_counts.most_common():
            name = _KRB_ETYPE_NAMES.get(etype, "unknown")
            if etype in _KRB_WEAK_ETYPES:
                strength = "WEAK (crackable)"
            elif etype in _KRB_STRONG_ETYPES:
                strength = "strong"
            else:
                strength = "-"
            rows.append([str(etype), name, strength, str(count)])
        lines.append(_format_table(rows))

    if summary.error_codes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Kerberos Errors by Code"))
        lines.append(_counter_table(summary.error_codes, "Error", limit=limit))

    if summary.realms:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Kerberos Realms"))
        lines.append(_counter_table(summary.realms, "Realm", limit=limit))

    if summary.principals:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Kerberos Principals"))
        lines.append(_counter_table(summary.principals, "Principal", limit=limit))

    discovered_users = Counter()
    for principal, count in summary.principals.items():
        local = str(principal).split("@", 1)[0]
        if "/" in local:
            continue
        if "." in local:
            continue
        if not local:
            continue
        if len(local) < 3:
            continue
        discovered_users[local] += int(count)
    lines.append(SUBSECTION_BAR)
    lines.append(header("Discovered Usernames"))
    if discovered_users:
        rows = [["Username", "Count"]]
        for name, count in discovered_users.most_common(limit):
            rows.append([_truncate_text(_redact_in_text(str(name)), 48), str(count)])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No Kerberos usernames discovered."))

    discovered_hosts = Counter()
    for spn, count in summary.spns.items():
        spn_name = str(spn).split("@", 1)[0]
        if "/" not in spn_name:
            continue
        _, host = spn_name.split("/", 1)
        if not host:
            continue
        if len(host) < 3:
            continue
        discovered_hosts[host] += int(count)
    lines.append(SUBSECTION_BAR)
    lines.append(header("Discovered Hostnames"))
    if discovered_hosts:
        rows = [["Hostname", "Count"]]
        for name, count in discovered_hosts.most_common(limit):
            rows.append([_truncate_text(_redact_in_text(str(name)), 48), str(count)])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No Kerberos hostnames discovered."))

    if getattr(summary, "principal_evidence", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Principal Evidence (Per Flow)"))
        rows = [["Src", "Dst", "Port", "Proto", "Principal", "Kind"]]
        for item in summary.principal_evidence[:limit]:
            rows.append(
                [
                    str(item.get("src_ip", "-")),
                    str(item.get("dst_ip", "-")),
                    str(item.get("dst_port", "-")),
                    str(item.get("protocol", "-")),
                    _truncate_text(str(item.get("principal", "-")), 60),
                    str(item.get("kind", "-")),
                ]
            )
        lines.append(_format_table(rows))

    if summary.spns:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Service Principals (SPNs)"))
        lines.append(_counter_table(summary.spns, "SPN", limit=limit))

    if summary.public_endpoints:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Public IP Kerberos Endpoints"))
        lines.append(_counter_table(summary.public_endpoints, "Endpoint", limit=limit))

    if summary.suspicious_attributes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Suspicious Kerberos Indicators"))
        lines.append(_counter_table(summary.suspicious_attributes, "Indicator", limit=limit))

    if summary.bind_bursts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Burst Activity / Brute Force Indicators"))
        rows = [["Client", "Peak AS/TGS Requests/Min"]]
        for client, count in summary.bind_bursts.most_common(limit):
            rows.append([client, str(count)])
        lines.append(_format_table(rows))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts"))
        rows = [["Artifact"]]
        for item in summary.artifacts[:limit]:
            rows.append([_truncate_text(str(item), 100)])
        lines.append(_format_table(rows))

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
            if severity == "warning":
                marker = warn("[WARN]")
            elif severity == "critical":
                marker = danger("[CRIT]")
            elif severity == "high":
                marker = danger("[HIGH]")
                summary_text = danger(summary_text)
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
