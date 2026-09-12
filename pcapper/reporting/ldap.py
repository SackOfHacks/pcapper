"""Rendered output for ldap analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from typing import TYPE_CHECKING
from ..coloring import (
    danger,
    header,
    muted,
    ok,
    warn,
)
from ..services import COMMON_PORTS
if TYPE_CHECKING:
    from ..ldap import LdapAnalysis

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
    _redact_secret,
    _render_deterministic_checks,
    _render_protocol_verdict,
)


def render_ldap_summary(
    summary: "LdapAnalysis", limit: int = 25, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit)

    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"LDAP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)
    _render_protocol_verdict(
        lines,
        label="LDAP",
        detections=getattr(summary, "detections", None),
        anomalies=getattr(summary, "anomalies", None),
    )

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Duration", f"{summary.duration:.2f}s"))
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    if summary.session_stats:
        lines.append(
            _format_kv(
                "LDAP Sessions", str(summary.session_stats.get("total_sessions", 0))
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

    if summary.ldap_domains:
        lines.append(SUBSECTION_BAR)
        lines.append(header("LDAP-Related DNS"))
        lines.append(_counter_table(summary.ldap_domains, "Domain", limit=limit))

    if summary.servers or summary.clients:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top LDAP Servers & Clients"))
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
        lines.append(header("LDAP Service Ports"))
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
        lines.append(header("LDAP Conversations"))
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

    if summary.ldap_queries:
        lines.append(SUBSECTION_BAR)
        lines.append(header("LDAP Queries"))
        lines.append(_counter_table(summary.ldap_queries, "Query", limit=limit))

    if summary.ldap_filter_types:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top LDAP Queries by Filter Type"))
        lines.append(_counter_table(summary.ldap_filter_types, "Filter Type", limit=limit))

    if summary.ldap_binds:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Binds"))
        lines.append(_counter_table(summary.ldap_binds, "Bind Identity", limit=limit))

    if summary.ldap_users:
        lines.append(SUBSECTION_BAR)
        lines.append(header("LDAP Users"))
        lines.append(_counter_table(summary.ldap_users, "User", limit=limit))

    if summary.ldap_systems:
        lines.append(SUBSECTION_BAR)
        lines.append(header("LDAP Systems"))
        lines.append(_counter_table(summary.ldap_systems, "System", limit=limit))

    if summary.response_codes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("LDAP Response Codes"))
        lines.append(_counter_table(summary.response_codes, "Code", limit=limit))

    if summary.ldap_error_codes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top LDAP Errors by Code"))
        lines.append(_counter_table(summary.ldap_error_codes, "Error", limit=limit))

    if summary.request_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("LDAP Requests"))
        lines.append(_counter_table(summary.request_counts, "Request", limit=limit))

    if summary.cleartext_packets or summary.ldaps_packets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("LDAP Cleartext vs LDAPS Ratio"))
        total = summary.cleartext_packets + summary.ldaps_packets
        clear_pct = (summary.cleartext_packets / total * 100.0) if total else 0.0
        ldaps_pct = (summary.ldaps_packets / total * 100.0) if total else 0.0
        rows = [["Type", "Packets", "Percent"]]
        rows.append(["Cleartext", str(summary.cleartext_packets), f"{clear_pct:.1f}%"])
        rows.append(["LDAPS", str(summary.ldaps_packets), f"{ldaps_pct:.1f}%"])
        lines.append(_format_table(rows))

    if summary.secrets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Secrets/Passwords"))
        rows = [["Value", "Count"]]
        for secret, count in summary.secrets.most_common(limit):
            rows.append([_redact_secret(str(secret)), str(count)])
        lines.append(_format_table(rows))

    if summary.public_endpoints:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Public IP LDAP Endpoints"))
        lines.append(_counter_table(summary.public_endpoints, "Endpoint", limit=limit))

    if summary.suspicious_attributes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Suspicious Attributes Queried"))
        lines.append(_counter_table(summary.suspicious_attributes, "Attribute", limit=limit))

    if summary.bind_bursts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Burst Activity / Brute Force Indicators"))
        rows = [["Client", "Peak Binds/Min"]]
        for client, count in summary.bind_bursts.most_common(limit):
            rows.append([client, str(count)])
        lines.append(_format_table(rows))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts"))
        lines.append(muted(", ".join(summary.artifacts[:limit])))

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
            if "extension/type mismatch" in summary_text.lower():
                severity = "high"
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
    _render_deterministic_checks(
        lines, summary, "Deterministic LDAP Security Checks", [
            ("cleartext_ldap_exposure", "Cleartext LDAP Exposure"),
            ("bind_auth_risk", "Bind Authentication Risk"),
            ("anonymous_or_guest_bind_activity", "Anonymous/Guest Bind Activity"),
            ("credential_error_burst", "Credential Error Burst"),
            ("enumeration_burst_activity", "Enumeration Burst Activity"),
            ("sensitive_attribute_access", "Sensitive Attribute Access"),
            ("secret_material_exposure", "Secret Material Exposure"),
            ("directory_write_activity", "Directory Write Activity"),
            ("public_ldap_endpoint_exposure", "Public LDAP Endpoint Exposure"),
        ]
    )
    return _finalize_output(lines)
