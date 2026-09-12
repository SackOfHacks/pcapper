"""Rendered output for snmp analysis.

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
from ..snmp import SnmpSummary
from ..utils import (
    format_bytes_as_mb,
    format_duration,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _apply_verbose_limit,
    _counter_table,
    _filtered_detections,
    _finalize_output,
    _format_client_server_table,
    _format_kv,
    _format_sessions_table,
    _format_table,
    _meaningful_plaintext_items,
    _redact_in_text,
    _redact_secret,
    _render_protocol_verdict,
    _truncate_text,
)


def render_snmp_summary(
    summary: SnmpSummary, limit: int = 12, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit)
    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"SNMP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)
    _render_protocol_verdict(
        lines,
        label="SNMP",
        detections=getattr(summary, "detections", None),
        anomalies=getattr(summary, "anomalies", None),
    )

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("SNMP Packets", str(summary.snmp_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    if summary.duration_seconds is not None:
        lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))
    lines.append(_format_kv("Messages", str(summary.total_messages)))
    lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))

    if summary.server_ports:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server Ports"))
        lines.append(_counter_table(summary.server_ports, "Port", limit=limit))

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top SNMP Clients & Servers"))
        lines.append(
            _format_client_server_table(summary.client_counts, summary.server_counts)
        )

    if summary.version_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SNMP Versions"))
        lines.append(_counter_table(summary.version_counts, "Version", limit=limit))

    if summary.community_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Community Strings"))
        rows = [["Community", "Count"]]
        for comm, count in summary.community_counts.most_common(limit):
            rows.append([_redact_secret(comm), str(count)])
        lines.append(_format_table(rows))

    usm_users = getattr(summary, "usm_users", None)
    if usm_users:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SNMPv3 USM Users"))
        lines.append(
            muted(
                "Device-management accounts (msgUserName is cleartext even in "
                "authPriv) — identity artifact for the SNMP managers."
            )
        )
        rows = [["USM Username", "Messages"]]
        for uname, count in usm_users.most_common(limit):
            rows.append([str(uname), str(count)])
        lines.append(_format_table(rows))

    if summary.pdu_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("PDU Types"))
        lines.append(_counter_table(summary.pdu_counts, "PDU", limit=limit))

    if summary.oid_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top OIDs"))
        rows = [["OID", "Count"]]
        for oid, count in summary.oid_counts.most_common(limit):
            rows.append([_truncate_text(oid, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.hostnames:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Hostnames"))
        rows = [["Hostname", "Count"]]
        for name, count in summary.hostnames.most_common(limit):
            rows.append([_truncate_text(name, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.ip_addresses:
        lines.append(SUBSECTION_BAR)
        lines.append(header("IP Addresses"))
        lines.append(_counter_table(summary.ip_addresses, "IP", limit=limit))

    if summary.mac_addresses:
        lines.append(SUBSECTION_BAR)
        lines.append(header("MAC Addresses"))
        lines.append(_counter_table(summary.mac_addresses, "MAC", limit=limit))

    if summary.services:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Discovered Services"))
        rows = [["Service", "Count"]]
        for name, count in summary.services.most_common(limit):
            rows.append([_truncate_text(name, 70), str(count)])
        lines.append(_format_table(rows))

    if summary.plaintext_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Plaintext"))
        rows = [["String", "Count"]]
        for text, count in _meaningful_plaintext_items(summary.plaintext_strings, limit):
            rows.append([_truncate_text(text, 70), str(count)])
        lines.append(_format_table(rows))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SNMP Sessions"))
        lines.append(_format_sessions_table(summary.conversations, limit))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = _redact_in_text(str(item.get("details", "")))
            if severity in {"critical", "high"}:
                marker = danger("[HIGH]")
                summary_text = danger(summary_text)
            elif severity == "warning":
                marker = warn("[WARN]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts"))
        rows = [["Type", "Detail", "Src", "Dst"]]
        for item in summary.artifacts[:limit]:
            rows.append(
                [
                    str(item.kind),
                    _truncate_text(str(item.detail), 60),
                    str(item.src),
                    str(item.dst),
                ]
            )
        lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
