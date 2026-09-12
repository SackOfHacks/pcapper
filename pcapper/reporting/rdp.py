"""Rendered output for rdp analysis.

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
from ..rdp import RdpSummary
from ..utils import (
    format_bytes_as_mb,
    format_duration,
    format_ts,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _annotate_macs,
    _apply_verbose_limit,
    _counter_table,
    _filtered_detections,
    _finalize_output,
    _format_client_server_table,
    _format_kv,
    _format_table,
    _limit_value,
    _meaningful_plaintext_items,
    _redact_in_text,
    _render_protocol_verdict,
    _truncate_text,
)


def render_rdp_summary(
    summary: RdpSummary, limit: int = 12, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit)
    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"RDP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)
    _render_protocol_verdict(
        lines,
        label="RDP",
        detections=getattr(summary, "detections", None),
        anomalies=getattr(summary, "anomalies", None),
    )

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("RDP Packets", str(summary.rdp_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    if summary.client_bytes or summary.server_bytes:
        lines.append(
            _format_kv("Client -> Server", format_bytes_as_mb(summary.client_bytes))
        )
        lines.append(
            _format_kv("Server -> Client", format_bytes_as_mb(summary.server_bytes))
        )
    if summary.duration_seconds is not None:
        lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))
    lines.append(_format_kv("Sessions", str(summary.total_sessions)))
    lines.append(_format_kv("TCP Sessions", str(summary.tcp_sessions)))
    lines.append(_format_kv("UDP Sessions", str(summary.udp_sessions)))
    lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))

    if summary.server_tcp_ports:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server TCP Ports"))
        lines.append(_counter_table(summary.server_tcp_ports, "Port", limit=limit))

    if summary.server_udp_ports:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server UDP Ports"))
        lines.append(_counter_table(summary.server_udp_ports, "Port", limit=limit))

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top RDP Clients & Servers"))
        lines.append(
            _format_client_server_table(summary.client_counts, summary.server_counts)
        )

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("RDP Sessions"))
        rows = [["Client", "Server", "Start", "End", "Duration", "Packets", "Size"]]
        if verbose:
            rows[0].extend(["UDP", "TLS"])
        top_sessions = sorted(
            summary.conversations, key=lambda conv: conv.bytes, reverse=True
        )[:limit]
        for conv in top_sessions:
            duration = None
            if conv.first_seen is not None and conv.last_seen is not None:
                duration = max(0.0, conv.last_seen - conv.first_seen)
            row = [
                f"{conv.client_ip}:{conv.client_port}",
                f"{conv.server_ip}:{conv.server_port}",
                format_ts(conv.first_seen),
                format_ts(conv.last_seen),
                format_duration(duration),
                str(conv.packets),
                format_bytes_as_mb(conv.bytes),
            ]
            if verbose:
                row.extend(
                    [
                        "yes" if conv.udp_detected else "no",
                        "yes" if conv.tls_detected else "no",
                    ]
                )
            rows.append(row)
        lines.append(_format_table(rows))

    if summary.ip_to_macs:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed MACs"))
        rows = [["IP", "MACs"]]
        ranked_ips = sorted(
            summary.ip_to_macs.keys(),
            key=lambda ip: summary.client_counts.get(ip, 0)
            + summary.server_counts.get(ip, 0),
            reverse=True,
        )
        for ip in ranked_ips[:limit]:
            macs = _annotate_macs(summary.ip_to_macs.get(ip, []))
            rows.append([ip, _truncate_text(macs, 60)])
        lines.append(_format_table(rows))

    if summary.client_names:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Client Hostnames (mstshash)"))
        rows = [["Hostname", "Count"]]
        for name, count in summary.client_names.most_common(limit):
            rows.append([_truncate_text(name, 48), str(count)])
        lines.append(_format_table(rows))

    if summary.tls_handshakes or getattr(summary, "dtls_handshakes", 0):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Security"))
        lines.append(_format_kv("TLS Handshakes Detected", str(summary.tls_handshakes)))
        if getattr(summary, "dtls_handshakes", 0):
            lines.append(
                _format_kv("DTLS Handshakes Detected", str(summary.dtls_handshakes))
            )

    if getattr(summary, "requested_protocols", None):
        if summary.requested_protocols or summary.selected_protocols:
            lines.append(SUBSECTION_BAR)
            lines.append(header("RDP Negotiation"))
            rows = [["Requested", "Selected"]]
            req_text = (
                ", ".join(
                    f"{name}({count})"
                    for name, count in summary.requested_protocols.most_common(
                        _limit_value(6)
                    )
                )
                or "-"
            )
            sel_text = (
                ", ".join(
                    f"{name}({count})"
                    for name, count in summary.selected_protocols.most_common(
                        _limit_value(6)
                    )
                )
                or "-"
            )
            rows.append([req_text, sel_text])
            lines.append(_format_table(rows))

    if getattr(summary, "client_builds", None):
        if summary.client_builds:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Client Builds"))
            lines.append(_counter_table(summary.client_builds, "Build", limit=limit))

    if getattr(summary, "decrypted_username", None):
        if (
            summary.decrypted_username
            or summary.decrypted_domain
            or summary.decrypted_client_name
        ):
            lines.append(SUBSECTION_BAR)
            lines.append(header("Decrypted Identity"))
            rows = [["Usernames", "Domains", "Client Names"]]
            user_text = (
                ", ".join(
                    f"{_truncate_text(name, 32)}({count})"
                    for name, count in summary.decrypted_username.most_common(
                        _limit_value(6)
                    )
                )
                or "-"
            )
            domain_text = (
                ", ".join(
                    f"{_truncate_text(name, 32)}({count})"
                    for name, count in summary.decrypted_domain.most_common(
                        _limit_value(6)
                    )
                )
                or "-"
            )
            client_text = (
                ", ".join(
                    f"{_truncate_text(name, 32)}({count})"
                    for name, count in summary.decrypted_client_name.most_common(
                        _limit_value(6)
                    )
                )
                or "-"
            )
            rows.append([user_text, domain_text, client_text])
            lines.append(_format_table(rows))

    if summary.plaintext_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Plaintext (Pre-Encryption/Decrypted)"))
        rows = [["String", "Count"]]
        for text, count in _meaningful_plaintext_items(summary.plaintext_strings, limit):
            rows.append([_truncate_text(text, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.suspicious_plaintext:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Suspicious Plaintext Indicators"))
        rows = [["Indicator", "Count"]]
        for text, count in summary.suspicious_plaintext.most_common(limit):
            rows.append([_truncate_text(text, 80), str(count)])
        lines.append(_format_table(rows))

    if summary.file_artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files Discovered"))
        rows = [["File", "Count"]]
        for name, count in summary.file_artifacts.most_common(limit):
            rows.append([_truncate_text(name, 60), str(count)])
        lines.append(_format_table(rows))

    if summary.anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies"))
        for item in summary.anomalies[:limit]:
            title = str(item.get("title", "Event"))
            details = str(item.get("details", ""))
            if details:
                lines.append(warn(f"- {title}: {details}"))
            else:
                lines.append(warn(f"- {title}"))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity == "critical":
                marker = danger("[CRIT]")
                summary_text = danger(summary_text)
            elif severity == "high":
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
        for item in summary.artifacts[:limit]:
            lines.append(muted(f"- {_truncate_text(_redact_in_text(item), 80)}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
