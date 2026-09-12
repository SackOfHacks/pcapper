"""Rendered output for ssh analysis.

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
from ..ssh import SshSummary
from ..utils import (
    format_bytes_as_mb,
    format_duration,
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
    _format_sessions_table,
    _format_table,
    _limit_value,
    _meaningful_plaintext_items,
    _redact_in_text,
    _render_protocol_verdict,
    _truncate_text,
)


def render_ssh_summary(
    summary: SshSummary, limit: int = 12, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit)
    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"SSH ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)
    _render_protocol_verdict(
        lines,
        label="SSH",
        detections=getattr(summary, "detections", None),
        anomalies=getattr(summary, "anomalies", None),
    )

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    if getattr(summary, "analysis_notes", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Notes"))
        for note in summary.analysis_notes:
            lines.append(muted(f"- {note}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("SSH Packets", str(summary.ssh_packets)))
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
    lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))

    if summary.server_ports:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server Ports"))
        lines.append(_counter_table(summary.server_ports, "Port", limit=limit))

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top SSH Clients & Servers"))
        lines.append(
            _format_client_server_table(summary.client_counts, summary.server_counts)
        )

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SSH Sessions"))
        lines.append(_format_sessions_table(summary.conversations, limit))

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

    if summary.client_versions or summary.server_versions:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SSH Versions"))
        rows = [["Client Versions", "Server Versions"]]
        client_text = (
            ", ".join(
                f"{_truncate_text(name, 40)}({count})"
                for name, count in summary.client_versions.most_common(_limit_value(6))
            )
            or "-"
        )
        server_text = (
            ", ".join(
                f"{_truncate_text(name, 40)}({count})"
                for name, count in summary.server_versions.most_common(_limit_value(6))
            )
            or "-"
        )
        rows.append([client_text, server_text])
        lines.append(_format_table(rows))

    if summary.client_software or summary.server_software:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SSH Software"))
        rows = [["Clients", "Servers"]]
        client_text = (
            ", ".join(
                f"{_truncate_text(name, 40)}({count})"
                for name, count in summary.client_software.most_common(_limit_value(6))
            )
            or "-"
        )
        server_text = (
            ", ".join(
                f"{_truncate_text(name, 40)}({count})"
                for name, count in summary.server_software.most_common(_limit_value(6))
            )
            or "-"
        )
        rows.append([client_text, server_text])
        lines.append(_format_table(rows))

    if getattr(summary, "device_fingerprints", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Device Fingerprints"))
        rows = [["Fingerprint", "Count"]]
        for fp, count in summary.device_fingerprints.most_common(limit):
            rows.append([_truncate_text(fp, 90), str(count)])
        lines.append(_format_table(rows))

    if summary.client_hassh:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Client HASSH"))
        rows = [["HASSH", "Count", "KEX String"]]
        for value, count in summary.client_hassh.most_common(limit):
            detail = summary.client_hassh_strings.get(value, "")
            rows.append([value, str(count), _truncate_text(detail, 70)])
        lines.append(_format_table(rows))

    if summary.server_hassh:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server HASSH"))
        rows = [["HASSH", "Count", "KEX String"]]
        for value, count in summary.server_hassh.most_common(limit):
            detail = summary.server_hassh_strings.get(value, "")
            rows.append([value, str(count), _truncate_text(detail, 70)])
        lines.append(_format_table(rows))

    if summary.host_key_fingerprints:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Host Key Fingerprints"))
        lines.append(_counter_table(summary.host_key_fingerprints, "Fingerprint", limit=limit))

    if summary.host_key_types:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Host Key Types"))
        lines.append(_counter_table(summary.host_key_types, "Type", limit=limit))

    if (
        summary.kex_algorithms
        or summary.cipher_algorithms
        or summary.mac_algorithms
        or summary.host_key_algorithms
    ):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Crypto Negotiation"))
        rows = [["KEX", "Host Key", "Cipher", "MAC", "Compression"]]
        rows.append(
            [
                ", ".join(
                    f"{name}({count})"
                    for name, count in summary.kex_algorithms.most_common(
                        _limit_value(3)
                    )
                )
                or "-",
                ", ".join(
                    f"{name}({count})"
                    for name, count in summary.host_key_algorithms.most_common(
                        _limit_value(3)
                    )
                )
                or "-",
                ", ".join(
                    f"{name}({count})"
                    for name, count in summary.cipher_algorithms.most_common(
                        _limit_value(3)
                    )
                )
                or "-",
                ", ".join(
                    f"{name}({count})"
                    for name, count in summary.mac_algorithms.most_common(
                        _limit_value(3)
                    )
                )
                or "-",
                ", ".join(
                    f"{name}({count})"
                    for name, count in summary.compression_algorithms.most_common(
                        _limit_value(3)
                    )
                )
                or "-",
            ]
        )
        lines.append(_format_table(rows))

    if summary.auth_methods:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Auth Methods"))
        lines.append(_counter_table(summary.auth_methods, "Method", limit=limit))

    if getattr(summary, "auth_usernames", None):
        if summary.auth_usernames:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Auth Usernames (Decrypted)"))
            rows = [["Username", "Count"]]
            for name, count in summary.auth_usernames.most_common(limit):
                rows.append([_truncate_text(name, 40), str(count)])
            lines.append(_format_table(rows))

    if summary.auth_failures_by_client or summary.auth_successes_by_client:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Auth Outcomes (By Client)"))
        rows = [["Client", "Failures", "Successes"]]
        ranked_clients = sorted(
            set(summary.auth_failures_by_client.keys())
            | set(summary.auth_successes_by_client.keys()),
            key=lambda ip: summary.auth_failures_by_client.get(ip, 0),
            reverse=True,
        )
        for ip in ranked_clients[:limit]:
            rows.append(
                [
                    ip,
                    str(summary.auth_failures_by_client.get(ip, 0)),
                    str(summary.auth_successes_by_client.get(ip, 0)),
                ]
            )
        lines.append(_format_table(rows))

    auth_inference = getattr(summary, "auth_inference", None)
    if auth_inference:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Auth Activity (Inferred from Encrypted Sessions)"))
        lines.append(
            muted(
                "SSH auth is encrypted; outcome is inferred from post-handshake "
                "traffic volume (sessions ending right after key exchange = likely "
                "failed/aborted login)."
            )
        )
        rows = [
            ["Client", "Server:Port", "Sessions", "Likely Fail", "Likely OK", "Client SW", "Assessment"]
        ]
        ranked = sorted(
            auth_inference,
            key=lambda r: (int(r.get("likely_failed", 0)), int(r.get("sessions", 0))),
            reverse=True,
        )
        for r in ranked[:limit]:
            rows.append(
                [
                    str(r.get("client", "-")),
                    f"{r.get('server', '-')}:{r.get('port', '-')}",
                    str(r.get("sessions", 0)),
                    str(r.get("likely_failed", 0)),
                    str(r.get("likely_success", 0)),
                    _truncate_text(str(r.get("client_software", "-")), 24),
                    str(r.get("verdict", "-")),
                ]
            )
        lines.append(_format_table(rows))

    if summary.request_counts or summary.response_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Requests & Responses"))
        rows = [["Requests", "Responses"]]
        req_text = (
            ", ".join(
                f"{name.replace('SSH_MSG_', '')}({count})"
                for name, count in summary.request_counts.most_common(_limit_value(6))
            )
            or "-"
        )
        resp_text = (
            ", ".join(
                f"{name.replace('SSH_MSG_', '')}({count})"
                for name, count in summary.response_counts.most_common(_limit_value(6))
            )
            or "-"
        )
        rows.append([req_text, resp_text])
        lines.append(_format_table(rows))

    if summary.disconnect_reasons:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Disconnect Reasons"))
        lines.append(_counter_table(summary.disconnect_reasons, "Reason", limit=limit))

    if summary.plaintext_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Plaintext (Pre-Encryption)"))
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

    if summary.conversations and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Sessions"))
        rows = [["Client", "Server", "C->S MB", "S->C MB", "Packets", "Auth Fail/OK"]]
        top_sessions = sorted(
            summary.conversations, key=lambda conv: conv.bytes, reverse=True
        )[:limit]
        for conv in top_sessions:
            rows.append(
                [
                    f"{conv.client_ip}:{conv.client_port}",
                    f"{conv.server_ip}:{conv.server_port}",
                    f"{conv.client_bytes / (1024 * 1024):.1f}",
                    f"{conv.server_bytes / (1024 * 1024):.1f}",
                    str(conv.packets),
                    f"{conv.auth_failures}/{conv.auth_successes}",
                ]
            )
        lines.append(_format_table(rows))

    if summary.anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies"))
        for item in summary.anomalies[:limit]:
            title = str(item.get("title", "Event"))
            details = str(item.get("details", ""))
            mitre = str(item.get("mitre", "")).strip()
            if details:
                lines.append(warn(f"- {title}: {details}"))
            else:
                lines.append(warn(f"- {title}"))
            if mitre:
                lines.append(muted(f"    ATT&CK: {mitre}"))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            confidence = str(item.get("confidence", "")).strip()
            mitre = str(item.get("mitre", "")).strip()
            evidence = item.get("evidence")
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
            header_line = f"{marker} {summary_text}"
            if confidence:
                header_line += muted(f"  (confidence: {confidence})")
            lines.append(header_line)
            if details:
                lines.append(muted(f"  {details}"))
            if mitre:
                lines.append(muted(f"  ATT&CK: {mitre}"))
            if isinstance(evidence, (list, tuple)) and evidence:
                lines.append(muted("  Evidence:"))
                for ev in list(evidence)[: _limit_value(8)]:
                    if ev:
                        lines.append(muted(f"    - {_truncate_text(str(ev), 110)}"))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts"))
        for item in summary.artifacts[:limit]:
            lines.append(muted(f"- {_truncate_text(_redact_in_text(item), 80)}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
