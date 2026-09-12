"""Rendered output for ftp analysis.

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
from ..ftp import FtpSummary
from ..utils import (
    format_bytes_as_mb,
    format_duration,
    format_ts,
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
    _format_table,
    _highlight_public_ips,
    _limit_value,
    _redact_in_text,
    _redact_secret,
    _truncate_text,
)


def render_ftp_summary(
    summary: FtpSummary, limit: int = 12, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit)
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"FTP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Packets Scanned", str(summary.total_packets)))
    lines.append(_format_kv("FTP Packets", str(summary.ftp_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(_format_kv("FTP Bytes", format_bytes_as_mb(summary.ftp_bytes)))
    lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))

    def _ftp_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        checks = getattr(summary, "deterministic_checks", {}) or {}
        detections = list(getattr(summary, "detections", []) or [])

        def _check_count(key: str) -> int:
            values = checks.get(key, []) if isinstance(checks, dict) else []
            return len([v for v in (values or []) if str(v).strip()])

        weighted_checks = {
            "cleartext_credential_exposure": 3,
            "anonymous_or_guest_abuse": 2,
            "bruteforce_or_spray": 3,
            "active_passive_mode_abuse": 2,
            "data_channel_integrity": 3,
            "high_risk_file_staging": 3,
            "ftps_downgrade_or_weak_protection": 1,
            "ftp_exfiltration_signal": 4,
        }
        for key, weight in weighted_checks.items():
            count = _check_count(key)
            if count:
                score += min(4, weight + min(2, count - 1))
                reasons.append(f"{key.replace('_', ' ')} evidence ({count})")

        high_count = sum(
            1
            for d in detections
            if str(d.get("severity", "")).lower() in {"high", "critical"}
        )
        med_count = sum(
            1 for d in detections if str(d.get("severity", "")).lower() == "medium"
        )
        if high_count:
            score += min(3, high_count)
            reasons.append(f"High-severity FTP detections observed ({high_count})")
        if med_count >= 2:
            score += 1
            reasons.append(
                f"Multiple medium-severity FTP detections observed ({med_count})"
            )

        if score >= 8:
            verdict = "YES - high-confidence malicious or compromised FTP activity is present."
            confidence = "High"
        elif score >= 5:
            verdict = "LIKELY - suspicious FTP activity with compromise indicators is present."
            confidence = "Medium"
        elif score >= 2:
            verdict = (
                "POSSIBLE - risky FTP behavior is present; corroboration recommended."
            )
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing malicious FTP pattern from current heuristics."
            confidence = "Low"

        if not reasons:
            reasons.append("No high-confidence FTP threat heuristic crossed threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _ftp_verdict()
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

    if summary.client_counts:
        lines.append(muted("Who:"))
        lines.append(muted("- Top FTP clients"))
        for client, count in summary.client_counts.most_common(_limit_value(6)):
            lines.append(muted(f"- {_highlight_public_ips(str(client))}: {int(count)}"))
    if summary.server_counts:
        lines.append(muted("Where:"))
        lines.append(muted("- Top FTP servers"))
        for server, count in summary.server_counts.most_common(_limit_value(6)):
            lines.append(muted(f"- {_highlight_public_ips(str(server))}: {int(count)}"))
    if summary.command_counts:
        lines.append(muted("What:"))
        lines.append(muted("- Top FTP commands"))
        for cmd, count in summary.command_counts.most_common(_limit_value(6)):
            lines.append(muted(f"- {cmd}: {int(count)}"))
    if getattr(summary, "incident_clusters", None):
        clusters = list(summary.incident_clusters or [])
        if clusters:
            lines.append(muted("When:"))
            lines.append(muted("- Incident cluster context"))
            for item in clusters[: _limit_value(4)]:
                lines.append(
                    muted(
                        f"- {_redact_in_text(str(item.get('cluster', '-')))} host={_highlight_public_ips(str(item.get('host', '-')))} "
                        f"signals={len(item.get('indicators', []) if isinstance(item.get('indicators', []), list) else [])}"
                    )
                )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic FTP Security Checks"))
    checks = getattr(summary, "deterministic_checks", {}) or {}
    check_labels = [
        ("cleartext_credential_exposure", "Cleartext Credential Exposure"),
        ("anonymous_or_guest_abuse", "Anonymous/Guest Abuse"),
        ("bruteforce_or_spray", "Bruteforce/Spray Behavior"),
        ("data_channel_integrity", "Data Channel Integrity"),
        ("ftp_exfiltration_signal", "FTP Exfiltration Signal"),
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

    if summary.server_ports:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server Ports"))
        lines.append(_counter_table(summary.server_ports, "Port", limit=limit))

    if summary.command_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Commands"))
        lines.append(_counter_table(summary.command_counts, "Command", limit=limit))

    if summary.response_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Responses"))
        lines.append(_counter_table(summary.response_counts, "Code", limit=limit))

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Clients & Servers"))
        lines.append(
            _format_client_server_table(summary.client_counts, summary.server_counts)
        )

    if summary.user_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Users"))
        rows = [["User", "Count"]]
        for user, count in summary.user_counts.most_common(limit):
            rows.append([_truncate_text(user, 32), str(count)])
        lines.append(_format_table(rows))

    if summary.banner_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server Banners"))
        rows = [["Banner", "Count"]]
        for banner, count in summary.banner_counts.most_common(limit):
            rows.append([_truncate_text(banner, 72), str(count)])
        lines.append(_format_table(rows))

    if summary.server_software:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server Software"))
        rows = [["Token", "Count"]]
        for token, count in summary.server_software.most_common(limit):
            rows.append([_truncate_text(token, 48), str(count)])
        lines.append(_format_table(rows))

    if summary.system_types:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SYST Responses"))
        rows = [["System", "Count"]]
        for system, count in summary.system_types.most_common(limit):
            rows.append([_truncate_text(system, 64), str(count)])
        lines.append(_format_table(rows))

    if summary.feature_counts and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("FEAT Features"))
        rows = [["Feature", "Count"]]
        for feat, count in summary.feature_counts.most_common(limit):
            rows.append([_truncate_text(feat, 64), str(count)])
        lines.append(_format_table(rows))

    if summary.mac_addresses and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("MAC Addresses"))
        rows = [["Host", "MACs"]]
        for host, macs in sorted(summary.mac_addresses.items()):
            rows.append([host, ", ".join(sorted(macs))])
        lines.append(_format_table(rows))

    if summary.transfers:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Data Transfers"))
        rows = [["Direction", "Bytes", "File", "Client", "Server"]]
        for transfer in summary.transfers[:limit]:
            rows.append(
                [
                    transfer.direction,
                    format_bytes_as_mb(transfer.bytes),
                    _truncate_text(transfer.filename or "-", 48),
                    transfer.client_ip,
                    transfer.server_ip,
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
                steps = item.get("steps", [])
                rows.append(
                    [
                        _highlight_public_ips(str(item.get("host", "-"))),
                        str(item.get("confidence", "-")),
                        _truncate_text(
                            ", ".join(str(v) for v in targets[:4])
                            if isinstance(targets, list)
                            else str(targets),
                            52,
                        ),
                        _truncate_text(
                            "; ".join(str(v) for v in steps[:3])
                            if isinstance(steps, list)
                            else str(steps),
                            70,
                        ),
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
                indicators = item.get("indicators", [])
                rows.append(
                    [
                        str(item.get("cluster", "-")),
                        _highlight_public_ips(str(item.get("host", "-"))),
                        str(len(indicators) if isinstance(indicators, list) else 0),
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
                rows.append(
                    [
                        _truncate_text(str(item.get("indicator", "-")), 40),
                        _truncate_text(
                            _redact_in_text(str(item.get("value", "-"))), 40
                        ),
                        _truncate_text(
                            ", ".join(_highlight_public_ips(str(v)) for v in hosts[:4])
                            if isinstance(hosts, list)
                            else "-",
                            70,
                        ),
                    ]
                )
            lines.append(_format_table(rows))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for detection in detections[: max(limit, 20)]:
            severity = str(detection.get("severity", "info")).lower()
            summary_text = str(detection.get("summary", ""))
            details = detection.get("details", "")
            if severity == "high":
                marker = danger("[HIGH]")
            elif severity == "medium":
                marker = warn("[WARN]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

    if summary.credential_hits:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Credential Hits"))
        for hit in summary.credential_hits[:limit]:
            lines.append(
                f"{format_ts(hit.ts)}  {hit.client_ip} -> {hit.server_ip}  "
                f"USER {hit.username or '-'} PASS {_redact_secret(hit.password)}"
            )

    if getattr(summary, "benign_context", None):
        notes = [str(v) for v in (summary.benign_context or []) if str(v).strip()]
        if notes:
            lines.append(SUBSECTION_BAR)
            lines.append(header("False-Positive Context"))
            for note in notes[: _limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(note)}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
