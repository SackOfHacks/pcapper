"""Rendered output for hostname analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from collections import Counter, defaultdict
from ..coloring import (
    danger,
    header,
    muted,
    ok,
    warn,
)
from ..hostname import HostnameSummary
from ..utils import (
    format_ts,
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
    _verbose_output,
    set_verbose_output,
)


def render_hostname_summary(
    summary: HostnameSummary, limit: int = 25, verbose: bool = False
) -> str:
    force_full_output = bool(summary.target_ip) or bool(
        str(getattr(summary, "hostname_query", "") or "").strip()
    )
    restore_verbose_flag: bool | None = None
    if force_full_output and not _verbose_output():
        restore_verbose_flag = _verbose_output()
        set_verbose_output(True)
    if force_full_output:
        verbose = True

    limit = _apply_verbose_limit(limit)
    lines: list[str] = []
    try:
        all_ip_mode = not bool(summary.target_ip)
        lines.append(SECTION_BAR)
        lines.append(header(f"HOSTNAME DISCOVERY :: {summary.path.name}"))
        lines.append(SECTION_BAR)

        if summary.errors:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Errors"))
            error_rows = summary.errors if verbose else summary.errors[: _limit_value(25)]
            for err in error_rows:
                lines.append(danger(f"- {err}"))
            if not verbose and len(summary.errors) > 25:
                lines.append(muted(f"... {len(summary.errors) - 25} more errors"))

        lines.append(_format_kv("Target IP", summary.target_ip or "ALL"))
        if str(getattr(summary, "hostname_query", "") or "").strip():
            lines.append(_format_kv("Hostname Filter", str(summary.hostname_query)))
        if getattr(summary, "port_filter", None):
            lines.append(_format_kv("Port Filter", str(summary.port_filter)))
        if str(getattr(summary, "search_query", "") or "").strip():
            lines.append(_format_kv("Search Filter", str(summary.search_query)))
        lines.append(_format_kv("Packets Scanned", str(summary.total_packets)))
        lines.append(_format_kv("Relevant Packets", str(summary.relevant_packets)))
        lines.append(
            _format_kv(
                "Hostnames Found", str(len({item.hostname for item in summary.findings}))
            )
        )
        lines.append(
            _format_kv("Evidence Rows", str(sum(item.count for item in summary.findings)))
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

        if summary.protocol_counts:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Protocol Evidence"))
            rows = [["Protocol", "Count"]]
            proto_limit = None if verbose else 10
            for proto, count in summary.protocol_counts.most_common(proto_limit):
                rows.append([str(proto), str(count)])
            lines.append(_format_table(rows))

        if summary.method_counts:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Discovery Methods"))
            rows = [["Method", "Count"]]
            method_limit = None if verbose else 12
            for method, count in summary.method_counts.most_common(method_limit):
                rows.append([str(method), str(count)])
            lines.append(_format_table(rows))

        conflict_profiles = list(getattr(summary, "conflict_profiles", []) or [])
        if conflict_profiles:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Conflict Profiles"))
            rows = [["Type", "Hostname/IP", "Scope", "Evidence", "Methods"]]
            for item in conflict_profiles[: _limit_value(limit if verbose else 12)]:
                profile_type = str(item.get("type", "-") or "-")
                if profile_type == "hostname_to_many_ips":
                    identity = str(item.get("hostname", "-"))
                    scope = f"ips={int(item.get('ip_count', 0) or 0)}"
                else:
                    identity = str(item.get("ip", "-"))
                    scope = f"hosts={int(item.get('host_count', 0) or 0)}"
                methods = item.get("methods", [])
                rows.append(
                    [
                        profile_type,
                        identity,
                        scope,
                        str(item.get("evidence", "-")),
                        _truncate_text(
                            ", ".join(str(v) for v in methods[:4])
                            if isinstance(methods, list)
                            else "-",
                            70,
                        ),
                    ]
                )
            lines.append(_format_table(rows))

        drift_profiles = list(getattr(summary, "drift_profiles", []) or [])
        if drift_profiles:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Temporal Drift Profiles"))
            rows = [["Hostname", "First Seen", "Last Seen", "IP Count", "IPs"]]
            for item in drift_profiles[: _limit_value(limit if verbose else 10)]:
                ips = item.get("ips", [])
                rows.append(
                    [
                        str(item.get("hostname", "-")),
                        format_ts(item.get("first_seen")),
                        format_ts(item.get("last_seen")),
                        str(item.get("ip_count", "-")),
                        _truncate_text(
                            ", ".join(
                                str(v) for v in (ips[:5] if isinstance(ips, list) else [])
                            )
                            or "-",
                            80,
                        ),
                    ]
                )
            lines.append(_format_table(rows))

        corroboration = list(getattr(summary, "cross_protocol_corroboration", []) or [])
        if corroboration:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Cross-Protocol Corroboration"))
            rows = [["Hostname", "Protocols", "Methods", "Confidence", "Evidence"]]
            for item in corroboration[: _limit_value(limit if verbose else 12)]:
                protocols = item.get("protocols", [])
                methods = item.get("methods", [])
                rows.append(
                    [
                        str(item.get("hostname", "-")),
                        _truncate_text(
                            ", ".join(
                                str(v)
                                for v in (
                                    protocols[:4] if isinstance(protocols, list) else []
                                )
                            )
                            or "-",
                            50,
                        ),
                        _truncate_text(
                            ", ".join(
                                str(v)
                                for v in (methods[:3] if isinstance(methods, list) else [])
                            )
                            or "-",
                            70,
                        ),
                        str(item.get("confidence", "-")),
                        str(item.get("evidence", "-")),
                    ]
                )
            lines.append(_format_table(rows))

        suspicious_names = list(getattr(summary, "suspicious_name_profiles", []) or [])
        if suspicious_names:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Suspicious Naming Analytics"))
            rows = [["Hostname", "Reasons", "Entropy", "Evidence", "Mapped IPs"]]
            for item in suspicious_names[: _limit_value(limit if verbose else 12)]:
                reasons_val = item.get("reasons", [])
                ips = item.get("ips", [])
                rows.append(
                    [
                        str(item.get("hostname", "-")),
                        _truncate_text(
                            ", ".join(
                                str(v)
                                for v in (
                                    reasons_val[:4] if isinstance(reasons_val, list) else []
                                )
                            )
                            or "-",
                            70,
                        ),
                        str(item.get("entropy", "-")),
                        str(item.get("evidence", "-")),
                        _truncate_text(
                            ", ".join(
                                str(v) for v in (ips[:4] if isinstance(ips, list) else [])
                            )
                            or "-",
                            70,
                        ),
                    ]
                )
            lines.append(_format_table(rows))

        lines.append(SUBSECTION_BAR)
        lines.append(header("IP ↔ Hostname Correlation"))
        if not summary.findings:
            lines.append(
                muted(
                    "No hostname-to-IP correlation evidence found in inspected protocols."
                )
            )
        else:
            ip_hosts: dict[str, set[str]] = defaultdict(set)
            ip_evidence: Counter[str] = Counter()
            for finding in summary.findings:
                if not finding.mapped_ip:
                    continue
                ip_hosts[finding.mapped_ip].add(finding.hostname)
                ip_evidence[finding.mapped_ip] += finding.count

            if not ip_hosts:
                lines.append(
                    muted(
                        "No attributable IP mappings were extracted from hostname evidence."
                    )
                )
            else:
                rows = [["IP Address", "Hostnames", "Evidence"]]
                corr_limit = None if verbose else limit
                for ip_addr, evidence_count in ip_evidence.most_common(corr_limit):
                    hosts = sorted(ip_hosts.get(ip_addr, set()))
                    host_display = (
                        ", ".join(hosts) if verbose else ", ".join(hosts[: _limit_value(3)])
                    )
                    rows.append([ip_addr, host_display, str(evidence_count)])
                lines.append(_format_table(rows))
                if not verbose and len(ip_evidence) > limit:
                    lines.append(
                        muted(
                            f"... {len(ip_evidence) - limit} additional IP correlation rows"
                        )
                    )

        lines.append(SUBSECTION_BAR)
        lines.append(header("Discovered Hostnames"))
        if not summary.findings:
            if all_ip_mode:
                lines.append(muted("No hostname evidence found in inspected protocols."))
            else:
                lines.append(
                    muted(
                        "No hostname evidence found for target IP in inspected protocols."
                    )
                )
        else:
            rows = [
                [
                    "Hostname",
                    "Mapped IP",
                    "Method",
                    "Protocol",
                    "Confidence",
                    "Seen",
                    "Flow",
                    "Details",
                ]
            ]
            row_findings = summary.findings if verbose else summary.findings[:limit]
            for finding in row_findings:
                confidence = str(finding.confidence)
                if confidence == "HIGH":
                    confidence_display = ok(confidence)
                elif confidence == "MEDIUM":
                    confidence_display = warn(confidence)
                else:
                    confidence_display = muted(confidence)

                rows.append(
                    [
                        str(finding.hostname),
                        str(finding.mapped_ip or "-"),
                        str(finding.method),
                        str(finding.protocol),
                        confidence_display,
                        str(finding.count),
                        f"{finding.src_ip} -> {finding.dst_ip}",
                        str(finding.details)
                        if verbose
                        else _truncate_text(str(finding.details), 70),
                    ]
                )
            lines.append(_format_table(rows))
            if not verbose and len(summary.findings) > limit:
                lines.append(
                    muted(
                        f"... {len(summary.findings) - limit} additional hostname evidence rows"
                    )
                )

        false_positive_context = [
            str(v)
            for v in list(getattr(summary, "false_positive_context", []) or [])
            if str(v).strip()
        ]
        if false_positive_context:
            lines.append(
                SUBSECTION_BAR
            )
            lines.append(header("False-Positive Context"))
            for note in false_positive_context[: _limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(note)}"))

        lines.append(SUBSECTION_BAR)
        lines.append(header("Forensics Notes"))
        lines.append(
            muted(
                "- DNS A/AAAA and PTR mappings are strongest hostname-to-IP attribution evidence."
            )
        )
        lines.append(
            muted(
                "- HTTP Host and TLS SNI indicate intended server name and can reveal virtual-host targeting."
            )
        )
        lines.append(
            muted(
                "- NTLM/NetBIOS names are contextual clues and may reflect client/workstation naming."
            )
        )

        lines.append(SECTION_BAR)
        return _finalize_output(lines)
    finally:
        if restore_verbose_flag is not None:
            set_verbose_output(restore_verbose_flag)
