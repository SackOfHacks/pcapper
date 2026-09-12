"""Rendered output for ntlm analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from typing import TYPE_CHECKING
from ..coloring import (
    danger,
    header,
    highlight,
    muted,
    ok,
)
if TYPE_CHECKING:
    from ..ntlm import NtlmAnalysis

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _counter_table,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
    _render_deterministic_checks,
    _render_protocol_verdict,
)


def render_ntlm_summary(summary: "NtlmAnalysis") -> str:
    """
    Render NTLM analysis results.
    """
    from ..utils import format_ts

    if not summary:
        return ""

    lines = []
    lines.append(SECTION_BAR)
    lines.append(header(f"NTLM ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)
    _render_protocol_verdict(
        lines, label="NTLM", anomalies=getattr(summary, "anomalies", None)
    )

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    # 1. Overview
    lines.append(_format_kv("Scan Duration", f"{summary.duration:.2f}s"))
    lines.append(_format_kv("Total Sessions", str(summary.total_sessions)))
    lines.append(_format_kv("Authenticated", str(summary.authenticated_sessions)))
    lines.append(_format_kv("Unique Users", str(len(summary.unique_users))))
    lines.append(_format_kv("Unique Domains", str(len(summary.unique_domains))))
    lines.append(_format_kv("Unique Sources", str(len(summary.src_counts))))
    lines.append(_format_kv("Unique Destinations", str(len(summary.dst_counts))))

    # Check for legacy NTLM usage
    legacy_count = sum(1 for s in summary.sessions if s.version == "NTLMv1")
    if legacy_count > 0:
        lines.append(danger(f"Legacy NTLMv1 Sessions: {legacy_count}"))
    else:
        lines.append(ok("No Legacy NTLMv1 detected."))

    # 2. Users & Domains
    lines.append(SUBSECTION_BAR)
    lines.append(header("Identified User Accounts"))
    if not summary.unique_users:
        lines.append(muted("No usernames extracted."))
    else:
        # Group by domain
        by_domain = {}
        for dom, user in summary.unique_users:
            if dom not in by_domain:
                by_domain[dom] = []
            by_domain[dom].append(user)

        for dom, users in sorted(by_domain.items()):
            display_dom = dom if dom != "<NO_DOMAIN>" else "(No Domain)"
            lines.append(highlight(f"Domain: {display_dom}"))
            for u in sorted(users):
                lines.append(f"  - {u}")

        # 3. Workstations
        # 4. Requests & Responses
        if summary.request_counts or summary.response_counts:
            lines.append(SUBSECTION_BAR)
            lines.append(header("NTLM Requests & Responses"))
            rows = [["Message", "Requests", "Responses"]]
            all_msgs = set(summary.request_counts.keys()).union(
                summary.response_counts.keys()
            )
            for name in sorted(all_msgs):
                rows.append(
                    [
                        name,
                        str(summary.request_counts.get(name, 0)),
                        str(summary.response_counts.get(name, 0)),
                    ]
                )
            lines.append(_format_table(rows))

        if summary.services:
            lines.append(SUBSECTION_BAR)
            lines.append(header("NTLM Services"))
            lines.append(_counter_table(summary.services, "Service", limit=_limit_value(10)))

        if summary.status_codes:
            lines.append(SUBSECTION_BAR)
            lines.append(header("NTLM Status Codes"))
            lines.append(_counter_table(summary.status_codes, "Status", limit=_limit_value(10)))

        # 5. Conversations
        lines.append(SUBSECTION_BAR)
        lines.append(header("NTLM Conversations"))
        if not summary.conversations:
            lines.append(muted("No NTLM conversations summarized."))
        else:
            rows = [["Src", "Dst", "Ports", "Packets", "First Seen", "Last Seen"]]
            for convo in sorted(
                summary.conversations, key=lambda c: c.packets, reverse=True
            )[: _limit_value(12)]:
                rows.append(
                    [
                        convo.src_ip,
                        convo.dst_ip,
                        f"{convo.src_port}->{convo.dst_port}",
                        str(convo.packets),
                        format_ts(convo.first_seen),
                        format_ts(convo.last_seen),
                    ]
                )
            lines.append(_format_table(rows))

        # 6. Artifacts
        if summary.artifacts:
            lines.append(SUBSECTION_BAR)
            lines.append(header("NTLM Artifacts"))
            rows = [["Artifact", "Description"]]
            for item in summary.artifacts[: _limit_value(15)]:
                rows.append([item.value, item.description])
            lines.append(_format_table(rows))

    crackable = getattr(summary, "crackable_hashes", None)
    if crackable:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Crackable Net-NTLM Hashes (offline password cracking)"))
        lines.append(
            danger(
                f"  {len(crackable)} authentication(s) yielded a crackable hash. "
                "Feed to Hashcat to recover/confirm the account password:"
            )
        )
        lines.append(
            muted("    NTLMv2 -> hashcat -m 5600   |   NTLMv1 -> hashcat -m 5500")
        )
        for rec in crackable[: _limit_value(20)]:
            user = rec.get("username", "?")
            domain = rec.get("domain") or "(no domain)"
            flow = f"{rec.get('src_ip', '?')} -> {rec.get('dst_ip', '?')}"
            lines.append(
                muted(
                    f"  [{rec.get('version', '?')}] {domain}\\{user}  ({flow}, "
                    f"-m {rec.get('hashcat_mode', '?')})"
                )
            )
            lines.append(f"    {rec.get('hash', '')}")

    lines.append(SUBSECTION_BAR)
    lines.append(header("Client Workstations"))
    if not summary.unique_workstations:
        lines.append(muted("No workstation names extracted."))
    else:
        for ws in sorted(summary.unique_workstations):
            lines.append(f"  - {ws}")

    # 4. Session Details (Top 10)
    lines.append(SUBSECTION_BAR)
    lines.append(header("Recent NTLM Sessions (Max 10)"))

    sorted_sessions = sorted(summary.sessions, key=lambda x: x.ts, reverse=True)[
        : _limit_value(10)
    ]
    if not sorted_sessions:
        lines.append(muted("No sessions."))
    else:
        # Table Header
        # TS | Src -> Dst | User | Domain | Ver
        row_fmt = "{:<20} | {:<35} | {:<15} | {:<15} | {:<10}"
        lines.append(
            muted(row_fmt.format("Timestamp", "Src -> Dst", "User", "Domain", "Ver"))
        )
        lines.append(muted("-" * 105))

        for s in sorted_sessions:
            ts_str = format_ts(s.ts)
            flow_str = f"{s.src_ip}:{s.src_port} -> {s.dst_ip}:{s.dst_port}"
            user_str = s.username if s.username else "-"
            dom_str = s.domain if s.domain else "-"
            ver_str = s.version

            line_str = row_fmt.format(ts_str, flow_str, user_str, dom_str, ver_str)
            if s.version == "NTLMv1":
                lines.append(danger(line_str))
            else:
                lines.append(line_str)

    lines.append(SECTION_BAR)
    _render_deterministic_checks(
        lines, summary, "Deterministic NTLM Security Checks", [
            ("ntlmv1_legacy_authentication", "NTLMv1 Legacy Authentication"),
            ("anonymous_or_null_session_attempts", "Anonymous/Null Session Attempts"),
            ("auth_failure_burst", "Authentication Failure Burst"),
            ("credential_reuse_spread", "Credential Reuse Spread"),
            ("cross_service_ntlm_usage", "Cross-Service NTLM Usage"),
            ("high_volume_ntlm_source", "High-Volume NTLM Source"),
            ("incomplete_handshake_patterns", "Incomplete Handshake Patterns"),
            ("public_endpoint_ntlm_activity", "Public Endpoint NTLM Activity"),
        ]
    )
    return _finalize_output(lines)
