"""Rendered output for strings analysis.

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
from ..strings import StringsSummary

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
    _render_deterministic_checks,
)


def render_strings_summary(summary: StringsSummary) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"STRINGS ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Strings Found", str(summary.strings_found)))
    lines.append(_format_kv("Unique Strings", str(summary.unique_strings)))

    # ---- Analyst Verdict -------------------------------------------------
    dc = summary.deterministic_checks or {}

    def _sdc(key: str) -> list[str]:
        return [str(v) for v in (dc.get(key, []) or []) if str(v).strip()]

    s_creds = _sdc("cleartext_credentials")
    s_lolbin = _sdc("command_execution_or_lolbin")
    s_exfil = _sdc("download_stager_or_exfil")
    s_otwrite = _sdc("ot_ics_control_write_ops")
    s_ctf = _sdc("ctf_flag_or_challenge_markers")
    reasons: list[str] = []
    if s_creds:
        reasons.append(f"cleartext credentials in {len(s_creds)} string(s)")
    if s_lolbin:
        reasons.append(f"command/LOLBin execution strings ({len(s_lolbin)})")
    if s_exfil:
        reasons.append(f"download-stager / exfil strings ({len(s_exfil)})")
    if s_otwrite:
        reasons.append(f"OT/ICS control-write operation markers ({len(s_otwrite)})")
    if s_ctf:
        reasons.append(f"CTF flag / challenge markers ({len(s_ctf)})")
    if s_creds or s_lolbin or s_exfil:
        v_text, v_fn = "MALICIOUS / SENSITIVE STRINGS PRESENT", danger
    elif s_otwrite:
        v_text, v_fn = "OT/ICS CONTROL-WRITE STRINGS PRESENT", warn
    elif s_ctf:
        v_text, v_fn = "CTF FLAG MARKERS IN STRINGS", warn
    elif summary.suspicious_strings:
        v_text, v_fn = "SUSPICIOUS STRINGS PRESENT", warn
    else:
        v_text, v_fn = "NO HIGH-RISK STRINGS DETECTED", ok
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    lines.append(v_fn(f"[VERDICT] {v_text}"))
    for reason in reasons:
        lines.append(warn(f"- {reason}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Top Cleartext Strings"))
    if not summary.top_strings:
        lines.append(muted("No cleartext strings extracted."))
    else:
        rows = [["String", "Count"]]
        for item in summary.top_strings:
            rows.append([item.value, str(item.count)])
        lines.append(_format_table(rows))

    if summary.urls or summary.emails or summary.domains:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts"))
        if summary.urls:
            rows = [["URL", "Count"]]
            for item in summary.urls:
                rows.append([item.value, str(item.count)])
            lines.append(_format_table(rows))
        if summary.emails:
            rows = [["Email", "Count"]]
            for item in summary.emails:
                rows.append([item.value, str(item.count)])
            lines.append(_format_table(rows))
        if summary.domains:
            rows = [["Domain", "Count"]]
            for item in summary.domains:
                rows.append([item.value, str(item.count)])
            lines.append(_format_table(rows))

    if summary.suspicious_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Suspicious or Malicious Indicators"))
        rows = [["String", "Count", "Reason", "Top Sources", "Top Destinations"]]
        if summary.suspicious_details:
            for item in summary.suspicious_details:
                reasons = ", ".join(item.get("reasons", [])) or "-"
                top_src = (
                    ", ".join(
                        f"{ip}({count})" for ip, count in item.get("top_sources", [])
                    )
                    or "-"
                )
                top_dst = (
                    ", ".join(
                        f"{ip}({count})"
                        for ip, count in item.get("top_destinations", [])
                    )
                    or "-"
                )
                rows.append(
                    [
                        str(item.get("value", "-")),
                        str(item.get("count", "-")),
                        reasons,
                        top_src,
                        top_dst,
                    ]
                )
        else:
            for item in summary.suspicious_strings:
                rows.append([item.value, str(item.count), "-", "-", "-"])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Client Cleartext Highlights"))
    if not summary.client_strings:
        lines.append(muted("No client-attributed strings."))
    else:
        for ip, items in summary.client_strings.items():
            lines.append(label(f"Client {ip}"))
            rows = [["String", "Count"]]
            for item in items:
                rows.append([item.value, str(item.count)])
            lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Server Cleartext Highlights"))
    if not summary.server_strings:
        lines.append(muted("No server-attributed strings."))
    else:
        for ip, items in summary.server_strings.items():
            lines.append(label(f"Server {ip}"))
            rows = [["String", "Count"]]
            for item in items:
                rows.append([item.value, str(item.count)])
            lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Strings Anomalies"))
    if not summary.anomalies:
        lines.append(ok("No string-specific anomalies detected."))
    else:
        for item in summary.anomalies:
            lines.append(warn(f"[WARN] {item}"))

    if summary.threat_hypotheses:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Threat Hypotheses"))
        for hyp in summary.threat_hypotheses:
            conf = str(hyp.get("confidence", "?"))
            text = str(hyp.get("hypothesis", "-"))
            ev = hyp.get("evidence", "")
            lines.append(warn(f"- [{conf}] {text} (evidence={ev})"))

    if summary.ot_findings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT/ICS Markers in Strings"))
        for item in summary.ot_findings[: _limit_value(15)]:
            lines.append(muted(f"- {item}"))
    if summary.ctf_indicators:
        lines.append(SUBSECTION_BAR)
        lines.append(header("CTF Flag / Challenge Markers"))
        for item in summary.ctf_indicators[: _limit_value(15)]:
            lines.append(muted(f"- {item}"))

    _render_deterministic_checks(
        lines,
        summary,
        "Deterministic String Security Checks",
        [
            ("cleartext_credentials", "Cleartext Credentials"),
            ("command_execution_or_lolbin", "Command Execution / LOLBin"),
            ("download_stager_or_exfil", "Download Stager / Exfil"),
            ("ot_ics_control_write_ops", "OT/ICS Control-Write Operations"),
            ("ot_ics_protocol_markers", "OT/ICS Protocol Markers"),
            ("ctf_flag_or_challenge_markers", "CTF Flag / Challenge Markers"),
        ],
    )

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
