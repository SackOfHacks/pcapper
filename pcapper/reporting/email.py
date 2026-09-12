"""Rendered output for email analysis.

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
from ..email import EmailSummary
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
    _format_counter,
    _format_kv,
    _format_sessions_table,
    _format_table,
    _limit_value,
    _meaningful_plaintext_items,
    _redact_in_text,
    _render_deterministic_checks,
    _truncate_text,
)


def _email_mitre_techniques(summary: EmailSummary) -> list[str]:
    """Map observed email findings to ATT&CK technique IDs for triage."""
    dc = summary.deterministic_checks or {}

    def _has(key: str) -> bool:
        return bool([v for v in (dc.get(key, []) or []) if str(v).strip()])

    tids: list[str] = []

    def _add(tid: str) -> None:
        if tid not in tids:
            tids.append(tid)

    if _has("phishing_indicators") or _has("suspicious_attachments"):
        _add("T1566.001 Phishing: Spearphishing Attachment")
    if _has("phishing_urls"):
        _add("T1566.002 Phishing: Spearphishing Link")
    if _has("sender_spoofing") or _has("email_auth_failures"):
        _add("T1566 Phishing")
        _add("T1656 Impersonation (BEC)")
    if _has("credential_exposure") or _has("webmail_credential_submission"):
        _add("T1040 Network Sniffing (cleartext credentials)")
    if _has("auth_abuse"):
        _add("T1110 Brute Force")
    if _has("smtp_recon"):
        _add("T1087.003 Account Discovery: Email Account")
    if _has("beaconing"):
        _add("T1071.003 Application Layer Protocol: Mail Protocols")
    if _has("exfiltration_signals"):
        _add("T1048 Exfiltration Over Alternative Protocol")
    if _has("server_fanout"):
        _add("T1590/T1046 Mail infrastructure enumeration")
    return tids


def render_email_summary(
    summary: EmailSummary, verbose: bool = False, show_timeline: bool = False
) -> str:
    limit = _apply_verbose_limit(12)
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"EMAIL ANALYSIS :: {summary.path.name}"))

    # ---- Analyst Verdict -------------------------------------------------
    dc = summary.deterministic_checks or {}

    def _edc(key: str) -> list[str]:
        return [str(v) for v in (dc.get(key, []) or []) if str(v).strip()]

    e_phish = _edc("phishing_indicators")
    e_cred = _edc("credential_exposure") + _edc("webmail_credential_submission")
    e_exfil = _edc("exfiltration_signals")
    e_attach = _edc("suspicious_attachments")
    e_authabuse = _edc("auth_abuse")
    e_fanout = _edc("server_fanout")
    e_spoof = _edc("sender_spoofing")
    e_authfail = _edc("email_auth_failures")
    e_urls = _edc("phishing_urls")
    e_recon = _edc("smtp_recon")
    e_beacon = _edc("beaconing")
    reasons: list[str] = []
    if e_cred:
        reasons.append(f"cleartext/webmail credential exposure ({len(e_cred)})")
    if e_spoof:
        reasons.append(f"sender spoofing / BEC indicator(s) ({len(e_spoof)})")
    if e_authfail:
        reasons.append(f"email-auth (SPF/DKIM/DMARC) failure(s) ({len(e_authfail)})")
    if e_phish:
        reasons.append(f"phishing subject indicator(s) ({len(e_phish)})")
    if e_urls:
        reasons.append(f"suspicious URL(s) in mail ({len(e_urls)})")
    if e_attach:
        reasons.append(f"suspicious attachment(s) ({len(e_attach)})")
    if e_exfil:
        reasons.append(f"exfiltration signal(s) ({len(e_exfil)})")
    if e_beacon:
        reasons.append(f"mail-protocol beaconing ({len(e_beacon)})")
    if e_authabuse:
        reasons.append(f"mail auth abuse ({len(e_authabuse)})")
    if e_fanout:
        reasons.append(f"mail-server fan-out ({len(e_fanout)})")
    if e_recon:
        reasons.append(f"SMTP user-enumeration recon ({len(e_recon)})")
    malicious = e_phish or e_exfil or e_attach or e_spoof
    if malicious:
        v_text, v_fn = "MALICIOUS EMAIL ACTIVITY", danger
    elif e_authfail:
        v_text, v_fn = "EMAIL SPOOFING / AUTH FAILURE — REVIEW", warn
    elif e_cred:
        v_text, v_fn = "CLEARTEXT MAIL CREDENTIALS EXPOSED", warn
    elif e_urls or e_authabuse or e_fanout or e_beacon or e_recon:
        v_text, v_fn = "SUSPICIOUS EMAIL ACTIVITY", warn
    elif summary.total_messages > 0 or summary.email_packets > 0:
        v_text, v_fn = "EMAIL TRAFFIC — NO HIGH-RISK SIGNAL", ok
    else:
        v_text, v_fn = "NO EMAIL ACTIVITY DETECTED", ok
    lines.append(header("Analyst Verdict"))
    lines.append(v_fn(f"[VERDICT] {v_text}"))
    for reason in reasons:
        lines.append(warn(f"- {reason}"))
    tids = _email_mitre_techniques(summary)
    if tids:
        lines.append(muted("  ATT&CK: " + ", ".join(tids)))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors[: _limit_value(4)]:
            lines.append(danger(f"- {err}"))

    # ---- Overview --------------------------------------------------------
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("Email Packets", str(summary.email_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    if summary.duration_seconds is not None:
        lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))
    lines.append(_format_kv("Messages", str(summary.total_messages)))
    lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))
    if summary.protocol_counts:
        lines.append(_format_kv("Protocols", _format_counter(summary.protocol_counts, 6)))

    if summary.server_ports:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server Ports"))
        lines.append(_counter_table(summary.server_ports, "Port", limit=limit))

    if summary.client_counts or summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Mail Clients & Servers"))
        lines.append(
            _format_client_server_table(summary.client_counts, summary.server_counts)
        )

    if summary.hostname_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Hostnames (HELO/EHLO)"))
        rows = [["Hostname", "Count"]]
        for name, count in summary.hostname_counts.most_common(limit):
            rows.append([_truncate_text(name, 50), str(count)])
        lines.append(_format_table(rows))

    if summary.smtp_command_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SMTP Commands"))
        lines.append(_counter_table(summary.smtp_command_counts, "Command", limit=limit))
    if summary.pop3_command_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("POP3 Commands"))
        lines.append(_counter_table(summary.pop3_command_counts, "Command", limit=limit))
    if summary.imap_command_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("IMAP Commands"))
        lines.append(_counter_table(summary.imap_command_counts, "Command", limit=limit))

    if summary.response_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Response Codes"))
        lines.append(_counter_table(summary.response_counts, "Code", limit=limit))

    if summary.auth_methods:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Auth Methods"))
        lines.append(_counter_table(summary.auth_methods, "Method", limit=limit))

    if summary.auth_failure_ip_counts or summary.auth_success_ip_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Auth Outcomes (by client)"))
        rows = [["Failures", "Successes"]]
        fail_text = (
            ", ".join(
                f"{ip}({count})"
                for ip, count in summary.auth_failure_ip_counts.most_common(
                    _limit_value(6)
                )
            )
            or "-"
        )
        succ_text = (
            ", ".join(
                f"{ip}({count})"
                for ip, count in summary.auth_success_ip_counts.most_common(
                    _limit_value(6)
                )
            )
            or "-"
        )
        rows.append([fail_text, succ_text])
        lines.append(_format_table(rows))

    # ---- Email authentication (SPF/DKIM/DMARC) ---------------------------
    if summary.auth_result_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Email Authentication (SPF/DKIM/DMARC)"))
        rows = [["Verdict", "Count"]]
        for token, count in summary.auth_result_counts.most_common(_limit_value(10)):
            verdict = token.split("=", 1)[-1].lower()
            label = token
            if verdict in {
                "fail", "softfail", "none", "hardfail", "permerror", "temperror",
            }:
                label = f"{token}  <-- FAIL"
            rows.append([label, str(count)])
        lines.append(_format_table(rows))

    if summary.from_counts or summary.to_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Senders / Recipients"))
        lines.append(_format_kv("Top Senders", _format_counter(summary.from_counts, 8)))
        lines.append(
            _format_kv("Top Recipients", _format_counter(summary.to_counts, 8))
        )

    if summary.email_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Email Addresses"))
        rows = [["Email", "Count"]]
        for name, count in summary.email_counts.most_common(limit):
            rows.append([_truncate_text(name, 70), str(count)])
        lines.append(_format_table(rows))

    if summary.domain_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Domains"))
        rows = [["Domain", "Count"]]
        for name, count in summary.domain_counts.most_common(limit):
            rows.append([_truncate_text(name, 50), str(count)])
        lines.append(_format_table(rows))

    if summary.webmail_provider_counts or summary.webmail_host_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Webmail Activity"))
        if summary.webmail_provider_counts:
            lines.append(
                _format_kv(
                    "Providers", _format_counter(summary.webmail_provider_counts, 6)
                )
            )
        if summary.webmail_host_counts:
            lines.append(
                _format_kv("Hosts", _format_counter(summary.webmail_host_counts, 6))
            )
        if summary.webmail_action_counts:
            lines.append(
                _format_kv("Actions", _format_counter(summary.webmail_action_counts, 8))
            )

    if summary.attachment_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Attachments"))
        rows = [["Filename", "Count"]]
        for name, count in summary.attachment_counts.most_common(limit):
            rows.append([_truncate_text(name, 60), str(count)])
        lines.append(_format_table(rows))

    # ---- Detections ------------------------------------------------------
    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections[: _limit_value(14)]:
            sev = str(item.get("severity", "info")).upper()
            title = str(item.get("title") or item.get("summary") or "Detection")
            details = _redact_in_text(str(item.get("details", "")))
            paint = danger if sev in {"CRITICAL", "HIGH"} else warn
            lines.append(paint(f"[{sev}] {title}"))
            if details:
                lines.append(muted(f"  {details}"))

    # ---- IOC summary (pivot points for the investigation) ----------------
    ioc_lines: list[str] = []
    if summary.originating_ip_counts:
        ioc_lines.append(
            _format_kv(
                "Originating IPs", _format_counter(summary.originating_ip_counts, 8)
            )
        )
    susp_urls = [
        a for a in (summary.artifacts or []) if getattr(a, "kind", "") == "suspicious_url"
    ]
    if susp_urls:
        ioc_lines.append(muted("Suspicious URLs:"))
        for art in susp_urls[: _limit_value(8)]:
            ioc_lines.append(muted(f"  - {_truncate_text(str(art.detail), 110)}"))
    elif summary.url_counts:
        ioc_lines.append(
            _format_kv("URLs in mail", _format_counter(summary.url_counts, 6))
        )
    attach_iocs = [
        a
        for a in (summary.artifacts or [])
        if getattr(a, "kind", "") == "mime_attachment" and "sha256=" in str(a.detail)
    ]
    if attach_iocs:
        ioc_lines.append(muted("Attachment hashes:"))
        for art in attach_iocs[: _limit_value(8)]:
            ioc_lines.append(muted(f"  - {_truncate_text(str(art.detail), 110)}"))
    if summary.mailer_counts:
        ioc_lines.append(
            _format_kv("Mailer/X-Mailer", _format_counter(summary.mailer_counts, 5))
        )
    if ioc_lines:
        lines.append(SUBSECTION_BAR)
        lines.append(header("IOC Summary"))
        lines.extend(ioc_lines)

    # ---- Cleartext credentials ------------------------------------------
    if summary.username_counts or summary.password_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Cleartext Credential Exposure"))
        lines.append(
            danger("Mail credentials observed in cleartext (rotate exposed accounts).")
        )
        if summary.username_counts:
            lines.append(
                _format_kv("Usernames", _format_counter(summary.username_counts, 8))
            )
        if summary.password_counts:
            lines.append(
                _format_kv("Passwords", _format_counter(summary.password_counts, 8))
            )

    # ---- Observed plaintext ---------------------------------------------
    if summary.plaintext_strings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Plaintext"))
        rows = [["String", "Count"]]
        for text, count in _meaningful_plaintext_items(summary.plaintext_strings, limit):
            rows.append([_truncate_text(text, 70), str(count)])
        lines.append(_format_table(rows))

    # ---- Sessions --------------------------------------------------------
    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Mail Sessions"))
        lines.append(
            _format_sessions_table(
                summary.conversations,
                limit,
                extra_cols=[("Proto", lambda c: getattr(c, "protocol", "-"))],
            )
        )

    # ---- Artifacts -------------------------------------------------------
    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts"))
        rows = [["Type", "Detail", "Src", "Dst", "Pkt"]]
        for item in summary.artifacts[: _limit_value(20)]:
            rows.append(
                [
                    str(item.kind),
                    _truncate_text(_redact_in_text(str(item.detail)), 56),
                    str(item.src),
                    str(item.dst),
                    str(getattr(item, "packet", "") or "-"),
                ]
            )
        lines.append(_format_table(rows))

    # ---- Timeline --------------------------------------------------------
    if show_timeline and summary.timeline_events:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Timeline"))
        rows = [["Time", "Protocol", "Direction", "Stage", "Detail"]]
        for ev in summary.timeline_events[: _limit_value(20)]:
            rows.append(
                [
                    format_ts(getattr(ev, "ts", None)),
                    getattr(ev, "protocol", "-"),
                    getattr(ev, "direction", "-"),
                    getattr(ev, "stage", "-"),
                    _truncate_text(getattr(ev, "detail", "-"), 64),
                ]
            )
        lines.append(_format_table(rows))

    # ---- Deterministic checks -------------------------------------------
    _render_deterministic_checks(
        lines,
        summary,
        "Deterministic Email Security Checks",
        [
            ("credential_exposure", "Cleartext Credential Exposure"),
            ("webmail_credential_submission", "Webmail Credential Submission"),
            ("email_auth_failures", "Email Auth Failures (SPF/DKIM/DMARC)"),
            ("sender_spoofing", "Sender Spoofing / BEC"),
            ("phishing_indicators", "Phishing Indicators"),
            ("phishing_urls", "Suspicious URLs"),
            ("suspicious_attachments", "Suspicious Attachments"),
            ("smtp_recon", "SMTP User Enumeration (VRFY/EXPN)"),
            ("beaconing", "Mail-Protocol Beaconing"),
            ("exfiltration_signals", "Exfiltration Signals"),
            ("auth_abuse", "Mail Auth Abuse"),
            ("server_fanout", "Server Fan-out"),
            ("originating_ips", "Originating IPs"),
            ("webmail_activity", "Webmail Activity"),
        ],
    )
    lines.append(SECTION_BAR)
    return _finalize_output(lines)
