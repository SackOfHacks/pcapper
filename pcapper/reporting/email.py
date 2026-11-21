"""Rendered output for email (SMTP, POP3, IMAP, webmail): the messages
(senders, recipients, subjects, attachments and their hashes), sender
authentication (SPF/DKIM/DMARC), cleartext mail credentials and the URLs and
originating IPs to pivot on; protocol command detail is -v."""

from __future__ import annotations

from ..email import EmailSummary
from ..utils import format_duration, format_ts
from . import _style as st
from ._common import _meaningful_plaintext_items, _redact_in_text, _redact_secret, _render_deterministic_checks
from ._kv import counter_line, findings_for
from ._remote import counts, session_table

_FAIL_VERDICTS = {"fail", "softfail", "none", "hardfail", "permerror", "temperror"}


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


def _headline(summary: EmailSummary) -> tuple[object, str, list[str]]:
    dc = summary.deterministic_checks or {}

    def _edc(key: str) -> list[str]:
        return [str(v) for v in (dc.get(key, []) or []) if str(v).strip()]

    phish, cred = _edc("phishing_indicators"), _edc("credential_exposure") + _edc("webmail_credential_submission")
    exfil, attach, authabuse = _edc("exfiltration_signals"), _edc("suspicious_attachments"), _edc("auth_abuse")
    fanout, spoof, authfail = _edc("server_fanout"), _edc("sender_spoofing"), _edc("email_auth_failures")
    urls, recon, beacon = _edc("phishing_urls"), _edc("smtp_recon"), _edc("beaconing")
    reasons = [text for hits, text in (
        (cred, f"cleartext/webmail credential exposure ({len(cred)})"),
        (spoof, f"sender spoofing / BEC indicators ({len(spoof)})"),
        (authfail, f"SPF/DKIM/DMARC failures ({len(authfail)})"),
        (phish, f"phishing subject indicators ({len(phish)})"),
        (urls, f"suspicious URLs in mail ({len(urls)})"),
        (attach, f"suspicious attachments ({len(attach)})"),
        (exfil, f"exfiltration signals ({len(exfil)})"),
        (beacon, f"mail-protocol beaconing ({len(beacon)})"),
        (authabuse, f"mail auth abuse ({len(authabuse)})"),
        (fanout, f"mail-server fan-out ({len(fanout)})"),
        (recon, f"SMTP user enumeration ({len(recon)})"),
    ) if hits]
    if phish or exfil or attach or spoof:
        return "high", "malicious email activity: investigate", reasons
    if authfail:
        return "medium", "email spoofing / authentication failures: review", reasons
    if cred:
        return "medium", "cleartext mail credentials exposed", reasons
    if urls or authabuse or fanout or beacon or recon:
        return "medium", "suspicious email activity", reasons
    return None, "email traffic, no high-risk signal", reasons


def render_email_summary(summary: EmailSummary, verbose: bool = False, show_timeline: bool = False) -> str:
    rep = st.Report("Email", summary.path)
    findings = findings_for(summary, ot=False)
    if not summary.email_packets and not summary.total_messages and not st.material(findings):
        return rep.absent("email traffic (SMTP, POP3, IMAP or webmail)", summary.errors)
    severity, text, reasons = _headline(summary)
    worst = st.worst(findings) if findings else -1
    if findings and (severity is None or worst > st.sev_rank(severity)):
        severity = next(f.severity for f in findings if st.sev_rank(f.severity) == worst)
    rep.headline(severity, st.join([st.plural(len(findings), "finding") if findings else "", text]), st.join([
        f"{st.count(summary.email_packets)} mail packets · {st.plural(summary.total_messages, 'message')}",
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
        st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else "",
    ]))
    rep.scope(st.join([f"{st.plural(summary.unique_clients, 'client')} -> {st.plural(summary.unique_servers, 'server')}",
                       st.top(summary.protocol_counts, 4)]))
    for reason in reasons:
        rep.scope(reason)
    tids = _email_mitre_techniques(summary)
    if tids:
        rep.scope("ATT&CK: " + ", ".join(tids))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    rep.section("Messages", st.kv([
        counter_line("Senders", summary.from_counts, 8),
        counter_line("Recipients", summary.to_counts, 8),
        ("Subjects", st.top(summary.subject_counts, 6, fmt=lambda k, v: f"{_redact_in_text(str(k))} ({st.count(v)})")),
        counter_line("Originating IPs", summary.originating_ip_counts, 8),
        counter_line("Mailers", summary.mailer_counts, 4),
        counter_line("HELO/EHLO", summary.hostname_counts, 6),
    ]))
    rep.section("Attachments", counts(summary.attachment_counts, "Filename", width=80, noun="attachment"))
    hashes = [a for a in (summary.artifacts or []) if getattr(a, "kind", "") == "mime_attachment" and "sha256=" in str(a.detail)]
    suspicious_urls = [a for a in (summary.artifacts or []) if getattr(a, "kind", "") == "suspicious_url"]
    rep.section("IOCs", st.bullets([f"attachment  {a.detail}" for a in hashes], max_items=8, noun="hash")
                + st.bullets([f"URL  {a.detail}" for a in suspicious_urls], max_items=8, noun="URL")
                + (st.kv([counter_line("URLs in mail", summary.url_counts, 6)]) if not suspicious_urls else []))
    auth_results = st.top(summary.auth_result_counts, 10, fmt=lambda k, v: (
        st.bad(f"{k} ({v})") if str(k).split("=", 1)[-1].lower() in _FAIL_VERDICTS else f"{k} ({v})"))
    rep.section("Sender authentication", st.kv([("SPF/DKIM/DMARC", auth_results)]))
    rep.section("Credentials", st.kv([
        counter_line("Users", summary.username_counts, 8),
        ("Passwords", st.top(summary.password_counts, 8, fmt=lambda k, v: f"{_redact_secret(str(k))} ({v})")),
        counter_line("Auth methods", summary.auth_methods, 6),
        counter_line("Auth failures", summary.auth_failure_ip_counts, 6),
        counter_line("Auth successes", summary.auth_success_ip_counts, 6),
    ]))
    rep.section("Webmail", st.kv([
        counter_line("Providers", summary.webmail_provider_counts, 6),
        counter_line("Hosts", summary.webmail_host_counts, 6),
        counter_line("Actions", summary.webmail_action_counts, 8),
    ]))
    if show_timeline and summary.timeline_events:
        rep.section("Timeline", st.table(
            ["Time", "Protocol", "Direction", "Stage", "Detail"],
            [[st.ts(getattr(e, "ts", None)), getattr(e, "protocol", "-"), getattr(e, "direction", "-"), getattr(e, "stage", "-"),
              _redact_in_text(str(getattr(e, "detail", "-")))] for e in summary.timeline_events],
            max_rows=20, noun="event",
        ))
    rep.section("Sessions", session_table(summary.conversations, [("Proto", lambda c: c.protocol)], max_rows=8))

    rep.section("Protocol", st.kv([
        counter_line("SMTP", summary.smtp_command_counts, None),
        counter_line("POP3", summary.pop3_command_counts, None),
        counter_line("IMAP", summary.imap_command_counts, None),
        counter_line("Replies", summary.response_counts, None),
        counter_line("Ports", summary.server_ports, None),
    ]), detail=True)
    rep.section("Addresses and domains", st.kv([
        counter_line("Addresses", summary.email_counts, None),
        counter_line("Domains", summary.domain_counts, None),
        counter_line("Message-IDs", summary.message_id_counts, None),
        counter_line("Webmail pages", summary.webmail_page_counts, None),
        ("Secrets", st.top(summary.secret_counts, None, fmt=lambda k, v: f"{_redact_secret(str(k))} ({v})")),
    ]), detail=True)
    rep.section("Plaintext", st.table(["String", "Count"], [[_redact_in_text(t), st.count(n)] for t, n in
                                                          _meaningful_plaintext_items(summary.plaintext_strings, 10**9)],
                                      align="lr", max_rows=None), detail=True)
    rep.section("Artifacts", st.table(
        ["Kind", "Detail", "Flow", "Packet"],
        [[a.kind, _redact_in_text(str(a.detail)), st.flow(a.src, a.dst), getattr(a, "packet", "") or "-"] for a in summary.artifacts],
        max_rows=None,
    ), detail=True)
    if not show_timeline:
        rep.section("Timeline", st.table(
            ["Time", "Protocol", "Direction", "Stage", "Detail"],
            [[st.ts(getattr(e, "ts", None)), getattr(e, "protocol", "-"), getattr(e, "direction", "-"), getattr(e, "stage", "-"),
              _redact_in_text(str(getattr(e, "detail", "-")))] for e in (summary.timeline_events or [])],
            max_rows=None, noun="event",
        ), detail=True)
    rep.section("Traffic", st.kv([
        ("Packets", f"{summary.total_packets} total · {summary.email_packets} mail"),
        ("Bytes", st.size(summary.total_bytes)),
        ("Start / end", f"{format_ts(summary.first_seen)} / {format_ts(summary.last_seen)}"),
        ("Duration", format_duration(summary.duration_seconds) if summary.duration_seconds is not None else ""),
        counter_line("Clients", summary.client_counts, None),
        counter_line("Servers", summary.server_counts, None),
    ]), detail=True)

    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic Email Security Checks", [
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
        ])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
