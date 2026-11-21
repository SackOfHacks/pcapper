"""Rendered output for --strings: cleartext strings carved from payloads,
led by the suspicious ones (credentials, commands, stagers, OT writes) and
the URLs, emails and domains they contain."""

from __future__ import annotations

from ..strings import StringsSummary
from . import _style as st
from ._common import _render_deterministic_checks


def _checks(summary: StringsSummary, key: str) -> list[str]:
    dc = summary.deterministic_checks or {}
    return [str(v) for v in (dc.get(key, []) or []) if str(v).strip()]


def _values(items: list, label_text: str, total: int | None = None) -> list[str]:
    """A ranked value/count table: the top 10 and the bottom 10."""
    return st.ranked([label_text, "Count"], [[i.value, st.count(i.count)] for i in items], align="lr",
                     widths=(100,), noun=label_text if label_text.isupper() else label_text.lower(), total=total)


def render_strings_summary(summary: StringsSummary) -> str:
    rep = st.Report("Strings", summary.path)
    creds = _checks(summary, "cleartext_credentials")
    lolbin = _checks(summary, "command_execution_or_lolbin")
    exfil = _checks(summary, "download_stager_or_exfil")
    otwrite = _checks(summary, "ot_ics_control_write_ops")
    ctf = _checks(summary, "ctf_flag_or_challenge_markers")
    reasons = [text for hits, text in (
        (creds, f"cleartext credentials in {len(creds)} string(s)"),
        (lolbin, f"command/LOLBin execution strings ({len(lolbin)})"),
        (exfil, f"download-stager / exfil strings ({len(exfil)})"),
        (otwrite, f"OT/ICS control-write operation markers ({len(otwrite)})"),
        (ctf, f"CTF flag / challenge markers ({len(ctf)})"),
    ) if hits]
    if creds or lolbin or exfil:
        severity, text = "high", "malicious or sensitive strings present"
    elif otwrite:
        severity, text = "medium", "OT/ICS control-write strings present"
    elif ctf:
        severity, text = "medium", "CTF flag markers in strings"
    elif summary.suspicious_strings:
        severity, text = "medium", "suspicious strings present"
    else:
        severity, text = None, "no high-risk strings"
    rep.headline(severity, text, st.join([f"{st.count(summary.strings_found)} strings",
                                          f"{st.count(summary.unique_strings)} unique"]))
    for reason in reasons:
        rep.scope(reason)
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])

    def _pairs(pairs: list) -> str:
        return ", ".join(f"{ip} ({n})" for ip, n in pairs) or "-"

    if summary.suspicious_details:
        rows = [[d.get("value", "-"), st.count(d.get("count", 0)), ", ".join(d.get("reasons", [])) or "-",
                 _pairs(d.get("top_sources", [])), _pairs(d.get("top_destinations", []))] for d in summary.suspicious_details]
    else:
        rows = [[i.value, st.count(i.count), "-", "-", "-"] for i in summary.suspicious_strings]
    rep.section("Suspicious strings", st.table(["String", "Count", "Reason", "Sources", "Destinations"], rows,
                                               align="lrlll", widths=(64, None, 40, 40, 40), noun="string"))
    rep.section("Anomalies", st.bullets([str(a) for a in (summary.anomalies or [])], max_items=None))
    totals = getattr(summary, "ranking_totals", None) or {}
    rep.section("URLs", _values(summary.urls, "URL", totals.get("urls")))
    rep.section("Emails", _values(summary.emails, "Email", totals.get("emails")))
    rep.section("Domains", _values(summary.domains, "Domain", totals.get("domains")))
    rep.section("OT/ICS markers", st.bullets([str(i) for i in (summary.ot_findings or [])], max_items=15, noun="marker"))
    rep.section("CTF markers", st.bullets([str(i) for i in (summary.ctf_indicators or [])], max_items=15, noun="marker"))
    # The analyzer keeps the 20 most and the 20 least common strings: the
    # top and the bottom of one ranking (bottom_strings is rarest first).
    top_values = {i.value for i in summary.top_strings or []}
    bottom = [i for i in reversed(getattr(summary, "bottom_strings", None) or []) if i.value not in top_values]
    rep.section("Strings", st.ranked(
        ["String", "Count"], [[i.value, st.count(i.count)] for i in [*(summary.top_strings or []), *bottom]],
        align="lr", widths=(100,), noun="string", total=summary.unique_strings or None,
        tail=len(bottom) if st.verbose() else st.TOP_ROWS,
    ))
    hosts: list[str] = []
    for role, mapping in (("client", summary.client_strings), ("server", summary.server_strings)):
        for ip, items in (mapping or {}).items():
            hosts.append(f"  {st.strong(f'{role} {ip}')}")
            hosts += _values(items, "String", None)
    rep.section("Strings by host", hosts, detail=True)
    hyp = [f"[{h.get('confidence', '?')}] {h.get('hypothesis', '-')} (evidence={h.get('evidence', '')})"
           for h in (summary.threat_hypotheses or [])]
    rep.section("Threat hypotheses", st.bullets(hyp, max_items=None), detail=True)
    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic String Security Checks", [
            ("cleartext_credentials", "Cleartext Credentials"),
            ("command_execution_or_lolbin", "Command Execution / LOLBin"),
            ("download_stager_or_exfil", "Download Stager / Exfil"),
            ("ot_ics_control_write_ops", "OT/ICS Control-Write Operations"),
            ("ot_ics_protocol_markers", "OT/ICS Protocol Markers"),
            ("ctf_flag_or_challenge_markers", "CTF Flag / Challenge Markers"),
        ])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
