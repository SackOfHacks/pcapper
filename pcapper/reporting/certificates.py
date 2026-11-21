"""Rendered output for certificates analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations

from ..certificates import CertificateSummary
from . import _style as st
from ._common import (
    _redact_in_text,
)
from ._kv import counter_line

# Each analyzer issue list as a finding: (field, title, severity).
_ISSUES = [
    ("issuer_impersonation", "Issuer/SAN impersonation", "high"),
    ("weak_keys", "Weak certificate key", "medium"),
    ("weak_signatures", "Weak signature algorithm", "medium"),
    ("expired", "Expired or invalid certificate", "medium"),
    ("name_mismatches", "Name/SAN mismatch", "medium"),
    ("self_signed", "Self-signed certificate", "low"),
    ("eku_mismatches", "EKU mismatch", "low"),
    ("key_usage_issues", "KeyUsage issue", "low"),
    ("validity_outliers", "Validity outlier", "low"),
    ("fingerprint_reuse", "Certificate fingerprint reused across contexts", "low"),
    ("serial_reuse", "Certificate serial reused across contexts", "low"),
    ("chain_gaps", "Chain/trust gap", "info"),
    ("revocation_gaps", "Revocation posture gap", "info"),
]


def _detail(item: object) -> str:
    if not isinstance(item, dict):
        return str(item)
    if "subject" in item and "reason" in item:
        return f"{item.get('subject')}: {item.get('reason')}"
    if "sha256" in item and "count" in item:
        return f"sha256={item.get('sha256')} in {item.get('count')} contexts"
    if "serial" in item and "count" in item:
        return f"serial={item.get('serial')} in {item.get('count')} contexts"
    if "subject" in item:
        extra = {k: v for k, v in item.items() if k not in ("subject", "src", "dst")}
        return str(item.get("subject")) + (" (" + ", ".join(f"{k}={v}" for k, v in extra.items()) + ")" if extra else "")
    return ", ".join(f"{k}={v}" for k, v in item.items() if k not in ("src", "dst"))


def _assessment(summary: CertificateSummary) -> tuple[str, str, int, list[str]]:
    score = 0
    reasons: list[str] = []
    known_bad = list(getattr(summary, "known_bad_certs", []) or [])
    if known_bad:
        score += 8
        reasons.append("known-malicious certificate present (" + ", ".join(sorted({str(i.get("label", "known-bad")) for i in known_bad})) + ")")
    for hit, weight, text in (
        (summary.weak_keys, min(2, len(summary.weak_keys)), f"weak-key certificates ({len(summary.weak_keys)})"),
        (summary.weak_signatures, min(2, len(summary.weak_signatures)), f"weak signature algorithms ({len(summary.weak_signatures)})"),
        (summary.expired, 1, f"expired/invalid certificates ({len(summary.expired)})"),
        (summary.eku_mismatches or summary.key_usage_issues, 1, "EKU/KeyUsage mismatches"),
        (summary.name_mismatches, 1, f"name/SAN mismatches ({len(summary.name_mismatches)})"),
        (summary.issuer_impersonation, 2, f"issuer/SAN impersonation signals ({len(summary.issuer_impersonation)})"),
        (summary.fingerprint_reuse or summary.serial_reuse, 1, "fingerprint/serial reuse across contexts"),
    ):
        if hit:
            score += weight
            reasons.append(text)
    if score >= 7:
        return "YES - high-confidence certificate risks or interception indicators", "High", score, reasons
    if score >= 4:
        return "LIKELY - significant certificate anomalies to investigate", "Medium", score, reasons
    if score >= 2:
        return "POSSIBLE - certificate anomalies; corroboration recommended", "Low", score, reasons
    return "NO STRONG SIGNAL from the current heuristics", "Low", score, reasons


def render_certificates_summary(summary: CertificateSummary) -> str:
    """Certificates carried in TLS (and OpenVPN): known-malicious matches and
    certificate problems as findings, then every certificate with its
    subject, issuer, validity, key, flags and the flow that carried it;
    subjects/issuers/SANs counters, endpoint profiles and the timeline are -v."""
    rep = st.Report("Certificates", summary.path)
    findings = [st.finding({"severity": "critical", "title": f"Known-malicious certificate: {i.get('label', 'IOC match')}",
                            "details": f"serial={i.get('serial', '-')} sha256={i.get('sha256', '-')}", "src": i.get("src"),
                            "dst": i.get("dst")}) for i in (getattr(summary, "known_bad_certs", None) or [])]
    for field, title, severity in _ISSUES:
        for item in getattr(summary, field, None) or []:
            src = item.get("src") if isinstance(item, dict) else None
            dst = item.get("dst") if isinstance(item, dict) else None
            findings.append(st.finding({"severity": severity, "title": title, "details": _redact_in_text(_detail(item)),
                                        "src": src, "dst": dst}))
    if not summary.cert_count and not st.material(findings):
        return rep.absent("TLS certificates", summary.errors)
    severity, text = st.verdict(findings, high="malicious or abused certificates: investigate", medium="certificate problems to review")
    rep.headline(severity, text, st.join([st.plural(summary.cert_count, "certificate"), f"{st.count(summary.tls_packets)} TLS packets"]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    flag_sets = {field: {(i.get("subject"), i.get("src"), i.get("dst")) for i in (getattr(summary, field, None) or [])
                         if isinstance(i, dict)} for field in ("self_signed", "expired", "weak_keys")}

    def _flags(c: object) -> str:
        key = (c.subject, c.src_ip, c.dst_ip)
        flags = [label for field, label in (("self_signed", "self-signed"), ("expired", "expired"), ("weak_keys", "weak key"))
                 if key in flag_sets[field]]
        if getattr(c, "is_ca", False):
            flags.append("CA")
        return st.caution(", ".join(flags)) if flags else ""

    verbose = st.verbose()
    rep.section("Certificates", st.table(
        ["Subject", "Issuer", "SNI", "Not after", "Key", "Flags", "Flow"] + (["Not before", "Serial", "Signature", "SANs", "SHA256"] if verbose else ["SHA256"]),
        [[_redact_in_text(c.subject), _redact_in_text(c.issuer), c.sni or "-", c.not_after, f"{c.pubkey_type} {c.pubkey_size}", _flags(c),
          st.flow(c.src_ip, c.dst_ip)]
         + ([c.not_before, c.serial, c.sig_algo, ", ".join(c.san) if isinstance(c.san, (list, tuple, set)) else str(c.san or "-"), c.sha256]
            if verbose else [str(c.sha256)[:16] + "…"]) for c in summary.artifacts],
        widths=(44, 40, 32), max_rows=12, noun="certificate",
    ))
    vpn = list(getattr(summary, "openvpn_certificates", None) or [])
    rep.section("OpenVPN certificates", st.table(
        ["Subject", "Issuer", "VPN server", "Client", "SHA256"],
        [[_redact_in_text(str(i.get("subject", "-"))), _redact_in_text(str(i.get("issuer", "-"))), i.get("src", "-"), i.get("dst", "-"),
          i.get("sha256", "-")] for i in vpn], max_rows=10,
    ) + ([st.dim("  carried in the OpenVPN control channel: VPN-server certificates, not web-service certificates")] if vpn else []))

    verdict, confidence, score, reasons = _assessment(summary)
    rep.section("Assessment", st.kv([("Verdict", verdict), ("Confidence", f"{confidence} (score={score})")])
                + st.bullets(reasons, max_items=None), detail=True)
    rep.section("Names", st.kv([counter_line("Subjects", summary.subjects, None), counter_line("Issuers", summary.issuers, None),
                                counter_line("SANs", summary.sas, None)]), detail=True)
    rep.section("Endpoint profiles", st.table(
        ["Endpoint", "Certs", "Subjects", "Issuers", "Flows", "Latest not-after"],
        [[i.get("endpoint", "-"), i.get("fingerprints", "-"), i.get("subjects", "-"), i.get("issuers", "-"), i.get("flows", "-"),
          i.get("latest_not_after", "-")] for i in (getattr(summary, "endpoint_profiles", None) or [])], max_rows=None,
    ), detail=True)
    rep.section("Timeline", st.table(
        ["Event", "Subject", "Issuer", "Flow", "Not after"],
        [[i.get("event", "-"), _redact_in_text(str(i.get("subject", "-"))), _redact_in_text(str(i.get("issuer", "-"))),
          st.flow(i.get("src", "-"), i.get("dst", "-")), i.get("not_after", "-")] for i in (getattr(summary, "timeline", None) or [])],
        max_rows=None,
    ), detail=True)
    return rep.render()
