"""Rendered output for certificates analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..certificates import CertificateSummary
from ..coloring import (
    danger,
    header,
    label,
    muted,
    ok,
    warn,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _counter_table,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
    _redact_in_text,
    _truncate_text,
)


def render_certificates_summary(summary: CertificateSummary) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"TLS CERTIFICATES :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("TLS Packets", str(summary.tls_packets)))
    lines.append(_format_kv("Certificates", str(summary.cert_count)))

    known_bad = list(getattr(summary, "known_bad_certs", []) or [])
    if known_bad:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Known-Malicious Certificate IOC Match"))
        for item in known_bad[:10]:
            lines.append(
                danger(
                    f"[CRITICAL] {item.get('label', 'known-bad certificate')} — "
                    f"{item.get('src', '?')} -> {item.get('dst', '?')}"
                )
            )
            lines.append(
                muted(
                    f"  serial={item.get('serial', '-')} "
                    f"sha256={item.get('sha256', '-')}"
                )
            )

    def _cert_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        known_bad = list(getattr(summary, "known_bad_certs", []) or [])
        if known_bad:
            score += 8  # a default C2-framework cert is a definitive IOC
            labels = ", ".join(
                sorted({str(item.get("label", "known-bad cert")) for item in known_bad})
            )
            reasons.append(f"Known-malicious certificate present ({labels})")
        if summary.weak_keys:
            score += min(2, len(summary.weak_keys))
            reasons.append(f"Weak key certificates detected ({len(summary.weak_keys)})")
        if summary.weak_signatures:
            score += min(2, len(summary.weak_signatures))
            reasons.append(
                f"Weak signature algorithms detected ({len(summary.weak_signatures)})"
            )
        if summary.expired:
            score += 1
            reasons.append(
                f"Expired/invalid certificates detected ({len(summary.expired)})"
            )
        if summary.eku_mismatches or summary.key_usage_issues:
            score += 1
            reasons.append("EKU/KeyUsage mismatches observed")
        if summary.name_mismatches:
            score += 1
            reasons.append(
                f"Name/SAN mismatches observed ({len(summary.name_mismatches)})"
            )
        if summary.issuer_impersonation:
            score += 2
            reasons.append(
                f"Issuer/SAN impersonation signals observed ({len(summary.issuer_impersonation)})"
            )
        if summary.fingerprint_reuse or summary.serial_reuse:
            score += 1
            reasons.append("Fingerprint/serial reuse across contexts observed")

        if score >= 7:
            verdict = "YES - high-confidence certificate security risks or interception indicators are present."
            confidence = "High"
        elif score >= 4:
            verdict = "LIKELY - significant certificate anomalies are present and require investigation."
            confidence = "Medium"
        elif score >= 2:
            verdict = "POSSIBLE - certificate anomalies are present; corroboration recommended."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing high-risk certificate abuse pattern from current heuristics."
            confidence = "Low"

        if not reasons:
            reasons.append(
                "No high-confidence certificate threat heuristic crossed threshold"
            )
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _cert_verdict()
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
    for reason in verdict_reasons[: _limit_value(10)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Certificate Security Checks"))

    checks: list[tuple[str, list[dict[str, object]]]] = [
        ("Chain/Trust Gaps", list(getattr(summary, "chain_gaps", []) or [])),
        (
            "Weak Signature Algorithms",
            list(getattr(summary, "weak_signatures", []) or []),
        ),
        (
            "EKU/KeyUsage Mismatch",
            list(getattr(summary, "eku_mismatches", []) or [])
            + list(getattr(summary, "key_usage_issues", []) or []),
        ),
        ("Name/SAN Mismatch", list(getattr(summary, "name_mismatches", []) or [])),
        ("Validity Outliers", list(getattr(summary, "validity_outliers", []) or [])),
        (
            "Issuer/SAN Impersonation",
            list(getattr(summary, "issuer_impersonation", []) or []),
        ),
        (
            "Fingerprint/Serial Reuse",
            list(getattr(summary, "fingerprint_reuse", []) or [])
            + list(getattr(summary, "serial_reuse", []) or []),
        ),
        (
            "Revocation Posture Gaps",
            list(getattr(summary, "revocation_gaps", []) or []),
        ),
    ]

    for label_text, evidence_items in checks:
        lines.append(label(label_text))
        if evidence_items:
            lines.append(
                warn(
                    f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"
                )
            )
            for item in evidence_items[: _limit_value(6)]:
                if isinstance(item, dict):
                    if "subject" in item and "reason" in item:
                        ev = f"subject={item.get('subject')} reason={item.get('reason')} src={item.get('src', '-')} dst={item.get('dst', '-')}"
                    elif "sha256" in item:
                        ev = f"sha256={item.get('sha256')} contexts={item.get('count')}"
                    elif "serial" in item:
                        ev = f"serial={item.get('serial')} contexts={item.get('count')}"
                    else:
                        ev = ", ".join(f"{k}={v}" for k, v in item.items())
                else:
                    ev = str(item)
                lines.append(muted(f"- {_redact_in_text(ev)}"))
        else:
            lines.append(
                ok(
                    f"No, there is no strong evidence for {label_text.lower()} in this capture."
                )
            )

    endpoint_profiles = list(getattr(summary, "endpoint_profiles", []) or [])
    if endpoint_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Endpoint Certificate Profiles"))
        rows = [
            ["Endpoint", "Certs", "Subjects", "Issuers", "Flows", "Latest NotAfter"]
        ]
        for item in endpoint_profiles[: _limit_value(12)]:
            rows.append(
                [
                    str(item.get("endpoint", "-")),
                    str(item.get("fingerprints", "-")),
                    str(item.get("subjects", "-")),
                    str(item.get("issuers", "-")),
                    str(item.get("flows", "-")),
                    str(item.get("latest_not_after", "-")),
                ]
            )
        lines.append(_format_table(rows))

    timeline = list(getattr(summary, "timeline", []) or [])
    if timeline:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Certificate Timeline"))
        rows = [["Event", "Subject", "Issuer", "Src", "Dst", "NotAfter"]]
        for item in timeline[: _limit_value(15)]:
            rows.append(
                [
                    str(item.get("event", "-")),
                    _truncate_text(str(item.get("subject", "-")), 48),
                    _truncate_text(str(item.get("issuer", "-")), 48),
                    str(item.get("src", "-")),
                    str(item.get("dst", "-")),
                    str(item.get("not_after", "-")),
                ]
            )
        lines.append(_format_table(rows))

    if summary.subjects:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Subjects"))
        lines.append(_counter_table(summary.subjects, "Subject", limit=_limit_value(10)))

    if summary.issuers:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Issuers"))
        lines.append(_counter_table(summary.issuers, "Issuer", limit=_limit_value(10)))

    if summary.sas:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top SANs"))
        lines.append(_counter_table(summary.sas, "SAN", limit=_limit_value(10)))

    if summary.weak_keys:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Weak Keys"))
        rows = [["Subject", "Key Size", "Src", "Dst"]]
        for item in summary.weak_keys[: _limit_value(10)]:
            rows.append(
                [
                    str(item.get("subject", "-")),
                    str(item.get("size", "-")),
                    str(item.get("src", "-")),
                    str(item.get("dst", "-")),
                ]
            )
        lines.append(_format_table(rows))

    if summary.expired:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Expired / Invalid Certificates"))
        lines.append(
            muted(
                "  Expired or invalid validity windows can indicate misconfigurations, expired infrastructure, or opportunistic interception."
            )
        )
        rows = [["Subject", "Reason", "Src", "Dst"]]
        for item in summary.expired[: _limit_value(10)]:
            rows.append(
                [
                    str(item.get("subject", "-")),
                    str(item.get("reason", "-")),
                    str(item.get("src", "-")),
                    str(item.get("dst", "-")),
                ]
            )
        lines.append(_format_table(rows))

    if summary.self_signed:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Self-Signed Certificates"))
        lines.append(
            muted(
                "  Self-signed certs may be benign in labs but can also signal spoofed services, internal C2, or TLS interception."
            )
        )
        rows = [["Subject", "Src", "Dst"]]
        for item in summary.self_signed[: _limit_value(10)]:
            rows.append(
                [
                    str(item.get("subject", "-")),
                    str(item.get("src", "-")),
                    str(item.get("dst", "-")),
                ]
            )
        lines.append(_format_table(rows))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Certificate Artifacts"))
        rows = [["Subject", "Issuer", "Not After", "Key", "SHA256"]]
        for cert in summary.artifacts[: _limit_value(10)]:
            rows.append(
                [
                    cert.subject,
                    cert.issuer,
                    cert.not_after,
                    f"{cert.pubkey_type} {cert.pubkey_size}",
                    cert.sha256[: _limit_value(32)] + "...",
                ]
            )
        lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
