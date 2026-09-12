"""Rendered output for secrets analysis.

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
from ..secrets import SecretsSummary

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _counter_table,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
    _render_deterministic_checks,
    _truncate_text,
)


def render_secrets_summary(summary: SecretsSummary, *, verbose: bool = False) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"SECRET DISCOVERY :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Packets Scanned", str(summary.total_packets)))
    lines.append(_format_kv("Matches", str(summary.matches)))

    # ---- Analyst Verdict -------------------------------------------------
    # The product of --secrets is the DECODED material and what it implies.
    # Lead with a triage call derived from the computed deterministic checks.
    dc = summary.deterministic_checks or {}

    def _dc(key: str) -> list[str]:
        return [str(v) for v in (dc.get(key, []) or []) if str(v).strip()]

    keys_hit = _dc("private_key_or_cryptographic_material")
    creds_hit = _dc("cleartext_credentials_in_decoded_secrets")
    c2_hit = _dc("c2_or_exfil_markers_in_decoded_payloads")
    lolbin_hit = _dc("command_execution_or_lolbin_in_secrets")
    ext_hit = _dc("external_public_secret_flow")
    token_hit = _dc("token_or_session_material")
    chain_hit = _dc("multi_stage_decoding_chain")
    ctf_hit = _dc("ctf_flag_or_challenge_markers")

    reasons: list[str] = []
    if keys_hit:
        reasons.append(f"private key / cryptographic material in {len(keys_hit)} payload(s)")
    if creds_hit:
        reasons.append(f"decoded cleartext credentials in {len(creds_hit)} payload(s)")
    if c2_hit:
        reasons.append(f"C2/exfil markers in {len(c2_hit)} decoded payload(s)")
    if lolbin_hit:
        reasons.append(f"encoded command/LOLBin execution in {len(lolbin_hit)} payload(s)")
    if ext_hit:
        reasons.append(f"decoded secret(s) flowed to a PUBLIC destination ({len(ext_hit)})")
    if token_hit:
        reasons.append(f"token/session material in {len(token_hit)} payload(s)")
    if chain_hit:
        reasons.append(f"multi-stage decoding chain in {len(chain_hit)} payload(s)")
    if ctf_hit:
        reasons.append(f"CTF flag/challenge marker(s) ({len(ctf_hit)})")

    if keys_hit or creds_hit or c2_hit or lolbin_hit:
        verdict_text, verdict_fn = "SENSITIVE MATERIAL DECODED — INVESTIGATE", danger
    elif ext_hit or token_hit or chain_hit:
        verdict_text, verdict_fn = "ENCODED SECRET MATERIAL OF INTEREST", warn
    elif ctf_hit:
        verdict_text, verdict_fn = "CTF FLAG MARKERS IN DECODED CONTENT", warn
    elif summary.matches > 0:
        verdict_text, verdict_fn = "REVERSIBLE ENCODED CONTENT FOUND", warn
    else:
        verdict_text, verdict_fn = "NO REVERSIBLE SECRETS DETECTED", ok

    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    lines.append(verdict_fn(f"[VERDICT] {verdict_text}"))
    for reason in reasons:
        lines.append(warn(f"- {reason}"))

    # ---- Decoded findings (default-visible — this is the deliverable) ----
    # Previously gated behind -v, so the default view showed only counters and
    # the analyst never saw the decoded cleartext. Show the top findings by
    # default; -v shows all of them.
    if summary.hits:
        lines.append(SUBSECTION_BAR)
        shown = summary.hits if verbose else summary.hits[: _limit_value(15)]
        lines.append(header(f"Decoded Findings ({len(shown)} of {len(summary.hits)})"))
        rows = [["Type", "Encoded", "Cleartext", "Location", "Src", "Dst", "Note"]]
        for hit in shown:
            loc_parts = [f"pkt {hit.packet_number}"]
            if hit.offset is not None:
                loc_parts.append(f"@{hit.offset}")
            location = " ".join(loc_parts)
            src = hit.src_ip
            dst = hit.dst_ip
            if hit.src_port is not None:
                src = f"{src}:{hit.src_port}"
            if hit.dst_port is not None:
                dst = f"{dst}:{hit.dst_port}"
            rows.append(
                [
                    hit.kind,
                    _truncate_text(hit.encoded, 48),
                    _truncate_text(hit.decoded, 64),
                    location,
                    src,
                    dst,
                    _truncate_text(hit.note or "-", 28),
                ]
            )
        lines.append(_format_table(rows))
        if not verbose and len(summary.hits) > len(shown):
            lines.append(
                muted(
                    f"... {len(summary.hits) - len(shown)} more finding(s); use -v for all."
                )
            )

    # ---- Threat hypotheses ----------------------------------------------
    if summary.threat_hypotheses:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Threat Hypotheses"))
        for hyp in summary.threat_hypotheses:
            conf = str(hyp.get("confidence", "?"))
            text = str(hyp.get("hypothesis", "-"))
            ev = hyp.get("evidence", "")
            lines.append(warn(f"- [{conf}] {text} (evidence={ev})"))

    # ---- OT / CTF context ------------------------------------------------
    if summary.ot_findings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT/ICS Markers in Decoded Content"))
        for item in summary.ot_findings[: _limit_value(15)]:
            lines.append(muted(f"- {item}"))
    if summary.ctf_indicators:
        lines.append(SUBSECTION_BAR)
        lines.append(header("CTF Flag / Challenge Markers"))
        for item in summary.ctf_indicators[: _limit_value(15)]:
            lines.append(muted(f"- {item}"))

    # ---- Deterministic checks -------------------------------------------
    _render_deterministic_checks(
        lines,
        summary,
        "Deterministic Secret Security Checks",
        [
            ("cleartext_credentials_in_decoded_secrets", "Decoded Cleartext Credentials"),
            ("private_key_or_cryptographic_material", "Private Key / Crypto Material"),
            ("token_or_session_material", "Token / Session Material"),
            ("command_execution_or_lolbin_in_secrets", "Encoded Command Execution / LOLBin"),
            ("c2_or_exfil_markers_in_decoded_payloads", "C2 / Exfil Markers"),
            ("external_public_secret_flow", "Secrets to Public Internet"),
            ("multi_stage_decoding_chain", "Multi-stage Decoding Chain"),
            ("high_reuse_or_staging_pattern", "High Reuse / Staging Pattern"),
            ("ot_ics_secret_transport_or_context", "OT/ICS Secret Transport / Context"),
            ("ctf_flag_or_challenge_markers", "CTF Flag / Challenge Markers"),
        ],
    )

    # ---- Aggregated counters (context, last) ----------------------------
    if (
        summary.kind_counts
        or summary.top_sources
        or summary.top_destinations
        or summary.protocol_counts
    ):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Aggregated Counters"))

        if summary.kind_counts:
            lines.append(header("Kind Counts"))
            lines.append(_counter_table(summary.kind_counts, "Item", limit=_limit_value(12)))

        if summary.top_sources:
            lines.append(header("Top Sources"))
            lines.append(_counter_table(summary.top_sources, "Item", limit=_limit_value(12)))

        if summary.top_destinations:
            lines.append(header("Top Destinations"))
            lines.append(_counter_table(summary.top_destinations, "Item", limit=_limit_value(12)))

        if summary.protocol_counts:
            lines.append(header("Protocol Counts"))
            lines.append(_counter_table(summary.protocol_counts, "Item", limit=_limit_value(12)))

    if summary.truncated:
        lines.append(warn(f"[WARN] Showing first {len(summary.hits)} matches."))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
