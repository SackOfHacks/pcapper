"""Rendered output for --secrets: reversibly encoded material (Base64, hex,
XOR ...) decoded from the traffic. The decoded findings are the deliverable;
counters and hypotheses are -v context."""

from __future__ import annotations

from ..secrets import SecretsSummary
from . import _style as st
from ._common import _render_deterministic_checks
from ._kv import counter_line


def _checks(summary: SecretsSummary, key: str) -> list[str]:
    dc = summary.deterministic_checks or {}
    return [str(v) for v in (dc.get(key, []) or []) if str(v).strip()]


def render_secrets_summary(summary: SecretsSummary, *, verbose: bool = False) -> str:
    rep = st.Report("Secrets", summary.path)
    keys = _checks(summary, "private_key_or_cryptographic_material")
    creds = _checks(summary, "cleartext_credentials_in_decoded_secrets")
    c2 = _checks(summary, "c2_or_exfil_markers_in_decoded_payloads")
    lolbin = _checks(summary, "command_execution_or_lolbin_in_secrets")
    external = _checks(summary, "external_public_secret_flow")
    tokens = _checks(summary, "token_or_session_material")
    chain = _checks(summary, "multi_stage_decoding_chain")
    ctf = _checks(summary, "ctf_flag_or_challenge_markers")
    reasons = [text for hits, text in (
        (keys, f"private key / cryptographic material in {len(keys)} payload(s)"),
        (creds, f"decoded cleartext credentials in {len(creds)} payload(s)"),
        (c2, f"C2/exfil markers in {len(c2)} decoded payload(s)"),
        (lolbin, f"encoded command/LOLBin execution in {len(lolbin)} payload(s)"),
        (external, f"decoded secrets flowed to a public destination ({len(external)})"),
        (tokens, f"token/session material in {len(tokens)} payload(s)"),
        (chain, f"multi-stage decoding chain in {len(chain)} payload(s)"),
        (ctf, f"CTF flag/challenge markers ({len(ctf)})"),
    ) if hits]
    if keys or creds or c2 or lolbin:
        severity, text = "high", "sensitive material decoded: investigate"
    elif external or tokens or chain:
        severity, text = "medium", "encoded secret material of interest"
    elif ctf:
        severity, text = "medium", "CTF flag markers in decoded content"
    elif summary.matches:
        severity, text = "low", "reversible encoded content found"
    else:
        severity, text = None, "no reversible secrets"
    rep.headline(severity, text, st.join([st.plural(summary.matches, "match", "matches"),
                                          f"{st.count(summary.total_packets)} packets scanned"]))
    for reason in reasons:
        rep.scope(reason)
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])

    def _end(ip: object, port: object) -> str:
        return f"{ip}:{port}" if port is not None else str(ip)

    rep.section("Decoded", st.table(
        ["Packet", "Type", "Encoded", "Cleartext", "Flow", "Note"],
        [[f"{h.packet_number}" + (f" @{h.offset}" if h.offset is not None else ""), h.kind, h.encoded, h.decoded,
          f"{_end(h.src_ip, h.src_port)} -> {_end(h.dst_ip, h.dst_port)}", h.note or "-"] for h in summary.hits],
        max_rows=None if (st.verbose() or verbose) else 15, widths=(None, None, 48, 64, None, 28), noun="decoded finding",
    ))
    if summary.truncated:
        rep.note("CAPPED", f"the analyzer kept the first {len(summary.hits)} matches")
    rep.section("OT/ICS markers", st.bullets([str(i) for i in (summary.ot_findings or [])], max_items=15, noun="marker"))
    rep.section("CTF markers", st.bullets([str(i) for i in (summary.ctf_indicators or [])], max_items=15, noun="marker"))

    hyp = [f"[{h.get('confidence', '?')}] {h.get('hypothesis', '-')} (evidence={h.get('evidence', '')})"
           for h in (summary.threat_hypotheses or [])]
    rep.section("Threat hypotheses", st.bullets(hyp, max_items=None), detail=True)
    rep.section("Counters", st.kv([
        counter_line("Kinds", summary.kind_counts, None), counter_line("Sources", summary.top_sources, None),
        counter_line("Destinations", summary.top_destinations, None), counter_line("Protocols", summary.protocol_counts, None),
    ]), detail=True)
    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic Secret Security Checks", [
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
        ])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
