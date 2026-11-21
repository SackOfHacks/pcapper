"""Rendered output for --ctf: the answer first -- every distinct flag with
the packet, flow and decode chain that carried it -- then credentials and
passphrase parameters seen in HTTP, and challenge-looking file names. The
full candidate provenance (score, confidence, context) and the scored
assessment are -v detail."""

from __future__ import annotations

from typing import Optional

from ..ctf import FLAG_PATTERNS, CtfSummary
from ..utils import format_duration, format_ts
from . import _style as st
from ._common import _redact_in_text, _render_deterministic_checks

_CREDENTIAL_CHAINS = {"http-basic": "HTTP Basic", "http-param": "parameter"}


def _flag_in(value: str) -> Optional[str]:
    """The flag inside a candidate: the longest wrapper match, so
    ``picoCTF{x}`` is not also listed as ``CTF{x}``."""
    matches = [m.group(1) for p in FLAG_PATTERNS for m in [p.search(value)] if m]
    return max(matches, key=len) if matches else None


def _via(item: dict) -> str:
    chain = str(item.get("decode_chain", "raw") or "raw").removeprefix("raw->")
    source = str(item.get("source", "") or "")
    return f"{source} ({chain})" if chain != "raw" else (source or "raw")


def _assessment(summary: CtfSummary) -> tuple[str, str, list[str], int]:
    """The weighted score the report used to lead with (kept as -v context)."""
    conf = getattr(summary, "confidence_counts", None) or {}
    checks = getattr(summary, "deterministic_checks", {}) or {}
    score, reasons = 0, []
    high, medium = int(conf.get("high", 0)), int(conf.get("medium", 0))
    if high:
        score += min(4, high)
        reasons.append(f"high-confidence candidates ({high})")
    if medium >= 2:
        score += 1
        reasons.append(f"multiple medium-confidence candidates ({medium})")
    for key, weight, text in (("decoded_wrapper_pattern_present", 2, "decoded wrapper-pattern matches"),
                              ("multi_source_corroboration", 1, "cross-source corroboration"),
                              ("stream_reassembled_match", 1, "wrapper recovered across a segment boundary"),
                              ("external_replay_exfil_behavior", 1, "candidate replayed or sent externally")):
        if checks.get(key):
            score += weight
            reasons.append(text)
    if score >= 7:
        verdict, confidence = "YES - high-confidence CTF flag evidence", "High"
    elif score >= 4:
        verdict, confidence = "LIKELY - strong CTF evidence with corroboration", "Medium"
    elif score >= 2:
        verdict, confidence = "POSSIBLE - weak-to-moderate CTF evidence", "Low"
    else:
        verdict, confidence = "NO STRONG SIGNAL from the current heuristics", "Low"
    return verdict, confidence, reasons, score


def render_ctf_summary(summary: CtfSummary) -> str:
    rep = st.Report("CTF", summary.path)
    candidates = [c for c in (getattr(summary, "candidate_findings", None) or []) if isinstance(c, dict)]
    flags: dict[str, list[dict]] = {}
    creds: list[dict] = []
    for c in candidates:
        value = str(c.get("candidate", ""))
        if str(c.get("decode_chain", "")) in _CREDENTIAL_CHAINS:
            creds.append(c)
        flag = _flag_in(value)
        if flag:
            flags.setdefault(flag, []).append(c)
    hints = [str(h) for h in (summary.file_hints or [])]
    if not summary.total_packets and not candidates:
        return rep.absent("traffic", summary.errors)
    conf = getattr(summary, "confidence_counts", None) or {}
    text = (f"{st.plural(len(flags), 'flag')} found" if flags else "no flag found") + (
        f" · {st.plural(len(creds), 'credential')}" if creds else "")
    rep.headline(False, st.good(text) if flags else text, st.join([
        (f"{st.plural(len(candidates), 'candidate')}" + (
            f" ({', '.join(f'{conf[k]} {k}' for k in ('high', 'medium', 'low') if conf.get(k))})" if conf else "")) if candidates else "",
        f"{st.count(summary.total_packets)} packets",
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
        st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else "",
    ]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])

    def _first(items: list[dict]) -> dict:
        return min(items, key=lambda i: int(i.get("packet", 0) or 0))

    # A -summarize rollup tags each candidate with its capture: packet
    # numbers only mean something next to it.
    by_capture = any(c.get("capture") for c in candidates)
    cap_col = ["Capture"] if by_capture else []

    def _cap(item: dict) -> list:
        return [item.get("capture", "-")] if by_capture else []

    rep.section("Flags", st.table(
        ["Flag", "Seen", *cap_col, "Packet", "Time", "Flow", "Proto", "Via"],
        [[st.strong(_redact_in_text(flag)), len(items), *_cap(_first(items)), _first(items).get("packet", "-"), st.ts(_first(items).get("ts")),
          st.flow(_first(items).get("src", "-"), _first(items).get("dst", "-")), _first(items).get("protocol", "-"), _via(_first(items))]
         for flag, items in sorted(flags.items(), key=lambda kv: int(_first(kv[1]).get("packet", 0) or 0))],
        align="lr" + ("l" if by_capture else "") + "rllll", max_rows=15, noun="flag",
    ))
    rep.section("Credentials", st.table(
        [*cap_col, "Packet", "Time", "Flow", "Kind", "Value"],
        [[*_cap(c), c.get("packet", "-"), st.ts(c.get("ts")), st.flow(c.get("src", "-"), c.get("dst", "-")),
          _CREDENTIAL_CHAINS[str(c.get("decode_chain"))], _redact_in_text(str(c.get("candidate", "-")))]
         for c in sorted(creds, key=lambda c: int(c.get("packet", 0) or 0))],
        align=("l" if by_capture else "") + "rllll", max_rows=10, noun="credential",
    ))
    rep.section("Challenge files", st.bullets([_redact_in_text(h) for h in hints], max_items=10, noun="file"))

    verdict, confidence, reasons, score = _assessment(summary)
    rep.section("Assessment", st.kv([("Verdict", verdict), ("Confidence", f"{confidence} (score {score})"),
                                     ("Window", f"{format_ts(summary.first_seen)} / {format_ts(summary.last_seen)}"),
                                     ("Duration", format_duration(summary.duration_seconds))])
                + st.bullets(reasons, max_items=None), detail=True)
    rep.section("Candidates", st.table(
        [*cap_col, "Time", "Packet", "Flow", "Proto", "Score", "Confidence", "Source", "Decode", "Candidate", "Context"],
        [[*_cap(c), st.ts(c.get("ts")), c.get("packet", "-"), st.flow(c.get("src", "-"), c.get("dst", "-")), c.get("protocol", "-"),
          c.get("score", "-"), c.get("confidence", "-"), c.get("source", "-"),
          f"{c.get('decode_chain', 'raw')}{' +reassembled' if c.get('reassembled') else ''}",
          _redact_in_text(str(c.get("candidate", "-"))), _redact_in_text(str(c.get("context", "") or "-"))]
         for c in sorted(candidates, key=lambda c: (float(c.get("ts") or 0.0), int(c.get("packet", 0) or 0)))],
        align=("l" if by_capture else "") + "lrllrlllll", max_rows=None,
    ), detail=True)
    rep.section("False-positive context", st.bullets([_redact_in_text(str(v)) for v in (summary.false_positive_context or [])],
                                                     max_items=None), detail=True)
    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic CTF Checks", [
            ("flag_wrapper_pattern_present", "Flag Wrapper Pattern Present"),
            ("decoded_wrapper_pattern_present", "Decoded Wrapper Pattern Present"),
            ("multi_source_corroboration", "Multi-Source Corroboration"), ("stream_reassembled_match", "Stream-Reassembled Match"),
            ("external_replay_exfil_behavior", "External Replay/Exfil Behavior"),
            ("challenge_file_hint_correlation", "Challenge File Hint Correlation"),
            ("credential_pattern_present", "Credential Pattern Present"),
            ("passphrase_parameter_present", "Passphrase Parameter Present"), ("likely_secret_not_flag", "Likely Secret (Not Flag)"),
        ])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
