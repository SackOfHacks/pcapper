"""Rendered output for ctf analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from collections import Counter
from ..coloring import (
    danger,
    header,
    label,
    muted,
    ok,
    warn,
)
from ..ctf import CtfSummary
from ..utils import (
    format_duration,
    format_ts,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _finalize_output,
    _format_counter,
    _format_kv,
    _format_table,
    _limit_value,
    _redact_in_text,
    _truncate_text,
)


def render_ctf_summary(summary: CtfSummary) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"CTF ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("Hits", str(len(summary.hits))))
    lines.append(_format_kv("Decoded Hits", str(len(summary.decoded_hits))))
    lines.append(
        _format_kv(
            "Candidate Findings",
            str(len(getattr(summary, "candidate_findings", []) or [])),
        )
    )
    lines.append(_format_kv("Start", format_ts(getattr(summary, "first_seen", None))))
    lines.append(_format_kv("End", format_ts(getattr(summary, "last_seen", None))))
    lines.append(
        _format_kv(
            "Duration", format_duration(getattr(summary, "duration_seconds", None))
        )
    )

    def _ctf_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        high_conf = int(getattr(summary, "confidence_counts", Counter()).get("high", 0))
        medium_conf = int(
            getattr(summary, "confidence_counts", Counter()).get("medium", 0)
        )
        checks = getattr(summary, "deterministic_checks", {}) or {}

        if high_conf:
            score += min(4, high_conf)
            reasons.append(f"High-confidence CTF candidates observed ({high_conf})")
        if medium_conf >= 2:
            score += 1
            reasons.append(
                f"Multiple medium-confidence candidates observed ({medium_conf})"
            )
        if checks.get("decoded_wrapper_pattern_present"):
            score += 2
            reasons.append("Decoded wrapper-pattern matches observed")
        if checks.get("multi_source_corroboration"):
            score += 1
            reasons.append("Cross-source corroboration observed")
        if checks.get("stream_reassembled_match"):
            score += 1
            reasons.append("Stream-boundary reconstruction recovered wrapper match")
        if checks.get("external_replay_exfil_behavior"):
            score += 1
            reasons.append("Candidate replay/exfil behavior observed")

        if score >= 7:
            verdict = "YES - high-confidence CTF flag evidence is present."
            confidence = "High"
        elif score >= 4:
            verdict = "LIKELY - strong CTF evidence is present with corroboration."
            confidence = "Medium"
        elif score >= 2:
            verdict = "POSSIBLE - weak-to-moderate CTF evidence is present."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing high-confidence CTF evidence from current heuristics."
            confidence = "Low"

        if not reasons:
            reasons.append("No high-confidence CTF heuristic crossed threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _ctf_verdict()
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", f"{confidence} (score={verdict_score})"))
    lines.append(muted("Reasons:"))
    for reason in verdict_reasons[: _limit_value(8)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    if summary.token_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Tokens"))
        lines.append(
            _format_kv("Token Frequency", _format_counter(summary.token_counts, 10))
        )

    if summary.decoded_hits:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Decoded Wrapper Hits"))
        for item in summary.decoded_hits[: _limit_value(8)]:
            lines.append(muted(f"- {_redact_in_text(item)}"))

    if getattr(summary, "file_hints", None):
        if summary.file_hints:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Challenge File Hints"))
            for item in summary.file_hints[: _limit_value(10)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic CTF Checks"))
    checks = getattr(summary, "deterministic_checks", {}) or {}
    check_labels = [
        ("flag_wrapper_pattern_present", "Flag Wrapper Pattern Present"),
        ("decoded_wrapper_pattern_present", "Decoded Wrapper Pattern Present"),
        ("multi_source_corroboration", "Multi-Source Corroboration"),
        ("stream_reassembled_match", "Stream-Reassembled Match"),
        ("external_replay_exfil_behavior", "External Replay/Exfil Behavior"),
        ("challenge_file_hint_correlation", "Challenge File Hint Correlation"),
        ("credential_pattern_present", "Credential Pattern Present"),
        ("passphrase_parameter_present", "Passphrase Parameter Present"),
        ("likely_secret_not_flag", "Likely Secret (Not Flag)"),
    ]

    matrix_rows = [["Category", "Risk", "Confidence", "Evidence"]]
    for key, label_text in check_labels:
        evidence_items = checks.get(key, []) if isinstance(checks, dict) else []
        evidence_items = [str(v) for v in (evidence_items or []) if str(v).strip()]
        lines.append(label(label_text))
        if evidence_items:
            if key == "likely_secret_not_flag":
                lines.append(
                    ok(
                        f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"
                    )
                )
                matrix_rows.append(
                    [label_text, "Low", "Medium", f"{len(evidence_items)} signal(s)"]
                )
            else:
                lines.append(
                    warn(
                        f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"
                    )
                )
                risk = (
                    "High"
                    if key
                    in {
                        "flag_wrapper_pattern_present",
                        "decoded_wrapper_pattern_present",
                        "stream_reassembled_match",
                    }
                    else "Medium"
                )
                conf_level = (
                    "High"
                    if key
                    in {"decoded_wrapper_pattern_present", "multi_source_corroboration"}
                    else "Medium"
                )
                matrix_rows.append(
                    [label_text, risk, conf_level, f"{len(evidence_items)} signal(s)"]
                )
            for item in evidence_items[: _limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))
        else:
            lines.append(
                ok(
                    f"No, there is no strong evidence for {label_text.lower()} in this capture."
                )
            )
            matrix_rows.append([label_text, "None", "Low", "No matching detections"])

    lines.append(SUBSECTION_BAR)
    lines.append(header("CTF Confidence Matrix"))
    lines.append(_format_table(matrix_rows))

    findings = list(getattr(summary, "candidate_findings", []) or [])
    if findings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Candidate Provenance"))
        rows = [
            [
                "Candidate",
                "Score",
                "Confidence",
                "Decode",
                "Source",
                "Flow",
                "Packet",
                "Time",
            ]
        ]
        for item in findings[: _limit_value(15)]:
            rows.append(
                [
                    _truncate_text(
                        _redact_in_text(str(item.get("candidate", "-"))), 36
                    ),
                    str(item.get("score", "-")),
                    str(item.get("confidence", "-")),
                    str(item.get("decode_chain", "raw")),
                    str(item.get("source", "-")),
                    f"{item.get('src', '-')}->{item.get('dst', '-')}",
                    str(item.get("packet", "-")),
                    format_ts(item.get("ts")),
                ]
            )
        lines.append(_format_table(rows))

    timeline = list(getattr(summary, "timeline", []) or [])
    if timeline:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Timeline"))
        rows = [["Time", "Event", "Candidate", "Confidence", "Flow", "Packet"]]
        for item in timeline[: _limit_value(15)]:
            rows.append(
                [
                    format_ts(item.get("ts")),
                    str(item.get("event", "-")),
                    _truncate_text(
                        _redact_in_text(str(item.get("candidate", "-"))), 42
                    ),
                    str(item.get("confidence", "-")),
                    f"{item.get('src', '-')}->{item.get('dst', '-')}",
                    str(item.get("packet", "-")),
                ]
            )
        lines.append(_format_table(rows))

    false_context = list(getattr(summary, "false_positive_context", []) or [])
    if false_context:
        lines.append(SUBSECTION_BAR)
        lines.append(header("False-Positive Context"))
        for item in false_context[: _limit_value(8)]:
            lines.append(muted(f"- {_redact_in_text(item)}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
