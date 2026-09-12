"""Rendered output for scan analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from typing import TYPE_CHECKING
from ..coloring import (
    danger,
    header,
    muted,
    ok,
    warn,
)
from ..scan import ScanSummary
from ..utils import (
    format_duration,
    format_ts,
)
if TYPE_CHECKING:
    from ..scan import ScanSourceResult

from ._common import (
    SUBSECTION_BAR,
    _always_full_render,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
)


_SCAN_SEVERITY_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}


_SCAN_STEALTH_MARKERS = ("FIN", "NULL", "XMAS", "Maimon", "ACK")


def _scan_source_severity(src: "ScanSourceResult") -> tuple[str, list[str]]:
    """Triage severity for one scanning source, with reasons."""
    reasons: list[str] = []
    rank = 1  # MEDIUM: any reconnaissance is at least notable
    techniques = list(getattr(src, "techniques", []) or [])
    stealth = [
        t for t in techniques if any(m in t for m in _SCAN_STEALTH_MARKERS)
    ]

    if getattr(src, "ot_ports", None):
        rank = max(rank, 3)
        ports = ", ".join(str(p) for p in src.ot_ports[:8])
        reasons.append(
            f"OT/ICS service ports probed ({ports}) across "
            f"{len(src.ot_targets)} asset(s) — ICS reconnaissance (ATT&CK ICS T0846)"
        )
    if getattr(src, "scanner_scope", "-") == "internal":
        rank = max(rank, 2)
        reasons.append(
            "Scanner is an INTERNAL host — likely post-compromise lateral "
            "discovery rather than external recon"
        )
    elif getattr(src, "scanner_scope", "-") == "external" and getattr(
        src, "target_scope", "-"
    ) in ("internal", "mixed"):
        rank = max(rank, 2)
        reasons.append("External host scanning internal assets (inbound recon)")
    if stealth:
        rank = max(rank, 2)
        reasons.append(
            "Stealth/firewall-evasion technique(s): " + ", ".join(stealth)
        )
    if src.unique_ports >= 500 or src.unique_targets >= 100:
        rank = max(rank, 2)
        reasons.append(
            f"Wide sweep: {src.unique_targets} target(s), {src.unique_ports} port(s)"
        )
    if src.open_responses:
        reasons.append(
            f"{src.open_responses} open-service response(s) — attacker learned live services"
        )
    label_for = {3: "CRITICAL", 2: "HIGH", 1: "MEDIUM", 0: "LOW"}
    return label_for[rank], reasons


def _scan_mitre_techniques(summary: ScanSummary) -> list[str]:
    tids: list[str] = []

    def _add(tid: str) -> None:
        if tid not in tids:
            tids.append(tid)

    for src in summary.scan_sources:
        if src.scan_type == "vertical":
            _add("T1046 Network Service Discovery")
        if src.scan_type == "horizontal":
            _add("T1018 Remote System Discovery")
        if getattr(src, "scanner_scope", "-") == "external":
            _add("T1595 Active Scanning")
        if getattr(src, "ot_ports", None):
            _add("ICS T0846 Remote System Discovery")
            _add("ICS T0840 Network Connection Enumeration")
    return tids


@_always_full_render
def render_scan_summary(summary: ScanSummary, verbose: bool = False) -> str:
    verbose = True  # --scan always shows the complete picture
    lines = [header("SCAN ANALYSIS")]
    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("Relevant Packets", str(summary.relevant_packets)))
    lines.append(_format_kv("Scanner Count", str(summary.scanner_count)))

    if not summary.scan_sources:
        lines.append(ok("No network scanning behavior detected."))
        if summary.errors:
            lines.append(
                _format_kv("Errors", "; ".join(summary.errors[: _limit_value(4)]))
            )
        return _finalize_output(lines)

    # Per-source severity + worst-case verdict.
    scored = [(src, *_scan_source_severity(src)) for src in summary.scan_sources]
    worst = max(_SCAN_SEVERITY_RANK[s[1]] for s in scored)
    worst_label = {3: "CRITICAL", 2: "HIGH", 1: "MEDIUM", 0: "LOW"}[worst]

    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    verdict_text = {
        "CRITICAL": "CRITICAL - active reconnaissance against OT/ICS or crown-jewel assets.",
        "HIGH": "HIGH - deliberate network reconnaissance (internal lateral discovery, stealth scan, or wide sweep).",
        "MEDIUM": "MEDIUM - network scanning activity detected.",
        "LOW": "LOW - limited probing activity.",
    }[worst_label]
    paint = danger if worst >= 2 else (warn if worst == 1 else ok)
    lines.append(paint(verdict_text))
    internal_scanners = [s for s, _l, _r in scored if s.scanner_scope == "internal"]
    if internal_scanners:
        lines.append(
            danger(
                f"{len(internal_scanners)} internal scanner(s) observed — treat as "
                "possible compromised host / lateral movement."
            )
        )

    # Findings table (triage-ordered: severity, then breadth).
    scored.sort(
        key=lambda x: (_SCAN_SEVERITY_RANK[x[1]], x[0].unique_ports, x[0].unique_targets),
        reverse=True,
    )
    lines.append(SUBSECTION_BAR)
    lines.append(header("Scanning Sources (triage order)"))
    rows = [
        [
            "Sev",
            "Scanner",
            "Scope",
            "Type",
            "Technique",
            "Tgts",
            "Ports",
            "Open/Closed/Filt",
            "Rate(pps)",
        ]
    ]
    for src, sev, _reasons in scored[: _limit_value(15)]:
        tech = ", ".join(t.split(" (")[0] for t in src.techniques) or src.scan_type
        rows.append(
            [
                sev,
                src.scanner_ip,
                src.scanner_scope,
                src.scan_type,
                tech,
                str(src.unique_targets),
                str(src.unique_ports),
                f"{src.open_responses}/{src.closed_responses}/{src.filtered_responses}",
                (
                    f"{src.packets_per_second:.1f}"
                    if 0 < src.packets_per_second < 100
                    else f"{src.packets_per_second:.0f}"
                ),
            ]
        )
    lines.append(_format_table(rows))

    # OT/ICS exposure callout.
    ot_sources = [s for s in summary.scan_sources if getattr(s, "ot_ports", None)]
    if ot_sources:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT/ICS Reconnaissance"))
        for src in ot_sources[: _limit_value(8)]:
            lines.append(
                danger(
                    f"- {src.scanner_ip} probed OT ports "
                    f"[{', '.join(str(p) for p in src.ot_ports[:10])}] on "
                    f"{', '.join(src.ot_targets[:5])}"
                )
            )

    # MITRE ATT&CK mapping.
    tids = _scan_mitre_techniques(summary)
    if tids:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ATT&CK Mapping"))
        for tid in tids:
            lines.append(muted(f"- {tid}"))

    # Focus Here First — top sources with reasons + timing.
    lines.append(SUBSECTION_BAR)
    lines.append(header("Focus Here First"))
    for src, sev, reasons in scored[: _limit_value(5)]:
        window = "-"
        if src.first_seen is not None and src.last_seen is not None:
            window = f"{format_ts(src.first_seen)} -> {format_ts(src.last_seen)} ({format_duration(src.duration_seconds)})"
        lines.append(
            f"[{sev}] {src.scanner_ip} ({src.scanner_scope}) -> "
            f"{src.scan_type} scan, {src.responsive_targets} live target(s)"
        )
        lines.append(muted(f"    window: {window}"))
        if src.scanner_software_guess and src.scanner_software_guess != "-":
            lines.append(muted(f"    tooling: {src.scanner_software_guess}"))
        for reason in reasons[: _limit_value(4)]:
            lines.append(muted(f"    - {reason}"))

    # Per-target detail (verbose).
    if verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Discovered Services / Targets"))
        rows = [
            ["Scanner", "Target", "Open Ports", "Banners", "Brute-Force"]
        ]
        for src, _sev, _r in scored[: _limit_value(6)]:
            for tgt in src.targets[: _limit_value(6)]:
                if not (tgt.open_ports or tgt.banner_samples or tgt.brute_force_attempts):
                    continue
                rows.append(
                    [
                        src.scanner_ip,
                        tgt.target_ip,
                        ",".join(str(p) for p in tgt.open_ports[:8]) or "-",
                        (tgt.banner_samples[0][:40] if tgt.banner_samples else "-"),
                        str(tgt.brute_force_attempts) if tgt.brute_force_attempts else "-",
                    ]
                )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    if summary.errors:
        lines.append(_format_kv("Errors", "; ".join(summary.errors[: _limit_value(4)])))
    return _finalize_output(lines)
