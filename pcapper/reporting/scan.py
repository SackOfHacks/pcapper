"""Rendered output for --scan: every scanning source in triage order (OT
reconnaissance first, then internal scanners, stealth techniques and wide
sweeps), what each one learned (open services, banners, brute force), the
OT assets it touched and the ATT&CK techniques; per-scanner fingerprint
detail (MACs, OS and tool guesses, top ports) is -v."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..scan import ScanSummary
from ..utils import display_safe, format_duration, format_ts
from . import _style as st

if TYPE_CHECKING:
    from ..scan import ScanSourceResult

_SCAN_SEVERITY_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
_SCAN_STEALTH_MARKERS = ("FIN", "NULL", "XMAS", "Maimon", "ACK")
_VERDICT = {
    "CRITICAL": "active reconnaissance against OT/ICS assets",
    "HIGH": "deliberate network reconnaissance",
    "MEDIUM": "network scanning",
    "LOW": "limited probing",
}


def _ot_open(src: "ScanSourceResult") -> list[int]:
    """OT service ports that answered open: the scanner learned they exist."""
    ot = set(getattr(src, "ot_ports", None) or [])
    return sorted({p for t in (src.targets or []) for p in (t.open_ports or []) if p in ot})


def _ot_focused(src: "ScanSourceResult") -> bool:
    """OT reconnaissance, as opposed to a broad sweep that happens to cover a
    few OT ports (nmap's default top-1000 list includes 2222, 4000, 20000):
    a narrow port set, a large OT share, or an OT port that answered open."""
    ot = list(getattr(src, "ot_ports", None) or [])
    if not ot:
        return False
    return src.unique_ports <= 64 or len(ot) / max(src.unique_ports, 1) >= 0.2 or bool(_ot_open(src))


def _scan_source_severity(src: "ScanSourceResult") -> tuple[str, list[str]]:
    """Triage severity for one scanning source, with reasons."""
    reasons: list[str] = []
    rank = 1  # MEDIUM: any reconnaissance is at least notable
    techniques = list(getattr(src, "techniques", []) or [])
    stealth = [t for t in techniques if any(m in t for m in _SCAN_STEALTH_MARKERS)]
    ot_ports = list(getattr(src, "ot_ports", None) or [])
    if ot_ports:
        ports = ", ".join(str(p) for p in ot_ports[:8])
        if _ot_focused(src):
            rank = 3
            opened = _ot_open(src)
            reasons.append(f"OT/ICS service ports probed ({ports}) across {len(src.ot_targets)} asset(s)"
                           + (f", open: {', '.join(str(p) for p in opened)}" if opened else "")
                           + " - ICS reconnaissance (ATT&CK ICS T0846)")
        else:
            reasons.append(f"broad sweep of {src.unique_ports} ports included OT ports ({ports}); none answered open - not OT-specific")
    if getattr(src, "scanner_scope", "-") == "internal":
        rank = max(rank, 2)
        reasons.append("scanner is an internal host - likely post-compromise lateral discovery rather than external recon")
    elif getattr(src, "scanner_scope", "-") == "external" and getattr(src, "target_scope", "-") in ("internal", "mixed"):
        rank = max(rank, 2)
        reasons.append("external host scanning internal assets (inbound recon)")
    if stealth:
        rank = max(rank, 2)
        reasons.append("stealth / firewall-evasion technique: " + ", ".join(stealth))
    if src.unique_ports >= 500 or src.unique_targets >= 100:
        rank = max(rank, 2)
        reasons.append(f"wide sweep: {st.plural(src.unique_targets, 'target')}, {st.plural(src.unique_ports, 'port')}")
    if src.open_responses:
        reasons.append(f"{src.open_responses} open-service responses - the scanner learned live services")
    return {3: "CRITICAL", 2: "HIGH", 1: "MEDIUM", 0: "LOW"}[rank], reasons


def _scan_mitre_techniques(summary: ScanSummary) -> list[str]:
    tids: list[str] = []
    for src in summary.scan_sources:
        candidates = []
        if src.scan_type == "vertical":
            candidates.append("T1046 Network Service Discovery")
        if src.scan_type == "horizontal":
            candidates.append("T1018 Remote System Discovery")
        if getattr(src, "scanner_scope", "-") == "external":
            candidates.append("T1595 Active Scanning")
        if _ot_focused(src):
            candidates += ["ICS T0846 Remote System Discovery", "ICS T0840 Network Connection Enumeration"]
        tids += [t for t in candidates if t not in tids]
    return tids


def _rate(pps: float) -> str:
    return f"{pps:.1f}" if 0 < pps < 100 else f"{pps:.0f}"


def render_scan_summary(summary: ScanSummary, verbose: bool = False) -> str:
    rep = st.Report("Scan", summary.path)
    if not summary.scan_sources:
        rep.headline(None, "no network scanning detected",
                     f"{st.count(summary.total_packets)} packets examined" if summary.total_packets else "")
        if summary.errors:
            rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
        return rep.render()
    scored = [(src, *_scan_source_severity(src)) for src in summary.scan_sources]
    scored.sort(key=lambda x: (_SCAN_SEVERITY_RANK[x[1]], x[0].unique_ports, x[0].unique_targets), reverse=True)
    worst = scored[0][1]
    internal = sum(1 for s, _l, _r in scored if s.scanner_scope == "internal")
    rep.headline(worst.lower(), _VERDICT[worst], st.join([
        st.plural(len(scored), "scanner") + (f" ({internal} internal)" if internal else ""),
        f"{st.count(summary.relevant_packets)} probe packets of {st.count(summary.total_packets)}",
    ]))
    if internal:
        rep.scope(st.bad(f"{internal} internal scanner{'s' if internal != 1 else ''}: treat as a possibly compromised host"))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])

    rep.section("Scanners", st.table(
        ["Severity", "Scanner", "Scope", "Type", "Technique", "Targets", "Ports", "Open/closed/filtered", "Rate (pps)", "Start"],
        [[st.badge(sev), src.scanner_ip, src.scanner_scope, src.scan_type,
          ", ".join(t.split(" (")[0] for t in src.techniques) or src.scan_type, st.count(src.unique_targets), st.count(src.unique_ports),
          f"{src.open_responses}/{src.closed_responses}/{src.filtered_responses}", _rate(src.packets_per_second), st.ts(src.first_seen)]
         for src, sev, _r in scored],
        align="lllllrrrrl", widths=(None, None, None, None, 48), max_rows=10, noun="scanner",
    ))
    focus: list[str] = []
    for src, sev, reasons in scored if st.verbose() else scored[:3]:
        window = (f"{st.ts_range(src.first_seen, src.last_seen)} ({format_duration(src.duration_seconds)})"
                  if src.first_seen is not None and src.last_seen is not None else "")
        focus.append(f"  {st.badge(sev)}  {st.strong(src.scanner_ip)} ({src.scanner_scope}) -> {src.scan_type} scan, "
                     f"{st.plural(src.responsive_targets, 'live target')}")
        pad = " " * (st.BADGE_W + 4)
        for line in ([window] if window else []) + ([f"tool: {src.scanner_software_guess}"] if src.scanner_software_guess not in ("", "-") else []) \
                + reasons:
            focus.append(f"{pad}{st.dim(line)}")
    rep.section("Focus", focus)
    ot_sources = [s for s, _l, _r in scored if _ot_focused(s)]
    rep.section("OT reconnaissance", st.table(
        ["Scanner", "OT ports probed", "Open", "OT assets"],
        [[s.scanner_ip, ", ".join(str(p) for p in s.ot_ports), ", ".join(str(p) for p in _ot_open(s)) or "-", st.listing(s.ot_targets, 5)]
         for s in ot_sources], max_rows=8, noun="scanner",
    ))
    rep.section("ATT&CK", st.bullets(_scan_mitre_techniques(summary), max_items=None))
    learned = [[src.scanner_ip, t.target_ip, ",".join(str(p) for p in t.open_ports) or "-",
                display_safe(t.banner_samples[0], preserve_newlines=False) if t.banner_samples else "-",
                f"{t.brute_force_attempts} ({t.brute_force_failures} failed)" if t.brute_force_attempts else "-"]
               for src, _s, _r in scored for t in src.targets
               if t.open_ports or t.banner_samples or t.brute_force_attempts]
    rep.section("What the scanners learned", st.table(
        ["Scanner", "Target", "Open ports", "Banner", "Brute force"], learned, widths=(None, None, 40, 48), max_rows=10, noun="target",
    ))
    creds = [[src.scanner_ip, t.target_ip, display_safe(c, preserve_newlines=False)]
             for src, _s, _r in scored for t in src.targets for c in (t.credential_samples or [])]
    rep.section("Credential samples", st.table(["Scanner", "Target", "Sample"], creds, max_rows=None), detail=True)
    rep.section("Scanner detail", st.table(
        ["Scanner", "MACs", "OS guess", "Hostnames", "Top ports", "OT ports", "OT assets", "SYN", "Probes", "First", "Last", "Duration"],
        [[s.scanner_ip, ", ".join(s.mac_addresses) or "-", s.possible_os or "-", ", ".join(s.hostname_hints) or "-",
          ", ".join(str(p) for p in s.top_ports) or "-", ", ".join(str(p) for p in s.ot_ports) or "-", ", ".join(s.ot_targets) or "-",
          st.count(s.syn_packets), st.count(s.probe_packets), format_ts(s.first_seen), format_ts(s.last_seen), format_duration(s.duration_seconds)]
         for s, _l, _r in scored], align="lllllllrrlll", max_rows=None,
    ), detail=True)
    return rep.render()
