"""Rendered output for --mitre: every detection mapped to MITRE ATT&CK
(Enterprise and ICS) -- the observed kill chain, where to look first,
techniques and per-host chains; per-hit evidence, the attack path, coverage
counters and corpus provenance are -v detail."""

from __future__ import annotations

from collections import Counter
from types import SimpleNamespace

from ..mitre import _HIGH_IMPACT_TACTICS as _MITRE_HIGH_IMPACT_TACTICS
from ..mitre import MitreSummary
from ..utils import format_ts
from . import _style as st
from ._common import _redact_in_text, _render_deterministic_checks
from ._kv import counter_line

# Canonical kill-chain ordering merging enterprise + ICS tactics, so the
# coverage ribbon reads left-to-right as the adversary progresses.
_MITRE_KILLCHAIN_ORDER: dict[str, int] = {
    "Reconnaissance": 1,
    "Resource Development": 2,
    "Initial Access": 3,
    "Execution": 4,
    "Persistence": 5,
    "Privilege Escalation": 6,
    "Defense Evasion": 7,
    "Evasion": 7,
    "Credential Access": 8,
    "Discovery": 9,
    "Lateral Movement": 10,
    "Collection": 11,
    "Command and Control": 12,
    "Impair Process Control": 13,
    "Inhibit Response Function": 14,
    "Exfiltration": 15,
    "Impact": 16,
}


# Per-tactic triage guidance: the pcapper next step + what to confirm.
_MITRE_TACTIC_ACTION: dict[str, str] = {
    "Reconnaissance": "--scan / --services; confirm whether the source is an approved scanner before treating as recon",
    "Discovery": "--scan / --protocols; compare against baseline (net-new src,dst,port tuples are the signal)",
    "Credential Access": "--creds / --ntlm / --kerberos; pull AD/auth logs (4625/4768/4769) for the host",
    "Initial Access": "--http / --files; review the delivery vector and first-seen flow",
    "Execution": "--powershell / --wmic; correlate with endpoint/EDR process telemetry",
    "Lateral Movement": "--hostdetails -ip <host> then --streams; confirm the admin session is sanctioned",
    "Command and Control": "--beacon -v; confirm destination reputation (C2 vs SaaS/update/NTP)",
    "Exfiltration": "--exfil / --files; quantify outbound volume and destination",
    "Impact": "--threats -v; scope the availability/DoS impact and affected hosts",
    "Impair Process Control": "--modbus/--dnp3/--s7/--cip; correlate a change ticket + verify the source is an authorized EWS",
    "Inhibit Response Function": "--safety + the OT protocol flag; verify SIS isolation and validate with process telemetry",
    "Collection": "--files / --streams; identify what data was staged",
}


def _mitre_tactic_action(tactic: str) -> str:
    return _MITRE_TACTIC_ACTION.get(
        tactic, "scope the host/flow and corroborate with endpoint/IDS telemetry"
    )


def _mitre_kill_chain_rows(summary: MitreSummary) -> list[dict[str, object]]:
    """Aggregate mapped hits by tactic, in kill-chain order, for the ribbon."""
    by_tactic: dict[str, dict[str, object]] = {}
    for hit in getattr(summary, "hits", []) or []:
        row = by_tactic.setdefault(
            hit.tactic,
            {
                "tactic": hit.tactic,
                "tactic_id": hit.tactic_id,
                "framework": hit.framework,
                "count": 0,
                "techniques": Counter(),
                "hosts": set(),
                "confidence_rank": 0,
            },
        )
        row["count"] = int(row["count"]) + 1
        row.setdefault("tactic_ids", set()).add(str(hit.tactic_id))
        row["techniques"][f"{hit.technique} ({hit.technique_id})"] += 1
        for host in hit.host_refs:
            if isinstance(row["hosts"], set):
                row["hosts"].add(host)
        rank = {"high": 3, "medium": 2}.get(str(hit.confidence), 1)
        row["confidence_rank"] = max(int(row["confidence_rank"]), rank)
    rows = list(by_tactic.values())
    for row in rows:
        # A tactic named in both matrices (Discovery: TA0007 Enterprise,
        # TA0102 ICS) carries both ids, not whichever hit came first.
        row["tactic_id"] = ", ".join(sorted(i for i in row.pop("tactic_ids", set()) if i)) or row["tactic_id"]
    rows.sort(key=lambda r: _MITRE_KILLCHAIN_ORDER.get(str(r["tactic"]), 99))
    return rows


def _conf_text(rank: object) -> str:
    return {3: "high", 2: "medium", 1: "low"}.get(int(rank or 1), "low")


def render_mitre_summary(summary: MitreSummary, verbose: bool = False) -> str:
    """ATT&CK view of every detection: the kill chain as observed (tactic,
    hits, hosts, top technique), where to look first with the pcapper
    command for each, the technique table and each host's chain; the full
    per-hit evidence, attack path, coverage counters and corpus provenance
    are -v detail."""
    rep = st.Report("MITRE ATT&CK", summary.path)
    hits = list(getattr(summary, "hits", None) or [])
    mapped = int(getattr(summary, "mapped_detections", 0) or 0)
    total = int(getattr(summary, "total_detections", 0) or 0)
    if not hits:
        rep.headline(None, "no detections mapped to ATT&CK", f"{st.plural(total, 'detection')} examined" if total else "")
        if summary.errors:
            rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
        return rep.render()
    rows = _mitre_kill_chain_rows(summary)
    verdict = str(getattr(summary, "executive_verdict", "") or "LOW-CONFIDENCE SIGNAL")
    worst = max(hits, key=lambda h: st.sev_rank(h.severity)).severity
    # The badge follows the assessment: a "possible" intrusion is at most HIGH
    # and a low-confidence signal at most MEDIUM, whatever single hit is worst.
    cap = "critical" if verdict.startswith("LIKELY") else "high" if verdict.startswith("POSSIBLE") else "medium"
    severity = worst if st.sev_rank(worst) <= st.sev_rank(cap) else cap
    rep.headline(severity, f"{verdict.lower()} ({getattr(summary, 'executive_confidence', 'low') or 'low'} confidence)", st.join([
        f"{st.plural(mapped, 'technique hit')} from {st.plural(total, 'detection')}",
        st.plural(len(rows), "tactic"), st.plural(len(summary.technique_counts), "technique"),
        st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else "",
    ]))
    rep.scope("observed: " + " -> ".join(str(r["tactic"]) for r in rows))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])

    def _tactic(row: dict) -> str:
        text = f"{row['tactic']} ({row['tactic_id']})"
        return st.bad(text) if str(row["tactic"]) in _MITRE_HIGH_IMPACT_TACTICS else text

    rep.section("Kill chain", st.table(
        ["Stage", "Tactic", "Hits", "Hosts", "Confidence", "Top technique"],
        [[_MITRE_KILLCHAIN_ORDER.get(str(r["tactic"]), "-"), _tactic(r), r["count"], len(r["hosts"]), _conf_text(r["confidence_rank"]),
          r["techniques"].most_common(1)[0][0] if r["techniques"] else "-"] for r in rows],
        align="rlrrll", widths=(None, None, None, None, None, 56), max_rows=None,
    ))
    focus = sorted(rows, key=lambda r: (str(r["tactic"]) in _MITRE_HIGH_IMPACT_TACTICS, _MITRE_KILLCHAIN_ORDER.get(str(r["tactic"]), 0),
                                        int(r["count"])), reverse=True)
    lines: list[str] = []
    for idx, r in enumerate(focus if st.verbose() else focus[:3], start=1):
        top = r["techniques"].most_common(1)[0][0] if r["techniques"] else "-"
        hit_text = st.plural(int(r["count"]), "hit")
        lines.append(f"  {idx}. {_tactic(r)}  {top}  {st.dim(f'[{hit_text}]')}")
        lines.append(f"     {st.dim('hosts:')} {st.listing(sorted(r['hosts']), 4) or 'no host attributed'}")
        lines.append(f"     {st.dim('next:')}  pcapper <capture> {_mitre_tactic_action(str(r['tactic']))}")
    rep.section("Focus", lines)
    heat = list(getattr(summary, "technique_heat", None) or [])
    rep.section("Techniques", st.table(
        ["Technique", "Tactic", "Hits", "Hosts", "Confidence", "First", "Last"]
        + (["Framework", "Sources", "Evidence"] if st.verbose() else []),
        [[f"{i.get('technique', '-')} ({i.get('technique_id', '-')})", i.get("tactic", "-"), i.get("count", "-"), i.get("host_count", "-"),
          i.get("confidence", "-"), st.ts(i.get("first_seen")), st.ts(i.get("last_seen"))]
         + ([i.get("framework", "-"), i.get("source_count", "-"), i.get("evidence_count", "-")] if st.verbose() else []) for i in heat],
        align="llrrlll" + ("lrr" if st.verbose() else ""), widths=(56,), max_rows=10, noun="technique",
    ))
    host_paths = getattr(summary, "host_attack_paths", {}) or {}
    host_roles = getattr(summary, "host_roles", {}) or {}
    rep.section("Host chains", st.table(
        ["Host", "Roles", "Steps", "Chain"],
        [[host, ", ".join((host_roles.get(host) or [])[:4]) or "-", len(chain),
          " -> ".join(chain if st.verbose() else chain[:3]) + ("" if st.verbose() or len(chain) <= 3 else " -> …")]
         for host, chain in host_paths.items()],
        align="llrl", widths=(None, 30, None, 110), max_rows=8, noun="host",
    ))
    rep.section("Sequence warnings", st.bullets([_redact_in_text(str(i)) for i in (getattr(summary, "sequence_issues", None) or [])],
                                                max_items=3, noun="warning"))
    rep.section("Indicators", st.kv([("IOCs", st.top(summary.ioc_counts, 8)), ("Artifacts", st.top(summary.artifact_counts, 8))]))

    ratio = f" ({mapped / total:.1%} mapped)" if total else ""
    rep.section("Assessment", st.kv([
        ("Verdict", f"{verdict} ({getattr(summary, 'executive_confidence', 'low') or 'low'} confidence)"),
        ("Coverage", f"{mapped} technique hits from {total} detections{ratio}"),
        counter_line("Frameworks", summary.framework_counts, None),
        ("Window", f"{format_ts(summary.first_seen)} / {format_ts(summary.last_seen)}" if summary.first_seen is not None else ""),
        ("Duration", f"{summary.duration_seconds:.1f}s" if summary.duration_seconds is not None else ""),
    ]) + st.bullets([_redact_in_text(str(r)) for r in (getattr(summary, "executive_reasons", None) or [])], max_items=None), detail=True)
    rep.section("Alternative explanations", st.bullets([_redact_in_text(str(i)) for i in (getattr(summary, "alternate_explanations", None) or [])],
                                                       max_items=None), detail=True)
    rep.section("Coverage counters", st.kv([counter_line("Tactics", summary.tactic_counts, None),
                                            counter_line("Techniques", summary.technique_counts, None),
                                            counter_line("Procedures", summary.procedure_counts, None)]), detail=True)
    path_lines = [f"  {st.dim('->')} {edge}" for edge in (summary.attack_path or [])]
    nodes = list(dict.fromkeys(part.strip() for edge in (summary.attack_path or []) for part in str(edge).split("->") if part.strip()))
    rep.section("Attack path", path_lines + ([f"  {st.dim('nodes:')} " + ", ".join(f"{i:02d}. {n}" for i, n in enumerate(nodes, 1))]
                                             if nodes else []), detail=True)
    details: list[str] = []
    for hit in hits:
        refs = (len(hit.evidence), len(hit.packet_refs or []), len(hit.flow_refs or []), len(hit.host_refs or []))
        details.append(f"  {st.badge(hit.severity)}  [{hit.framework.upper()}] {hit.tactic} ({hit.tactic_id}) -> "
                       f"{st.strong(f'{hit.technique} ({hit.technique_id})')}")
        pad = " " * (st.BADGE_W + 4)
        for label_text, value in (
            ("procedure", hit.procedure), ("source", f"{hit.source} · {hit.confidence} confidence · {hit.occurrence}x · "
                                                     f"{int(getattr(hit, 'corroborating_sources', 0) or 0)} corroborating sources"),
            ("seen", f"{format_ts(hit.first_seen)} / {format_ts(hit.last_seen)}"),
            ("refs", f"{refs[0]} evidence · {refs[1]} packets · {refs[2]} flows · {refs[3]} hosts"),
            ("rationale", _redact_in_text(str(getattr(hit, "rationale", "") or ""))), ("explanation", _redact_in_text(hit.details or "")),
            ("keywords", ", ".join(getattr(hit, "matched_keywords", None) or [])), ("packets", ", ".join(hit.packet_refs or [])),
            ("flows", ", ".join(hit.flow_refs or [])), ("hosts", ", ".join(hit.host_refs or [])),
            ("contradictions", ", ".join(getattr(hit, "contradictory_signals", None) or [])),
            ("artifacts", ", ".join(hit.artifacts or [])), ("IOCs", ", ".join(hit.iocs or [])),
        ):
            if value:
                details.append(f"{pad}{st.dim(label_text + ':')} {value}")
        details += [f"{pad}  {st.dim(f'{i:02d}.')} {_redact_in_text(str(e))}" for i, e in enumerate(hit.evidence, 1)]
    rep.section("TTP details", details, detail=True)
    rep.section("Provenance", st.kv([("Enterprise corpus", str(getattr(summary, "attack_enterprise_version", "-"))),
                                     ("ICS corpus", str(getattr(summary, "attack_ics_version", "-"))),
                                     ("Mapping pack", str(getattr(summary, "mapping_pack_version", "-")))]), detail=True)
    if st.analysis_sections():
        legacy: list[str] = []
        checks = getattr(summary, "checks", {}) or {}
        _render_deterministic_checks(legacy, SimpleNamespace(deterministic_checks=checks), "Deterministic Checks", [
            ("cross_signal_corroboration", "Cross-Signal Corroboration"), ("sequence_plausibility", "Sequence Plausibility"),
            ("ics_process_impact", "ICS Process/Safety Impact"), ("host_boundary_activity", "Host Boundary Activity"),
        ])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
