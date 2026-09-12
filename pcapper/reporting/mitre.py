"""Rendered output for mitre analysis.

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
from ..mitre import MitreSummary, _HIGH_IMPACT_TACTICS as _MITRE_HIGH_IMPACT_TACTICS
from ..utils import (
    format_ts,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _finalize_output,
    _format_counter,
    _format_kv,
    _format_table,
    _highlight_public_ips,
    _limit_value,
    _redact_in_text,
    _truncate_text,
)


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
        row["techniques"][f"{hit.technique} ({hit.technique_id})"] += 1
        for host in hit.host_refs:
            if isinstance(row["hosts"], set):
                row["hosts"].add(host)
        rank = {"high": 3, "medium": 2}.get(str(hit.confidence), 1)
        row["confidence_rank"] = max(int(row["confidence_rank"]), rank)
    rows = list(by_tactic.values())
    rows.sort(key=lambda r: _MITRE_KILLCHAIN_ORDER.get(str(r["tactic"]), 99))
    return rows


def render_mitre_summary(summary: MitreSummary, verbose: bool = False) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"MITRE ATT&CK MAPPING :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    lines.append(SUBSECTION_BAR)
    lines.append(header("Executive Assessment"))
    verdict = str(getattr(summary, "executive_verdict", "") or "LOW-CONFIDENCE SIGNAL")
    confidence = str(getattr(summary, "executive_confidence", "low") or "low")
    if verdict.startswith("LIKELY"):
        lines.append(danger(verdict))
    elif verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", confidence))
    mapped = int(getattr(summary, "mapped_detections", 0) or 0)
    total = int(getattr(summary, "total_detections", 0) or 0)
    lines.append(
        _format_kv("Mapped TTPs", f"{mapped} technique-hit(s) from {total} detection(s)")
    )
    for reason in (getattr(summary, "executive_reasons", []) or [])[: _limit_value(8)]:
        lines.append(muted(f"- {_redact_in_text(str(reason))}"))

    # ---- Kill-Chain Coverage (the primary ATT&CK triage view) --------------
    kill_chain_rows = _mitre_kill_chain_rows(summary)
    if kill_chain_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Kill-Chain Coverage"))
        present = " -> ".join(str(r["tactic"]) for r in kill_chain_rows)
        lines.append(muted(f"Observed progression: {present}"))
        rows = [["Stage", "Tactic", "Hits", "Hosts", "Conf", "Top Technique"]]
        for row in kill_chain_rows:
            techs = row["techniques"]
            top_tech = techs.most_common(1)[0][0] if techs else "-"
            conf = {3: "high", 2: "medium", 1: "low"}.get(
                int(row["confidence_rank"]), "low"
            )
            tactic_text = f"{row['tactic']} ({row['tactic_id']})"
            if str(row["tactic"]) in _MITRE_HIGH_IMPACT_TACTICS:
                tactic_text = danger(tactic_text)
            rows.append(
                [
                    str(_MITRE_KILLCHAIN_ORDER.get(str(row["tactic"]), "-")),
                    tactic_text,
                    str(row["count"]),
                    str(len(row["hosts"]) if isinstance(row["hosts"], set) else 0),
                    conf,
                    _truncate_text(str(top_tech), 40),
                ]
            )
        lines.append(_format_table(rows))

    # ---- Focus Here First: prioritized techniques + next action ------------
    if getattr(summary, "hits", None):
        # Rank tactics: objective-stage first, then later kill-chain stage, then hits.
        focus = sorted(
            kill_chain_rows,
            key=lambda r: (
                str(r["tactic"]) in _MITRE_HIGH_IMPACT_TACTICS,
                _MITRE_KILLCHAIN_ORDER.get(str(r["tactic"]), 0),
                int(r["count"]),
            ),
            reverse=True,
        )
        lines.append(SUBSECTION_BAR)
        lines.append(header("Focus Here First"))
        for idx, row in enumerate(focus[: _limit_value(5)], start=1):
            techs = row["techniques"]
            top_tech = techs.most_common(1)[0][0] if techs else "-"
            host_set = row["hosts"] if isinstance(row["hosts"], set) else set()
            host_hint = (
                ", ".join(sorted(host_set)[:3]) if host_set else "no host attributed"
            )
            sev_style = (
                danger if str(row["tactic"]) in _MITRE_HIGH_IMPACT_TACTICS else warn
            )
            lines.append(
                sev_style(
                    f"{idx}. {row['tactic']} ({row['tactic_id']}) - {top_tech} "
                    f"[{row['count']} hit(s)]"
                )
            )
            lines.append(
                muted(f"   hosts: {_highlight_public_ips(host_hint)}")
            )
            lines.append(
                muted(f"   run:  pcapper <capture> {_mitre_tactic_action(str(row['tactic']))}")
            )

    checks = getattr(summary, "checks", {}) or {}
    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Checks"))
    check_labels = [
        ("cross_signal_corroboration", "Cross-Signal Corroboration"),
        ("sequence_plausibility", "Sequence Plausibility"),
        ("ics_process_impact", "ICS Process/Safety Impact"),
        ("host_boundary_activity", "Host Boundary Activity"),
    ]
    for key, label_text in check_labels:
        evidence = checks.get(key, []) if isinstance(checks, dict) else []
        evidence_items = [str(v) for v in (evidence or []) if str(v).strip()]
        lines.append(label(label_text))
        if evidence_items:
            lines.append(
                warn(
                    f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"
                )
            )
            for item in evidence_items[: _limit_value(8 if verbose else 5)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))
        else:
            lines.append(
                ok(
                    f"No, there is no strong evidence for {label_text.lower()} in this capture."
                )
            )

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors[: _limit_value(10)]:
            lines.append(danger(f"- {err}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Coverage"))
    lines.append(_format_kv("Total Detections", str(summary.total_detections)))
    lines.append(_format_kv("Mapped to ATT&CK", str(summary.mapped_detections)))
    if summary.total_detections > 0:
        ratio = (
            float(summary.mapped_detections) / float(summary.total_detections)
        ) * 100.0
        lines.append(_format_kv("Mapping Ratio", f"{ratio:.1f}%"))
    if summary.first_seen is not None:
        lines.append(_format_kv("First Seen", format_ts(summary.first_seen)))
    if summary.last_seen is not None:
        lines.append(_format_kv("Last Seen", format_ts(summary.last_seen)))
    if summary.duration_seconds is not None:
        lines.append(_format_kv("Duration", f"{summary.duration_seconds:.1f}s"))
    lines.append(
        _format_kv("Framework Split", _format_counter(summary.framework_counts, 4))
    )
    lines.append(
        _format_kv("Top Tactics", _format_counter(summary.tactic_counts, 8, key_max=56))
    )
    lines.append(
        _format_kv(
            "Top Techniques", _format_counter(summary.technique_counts, 10, key_max=64)
        )
    )
    lines.append(
        _format_kv(
            "Top Procedures", _format_counter(summary.procedure_counts, 8, key_max=70)
        )
    )

    technique_heat = list(getattr(summary, "technique_heat", []) or [])
    if technique_heat:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Technique Heat Table"))
        rows = [
            [
                "Framework",
                "Tactic",
                "Technique",
                "Count",
                "Hosts",
                "Sources",
                "Evidence",
                "Confidence",
                "First",
                "Last",
            ]
        ]
        for item in technique_heat[: _limit_value(30 if verbose else 14)]:
            rows.append(
                [
                    str(item.get("framework", "-")),
                    str(item.get("tactic", "-")),
                    f"{item.get('technique', '-')} ({item.get('technique_id', '-')})",
                    str(item.get("count", "-")),
                    str(item.get("host_count", "-")),
                    str(item.get("source_count", "-")),
                    str(item.get("evidence_count", "-")),
                    str(item.get("confidence", "-")),
                    format_ts(item.get("first_seen")),
                    format_ts(item.get("last_seen")),
                ]
            )
        lines.append(_format_table(rows))

    host_paths = getattr(summary, "host_attack_paths", {}) or {}
    host_roles = getattr(summary, "host_roles", {}) or {}
    if host_paths:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Host-Centric ATT&CK Chains"))
        rows = [["Host", "Role(s)", "Chain Length", "Chain Preview"]]
        for host, chain in list(host_paths.items())[
            : _limit_value(24 if verbose else 10)
        ]:
            role_text = (
                ",".join(host_roles.get(host, [])[:4])
                if isinstance(host_roles, dict)
                else "-"
            )
            preview = " -> ".join(chain[:3]) if chain else "-"
            rows.append(
                [
                    str(host),
                    role_text or "-",
                    str(len(chain)),
                    _truncate_text(preview, 120),
                ]
            )
        lines.append(_format_table(rows))

    sequence_issues = list(getattr(summary, "sequence_issues", []) or [])
    if sequence_issues:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Sequence Plausibility Warnings"))
        for item in sequence_issues[: _limit_value(10 if verbose else 6)]:
            lines.append(warn(f"- {_redact_in_text(str(item))}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Attack Path Visualization"))
    if summary.attack_path:
        unique_nodes: list[str] = []
        seen_nodes: set[str] = set()
        for edge in summary.attack_path[: _limit_value(40 if verbose else 20)]:
            lines.append(f"  {muted('->')} {edge}")
            for node in [part.strip() for part in edge.split("->") if part.strip()]:
                if node not in seen_nodes:
                    seen_nodes.add(node)
                    unique_nodes.append(node)
        if unique_nodes:
            lines.append(muted("Path Nodes:"))
            for idx, node in enumerate(
                unique_nodes[: _limit_value(18 if verbose else 10)], start=1
            ):
                lines.append(muted(f"  {idx:02d}. {node}"))
    else:
        lines.append(
            muted("No attack chain could be inferred from current detections.")
        )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Evidence and Artifacts/IOC"))
    lines.append(
        _format_kv(
            "IOC Highlights", _format_counter(summary.ioc_counts, 12, key_max=56)
        )
    )
    lines.append(
        _format_kv(
            "Artifact Highlights",
            _format_counter(summary.artifact_counts, 12, key_max=56),
        )
    )
    total_evidence_items = sum(len(hit.evidence) for hit in summary.hits)
    total_packet_refs = sum(
        len(list(getattr(hit, "packet_refs", []) or [])) for hit in summary.hits
    )
    total_flow_refs = sum(
        len(list(getattr(hit, "flow_refs", []) or [])) for hit in summary.hits
    )
    total_host_refs = sum(
        len(list(getattr(hit, "host_refs", []) or [])) for hit in summary.hits
    )
    lines.append(_format_kv("Evidence Entries", str(total_evidence_items)))
    lines.append(_format_kv("Packet References", str(total_packet_refs)))
    lines.append(_format_kv("Flow References", str(total_flow_refs)))
    lines.append(_format_kv("Host References", str(total_host_refs)))

    if summary.hits:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Evidence Deep Dive"))
        rows = [
            [
                "Technique",
                "Source",
                "Severity",
                "Confidence",
                "Evidence",
                "Packets",
                "Flows",
                "Hosts",
            ]
        ]
        for hit in summary.hits[: _limit_value(200)]:
            rows.append(
                [
                    f"{hit.technique} ({hit.technique_id})",
                    str(hit.source),
                    str(hit.severity),
                    str(hit.confidence),
                    str(len(hit.evidence)),
                    str(len(list(getattr(hit, "packet_refs", []) or []))),
                    str(len(list(getattr(hit, "flow_refs", []) or []))),
                    str(len(list(getattr(hit, "host_refs", []) or []))),
                ]
            )
        lines.append(_format_table(rows))

    alternates = list(getattr(summary, "alternate_explanations", []) or [])
    if alternates:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Alternative Explanations"))
        for item in alternates[: _limit_value(8)]:
            lines.append(muted(f"- {_redact_in_text(str(item))}"))

    if summary.hits:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TTP Details"))
        max_hits = _limit_value(200)
        for hit in summary.hits[:max_hits]:
            title = (
                f"[{hit.framework.upper()}] {hit.tactic} ({hit.tactic_id}) -> "
                f"{hit.technique} ({hit.technique_id})"
            )
            lines.append(label(title))
            lines.append(muted(f"  Procedure: {hit.procedure}"))
            lines.append(
                muted(
                    f"  Source/Severity/Confidence: {hit.source} / {hit.severity} / {hit.confidence}"
                )
            )
            lines.append(muted(f"  Occurrence: {hit.occurrence}"))
            lines.append(
                muted(
                    f"  First/Last Seen: {format_ts(hit.first_seen)} / {format_ts(hit.last_seen)}"
                )
            )
            lines.append(
                muted(
                    f"  Corroborating Sources: {int(getattr(hit, 'corroborating_sources', 0) or 0)}"
                )
            )
            if getattr(hit, "rationale", ""):
                lines.append(
                    muted(
                        f"  Rationale: {_truncate_text(_redact_in_text(str(hit.rationale)), 260)}"
                    )
                )
            if getattr(hit, "matched_keywords", None):
                lines.append(
                    muted(
                        f"  Matched Keywords: {', '.join(list(getattr(hit, 'matched_keywords', []) or [])[:8])}"
                    )
                )
            if getattr(hit, "packet_refs", None):
                lines.append(
                    muted(
                        f"  Packet Refs: {', '.join(list(getattr(hit, 'packet_refs', []) or [])[:8])}"
                    )
                )
            if getattr(hit, "flow_refs", None):
                lines.append(
                    muted(
                        f"  Flow Refs: {', '.join(list(getattr(hit, 'flow_refs', []) or [])[:4])}"
                    )
                )
            if getattr(hit, "host_refs", None):
                lines.append(
                    muted(
                        f"  Host Refs: {', '.join(list(getattr(hit, 'host_refs', []) or [])[:8])}"
                    )
                )
            if getattr(hit, "contradictory_signals", None):
                lines.append(
                    muted(
                        f"  Contradictions: {', '.join(list(getattr(hit, 'contradictory_signals', []) or []))}"
                    )
                )
            if hit.details:
                lines.append(
                    muted(
                        f"  Explanation: {_truncate_text(_redact_in_text(hit.details), 240)}"
                    )
                )
            if hit.evidence:
                lines.append(muted("  Evidence:"))
                for idx, evidence in enumerate(
                    hit.evidence[: _limit_value(200)], start=1
                ):
                    lines.append(
                        muted(f"    {idx:02d}. {_redact_in_text(str(evidence))}")
                    )
            if hit.artifacts:
                lines.append(
                    muted(
                        f"  Artifacts: {', '.join(hit.artifacts[: _limit_value(40)])}"
                    )
                )
            if hit.iocs:
                lines.append(muted(f"  IOC: {', '.join(hit.iocs[: _limit_value(40)])}"))
        hidden = max(0, len(summary.hits) - max_hits)
        if hidden:
            lines.append(
                muted(
                    f"{hidden} additional mapped TTP entries suppressed for readability."
                )
            )
    else:
        lines.append(
            muted("No MITRE ATT&CK TTP mappings were derived from this capture.")
        )

    lines.append(SUBSECTION_BAR)
    lines.append(header("ATT&CK Corpus / Provenance"))
    lines.append(
        _format_kv(
            "Enterprise Corpus", str(getattr(summary, "attack_enterprise_version", "-"))
        )
    )
    lines.append(
        _format_kv("ICS Corpus", str(getattr(summary, "attack_ics_version", "-")))
    )
    lines.append(
        _format_kv("Mapping Pack", str(getattr(summary, "mapping_pack_version", "-")))
    )

    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)
