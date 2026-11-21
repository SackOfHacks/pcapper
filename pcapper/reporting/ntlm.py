"""Rendered output for NTLM: who authenticated where (domain, user,
workstation, NTLM version), the crackable Net-NTLM hashes, and the
negotiation; conversations and analysis notes are -v detail."""

from __future__ import annotations

from typing import TYPE_CHECKING

from . import _style as st
from ._common import _render_deterministic_checks
from ._kv import counter_line, findings_for

if TYPE_CHECKING:
    from ..ntlm import NtlmAnalysis


def _account(domain: object, user: object) -> str:
    dom = str(domain or "")
    name = str(user or "-")
    return f"{dom}\\{name}" if dom and dom not in ("Unknown", "<NO_DOMAIN>") else name


def render_ntlm_summary(summary: "NtlmAnalysis") -> str:
    rep = st.Report("NTLM", summary.path)
    findings = findings_for(summary, ot=False)
    if not summary.sessions and not getattr(summary, "ntlm_packets", 0) and not st.material(findings):
        return rep.absent("NTLM authentication", summary.errors)
    v1 = [s for s in summary.sessions if s.version == "NTLMv1"]
    severity, text = st.verdict(findings, high="high-severity NTLM activity: investigate",
                                medium="NTLM activity to review",
                                clean=st.join(["no findings", st.bad(f"{len(v1)} NTLMv1 session(s)") if v1 else ""]))
    if v1 and severity is None:
        severity, text = "medium", f"legacy NTLMv1 in {st.plural(len(v1), 'session')}: crackable to the NT hash"
    rep.headline(severity, text, st.join([
        f"{st.count(getattr(summary, 'ntlm_packets', 0))} NTLM packets" if getattr(summary, "ntlm_packets", 0) else "",
        st.plural(summary.authenticated_sessions, "authentication"),
        st.duration(summary.duration) if summary.duration else "",
        counter_line("", getattr(summary, "versions", None), 3)[1],
    ]))
    rep.scope(f"{st.plural(len(summary.src_counts), 'source')} -> {st.plural(len(summary.dst_counts), 'destination')}")
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    auths = sorted((s for s in summary.sessions if s.message_type == "Authenticate"), key=lambda s: s.ts or 0.0)
    rep.section("Authentications", st.table(
        ["Time", "Flow", "Account", "Workstation", "Version"],
        [[st.ts(s.ts), f"{s.src_ip}:{s.src_port} -> {s.dst_ip}:{s.dst_port}", _account(s.domain, s.username),
          s.workstation if s.workstation and s.workstation != "Unknown" else "-",
          st.bad(s.version) if s.version == "NTLMv1" else s.version] for s in auths],
        max_rows=10, noun="authentication",
    ))

    crackable = list(getattr(summary, "crackable_hashes", None) or [])
    if crackable:
        shown = crackable if st.verbose() else crackable[:5]
        lines = [f"  {st.bad(st.plural(len(crackable), 'crackable hash', 'crackable hashes'))}"
                 f"  {st.dim('NTLMv2: hashcat -m 5600 · NTLMv1: hashcat -m 5500')}"]
        for rec in shown:
            lines.append(f"  {st.strong(_account(rec.get('domain'), rec.get('username')))}  "
                         + st.dim(f"{rec.get('version', '?')} · {rec.get('src_ip', '?')} -> {rec.get('dst_ip', '?')} · "
                                  f"-m {rec.get('hashcat_mode', '?')}"))
            lines.append(f"    {rec.get('hash', '')}")
        if len(crackable) > len(shown):
            lines.append(st.more(len(crackable) - len(shown), "hash"))
        rep.section("Crackable hashes", lines)

    users = sorted({_account(d, u) for d, u in summary.unique_users})
    rep.section("Accounts", st.kv([
        ("Users", ", ".join(users) if st.verbose() or len(users) <= 10 else ", ".join(users[:10]) + st.dim(f", +{len(users) - 10} more")),
        ("Domains", ", ".join(sorted(summary.unique_domains))),
        ("Workstations", ", ".join(sorted(summary.unique_workstations))),
    ]))
    messages = sorted(set(summary.request_counts) | set(summary.response_counts))
    rep.section("Protocol", st.kv([
        ("Messages", ", ".join(f"{m} ({summary.request_counts.get(m, 0)} req / {summary.response_counts.get(m, 0)} resp)"
                               for m in messages)),
        counter_line("Services", summary.services, 6),
        counter_line("Status codes", summary.status_codes, 6),
    ]))

    rep.section("Conversations", st.table(
        ["Source", "Destination", "Packets", "First", "Last"],
        [[f"{c.src_ip}:{c.src_port}", f"{c.dst_ip}:{c.dst_port}", st.count(c.packets), st.ts(c.first_seen), st.ts(c.last_seen)]
         for c in sorted(summary.conversations, key=lambda c: c.packets, reverse=True)],
        align="llrll", max_rows=None, noun="conversation",
    ), detail=True)
    rep.section("Session records", st.table(
        ["Time", "Flow", "Type", "Account", "Version"],
        [[st.ts(s.ts), f"{s.src_ip}:{s.src_port} -> {s.dst_ip}:{s.dst_port}", s.message_type, _account(s.domain, s.username),
          s.version] for s in sorted(summary.sessions, key=lambda s: s.ts or 0.0)],
        max_rows=None, noun="record",
    ), detail=True)
    rep.section("Artifacts", st.table(["Artifact", "Description"], [[a.value, a.description] for a in summary.artifacts],
                                      max_rows=None), detail=True)
    hyp = [f"[{h.get('confidence', '?')}] {h.get('hypothesis', '-')} (evidence={h.get('evidence', '')})"
           for h in (getattr(summary, "threat_hypotheses", None) or [])]
    rep.section("Threat hypotheses", st.bullets(hyp, max_items=None), detail=True)
    rep.section("Benign context", st.bullets(getattr(summary, "benign_context", None) or [], max_items=None), detail=True)
    rep.section("Traffic", st.kv([
        ("Duration", f"{summary.duration:.2f}s"),
        ("Packets", f"{getattr(summary, 'total_packets', 0)} total · {getattr(summary, 'ntlm_packets', 0)} NTLM"),
        ("Sources", st.top(summary.src_counts, None)),
        ("Destinations", st.top(summary.dst_counts, None)),
    ]), detail=True)

    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic NTLM Security Checks", [
            ("ntlmv1_legacy_authentication", "NTLMv1 Legacy Authentication"),
            ("anonymous_or_null_session_attempts", "Anonymous/Null Session Attempts"),
            ("auth_failure_burst", "Authentication Failure Burst"),
            ("credential_reuse_spread", "Credential Reuse Spread"),
            ("cross_service_ntlm_usage", "Cross-Service NTLM Usage"),
            ("high_volume_ntlm_source", "High-Volume NTLM Source"),
            ("incomplete_handshake_patterns", "Incomplete Handshake Patterns"),
            ("public_endpoint_ntlm_activity", "Public Endpoint NTLM Activity"),
        ])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
