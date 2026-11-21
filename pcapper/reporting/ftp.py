"""Rendered output for FTP: cleartext logins, the files moved (STOR is
upload/exfiltration, RETR download) and the server's identity; the scored
assessment, profiles and clusters are -v detail."""

from __future__ import annotations

from ..ftp import FtpSummary
from ..utils import format_duration, format_ts
from . import _style as st
from ._common import _redact_in_text, _redact_secret, _render_deterministic_checks
from ._kv import counter_line, findings_for


def _assessment(summary: FtpSummary) -> tuple[str, str, list[str], int]:
    """The weighted score the report used to lead with (kept as -v context)."""
    checks = getattr(summary, "deterministic_checks", {}) or {}
    detections = list(getattr(summary, "detections", []) or [])
    score = 0
    reasons: list[str] = []
    weighted = {
        "cleartext_credential_exposure": 3, "anonymous_or_guest_abuse": 2, "bruteforce_or_spray": 3,
        "active_passive_mode_abuse": 2, "data_channel_integrity": 3, "high_risk_file_staging": 3,
        "ftps_downgrade_or_weak_protection": 1, "ftp_exfiltration_signal": 4,
    }
    for key, weight in weighted.items():
        n = len([v for v in (checks.get(key, []) if isinstance(checks, dict) else []) or [] if str(v).strip()])
        if n:
            score += min(4, weight + min(2, n - 1))
            reasons.append(f"{key.replace('_', ' ')} evidence ({n})")
    high = sum(1 for d in detections if str(d.get("severity", "")).lower() in {"high", "critical"})
    medium = sum(1 for d in detections if str(d.get("severity", "")).lower() == "medium")
    if high:
        score += min(3, high)
        reasons.append(f"high-severity FTP detections ({high})")
    if medium >= 2:
        score += 1
        reasons.append(f"multiple medium-severity FTP detections ({medium})")
    if score >= 8:
        verdict, confidence = "YES - high-confidence malicious or compromised FTP activity", "High"
    elif score >= 5:
        verdict, confidence = "LIKELY - suspicious FTP activity with compromise indicators", "Medium"
    elif score >= 2:
        verdict, confidence = "POSSIBLE - risky FTP behavior; corroboration recommended", "Low"
    else:
        verdict, confidence = "NO STRONG SIGNAL from the current heuristics", "Low"
    return verdict, confidence, reasons, score


def _records(items: list, keys: tuple[str, ...] = ()) -> list[str]:
    """Analysis dicts as one line each: ``key=value`` pairs (lists joined)."""
    out = []
    for item in items:
        if not isinstance(item, dict):
            out.append(_redact_in_text(str(item)))
            continue
        pairs = []
        for k, v in item.items():
            if keys and k not in keys:
                continue
            text = ", ".join(str(x) for x in v) if isinstance(v, (list, tuple, set)) else str(v)
            pairs.append(f"{k}={_redact_in_text(text)}")
        out.append("  ".join(pairs))
    return out


def render_ftp_summary(summary: FtpSummary, limit: int = 12, verbose: bool = False) -> str:
    rep = st.Report("FTP", summary.path)
    findings = findings_for(summary, ot=False)
    if not summary.ftp_packets and not st.material(findings):
        return rep.absent("FTP traffic", summary.errors)
    severity, text = st.verdict(findings, high="high-severity FTP activity (credentials, exfiltration): investigate",
                                medium="FTP activity to review")
    rep.headline(severity, text, st.join([
        f"{st.count(summary.ftp_packets)} FTP packets · {st.size(summary.ftp_bytes)}",
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
        st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else "",
    ]))
    ports = ", ".join(str(p) for p, _ in summary.server_ports.most_common(4))
    rep.scope(st.join([f"{st.plural(summary.unique_clients, 'client')} -> {st.plural(summary.unique_servers, 'server')}",
                       f"port {ports}" if ports else ""]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    rep.section("Credentials", st.table(
        ["Time", "Flow", "User", "Password"],
        [[st.ts(h.ts), st.flow(h.client_ip, h.server_ip), h.username or "-", _redact_secret(h.password)]
         for h in sorted(summary.credential_hits, key=lambda h: h.ts or 0.0)],
        max_rows=10, noun="login",
    ))

    def _direction(text: str) -> str:
        low = str(text).lower()
        return st.caution(text) if low.startswith(("up", "stor", "out")) else str(text)

    rep.section("Transfers", st.table(
        ["Time", "Direction", "File", "Size", "Client", "Server", "Data channel"],
        [[st.ts(t.first_seen), _direction(t.direction), t.filename or "-", st.size(t.bytes), t.client_ip, t.server_ip,
          f"{t.data_host}:{t.data_port}" if t.data_host else "-"] for t in sorted(summary.transfers, key=lambda t: t.first_seen or 0.0)],
        align="lllrlll", widths=(None, None, 60), max_rows=10, noun="transfer",
    ))
    rep.section("Server", st.kv([
        counter_line("Banners", summary.banner_counts, 3),
        counter_line("Software", summary.server_software, 4),
        counter_line("SYST", summary.system_types, 3),
        counter_line("Users", summary.user_counts, 8),
    ]))
    rep.section("Commands", st.kv([
        counter_line("Commands", summary.command_counts, 10),
        counter_line("Suspicious", summary.suspicious_commands, 6),
        counter_line("Replies", summary.response_counts, 8),
    ]))
    rep.section("Endpoints", st.kv([counter_line("Clients", summary.client_counts, 6),
                                    counter_line("Servers", summary.server_counts, 6)]))

    verdict, confidence, reasons, score = _assessment(summary)
    rep.section("Assessment", st.kv([("Verdict", verdict), ("Confidence", f"{confidence} (score={score})")])
                + st.bullets([_redact_in_text(r) for r in reasons], max_items=None), detail=True)
    rep.section("Attack paths", st.table(
        ["Host", "Confidence", "Targets", "Steps"],
        [[p.get("host", "-"), p.get("confidence", "-"), ", ".join(str(v) for v in p.get("targets", []) or []),
          "; ".join(str(v) for v in p.get("steps", []) or [])] for p in (summary.host_attack_paths or [])],
        max_rows=None,
    ), detail=True)
    rep.section("Incident clusters", st.table(
        ["Cluster", "Host", "Signals", "Targets", "Confidence"],
        [[c.get("cluster", "-"), c.get("host", "-"), len(c.get("indicators", []) or []), c.get("target_count", "-"),
          c.get("confidence", "-")] for c in (summary.incident_clusters or [])],
        max_rows=None,
    ), detail=True)
    rep.section("Campaign indicators", st.table(
        ["Indicator", "Value", "Hosts"],
        [[c.get("indicator", "-"), _redact_in_text(str(c.get("value", "-"))), ", ".join(str(h) for h in c.get("hosts", []) or [])]
         for c in (summary.campaign_indicators or [])], max_rows=None,
    ), detail=True)
    for title, field_name in (("Sequence violations", "sequence_violations"), ("Control/data integrity", "control_data_integrity"),
                              ("Auth abuse profiles", "auth_abuse_profiles"), ("Exfil profiles", "exfil_profiles"),
                              ("Lateral clusters", "lateral_clusters")):
        rep.section(title, st.bullets(_records(list(getattr(summary, field_name, None) or [])), max_items=None), detail=True)
    rep.section("FEAT", st.kv([counter_line("Features", summary.feature_counts, None)]), detail=True)
    rep.section("MAC addresses", st.table(["Host", "MACs"], [[h, ", ".join(sorted(m))] for h, m in sorted(summary.mac_addresses.items())],
                                          max_rows=None), detail=True)
    rep.section("False-positive context", st.bullets([_redact_in_text(str(n)) for n in (summary.benign_context or [])],
                                                     max_items=None), detail=True)
    rep.section("Traffic", st.kv([
        ("Packets", f"{summary.total_packets} scanned · {summary.ftp_packets} FTP"),
        ("Bytes", f"{st.size(summary.total_bytes)} total · {st.size(summary.ftp_bytes)} FTP"),
        ("Start / end", f"{format_ts(summary.first_seen)} / {format_ts(summary.last_seen)}"),
        ("Duration", format_duration(summary.duration_seconds)),
        counter_line("Ports", summary.server_ports, None),
    ]), detail=True)

    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic FTP Security Checks", [
            ("cleartext_credential_exposure", "Cleartext Credential Exposure"),
            ("anonymous_or_guest_abuse", "Anonymous/Guest Abuse"),
            ("bruteforce_or_spray", "Bruteforce/Spray Behavior"),
            ("data_channel_integrity", "Data Channel Integrity"),
            ("ftp_exfiltration_signal", "FTP Exfiltration Signal"),
        ])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
