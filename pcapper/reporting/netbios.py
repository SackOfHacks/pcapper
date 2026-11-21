"""Rendered output for NetBIOS (NBNS, datagram/browser, NBSS): spoofing and
browser-takeover signals first, then the host inventory the protocol
discloses (names, roles, OS, domain controllers), NETLOGON account queries
and recon sources; service, endpoint and conversation statistics are -v."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from . import _style as st
from ._common import _render_deterministic_checks
from ._kv import counter_line

if TYPE_CHECKING:
    from ..netbios import NetbiosAnalysis


def _assessment(summary: "NetbiosAnalysis") -> tuple[object, str, int, list[str]]:
    """(severity, verdict, score, reasons) from the threat clusters."""
    ts = getattr(summary, "threat_summary", Counter()) or Counter()
    checks = getattr(summary, "deterministic_checks", {}) or {}

    def _ts(*names: str) -> int:
        return sum(int(ts.get(n, 0) or 0) for n in names)

    poisoning = _ts("NBNS Response Spoofing", "PDC Role Conflict")
    rogue = _ts("Rogue Master Browser Bid")
    # Takeover needs crafted evidence; election volume alone is two peers
    # legitimately contesting the master browser.
    takeover = _ts("Rogue Master Browser Bid", "Announced Role Inconsistency", "Browser Reset Request")
    churn = _ts("Browser Election Storm")
    cred = _ts("SMB Brute-Force Indicators", "Potential Exfiltration")
    recon = _ts("NBNS Name Scanning", "Host Probing", "Logon Mailslot Enumeration")
    public = 1 if checks.get("public_netbios_exposure") else 0
    periodic = _ts("Beaconing Pattern", "Broadcast/Name Storm")
    conflicts = int(getattr(summary, "name_conflicts", 0) or 0)
    score = poisoning * 4 + rogue * 3 + takeover + cred * 3 + recon + public * 2 + periodic + churn
    reasons = [text for hit, text in (
        (poisoning, f"NBNS/PDC identity spoofing or conflict ({poisoning}): on-path/poisoning risk (T1557)"),
        (rogue, "rogue master-browser bid (crafted election criteria): MITM of host discovery"),
        (_ts("Announced Role Inconsistency"), "inconsistent (crafted) browser role announcement"),
        (cred, f"credential/session abuse over NetBIOS ({cred}): brute force or bulk write"),
        (recon, f"NetBIOS name/host reconnaissance ({recon})"),
        (public, "legacy NetBIOS exposed on a public network path"),
        (periodic, f"periodic or broadcast-storm NetBIOS activity ({periodic})"),
        (churn, "browser election churn: contested master browser (benign contention or forced-election nuisance)"),
    ) if hit]
    if poisoning or rogue:
        return "high", "NetBIOS spoofing / poisoning (NBT-NS or browser takeover, T1557)", score, reasons
    if takeover:
        return "high", "browser takeover: crafted master-browser / role announcements (T1557)", score, reasons
    if cred:
        return "high", "credential / session abuse over NetBIOS/SMB", score, reasons
    if recon or public:
        return "medium", "NetBIOS reconnaissance or legacy exposure", score, reasons
    if periodic or conflicts or churn:
        return "low", "browser election churn, storm or name conflict to review", score, reasons
    return None, "baseline name service and browser traffic", score, reasons


def render_netbios_summary(summary: "NetbiosAnalysis") -> str:
    if not summary:
        return ""
    rep = st.Report("NetBIOS", summary.path)
    anomalies = list(summary.anomalies or [])
    findings = [st.finding({"severity": a.severity, "title": a.type, "details": a.details, "src": a.src_ip,
                            "dst": a.dst_ip, "ts": a.timestamp}) for a in anomalies]
    if not summary.total_packets and not st.material(findings):
        return rep.absent("NetBIOS traffic", summary.errors)
    severity, text, score, reasons = _assessment(summary)
    if findings and (severity is None or st.worst(findings) > st.sev_rank(severity)):
        severity = next(f.severity for f in findings if st.sev_rank(f.severity) == st.worst(findings))
    rep.headline(severity, st.join([st.plural(len(findings), "finding") if findings else "", text]), st.join([
        f"{st.count(summary.total_packets)} NetBIOS packets · {st.size(summary.total_bytes)}",
        st.duration(summary.duration) if summary.duration else "",
    ]))
    dcs = sorted(getattr(summary, "announced_dcs", set()) or set())
    masters = sorted((getattr(summary, "master_browsers", set()) or set()) - set(dcs))
    browser_hosts = getattr(summary, "browser_hosts", {}) or {}
    rep.scope(st.join([st.plural(len(summary.hosts), "host"), st.plural(len(summary.unique_names), "name"),
                       f"{summary.name_conflicts} name conflicts" if summary.name_conflicts else "",
                       f"{summary.browser_elections} browser elections" if summary.browser_elections else ""]))
    infra = [f"DC {ip}" + (f" ({browser_hosts[ip].name})" if browser_hosts.get(ip) and browser_hosts[ip].name else "")
             for ip in dcs] + [f"master browser {ip}" for ip in masters]
    if infra:
        rep.scope(st.join(infra[:8]))
    for reason in reasons:
        rep.scope(reason)
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    host_rows = []
    for ip, host in sorted(summary.hosts.items(), key=lambda kv: (not kv[1].is_domain_controller, not kv[1].is_master_browser, kv[0])):
        roles = ", ".join(r for r, on in (("DC", host.is_domain_controller), ("master browser", host.is_master_browser)) if on)
        names = ", ".join(f"{n.name.strip()}<{n.suffix:02X}> {n.type_str}" for n in host.names) or "-"
        host_rows.append([ip, names, host.mac or "-", st.caution(roles) if roles else "", host.group_name or "-"])
    rep.section("Hosts", st.table(["IP", "Names", "MAC", "Roles", "Group"], host_rows, widths=(None, 80), max_rows=15,
                                  noun="host"))
    rep.section("Browser announcements", st.table(
        ["Host", "IP", "OS", "Domain", "Roles", "Comment"],
        [[b.name or "-", ip, b.os_label, b.domain or "-", ", ".join(b.roles) or "-", b.comment or "-"]
         for ip, b in sorted(browser_hosts.items(), key=lambda kv: (not kv[1].is_domain_controller, kv[0]))],
        widths=(None, None, None, None, 40, 32), max_rows=15, noun="host",
    ) + st.kv([counter_line("Workgroups/domains", getattr(summary, "browser_domains", None), 6)]))
    seen: set = set()
    logon_rows = []
    for lr in getattr(summary, "logon_requests", None) or []:
        key = (lr.get("src_ip"), lr.get("op_name"), lr.get("computer"), lr.get("user"))
        if key in seen:
            continue
        seen.add(key)
        logon_rows.append([lr.get("src_ip", "-"), lr.get("mailslot", "-"), lr.get("op_name", "-"), lr.get("computer") or "-",
                           st.caution(str(lr["user"])) if lr.get("user") else "-"])
    rep.section("Logon queries", st.table(["Source", "Mailslot", "Operation", "Querying host", "Queried account"], logon_rows,
                                          max_rows=15, noun="query"))
    rep.section("Threat signals", st.kv([
        counter_line("Clusters", summary.threat_summary, 8),
        counter_line("Scanning", summary.scanning_sources, 6),
        counter_line("Probing", summary.probe_sources, 6),
        counter_line("Brute force", summary.brute_force_sources, 6),
        counter_line("Beaconing", summary.beacon_candidates, 4),
        ("Exfil candidates", st.top(summary.exfil_candidates, 4, fmt=lambda k, v: f"{k} ({st.size(v)})")),
    ]))
    rep.section("Identities", st.kv([
        counter_line("SMB users", summary.smb_users, 8),
        counter_line("SMB domains", summary.smb_domains, 6),
        counter_line("Names seen", summary.observed_users, 10),
    ]))
    # Repeated bids from one candidate collapse to one row with a count.
    elections: dict[tuple, list] = {}
    for e in getattr(summary, "election_events", None) or []:
        key = (e.get("src_ip", "-"), int(e.get("criteria", 0) or 0), e.get("server_name") or "-")
        uptime = float(e.get("uptime_s", 0.0) or 0.0)
        entry = elections.setdefault(key, [0, uptime, uptime])
        entry[0] += 1
        entry[1], entry[2] = min(entry[1], uptime), max(entry[2], uptime)
    rep.section("Elections", st.table(
        ["Source", "Candidate", "Criteria", "Uptime", "Bids"],
        [[src, name, f"0x{crit:08x}", st.duration(lo) if lo == hi else f"{st.duration(lo)} - {st.duration(hi)}", st.count(n)]
         for (src, crit, name), (n, lo, hi) in sorted(elections.items(), key=lambda kv: -kv[1][0])],
        align="lllrr", max_rows=st.TOP_ROWS, tail=st.TOP_ROWS, noun="candidate",
    ))

    # ---- reference (-v) --------------------------------------------------
    rep.section("Assessment", st.kv([("Score", str(score))]), detail=True)
    endpoints = Counter(summary.src_counts)
    endpoints.update(summary.dst_counts)
    rep.section("Endpoints", st.table(
        ["Endpoint", "Packets", "Sent", "Received"],
        [[ep, st.count(n), st.size(summary.endpoint_bytes_sent.get(ep, 0)), st.size(summary.endpoint_bytes_recv.get(ep, 0))]
         for ep, n in endpoints.most_common()], align="lrrr", max_rows=None,
    ) + st.kv([counter_line("Sources", summary.src_counts, None), counter_line("Destinations", summary.dst_counts, None),
               counter_line("SMB clients", summary.smb_clients, None), counter_line("SMB servers", summary.smb_servers, None)]),
        detail=True)
    suspicious = set(summary.suspicious_smb_commands or [])

    def _risk(cmd: str) -> str:
        if any(t in cmd for t in ("Write", "Set Info", "Ioctl")):
            return "high-risk"
        return "suspicious" if cmd in suspicious else "normal"

    rep.section("Services and commands", st.kv([
        counter_line("Protocols", summary.protocol_packets, None),
        counter_line("Services", summary.service_counts, None),
        counter_line("NBSS types", summary.nbss_message_types, None),
        counter_line("SMB versions", summary.smb_versions, None),
        counter_line("Browser commands", getattr(summary, "browser_command_counts", None), None),
        counter_line("Requests", summary.request_counts, None),
        counter_line("Response codes", summary.response_codes, None),
    ]) + st.table(["SMB command", "Count", "Risk"], [[c, st.count(n), _risk(c)] for c, n in summary.smb_commands.most_common()],
                  align="lrl", max_rows=None), detail=True)
    svc_rows = []
    for service, counter in sorted((summary.service_endpoints or {}).items(),
                                   key=lambda kv: int(summary.service_counts.get(kv[0], sum(kv[1].values()))), reverse=True):
        top_ep, top_n = counter.most_common(1)[0] if counter else ("-", 0)
        svc_rows.append([service, st.count(summary.service_counts.get(service, sum(counter.values()))), st.count(len(counter)),
                         top_ep, st.count(top_n), st.top(counter, None)])
    rep.section("Service flows", st.table(["Service", "Hits", "Flows", "Top flow", "Top hits", "All flows"], svc_rows,
                                          align="lrrlrl", max_rows=None), detail=True)
    rep.section("Conversations", st.table(
        ["Source", "Destination", "Proto", "Ports", "Packets", "Req", "Resp", "First", "Last"],
        [[c.src_ip, c.dst_ip, c.protocol, f"{c.src_port} -> {c.dst_port}", st.count(c.packets), c.requests, c.responses,
          st.ts(c.first_seen), st.ts(c.last_seen)] for c in summary.conversations],
        align="llllrrrll", max_rows=None, noun="conversation",
    ) + st.table(
        ["Session source", "Destination", "Ports", "Packets", "First", "Last"],
        [[s.src_ip, s.dst_ip, f"{s.src_port} -> {s.dst_port}", st.count(s.packets), st.ts(s.first_seen), st.ts(s.last_seen)]
         for s in summary.sessions], align="lllrll", max_rows=None, noun="session",
    ), detail=True)
    rep.section("Files", st.bullets([str(f) for f in summary.files_discovered or []], max_items=None), detail=True)
    rep.section("Plaintext", st.table(["String", "Count"], [[t, st.count(n)] for t, n in (summary.plaintext_observed or Counter()).most_common()],
                                      align="lr", max_rows=None), detail=True)
    rep.section("Artifacts", st.bullets([str(a) for a in summary.artifacts or []], max_items=None), detail=True)
    hyp = [f"[{str(h.get('confidence', '')).upper()}] {h.get('hypothesis', '')}" for h in (summary.threat_hypotheses or [])
           if isinstance(h, dict)]
    rep.section("Threat hypotheses", st.bullets(hyp, max_items=None), detail=True)
    rep.section("Benign context", st.bullets(summary.benign_context or [], max_items=None), detail=True)
    rep.section("Traffic", st.kv([("Duration", f"{summary.duration:.2f}s"), ("Packets", str(summary.total_packets)),
                                  ("Bytes", st.size(summary.total_bytes))]), detail=True)

    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic NetBIOS Security Checks", [
            ("nbns_spoofing_or_conflict", "NBNS Spoofing/Name Conflict"),
            ("nbns_scan_or_probe_fanout", "NBNS Scan/Probe Fan-out"),
            ("nbns_broadcast_storm", "NBNS Broadcast Storm"),
            ("netbios_beaconing_pattern", "NetBIOS Beaconing Pattern"),
            ("role_claim_anomaly", "Role-Claim Anomaly"),
            ("browser_election_or_takeover", "Browser Election / Master-Browser Takeover"),
            ("browser_role_spoofing_or_conflict", "Browser Role Spoofing / PDC Conflict"),
            ("logon_mailslot_enumeration", "NETLOGON/NTLOGON Enumeration"),
            ("smb_auth_abuse_over_netbios", "SMB Auth Abuse over NetBIOS"),
            ("smb_write_exfil_over_netbios", "SMB Write/Exfil over NetBIOS"),
            ("public_netbios_exposure", "Public NetBIOS Exposure"),
        ])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
