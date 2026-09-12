"""Rendered output for netbios analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from collections import Counter
from typing import TYPE_CHECKING
from ..coloring import (
    danger,
    header,
    highlight,
    muted,
    ok,
    warn,
)
from ..utils import (
    format_bytes_as_mb,
    format_ts,
)
if TYPE_CHECKING:
    from ..netbios import NetbiosAnalysis

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _counter_table,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
    _render_deterministic_checks,
    _truncate_text,
)


def render_netbios_summary(summary: "NetbiosAnalysis") -> str:
    if not summary:
        return ""

    lines = []
    lines.append(SECTION_BAR)
    lines.append(header(f"NETBIOS ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    ts = getattr(summary, "threat_summary", Counter()) or Counter()
    checks = getattr(summary, "deterministic_checks", {}) or {}

    def _ts(*names: str) -> int:
        return sum(int(ts.get(n, 0) or 0) for n in names)

    poisoning = _ts("NBNS Response Spoofing", "PDC Role Conflict")
    # "Takeover" requires CRAFTED evidence (a rogue bid with server-class criteria
    # + implausible uptime, an inconsistent role announcement, or a reset). Plain
    # election volume is NOT takeover: two peers legitimately contest the master
    # browser and produce many normal RequestElection frames.
    takeover = _ts(
        "Rogue Master Browser Bid",
        "Announced Role Inconsistency",
        "Browser Reset Request",
    )
    election_churn = _ts("Browser Election Storm")
    cred_exposure = _ts("SMB Brute-Force Indicators", "Potential Exfiltration")
    recon = _ts("NBNS Name Scanning", "Host Probing", "Logon Mailslot Enumeration")
    public_exposure = 1 if checks.get("public_netbios_exposure") else 0
    periodic = _ts("Beaconing Pattern", "Broadcast/Name Storm")
    name_conflicts = int(getattr(summary, "name_conflicts", 0) or 0)

    score = (
        poisoning * 4
        + _ts("Rogue Master Browser Bid") * 3
        + takeover * 1
        + cred_exposure * 3
        + recon * 1
        + public_exposure * 2
        + periodic
        + election_churn
    )
    verdict_reasons: list[str] = []
    if poisoning:
        verdict_reasons.append(
            f"NBNS/PDC identity spoofing or conflict ({poisoning}) — on-path/poisoning risk (T1557)"
        )
    if _ts("Rogue Master Browser Bid"):
        verdict_reasons.append(
            "Rogue master-browser bid (crafted election criteria) — MITM of host discovery"
        )
    if _ts("Announced Role Inconsistency"):
        verdict_reasons.append("Inconsistent (crafted) browser role announcement observed")
    if cred_exposure:
        verdict_reasons.append(
            f"Credential/session abuse over NetBIOS ({cred_exposure}) — brute-force or bulk write"
        )
    if recon:
        verdict_reasons.append(f"NetBIOS name/host reconnaissance ({recon})")
    if public_exposure:
        verdict_reasons.append("Legacy NetBIOS exposed on a public network path")
    if periodic:
        verdict_reasons.append(f"Periodic/broadcast-storm NetBIOS activity ({periodic})")
    if election_churn:
        verdict_reasons.append(
            "Browser election churn/instability — contested master browser (review; "
            "benign contention or forced-election nuisance)"
        )

    if poisoning or _ts("Rogue Master Browser Bid"):
        verdict = "SPOOFING / POISONING - NetBIOS identity abuse (LLMNR/NBT-NS or browser takeover, T1557)."
        vfn, conf = danger, "High"
    elif takeover:
        verdict = "BROWSER TAKEOVER - crafted master-browser / role announcements (T1557)."
        vfn, conf = danger, "Medium"
    elif cred_exposure:
        verdict = "CREDENTIAL / SESSION EXPOSURE - authentication abuse over NetBIOS/SMB."
        vfn, conf = danger, "High"
    elif recon or public_exposure:
        verdict = "RECONNAISSANCE / EXPOSURE - NetBIOS name enumeration or legacy exposure."
        vfn, conf = warn, "Medium"
    elif periodic or name_conflicts or election_churn:
        verdict = "SUSPICIOUS - browser election churn / storm / name-conflict to review."
        vfn, conf = warn, "Low"
    else:
        verdict = "BASELINE - normal NetBIOS name service / browser announcements; no attack signal."
        vfn, conf = ok, "Low"

    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    lines.append(vfn(verdict))
    lines.append(_format_kv("Confidence", f"{conf} (score={score})"))
    if verdict_reasons:
        lines.append(muted("Why:"))
        for reason in verdict_reasons[: _limit_value(8)]:
            lines.append(muted(f"- {reason}"))
    # Asset context (OT-aware): surface identified directory infrastructure.
    announced_dcs = getattr(summary, "announced_dcs", set()) or set()
    master_browsers = getattr(summary, "master_browsers", set()) or set()
    if announced_dcs or master_browsers:
        bhosts = getattr(summary, "browser_hosts", {}) or {}
        infra = []
        for ip in sorted(announced_dcs):
            nm = bhosts.get(ip).name if bhosts.get(ip) else ""
            infra.append(f"DC {ip}{f' ({nm})' if nm else ''}")
        for ip in sorted(master_browsers - announced_dcs):
            infra.append(f"Master Browser {ip}")
        lines.append(
            highlight(f"Directory/infra assets (from browser announcements): {', '.join(infra[:8])}")
        )

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors[: _limit_value(25)]:
            lines.append(danger(f"- {err}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Overall Traffic Statistics"))
    lines.append(_format_kv("Scan Duration", f"{summary.duration:.2f}s"))
    lines.append(_format_kv("Total NetBIOS Packets", str(summary.total_packets)))
    lines.append(
        _format_kv("Total NetBIOS Bytes", format_bytes_as_mb(summary.total_bytes))
    )
    lines.append(_format_kv("Unique Hosts", str(len(summary.hosts))))
    lines.append(_format_kv("Unique Sources", str(len(summary.src_counts))))
    lines.append(_format_kv("Unique Destinations", str(len(summary.dst_counts))))
    lines.append(_format_kv("Unique NetBIOS Names", str(len(summary.unique_names))))
    lines.append(_format_kv("Name Conflicts", str(summary.name_conflicts)))
    lines.append(_format_kv("Browser Elections", str(summary.browser_elections)))

    # Browser (MS-BRWS) passive inventory: announced hosts, OS, roles, comments.
    browser_hosts = getattr(summary, "browser_hosts", {}) or {}
    if browser_hosts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Announced Hosts & Roles (Browser / MS-BRWS)"))
        rows = [["Host", "IP", "OS", "Domain", "Roles", "Comment"]]
        for ip, bh in sorted(
            browser_hosts.items(),
            key=lambda kv: (not kv[1].is_domain_controller, kv[0]),
        )[: _limit_value(20)]:
            role_txt = ", ".join(bh.roles) if bh.roles else "-"
            row = [
                bh.name or "-",
                ip,
                bh.os_label,
                bh.domain or "-",
                role_txt,
                (bh.comment[:32] if bh.comment else "-"),
            ]
            if bh.is_domain_controller or bh.is_master_browser:
                row[4] = danger(role_txt)
            rows.append(row)
        lines.append(_format_table(rows))
        muted_note = []
        if getattr(summary, "browser_domains", None):
            doms = ", ".join(
                f"{d}({c})" for d, c in summary.browser_domains.most_common(_limit_value(6))
            )
            muted_note.append(f"Workgroups/Domains announced: {doms}")
        if muted_note:
            for note in muted_note:
                lines.append(muted(note))

    # Browser protocol command breakdown + elections.
    bcmds = getattr(summary, "browser_command_counts", None)
    election_events = getattr(summary, "election_events", []) or []
    if bcmds or election_events:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Browser Protocol Activity"))
        if bcmds:
            lines.append(_counter_table(bcmds, "Browser Command", limit=_limit_value(12)))
        if election_events:
            rows = [["Election Src", "Criteria", "Uptime(s)", "Candidate"]]
            for ev in election_events[: _limit_value(10)]:
                rows.append(
                    [
                        str(ev.get("src_ip", "-")),
                        f"0x{int(ev.get('criteria', 0) or 0):08x}",
                        f"{float(ev.get('uptime_s', 0.0) or 0.0):.0f}",
                        str(ev.get("server_name", "") or "-"),
                    ]
                )
            lines.append(_format_table(rows))

    # NETLOGON / NTLOGON logon activity (DC discovery + queried accounts).
    logon_requests = getattr(summary, "logon_requests", []) or []
    if logon_requests:
        lines.append(SUBSECTION_BAR)
        lines.append(header("NETLOGON / Logon Mailslot Activity"))
        rows = [["Src", "Mailslot", "Operation", "Querying Host", "Queried Account"]]
        seen_l: set = set()
        for lr in logon_requests:
            key = (
                str(lr.get("src_ip", "-")),
                str(lr.get("op_name", "-")),
                str(lr.get("computer", "")),
                str(lr.get("user", "")),
            )
            if key in seen_l:
                continue
            seen_l.add(key)
            rows.append(
                [
                    str(lr.get("src_ip", "-")),
                    str(lr.get("mailslot", "-")),
                    str(lr.get("op_name", "-")),
                    str(lr.get("computer", "") or "-"),
                    (danger(str(lr.get("user", ""))) if lr.get("user") else "-"),
                ]
            )
            if len(rows) > _limit_value(15):
                break
        lines.append(_format_table(rows))

    if summary.protocol_packets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Protocol Statistics"))
        rows = [["Protocol", "Packets"]]
        for proto, count in summary.protocol_packets.most_common(_limit_value(10)):
            rows.append([proto, str(count)])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Endpoint Statistics"))
    if not summary.src_counts and not summary.dst_counts:
        lines.append(muted("No endpoint statistics available."))
    else:
        rows = [["Endpoint", "Packets", "Bytes Sent", "Bytes Recv"]]
        endpoints = Counter(summary.src_counts)
        endpoints.update(summary.dst_counts)
        for endpoint, count in endpoints.most_common(_limit_value(15)):
            rows.append(
                [
                    endpoint,
                    str(count),
                    format_bytes_as_mb(summary.endpoint_bytes_sent.get(endpoint, 0)),
                    format_bytes_as_mb(summary.endpoint_bytes_recv.get(endpoint, 0)),
                ]
            )
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Top NetBIOS Sources & Destinations"))
    if summary.src_counts:
        rows = [["Source", "Packets"]]
        for ip, count in summary.src_counts.most_common(_limit_value(12)):
            rows.append([ip, str(count)])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No source statistics available."))
    if summary.dst_counts:
        rows = [["Destination", "Packets"]]
        for ip, count in summary.dst_counts.most_common(_limit_value(12)):
            rows.append([ip, str(count)])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No destination statistics available."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Client/Server Statistics"))
    if not summary.smb_clients and not summary.smb_servers:
        lines.append(muted("No SMB-over-NetBIOS client/server stats detected."))
    else:
        rows = [["Top Clients", "Sessions", "Top Servers", "Sessions"]]
        clients = summary.smb_clients.most_common(_limit_value(10))
        servers = summary.smb_servers.most_common(_limit_value(10))
        max_len = max(len(clients), len(servers))
        for idx in range(max_len):
            c_ip, c_cnt = clients[idx] if idx < len(clients) else ("-", 0)
            s_ip, s_cnt = servers[idx] if idx < len(servers) else ("-", 0)
            rows.append(
                [
                    c_ip,
                    str(c_cnt) if c_ip != "-" else "-",
                    s_ip,
                    str(s_cnt) if s_ip != "-" else "-",
                ]
            )
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Observed NETBIOS Functions / Services / Commands"))
    if summary.service_counts:
        lines.append(_counter_table(summary.service_counts, "Service", limit=_limit_value(15)))
    if summary.nbss_message_types:
        lines.append(_counter_table(summary.nbss_message_types, "NBSS Type", limit=_limit_value(15)))
    if summary.smb_commands:
        rows = [["SMB Command", "Count", "Risk"]]
        for cmd, count in summary.smb_commands.most_common(_limit_value(20)):
            risk = "Normal"
            if cmd in summary.suspicious_smb_commands:
                risk = "Suspicious"
            if any(token in cmd for token in ("Write", "Set Info", "Ioctl")):
                risk = "High-Risk"
            rows.append([cmd, str(count), risk])
        lines.append(_format_table(rows))
        if summary.suspicious_smb_commands:
            lines.append(warn("Suspicious/High-risk SMB commands observed."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("NETBIOS Services Statistics (Endpoints Involved)"))
    if not summary.service_endpoints:
        lines.append(muted("No service endpoint mapping available."))
    else:
        # Consolidated per-service view for the full capture.
        overview_rows = [
            [
                "Service",
                "Total Hits",
                "Unique Endpoint Flows",
                "Top Endpoint Flow",
                "Top Flow Hits",
            ]
        ]
        for service, counter in sorted(
            summary.service_endpoints.items(),
            key=lambda item: int(
                summary.service_counts.get(item[0], sum(item[1].values()))
            ),
            reverse=True,
        ):
            top_endpoint, top_count = ("-", 0)
            if counter:
                top_endpoint, top_count = counter.most_common(1)[0]
            overview_rows.append(
                [
                    service,
                    str(
                        int(summary.service_counts.get(service, sum(counter.values())))
                    ),
                    str(len(counter)),
                    str(top_endpoint),
                    str(int(top_count)),
                ]
            )
        lines.append(header("Consolidated Services Overview (Entire PCAP)"))
        lines.append(_format_table(overview_rows))

        lines.append(header("Per-Service Endpoint Flows"))
        rows = [["Service", "Top Endpoints"]]
        for service, counter in summary.service_endpoints.items():
            endpoints = ", ".join(
                f"{ep} ({cnt})" for ep, cnt in counter.most_common(_limit_value(5))
            )
            rows.append([service, endpoints or "-"])
        lines.append(_format_table(rows))

    if summary.smb_versions:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Client/Server Versions"))
        lines.append(_counter_table(summary.smb_versions, "Version", limit=_limit_value(10)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("NetBIOS Hosts & Names"))
    if not summary.hosts:
        lines.append(muted("No NetBIOS hosts identified."))
    else:
        for ip, host in sorted(summary.hosts.items()):
            roles = []
            if host.is_domain_controller:
                roles.append("DC")
            if host.is_master_browser:
                roles.append("Master Browser")
            role_str = f" [{', '.join(roles)}]" if roles else ""
            lines.append(highlight(f"Host: {ip}{role_str}"))
            if host.mac:
                lines.append(muted(f"  MAC: {host.mac}"))
            if not host.names:
                lines.append(muted("  (No advertised names seen)"))
            else:
                for item in host.names[: _limit_value(20)]:
                    lines.append(
                        f"  - {item.name:<16} <0x{item.suffix:02X}> : {item.type_str}"
                    )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Observed NetBIOS Names"))
    if not summary.observed_users:
        lines.append(muted("No observed NetBIOS names."))
    else:
        lines.append(_counter_table(summary.observed_users, "Name", limit=_limit_value(20)))

    if summary.response_codes or summary.request_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Request / Response Code Summary"))
        if summary.request_counts:
            lines.append(_counter_table(summary.request_counts, "Request Type", limit=_limit_value(15)))
        if summary.response_codes:
            rows = [["Response Code", "Count", "Risk"]]
            for code, count in summary.response_codes.most_common(_limit_value(15)):
                risk = "High" if code in {"Refused", "ServFail", "FormErr"} else "Info"
                rows.append([code, str(count), risk])
            lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Conversations & Sessions"))
    if summary.conversations:
        rows = [
            ["Src", "Dst", "Proto", "Ports", "Pkts", "Req", "Resp", "First", "Last"]
        ]
        for convo in summary.conversations[: _limit_value(12)]:
            rows.append(
                [
                    convo.src_ip,
                    convo.dst_ip,
                    convo.protocol,
                    f"{convo.src_port}->{convo.dst_port}",
                    str(convo.packets),
                    str(convo.requests),
                    str(convo.responses),
                    format_ts(convo.first_seen),
                    format_ts(convo.last_seen),
                ]
            )
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No NetBIOS conversations summarized."))

    if summary.sessions:
        rows = [["Src", "Dst", "Ports", "Pkts", "First", "Last"]]
        for sess in summary.sessions[: _limit_value(12)]:
            rows.append(
                [
                    sess.src_ip,
                    sess.dst_ip,
                    f"{sess.src_port}->{sess.dst_port}",
                    str(sess.packets),
                    format_ts(sess.first_seen),
                    format_ts(sess.last_seen),
                ]
            )
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Threat Hunting Detections"))
    if summary.threat_summary:
        lines.append(_counter_table(summary.threat_summary, "Threat", limit=_limit_value(20)))
    else:
        lines.append(ok("No high-confidence threat clusters detected."))

    if summary.scanning_sources:
        rows = [["Scan Source", "Indicator Count"]]
        for src, count in summary.scanning_sources.most_common(_limit_value(10)):
            rows.append([src, str(count)])
        lines.append(_format_table(rows))
    if summary.probe_sources:
        rows = [["Probe Source", "Indicator Count"]]
        for src, count in summary.probe_sources.most_common(_limit_value(10)):
            rows.append([src, str(count)])
        lines.append(_format_table(rows))
    if summary.brute_force_sources:
        rows = [["Bruteforce Source", "Attempts"]]
        for src, count in summary.brute_force_sources.most_common(_limit_value(10)):
            rows.append([src, str(count)])
        lines.append(_format_table(rows))
    if summary.beacon_candidates:
        rows = [["Beacon Flow", "Intervals"]]
        for flow, count in summary.beacon_candidates.most_common(_limit_value(10)):
            rows.append([flow, str(count)])
        lines.append(_format_table(rows))
    if summary.exfil_candidates:
        rows = [["Exfil Candidate", "Bytes"]]
        for src, count in summary.exfil_candidates.most_common(_limit_value(10)):
            rows.append([src, format_bytes_as_mb(count)])
        lines.append(_format_table(rows))

    if summary.smb_users or summary.smb_domains:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Identities (SMB/NTLM)"))
        if summary.smb_users:
            lines.append(_counter_table(summary.smb_users, "User", limit=_limit_value(12)))
        if summary.smb_domains:
            lines.append(_counter_table(summary.smb_domains, "Domain", limit=_limit_value(12)))

    if summary.files_discovered:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files Discovered"))
        for item in summary.files_discovered[: _limit_value(30)]:
            lines.append(f"  - {item}")

    if summary.plaintext_observed:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Plaintext Artifacts"))
        rows = [["String", "Count"]]
        for text, count in summary.plaintext_observed.most_common(_limit_value(15)):
            rows.append([_truncate_text(text, 88), str(count)])
        lines.append(_format_table(rows))

    if summary.anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Attack Signals"))
        for item in summary.anomalies[: _limit_value(40)]:
            sev_color = danger if item.severity in ("HIGH", "CRITICAL") else warn
            lines.append(sev_color(f"[{item.severity}] {item.type}: {item.details}"))
            lines.append(
                muted(f"  {item.src_ip} -> {item.dst_ip} @ {format_ts(item.timestamp)}")
            )

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Additional Artifacts"))
        for value in summary.artifacts[: _limit_value(40)]:
            lines.append(f"  - {_truncate_text(value, 120)}")

    hypotheses = getattr(summary, "threat_hypotheses", None) or []
    benign_context = getattr(summary, "benign_context", None) or []
    if hypotheses:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Threat Hypotheses"))
        for hyp in hypotheses[: _limit_value(8)]:
            if isinstance(hyp, dict):
                conf = str(hyp.get("confidence", "")).upper()
                text = str(hyp.get("hypothesis", ""))
                lines.append(warn(f"[{conf}] {text}"))
    if benign_context:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Benign / Asset Context"))
        for note in benign_context[: _limit_value(8)]:
            lines.append(muted(f"- {note}"))

    lines.append(SECTION_BAR)
    _render_deterministic_checks(
        lines, summary, "Deterministic NetBIOS Security Checks", [
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
        ]
    )
    return _finalize_output(lines)
