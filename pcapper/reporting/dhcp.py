"""Rendered output for DHCP: which server handed which client (MAC,
hostname, OS fingerprint) which address, the options each server pushes
(router, DNS, WPAD, PXE: the rogue-DHCP payload), and integrity problems
(competing servers, tampered options, conflicting leases); counters,
conversations and profiles are -v detail."""

from __future__ import annotations

from collections import Counter

from ..dhcp import DhcpSummary
from . import _style as st
from ._common import _redact_in_text, _render_deterministic_checks
from ._kv import counter_line, findings_for


def _assessment(summary: DhcpSummary) -> tuple[str, str, int, list[str]]:
    score = 0
    reasons: list[str] = []
    high = sum(1 for a in summary.anomalies if a.severity in {"HIGH", "CRITICAL"})
    for hit, weight, text in (
        (high, min(4, high), f"high-severity DHCP anomalies ({high})"),
        (len(summary.transaction_violations), 2, f"transaction integrity violations ({len(summary.transaction_violations)})"),
        (len(summary.policy_tampering), 2, f"DHCP option tampering/drift ({len(summary.policy_tampering)})"),
        (len(summary.lease_conflicts), 2, f"duplicate lease assignments ({len(summary.lease_conflicts)})"),
        (len(summary.relay_anomalies), 1, f"relay-agent anomalies ({len(summary.relay_anomalies)})"),
        (summary.attacks.get("Rogue DHCP Server", 0), 2, "competing/rogue DHCP server evidence"),
        (summary.attacks.get("DHCP Starvation", 0), 2, "DHCP starvation/exhaustion behavior"),
    ):
        if hit:
            score += weight
            reasons.append(text)
    if score >= 8:
        verdict, confidence = "YES - high-confidence DHCP abuse or policy hijack", "High"
    elif score >= 5:
        verdict, confidence = "LIKELY - significant suspicious DHCP activity", "Medium"
    elif score >= 2:
        verdict, confidence = "POSSIBLE - weak-to-moderate DHCP threat indicators", "Low"
    else:
        verdict, confidence = "NO STRONG SIGNAL from the current heuristics", "Low"
    return verdict, confidence, score, reasons


def _lease(seconds: object) -> str:
    try:
        value = float(seconds)
    except (TypeError, ValueError):
        return "-"
    return st.duration(value) if value else "-"


def render_dhcp_summary(summary: DhcpSummary, limit: int = 15, verbose: bool = False) -> str:
    rep = st.Report("DHCP", summary.path)
    findings = findings_for(summary, ot=False)
    if not summary.dhcp_packets and not st.material(findings):
        return rep.absent("DHCP traffic", summary.errors)
    severity, text = st.verdict(findings, high="DHCP abuse (rogue server, starvation, option tampering): investigate",
                                medium="DHCP activity to review")
    rep.headline(severity, text, st.join([
        f"{st.count(summary.dhcp_packets)} DHCP packets", st.duration(summary.duration) if summary.duration else "",
        counter_line("", summary.message_types, 6)[1],
    ]))
    rep.scope(st.join([st.plural(len(summary.client_details), "client"), st.plural(len(summary.server_details), "server"),
                       st.plural(len(summary.host_leases or []), "lease") if getattr(summary, "host_leases", None) else ""]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    profiles = list(summary.server_policy_profiles or [])

    def _v(item: dict, key: str) -> str:
        return _redact_in_text(str(item.get(key) or "-"))

    rep.section("Servers", st.table(
        ["Server", "Router", "DNS", "Domain", "WPAD", "Routes", "PXE"],
        [[p.get("server", "-"), _v(p, "router_value"), _v(p, "dns_value"), _v(p, "domain_value"), _v(p, "wpad_value"),
          _v(p, "routes_value"), _redact_in_text(str(p.get("bootfile_value") or p.get("tftp_value") or "-"))] for p in profiles],
        widths=(None, 24, 30, 24, 30, 24, 24), noun="server",
    ) or st.kv([counter_line("Servers", summary.server_details, 6), counter_line("Lease servers", summary.lease_servers, 6)]))
    leases = sorted(getattr(summary, "host_leases", None) or [], key=lambda h: h.lease_start or h.first_seen or 0.0)
    rep.section("Leases", st.table(
        ["Time", "Client MAC", "Hostname", "Address", "Server", "Lease"] + (["Ends (est.)", "Messages"] if st.verbose() else []),
        [[st.ts(h.lease_start or h.first_seen), h.client_mac,
          _redact_in_text(str(h.hostname or ", ".join(sorted((summary.client_hostnames_by_mac or {}).get(h.client_mac, []) or []))
                              or "-")), h.client_ip or "-",
          h.server or "-", _lease(h.lease_seconds)] + ([st.ts(h.lease_end_estimate), h.message_count] if st.verbose() else [])
         for h in leases],
        max_rows=12, noun="lease",
    ) if leases else st.table(
        ["Client MAC", "Address", "Server", "Req", "Offer", "Ack", "Nak", "First seen"],
        [[s.client_mac, s.client_ip or "-", s.server_ip or "-", s.requests, s.offers, s.acks, s.naks, st.ts(s.first_seen)]
         for s in summary.sessions], align="lllrrrrl", max_rows=12, noun="client",
    ))
    fingerprints = dict(getattr(summary, "os_fingerprints", None) or {})
    rep.section("Devices", st.table(
        ["Client MAC", "OS/device guess", "Hostname", "Vendor class"] + (["Option 55"] if st.verbose() else []),
        [[mac, (fp[1] if isinstance(fp, (list, tuple)) and len(fp) > 1 else "unknown"),
          ", ".join(sorted((summary.client_hostnames_by_mac or {}).get(mac, []) or [])) or "-",
          ", ".join(sorted((summary.vendor_classes_by_mac or {}).get(mac, []) or [])) or "-"]
         + ([fp[0] if isinstance(fp, (list, tuple)) else str(fp)] if st.verbose() else [])
         for mac, fp in fingerprints.items()],
        widths=(None, 40, 30, 40), max_rows=12, noun="device",
    ) or st.kv([counter_line("Hostnames", summary.hostnames, 8), counter_line("Vendor classes", summary.vendor_classes, 4)]))

    rep.section("Integrity", st.table(
        ["Type", "Server", "Client", "XID", "Flow", "Time"],
        [[v.get("type", "-"), v.get("server", "-"), v.get("client_mac", "-"), v.get("xid", "-"),
          st.flow(v.get("src", "-"), v.get("dst", "-")), st.ts(v.get("ts"))] for v in summary.transaction_violations],
        max_rows=10, noun="violation",
    ) + st.table(
        ["Server", "Option drift"],
        [[p.get("server", "-"), "; ".join(str(x) for x in (p.get("drift") or []))] for p in summary.policy_tampering],
        widths=(None, 100), max_rows=10, noun="server",
    ) + st.table(
        ["Address", "Clients", "Client MACs"],
        [[c.get("ip", "-"), c.get("count", "-"), ", ".join(str(x) for x in (c.get("clients") or []))] for c in summary.lease_conflicts],
        align="lrl", max_rows=10, noun="conflict",
    ) + st.table(
        ["Relay", "Servers", "Clients", "Top servers"],
        [[r.get("relay", "-"), r.get("server_count", "-"), r.get("client_count", "-"),
          ", ".join(str(x) for x in (r.get("servers") or []))] for r in summary.relay_anomalies],
        align="lrrl", max_rows=10, noun="relay",
    ))
    rep.section("Timeline", st.table(
        ["Time", "Event", "Detail", "Flow"],
        [[st.ts(t.get("ts")), t.get("event", "-"), _redact_in_text(str(t.get("detail", "-"))),
          st.flow(t.get("src", "-"), t.get("dst", "-"))] for t in summary.timeline],
        widths=(None, None, 90), max_rows=10, noun="event",
    ))

    # ---- reference (-v) --------------------------------------------------
    verdict, confidence, score, reasons = _assessment(summary)
    rep.section("Assessment", st.kv([("Verdict", verdict), ("Confidence", f"{confidence} (score={score})")])
                + st.bullets(reasons, max_items=None), detail=True)
    rep.section("Counters", st.kv([
        counter_line("Message types", summary.message_types, None),
        counter_line("Clients", summary.client_details, None),
        counter_line("Servers", summary.server_details, None),
        counter_line("Lease servers", summary.lease_servers, None),
        counter_line("Requested IPs", summary.requested_ips, None),
        counter_line("Offered IPs", summary.offered_ips, None),
        counter_line("Lease buckets", summary.lease_time_buckets, None),
        counter_line("Hostnames", summary.hostnames, None),
        counter_line("Domains", getattr(summary, "domains", None), None),
        counter_line("Vendor classes", summary.vendor_classes, None),
        counter_line("Client IDs", getattr(summary, "client_ids", None), None),
        counter_line("Relay agents", getattr(summary, "relay_agents", None), None),
        counter_line("Options", getattr(summary, "dhcp_option_counts", None), None),
        counter_line("Source IPs", summary.src_ips, None),
        counter_line("Destination IPs", summary.dst_ips, None),
        counter_line("Source MACs", getattr(summary, "src_macs", None), None),
        counter_line("Destination MACs", getattr(summary, "dst_macs", None), None),
        counter_line("Attacks", summary.attacks, None),
        counter_line("Threat clusters", summary.threat_summary, None),
        counter_line("Beacon candidates", summary.beacon_candidates, None),
        counter_line("Exfil candidates", summary.exfil_candidates, None),
        counter_line("Probe sources", summary.probe_sources, None),
        counter_line("Brute-force sources", summary.brute_force_sources, None),
    ]), detail=True)
    option_values = getattr(summary, "dhcp_option_values", None) or {}
    rep.section("Option values", st.table(
        ["Option", "Values"],
        [[k, st.top(v, None) if hasattr(v, "items") else ", ".join(str(x) for x in v)] for k, v in sorted(option_values.items(), key=lambda kv: str(kv[0]))],
        max_rows=None,
    ), detail=True)
    rep.section("Device fingerprints", st.table(
        ["Fingerprint", "Count", "Endpoints"],
        [[d, st.count(n), eps] for d, n, eps in _device_rows(summary)], max_rows=None,
    ), detail=True)
    rep.section("Client profiles", st.table(
        ["Client MAC", "Req", "Requested IPs", "XIDs", "Hostnames", "Client IDs", "Vendors"],
        [[p.get("client_mac", "-"), p.get("requests", "-"), p.get("requested_ip_count", "-"), p.get("xid_count", "-"),
          p.get("hostname_count", "-"), p.get("client_id_count", "-"), p.get("vendor_class_count", "-")]
         for p in summary.client_abuse_profiles], align="lrrrrrr", max_rows=None,
    ), detail=True)
    rep.section("Conversations", st.table(
        ["Source", "Destination", "Message", "Ports", "Packets", "First", "Last"],
        [[c.src_ip, c.dst_ip, c.message_type, f"{c.src_port} -> {c.dst_port}", st.count(c.packets), st.ts(c.first_seen),
          st.ts(c.last_seen)] for c in summary.conversations], align="llllrll", max_rows=None,
    ) + st.table(
        ["Client MAC", "Address", "Server", "Req", "Offer", "Ack", "Nak", "First", "Last"],
        [[s.client_mac, s.client_ip or "-", s.server_ip or "-", s.requests, s.offers, s.acks, s.naks, st.ts(s.first_seen),
          st.ts(s.last_seen)] for s in summary.sessions], align="lllrrrrll", max_rows=None,
    ), detail=True)
    rep.section("Risk factors", st.bullets([_redact_in_text(str(r)) for r in (getattr(summary, "risk_factors", None) or [])],
                                           max_items=None), detail=True)
    rep.section("False-positive context", st.bullets([_redact_in_text(str(b)) for b in summary.benign_context or []],
                                                     max_items=None), detail=True)
    rep.section("Artifacts", st.table(
        ["Kind", "Detail", "Flow", "Time"],
        [[a.kind, _redact_in_text(str(a.detail)), st.flow(a.src, a.dst), st.ts(a.ts)] for a in summary.artifacts],
        max_rows=None,
    ), detail=True)
    rep.section("Plaintext", st.table(["String", "Count"], [[t, st.count(n)] for t, n in summary.plaintext_observed.most_common()],
                                      align="lr", max_rows=None), detail=True)
    rep.section("Files", st.bullets([str(f) for f in summary.files_discovered or []], max_items=None), detail=True)
    rep.section("Traffic", st.kv([("Duration", f"{summary.duration:.2f}s"),
                                  ("Packets", f"{summary.total_packets} total · {summary.dhcp_packets} DHCP")]), detail=True)

    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic DHCP Security Checks", [
            ("transaction_integrity_violation", "Transaction Integrity Violation"),
            ("rogue_competing_server_evidence", "Rogue/Competing Server Evidence"),
            ("starvation_exhaustion_behavior", "Starvation/Exhaustion Behavior"),
            ("option_tampering_router_dns_routes_wpad_pxe", "Option Tampering (Router/DNS/Routes/WPAD/PXE)"),
            ("relay_abuse_option82", "Relay Abuse / Option 82 Anomaly"),
            ("lease_conflict_duplicate_assignment", "Lease Conflict / Duplicate Assignment"),
            ("beacon_periodic_dhcp", "Periodic DHCP Beacon Behavior"),
            ("likely_benign_failover_context", "Likely Benign Failover Context"),
        ])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()


def _device_rows(summary: DhcpSummary) -> list[tuple[str, int, str]]:
    counts: Counter[str] = Counter()
    endpoints: dict[str, Counter[str]] = {}
    for item in summary.artifacts:
        if str(getattr(item, "kind", "")) != "device":
            continue
        detail = str(getattr(item, "detail", "") or "")
        counts[detail] += 1
        endpoints.setdefault(detail, Counter())[st.flow(getattr(item, "src", "?"), getattr(item, "dst", "?"))] += 1
    return [(d, n, st.top(endpoints[d], 3)) for d, n in counts.most_common()]
