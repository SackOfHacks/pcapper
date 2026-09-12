"""Rendered output for dhcp analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from collections import Counter, defaultdict
from ..coloring import (
    danger,
    header,
    label,
    muted,
    ok,
    warn,
)
from ..dhcp import DhcpSummary
from ..utils import (
    format_ts,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _apply_verbose_limit,
    _counter_table,
    _finalize_output,
    _format_kv,
    _format_table,
    _highlight_public_ips,
    _limit_value,
    _redact_in_text,
    _truncate_text,
)


def render_dhcp_summary(
    summary: DhcpSummary, limit: int = 15, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit) or limit

    def _truncate_text_local(value: str, max_len: int = 80) -> str:
        return _truncate_text(str(value), max_len)

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"DHCP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors[: _limit_value(25)]:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Scan Duration", f"{summary.duration:.2f}s"))
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("DHCP Packets", str(summary.dhcp_packets)))
    lines.append(_format_kv("Conversations", str(len(summary.conversations))))
    lines.append(_format_kv("Sessions", str(len(summary.sessions))))

    def _dhcp_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        high_anomalies = sum(
            1 for item in summary.anomalies if item.severity in {"HIGH", "CRITICAL"}
        )
        if high_anomalies:
            score += min(4, high_anomalies)
            reasons.append(f"High-severity DHCP anomalies observed ({high_anomalies})")
        if summary.transaction_violations:
            score += 2
            reasons.append(
                f"Transaction integrity violations observed ({len(summary.transaction_violations)})"
            )
        if summary.policy_tampering:
            score += 2
            reasons.append(
                f"DHCP policy tampering/drift observed ({len(summary.policy_tampering)})"
            )
        if summary.lease_conflicts:
            score += 2
            reasons.append(
                f"Duplicate lease assignment conflicts observed ({len(summary.lease_conflicts)})"
            )
        if summary.relay_anomalies:
            score += 1
            reasons.append(
                f"Relay-agent anomalies observed ({len(summary.relay_anomalies)})"
            )
        if summary.attacks.get("Rogue DHCP Server", 0):
            score += 2
            reasons.append("Competing/rogue DHCP server evidence observed")
        if summary.attacks.get("DHCP Starvation", 0):
            score += 2
            reasons.append("DHCP starvation/exhaustion behavior observed")

        if score >= 8:
            verdict = (
                "YES - high-confidence DHCP abuse or policy-hijack activity is present."
            )
            confidence = "High"
        elif score >= 5:
            verdict = "LIKELY - significant suspicious DHCP activity is present."
            confidence = "Medium"
        elif score >= 2:
            verdict = "POSSIBLE - weak-to-moderate DHCP threat indicators are present."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing high-risk DHCP attack pattern from current heuristics."
            confidence = "Low"

        if not reasons:
            reasons.append("No high-confidence DHCP heuristic crossed threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _dhcp_verdict()
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", f"{confidence} (score={verdict_score})"))
    lines.append(muted("Why confidence:"))
    for reason in verdict_reasons[: _limit_value(8)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    # Add concrete context for immediate triage.
    if summary.server_details:
        lines.append(muted("Where:"))
        lines.append(muted("- Top DHCP servers"))
        for server, count in summary.server_details.most_common(_limit_value(8)):
            lines.append(
                muted(f"- {_highlight_public_ips(str(server))}: {int(count)} packets")
            )
    if summary.client_details:
        lines.append(muted("Who:"))
        lines.append(muted("- Top DHCP clients"))
        for client, count in summary.client_details.most_common(_limit_value(8)):
            lines.append(muted(f"- {client}: {int(count)} packets"))
    if summary.attacks:
        lines.append(muted("What:"))
        lines.append(muted("- Attack category hits"))
        for attack, count in summary.attacks.most_common(_limit_value(8)):
            lines.append(muted(f"- {_redact_in_text(str(attack))}: {int(count)}"))
    if getattr(summary, "transaction_violations", None):
        violations = list(summary.transaction_violations or [])
        if violations:
            lines.append(muted("When:"))
            lines.append(muted("- Transaction violations"))
            for item in violations[: _limit_value(6)]:
                lines.append(
                    muted(
                        f"- {item.get('type', '-')} xid={item.get('xid', '-')} "
                        f"server={_highlight_public_ips(str(item.get('server', '-')))} "
                        f"client={item.get('client_mac', '-')} at {format_ts(item.get('ts'))}"
                    )
                )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic DHCP Security Checks"))
    checks = getattr(summary, "deterministic_checks", {}) or {}
    check_labels = [
        ("transaction_integrity_violation", "Transaction Integrity Violation"),
        ("rogue_competing_server_evidence", "Rogue/Competing Server Evidence"),
        ("starvation_exhaustion_behavior", "Starvation/Exhaustion Behavior"),
        (
            "option_tampering_router_dns_routes_wpad_pxe",
            "Option Tampering (Router/DNS/Routes/WPAD/PXE)",
        ),
        ("relay_abuse_option82", "Relay Abuse / Option 82 Anomaly"),
        (
            "lease_conflict_duplicate_assignment",
            "Lease Conflict / Duplicate Assignment",
        ),
        ("beacon_periodic_dhcp", "Periodic DHCP Beacon Behavior"),
        ("likely_benign_failover_context", "Likely Benign Failover Context"),
    ]

    for key, label_text in check_labels:
        evidence_items = checks.get(key, []) if isinstance(checks, dict) else []
        evidence_items = [str(v) for v in (evidence_items or []) if str(v).strip()]
        lines.append(label(label_text))
        if evidence_items:
            if key == "likely_benign_failover_context":
                lines.append(
                    ok(
                        f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"
                    )
                )
            else:
                lines.append(
                    warn(
                        f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"
                    )
                )
            for item in evidence_items[: _limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))
        else:
            lines.append(
                ok(
                    f"No, there is no strong evidence for {label_text.lower()} in this capture."
                )
            )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Message Type Statistics"))
    if not summary.message_types:
        lines.append(muted("No DHCP message types observed."))
    else:
        lines.append(_counter_table(summary.message_types, "Type", limit=limit))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Client/Server Details"))
    if summary.client_details:
        rows = [["Client MAC", "Packets"]]
        for client, count in summary.client_details.most_common(limit):
            rows.append([client, str(count)])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No client details observed."))

    if summary.server_details:
        rows = [["Server", "Packets"]]
        for server, count in summary.server_details.most_common(limit):
            rows.append([server, str(count)])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No server details observed."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Lease and Option Intelligence"))
    if summary.lease_servers:
        lines.append(_counter_table(summary.lease_servers, "Lease Server", limit=limit))
    if summary.requested_ips:
        lines.append(_counter_table(summary.requested_ips, "Requested IP", limit=limit))
    if summary.offered_ips:
        lines.append(_counter_table(summary.offered_ips, "Offered/Assigned IP", limit=limit))
    if summary.lease_time_buckets:
        lines.append(_counter_table(summary.lease_time_buckets, "Lease Bucket", limit=limit))
    if summary.hostnames:
        lines.append(_counter_table(summary.hostnames, "Hostname", limit=limit))
    if summary.vendor_classes:
        rows = [["Vendor Class", "Count"]]
        for value, count in summary.vendor_classes.most_common(limit):
            rows.append([_truncate_text_local(value, 72), str(count)])
        lines.append(_format_table(rows))

    os_fingerprints = getattr(summary, "os_fingerprints", None)
    if os_fingerprints:
        lines.append(SUBSECTION_BAR)
        lines.append(header("DHCP OS/Device Fingerprints (option 55)"))
        rows = [["Client MAC", "OS/Device guess", "Fingerprint (opt-55)"]]
        for mac, value in list(os_fingerprints.items())[: _limit_value(25)]:
            try:
                fp, guess = value
            except Exception:
                fp, guess = str(value), "unknown"
            rows.append([mac, guess, _truncate_text_local(fp, 48)])
        lines.append(_format_table(rows))

    device_hits = [
        item for item in summary.artifacts if str(getattr(item, "kind", "")) == "device"
    ]
    if device_hits:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Device Fingerprints"))
        device_counts: Counter[str] = Counter()
        device_endpoints: dict[str, Counter[str]] = defaultdict(Counter)
        for item in device_hits:
            detail = str(getattr(item, "detail", "") or "")
            device_counts[detail] += 1
            src = str(getattr(item, "src", "?"))
            dst = str(getattr(item, "dst", "?"))
            device_endpoints[detail][f"{src} -> {dst}"] += 1
        rows = [["Fingerprint", "Count", "Top Endpoints"]]
        for detail, count in device_counts.most_common(limit):
            top_eps = ", ".join(
                f"{ep} ({cnt})"
                for ep, cnt in device_endpoints[detail].most_common(_limit_value(3))
            )
            rows.append([_truncate_text_local(detail, 90), str(count), top_eps or "-"])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Endpoint Statistics"))
    if summary.src_ips:
        rows = [["Source IP", "Packets"]]
        for item, count in summary.src_ips.most_common(limit):
            rows.append([item, str(count)])
        lines.append(_format_table(rows))
    if summary.dst_ips:
        rows = [["Destination IP", "Packets"]]
        for item, count in summary.dst_ips.most_common(limit):
            rows.append([item, str(count)])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Hunt Detections"))
    if not summary.threat_summary and not summary.anomalies:
        lines.append(ok("No high-confidence DHCP threat clusters detected."))
    else:
        if summary.threat_summary:
            lines.append(_counter_table(summary.threat_summary, "Threat", limit=limit))

        if summary.beacon_candidates:
            rows = [["Beacon Candidate", "Intervals"]]
            for endpoint, count in summary.beacon_candidates.most_common(limit):
                rows.append([endpoint, str(count)])
            lines.append(_format_table(rows))

        if summary.exfil_candidates:
            rows = [["Exfil Candidate", "Signals"]]
            for endpoint, count in summary.exfil_candidates.most_common(limit):
                rows.append([endpoint, str(count)])
            lines.append(_format_table(rows))

        if summary.probe_sources:
            lines.append(_counter_table(summary.probe_sources, "Probe Source", limit=limit))

        if summary.brute_force_sources:
            lines.append(_counter_table(summary.brute_force_sources, "Brute-Force Source", limit=limit))

        for item in summary.anomalies[:limit]:
            sev = danger if item.severity in {"HIGH", "CRITICAL"} else warn
            lines.append(sev(f"[{item.severity}] {item.title}: {item.description}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Conversations and Sessions"))
    if summary.conversations:
        rows = [["Src", "Dst", "Msg", "Ports", "Packets", "First", "Last"]]
        for item in summary.conversations[:limit]:
            rows.append(
                [
                    item.src_ip,
                    item.dst_ip,
                    item.message_type,
                    f"{item.src_port}->{item.dst_port}",
                    str(item.packets),
                    format_ts(item.first_seen),
                    format_ts(item.last_seen),
                ]
            )
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No DHCP conversations identified."))

    if summary.sessions:
        rows = [
            [
                "Client MAC",
                "Client IP",
                "Server",
                "Req",
                "Offer",
                "Ack",
                "Nak",
                "First",
                "Last",
            ]
        ]
        for item in summary.sessions[:limit]:
            rows.append(
                [
                    item.client_mac,
                    item.client_ip,
                    item.server_ip,
                    str(item.requests),
                    str(item.offers),
                    str(item.acks),
                    str(item.naks),
                    format_ts(item.first_seen),
                    format_ts(item.last_seen),
                ]
            )
        lines.append(_format_table(rows))

    if getattr(summary, "server_policy_profiles", None):
        if summary.server_policy_profiles:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Server Policy Profiles"))
            rows = [["Server", "Router", "DNS", "Domain", "WPAD", "Routes", "PXE"]]
            for item in summary.server_policy_profiles[:limit]:
                pxe_value = str(
                    item.get("bootfile_value", "") or item.get("tftp_value", "") or "-"
                )
                rows.append(
                    [
                        str(item.get("server", "-")),
                        _truncate_text_local(str(item.get("router_value", "-")), 22),
                        _truncate_text_local(str(item.get("dns_value", "-")), 22),
                        _truncate_text_local(str(item.get("domain_value", "-")), 18),
                        _truncate_text_local(str(item.get("wpad_value", "-")), 16),
                        _truncate_text_local(str(item.get("routes_value", "-")), 18),
                        _truncate_text_local(pxe_value, 18),
                    ]
                )
            lines.append(_format_table(rows))

    if getattr(summary, "client_abuse_profiles", None):
        if summary.client_abuse_profiles:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Client Abuse Profiles"))
            rows = [
                [
                    "Client MAC",
                    "Req",
                    "Requested IPs",
                    "XIDs",
                    "Hostnames",
                    "Client IDs",
                    "Vendors",
                ]
            ]
            for item in summary.client_abuse_profiles[:limit]:
                rows.append(
                    [
                        str(item.get("client_mac", "-")),
                        str(item.get("requests", "-")),
                        str(item.get("requested_ip_count", "-")),
                        str(item.get("xid_count", "-")),
                        str(item.get("hostname_count", "-")),
                        str(item.get("client_id_count", "-")),
                        str(item.get("vendor_class_count", "-")),
                    ]
                )
            lines.append(_format_table(rows))

    if getattr(summary, "policy_tampering", None):
        if summary.policy_tampering:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Option Policy Drift/Tampering"))
            rows = [["Server", "Signals"]]
            for item in summary.policy_tampering[:limit]:
                drift = item.get("drift", [])
                drift_text = "; ".join(
                    str(v) for v in (drift[:3] if isinstance(drift, list) else [drift])
                )
                rows.append(
                    [
                        str(item.get("server", "-")),
                        _truncate_text_local(drift_text or "-", 92),
                    ]
                )
            lines.append(_format_table(rows))

    if getattr(summary, "transaction_violations", None):
        if summary.transaction_violations:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Transaction Integrity Violations"))
            rows = [["Type", "Server", "Client", "XID", "Flow", "Time"]]
            for item in summary.transaction_violations[:limit]:
                rows.append(
                    [
                        str(item.get("type", "-")),
                        str(item.get("server", "-")),
                        str(item.get("client_mac", "-")),
                        str(item.get("xid", "-")),
                        f"{item.get('src', '-')}->{item.get('dst', '-')}",
                        format_ts(item.get("ts")),
                    ]
                )
            lines.append(_format_table(rows))

    if getattr(summary, "lease_conflicts", None):
        if summary.lease_conflicts:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Lease Conflict View"))
            rows = [["IP", "Client Count", "Clients"]]
            for item in summary.lease_conflicts[:limit]:
                clients = item.get("clients", [])
                client_text = ", ".join(
                    str(v)
                    for v in (clients[:4] if isinstance(clients, list) else [clients])
                )
                rows.append(
                    [
                        str(item.get("ip", "-")),
                        str(item.get("count", "-")),
                        client_text,
                    ]
                )
            lines.append(_format_table(rows))

    if getattr(summary, "relay_anomalies", None):
        if summary.relay_anomalies:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Relay Abuse Indicators"))
            rows = [["Relay", "Servers", "Clients", "Top Servers"]]
            for item in summary.relay_anomalies[:limit]:
                servers = item.get("servers", [])
                top_servers = ", ".join(
                    str(v)
                    for v in (servers[:3] if isinstance(servers, list) else [servers])
                )
                rows.append(
                    [
                        str(item.get("relay", "-")),
                        str(item.get("server_count", "-")),
                        str(item.get("client_count", "-")),
                        top_servers,
                    ]
                )
            lines.append(_format_table(rows))

    if getattr(summary, "timeline", None):
        if summary.timeline:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Attack Chain Timeline"))
            rows = [["Time", "Event", "Detail", "Flow"]]
            for item in summary.timeline[:limit]:
                rows.append(
                    [
                        format_ts(item.get("ts")),
                        str(item.get("event", "-")),
                        _truncate_text_local(
                            _redact_in_text(str(item.get("detail", "-"))), 96
                        ),
                        f"{item.get('src', '-')}->{item.get('dst', '-')}",
                    ]
                )
            lines.append(_format_table(rows))

    if getattr(summary, "benign_context", None):
        if summary.benign_context:
            lines.append(SUBSECTION_BAR)
            lines.append(header("False-Positive Context"))
            for item in summary.benign_context[: _limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(str(item))}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Artifacts"))
    if summary.artifacts:
        rows = [["Kind", "Detail", "Src", "Dst", "TS"]]
        for item in summary.artifacts[:limit]:
            rows.append(
                [
                    item.kind,
                    _truncate_text_local(item.detail, 72),
                    item.src,
                    item.dst,
                    format_ts(item.ts),
                ]
            )
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No DHCP artifacts recorded."))

    if summary.plaintext_observed:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Plaintext"))
        rows = [["String", "Count"]]
        for item, count in summary.plaintext_observed.most_common(limit):
            rows.append([_truncate_text_local(item, 96), str(count)])
        lines.append(_format_table(rows))

    if summary.files_discovered:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files Discovered"))
        for item in summary.files_discovered[:limit]:
            lines.append(f"  - {item}")

    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)
