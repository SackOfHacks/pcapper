"""Rendered output for protocols analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    danger,
    header,
    muted,
    ok,
    warn,
)
from ..protocols import ProtocolSummary
from ..utils import (
    format_bytes_as_mb,
    format_duration,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _finalize_output,
    _format_kv,
    _format_table,
)


# Cleartext / insecure protocols that are forensically notable on the wire
# (credentials or sensitive data exposed, or commonly abused for spoofing/C2).
_INSECURE_WIRE_PROTOCOLS = {
    "Telnet": "cleartext remote admin (credentials in the clear) — T1040",
    "FTP": "cleartext file transfer / credentials — T1040",
    "FTP-Data": "cleartext file transfer payloads — T1040",
    "TFTP": "no-auth file transfer (config/firmware exfil) — T1040",
    "HTTP": "cleartext web (credentials/cookies/data exposed) — T1040",
    "HTTP-Alt": "cleartext web (alt port) — T1040",
    "HTTP-Proxy": "cleartext web proxy — T1040",
    "POP3": "cleartext mail retrieval / credentials — T1040",
    "IMAP": "cleartext mail access / credentials — T1040",
    "SMTP": "cleartext mail (may carry AUTH LOGIN/PLAIN) — T1040",
    "SNMP": "SNMP v1/v2c community strings in cleartext — T1040",
    "LDAP": "cleartext directory queries / simple-bind credentials — T1040",
    "Syslog": "cleartext log data (UDP, spoofable) — T1040",
    "NetBIOS": "legacy name service — poisoning/relay abuse — T1557",
    "mDNS": "multicast name service — spoofing/recon — T1557",
}


def _protocols_mitre_techniques(summary: ProtocolSummary) -> list[str]:
    """Map observed protocol anomalies to ATT&CK technique IDs."""
    tids: list[str] = []

    def _add(tid: str) -> None:
        if tid not in tids:
            tids.append(tid)

    type_map = {
        "Port Scan": "T1046 Network Service Discovery",
        "TCP Null Scan": "T1046 Network Service Discovery",
        "TCP FIN Scan": "T1046 Network Service Discovery",
        "TCP Xmas Scan": "T1046 Network Service Discovery",
        "ARP Spoofing": "T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning",
        "Gratuitous ARP": "T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning",
        "Cleartext Creds": "T1040 Network Sniffing",
        "Credential Leakage": "T1040 Network Sniffing",
        "Basic Auth": "T1040 Network Sniffing",
        "Cleartext Auth": "T1040 Network Sniffing",
        "Broadcast Storm": "T1498 Network Denial of Service",
        "TCP Reset Flood": "T1498 Network Denial of Service",
        "Large ICMP Payloads": "T1572 Protocol Tunneling",
        "IP Fragmentation": "T1599 Network Boundary Bridging / evasion",
    }
    for anom in getattr(summary, "anomalies", []) or []:
        tid = type_map.get(str(getattr(anom, "type", "")))
        if tid:
            _add(tid)
    return tids


def render_protocols_summary(summary: ProtocolSummary, verbose: bool = False) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"PROTOCOL & CONVERSATION ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    verdict = str(getattr(summary, "analyst_verdict", "") or "")
    confidence = str(getattr(summary, "analyst_confidence", "") or "").upper()
    reasons = [str(v) for v in list(getattr(summary, "analyst_reasons", []) or [])]
    if verdict:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Analyst Verdict"))
        if confidence:
            lines.append(_format_kv("Verdict", f"{verdict} (confidence: {confidence})"))
        else:
            lines.append(_format_kv("Verdict", verdict))
        for reason in reasons:
            lines.append(muted(f"- {reason}"))
        tids = _protocols_mitre_techniques(summary)
        if tids:
            lines.append(muted("  ATT&CK: " + ", ".join(tids)))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("Duration", format_duration(summary.duration)))

    # 1. Top Protocols
    lines.append(SUBSECTION_BAR)
    lines.append(header("Top Protocols"))
    rows = [["Protocol", "Packets", "% traffic"]]
    for name, count in summary.top_protocols:
        pct = (count / summary.total_packets * 100) if summary.total_packets else 0
        rows.append([name, str(count), f"{pct:.1f}%"])
    lines.append(_format_table(rows))

    if summary.port_protocols:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Port-Based Protocols (Service Heuristics)"))
        rows = [["Protocol", "Packets", "% traffic"]]
        for name, count in summary.port_protocols:
            pct = (count / summary.total_packets * 100) if summary.total_packets else 0
            rows.append([name, str(count), f"{pct:.1f}%"])
        lines.append(_format_table(rows))

    if summary.ethertype_protocols:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Ethertype Protocols (L2)"))
        rows = [["Protocol", "Packets", "% traffic"]]
        for name, count in summary.ethertype_protocols:
            pct = (count / summary.total_packets * 100) if summary.total_packets else 0
            rows.append([name, str(count), f"{pct:.1f}%"])
        lines.append(_format_table(rows))

    # Insecure / cleartext protocols on the wire — core triage: what sensitive
    # traffic is exposed and what's commonly abused for spoofing/relay.
    insecure_seen: dict[str, int] = {}
    for name, count in list(summary.port_protocols) + list(summary.top_protocols):
        if name in _INSECURE_WIRE_PROTOCOLS:
            insecure_seen[name] = max(insecure_seen.get(name, 0), int(count))
    if insecure_seen:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Insecure / Cleartext Protocols Observed"))
        rows = [["Protocol", "Packets", "Risk / ATT&CK"]]
        for name in sorted(insecure_seen, key=lambda n: insecure_seen[n], reverse=True):
            rows.append(
                [name, str(insecure_seen[name]), _INSECURE_WIRE_PROTOCOLS[name]]
            )
        lines.append(_format_table(rows))

    checks = dict(getattr(summary, "deterministic_checks", {}) or {})
    if checks:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Deterministic Protocol Security Checks"))
        check_labels = {
            "protocol_identity_mismatch": "Protocol identity mismatch",
            "anomalous_protocol_sequence": "Anomalous protocol sequence",
            "cross_protocol_corroboration": "Cross-protocol corroboration",
            "evidence_provenance": "Evidence provenance",
        }
        for key, label_text in check_labels.items():
            values = [str(v) for v in list(checks.get(key, []) or [])]
            if values:
                lines.append(warn(f"[!] {label_text}: {len(values)}"))
                for item in values:
                    lines.append(muted(f"  - {item}"))
            else:
                lines.append(ok(f"[ ] {label_text}: none"))


    corroborated_findings = list(getattr(summary, "corroborated_findings", []) or [])
    if corroborated_findings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Corroborated Findings"))
        rows = [["Host", "Score", "Confidence", "Reasons"]]
        for finding in corroborated_findings:
            if not isinstance(finding, dict):
                continue
            rows.append(
                [
                    str(finding.get("host", "-")),
                    str(finding.get("score", 0)),
                    str(finding.get("confidence", "-")),
                    ", ".join(str(v) for v in list(finding.get("reasons", []) or []))
                    or "-",
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    sequence_profiles = list(getattr(summary, "sequence_profiles", []) or [])
    if sequence_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Protocol Sequence Integrity"))
        rows = [["Entity", "Sequence", "Evidence", "Confidence"]]
        for profile in sequence_profiles:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("entity", "-")),
                    " -> ".join(str(v) for v in list(profile.get("sequence", []) or []))
                    or "-",
                    str(profile.get("evidence_count", 0)),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    zone_profiles = list(getattr(summary, "zone_protocol_profiles", []) or [])
    if zone_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Zone Posture (East-West / North-South)"))
        rows = [["Src", "Dst", "Proto", "Zone", "Packets", "Confidence"]]
        for profile in zone_profiles:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("src", "-")),
                    str(profile.get("dst", "-")),
                    str(profile.get("protocol", "-")),
                    str(profile.get("zone_pair", "-")),
                    str(profile.get("packets", 0)),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    baseline_profiles = list(getattr(summary, "baseline_drift_profiles", []) or [])
    if baseline_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Baseline Drift"))
        rows = [["Protocol", "Baseline", "Current %", "Status"]]
        for profile in baseline_profiles:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("protocol", "-")),
                    str(profile.get("baseline_prevalence", "-")),
                    str(profile.get("current_prevalence_pct", "-")),
                    str(profile.get("status", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    tunneling_profiles = list(getattr(summary, "tunneling_profiles", []) or [])
    if tunneling_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Encapsulation/Tunneling Suspicion"))
        rows = [["Src", "Dst", "Proto", "Avg Payload", "Packets", "Confidence"]]
        for profile in tunneling_profiles:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("src", "-")),
                    str(profile.get("dst", "-")),
                    str(profile.get("protocol", "-")),
                    str(profile.get("avg_payload", "-")),
                    str(profile.get("packets", 0)),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    beacon_profiles = list(getattr(summary, "beacon_profiles", []) or [])
    if beacon_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Protocol Cadence Anomalies"))
        rows = [["Src", "Dst", "Proto", "Packets", "Duration", "PPS"]]
        for profile in beacon_profiles:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("src", "-")),
                    str(profile.get("dst", "-")),
                    str(profile.get("protocol", "-")),
                    str(profile.get("packets", 0)),
                    str(profile.get("duration_s", "-")),
                    str(profile.get("pps", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    role_profiles = list(getattr(summary, "role_inversion_profiles", []) or [])
    if role_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Role Drift by Protocol"))
        rows = [["Host", "Protocol", "Protocol Count", "Zone", "Confidence"]]
        for profile in role_profiles:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("host", "-")),
                    str(profile.get("protocol", "-")),
                    str(profile.get("protocol_count", 0)),
                    str(profile.get("zone", "-")),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    false_positive_context = [
        str(v)
        for v in list(getattr(summary, "false_positive_context", []) or [])
        if str(v).strip()
    ]
    if false_positive_context:
        lines.append(SUBSECTION_BAR)
        lines.append(header("False-Positive Context"))
        for item in false_positive_context:
            lines.append(muted(f"- {item}"))

    # 2. Hierarchy
    lines.append(SUBSECTION_BAR)
    lines.append(header("Protocol Hierarchy"))

    def _clean_proto_name(name: str) -> str:
        # 1. Scapy "Layer in Layer" simplification
        if " in ICMP" in name:
            name = name.replace(" in ICMP", " (quoted)")

        # 2. Shorten verbose IPv6/ICMPv6 names
        mappings = [
            (
                "ICMPv6 Neighbor Discovery - Neighbor Solicitation",
                "ICMPv6 Neighbor Sol.",
            ),
            (
                "ICMPv6 Neighbor Discovery - Neighbor Advertisement",
                "ICMPv6 Neighbor Adv.",
            ),
            ("ICMPv6 Neighbor Discovery - Router Solicitation", "ICMPv6 Router Sol."),
            ("ICMPv6 Neighbor Discovery - Router Advertisement", "ICMPv6 Router Adv."),
            (
                "ICMPv6 Neighbor Discovery Option - Scapy Unimplemented",
                "ICMPv6 Option (Unknown)",
            ),
            ("ICMPv6 Neighbor Discovery Option", "ICMPv6 Option"),
            ("IPv6 Extension Header - Hop-by-Hop Options Header", "IPv6 Hop-by-Hop"),
            ("IPv6 Extension Header", "IPv6 Ext"),
            ("MLDv2 - Multicast Listener Report", "MLDv2 Report"),
        ]

        for old, new in mappings:
            if old in name:
                name = name.replace(old, new)
        return name

    def render_node(node, depth=0):
        res = []
        indent = "  " * depth

        # Display:  |- HTTP (50 pkts, 10.2%)
        tree_char = "|- " if depth > 0 else ""

        clean_name = _clean_proto_name(node.name)
        name_display = f"{indent}{tree_char}{clean_name}"
        stats_display = f"{node.packets} pkts, {format_bytes_as_mb(node.bytes)}"

        # Dynamic padding calc could be better but fixed width for now
        res.append(f"{name_display:<50} {stats_display}")

        # Sort sub-protocols by packet count for better visibility
        sorted_subs = sorted(
            node.sub_protocols.values(), key=lambda x: x.packets, reverse=True
        )

        for sub in sorted_subs:
            res.extend(render_node(sub, depth + 1))
        return res

    hierarchy_lines = render_node(summary.hierarchy)
    # Remove Root if it's just a wrapper
    if len(summary.hierarchy.sub_protocols) > 0:
        hierarchy_lines = []
        # Sort root children too
        sorted_root_subs = sorted(
            summary.hierarchy.sub_protocols.values(),
            key=lambda x: x.packets,
            reverse=True,
        )
        for sub in sorted_root_subs:
            hierarchy_lines.extend(render_node(sub, 0))

    lines.extend(hierarchy_lines)

    # 3. Anomalies / Threats
    if summary.anomalies:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Potential Risks"))
        if verbose:
            for a in summary.anomalies:
                sev_color = danger if a.severity in ("HIGH", "CRITICAL") else warn
                lines.append(sev_color(f"[{a.severity}] {a.type}: {a.description}"))
                if a.src or a.dst:
                    lines.append(muted(f"  src: {str(a.src)} -> dst: {str(a.dst)}"))
        else:
            lines.append(_format_kv("Total Anomalies", str(len(summary.anomalies))))
            severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            grouped: dict[tuple[str, str, str], dict[str, object]] = {}
            for a in summary.anomalies:
                key = (a.severity, a.type, a.description)
                entry = grouped.setdefault(key, {"count": 0, "examples": []})
                entry["count"] = int(entry["count"]) + 1
                if (a.src or a.dst) and len(entry["examples"]) < 3:
                    example = f"{a.src or '-'} -> {a.dst or '-'}"
                    if example not in entry["examples"]:
                        entry["examples"].append(example)

            grouped_items = sorted(
                grouped.items(),
                key=lambda item: (
                    severity_rank.get(item[0][0], 9),
                    -int(item[1]["count"]),
                    item[0][1],
                ),
            )
            limit = len(grouped_items)
            for (sev, a_type, desc), data in grouped_items[:limit]:
                sev_color = (
                    danger
                    if sev in ("HIGH", "CRITICAL")
                    else warn
                    if sev == "MEDIUM"
                    else muted
                )
                lines.append(sev_color(f"[{sev}] {a_type}: {desc} (x{data['count']})"))
                examples = data.get("examples", [])
                if examples:
                    for ex in examples:
                        lines.append(muted(f"  example: {ex}"))
    else:
        lines.append(SUBSECTION_BAR)
        lines.append(ok("No clear anomalies detected."))

    # 4. Conversations (Top 10 by bytes)
    lines.append(SUBSECTION_BAR)
    lines.append(header("Top Conversations (by volume)"))

    sorted_convs = sorted(summary.conversations, key=lambda c: c.bytes, reverse=True)

    rows = [["Src", "Dst", "Proto", "Packets", "Bytes", "Duration", "Ports"]]
    for c in sorted_convs:
        # Sort ports by value for consistent display
        ports_list = sorted(list(c.ports))
        ports_str = ",".join(map(str, ports_list))

        dur = format_duration(c.end_ts - c.start_ts)
        rows.append(
            [
                c.src,
                c.dst,
                c.protocol,
                str(c.packets),
                format_bytes_as_mb(c.bytes),
                dur,
                ports_str,
            ]
        )
    lines.append(_format_table(rows))

    if verbose:
        # 5. Top Endpoints
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Endpoints"))
        sorted_eps = sorted(
            summary.endpoints, key=lambda e: e.bytes_sent + e.bytes_recv, reverse=True
        )
        rows = [["Address", "Sent", "Recv", "Total Bytes", "Protocols"]]
        for e in sorted_eps:
            protos = ",".join(sorted(str(p) for p in list(e.protocols)))
            rows.append(
                [
                    e.address,
                    str(e.packets_sent),
                    str(e.packets_recv),
                    format_bytes_as_mb(e.bytes_sent + e.bytes_recv),
                    protos,
                ]
            )
        lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)
