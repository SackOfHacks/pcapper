"""Rendered output for ips analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..utils import is_public_ip as _is_public_ip
from collections import Counter
from ..coloring import (
    danger,
    header,
    muted,
    ok,
    warn,
)
from ..ips import IpSummary
from ..utils import (
    format_bytes_as_mb,
    format_duration,
    format_ts,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _apply_verbose_limit,
    _filtered_detections,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
    _short_browser_role,
    _truncate_text,
)


def render_ips_summary(
    summary: IpSummary, limit: int = 12, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit)
    concise_mode = not verbose
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"IP INTELLIGENCE & CONVERSATIONS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(_format_kv("Unique IPs", str(summary.unique_ips)))
    lines.append(_format_kv("Unique Sources", str(summary.unique_sources)))
    lines.append(_format_kv("Unique Destinations", str(summary.unique_destinations)))
    lines.append(
        _format_kv("IPv4 / IPv6", f"{summary.ipv4_count} / {summary.ipv6_count}")
    )
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))
    lines.append(_format_kv("TLS ClientHello", str(summary.tls_client_hellos)))

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
        for reason in reasons[: _limit_value(8)]:
            lines.append(muted(f"- {reason}"))

    checks = dict(getattr(summary, "deterministic_checks", {}) or {})
    if checks:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Deterministic IPS Security Checks"))
        check_labels = {
            "indicator_quality_gate": "Indicator quality gate",
            "boundary_cross_zone_contact": "Boundary cross-zone contact",
            "corroborated_multi_signal_hit": "Corroborated multi-signal hit",
            "intent_heuristics": "Intent heuristics",
            "evidence_provenance": "Evidence provenance",
        }
        for key, label_text in check_labels.items():
            values = [str(v) for v in list(checks.get(key, []) or [])]
            if values:
                lines.append(warn(f"[!] {label_text}: {len(values)}"))
                for item in values[: _limit_value(8)]:
                    lines.append(muted(f"  - {item}"))
            else:
                lines.append(ok(f"[ ] {label_text}: none"))


    priority_asset_profiles = list(
        getattr(summary, "priority_asset_profiles", []) or []
    )
    if priority_asset_profiles and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Priority Asset Impact"))
        rows = [["IP", "Score", "Peers", "Ports", "Packets Sent", "Confidence"]]
        for item in priority_asset_profiles[:limit]:
            if not isinstance(item, dict):
                continue
            rows.append(
                [
                    str(item.get("ip", "-")),
                    str(item.get("score", "-")),
                    str(item.get("peers", "-")),
                    str(item.get("ports", "-")),
                    str(item.get("packets_sent", "-")),
                    str(item.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    exposure_profiles = list(getattr(summary, "exposure_profiles", []) or [])
    if exposure_profiles and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Exposure Posture"))
        rows = [
            ["Src", "Dst", "Protocol", "Direction", "Packets", "Bytes", "Confidence"]
        ]
        for item in exposure_profiles[:limit]:
            if not isinstance(item, dict):
                continue
            rows.append(
                [
                    str(item.get("src", "-")),
                    str(item.get("dst", "-")),
                    str(item.get("protocol", "-")),
                    str(item.get("direction", "-")),
                    str(item.get("packets", "-")),
                    str(item.get("bytes", "-")),
                    str(item.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    corroborated_findings = list(getattr(summary, "corroborated_findings", []) or [])
    if corroborated_findings and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Corroborated Findings"))
        rows = [["IP", "Score", "Confidence", "Reasons"]]
        for item in corroborated_findings[:limit]:
            if not isinstance(item, dict):
                continue
            reasons_text = "; ".join(
                str(v) for v in list(item.get("reasons", []) or [])[:3]
            )
            rows.append(
                [
                    str(item.get("ip", "-")),
                    str(item.get("score", "-")),
                    str(item.get("confidence", "-")),
                    reasons_text or "-",
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    infrastructure_clusters = list(
        getattr(summary, "infrastructure_clusters", []) or []
    )
    if infrastructure_clusters and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Infrastructure Clusters"))
        rows = [["Cluster", "IP Count", "IPs", "Confidence"]]
        for item in infrastructure_clusters[:limit]:
            if not isinstance(item, dict):
                continue
            ips = ",".join(
                str(v) for v in list(item.get("ips", []) or [])[: _limit_value(5)]
            )
            rows.append(
                [
                    str(item.get("cluster", "-")),
                    str(item.get("ip_count", "-")),
                    ips or "-",
                    str(item.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    intent_profiles = list(getattr(summary, "intent_profiles", []) or [])
    if intent_profiles and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Intent Heuristics"))
        rows = [["Src", "Dst", "Protocol", "Ports", "Intent", "Confidence"]]
        for item in intent_profiles[:limit]:
            if not isinstance(item, dict):
                continue
            ports = ",".join(
                str(v) for v in list(item.get("ports", []) or [])[: _limit_value(6)]
            )
            rows.append(
                [
                    str(item.get("src", "-")),
                    str(item.get("dst", "-")),
                    str(item.get("protocol", "-")),
                    ports or "-",
                    str(item.get("intent", "-")),
                    str(item.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    if verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("IP Protocol Utilization"))
        rows = [["Protocol", "Packets", "% traffic"]]
        for name, count in summary.protocol_counts.most_common(limit):
            pct = (count / summary.total_packets * 100) if summary.total_packets else 0
            rows.append([name, str(count), f"{pct:.1f}%"])
        lines.append(_format_table(rows))

    if summary.ip_category_counts and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Addressing Observations"))
        rows = [["Category", "Packets"]]
        preferred = [
            "public",
            "private",
            "multicast",
            "broadcast",
            "loopback",
            "link_local",
            "reserved",
            "unspecified",
            "invalid",
            "unknown",
        ]
        for cat in preferred:
            if summary.ip_category_counts.get(cat, 0) > 0:
                rows.append(
                    [cat.replace("_", " "), str(summary.ip_category_counts[cat])]
                )
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Top Sources"))
    rows = [["Source", "Packets", "% of IP traffic"]]
    for ip, count in summary.src_counts.most_common(limit):
        pct = (count / summary.total_packets * 100) if summary.total_packets else 0
        rows.append([ip, str(count), f"{pct:.1f}%"])
    lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Top Destinations"))
    rows = [["Destination", "Packets", "% of IP traffic"]]
    for ip, count in summary.dst_counts.most_common(limit):
        pct = (count / summary.total_packets * 100) if summary.total_packets else 0
        rows.append([ip, str(count), f"{pct:.1f}%"])
    lines.append(_format_table(rows))

    if summary.ip_mac_counts:
        endpoint_by_ip = {ep.ip: ep for ep in summary.endpoints}
        confirmed_ports_by_ip = {
            str(ip): sorted(
                {
                    int(port)
                    for port in list(ports or [])
                    if isinstance(port, int) or str(port).isdigit()
                }
            )
            for ip, ports in (getattr(summary, "confirmed_tcp_service_ports", {}) or {}).items()
        }
        lines.append(SUBSECTION_BAR)
        lines.append(header("IP Host Details"))
        rows = [
            [
                "IP",
                "Class / Role",
                "Hostname",
                "Geo / ASN / Org",
                "Service Ports",
                "Traffic",
            ]
        ]
        ip_enrichment = getattr(summary, "ip_enrichment", {}) or {}
        # Role classification: scanners (in a scan profile), servers (confirmed
        # listening ports), else clients — the key "what is this host" triage cue.
        scanner_ips = {
            str(p.get("src", ""))
            for p in (getattr(summary, "suspicious_port_profiles", []) or [])
            if p.get("src")
        }
        sorted_macs = sorted(
            summary.ip_mac_counts.items(),
            key=lambda item: sum(item[1].values()),
            reverse=True,
        )
        for ip_value, mac_counts in sorted_macs[:limit]:
            hostnames = list((summary.ip_hostnames or {}).get(ip_value, Counter()).items())
            hostname_text = "-"
            if hostnames:
                hostnames = sorted(hostnames, key=lambda item: (-item[1], item[0]))
                hostname_text = ", ".join(
                    f"{name}({count})" for name, count in hostnames[:2]
                )
            endpoint = endpoint_by_ip.get(ip_value)
            ports_text = "-"
            traffic_text = "-"
            confirmed_ports = confirmed_ports_by_ip.get(ip_value, [])
            if confirmed_ports:
                ports_text = ",".join(str(port) for port in confirmed_ports[:8])
                if len(confirmed_ports) > 8:
                    ports_text += "..."
            if endpoint is not None:
                traffic_text = (
                    f"pkts s/r={endpoint.packets_sent}/{endpoint.packets_recv}, "
                    f"bytes={format_bytes_as_mb(endpoint.bytes_sent + endpoint.bytes_recv)}"
                )
            # Scope + role
            external = _is_public_ip(ip_value)
            scope = "ext" if external else "int"
            # Browser (MS-BRWS) announced roles are the authoritative "what is
            # this host" cue when present (DC / SQL / print / master browser).
            nb_roles = (getattr(summary, "ip_roles", {}) or {}).get(ip_value, [])
            role_short = _short_browser_role(nb_roles)
            if role_short:
                role = role_short
            elif ip_value in scanner_ips:
                role = "scanner"
            elif confirmed_ports:
                role = "server"
            else:
                role = "client"
            class_text = f"{scope}/{role}"
            # Fold the browser-announced OS into the hostname cell (compact).
            nb_os = (getattr(summary, "ip_os", {}) or {}).get(ip_value, "")
            if nb_os and hostname_text != "-":
                hostname_text = f"{hostname_text} [{nb_os.split(' (')[0]}]"
            elif nb_os:
                hostname_text = f"[{nb_os.split(' (')[0]}]"
            # Geo / ASN / Org (MaxMind or online), with hosting/proxy flags.
            enr = ip_enrichment.get(ip_value, {})
            geo_bits: list[str] = []
            if enr.get("country") or enr.get("geo"):
                geo_bits.append(str(enr.get("country") or enr.get("geo")))
            if enr.get("asn"):
                geo_bits.append(str(enr.get("asn")))
            elif enr.get("org"):
                geo_bits.append(str(enr.get("org")))
            flags = [f for f in ("hosting", "proxy", "mobile") if enr.get(f)]
            if flags:
                geo_bits.append("[" + ",".join(flags) + "]")
            geo_text = " · ".join(geo_bits) if geo_bits else ("-" if external else "internal")
            rows.append(
                [
                    danger(ip_value) if external and ip_value in scanner_ips else ip_value,
                    class_text,
                    _truncate_text(hostname_text, 34),
                    _truncate_text(geo_text, 40),
                    _truncate_text(ports_text, 24),
                    _truncate_text(traffic_text, 38),
                ]
            )
        lines.append(_format_table(rows))

    sorted_eps = sorted(
        summary.endpoints,
        key=lambda e: e.bytes_sent + e.bytes_recv,
        reverse=True,
    )[:limit]
    if verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Endpoints (bytes + peers)"))
        rows = [
            ["IP", "Sent", "Recv", "Total", "Peers", "Ports", "Protocols", "Geo", "ASN"]
        ]
        for ep in sorted_eps:
            ports_str = ",".join(str(p) for p in ep.ports[: _limit_value(6)])
            if len(ep.ports) > 6:
                ports_str += "..."
            proto_str = ",".join(ep.protocols[: _limit_value(4)])
            if len(ep.protocols) > 4:
                proto_str += "..."
            rows.append(
                [
                    ep.ip,
                    format_bytes_as_mb(ep.bytes_sent),
                    format_bytes_as_mb(ep.bytes_recv),
                    format_bytes_as_mb(ep.bytes_sent + ep.bytes_recv),
                    str(len(ep.peers)),
                    ports_str or "-",
                    proto_str or "-",
                    ep.geo or "-",
                    ep.asn or "-",
                ]
            )
        lines.append(_format_table(rows))

    if verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top IP Conversations"))
        sorted_convs = sorted(summary.conversations, key=lambda c: c.bytes, reverse=True)[
            :limit
        ]
        rows = [["Src", "Dst", "Proto", "Packets", "Bytes", "Duration", "Ports"]]
        for conv in sorted_convs:
            duration = "-"
            if conv.first_seen is not None and conv.last_seen is not None:
                duration = format_duration(conv.last_seen - conv.first_seen)
            ports_str = ",".join(str(p) for p in conv.ports[: _limit_value(6)])
            if len(conv.ports) > 6:
                ports_str += "..."
            rows.append(
                [
                    conv.src,
                    conv.dst,
                    conv.protocol,
                    str(conv.packets),
                    format_bytes_as_mb(conv.bytes),
                    duration,
                    ports_str or "-",
                ]
            )
        lines.append(_format_table(rows))

    if summary.ja_reputation_hits and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TLS Fingerprint Reputation"))
        rows = [["Type", "Fingerprint", "Label", "Count"]]
        for item in summary.ja_reputation_hits[:limit]:
            rows.append(
                [
                    str(item.get("type", "-")),
                    str(item.get("fingerprint", "-")),
                    str(item.get("label", "-")),
                    str(item.get("count", "-")),
                ]
            )
        lines.append(_format_table(rows))

    if summary.tls_cert_risks and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TLS Certificate Risks"))
        rows = [["Server", "Risk Type", "Details"]]
        for item in summary.tls_cert_risks[:limit]:
            src = str(item.get("src", "-"))
            dst = str(item.get("dst", "-"))
            risks = item.get("risks", [])
            if isinstance(risks, list):
                for risk in risks[: _limit_value(5)]:
                    rows.append(
                        [
                            f"{src}->{dst}",
                            str(risk.get("type", "-")),
                            str(risk.get("details", "-")),
                        ]
                    )
        lines.append(_format_table(rows))

    if summary.suspicious_port_profiles and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Suspicious Port Profiles"))
        rows = [["Type", "Source", "Unique Ports", "Unique Targets", "High Ports"]]
        for item in summary.suspicious_port_profiles[:limit]:
            rows.append(
                [
                    str(item.get("type", "-")),
                    str(item.get("src", "-")),
                    str(item.get("unique_ports", "-")),
                    str(item.get("unique_dsts", "-")),
                    str(item.get("high_ports", "-")),
                ]
            )
        lines.append(_format_table(rows))

    if summary.lateral_movement_scores and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Lateral Movement Scoring"))
        rows = [["IP", "Score", "Peers", "Ports", "Packets Sent"]]
        for item in sorted(
            summary.lateral_movement_scores,
            key=lambda x: x.get("score", 0),
            reverse=True,
        )[:limit]:
            rows.append(
                [
                    str(item.get("ip", "-")),
                    str(item.get("score", "-")),
                    str(item.get("peers", "-")),
                    str(item.get("ports", "-")),
                    str(item.get("packets_sent", "-")),
                ]
            )
        lines.append(_format_table(rows))

    if verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Endpoint Timing"))
        rows = [["IP", "First Seen", "Last Seen", "Duration"]]
        for ep in sorted_eps:
            ep_duration = "-"
            if ep.first_seen is not None and ep.last_seen is not None:
                ep_duration = format_duration(ep.last_seen - ep.first_seen)
            rows.append(
                [
                    ep.ip,
                    format_ts(ep.first_seen),
                    format_ts(ep.last_seen),
                    ep_duration,
                ]
            )
        lines.append(_format_table(rows))

    detections = _filtered_detections(summary, verbose)
    if concise_mode:
        actionable = []
        for item in detections:
            severity = str(item.get("severity", "info")).lower()
            if severity in {"critical", "high", "severe", "medium", "warning"}:
                actionable.append(item)
        detections = actionable
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Anomalies & Threat Indicators"))
        for item in detections:
            severity = item.get("severity", "info")
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity in {"warning", "medium"}:
                marker = warn("[WARN]")
            elif severity in {"critical", "severe"}:
                marker = danger("[CRIT]")
            elif severity == "high":
                marker = danger("[HIGH]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))
            top_sources = item.get("top_sources")
            if top_sources:
                src_text = ", ".join(f"{ip}({count})" for ip, count in top_sources)
                lines.append(muted(f"  Sources: {src_text}"))
            top_destinations = item.get("top_destinations")
            if top_destinations:
                dst_text = ", ".join(f"{ip}({count})" for ip, count in top_destinations)
                lines.append(muted(f"  Destinations: {dst_text}"))

    if summary.intel_findings and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Threat Intel Hits"))
        rows = [["IP", "Source", "Signal", "Details"]]
        for item in summary.intel_findings:
            ip = str(item.get("ip", ""))
            source = str(item.get("source", ""))
            signal = "-"
            details = []
            if source == "AbuseIPDB":
                score = item.get("score")
                reports = item.get("reports")
                if score is not None:
                    signal = f"score {score}"
                if reports is not None:
                    details.append(f"reports {reports}")
                usage = item.get("usage")
                if usage:
                    details.append(f"usage {usage}")
                country = item.get("country")
                if country:
                    details.append(f"country {country}")
            elif source == "OTX":
                pulses = item.get("pulses")
                if pulses is not None:
                    signal = f"pulses {pulses}"
            elif source == "VirusTotal":
                malicious = item.get("malicious")
                suspicious = item.get("suspicious")
                harmless = item.get("harmless")
                signal = f"mal {malicious} / sus {suspicious}"
                if harmless is not None:
                    details.append(f"harmless {harmless}")

            rows.append([ip, source, signal, "; ".join(details) or "-"])
        lines.append(_format_table(rows))

    false_positive_context = [
        str(v) for v in list(getattr(summary, "false_positive_context", []) or [])
    ]
    if false_positive_context and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("False-Positive Context"))
        for item in false_positive_context[: _limit_value(8)]:
            lines.append(muted(f"- {item}"))

    if concise_mode:
        lines.append(SUBSECTION_BAR)
        lines.append(
            muted(
                "Default IPS view shows host details, top talkers, and medium/high/severe findings only."
            )
        )
        lines.append(muted("Use `-v` for full IPS analytics and forensic context."))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
