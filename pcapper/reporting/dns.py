"""Rendered output for dns analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    danger,
    header,
    label,
    muted,
    ok,
    warn,
)
from ..dns import PUBLIC_DNS_RESOLVERS, DnsSummary
from ..utils import (
    format_bytes_as_mb,
    format_duration,
    format_ts,
    sparkline,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _apply_verbose_limit,
    _counter_table,
    _filtered_detections,
    _finalize_output,
    _format_kv,
    _format_table,
    _highlight_public_ips,
    _limit_value,
    _redact_in_text,
    _truncate_text,
)


def render_dns_summary(
    summary: DnsSummary, limit: int = 12, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit)

    def _dns_type_name(type_id: int) -> str:
        # IANA DNS RR TYPEs (https://www.iana.org/assignments/dns-parameters).
        name = {
            1: "A",
            2: "NS",
            3: "MD",
            4: "MF",
            5: "CNAME",
            6: "SOA",
            7: "MB",
            8: "MG",
            9: "MR",
            10: "NULL",
            11: "WKS",
            12: "PTR",
            13: "HINFO",
            14: "MINFO",
            15: "MX",
            16: "TXT",
            17: "RP",
            18: "AFSDB",
            24: "SIG",
            25: "KEY",
            28: "AAAA",
            29: "LOC",
            33: "SRV",
            35: "NAPTR",
            36: "KX",
            37: "CERT",
            39: "DNAME",
            41: "OPT",
            42: "APL",
            43: "DS",
            44: "SSHFP",
            45: "IPSECKEY",
            46: "RRSIG",
            47: "NSEC",
            48: "DNSKEY",
            49: "DHCID",
            50: "NSEC3",
            51: "NSEC3PARAM",
            52: "TLSA",
            53: "SMIMEA",
            55: "HIP",
            59: "CDS",
            60: "CDNSKEY",
            61: "OPENPGPKEY",
            62: "CSYNC",
            63: "ZONEMD",
            64: "SVCB",
            65: "HTTPS",
            99: "SPF",
            108: "EUI48",
            109: "EUI64",
            249: "TKEY",
            250: "TSIG",
            251: "IXFR",
            252: "AXFR",
            253: "MAILB",
            254: "MAILA",
            255: "ANY",
            256: "URI",
            257: "CAA",
            32768: "TA",
            32769: "DLV",
        }.get(type_id)
        if name:
            return name
        if type_id == 0 or 65280 <= type_id <= 65535:
            return "RESERVED"
        return "UNASSIGNED"

    def _dns_rcode_name(rcode_id: int) -> str:
        # IANA DNS RCODEs. Values 16+ are EDNS/TSIG extended codes; the basic
        # header carries only the low 4 bits so 11-15 are what normally surface.
        name = {
            0: "NOERROR",
            1: "FORMERR",
            2: "SERVFAIL",
            3: "NXDOMAIN",
            4: "NOTIMP",
            5: "REFUSED",
            6: "YXDOMAIN",
            7: "YXRRSET",
            8: "NXRRSET",
            9: "NOTAUTH",
            10: "NOTZONE",
            11: "DSOTYPENI",
            16: "BADVERS/BADSIG",
            17: "BADKEY",
            18: "BADTIME",
            19: "BADMODE",
            20: "BADNAME",
            21: "BADALG",
            22: "BADTRUNC",
            23: "BADCOOKIE",
        }.get(rcode_id)
        if name:
            return name
        if 12 <= rcode_id <= 15:
            return "UNASSIGNED"
        return "UNKNOWN"

    def _dns_opcode_name(opcode_id: int) -> str:
        # IANA DNS OpCodes. 3 and 7-15 are unassigned/reserved; their presence on
        # port 53 usually means malformed traffic, a non-DNS protocol parsed as
        # DNS, or deliberate tunneling/evasion rather than a real DNS operation.
        name = {
            0: "QUERY",
            1: "IQUERY",
            2: "STATUS",
            4: "NOTIFY",
            5: "UPDATE",
            6: "DSO",
        }.get(opcode_id)
        if name:
            return name
        return "RESERVED/UNASSIGNED"

    def _dns_base_domain(name: str) -> str:
        parts = [part for part in name.strip(".").split(".") if part]
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return name.strip(".")

    def _vt_info(name: str) -> tuple[str, str]:
        if not summary.vt_results:
            return "-", "-"
        info = summary.vt_results.get(name)
        if info is None:
            info = summary.vt_results.get(_dns_base_domain(name))
        if not info:
            return "-", "-"
        return str(info.get("score", "-")), str(info.get("rating", "-"))

    def _render_mdns_section() -> None:
        if summary.mdns_packets <= 0:
            return
        lines.append(SUBSECTION_BAR)
        lines.append(header("mDNS Analysis"))
        mdns_share = (summary.mdns_packets / summary.total_packets * 100.0) if summary.total_packets else 0.0
        q_resp_ratio = (
            summary.mdns_query_packets / max(1, summary.mdns_response_packets)
            if summary.mdns_response_packets
            else float(summary.mdns_query_packets)
        )
        lines.append(_format_kv("mDNS Packets", str(summary.mdns_packets)))
        lines.append(_format_kv("Traffic Share", f"{mdns_share:.2f}% of DNS packets"))
        lines.append(_format_kv("mDNS Queries", str(summary.mdns_query_packets)))
        lines.append(_format_kv("mDNS Responses", str(summary.mdns_response_packets)))
        lines.append(_format_kv("mDNS Query/Response Ratio", f"{q_resp_ratio:.2f}"))
        lines.append(_format_kv("mDNS Error Responses", str(summary.mdns_error_responses)))
        lines.append(_format_kv("Unique mDNS Clients", str(summary.unique_mdns_clients)))
        lines.append(_format_kv("Unique mDNS Responders", str(summary.unique_mdns_servers)))
        lines.append(_format_kv("Unique mDNS Names", str(len(summary.mdns_qname_counts))))
        lines.append(_format_kv("Unique mDNS Services", str(len(summary.mdns_service_counts))))

        if summary.mdns_qtype_counts:
            rows = [["QType", "Count"]]
            for qtype, count in summary.mdns_qtype_counts.most_common(limit):
                rows.append([f"{_dns_type_name(int(qtype))} ({qtype})", str(count)])
            lines.append(_format_table(rows))

        if summary.mdns_client_counts:
            rows = [["Top mDNS Client", "Packets"]]
            for name, count in summary.mdns_client_counts.most_common(limit):
                rows.append([str(name), str(count)])
            lines.append(_format_table(rows))

        if summary.mdns_server_counts:
            rows = [["Top mDNS Responder", "Packets"]]
            for name, count in summary.mdns_server_counts.most_common(limit):
                rows.append([str(name), str(count)])
            lines.append(_format_table(rows))

        if summary.mdns_qname_counts:
            lines.append(_counter_table(summary.mdns_qname_counts, "Top mDNS Name", limit=limit))

        if summary.mdns_service_counts:
            lines.append(_counter_table(summary.mdns_service_counts, "Top mDNS Service", limit=limit))

        suspicious_mdns = []
        for item in list(getattr(summary, "detections", []) or []):
            det_type = str(item.get("type", "")).lower()
            det_summary = str(item.get("summary", ""))
            det_details = str(item.get("details", ""))
            blob = f"{det_type} {det_summary} {det_details}".lower()
            if det_type.startswith("mdns_") or "mdns" in blob:
                suspicious_mdns.append(item)

        if suspicious_mdns:
            lines.append(muted("Suspicious/Malicious mDNS Artifacts"))
            rows = [["Severity", "Artifact", "Details"]]
            for item in suspicious_mdns[:limit]:
                rows.append(
                    [
                        str(item.get("severity", "info")).upper(),
                        _truncate_text(str(item.get("summary", "-")), 56),
                        _truncate_text(str(item.get("details", "-")), 88),
                    ]
                )
            lines.append(_format_table(rows))
        else:
            lines.append(ok("No suspicious mDNS artifacts were flagged by current heuristics."))

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"DNS ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    lines.append(_format_kv("DNS Packets", str(summary.total_packets)))
    lines.append(_format_kv("DNS Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(_format_kv("Queries", str(summary.query_packets)))
    lines.append(_format_kv("Responses", str(summary.response_packets)))
    lines.append(_format_kv("UDP", str(summary.udp_packets)))
    lines.append(_format_kv("TCP", str(summary.tcp_packets)))
    lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))
    lines.append(_format_kv("Unique QNames", str(summary.unique_qnames)))
    lines.append(_format_kv("First Seen", format_ts(summary.first_seen)))
    lines.append(_format_kv("Last Seen", format_ts(summary.last_seen)))

    def _dns_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        detections = list(getattr(summary, "detections", []) or [])
        warn_count = sum(
            1
            for item in detections
            if str(item.get("severity", "")).lower() == "warning"
        )
        if warn_count:
            score += min(3, warn_count)
            reasons.append(f"Warning-level DNS detections observed ({warn_count})")

        checks = getattr(summary, "deterministic_checks", {}) or {}
        high_signal_keys = (
            "dns_tunneling_indicators",
            "dga_like_behavior",
            "fast_flux_or_rebinding",
            "zone_transfer_attempt",
            "dnssec_or_integrity_anomaly",
            "amplification_abuse_signal",
        )
        for key in high_signal_keys:
            values = checks.get(key, []) if isinstance(checks, dict) else []
            if values:
                score += 1
                reasons.append(
                    f"{key.replace('_', ' ')} evidence observed ({len(values)})"
                )

        if getattr(summary, "transaction_violations", None):
            score += 2
            reasons.append(
                f"Transaction integrity violations observed ({len(summary.transaction_violations)})"
            )
        if getattr(summary, "resolver_drift", None):
            score += 1
            reasons.append(
                f"Resolver drift observed ({len(summary.resolver_drift)} clients)"
            )

        if score >= 8:
            verdict = "YES - high-confidence suspicious DNS abuse or compromise indicators are present."
            confidence = "High"
        elif score >= 5:
            verdict = "LIKELY - significant suspicious DNS behavior is present."
            confidence = "Medium"
        elif score >= 2:
            verdict = (
                "POSSIBLE - weak-to-moderate suspicious DNS indicators are present."
            )
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing high-risk DNS threat pattern from current heuristics."
            confidence = "Low"

        if not reasons:
            reasons.append("No high-confidence DNS threat heuristic crossed threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _dns_verdict()
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
    if summary.client_counts:
        lines.append(muted("Who:"))
        lines.append(muted("- Top querying clients"))
        for client, count in summary.client_counts.most_common(_limit_value(8)):
            lines.append(muted(f"- {_highlight_public_ips(str(client))}: {int(count)}"))
    if summary.server_counts:
        lines.append(muted("Where:"))
        lines.append(muted("- Top DNS servers"))
        for server, count in summary.server_counts.most_common(_limit_value(8)):
            lines.append(muted(f"- {_highlight_public_ips(str(server))}: {int(count)}"))
    if verbose and summary.qname_counts:
        lines.append(muted("What:"))
        lines.append(muted("- Top queried names"))
        for qname, count in summary.qname_counts.most_common(_limit_value(6)):
            lines.append(muted(f"- {_redact_in_text(str(qname))}: {int(count)}"))
    if getattr(summary, "transaction_violations", None):
        tv = list(summary.transaction_violations or [])
        if tv:
            lines.append(muted("When:"))
            lines.append(muted("- Transaction integrity violations"))
            for item in tv[: _limit_value(6)]:
                lines.append(
                    muted(
                        f"- id={item.get('id', '-')} {_highlight_public_ips(str(item.get('src', '-')))}"
                        f"->{_highlight_public_ips(str(item.get('dst', '-')))} at {format_ts(item.get('ts'))}"
                    )
                )

    if not verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Traffic Statistics"))
        q_resp_ratio = "-"
        if summary.response_packets:
            q_resp_ratio = f"{summary.query_packets / max(1, summary.response_packets):.2f}"
        lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))
        lines.append(_format_kv("Query/Response Ratio", q_resp_ratio))
        lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
        lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))
        lines.append(_format_kv("Unique QNames", str(summary.unique_qnames)))

        lines.append(SUBSECTION_BAR)
        lines.append(header("DNS Service Statistics"))
        if summary.type_counts:
            rows = [["Query Type", "Count"]]
            for name, count in summary.type_counts.most_common(15):
                try:
                    type_id = int(name)
                    type_label = f"{_dns_type_name(type_id)} ({type_id})"
                except Exception:
                    type_label = str(name)
                rows.append([type_label, str(count)])
            lines.append(_format_table(rows))
        if summary.rcode_counts:
            rows = [["Response Code", "Count"]]
            for name, count in summary.rcode_counts.most_common(15):
                try:
                    rcode_id = int(name)
                    rcode_label = f"{_dns_rcode_name(rcode_id)} ({rcode_id})"
                except Exception:
                    rcode_label = str(name)
                rows.append([rcode_label, str(count)])
            lines.append(_format_table(rows))
        if summary.opcode_counts:
            rows = [["Opcode", "Count"]]
            for opcode, count in summary.opcode_counts.most_common(15):
                rows.append([f"{_dns_opcode_name(int(opcode))} ({opcode})", str(count)])
            lines.append(_format_table(rows))

        lines.append(SUBSECTION_BAR)
        lines.append(header("DNS Client Statistics"))
        if summary.client_counts:
            rows = [["Client", "Queries"]]
            for name, count in summary.client_counts.most_common(15):
                rows.append([str(name), str(count)])
            lines.append(_format_table(rows))
        else:
            lines.append(muted("No DNS clients observed."))

        lines.append(SUBSECTION_BAR)
        lines.append(header("DNS Server Statistics"))
        if summary.server_counts:
            rows = [["Server", "Responses"]]
            for name, count in summary.server_counts.most_common(15):
                rows.append([str(name), str(count)])
            lines.append(_format_table(rows))
        else:
            lines.append(muted("No DNS servers observed."))

        lines.append(SUBSECTION_BAR)
        lines.append(header("Most Queried Domains/URLs"))
        if summary.qname_counts:
            lines.append(_counter_table(summary.qname_counts, "QName", limit=15))
        else:
            lines.append(muted("No queried names observed."))

        lines.append(SUBSECTION_BAR)
        lines.append(header("Least Queried Domains/URLs"))
        if summary.qname_counts:
            rows = [["QName", "Count"]]
            bottom_names = sorted(
                summary.qname_counts.items(), key=lambda item: (item[1], item[0])
            )[:15]
            for name, count in bottom_names:
                rows.append([str(name), str(count)])
            lines.append(_format_table(rows))
        else:
            lines.append(muted("No queried names observed."))

        lines.append(SUBSECTION_BAR)
        lines.append(header("Most Queried Base Domains"))
        if summary.base_domain_counts:
            lines.append(_counter_table(summary.base_domain_counts, "Base Domain", limit=15))
        else:
            lines.append(muted("No base-domain observations available."))

        lines.append(SUBSECTION_BAR)
        lines.append(header("Least Queried Base Domains"))
        if summary.base_domain_counts:
            rows = [["Base Domain", "Count"]]
            bottom_domains = sorted(
                summary.base_domain_counts.items(),
                key=lambda item: (item[1], item[0]),
            )[:15]
            for name, count in bottom_domains:
                rows.append([str(name), str(count)])
            lines.append(_format_table(rows))
        else:
            lines.append(muted("No base-domain observations available."))

        severity_rank = {"critical": 0, "high": 1, "medium": 2, "warning": 2}
        severe_items: list[dict[str, object]] = [
            item
            for item in list(getattr(summary, "detections", []) or [])
            if str(item.get("severity", "info")).lower() in severity_rank
        ]
        # Most severe first so the analyst reads the highest-risk findings at the
        # top of the triage section.
        severe_items.sort(
            key=lambda it: severity_rank.get(
                str(it.get("severity", "")).lower(), 3
            )
        )
        if severe_items:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Medium/High/Critical Issues"))
            for item in severe_items[:15]:
                severity = str(item.get("severity", "info")).lower()
                summary_text = _truncate_text(str(item.get("summary", "")), 120)
                details = _truncate_text(str(item.get("details", "")), 220)
                if severity == "critical":
                    marker = danger("[CRITICAL]")
                elif severity == "high":
                    marker = danger("[HIGH]")
                elif severity in {"medium", "warning"}:
                    marker = warn("[MEDIUM]")
                else:
                    marker = ok("[INFO]")
                lines.append(f"{marker} {summary_text}")
                if details:
                    lines.append(muted(f"  Details: {details}"))

                # Evidence: concrete clients/servers/reputation so the finding can
                # be pivoted on immediately without re-running in verbose mode.
                def _ev_pairs(values: object) -> str:
                    if not isinstance(values, list):
                        return ""
                    parts = []
                    for entry in values[:3]:
                        if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                            who, num = entry[0], entry[1]
                        else:
                            who, num = entry, None
                        if not who:
                            continue
                        label_txt = _highlight_public_ips(str(who))
                        parts.append(
                            f"{label_txt} ({num})" if num is not None else label_txt
                        )
                    return ", ".join(parts)

                client_ev = _ev_pairs(item.get("top_clients"))
                if client_ev:
                    lines.append(muted(f"  Evidence - top clients: {client_ev}"))
                server_ev = _ev_pairs(item.get("top_servers"))
                if server_ev:
                    lines.append(muted(f"  Evidence - top servers: {server_ev}"))
                vt_findings = item.get("vt_findings")
                if isinstance(vt_findings, list) and vt_findings:
                    vt_ev = ", ".join(
                        f"{vf.get('domain', '-')}={vf.get('rating', '-')}"
                        f"({vf.get('score', 0)})"
                        for vf in vt_findings[:3]
                        if isinstance(vf, dict)
                        and int(vf.get("score", 0) or 0) > 0
                    )
                    if vt_ev:
                        lines.append(muted(f"  Evidence - VirusTotal: {vt_ev}"))

        _render_mdns_section()

        if summary.errors:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Errors"))
            for err in summary.errors[: _limit_value(12)]:
                lines.append(danger(f"- {err}"))

        lines.append(SECTION_BAR)
        return _finalize_output(lines)

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic DNS Security Checks"))
    checks = getattr(summary, "deterministic_checks", {}) or {}
    check_labels = [
        ("dns_tunneling_indicators", "DNS Tunneling Indicators"),
        ("dga_like_behavior", "DGA-like Behavior"),
        ("fast_flux_or_rebinding", "Fast-Flux/Rebinding"),
        ("zone_transfer_attempt", "Zone Transfer Attempt"),
        ("resolver_policy_violation", "Resolver Policy Violation"),
        ("dnssec_or_integrity_anomaly", "DNSSEC/Integrity Anomaly"),
        ("amplification_abuse_signal", "Amplification Abuse Signal"),
        ("opcode_or_any_abuse", "Opcode / ANY-Query Abuse"),
        ("dns_beaconing_periodicity", "DNS Beaconing Periodicity"),
        ("likely_benign_cdn_rotation", "Likely Benign CDN Rotation"),
    ]
    for key, label_text in check_labels:
        evidence_items = checks.get(key, []) if isinstance(checks, dict) else []
        evidence_items = [str(v) for v in (evidence_items or []) if str(v).strip()]
        lines.append(label(label_text))
        if evidence_items:
            if key == "likely_benign_cdn_rotation":
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
    if summary.edns0_opt_count:
        lines.append(_format_kv("EDNS0 OPT Records", str(summary.edns0_opt_count)))
    if summary.mdns_packets:
        lines.append(_format_kv("mDNS Packets", str(summary.mdns_packets)))
        lines.append(_format_kv("mDNS Queries", str(summary.mdns_query_packets)))
        lines.append(_format_kv("mDNS Responses", str(summary.mdns_response_packets)))
        lines.append(_format_kv("mDNS Clients", str(summary.unique_mdns_clients)))
        lines.append(_format_kv("mDNS Servers", str(summary.unique_mdns_servers)))
        lines.append(
            _format_kv("mDNS Error Responses", str(summary.mdns_error_responses))
        )
    if summary.llmnr_packets:
        lines.append(_format_kv("LLMNR Packets", str(summary.llmnr_packets)))
        lines.append(_format_kv("LLMNR Queries", str(summary.llmnr_query_packets)))
        lines.append(_format_kv("LLMNR Responses", str(summary.llmnr_response_packets)))

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    if summary.type_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Query Types"))
        rows = [["Type", "Count"]]
        for name, count in summary.type_counts.most_common(limit):
            try:
                type_id = int(name)
                type_label = f"{_dns_type_name(type_id)} ({type_id})"
            except Exception:
                type_label = str(name)
            rows.append([type_label, str(count)])
        lines.append(_format_table(rows))

    if summary.rcode_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Response Codes"))
        rows = [["RCode", "Count"]]
        for name, count in summary.rcode_counts.most_common(limit):
            try:
                rcode_id = int(name)
                rcode_label = f"{_dns_rcode_name(rcode_id)} ({rcode_id})"
            except Exception:
                rcode_label = str(name)
            rows.append([rcode_label, str(count)])
        lines.append(_format_table(rows))

    if summary.opcode_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("DNS Opcodes"))
        rows = [["Opcode", "Count"]]
        for opcode, count in summary.opcode_counts.most_common(limit):
            opcode_label = f"{_dns_opcode_name(int(opcode))} ({opcode})"
            rows.append([opcode_label, str(count)])
        lines.append(_format_table(rows))

    if summary.flag_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("DNS Flags"))
        lines.append(_counter_table(summary.flag_counts, "Flag", limit=limit))

    if summary.query_size_stats or summary.response_size_stats:
        lines.append(SUBSECTION_BAR)
        lines.append(header("DNS Payload Sizes"))
        rows = [["Metric", "Query", "Response"]]
        metrics = ["count", "min", "max", "avg", "median", "p95"]
        for metric in metrics:
            qval = (
                summary.query_size_stats.get(metric, "-")
                if summary.query_size_stats
                else "-"
            )
            rval = (
                summary.response_size_stats.get(metric, "-")
                if summary.response_size_stats
                else "-"
            )
            if metric == "avg":
                qval = f"{float(qval):.1f}" if isinstance(qval, (int, float)) else qval
                rval = f"{float(rval):.1f}" if isinstance(rval, (int, float)) else rval
            rows.append([metric, str(qval), str(rval)])
        lines.append(_format_table(rows))

    if summary.client_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Clients"))
        rows = [["Client", "Queries"]]
        for name, count in summary.client_counts.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Servers"))
        rows = [["Server", "Responses"]]
        for name, count in summary.server_counts.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.public_resolver_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Public DNS Resolvers"))
        rows = [["Resolver", "Count", "Provider"]]
        for ip_value, count in summary.public_resolver_counts.most_common(limit):
            rows.append([ip_value, str(count), PUBLIC_DNS_RESOLVERS.get(ip_value, "-")])
        lines.append(_format_table(rows))

    if summary.base_domain_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Base Domains"))
        if summary.vt_results:
            rows = [["Base Domain", "Count", "VT Score", "VT Rating"]]
            for name, count in summary.base_domain_counts.most_common(limit):
                score, rating = _vt_info(name)
                rows.append([name, str(count), score, rating])
        else:
            rows = [["Base Domain", "Count"]]
            for name, count in summary.base_domain_counts.most_common(limit):
                rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.qname_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Queried Names"))
        if summary.vt_results:
            rows = [["QName", "Count", "VT Score", "VT Rating"]]
            for name, count in summary.qname_counts.most_common(limit):
                score, rating = _vt_info(name)
                rows.append([name, str(count), score, rating])
        else:
            rows = [["QName", "Count"]]
            for name, count in summary.qname_counts.most_common(limit):
                rows.append([name, str(count)])
        lines.append(_format_table(rows))

        lines.append(SUBSECTION_BAR)
        lines.append(header("Bottom Queried Names"))
        rows = [["QName", "Count"]]
        bottom_names = sorted(
            summary.qname_counts.items(), key=lambda item: (item[1], item[0])
        )[: _limit_value(15)]
        for name, count in bottom_names:
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    if summary.tld_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top TLDs"))
        lines.append(_counter_table(summary.tld_counts, "TLD", limit=limit))

    if summary.answers_by_qname:
        candidates = [
            (name, answers)
            for name, answers in summary.answers_by_qname.items()
            if len(answers) > 1
        ]
        if candidates:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Answer Variability (QName)"))
            rows = [["QName", "Unique Answers", "Sample"]]
            for name, answers in sorted(
                candidates, key=lambda item: len(item[1]), reverse=True
            )[:limit]:
                sample = ", ".join(sorted(list(answers))[: _limit_value(3)])
                if len(answers) > _limit_value(3):
                    sample += "..."
                rows.append([name, str(len(answers)), sample or "-"])
            lines.append(_format_table(rows))

    if getattr(summary, "resolver_drift", None):
        if summary.resolver_drift:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Resolver Drift Profiles"))
            rows = [["Client", "Resolvers", "Public", "Private", "Top Resolvers"]]
            for item in summary.resolver_drift[:limit]:
                tops = item.get("top_resolvers", [])
                top_text = ", ".join(
                    f"{ip}({count})"
                    for ip, count in (tops[:3] if isinstance(tops, list) else [])
                )
                rows.append(
                    [
                        str(item.get("client", "-")),
                        str(item.get("resolver_count", "-")),
                        str(item.get("public", "-")),
                        str(item.get("private", "-")),
                        top_text or "-",
                    ]
                )
            lines.append(_format_table(rows))

    if getattr(summary, "client_abuse_profiles", None):
        if summary.client_abuse_profiles:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Client Abuse Profiles"))
            rows = [
                [
                    "Client",
                    "Queries",
                    "Unique",
                    "Unique Ratio",
                    "Avg Entropy",
                    "NXDOMAIN",
                    "TXT",
                    "Long",
                ]
            ]
            for item in summary.client_abuse_profiles[:limit]:
                rows.append(
                    [
                        str(item.get("client", "-")),
                        str(item.get("queries", "-")),
                        str(item.get("unique_qnames", "-")),
                        str(item.get("unique_ratio", "-")),
                        str(item.get("avg_entropy", "-")),
                        str(item.get("nxdomain", "-")),
                        str(item.get("txt_queries", "-")),
                        str(item.get("long_queries", "-")),
                    ]
                )
            lines.append(_format_table(rows))

    if getattr(summary, "ttl_outliers", None):
        if summary.ttl_outliers:
            lines.append(SUBSECTION_BAR)
            lines.append(header("TTL Outliers"))
            rows = [["QName", "Samples", "Unique TTL", "Min TTL", "Max TTL"]]
            for item in summary.ttl_outliers[:limit]:
                rows.append(
                    [
                        _truncate_text(str(item.get("qname", "-")), 64),
                        str(item.get("samples", "-")),
                        str(item.get("unique_ttl", "-")),
                        str(item.get("min_ttl", "-")),
                        str(item.get("max_ttl", "-")),
                    ]
                )
            lines.append(_format_table(rows))

    if getattr(summary, "cname_anomalies", None):
        if summary.cname_anomalies:
            lines.append(SUBSECTION_BAR)
            lines.append(header("CNAME Anomalies"))
            rows = [["QName", "Targets", "Sample Targets"]]
            for item in summary.cname_anomalies[:limit]:
                targets = item.get("targets", [])
                target_text = ", ".join(
                    str(v) for v in (targets[:3] if isinstance(targets, list) else [])
                )
                rows.append(
                    [
                        _truncate_text(str(item.get("qname", "-")), 64),
                        str(item.get("target_count", "-")),
                        _truncate_text(target_text or "-", 80),
                    ]
                )
            lines.append(_format_table(rows))

    if getattr(summary, "transaction_violations", None):
        if summary.transaction_violations:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Transaction Integrity Violations"))
            rows = [["DNS ID", "Source", "Destination", "Time"]]
            for item in summary.transaction_violations[:limit]:
                rows.append(
                    [
                        str(item.get("id", "-")),
                        str(item.get("src", "-")),
                        str(item.get("dst", "-")),
                        format_ts(item.get("ts")),
                    ]
                )
            lines.append(_format_table(rows))

    if getattr(summary, "amplification_candidates", None):
        if summary.amplification_candidates:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Amplification Candidates"))
            rows = [["Client", "Resolver", "Query Bytes", "Response Bytes", "Ratio"]]
            for item in summary.amplification_candidates[:limit]:
                rows.append(
                    [
                        str(item.get("client", "-")),
                        str(item.get("resolver", "-")),
                        str(item.get("query_bytes", "-")),
                        str(item.get("response_bytes", "-")),
                        str(item.get("ratio", "-")),
                    ]
                )
            lines.append(_format_table(rows))

    if getattr(summary, "timeline", None):
        if summary.timeline:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Attack Timeline"))
            rows = [["Time", "Event", "Summary", "Details"]]
            for item in summary.timeline[:limit]:
                rows.append(
                    [
                        format_ts(item.get("ts")),
                        str(item.get("event", "-")),
                        _truncate_text(
                            _redact_in_text(str(item.get("summary", "-"))), 56
                        ),
                        _truncate_text(
                            _redact_in_text(str(item.get("details", "-"))), 90
                        ),
                    ]
                )
            lines.append(_format_table(rows))

    if getattr(summary, "benign_context", None):
        if summary.benign_context:
            lines.append(SUBSECTION_BAR)
            lines.append(header("False-Positive Context"))
            for item in summary.benign_context[: _limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(str(item))}"))

    if summary.base_domain_answers:
        candidates = [
            (name, answers)
            for name, answers in summary.base_domain_answers.items()
            if len(answers) > 1
        ]
        if candidates:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Answer Variability (Base Domain)"))
            rows = [["Domain", "Unique Answers", "Sample"]]
            for name, answers in sorted(
                candidates, key=lambda item: len(item[1]), reverse=True
            )[:limit]:
                sample = ", ".join(sorted(list(answers))[: _limit_value(3)])
                if len(answers) > _limit_value(3):
                    sample += "..."
                rows.append([name, str(len(answers)), sample or "-"])
            lines.append(_format_table(rows))

    if summary.local_unicast_qname_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Unicast Local TLD Queries"))
        lines.append(_counter_table(summary.local_unicast_qname_counts, "QName", limit=limit))

    if summary.ot_keyword_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT/ICS Keywords"))
        lines.append(_counter_table(summary.ot_keyword_counts, "Keyword", limit=limit))

    if summary.ot_qname_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT/ICS Hostname Indicators"))
        lines.append(_counter_table(summary.ot_qname_counts, "QName", limit=limit))

    if summary.zone_transfer_requests:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Zone Transfer Requests"))
        samples = ", ".join(sorted(summary.zone_transfer_requests)[: _limit_value(20)])
        lines.append(muted(samples or "-"))

    if summary.txt_query_names:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TXT Query Names"))
        samples = ", ".join(sorted(summary.txt_query_names)[: _limit_value(20)])
        lines.append(muted(samples or "-"))

    if summary.vt_results:
        vt_hits = [
            item
            for item in summary.vt_results.values()
            if int(item.get("score", 0) or 0) > 0
        ]
        lines.append(SUBSECTION_BAR)
        lines.append(header("VirusTotal Reputation"))
        if vt_hits:
            rows = [["Domain", "Score", "Rating", "Reputation", "Last Analysis"]]
            for item in sorted(
                vt_hits,
                key=lambda entry: int(entry.get("score", 0) or 0),
                reverse=True,
            )[:limit]:
                last_seen = (
                    format_ts(item.get("last_analysis_date"))
                    if item.get("last_analysis_date")
                    else "-"
                )
                rows.append(
                    [
                        str(item.get("domain", "-")),
                        str(item.get("score", "-")),
                        str(item.get("rating", "-")),
                        str(item.get("reputation", "-")),
                        last_seen,
                    ]
                )
            lines.append(_format_table(rows))
        else:
            lines.append(
                muted("No malicious/suspicious VirusTotal hits in sampled domains.")
            )

    if summary.llmnr_packets:
        lines.append(SUBSECTION_BAR)
        lines.append(header("LLMNR Clients"))
        rows = [["Client", "Queries"]]
        for name, count in summary.llmnr_client_counts.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

        lines.append(SUBSECTION_BAR)
        lines.append(header("LLMNR Servers"))
        rows = [["Server", "Responses"]]
        for name, count in summary.llmnr_server_counts.most_common(limit):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))
    _render_mdns_section()

    if summary.packet_length_stats:
        lines.append(SUBSECTION_BAR)
        lines.append(header("DNS Packet Length Analysis"))
        total_packets = summary.total_packets or sum(
            int(item.get("count", 0) or 0) for item in summary.packet_length_stats
        )

        def _bucket_range(label: str) -> tuple[int, int | None]:
            if label.endswith("+"):
                try:
                    return int(label[:-1]), None
                except Exception:
                    return 0, None
            if "-" in label:
                low_text, high_text = label.split("-", 1)
                try:
                    return int(low_text), int(high_text)
                except Exception:
                    return 0, 0
            return 0, 0

        short_total = 0
        long_total = 0
        dominant_bucket = None
        dominant_pct = 0.0
        outlier_rows: list[list[str]] = []
        count_threshold = max(50, int(total_packets * 0.25)) if total_packets else 50

        for item in summary.packet_length_stats:
            bucket_label = str(item.get("bucket", "-"))
            count = int(item.get("count", 0) or 0)
            pct = (count / total_packets * 100) if total_packets else 0.0
            low, high = _bucket_range(bucket_label)
            is_short = high is not None and high <= 100
            is_long = low >= 1201
            notes: list[str] = []
            if is_short:
                short_total += count
                notes.append("very short")
            if is_long:
                long_total += count
                notes.append("very long")
            if pct >= 40.0:
                notes.append("dominant")
            elif count >= count_threshold:
                notes.append("high count")
            if pct > dominant_pct:
                dominant_pct = pct
                dominant_bucket = bucket_label
            if notes:
                outlier_rows.append(
                    [
                        bucket_label,
                        str(count),
                        f"{pct:.1f}%",
                        ", ".join(notes),
                        f"{item.get('burst_rate', 0):.0f}",
                        format_ts(item.get("burst_start"))
                        if item.get("burst_start")
                        else "-",
                    ]
                )

        if total_packets:
            short_pct = (short_total / total_packets * 100) if total_packets else 0.0
            long_pct = (long_total / total_packets * 100) if total_packets else 0.0
            lines.append(
                _format_kv(
                    "Very Short DNS Packets (<=100B)",
                    f"{short_total} ({short_pct:.1f}%)",
                )
            )
            lines.append(
                _format_kv(
                    "Very Large DNS Packets (>=1201B)",
                    f"{long_total} ({long_pct:.1f}%)",
                )
            )
            if dominant_bucket:
                lines.append(
                    _format_kv(
                        "Dominant Size Bucket",
                        f"{dominant_bucket} ({dominant_pct:.1f}%)",
                    )
                )

        if outlier_rows:
            lines.append("")
            lines.append(muted("Outlier Buckets"))
            rows = [["Size Bucket", "Count", "%", "Note", "Burst Rate", "Burst Start"]]
            rows.extend(outlier_rows)
            lines.append(_format_table(rows))

        lines.append("")
        rows = [
            [
                "Size Bucket",
                "Count",
                "Avg",
                "Min",
                "Max",
                "Rate(pkt/s)",
                "%",
                "Burst Rate",
                "Burst Start",
            ]
        ]
        for item in summary.packet_length_stats:
            rows.append(
                [
                    str(item.get("bucket", "-")),
                    str(item.get("count", "-")),
                    f"{item.get('avg', 0):.1f}",
                    str(item.get("min", "-")),
                    str(item.get("max", "-")),
                    f"{item.get('rate', 0):.2f}",
                    f"{item.get('pct', 0):.1f}%",
                    f"{item.get('burst_rate', 0):.0f}",
                    format_ts(item.get("burst_start"))
                    if item.get("burst_start")
                    else "-",
                ]
            )
        lines.append(_format_table(rows))
        lines.append("")
        lines.append(
            muted(
                f"Distribution Sparkline: {sparkline([int(item.get('count', 0) or 0) for item in summary.packet_length_stats])}"
            )
        )

    if summary.multicast_streams:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Multicast Streams Summary"))
        rows = [
            [
                "Group",
                "Proto",
                "Port",
                "Packets",
                "Bytes",
                "Sources",
                "First Seen",
                "Last Seen",
            ]
        ]
        for item in summary.multicast_streams:
            sources = item.get("sources", [])
            source_text = ", ".join(f"{ip}({count})" for ip, count in sources)
            rows.append(
                [
                    str(item.get("group", "-")),
                    str(item.get("protocol", "-")),
                    str(item.get("port", "-")),
                    str(item.get("count", "-")),
                    format_bytes_as_mb(int(item.get("bytes", 0))),
                    source_text or "-",
                    format_ts(item.get("first_seen")),
                    format_ts(item.get("last_seen")),
                ]
            )
        lines.append(_format_table(rows))

    if verbose and summary.qname_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("DNS Artifacts"))
        qnames = ", ".join(
            name for name, _count in summary.qname_counts.most_common(_limit_value(25))
        )
        lines.append(f"Observed QNames: {qnames}")

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
            severity = item.get("severity", "info")
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity == "warning":
                marker = warn("[WARN]")
            elif severity == "critical":
                marker = danger("[CRIT]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  Details: {details}"))
            top_clients = item.get("top_clients")
            if top_clients:
                client_text = ", ".join(f"{ip}({count})" for ip, count in top_clients)
                lines.append(muted(f"  Clients: {client_text}"))
            top_servers = item.get("top_servers")
            if top_servers:
                server_text = ", ".join(f"{ip}({count})" for ip, count in top_servers)
                lines.append(muted(f"  Servers: {server_text}"))

            artifacts = item.get("artifacts")
            if isinstance(artifacts, list) and artifacts:
                lines.append(muted("  Artifacts:"))
                for art in artifacts[: _limit_value(8)]:
                    lines.append(muted(f"    {str(art)}"))
                if len(artifacts) > _limit_value(8):
                    lines.append(
                        muted(f"    ... {len(artifacts) - _limit_value(8)} more")
                    )

            evidence = item.get("evidence")
            if isinstance(evidence, list) and evidence:
                lines.append(muted("  Evidence:"))
                for ev in evidence[: _limit_value(8)]:
                    lines.append(muted(f"    {str(ev)}"))
                if len(evidence) > _limit_value(8):
                    lines.append(
                        muted(f"    ... {len(evidence) - _limit_value(8)} more")
                    )

            vt_findings = item.get("vt_findings")
            if isinstance(vt_findings, list) and vt_findings:
                lines.append(
                    muted(
                        "  VirusTotal (target | benign | suspicious | malicious | report):"
                    )
                )
                for entry in vt_findings[: _limit_value(12)]:
                    target = str(entry.get("domain") or entry.get("target", "-"))
                    benign = int(entry.get("harmless", 0) or 0)
                    suspicious = int(entry.get("suspicious", 0) or 0)
                    malicious = int(entry.get("malicious", 0) or 0)
                    report = str(entry.get("report_url", "-"))
                    vt_line = (
                        f"{target} | {benign} | {suspicious} | {malicious} | {report}"
                    )
                    if malicious > 0:
                        lines.append(danger(f"    {vt_line}"))
                    elif suspicious > 0:
                        lines.append(warn(f"    {vt_line}"))
                    else:
                        lines.append(ok(f"    {vt_line}"))
                if len(vt_findings) > _limit_value(12):
                    lines.append(
                        muted(f"    ... {len(vt_findings) - _limit_value(12)} more")
                    )

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
