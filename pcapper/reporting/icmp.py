"""Rendered output for icmp analysis.

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
from ..icmp import IcmpSummary
from ..utils import (
    format_bytes_as_mb,
    format_ts,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _FULL_OUTPUT_LIMIT,
    _apply_verbose_limit,
    _counter_table,
    _filtered_detections,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
)


def render_icmp_summary(
    summary: IcmpSummary, limit: int = 12, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit) or limit

    def _icmpv4_type_name(type_id: int) -> str:
        return {
            0: "Echo Reply",
            3: "Destination Unreachable",
            4: "Source Quench",
            5: "Redirect",
            8: "Echo Request",
            9: "Router Advertisement",
            10: "Router Solicitation",
            11: "Time Exceeded",
            12: "Parameter Problem",
            13: "Timestamp",
            14: "Timestamp Reply",
            15: "Information Request",
            16: "Information Reply",
            17: "Address Mask Request",
            18: "Address Mask Reply",
        }.get(type_id, "Unknown")

    def _icmpv4_code_name(type_id: int, code_id: int) -> str:
        if type_id == 3:
            return {
                0: "Network Unreachable",
                1: "Host Unreachable",
                2: "Protocol Unreachable",
                3: "Port Unreachable",
                4: "Fragmentation Needed",
                5: "Source Route Failed",
                6: "Network Unknown",
                7: "Host Unknown",
                8: "Host Isolated",
                9: "Network Prohibited",
                10: "Host Prohibited",
                11: "Network Unreachable for TOS",
                12: "Host Unreachable for TOS",
                13: "Communication Prohibited",
                14: "Host Precedence Violation",
                15: "Precedence Cutoff",
            }.get(code_id, "Unknown")
        if type_id == 5:
            return {
                0: "Redirect for Network",
                1: "Redirect for Host",
                2: "Redirect for TOS and Network",
                3: "Redirect for TOS and Host",
            }.get(code_id, "Unknown")
        if type_id == 11:
            return {
                0: "TTL Exceeded in Transit",
                1: "Fragment Reassembly Time Exceeded",
            }.get(code_id, "Unknown")
        if type_id == 12:
            return {
                0: "Pointer Indicates Error",
                1: "Missing Required Option",
                2: "Bad Length",
            }.get(code_id, "Unknown")
        return "Unknown"

    def _icmpv6_type_name(type_id: int) -> str:
        return {
            1: "Destination Unreachable",
            2: "Packet Too Big",
            3: "Time Exceeded",
            4: "Parameter Problem",
            128: "Echo Request",
            129: "Echo Reply",
            133: "Router Solicitation",
            134: "Router Advertisement",
            135: "Neighbor Solicitation",
            136: "Neighbor Advertisement",
            137: "Redirect",
        }.get(type_id, "Unknown")

    def _icmpv6_code_name(type_id: int, code_id: int) -> str:
        if type_id == 1:
            return {
                0: "No Route to Destination",
                1: "Admin Prohibited",
                2: "Beyond Scope",
                3: "Address Unreachable",
                4: "Port Unreachable",
                5: "Source Address Failed Policy",
                6: "Reject Route",
            }.get(code_id, "Unknown")
        if type_id == 3:
            return {
                0: "Hop Limit Exceeded",
                1: "Fragment Reassembly Time Exceeded",
            }.get(code_id, "Unknown")
        if type_id == 4:
            return {
                0: "Erroneous Header Field",
                1: "Unrecognized Next Header",
                2: "Unrecognized IPv6 Option",
            }.get(code_id, "Unknown")
        return "Unknown"

    def _type_label(key: str) -> str:
        try:
            family, type_id = key.split(":", 1)
            type_num = int(type_id)
        except Exception:
            return key
        if family == "icmpv4":
            return f"ICMPv4 {_icmpv4_type_name(type_num)} ({type_num})"
        if family == "icmpv6":
            return f"ICMPv6 {_icmpv6_type_name(type_num)} ({type_num})"
        return key

    def _code_label(key: str) -> str:
        try:
            family, type_id, code_id = key.split(":", 2)
            type_num = int(type_id)
            code_num = int(code_id)
        except Exception:
            return key
        if family == "icmpv4":
            return f"ICMPv4 {_icmpv4_type_name(type_num)}: {_icmpv4_code_name(type_num, code_num)} ({type_num}/{code_num})"
        if family == "icmpv6":
            return f"ICMPv6 {_icmpv6_type_name(type_num)}: {_icmpv6_code_name(type_num, code_num)} ({type_num}/{code_num})"
        return key

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"ICMP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    lines.append(_format_kv("ICMP Packets", str(summary.total_packets)))
    lines.append(_format_kv("ICMP Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(_format_kv("ICMPv4", str(summary.ipv4_packets)))
    lines.append(_format_kv("ICMPv6", str(summary.ipv6_packets)))
    lines.append(_format_kv("First Seen", format_ts(summary.first_seen)))
    lines.append(_format_kv("Last Seen", format_ts(summary.last_seen)))
    lines.append(_format_kv("Avg Payload", f"{summary.avg_payload_bytes:.1f} bytes"))
    lines.append(_format_kv("Max Payload", f"{summary.max_payload_bytes} bytes"))
    lines.append(_format_kv("Payload Variants", str(summary.payload_size_variants)))
    if summary.duration_seconds:
        pps = (
            summary.total_packets / summary.duration_seconds
            if summary.duration_seconds
            else 0.0
        )
        lines.append(_format_kv("ICMP Rate", f"{pps:.1f} pkt/s"))

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

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    checks = dict(getattr(summary, "deterministic_checks", {}) or {})
    if checks:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Deterministic ICMP Security Checks"))
        check_labels = {
            "icmp_recon_sweep_behavior": "ICMP recon/sweep behavior",
            "icmp_control_plane_abuse": "ICMP control-plane abuse",
            "icmp_tunneling_signal": "ICMP tunneling/covert signal",
            "icmp_zone_boundary_exposure": "ICMP internet-boundary crossing",
        }
        for key, label_text in check_labels.items():
            values = [str(v) for v in list(checks.get(key, []) or [])]
            if values:
                lines.append(warn(f"[!] {label_text}: {len(values)}"))
                for item in values[: _limit_value(8)]:
                    lines.append(muted(f"  - {item}"))
            else:
                lines.append(ok(f"[ ] {label_text}: none"))


    asymmetry_profiles = list(getattr(summary, "asymmetry_profiles", []) or [])
    if asymmetry_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Asymmetry Matrix"))
        rows = [["Scope", "Requests", "Replies", "Reply Ratio", "Confidence"]]
        for profile in asymmetry_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("scope", "-")),
                    str(profile.get("requests", "-")),
                    str(profile.get("replies", "-")),
                    str(profile.get("reply_ratio", "-")),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    recon_profiles = list(getattr(summary, "recon_profiles", []) or [])
    if recon_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Recon Indicators"))
        rows = [["Source", "Targets", "Packets", "Confidence"]]
        for profile in recon_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("source", "-")),
                    str(profile.get("targets", "-")),
                    str(profile.get("packets", "-")),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    control_plane_profiles = list(getattr(summary, "control_plane_profiles", []) or [])
    if control_plane_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Control-Plane Abuse"))
        rows = [["Type", "Count", "Confidence"]]
        for profile in control_plane_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("type", "-")),
                    str(profile.get("count", "-")),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    fragmentation_profiles = list(getattr(summary, "fragmentation_profiles", []) or [])
    if fragmentation_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Fragmentation/Path-MTU Anomalies"))
        rows = [["Packet Too Big", "Fragmentation Related", "Confidence"]]
        for profile in fragmentation_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("packet_too_big", "-")),
                    str(profile.get("fragmentation_related", "-")),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    cadence_profiles = list(getattr(summary, "cadence_profiles", []) or [])
    if cadence_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Cadence Anomalies"))
        rows = [["Flow", "Packets", "Duration", "PPS", "Confidence"]]
        for profile in cadence_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("flow", "-")),
                    str(profile.get("packets", "-")),
                    str(profile.get("duration_s", "-")),
                    str(profile.get("pps", "-")),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    tunneling_profiles = list(getattr(summary, "tunneling_profiles", []) or [])
    if tunneling_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Encapsulation/Tunneling Suspicion"))
        rows = [["Entropy", "Size", "Count", "Preview", "Confidence"]]
        for profile in tunneling_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("entropy", "-")),
                    str(profile.get("size", "-")),
                    str(profile.get("count", "-")),
                    str(profile.get("preview", "-")),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    zone_profiles = list(getattr(summary, "zone_profiles", []) or [])
    if zone_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Zone Posture (East-West / North-South)"))
        rows = [["Src", "Dst", "Zone", "Packets", "Confidence"]]
        for profile in zone_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("src", "-")),
                    str(profile.get("dst", "-")),
                    str(profile.get("zone", "-")),
                    str(profile.get("packets", "-")),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    role_profiles = list(getattr(summary, "role_drift_profiles", []) or [])
    if role_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Role Drift by ICMP Behavior"))
        rows = [["Host", "Dst", "Packets", "Reason", "Confidence"]]
        for profile in role_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("host", "-")),
                    str(profile.get("dst", "-")),
                    str(profile.get("packets", "-")),
                    str(profile.get("reason", "-")),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    ot_profiles = list(getattr(summary, "ot_boundary_profiles", []) or [])
    if ot_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT Boundary Crossing Profiles"))
        rows = [["Src", "Dst", "Packets", "Confidence"]]
        for profile in ot_profiles[:limit]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("src", "-")),
                    str(profile.get("dst", "-")),
                    str(profile.get("packets", "-")),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    corroborated_findings = list(getattr(summary, "corroborated_findings", []) or [])
    if corroborated_findings:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Corroborated Findings"))
        rows = [["Host", "Score", "Confidence", "Reasons"]]
        for finding in corroborated_findings[:limit]:
            if not isinstance(finding, dict):
                continue
            rows.append(
                [
                    str(finding.get("host", "-")),
                    str(finding.get("score", "-")),
                    str(finding.get("confidence", "-")),
                    ", ".join(str(v) for v in list(finding.get("reasons", []) or []))
                    or "-",
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
        for item in false_positive_context[: _limit_value(8)]:
            lines.append(muted(f"- {item}"))

    if summary.type_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Types"))
        rows = [["Type", "Packets"]]
        for name, count in summary.type_counts.most_common(_FULL_OUTPUT_LIMIT):
            rows.append([_type_label(name), str(count)])
        lines.append(_format_table(rows))

    if summary.code_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Codes"))
        rows = [["Type:Code", "Packets"]]
        for name, count in summary.code_counts.most_common(_FULL_OUTPUT_LIMIT):
            rows.append([_code_label(name), str(count)])
        lines.append(_format_table(rows))

    if summary.request_counts or summary.response_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Requests & Responses"))
        rows = [["Category", "Requests", "Responses"]]
        categories = set(summary.request_counts.keys()).union(
            summary.response_counts.keys()
        )
        for name in sorted(categories):
            rows.append(
                [
                    name,
                    str(summary.request_counts.get(name, 0)),
                    str(summary.response_counts.get(name, 0)),
                ]
            )
        lines.append(_format_table(rows))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Conversations"))
        rows = [["Src", "Dst", "Proto", "Packets", "Bytes", "First Seen", "Last Seen"]]
        for convo in sorted(
            summary.conversations, key=lambda c: c.get("packets", 0), reverse=True
        ):
            rows.append(
                [
                    str(convo.get("src", "-")),
                    str(convo.get("dst", "-")),
                    str(convo.get("protocol", "-")),
                    str(convo.get("packets", "-")),
                    format_bytes_as_mb(int(convo.get("bytes", 0))),
                    format_ts(convo.get("first_seen")),
                    format_ts(convo.get("last_seen")),
                ]
            )
        lines.append(_format_table(rows))

    if summary.sessions:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Echo Sessions"))
        rows = [
            [
                "Src",
                "Dst",
                "ID",
                "Requests",
                "Replies",
                "Packets",
                "First Seen",
                "Last Seen",
            ]
        ]
        for sess in summary.sessions:
            rows.append(
                [
                    str(sess.get("src", "-")),
                    str(sess.get("dst", "-")),
                    str(sess.get("id", "-")),
                    str(sess.get("requests", "-")),
                    str(sess.get("replies", "-")),
                    str(sess.get("packets", "-")),
                    format_ts(sess.get("first_seen")),
                    format_ts(sess.get("last_seen")),
                ]
            )
        lines.append(_format_table(rows))

    if summary.payload_summaries:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Payload Summary"))
        rows = [
            [
                "Payload (cleartext preview)",
                "Count",
                "Size",
                "Entropy",
                "Top Sources",
                "Top Destinations",
            ]
        ]
        for item in summary.payload_summaries[:limit]:
            top_src = ", ".join(
                f"{ip}({count})" for ip, count in item.get("top_sources", [])
            )
            top_dst = ", ".join(
                f"{ip}({count})" for ip, count in item.get("top_destinations", [])
            )
            rows.append(
                [
                    str(item.get("payload_preview", "-")),
                    str(item.get("count", "-")),
                    str(item.get("size", "-")),
                    f"{item.get('entropy', 0):.2f}",
                    top_src or "-",
                    top_dst or "-",
                ]
            )
        lines.append(_format_table(rows))

    if verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Artifacts"))
        lines.append(
            f"Sources: {', '.join(sorted(summary.src_ips)) if summary.src_ips else '-'}"
        )
        lines.append(
            f"Destinations: {', '.join(sorted(summary.dst_ips)) if summary.dst_ips else '-'}"
        )
        if summary.src_ip_counts:
            top_sources = ", ".join(
                f"{ip}({count})"
                for ip, count in summary.src_ip_counts.most_common(_FULL_OUTPUT_LIMIT)
            )
            lines.append(f"Top Sources: {top_sources}")
        if summary.dst_ip_counts:
            top_dests = ", ".join(
                f"{ip}({count})"
                for ip, count in summary.dst_ip_counts.most_common(_FULL_OUTPUT_LIMIT)
            )
            lines.append(f"Top Destinations: {top_dests}")

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
            severity = item.get("severity", "info")
            summary_text = item.get("summary", "")
            details = item.get("details", "")
            if severity == "warning":
                marker = warn("[WARN]")
            elif severity == "critical":
                marker = danger("[CRIT]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ICMP Artifacts"))
        lines.append(muted(", ".join(summary.artifacts)))

    if summary.observed_users:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Users"))
        lines.append(_counter_table(summary.observed_users, "User", limit=_FULL_OUTPUT_LIMIT))

    if summary.files_discovered:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files Discovered"))
        lines.append(muted(", ".join(summary.files_discovered)))

    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)
