"""Rendered output for timeline analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
import ipaddress
import re
from collections import Counter
from typing import TYPE_CHECKING
from ..coloring import (
    danger,
    danger_bg,
    header,
    label,
    muted,
    ok,
    orange,
    suspicious_bg,
)
from ..timeline import TimelineSummary
from ..utils import (
    format_duration,
    format_ts,
    sparkline,
)
if TYPE_CHECKING:
    from ..timeline import TimelineEvent

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _apply_verbose_limit,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
    _redact_in_text,
    _truncate_text,
)


def render_timeline_summary(
    summary: TimelineSummary, limit: int = 200, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit) or limit

    def _mal(text: str) -> str:
        return danger_bg(text)

    def _sus(text: str) -> str:
        return suspicious_bg(text)

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"TIMELINE :: {summary.target_ip} :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("Events", str(len(summary.events))))
    if summary.first_seen is not None or summary.last_seen is not None:
        lines.append(_format_kv("First Seen", format_ts(summary.first_seen)))
        lines.append(_format_kv("Last Seen", format_ts(summary.last_seen)))
    if summary.duration is not None:
        lines.append(_format_kv("Duration", f"{summary.duration:.1f}s"))
    if summary.ot_risk_score:
        risk_level = "LOW"
        if summary.ot_risk_score >= 60:
            risk_level = "HIGH"
        elif summary.ot_risk_score >= 25:
            risk_level = "MEDIUM"
        score_text = f"{summary.ot_risk_score}/100 ({risk_level})"
        lines.append(_format_kv("OT Risk Posture", score_text))
        if summary.ot_risk_findings:
            lines.append(muted("Findings:"))
            for finding in summary.ot_risk_findings:
                lines.append(muted(f"- {finding}"))
    if summary.ot_storyline:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT Attack Storyline"))
        for line in summary.ot_storyline:
            lines.append(muted(f"- {line}"))

    # The timeline's analyst-verdict enrichment is currently disabled (the
    # builder returns no verdict), so only render this block when a verdict is
    # actually present -- otherwise it printed a fixed "NO STRONG SIGNAL"
    # pseudo-verdict on every capture, which misleadingly implies the timeline
    # was assessed and cleared. The timeline itself is the forensic artifact.
    if summary.analyst_verdict:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Analyst Verdict"))
        verdict_text = summary.analyst_verdict
        confidence_text = (summary.analyst_confidence or "low").strip().lower()
        if verdict_text.startswith("YES"):
            lines.append(_mal(verdict_text))
        elif verdict_text.startswith("LIKELY") or verdict_text.startswith("POSSIBLE"):
            lines.append(_sus(verdict_text))
        else:
            lines.append(ok(verdict_text))
        lines.append(_format_kv("Confidence", confidence_text.capitalize()))
        if summary.analyst_reasons:
            lines.append(muted("Why confidence:"))
            for reason in summary.analyst_reasons[: _limit_value(10 if verbose else 6)]:
                lines.append(muted(f"- {_redact_in_text(str(reason))}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Timeline Security Checks"))
    checks = summary.deterministic_checks or {}

    def _style_timeline_artifact_line(text: str) -> str:
        lowered = str(text or "").lower()
        malicious_tokens = (
            "malware",
            "ransomware",
            "c2",
            "command-and-control",
            ".exe",
            ".dll",
            ".ps1",
            ".vbs",
            ".bat",
            ".scr",
            "credential theft",
            "payload",
        )
        suspicious_tokens = (
            "exfiltration",
            "exfil",
            "beacon",
            "lateral movement",
            "port scan",
            "brute force",
            "suspicious",
            "http post",
            "handshake incomplete",
            "final ack missing",
            "write command",
            "control command",
        )
        line = f"- {_redact_in_text(str(text))}"

        # Only apply alert styling to concrete artifact/evidence lines.
        artifact_markers = (
            "pkt=",
            "packet=",
            "packet ",
            "flow=",
            "src=",
            "dst=",
            "remote=",
            "domain=",
            "host=",
            "uri=",
            "sni=",
            "sha256=",
            "md5=",
            "http://",
            "https://",
            "tcp/",
            "udp/",
            "dns",
            "->",
        )
        has_artifact_marker = any(marker in lowered for marker in artifact_markers)
        if not has_artifact_marker:
            if re.search(r"\b(?:pkt|packet)\s*\d+\b", lowered):
                has_artifact_marker = True
            elif re.search(
                r"\b\d{1,3}(?:\.\d{1,3}){3}\b", lowered
            ) and any(token in lowered for token in suspicious_tokens + malicious_tokens):
                has_artifact_marker = True

        if not has_artifact_marker:
            return muted(line)

        if any(token in lowered for token in malicious_tokens):
            return _mal(line)
        if any(token in lowered for token in suspicious_tokens):
            return _sus(line)
        return muted(line)

    check_labels = [
        ("access_to_execution_sequence", "Access to Execution Sequence"),
        ("remote_execution_tooling", "Remote Execution Tooling"),
        ("cleartext_remote_admin", "Cleartext Remote Admin"),
        ("ot_impact_signal", "OT Impact Signal"),
        ("evidence_provenance", "Evidence Provenance"),
    ]
    for key, label_text in check_labels:
        evidence_items = [
            str(v) for v in list(checks.get(key, []) or []) if str(v).strip()
        ]
        lines.append(label(label_text))
        if evidence_items:
            lines.append(
                f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"
            )
            for item in evidence_items[: _limit_value(8 if verbose else 5)]:
                lines.append(_style_timeline_artifact_line(item))
        else:
            lines.append(
                ok(
                    f"No, there is no strong evidence for {label_text.lower()} in this capture."
                )
            )

    sequence_rows = list(getattr(summary, "sequence_timeline", []) or [])
    if sequence_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Sequence Plausibility Timeline"))
        rows = [["Stage", "First Seen", "Last Seen", "Count", "Dwell", "Evidence"]]
        for item in sequence_rows[: _limit_value(20 if verbose else 10)]:
            evidence = item.get("evidence", [])
            if isinstance(evidence, list):
                evidence_text = " | ".join(str(v) for v in evidence[:3])
            else:
                evidence_text = str(evidence)
            rows.append(
                [
                    str(item.get("stage", "-")),
                    format_ts(item.get("first_ts")),
                    format_ts(item.get("last_ts")),
                    str(item.get("count", "-")),
                    format_duration(item.get("dwell")),
                    _truncate_text(evidence_text or "-", 70),
                ]
            )
        lines.append(_format_table(rows))

    if summary.sequence_violations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Sequence Violations"))
        for item in summary.sequence_violations[: _limit_value(10 if verbose else 6)]:
            lines.append(_style_timeline_artifact_line(str(item)))

    beacon_rows = list(getattr(summary, "beacon_candidates", []) or [])
    if beacon_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Beaconing Candidates"))
        rows = [
            [
                "Peer",
                "Category",
                "Signal",
                "Count",
                "Mean Interval",
                "Jitter",
                "CV",
                "Confidence",
            ]
        ]
        for item in beacon_rows[: _limit_value(12 if verbose else 8)]:
            rows.append(
                [
                    str(item.get("peer", "-")),
                    str(item.get("category", "-")),
                    _truncate_text(str(item.get("summary", "-")), 32),
                    str(item.get("count", "-")),
                    f"{item.get('mean_interval', '-')}s",
                    f"{item.get('jitter', '-')}s",
                    str(item.get("cv", "-")),
                    str(item.get("confidence", "-")).upper(),
                ]
            )
        lines.append(_format_table(rows))

    auth_rows = list(getattr(summary, "auth_abuse_profiles", []) or [])
    if auth_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Authentication Abuse Profiles"))
        rows = [["Source", "Target", "Attempts", "Target Count", "Confidence"]]
        for item in auth_rows[: _limit_value(12 if verbose else 8)]:
            rows.append(
                [
                    str(item.get("src", "-")),
                    str(item.get("dst", "-")),
                    str(item.get("attempts", "-")),
                    str(item.get("target_count", "-")),
                    str(item.get("confidence", "-")).upper(),
                ]
            )
        lines.append(_format_table(rows))

    lateral_rows = list(getattr(summary, "lateral_movement_paths", []) or [])
    if lateral_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Lateral Movement Paths"))
        rows = [["Source", "Peers", "Admin Hits", "Top Peers", "Confidence"]]
        for item in lateral_rows[: _limit_value(12 if verbose else 8)]:
            peers = item.get("peers", [])
            peer_text = (
                ", ".join(str(v) for v in peers[:4])
                if isinstance(peers, list)
                else str(peers)
            )
            rows.append(
                [
                    str(item.get("src", "-")),
                    str(item.get("peer_count", "-")),
                    str(item.get("admin_hits", "-")),
                    _truncate_text(peer_text or "-", 48),
                    str(item.get("confidence", "-")).upper(),
                ]
            )
        lines.append(_format_table(rows))

    exfil_rows = list(getattr(summary, "exfiltration_chains", []) or [])
    if exfil_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Exfiltration Chain Signals"))
        for item in exfil_rows[: _limit_value(14 if verbose else 8)]:
            lines.append(_style_timeline_artifact_line(str(item.get("signal", "-"))))

    ot_impact_rows = list(getattr(summary, "ot_impact_signals", []) or [])
    if ot_impact_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT Impact Signals"))
        rows = [["Protocol", "Summary", "Timestamp", "Details"]]
        for item in ot_impact_rows[: _limit_value(14 if verbose else 8)]:
            rows.append(
                [
                    str(item.get("protocol", "-")),
                    _truncate_text(str(item.get("summary", "-")), 32),
                    format_ts(item.get("ts")),
                    _truncate_text(_redact_in_text(str(item.get("details", "-"))), 80),
                ]
            )
        lines.append(_format_table(rows))

    benign_rows = list(getattr(summary, "benign_context", []) or [])
    if benign_rows:
        lines.append(SUBSECTION_BAR)
        lines.append(header("False-Positive Context"))
        for item in benign_rows[: _limit_value(10 if verbose else 6)]:
            lines.append(muted(f"- {_redact_in_text(str(item))}"))

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    def _severity_for_event(item: TimelineEvent) -> str:
        text = f"{item.summary} {item.details}".lower()
        # Inbound remote-access TO the target (SSH/RDP/etc.) is high-risk -- the
        # entry point for an IT->OT pivot. External source escalates to critical
        # (red); internal source is high (suspicious highlight).
        if item.category == "Remote IN":
            return "malicious" if "critical" in text else "suspicious"
        if "handshake incomplete" in text or "final ack missing" in text:
            return "suspicious"
        if "potential port scan" in text:
            return "suspicious"
        if "http post" in text:
            return "suspicious"
        if "file artifact" in text:
            if any(
                token in text
                for token in [
                    "(exe/dll)",
                    "(archive)",
                    ".exe",
                    ".dll",
                    ".ps1",
                    ".vbs",
                    ".bat",
                    ".scr",
                    ".js",
                ]
            ):
                return "malicious"
            return "suspicious"
        if "tcp connect attempt" in text:
            for port in (445, 3389, 22, 23, 135, 139, 5985, 5986):
                if f":{port}" in text:
                    return "suspicious"
        if any(
            token in text
            for token in (
                "write",
                "control",
                "start",
                "stop",
                "setpoint",
                "program",
                "firmware",
                "writevar",
                "vartabwrite",
                "plcstop",
                "plchotstart",
                "plccoldstart",
                "requestdownload",
                "downloadblock",
                "startupload",
                "uploadblock",
                "cpupassword",
                "setclock",
            )
        ):
            if item.category in {
                "Modbus",
                "DNP3",
                "IEC-104",
                "S7",
                "CIP",
                "ENIP",
                "BACnet",
                "OPC UA",
                "PROFINET",
            }:
                return "suspicious"
        return "info"

    def _highlight_c2_payload_file_artifact(text: str) -> str:
        return text.replace(
            "[C2] [Payload] File artifact", _sus("[C2] [Payload] File artifact")
        )

    def _highlight_ips(text: str, target_ip: str) -> str:
        tokens = text.split()
        for idx, token in enumerate(tokens):
            stripped = token.strip("[](),;|")
            candidate = stripped
            if ":" in candidate and not candidate.startswith("["):
                host_part, port_part = candidate.rsplit(":", 1)
                if port_part.isdigit():
                    candidate = host_part
            if candidate == target_ip:
                continue
            try:
                ip = ipaddress.ip_address(candidate)
            except Exception:
                continue
            if ip.is_private:
                tokens[idx] = token.replace(stripped, orange(stripped))
            elif ip.is_global:
                tokens[idx] = token.replace(stripped, danger(stripped))
            else:
                tokens[idx] = token.replace(stripped, ok(stripped))
        return " ".join(tokens)

    def _extract_ips(text: str) -> list[str]:
        candidates: list[str] = []
        for token in re.split(r"[\s,;()\[\]{}<>]", text):
            if not token:
                continue
            value = token.strip(".,;:|")
            if ":" in value and not value.startswith("[") and value.count(":") == 1:
                host_part, port_part = value.rsplit(":", 1)
                if port_part.isdigit():
                    value = host_part
            value = value.strip("[]")
            try:
                ipaddress.ip_address(value)
            except Exception:
                continue
            candidates.append(value)
        return candidates

    def _dns_base_domain(name: str) -> str:
        parts = [part for part in str(name).strip(".").split(".") if part]
        if len(parts) >= 2:
            return ".".join(parts[-2:]).lower()
        return str(name).strip(".").lower()

    def _timeline_vt_info(name: str) -> dict[str, object] | None:
        if not summary.vt_results:
            return None
        key = str(name or "").strip(".").lower()
        if not key:
            return None
        info = summary.vt_results.get(key)
        if info is None:
            info = summary.vt_results.get(_dns_base_domain(key))
        if not isinstance(info, dict):
            return None
        return info

    vt_malicious_domains: set[str] = set()
    vt_suspicious_domains: set[str] = set()
    vt_malicious_ips: set[str] = set()
    vt_suspicious_ips: set[str] = set()
    for key, info in dict(summary.vt_results or {}).items():
        if not isinstance(info, dict):
            continue
        domain = str(info.get("domain", key) or key).strip(".").lower()
        if not domain:
            continue
        malicious = int(info.get("malicious", 0) or 0)
        suspicious = int(info.get("suspicious", 0) or 0)
        score = int(info.get("score", 0) or 0)
        if malicious > 0:
            vt_malicious_domains.add(domain)
        elif suspicious > 0 or score > 0:
            vt_suspicious_domains.add(domain)

        ip_candidates: set[str] = set()
        for field_name in ("ips", "resolved_ips"):
            values = info.get(field_name)
            if isinstance(values, list):
                for value in values:
                    ip_text = str(value or "").strip()
                    try:
                        ipaddress.ip_address(ip_text)
                    except Exception:
                        continue
                    ip_candidates.add(ip_text)
        records = info.get("last_dns_records")
        if isinstance(records, list):
            for record in records:
                if not isinstance(record, dict):
                    continue
                ip_text = str(record.get("value", "") or "").strip()
                try:
                    ipaddress.ip_address(ip_text)
                except Exception:
                    continue
                ip_candidates.add(ip_text)
        if malicious > 0:
            vt_malicious_ips.update(ip_candidates)
        elif suspicious > 0 or score > 0:
            vt_suspicious_ips.update(ip_candidates)

    def _extract_domains(text: str) -> list[str]:
        if not text:
            return []
        hits = re.findall(
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b",
            text,
        )
        ordered: list[str] = []
        seen: set[str] = set()
        for value in hits:
            lowered = value.strip(".").lower()
            if not lowered or lowered in seen:
                continue
            seen.add(lowered)
            ordered.append(lowered)
        return ordered

    def _highlight_vt_artifacts(text: str) -> str:
        if not text:
            return text
        if not (
            vt_malicious_domains
            or vt_suspicious_domains
            or vt_malicious_ips
            or vt_suspicious_ips
        ):
            return text

        highlighted = text

        # Highlight URL hosts first so full URLs stand out by VT risk.
        for match in re.finditer(
            r"https?://[^\s)\]>]+", highlighted, flags=re.IGNORECASE
        ):
            token = match.group(0)
            host = re.sub(r"^https?://", "", token, flags=re.IGNORECASE)
            host = host.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
            host = host.split("@", 1)[-1].split(":", 1)[0].strip(".[]").lower()
            if (
                host in vt_malicious_domains
                or _dns_base_domain(host) in vt_malicious_domains
            ):
                highlighted = highlighted.replace(token, _mal(token))
            elif (
                host in vt_suspicious_domains
                or _dns_base_domain(host) in vt_suspicious_domains
            ):
                highlighted = highlighted.replace(token, _sus(token))

        # Highlight standalone domains.
        for domain in _extract_domains(highlighted):
            if (
                domain in vt_malicious_domains
                or _dns_base_domain(domain) in vt_malicious_domains
            ):
                highlighted = re.sub(
                    rf"\b{re.escape(domain)}\b",
                    _mal(domain),
                    highlighted,
                    flags=re.IGNORECASE,
                )
            elif (
                domain in vt_suspicious_domains
                or _dns_base_domain(domain) in vt_suspicious_domains
            ):
                highlighted = re.sub(
                    rf"\b{re.escape(domain)}\b",
                    _sus(domain),
                    highlighted,
                    flags=re.IGNORECASE,
                )

        # Highlight IPs if VT provided resolved/risky addresses.
        for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", highlighted):
            try:
                ip_text = str(ipaddress.ip_address(match))
            except Exception:
                continue
            if ip_text in vt_malicious_ips:
                highlighted = re.sub(
                    rf"\b{re.escape(match)}\b", _mal(match), highlighted
                )
            elif ip_text in vt_suspicious_ips:
                highlighted = re.sub(
                    rf"\b{re.escape(match)}\b", _sus(match), highlighted
                )

        return highlighted

    def _highlight_executable_artifacts(text: str) -> str:
        if not text:
            return text
        pattern = re.compile(
            r"\b[\w./\\-]+\.(?:exe|elf|dll|sys|bin|scr|msi|apk|dmg|pkg|jar)\b",
            re.IGNORECASE,
        )
        return pattern.sub(lambda match: _mal(match.group(0)), text)

    def _vt_event_match(text: str) -> tuple[str, int, int, int, str] | None:
        best: tuple[str, int, int, int, str] | None = None
        for domain in _extract_domains(text):
            info = _timeline_vt_info(domain)
            if not info:
                continue
            malicious = int(info.get("malicious", 0) or 0)
            suspicious = int(info.get("suspicious", 0) or 0)
            score = int(info.get("score", 0) or 0)
            rating = str(info.get("rating", "-") or "-")
            candidate = (domain, score, malicious, suspicious, rating)
            if best is None:
                best = candidate
                continue
            if (candidate[2], candidate[3], candidate[1]) > (best[2], best[3], best[1]):
                best = candidate
        return best

    def _event_tags(item: TimelineEvent) -> list[str]:
        text = f"{item.category} {item.summary} {item.details}".lower()
        tags: list[str] = []
        if any(
            token in text
            for token in (
                "scan",
                "recon",
                "probe",
                "enumeration",
                "icmp",
                "arp",
                "nbns",
                "mdns",
            )
        ):
            tags.append("Recon")
        if any(
            token in text
            for token in ("dns", "hostname", "domain", "netbios", "whoami", "ipconfig")
        ):
            tags.append("Discovery")
        if any(
            token in text
            for token in (
                "auth",
                "login",
                "credential",
                "ntlm",
                "kerberos",
                "password",
                "cpupassword",
            )
        ):
            tags.append("Credential")
        if any(
            token in text
            for token in (
                "smb",
                "rdp",
                "winrm",
                "wmic",
                "ssh",
                "rpc",
                "lateral",
            )
        ):
            tags.append("Lateral")
        if any(
            token in text
            for token in (
                "powershell",
                "cmd.exe",
                "rundll32",
                "regsvr32",
                "mshta",
                "bitsadmin",
                "wmic",
                "schtasks",
                "msiexec",
            )
        ):
            tags.append("Execution")
            tags.append("LOLBAS")
        if any(token in text for token in ("beacon", "c2", "command and control")):
            tags.append("C2")
        if any(
            token in text
            for token in ("exfil", "tunnel", "dns txt", "http post", "upload")
        ):
            tags.append("Exfil")
        if any(
            token in text
            for token in (
                "write",
                "writevar",
                "vartabwrite",
                "setpoint",
                "operate",
                "trip",
                "shutdown",
                "stop",
                "start",
                "plcstop",
                "plchotstart",
                "plccoldstart",
                "requestdownload",
                "downloadblock",
                "startupload",
                "uploadblock",
                "setclock",
            )
        ) and item.category in {
            "Modbus",
            "DNP3",
            "IEC-104",
            "S7",
            "CIP",
            "ENIP",
            "BACnet",
            "OPC UA",
            "PROFINET",
            "Triconex/SIS",
        }:
            tags.append("OT Control")
        if any(token in text for token in ("dos", "flood", "impact", "disruption")):
            tags.append("Impact")
        if any(
            token in text
            for token in (".exe", ".dll", ".ps1", ".vbs", ".bat", ".scr", ".js")
        ):
            tags.append("Payload")
        if not tags:
            return []
        # Deduplicate while preserving order
        seen: set[str] = set()
        ordered: list[str] = []
        for tag in tags:
            if tag in seen:
                continue
            seen.add(tag)
            ordered.append(tag)
        return ordered[:3]

    if summary.dns_queries:
        lines.append(SUBSECTION_BAR)
        lines.append(header("DNS Queries Performed"))
        dns_rows = summary.dns_queries
        for item in dns_rows:
            qtype = item.qtype or "-"
            port = item.dst_port if item.dst_port is not None else "-"
            detail = f"{item.src_ip} -> {item.dst_ip}:{port} {item.protocol}"
            detail = _highlight_ips(_redact_in_text(detail), summary.target_ip)
            vt_info = _timeline_vt_info(item.name)
            vt_suffix = ""
            if vt_info:
                vt_score = int(vt_info.get("score", 0) or 0)
                vt_rating = str(vt_info.get("rating", "-") or "-")
                vt_mal = int(vt_info.get("malicious", 0) or 0)
                vt_sus = int(vt_info.get("suspicious", 0) or 0)
                vt_suffix = f" VT(score={vt_score} rating={vt_rating} sus={vt_sus} mal={vt_mal})"
            query_text = (
                f"- {format_ts(item.ts)} {item.name} (type {qtype}) {detail}{vt_suffix}"
            )
            if vt_info and int(vt_info.get("malicious", 0) or 0) > 0:
                lines.append(_mal(query_text))
            elif vt_info and (
                int(vt_info.get("suspicious", 0) or 0) > 0
                or int(vt_info.get("score", 0) or 0) > 0
            ):
                lines.append(_sus(query_text))
            else:
                lines.append(muted(query_text))

    if summary.vt_lookup_enabled or summary.vt_results or summary.vt_errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("VirusTotal Enrichment"))
        lines.append(
            _format_kv(
                "VT Lookup Enabled", "Yes" if summary.vt_lookup_enabled else "No"
            )
        )
        lines.append(
            _format_kv("VT Enriched Domains", str(len(summary.vt_results or {})))
        )
        if summary.vt_results:
            rows = [
                ["Domain", "Score", "Rating", "Suspicious", "Malicious", "Reputation"]
            ]
            vt_items = sorted(
                summary.vt_results.items(),
                key=lambda item: (
                    int(item[1].get("malicious", 0) or 0),
                    int(item[1].get("suspicious", 0) or 0),
                    int(item[1].get("score", 0) or 0),
                ),
                reverse=True,
            )
            for domain, info in vt_items:
                rows.append(
                    [
                        str(domain),
                        str(info.get("score", "-")),
                        str(info.get("rating", "-")),
                        str(info.get("suspicious", "-")),
                        str(info.get("malicious", "-")),
                        str(info.get("reputation", "-")),
                    ]
                )
            lines.append(_format_table(rows))
        if summary.vt_errors:
            lines.append(muted("VT errors:"))
            for err in summary.vt_errors:
                lines.append(_sus(f"- {err}"))

    scoped_downloads = [
        item
        for item in list(summary.file_downloads or [])
        if str(getattr(item, "dst_ip", "") or "") == str(summary.target_ip)
    ]
    if scoped_downloads:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Files Downloaded"))
        file_rows = scoped_downloads
        for item in file_rows:
            size_text = (
                f"{item.size_bytes} bytes" if item.size_bytes is not None else "-"
            )
            meta_bits = []
            if getattr(item, "packet_number", None) is not None:
                meta_bits.append(f"pkt={item.packet_number}")
            if item.hostname:
                meta_bits.append(f"host={item.hostname}")
            if item.content_type:
                meta_bits.append(f"type={item.content_type}")
            if item.sha256:
                meta_bits.append(f"sha256={item.sha256}")
            elif item.md5:
                meta_bits.append(f"md5={item.md5}")
            meta_text = " ".join(meta_bits)
            detail = f"{item.src_ip} -> {item.dst_ip} {item.protocol} {size_text}"
            detail = _highlight_ips(_redact_in_text(detail), summary.target_ip)
            line = f"- {format_ts(item.ts)} {item.filename} ({item.file_type}) {detail}"
            if meta_text:
                line = f"{line} {meta_text}"
            lines.append(muted(line))

    def _is_high_value_ot_action(item: TimelineEvent) -> bool:
        if item.category not in {
            "Modbus",
            "DNP3",
            "IEC-104",
            "S7",
            "CIP",
            "ENIP",
            "BACnet",
            "OPC UA",
            "PROFINET",
            "Triconex/SIS",
        }:
            return False
        text = f"{item.summary} {item.details}".lower()
        if any(
            token in text
            for token in (
                "write",
                "writevar",
                "vartabwrite",
                "setpoint",
                "operate",
                "trip",
                "shutdown",
                "plcstop",
                "plchotstart",
                "plccoldstart",
                "requestdownload",
                "downloadblock",
                "startupload",
                "uploadblock",
                "cpupassword",
                "setclock",
                "security",
                "error response",
                "failed",
                "disconnect request",
            )
        ):
            return True
        if "anomaly" in text:
            return True
        return False

    high_value_events: list[TimelineEvent] = []
    high_seen: set[tuple[object, ...]] = set()
    for event in summary.events:
        if not _is_high_value_ot_action(event):
            continue
        key = (
            event.category,
            event.summary,
            event.details,
            int(float(event.ts) * 1000.0) if event.ts is not None else None,
        )
        if key in high_seen:
            continue
        high_seen.add(key)
        high_value_events.append(event)
        if len(high_value_events) >= _limit_value(18 if verbose else 12):
            break

    if high_value_events:
        lines.append(SUBSECTION_BAR)
        lines.append(header("High-Value OT Actions"))
        for event in high_value_events:
            detail_text = _highlight_ips(_redact_in_text(event.details), summary.target_ip)
            meta_bits: list[str] = []
            if event.source and event.source != "timeline":
                meta_bits.append(f"source={event.source}")
            if event.packet_index is not None:
                meta_bits.append(f"pkt={event.packet_index}")
            if meta_bits:
                detail_text = f"{detail_text} [{' '.join(meta_bits)}]"
            lines.append(
                muted(
                    f"- {format_ts(event.ts)} {event.category} {event.summary} | {detail_text}"
                )
            )

    event_limit = min(len(summary.events), int(limit))
    lines.append(SUBSECTION_BAR)
    lines.append(header("Activity Timeline"))
    lines.append(muted("Time | Category | Summary | Details"))
    tag_counts: Counter[str] = Counter()
    last_event_by_actor: dict[str, tuple[float, str, str]] = {}
    for event in summary.events[:event_limit]:
        severity = _severity_for_event(event)
        summary_text = event.summary
        vt_match = _vt_event_match(f"{event.summary} {event.details}")
        if vt_match is not None:
            vt_domain, vt_score, vt_malicious, vt_suspicious, vt_rating = vt_match
            summary_text = f"[VT:{vt_domain} score={vt_score} rating={vt_rating} sus={vt_suspicious} mal={vt_malicious}] {summary_text}"
            if vt_malicious > 0:
                severity = "malicious"
            elif vt_suspicious > 0 or vt_score > 0:
                severity = "suspicious"
        tags = _event_tags(event)
        for tag in tags:
            tag_counts[tag] += 1
        if tags:
            summary_text = f"[{'] ['.join(tags)}] {summary_text}"
        if severity == "malicious":
            summary_text = _mal(summary_text)
        elif severity == "suspicious":
            summary_text = _sus(summary_text)
        summary_text = _highlight_c2_payload_file_artifact(summary_text)
        details_text = _highlight_ips(_redact_in_text(event.details), summary.target_ip)
        actor_ip = None
        if event.ts is not None:
            ips = _extract_ips(event.details)
            if ips:
                if summary.target_ip in ips and len(ips) > 1:
                    actor_ip = next((ip for ip in ips if ip != summary.target_ip), None)
                else:
                    actor_ip = ips[0]
            if actor_ip:
                prev = last_event_by_actor.get(actor_ip)
                if prev:
                    prev_ts, prev_cat, prev_summary = prev
                    dt = float(event.ts) - float(prev_ts)
                    if 0 <= dt <= 600:
                        link = f"linked to {prev_cat}: {_truncate_text(prev_summary, max_len=48)} (+{dt:.0f}s)"
                        details_text = f"{details_text} | {link}"
                last_event_by_actor[actor_ip] = (
                    float(event.ts),
                    event.category,
                    event.summary,
                )
        meta_bits: list[str] = []
        if event.source and event.source != "timeline":
            meta_bits.append(f"source={event.source}")
        if event.packet_index is not None:
            meta_bits.append(f"pkt={event.packet_index}")
        if meta_bits:
            details_text = f"{details_text} [{' '.join(meta_bits)}]"
        lines.append(
            f"{format_ts(event.ts)} | {event.category} | {summary_text} | {details_text}"
        )

    if summary.category_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Category Overview"))
        categories = sorted(
            summary.category_counts.items(), key=lambda item: (-item[1], item[0])
        )
        for name, count in categories:
            lines.append(muted(f"- {name}: {count}"))

    if tag_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Kill-Chain Tags"))
        for tag, count in tag_counts.most_common():
            lines.append(muted(f"- {tag}: {count}"))

    if summary.ot_protocol_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT Protocols Seen"))
        for name, count in sorted(
            summary.ot_protocol_counts.items(), key=lambda item: (-item[1], item[0])
        ):
            lines.append(muted(f"- {name}: {count}"))

    if summary.ot_activity_bins:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT Activity Sparklines"))
        for name, bins in sorted(
            summary.ot_activity_bins.items(), key=lambda item: (-sum(item[1]), item[0])
        ):
            graph = sparkline(bins)
            lines.append(muted(f"- {name}: {graph} ({sum(bins)})"))

    for idx, line in enumerate(lines):
        if line == SECTION_BAR or line == SUBSECTION_BAR:
            continue
        rendered_line = _highlight_executable_artifacts(line)
        if summary.vt_lookup_enabled or summary.vt_results:
            rendered_line = _highlight_vt_artifacts(rendered_line)
        lines[idx] = rendered_line

    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)
