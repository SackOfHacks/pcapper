"""Rendered output for files analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from collections import Counter
from typing import Any
from ..coloring import (
    danger,
    danger_bg,
    header,
    label,
    muted,
    ok,
    orange,
    warn,
)
from ..files import FileTransferSummary
from ..utils import (
    decode_payload,
    format_bytes_as_mb,
    hexdump,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _apply_verbose_limit,
    _filtered_detections,
    _finalize_output,
    _format_kv,
    _format_table,
    _highlight_public_ips,
    _limit_value,
    _redact_in_text,
    _truncate_text,
    _verbose_output,
    set_verbose_output,
)


def render_files_summary(
    summary: FileTransferSummary,
    limit: int | None = None,
    verbose: bool = False,
    show_hashes: bool = False,
    hash_filter: str | None = None,
) -> str:
    # `-hash` with no filename lists every discovered file's hash; `-hash FILE`
    # narrows to the matching file(s), rendered by the "Requested File Hashes"
    # section below, so the all-files table is suppressed in that case.
    hash_filter_active = bool(str(hash_filter or "").strip())
    previous_verbose_state = _verbose_output()
    forced_verbose_state = bool(verbose and not previous_verbose_state)
    if forced_verbose_state:
        set_verbose_output(True)
    limit = _apply_verbose_limit(limit)
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"FILES OVERVIEW :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    effective_limit = limit if limit is not None else max(len(summary.artifacts), 0)

    def _files_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        detections = list(getattr(summary, "detections", []) or [])
        checks = getattr(summary, "deterministic_checks", {}) or {}

        def _occurrence_weight(item: dict[str, Any]) -> int:
            try:
                value = int(item.get("occurrences", 1) or 1)
            except Exception:
                value = 1
            return max(1, value)

        def _check_count(key: str) -> int:
            values = checks.get(key, []) if isinstance(checks, dict) else []
            return len([v for v in (values or []) if str(v).strip()])

        high_weight_checks = {
            "multi_signal_masquerade": 3,
            "archive_container_abuse": 3,
            "macro_script_lolbas_staging": 3,
            "exfiltration_file_movement": 3,
            "lateral_copy_propagation": 4,
            "auth_file_correlation": 2,
            "reputation_or_prevalence_outlier": 1,
            "reconstruction_confidence": 1,
        }
        for key, base_weight in high_weight_checks.items():
            count = _check_count(key)
            if not count:
                continue
            score += min(4, base_weight + min(2, count - 1))
            reasons.append(f"{key.replace('_', ' ')} evidence ({count})")

        high_findings = sum(
            _occurrence_weight(d)
            for d in detections
            if str(d.get("severity", "")).lower() in {"high", "critical"}
        )
        warn_findings = sum(
            _occurrence_weight(d)
            for d in detections
            if str(d.get("severity", "")).lower() == "warning"
        )
        if high_findings:
            score += min(3, high_findings)
            reasons.append(f"High-severity file detections observed ({high_findings})")
        if warn_findings >= 2:
            score += 1
            reasons.append(
                f"Multiple warning-level file detections observed ({warn_findings})"
            )

        if score >= 8:
            verdict = "YES - high-confidence malicious file activity is present."
            confidence = "High"
        elif score >= 5:
            verdict = "LIKELY - suspicious file activity with compromise indicators is present."
            confidence = "Medium"
        elif score >= 2:
            verdict = "POSSIBLE - risky file-transfer behavior is present; corroboration recommended."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing malicious file pattern from current heuristics."
            confidence = "Low"

        if not reasons:
            reasons.append("No high-confidence file threat heuristic crossed threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _files_verdict()
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

    if summary.artifacts:
        lines.append(muted("Who:"))
        lines.append(muted("- Top source hosts by artifact count"))
        src_counts = Counter(item.src_ip for item in summary.artifacts if item.src_ip)
        for ip, count in src_counts.most_common(_limit_value(6)):
            lines.append(muted(f"- {_highlight_public_ips(str(ip))}: {int(count)}"))

        lines.append(muted("Where:"))
        lines.append(muted("- Top destinations by artifact count"))
        dst_counts = Counter(item.dst_ip for item in summary.artifacts if item.dst_ip)
        for ip, count in dst_counts.most_common(_limit_value(6)):
            lines.append(muted(f"- {_highlight_public_ips(str(ip))}: {int(count)}"))

        lines.append(muted("What:"))
        lines.append(muted("- Top transferred filenames"))
        name_counts = Counter(
            item.filename for item in summary.artifacts if item.filename
        )
        for name, count in name_counts.most_common(_limit_value(6)):
            lines.append(muted(f"- {_redact_in_text(str(name))}: {int(count)}"))

    if getattr(summary, "incident_clusters", None):
        clusters = list(summary.incident_clusters or [])
        if clusters:
            lines.append(muted("When:"))
            lines.append(muted("- Incident cluster context"))
            for item in clusters[: _limit_value(4)]:
                lines.append(
                    muted(
                        f"- {_redact_in_text(str(item.get('cluster', '-')))} src={_highlight_public_ips(str(item.get('src', '-')))} "
                        f"findings={len(item.get('findings', []) if isinstance(item.get('findings', []), list) else [])}"
                    )
                )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Files Security Checks"))
    checks = getattr(summary, "deterministic_checks", {}) or {}
    check_labels = [
        ("multi_signal_masquerade", "Multi-signal Masquerade"),
        ("macro_script_lolbas_staging", "Macro/Script/LOLBAS Staging"),
    ]
    cleared_checks: list[str] = []
    fired_any = False
    for key, label_text in check_labels:
        evidence_items = checks.get(key, []) if isinstance(checks, dict) else []
        evidence_items = [str(v) for v in (evidence_items or []) if str(v).strip()]
        if evidence_items:
            fired_any = True
            lines.append(label(label_text))
            lines.append(
                warn(
                    f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"
                )
            )
            for item in evidence_items[: _limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))
        else:
            cleared_checks.append(label_text)
    # Collapse the (usually many) checks with no evidence into one line instead
    # of a wall of negatives.
    if not fired_any:
        lines.append(ok("No file-threat checks crossed threshold in this capture."))
    elif cleared_checks:
        lines.append(
            muted(f"Cleared (no evidence): {', '.join(cleared_checks)}")
        )

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Discovered Files"))

        def _collapse_files_artifacts_for_display() -> list[tuple[Any, int, int]]:
            if summary.path.name != "ALL_PCAPS":
                return [
                    (
                        item,
                        1,
                        int(getattr(item, "packet_index", 0) or 0),
                    )
                    for item in summary.artifacts
                ]

            buckets: dict[
                tuple[
                    str,
                    str,
                    str,
                    str,
                    str,
                    str,
                    str,
                    str,
                    int | None,
                ],
                dict[str, Any],
            ] = {}
            order: list[
                tuple[
                    str,
                    str,
                    str,
                    str,
                    str,
                    str,
                    str,
                    str,
                    int | None,
                ]
            ] = []

            for item in summary.artifacts:
                display_hostname = str(getattr(item, "hostname", None) or "-")
                display_content_type = str(getattr(item, "content_type", "-") or "-")
                display_note = str(getattr(item, "note", None) or "-")
                display_size = (
                    format_bytes_as_mb(item.size_bytes)
                    if item.size_bytes is not None
                    else "-"
                )
                key = (
                    str(getattr(item, "protocol", "") or ""),
                    str(getattr(item, "filename", "") or ""),
                    str(getattr(item, "file_type", "") or ""),
                    str(getattr(item, "src_ip", "") or ""),
                    str(getattr(item, "dst_ip", "") or ""),
                    display_hostname,
                    display_content_type,
                    display_note,
                    display_size,
                )
                packet_idx = int(getattr(item, "packet_index", 0) or 0)
                if key not in buckets:
                    buckets[key] = {
                        "item": item,
                        "count": 1,
                        "packet_index": packet_idx,
                    }
                    order.append(key)
                    continue

                bucket = buckets[key]
                bucket["count"] = int(bucket.get("count", 1)) + 1
                current_packet = int(bucket.get("packet_index", 0) or 0)
                if current_packet <= 0 or (
                    packet_idx > 0 and packet_idx < current_packet
                ):
                    bucket["packet_index"] = packet_idx

            return [
                (
                    buckets[key]["item"],
                    int(buckets[key]["count"]),
                    int(buckets[key]["packet_index"]),
                )
                for key in order
            ]

        display_artifacts = _collapse_files_artifacts_for_display()
        if summary.path.name == "ALL_PCAPS" and len(display_artifacts) < len(
            summary.artifacts
        ):
            collapsed = len(summary.artifacts) - len(display_artifacts)
            lines.append(
                muted(
                    f"Summarized view collapsed {collapsed} duplicate artifact row(s); occurrence counts are shown as [xN] in Note."
                )
            )

        # `-hash FILE` scopes the whole files view to the matching file(s): the
        # Discovered Files table is filtered by filename here, mirroring the
        # "Requested File Hashes" section so the two stay in sync.
        if hash_filter_active:
            needle = str(hash_filter).strip().lower()
            display_artifacts = [
                entry
                for entry in display_artifacts
                if needle in str(getattr(entry[0], "filename", "") or "").lower()
            ]
            if not display_artifacts:
                lines.append(
                    muted(f"No discovered files matched -hash filter: {hash_filter}")
                )

        # Define executable types and extension mappings
        executable_types = {"EXE/DLL", "ELF"}
        type_extensions = {
            "EXE/DLL": {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"},
            "PDF": {".pdf"},
            "ZIP/Office": {
                ".zip",
                ".docx",
                ".xlsx",
                ".pptx",
                ".jar",
                ".apk",
                ".odt",
                ".ods",
                ".odp",
                ".docm",
                ".xlsm",
                ".pptm",
            },
            "ELF": {".elf", ".so", ".bin", ".out"},
            "PNG": {".png"},
            "JPG": {".jpg", ".jpeg"},
            "GIF": {".gif"},
            "GZIP": {".gz", ".tgz", ".gzip"},
            "HTML": {".html", ".htm", ".xhtml", ".shtml"},
            "X509": {".cer", ".crt", ".pem", ".der", ".p7b", ".pfx", ".p12"},
            "DICOM": {".dcm"},
        }
        rows = [
            [
                "Protocol",
                "Filename",
                "Type",
                "Size",
                "Packet",
                "Src",
                "Dst",
                "Hostname",
                "Content Type",
                "Note",
            ]
        ]
        artifact_limit = limit if limit is not None else max(len(display_artifacts), 0)
        for item, seen_count, display_packet in display_artifacts[:artifact_limit]:
            size = (
                format_bytes_as_mb(item.size_bytes)
                if item.size_bytes is not None
                else "-"
            )
            # Fallback for old artifacts without file_type
            ftype = getattr(item, "file_type", "UNKNOWN")
            hostname = getattr(item, "hostname", None) or "-"

            # Apply coloring
            colored_filename = item.filename
            colored_ftype = ftype

            # Orange for executables (type) and red background for filenames
            if ftype in executable_types:
                colored_ftype = orange(ftype)
                colored_filename = danger_bg(item.filename)

            # Orange for BINARY filenames
            if ftype == "BINARY":
                colored_filename = orange(item.filename)

            # Red for extension mismatch
            if ftype in type_extensions:
                expected_exts = type_extensions[ftype]
                filename_lower = item.filename.lower()
                has_expected_ext = any(
                    filename_lower.endswith(ext) for ext in expected_exts
                )
                if (
                    not has_expected_ext
                    and item.filename != "http_response.bin"
                    and not item.filename.startswith("extracted_")
                ):
                    colored_filename = danger(item.filename)

            note_text = item.note or "-"
            if seen_count > 1:
                note_text = f"{note_text} [x{seen_count}]"

            rows.append(
                [
                    item.protocol,
                    colored_filename,
                    colored_ftype,
                    size,
                    str(display_packet),
                    item.src_ip,
                    item.dst_ip,
                    hostname,
                    getattr(item, "content_type", "-"),
                    note_text,
                ]
            )
        lines.append(_format_table(rows))

        # File hashes — the primary forensic/IR deliverable: copy-pasteable
        # MD5/SHA-256 for VirusTotal / threat-intel lookups and known-bad
        # matching. Deduplicated by hash so repeated transfers list once.
        # Only rendered when the user asked for hashes via -hash, keeping the
        # default --files output focused on the transfer inventory.
        hashed_seen: set[str] = set()
        hash_rows = [["Filename", "Type", "Size", "MD5", "SHA-256"]]
        for item in summary.artifacts:
            md5 = getattr(item, "md5", None)
            sha = getattr(item, "sha256", None)
            if not md5 and not sha:
                continue
            dedupe_key = sha or md5 or ""
            if dedupe_key in hashed_seen:
                continue
            hashed_seen.add(dedupe_key)
            hash_rows.append(
                [
                    _truncate_text(str(item.filename), 32),
                    getattr(item, "file_type", "UNKNOWN"),
                    (
                        format_bytes_as_mb(item.size_bytes)
                        if item.size_bytes is not None
                        else "-"
                    ),
                    md5 or "-",
                    sha or "-",
                ]
            )
        if show_hashes and not hash_filter_active and len(hash_rows) > 1:
            lines.append(SUBSECTION_BAR)
            lines.append(header("File Hashes (VirusTotal / threat-intel lookup)"))
            lines.append(_format_table(hash_rows))

    if getattr(summary, "lineage_chains", None):
        chains = list(summary.lineage_chains or [])
        if chains:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Artifact Lineage Chains"))
            rows = [["Source", "Steps", "Evidence"]]
            for item in chains[:effective_limit]:
                steps = item.get("steps", [])
                evidence = item.get("evidence", [])
                rows.append(
                    [
                        _highlight_public_ips(str(item.get("src", "-"))),
                        _truncate_text(
                            "; ".join(str(v) for v in steps[:3])
                            if isinstance(steps, list)
                            else str(steps),
                            70,
                        ),
                        _truncate_text(
                            ", ".join(_redact_in_text(str(v)) for v in evidence[:4])
                            if isinstance(evidence, list)
                            else _redact_in_text(str(evidence)),
                            90,
                        ),
                    ]
                )
            lines.append(_format_table(rows))

    if getattr(summary, "incident_clusters", None):
        clusters = list(summary.incident_clusters or [])
        if clusters:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Incident Clusters"))
            rows = [["Cluster", "Source", "Artifacts", "Findings", "Confidence"]]
            for item in clusters[:effective_limit]:
                findings = item.get("findings", [])
                rows.append(
                    [
                        str(item.get("cluster", "-")),
                        _highlight_public_ips(str(item.get("src", "-"))),
                        str(item.get("artifacts", "-")),
                        _truncate_text(
                            "; ".join(str(v) for v in findings[:3])
                            if isinstance(findings, list)
                            else str(findings),
                            76,
                        ),
                        str(item.get("confidence", "-")),
                    ]
                )
            lines.append(_format_table(rows))

    if getattr(summary, "campaign_indicators", None):
        campaigns = list(summary.campaign_indicators or [])
        if campaigns:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Shared Campaign Indicators"))
            rows = [["Indicator", "Value", "Hosts"]]
            for item in campaigns[:effective_limit]:
                hosts = item.get("hosts", [])
                host_text = (
                    ", ".join(_highlight_public_ips(str(v)) for v in hosts[:4])
                    if isinstance(hosts, list)
                    else "-"
                )
                rows.append(
                    [
                        _truncate_text(str(item.get("indicator", "-")), 42),
                        _truncate_text(
                            _redact_in_text(str(item.get("value", "-"))), 42
                        ),
                        _truncate_text(host_text or "-", 68),
                    ]
                )
            lines.append(_format_table(rows))

    if summary.extracted:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Extracted Files"))
        for path in summary.extracted:
            lines.append(ok(f"- {path}"))

    if summary.views:
        lines.append(SUBSECTION_BAR)
        raw_mode = any(bool(item.get("raw")) for item in summary.views)
        lines.append(
            header("File View (Raw Text)" if raw_mode else "File View (ASCII/HEX)")
        )
        for item in summary.views:
            filename = str(item.get("filename", ""))
            payload = item.get("payload")
            size = item.get("size")
            if isinstance(payload, (bytes, bytearray)):
                lines.append(label(f"{filename} ({size} bytes)"))
                if item.get("raw"):
                    text = decode_payload(bytes(payload), encoding="latin-1")
                    lines.append(text if text else muted("<no printable text>"))
                else:
                    lines.append(hexdump(bytes(payload)))

    if getattr(summary, "hashes", None):
        hash_rows = [
            ["Filename", "Protocol", "Packet", "SHA256", "MD5", "IMPHASH", "Flow"]
        ]
        for item in list(summary.hashes or [])[:effective_limit]:
            hash_rows.append(
                [
                    str(item.get("filename", "-")),
                    str(item.get("protocol", "-")),
                    str(item.get("packet_index", "-")),
                    str(item.get("sha256", "-")),
                    str(item.get("md5", "-")),
                    str(item.get("imphash", "-")),
                    f"{_highlight_public_ips(str(item.get('src_ip', '-')))}->{_highlight_public_ips(str(item.get('dst_ip', '-')))}",
                ]
            )
        if len(hash_rows) > 1:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Requested File Hashes"))
            lines.append(_format_table(hash_rows))

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
            severity = item.get("severity", "info")
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            top_sources = list(item.get("top_sources") or [])
            top_destinations = list(item.get("top_destinations") or [])
            evidence = [str(v) for v in list(item.get("evidence") or []) if str(v).strip()]
            if severity == "warning":
                marker = warn("[WARN]")
            elif severity == "critical":
                marker = danger("[CRIT]")
            elif severity == "high":
                marker = danger("[HIGH]")
            else:
                marker = ok("[INFO]")
            occurrence_suffix = ""
            try:
                occurrences = int(item.get("occurrences", 1) or 1)
            except Exception:
                occurrences = 1
            if occurrences > 1:
                occurrence_suffix = f" [x{occurrences}]"
            lines.append(f"{marker} {summary_text}{occurrence_suffix}")
            if details:
                lines.append(muted(f"  {details}"))
            if top_sources:
                src_text = ", ".join(f"{ip}({count})" for ip, count in top_sources[:5])
                lines.append(muted(f"  Top Sources: {src_text}"))
            if top_destinations:
                dst_text = ", ".join(
                    f"{ip}({count})" for ip, count in top_destinations[:5]
                )
                lines.append(muted(f"  Top Destinations: {dst_text}"))
            if evidence:
                lines.append(muted("  Evidence:"))
                for ev in evidence[: _limit_value(5)]:
                    lines.append(muted(f"    - {_redact_in_text(ev)}"))

    if getattr(summary, "benign_context", None):
        notes = [str(v) for v in (summary.benign_context or []) if str(v).strip()]
        if notes:
            lines.append(SUBSECTION_BAR)
            lines.append(header("False-Positive Context"))
            for note in notes[: _limit_value(8)]:
                lines.append(muted(f"- {_redact_in_text(note)}"))

    lines.append(SECTION_BAR)
    output = _finalize_output(lines, show_truncation_note=not verbose)
    if forced_verbose_state:
        set_verbose_output(previous_verbose_state)
    return output
