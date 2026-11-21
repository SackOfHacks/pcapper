"""Rendered output for --files: every file seen crossing the wire (SMB,
HTTP, FTP, SMTP, TFTP ...) with its type, size, flow and host, executables
and type/extension mismatches first; hashes on request (-hash), extracted
files, lineage and clusters follow. The scored assessment and the analyzer's
signal lists are -v."""

from __future__ import annotations

from collections import Counter
from typing import Any

from ..coloring import danger_bg, orange
from ..files import FileTransferSummary
from ..utils import decode_payload, hexdump
from . import _style as st
from ._common import _redact_in_text, _render_deterministic_checks, _verbose_output, set_verbose_output
from ._kv import counter_line, findings_for

_EXECUTABLE_TYPES = {"EXE/DLL", "ELF"}
_TYPE_EXTENSIONS = {
    "EXE/DLL": {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"},
    "PDF": {".pdf"},
    "ZIP/Office": {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".odt", ".ods", ".odp", ".docm", ".xlsm", ".pptm"},
    "ELF": {".elf", ".so", ".bin", ".out"},
    "PNG": {".png"},
    "JPG": {".jpg", ".jpeg"},
    "GIF": {".gif"},
    "GZIP": {".gz", ".tgz", ".gzip"},
    "HTML": {".html", ".htm", ".xhtml", ".shtml"},
    "X509": {".cer", ".crt", ".pem", ".der", ".p7b", ".pfx", ".p12"},
    "DICOM": {".dcm"},
}


def _mismatch(item: Any) -> bool:
    ftype = getattr(item, "file_type", "UNKNOWN")
    name = str(item.filename or "")
    if ftype not in _TYPE_EXTENSIONS or name == "http_response.bin" or name.startswith("extracted_"):
        return False
    return not any(name.lower().endswith(ext) for ext in _TYPE_EXTENSIONS[ftype])


def _assessment(summary: FileTransferSummary) -> tuple[str, str, int, list[str]]:
    checks = getattr(summary, "deterministic_checks", {}) or {}
    detections = list(getattr(summary, "detections", []) or [])
    score = 0
    reasons: list[str] = []
    for key, weight in {"multi_signal_masquerade": 3, "archive_container_abuse": 3, "macro_script_lolbas_staging": 3,
                        "known_malware_filename": 3, "internal_executable_staging": 2, "exfiltration_file_movement": 3,
                        "lateral_copy_propagation": 4, "auth_file_correlation": 2, "reputation_or_prevalence_outlier": 1,
                        "reconstruction_confidence": 1}.items():
        n = len([v for v in (checks.get(key, []) if isinstance(checks, dict) else []) or [] if str(v).strip()])
        if n:
            score += min(4, weight + min(2, n - 1))
            reasons.append(f"{key.replace('_', ' ')} evidence ({n})")

    def _weight(d: dict) -> int:
        try:
            return max(1, int(d.get("occurrences", 1) or 1))
        except (TypeError, ValueError):
            return 1

    high = sum(_weight(d) for d in detections if str(d.get("severity", "")).lower() in {"high", "critical"})
    warn = sum(_weight(d) for d in detections if str(d.get("severity", "")).lower() == "warning")
    if high:
        score += min(3, high)
        reasons.append(f"high-severity file detections ({high})")
    if warn >= 2:
        score += 1
        reasons.append(f"multiple warning-level file detections ({warn})")
    if score >= 8:
        return "YES - high-confidence malicious file activity", "High", score, reasons
    if score >= 5:
        return "LIKELY - suspicious file activity with compromise indicators", "Medium", score, reasons
    if score >= 2:
        return "POSSIBLE - risky file-transfer behavior; corroboration recommended", "Low", score, reasons
    return "NO STRONG SIGNAL from the current heuristics", "Low", score, reasons


def _display_artifacts(summary: FileTransferSummary) -> list[tuple[Any, int, int]]:
    """(artifact, occurrences, first packet). A multi-capture rollup collapses
    identical rows into one with a count."""
    if not st.is_rollup(summary):
        return [(a, 1, int(getattr(a, "packet_index", 0) or 0)) for a in summary.artifacts]
    buckets: dict[tuple, dict[str, Any]] = {}
    for a in summary.artifacts:
        key = (str(a.protocol or ""), str(a.filename or ""), str(getattr(a, "file_type", "") or ""), str(a.src_ip or ""),
               str(a.dst_ip or ""), str(getattr(a, "hostname", None) or "-"), str(getattr(a, "content_type", "-") or "-"),
               str(a.note or "-"), a.size_bytes)
        packet = int(getattr(a, "packet_index", 0) or 0)
        b = buckets.setdefault(key, {"item": a, "count": 0, "packet": packet})
        b["count"] += 1
        if b["packet"] <= 0 or (0 < packet < b["packet"]):
            b["packet"] = packet
    return [(b["item"], b["count"], b["packet"]) for b in buckets.values()]


def render_files_summary(
    summary: FileTransferSummary,
    limit: int | None = None,
    verbose: bool = False,
    show_hashes: bool = False,
    hash_filter: str | None = None,
) -> str:
    previous = _verbose_output()
    forced = bool(verbose and not previous)
    if forced:
        set_verbose_output(True)
    try:
        return _render(summary, limit, show_hashes, hash_filter)
    finally:
        if forced:
            set_verbose_output(previous)


def _render(summary: FileTransferSummary, limit: int | None, show_hashes: bool, hash_filter: str | None) -> str:
    rep = st.Report("Files", summary.path)
    findings = findings_for(summary, ot=False)
    hash_filter_active = bool(str(hash_filter or "").strip())
    artifacts = list(summary.artifacts or [])
    if not artifacts and not summary.extracted and not st.material(findings):
        return rep.absent("file transfers", summary.errors)
    executables = sum(1 for a in artifacts if getattr(a, "file_type", "") in _EXECUTABLE_TYPES)
    mismatches = sum(1 for a in artifacts if _mismatch(a))
    severity, text = st.verdict(findings, high="malicious file activity: investigate", medium="file activity to review",
                                clean=st.join(["no findings", st.plural(len(artifacts), "file")]))
    rep.headline(severity, text, st.join([
        st.plural(len(artifacts), "file"), st.bad(st.plural(executables, "executable")) if executables else "",
        st.caution(f"{mismatches} type/extension mismatch" + ("es" if mismatches != 1 else "")) if mismatches else "",
        f"{len(summary.extracted)} extracted" if summary.extracted else "",
        st.top(Counter(a.protocol for a in artifacts), 5),
    ]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    display = _display_artifacts(summary)
    if st.is_rollup(summary) and len(display) < len(artifacts):
        rep.note("MERGED", f"{len(artifacts) - len(display)} duplicate rows collapsed; counts are shown as ×N")
    if hash_filter_active:
        needle = str(hash_filter).strip().lower()
        display = [d for d in display if needle in str(d[0].filename or "").lower()]
        if not display:
            rep.note("NO MATCH", f"no discovered file matched -hash filter: {hash_filter}")

    def _interest(entry: tuple[Any, int, int]) -> tuple[int, int]:
        item = entry[0]
        flagged = getattr(item, "file_type", "") in _EXECUTABLE_TYPES or _mismatch(item)
        return (0 if flagged else 1, entry[2])

    rows = []
    for item, count, packet in sorted(display, key=_interest):
        ftype = getattr(item, "file_type", "UNKNOWN")
        name = str(item.filename)
        if ftype in _EXECUTABLE_TYPES:
            name, ftype = danger_bg(name), orange(ftype)
        elif ftype == "BINARY":
            name = orange(name)
        elif _mismatch(item):
            name = st.bad(name)
        note = str(item.note or "-") + (f" ×{count}" if count > 1 else "")
        rows.append([packet, item.protocol, name, ftype, st.size(item.size_bytes) if item.size_bytes is not None else "-",
                     st.flow(item.src_ip, item.dst_ip), getattr(item, "hostname", None) or "-", getattr(item, "content_type", "-") or "-",
                     note])
    rep.section("Files", st.table(
        ["Packet", "Proto", "Filename", "Type", "Size", "Flow", "Host", "Content type", "Note"], rows,
        align="rllllllll", widths=(None, None, 56, None, None, None, 32, 28, 40),
        max_rows=None if (st.verbose() or limit is None and len(rows) <= 25) else (limit or 25), noun="file",
    ))
    if show_hashes and not hash_filter_active:
        seen: set[str] = set()
        hash_rows = []
        for a in artifacts:
            md5, sha = getattr(a, "md5", None), getattr(a, "sha256", None)
            key = sha or md5
            if not key or key in seen:
                continue
            seen.add(key)
            hash_rows.append([a.filename, getattr(a, "file_type", "UNKNOWN"), st.size(a.size_bytes) if a.size_bytes is not None else "-",
                              md5 or "-", sha or "-"])
        rep.section("Hashes", st.table(["Filename", "Type", "Size", "MD5", "SHA-256"], hash_rows, max_rows=None, noun="file"))
    hashes = list(getattr(summary, "hashes", None) or [])
    rep.section("Requested hashes", st.table(
        ["Filename", "Proto", "Packet", "SHA-256", "MD5", "Imphash", "Flow"],
        [[h.get("filename", "-"), h.get("protocol", "-"), h.get("packet_index", "-"), h.get("sha256", "-"), h.get("md5", "-"),
          h.get("imphash", "-"), st.flow(h.get("src_ip", "-"), h.get("dst_ip", "-"))] for h in hashes], max_rows=None,
    ))
    rep.section("Extracted", st.bullets([st.good(str(p)) for p in summary.extracted or []], max_items=None))
    views: list[str] = []
    for item in summary.views or []:
        payload = item.get("payload")
        if not isinstance(payload, (bytes, bytearray)):
            continue
        size_note = f"({item.get('size')} bytes)"
        views.append(f"  {st.strong(str(item.get('filename', '')))} {st.dim(size_note)}")
        if item.get("raw"):
            text = decode_payload(bytes(payload), encoding="latin-1")
            views.append(text if text else st.dim("  <no printable text>"))
        else:
            views.append(hexdump(bytes(payload)))
    if views:
        raw_mode = any(bool(i.get("raw")) for i in summary.views)
        rep.section("File view (raw text)" if raw_mode else "File view (hex)", views)
    rep.section("Lineage", st.table(
        ["Source", "Steps", "Evidence"],
        [[c.get("src", "-"), "; ".join(str(x) for x in c.get("steps", []) or []), _redact_in_text(", ".join(str(x) for x in c.get("evidence", []) or []))]
         for c in (getattr(summary, "lineage_chains", None) or []) if isinstance(c, dict)],
        widths=(None, 70, 90), max_rows=8, noun="chain",
    ))
    rep.section("Incident clusters", st.table(
        ["Cluster", "Source", "Artifacts", "Findings", "Confidence"],
        [[c.get("cluster", "-"), c.get("src", "-"), c.get("artifacts", "-"), "; ".join(str(x) for x in c.get("findings", []) or []),
          c.get("confidence", "-")] for c in (getattr(summary, "incident_clusters", None) or []) if isinstance(c, dict)],
        widths=(None, None, None, 76), max_rows=8, noun="cluster",
    ))
    rep.section("Campaign indicators", st.table(
        ["Indicator", "Value", "Hosts"],
        [[c.get("indicator", "-"), _redact_in_text(str(c.get("value", "-"))), ", ".join(str(h) for h in c.get("hosts", []) or [])]
         for c in (getattr(summary, "campaign_indicators", None) or []) if isinstance(c, dict)], max_rows=8,
    ))

    verdict, confidence, score, reasons = _assessment(summary)
    rep.section("Assessment", st.kv([("Verdict", verdict), ("Confidence", f"{confidence} (score={score})")])
                + st.bullets([_redact_in_text(r) for r in reasons], max_items=None), detail=True)
    rep.section("Endpoints", st.kv([
        counter_line("Sources", Counter(a.src_ip for a in artifacts if a.src_ip), None),
        counter_line("Destinations", Counter(a.dst_ip for a in artifacts if a.dst_ip), None),
        counter_line("Filenames", Counter(a.filename for a in artifacts if a.filename), None),
        ("Candidates", str(getattr(summary, "total_candidates", "") or "")),
    ]), detail=True)
    for title, field in (("Reconstruction issues", "reconstruction_issues"), ("Masquerade signals", "masquerade_signals"),
                         ("Archive abuse", "archive_abuse_signals"), ("Exfil signals", "exfil_signals"),
                         ("Lateral copies", "lateral_copy_clusters"), ("Auth/file correlation", "auth_file_correlations")):
        items = []
        for entry in getattr(summary, field, None) or []:
            if isinstance(entry, dict):
                items.append("  ".join(f"{k}={', '.join(str(x) for x in v) if isinstance(v, (list, tuple, set)) else v}"
                                       for k, v in entry.items()))
            else:
                items.append(str(entry))
        rep.section(title, st.bullets([_redact_in_text(i) for i in items], max_items=None), detail=True)
    rep.section("False-positive context", st.bullets([_redact_in_text(str(n)) for n in (summary.benign_context or [])],
                                                     max_items=None), detail=True)
    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic Files Security Checks", [
            ("multi_signal_masquerade", "Multi-signal Masquerade"), ("macro_script_lolbas_staging", "Macro/Script/LOLBAS Staging"),
            ("known_malware_filename", "Known Malware/Tool Filename"), ("internal_executable_staging", "Internal Executable Staging"),
        ])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
