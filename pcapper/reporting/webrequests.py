"""Rendered output for webrequests analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
import ipaddress
import re
from ..coloring import (
    danger,
    header,
    label,
    muted,
)
from ..utils import (
    format_ts,
)
from ..webrequests import WebRequestSummary

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _apply_verbose_limit,
    _finalize_output,
    _format_counter,
    _format_kv,
    _format_table,
    _limit_value,
    _truncate_text,
)


def render_webrequests_summary(
    summary: WebRequestSummary,
    limit: int = 15,
    verbose: bool = False,
    view: str = "minimal",
) -> str:
    limit = _apply_verbose_limit(limit) or limit
    view_mode = str(view or "minimal").strip().lower()
    if view_mode not in {"minimal", "simple", "full"}:
        view_mode = "minimal"

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"WEB REQUESTS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors if verbose else summary.errors[: _limit_value(12)]:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("Scope", summary.target_ip if summary.scoped else "ALL"))
    if str(getattr(summary, "search_query", "") or "").strip():
        lines.append(_format_kv("Search Filter", str(summary.search_query)))
    lines.append(_format_kv("HTTP Packets", str(summary.http_packets)))
    lines.append(_format_kv("Matched Requests", str(summary.matched_requests)))
    lines.append(_format_kv("Suspicious Requests", str(summary.suspicious_requests)))

    if summary.method_counts:
        lines.append(_format_kv("Methods", _format_counter(summary.method_counts, 8)))
    if summary.host_counts:
        lines.append(
            _format_kv("Top Hosts", _format_counter(summary.host_counts, 6, key_max=50))
        )
    if (
        getattr(summary, "vt_lookup_enabled", False)
        or getattr(summary, "vt_results", None)
        or getattr(summary, "vt_errors", None)
    ):
        lines.append(_format_kv("VT Lookup Enabled", "Yes" if summary.vt_lookup_enabled else "No"))
        lines.append(_format_kv("VT Enriched Domains", str(len(summary.vt_results or {}))))

    if summary.vt_results:
        lines.append(SUBSECTION_BAR)
        lines.append(header("VirusTotal Reputation"))
        rows = [["Domain", "Mal", "Susp", "Rep", "Report"]]
        ranked = sorted(
            summary.vt_results.items(),
            key=lambda item: (
                int(item[1].get("malicious", 0) or 0),
                int(item[1].get("suspicious", 0) or 0),
                int(item[1].get("reputation", 0) or 0),
            ),
            reverse=True,
        )
        display_rows = ranked if verbose else ranked[: _limit_value(12)]
        for domain, info in display_rows:
            malicious = int(info.get("malicious", 0) or 0)
            suspicious = int(info.get("suspicious", 0) or 0)
            if not verbose and malicious <= 0 and suspicious <= 0:
                continue
            rows.append(
                [
                    _truncate_text(domain, 42),
                    str(malicious),
                    str(suspicious),
                    str(info.get("reputation", "-")),
                    _truncate_text(str(info.get("report_url", "-")), 74),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))
        else:
            lines.append(muted("No malicious/suspicious VirusTotal hits in sampled domains."))

    if summary.requests:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Requests"))

        rows: list[list[str]]
        if view_mode == "minimal":
            rows = [
                [
                    "Time",
                    "Packet",
                    "Method",
                    "Request",
                    "Remote",
                    "Status",
                    "Referer",
                    "User Agent",
                ]
            ]
            for item in summary.requests if verbose else summary.requests[:limit]:
                status = "-"
                if item.response_code is not None:
                    status = str(item.response_code)
                    if item.response_name and item.response_name != "-":
                        status = f"{status} {item.response_name}"
                referer = str(item.headers.get("referer", "") or "-")
                user_agent = str(item.headers.get("user-agent", "") or "-")
                rows.append(
                    [
                        format_ts(item.ts),
                        str(item.packet_number),
                        item.method,
                        _truncate_text(f"{item.host}{item.uri}", 62),
                        f"{item.dst_ip}:{item.dst_port or '-'}",
                        status,
                        _truncate_text(referer, 44),
                        _truncate_text(user_agent, 56),
                    ]
                )
        elif view_mode == "simple":
            rows = [
                ["Time", "Packet", "Method", "Host", "URI", "Src", "Dst", "Status", "Risk"]
            ]
            for item in summary.requests if verbose else summary.requests[:limit]:
                status = "-"
                if item.response_code is not None:
                    status = str(item.response_code)
                rows.append(
                    [
                        format_ts(item.ts),
                        str(item.packet_number),
                        item.method,
                        _truncate_text(item.host or "-", 28),
                        _truncate_text(item.uri or "-", 44),
                        f"{item.src_ip}:{item.src_port or '-'}",
                        f"{item.dst_ip}:{item.dst_port or '-'}",
                        status,
                        f"{item.risk_level} ({item.risk_score})",
                    ]
                )
        else:
            detailed_items = summary.requests if verbose else summary.requests[:limit]
            for idx, item in enumerate(detailed_items, start=1):
                status = "-"
                if item.response_code is not None:
                    status = str(item.response_code)
                    if item.response_name and item.response_name != "-":
                        status = f"{status} {item.response_name}"
                reason_text = (
                    ", ".join(item.risk_reasons[:3]) if item.risk_reasons else "-"
                )
                request_target = f"{item.host}{item.uri}" if item.host else item.uri
                lines.append(
                    label(
                        f"[{idx}] {format_ts(item.ts)} {item.method} "
                        f"{_truncate_text(request_target or '-', 120)}"
                    )
                )
                lines.append(
                    _format_kv(
                        "Flow",
                        f"{item.src_ip}:{item.src_port or '-'} -> {item.dst_ip}:{item.dst_port or '-'}",
                    )
                )
                lines.append(_format_kv("Packet", str(item.packet_number)))
                lines.append(
                    _format_kv(
                        "Request Line",
                        item.request_line
                        or f"{item.method} {item.uri} HTTP/{item.http_version}",
                    )
                )
                lines.append(_format_kv("Status", status))
                lines.append(_format_kv("Risk", f"{item.risk_level} ({item.risk_score})"))
                lines.append(_format_kv("Reasons", reason_text))
                if item.response_location:
                    lines.append(_format_kv("Location", item.response_location))

                if item.params:
                    param_text = ", ".join(
                        f"{k}={v}" if v else f"{k}="
                        for k, v in item.params[: _limit_value(15)]
                    )
                    lines.append(_format_kv("Query Params", _truncate_text(param_text, 180)))

                headers = dict(item.headers or {})
                if headers:
                    lines.append("Headers:")
                    preferred_order = [
                        "host",
                        "referer",
                        "user-agent",
                        "content-type",
                        "content-length",
                        "origin",
                        "cookie",
                        "authorization",
                    ]
                    seen_header_keys: set[str] = set()
                    for key in preferred_order:
                        value = str(headers.get(key, "") or "").strip()
                        if not value:
                            continue
                        seen_header_keys.add(key)
                        lines.append(
                            muted(f"  {key}: {_truncate_text(value, 220 if verbose else 140)}")
                        )
                    for key in sorted(headers.keys()):
                        if key in seen_header_keys:
                            continue
                        value = str(headers.get(key, "") or "").strip()
                        if not value:
                            continue
                        lines.append(
                            muted(f"  {key}: {_truncate_text(value, 220 if verbose else 140)}")
                        )

                body_text = str(item.body or "")
                if body_text:
                    max_chars = 6000 if verbose else 1500
                    clipped = body_text[:max_chars]
                    lines.append("Body:")
                    body_lines = clipped.splitlines() or [clipped]
                    max_lines = 200 if verbose else 60
                    for body_line in body_lines[:max_lines]:
                        lines.append(muted(f"  {body_line}"))
                    if len(body_text) > max_chars or len(body_lines) > max_lines:
                        lines.append(
                            muted(
                                f"  ... truncated body ({len(body_text)} chars total)"
                            )
                        )
                if idx < len(detailed_items):
                    lines.append("")

        if view_mode in {"minimal", "simple"}:
            lines.append(_format_table(rows))
        if not verbose and len(summary.requests) > limit:
            lines.append(muted(f"... {len(summary.requests) - limit} more requests"))

        def _host_is_ip_literal(host_value: str) -> bool:
            text = str(host_value or "").strip()
            if not text:
                return False
            if text.startswith("[") and "]" in text:
                text = text[1 : text.index("]")]
            elif ":" in text and text.count(":") == 1:
                candidate, maybe_port = text.rsplit(":", 1)
                if maybe_port.isdigit():
                    text = candidate
            try:
                ipaddress.ip_address(text)
                return True
            except Exception:
                return False

        exe_re = re.compile(r"(?i)\.(exe|elf|dll|sys|msi|scr|jar|apk|bin)(?:$|[?#])")
        interesting_rows: list[tuple[object, list[str], str]] = []
        for item in summary.requests:
            reasons: list[str] = []
            request_target = f"{item.host or ''}{item.uri or ''}"
            if exe_re.search(item.uri or "") or exe_re.search(
                item.response_location or ""
            ):
                reasons.append("executable-target")
            if _host_is_ip_literal(item.host or ""):
                reasons.append("host-is-ip")
            if not reasons:
                continue
            request_text = f"{item.host}{item.uri}" if item.host else item.uri
            interesting_rows.append(
                (
                    item,
                    reasons,
                    _truncate_text(request_text or request_target or "-", 72),
                )
            )

        if interesting_rows:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Interesting Requests"))
            rows = [["Time", "Method", "Request", "Remote", "Status", "Reasons"]]
            max_rows = max(limit, 8)
            for item, reasons, req_text in interesting_rows[:max_rows]:
                status = "-"
                if item.response_code is not None:
                    status = str(item.response_code)
                    if item.response_name and item.response_name != "-":
                        status = f"{status} {item.response_name}"
                rows.append(
                    [
                        format_ts(item.ts),
                        item.method,
                        req_text,
                        f"{item.dst_ip}:{item.dst_port or '-'}",
                        status,
                        ", ".join(reasons),
                    ]
                )
            lines.append(_format_table(rows))
            if len(interesting_rows) > max_rows:
                lines.append(
                    muted(
                        f"... {len(interesting_rows) - max_rows} more interesting requests"
                    )
                )

    else:
        lines.append(SUBSECTION_BAR)
        lines.append(muted("No web requests matched current scope."))

    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)
