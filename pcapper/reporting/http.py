"""Rendered output for http analysis.

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
from ..http import HttpSummary
from ..utils import (
    format_duration,
    format_ts,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _apply_verbose_limit,
    _conv_value,
    _counter_table,
    _filtered_detections,
    _finalize_output,
    _format_kv,
    _format_sessions_table,
    _format_table,
    _highlight_public_ips,
    _limit_value,
    _redact_in_text,
    _truncate_text,
)


_HTTP_STATUS_TEXT = {
    100: "Continue",
    101: "Switching Protocols",
    102: "Processing",
    103: "Early Hints",
    200: "OK",
    201: "Created",
    202: "Accepted",
    203: "Non-Authoritative Information",
    204: "No Content",
    205: "Reset Content",
    206: "Partial Content",
    207: "Multi-Status",
    208: "Already Reported",
    226: "IM Used",
    300: "Multiple Choices",
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    304: "Not Modified",
    305: "Use Proxy",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    400: "Bad Request",
    401: "Unauthorized",
    402: "Payment Required",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    407: "Proxy Authentication Required",
    408: "Request Timeout",
    409: "Conflict",
    410: "Gone",
    411: "Length Required",
    412: "Precondition Failed",
    413: "Payload Too Large",
    414: "URI Too Long",
    415: "Unsupported Media Type",
    416: "Range Not Satisfiable",
    417: "Expectation Failed",
    418: "I'm a Teapot",
    421: "Misdirected Request",
    422: "Unprocessable Entity",
    423: "Locked",
    424: "Failed Dependency",
    425: "Too Early",
    426: "Upgrade Required",
    428: "Precondition Required",
    429: "Too Many Requests",
    431: "Request Header Fields Too Large",
    451: "Unavailable For Legal Reasons",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
    505: "HTTP Version Not Supported",
    506: "Variant Also Negotiates",
    507: "Insufficient Storage",
    508: "Loop Detected",
    510: "Not Extended",
    511: "Network Authentication Required",
}


def _http_status_text(value: object) -> str:
    try:
        code = int(str(value).strip())
    except Exception:
        return "-"
    return _HTTP_STATUS_TEXT.get(code, "-")


def render_http_summary(
    summary: HttpSummary, limit: int = 12, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit) or limit
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"HTTP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(_format_kv("HTTP Requests", str(summary.total_requests)))
    lines.append(_format_kv("HTTP Responses", str(summary.total_responses)))
    lines.append(_format_kv("Unique Clients", str(summary.unique_clients)))
    lines.append(_format_kv("Unique Servers", str(summary.unique_servers)))
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))

    def _http_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        detections = list(getattr(summary, "detections", []) or [])
        suspicious_ua_markers = (
            "sqlmap",
            "nikto",
            "nmap",
            "acunetix",
            "python-requests",
            "curl",
            "wget",
            "masscan",
        )

        critical_count = sum(
            1 for d in detections if str(d.get("severity", "")).lower() == "critical"
        )
        high_count = sum(
            1 for d in detections if str(d.get("severity", "")).lower() == "high"
        )
        warning_count = sum(
            1 for d in detections if str(d.get("severity", "")).lower() == "warning"
        )

        if critical_count:
            score += min(4, critical_count * 2)
            reasons.append(f"Critical HTTP findings detected ({critical_count})")
        if high_count:
            score += min(3, high_count)
            reasons.append(f"High-severity HTTP findings detected ({high_count})")
        if warning_count >= 2:
            score += 1
            reasons.append(
                f"Multiple warning-level HTTP findings detected ({warning_count})"
            )

        if summary.downloads:
            mismatch_count = sum(
                1 for item in summary.downloads if bool(item.get("mismatch"))
            )
            if mismatch_count:
                score += 3
                reasons.append(
                    f"HTTP download type mismatches observed ({mismatch_count})"
                )

        suspicious_ua_hits = sum(
            int(count)
            for ua, count in summary.user_agents.items()
            if any(tag in ua.lower() for tag in suspicious_ua_markers)
        )
        if suspicious_ua_hits:
            score += 1
            reasons.append(
                f"Suspicious scanner/tool user-agents observed ({suspicious_ua_hits})"
            )

        risky_method_hits = int(summary.method_counts.get("TRACE", 0)) + int(
            summary.method_counts.get("CONNECT", 0)
        )
        if risky_method_hits:
            score += 1
            reasons.append(f"Risky HTTP methods observed ({risky_method_hits})")

        if summary.referrer_token_counts:
            token_hits = sum(int(v) for v in summary.referrer_token_counts.values())
            if token_hits:
                score += 1
                reasons.append(f"Potential token leakage in referrers ({token_hits})")

        vt_mal = 0
        vt_sus = 0
        for det in detections:
            findings = det.get("vt_findings")
            if not isinstance(findings, list):
                continue
            for item in findings:
                if not isinstance(item, dict):
                    continue
                vt_mal += int(item.get("malicious", 0) or 0)
                vt_sus += int(item.get("suspicious", 0) or 0)
        if vt_mal > 0:
            score += 3
            reasons.append(f"VirusTotal malicious verdicts present (sum={vt_mal})")
        elif vt_sus > 0:
            score += 1
            reasons.append(f"VirusTotal suspicious verdicts present (sum={vt_sus})")

        if score >= 7:
            verdict = "YES - high-confidence malicious or compromised HTTP activity is present."
            confidence = "High"
        elif score >= 4:
            verdict = "LIKELY - suspicious HTTP activity with compromise indicators is present."
            confidence = "Medium"
        elif score >= 2:
            verdict = "POSSIBLE - potentially risky HTTP activity is present; corroboration recommended."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing malicious HTTP pattern from current heuristics."
            confidence = "Low"

        if not reasons:
            reasons.append("No high-confidence HTTP threat heuristic crossed threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _http_verdict()
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
    for reason in verdict_reasons[: _limit_value(10)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    # Add concrete context for immediate triage.
    if summary.host_counts:
        lines.append(muted("Where:"))
        lines.append(muted("- Top HTTP hosts"))
        for host, count in summary.host_counts.most_common(_limit_value(8)):
            lines.append(muted(f"- {_redact_in_text(str(host))}: {int(count)}"))
    if summary.client_counts:
        lines.append(muted("Who:"))
        lines.append(muted("- Top source clients"))
        for client, count in summary.client_counts.most_common(_limit_value(8)):
            lines.append(muted(f"- {_highlight_public_ips(str(client))}: {int(count)}"))
    if summary.server_counts:
        lines.append(muted("Where:"))
        lines.append(muted("- Top target servers"))
        for server, count in summary.server_counts.most_common(_limit_value(8)):
            lines.append(muted(f"- {_highlight_public_ips(str(server))}: {int(count)}"))
    suspicious_downloads = [
        item for item in summary.downloads if bool(item.get("mismatch"))
    ]
    if suspicious_downloads:
        lines.append(muted("What:"))
        lines.append(muted("- Suspicious downloads"))
        for item in suspicious_downloads[: _limit_value(6)]:
            lines.append(
                muted(
                    f"- {_highlight_public_ips(str(item.get('src', '-')))}"
                    f"->{_highlight_public_ips(str(item.get('dst', '-')))} "
                    f"file={_redact_in_text(str(item.get('filename', '-')))} "
                    f"type={_redact_in_text(str(item.get('content_type', '-')))}"
                )
            )
    if summary.detections:
        lines.append(muted("What:"))
        lines.append(muted("- Top detections"))
        for det in summary.detections[: _limit_value(6)]:
            lines.append(
                muted(
                    f"- [{str(det.get('severity', 'info')).upper()}] "
                    f"{_redact_in_text(str(det.get('summary', '-')))}"
                )
            )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic HTTP Security Checks"))

    detection_items = list(getattr(summary, "detections", []) or [])

    def _matching_detections(keywords: tuple[str, ...]) -> list[dict[str, object]]:
        matches: list[dict[str, object]] = []
        for det in detection_items:
            summary_text = str(det.get("summary", "") or "")
            details_text = str(det.get("details", "") or "")
            blob = f"{summary_text} {details_text}".lower()
            if any(key in blob for key in keywords):
                matches.append(det)
        return matches

    def _matching_detection_lines(
        keywords: tuple[str, ...], limit_lines: int = 4
    ) -> list[str]:
        out: list[str] = []
        for det in _matching_detections(keywords):
            summary_text = str(det.get("summary", "") or "")
            details_text = str(det.get("details", "") or "")
            line = summary_text
            if details_text:
                line = f"{summary_text}: {details_text}"
            out.append(_redact_in_text(line))
            artifacts = det.get("artifacts")
            if isinstance(artifacts, list) and artifacts:
                out.append(
                    _redact_in_text(
                        "artifacts=" + ", ".join(str(v) for v in artifacts[:3])
                    )
                )
            if len(out) >= limit_lines:
                break
        return out[:limit_lines]

    checks: list[tuple[str, tuple[str, ...]]] = [
        ("Authentication Abuse", ("authentication abuse", "authorization schemes")),
        ("Suspicious Upload Activity", ("upload profile", "upload")),
        ("Web Shell/Dropper Behavior", ("web shell", "dropper")),
        (
            "HTTP Beaconing/C2-like Check-ins",
            ("periodic http check-in", "check-in behavior"),
        ),
        ("URI/Token Obfuscation", ("high-entropy uri/token", "entropy")),
        (
            "Host Header / Fronting Anomalies",
            ("host header / destination anomalies", "host-to-ip churn"),
        ),
        ("Method Misuse/Tunneling", ("method misuse/tunneling", "risky http methods")),
        (
            "User-Agent Impersonation",
            ("browser ua impersonation", "suspicious user agents"),
        ),
        ("Session Token Replay", ("token replay", "token leakage")),
        (
            "Burst/Fan-out Reconnaissance",
            ("burst/fan-out reconnaissance", "single http uri reached many targets"),
        ),
        (
            "Content-Type/Payload Mismatch",
            ("content-type/payload mismatch", "file type discrepancies"),
        ),
        ("Threat Intelligence Reputation", ("threat intelligence", "virustotal")),
    ]

    for label_text, keywords in checks:
        lines.append(label(label_text))
        evidence_lines = _matching_detection_lines(keywords)
        if evidence_lines:
            lines.append(
                warn(
                    f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"
                )
            )
            for item in evidence_lines:
                lines.append(muted(f"- {item}"))
        else:
            lines.append(
                ok(
                    f"No, there is no strong evidence for {label_text.lower()} in this capture."
                )
            )

    if summary.method_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Request Methods"))
        lines.append(_counter_table(summary.method_counts, "Method", limit=limit))

    if summary.version_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("HTTP Versions"))
        lines.append(_counter_table(summary.version_counts, "Version", limit=limit))

    if summary.status_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Response Codes"))
        rows = [["Status", "Description", "Count"]]
        for code, count in summary.status_counts.most_common(limit):
            rows.append([str(code), _http_status_text(code), str(count)])
        lines.append(_format_table(rows))

    if summary.host_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Hosts"))
        rows = [["Host", "IPs", "Requests", "Note"]]
        host_ip_map = getattr(summary, "host_ip_counts", {}) or {}
        for host, count in summary.host_counts.most_common(limit):
            host_key = host.lower().split(":", 1)[0]
            ip_counter = host_ip_map.get(host) or host_ip_map.get(host_key, Counter())
            ip_text = "-"
            note = "-"
            if ip_counter:
                ip_text = ", ".join(
                    f"{ip}({cnt})"
                    for ip, cnt in ip_counter.most_common(_limit_value(3))
                )
                if len(ip_counter) > 3:
                    ip_text += "..."
                if len(ip_counter) > 1:
                    note = "multiple IPs"
            rows.append([host, ip_text, str(count), note])
        lines.append(_format_table(rows))

    if summary.client_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Clients"))
        rows = [["Client", "Hostname", "Requests"]]
        client_host_map = getattr(summary, "client_host_counts", {}) or {}
        for client, count in summary.client_counts.most_common(limit):
            host_counter = client_host_map.get(client, Counter())
            host_text = "-"
            if host_counter:
                top_host, _hcount = host_counter.most_common(1)[0]
                extra = len(host_counter) - 1
                host_text = f"{top_host} (+{extra} more)" if extra > 0 else top_host
            rows.append([client, host_text, str(count)])
        lines.append(_format_table(rows))

    if summary.server_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Servers"))
        rows = [["Server", "Hostname", "Responses"]]
        server_host_map = getattr(summary, "server_host_counts", {}) or {}
        for server, count in summary.server_counts.most_common(limit):
            host_counter = server_host_map.get(server, Counter())
            host_text = "-"
            if host_counter:
                top_host, _hcount = host_counter.most_common(1)[0]
                extra = len(host_counter) - 1
                host_text = f"{top_host} (+{extra} more)" if extra > 0 else top_host
            rows.append([server, host_text, str(count)])
        lines.append(_format_table(rows))

    if summary.url_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top 25 URLs"))
        top_rows = [["URL", "Count"]]
        for url, count in summary.url_counts.most_common(25):
            top_rows.append([url, str(count)])
        lines.append(_format_table(top_rows))

        lines.append(SUBSECTION_BAR)
        lines.append(header("Bottom 25 URLs"))
        bottom_rows = [["URL", "Count"]]
        url_items = sorted(
            summary.url_counts.items(), key=lambda item: (item[1], item[0])
        )
        for url, count in url_items[:25]:
            bottom_rows.append([url, str(count)])
        lines.append(_format_table(bottom_rows))

    if summary.user_agents:
        lines.append(SUBSECTION_BAR)
        lines.append(header("User Agents"))
        lines.append(_counter_table(summary.user_agents, "User-Agent", limit=limit))

    if summary.referrer_counts or summary.referrer_present or summary.referrer_missing:
        lines.append(SUBSECTION_BAR)
        lines.append(header("HTTP Referrer Analysis"))

        def _normalize_referrer_items(
            items: list[tuple[str, int]], truncate: bool
        ) -> list[tuple[str, int]]:
            ordered = sorted(items, key=lambda item: (-item[1], item[0]))
            if not truncate:
                return ordered
            if verbose:
                return ordered
            merged: dict[str, int] = {}
            for value, count in ordered:
                display = _truncate_text(value, max_len=96)
                merged[display] = merged.get(display, 0) + count
            return sorted(merged.items(), key=lambda item: (-item[1], item[0]))

        def _append_referrer_table(
            title: str,
            header_text: str,
            items: list[tuple[str, int]],
            truncate: bool = False,
        ) -> None:
            if not items:
                return
            normalized = _normalize_referrer_items(items, truncate)
            if not normalized:
                return
            lines.append(label(title))
            count_width = max(1, max(len(str(count)) for _, count in normalized))
            rows = [[label(header_text), label("Count")]]
            for value, count in normalized:
                rows.append([value, str(count).rjust(count_width)])
            lines.append(_format_table(rows))

        lines.append(label("Summary"))
        stats_rows = [
            [label("Metric"), label("Value")],
            ["Referrers Present", str(summary.referrer_present)],
            ["Referrers Missing", str(summary.referrer_missing)],
            ["Unique Referrers", str(len(summary.referrer_counts))],
            ["Unique Referrer Hosts", str(len(summary.referrer_host_counts))],
            ["Cross-Host Referrers", str(summary.referrer_cross_host)],
            ["HTTPS→HTTP Referrers", str(summary.referrer_https_to_http)],
            ["Referrers w/ Tokens", str(sum(summary.referrer_token_counts.values()))],
            ["Referrers w/ IP Hosts", str(len(summary.referrer_ip_hosts))],
        ]
        lines.append(_format_table(stats_rows))

        anomalies: list[str] = []
        if summary.referrer_https_to_http:
            anomalies.append(
                f"Mixed content/downgrade referrers: {summary.referrer_https_to_http}"
            )
        if summary.referrer_token_counts:
            anomalies.append(
                f"Token-like strings in referrers: {sum(summary.referrer_token_counts.values())}"
            )
        if summary.referrer_ip_hosts:
            anomalies.append(
                f"IP-literal referrer hosts: {len(summary.referrer_ip_hosts)}"
            )
        if summary.referrer_cross_host and summary.referrer_present:
            ratio = summary.referrer_cross_host / max(1, summary.referrer_present)
            if ratio > 0.7:
                anomalies.append(
                    f"High cross-site referrer rate: {summary.referrer_cross_host}/{summary.referrer_present}"
                )
        if anomalies:
            lines.append(header("Referrer Anomalies/Threats"))
            for item in anomalies:
                lines.append(warn(f"- {item}"))

        if summary.referrer_scheme_counts:
            _append_referrer_table(
                "Scheme Counts",
                "Scheme",
                summary.referrer_scheme_counts.most_common(limit),
            )

        if summary.referrer_host_counts:
            _append_referrer_table(
                "Top Referrer Hosts",
                "Host",
                summary.referrer_host_counts.most_common(limit),
            )

        show_paths = bool(summary.referrer_path_counts) and (
            verbose
            or not summary.referrer_counts
            or len(summary.referrer_path_counts) != len(summary.referrer_counts)
        )
        if show_paths:
            _append_referrer_table(
                "Top Referrer Paths",
                "Path",
                summary.referrer_path_counts.most_common(limit),
                truncate=True,
            )

        if summary.referrer_counts:
            raw_referrers = summary.referrer_counts.most_common(limit)
            normalized_referrers = _normalize_referrer_items(raw_referrers, True)
            if normalized_referrers:
                lines.append(label("Top Referrer URLs"))
                count_width = max(
                    1, max(len(str(count)) for _, count in normalized_referrers)
                )
                rows = [[label("URL"), label("Host"), label("Count")]]
                host_map = getattr(summary, "referrer_request_host_counts", {}) or {}
                display_host_map: dict[str, Counter[str]] = defaultdict(Counter)
                for ref_value, _ in raw_referrers:
                    display_value = (
                        ref_value if verbose else _truncate_text(ref_value, max_len=96)
                    )
                    host_counter = host_map.get(ref_value)
                    if not host_counter:
                        continue
                    for host, host_count in host_counter.items():
                        display_host_map[display_value][host] += int(host_count)
                for value, count in normalized_referrers:
                    host_counter = display_host_map.get(value)
                    if host_counter:
                        top_hosts = host_counter.most_common(_limit_value(2))
                        host_display = ", ".join(
                            f"{host} ({host_count})" for host, host_count in top_hosts
                        )
                    else:
                        host_display = "-"
                    rows.append([value, host_display, str(count).rjust(count_width)])
                lines.append(_format_table(rows))

        if summary.referrer_token_counts:
            _append_referrer_table(
                "Token Fingerprints",
                "Token Fingerprint",
                summary.referrer_token_counts.most_common(limit),
            )

    if summary.server_headers:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Server Headers"))
        lines.append(_counter_table(summary.server_headers, "Server", limit=limit))

    if getattr(summary, "device_fingerprints", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Device Fingerprints"))
        rows = [["Fingerprint", "Count"]]
        for fp, count in summary.device_fingerprints.most_common(limit):
            rows.append([_truncate_text(fp, 90), str(count)])
        lines.append(_format_table(rows))

    if summary.content_types:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Content Types"))
        lines.append(_counter_table(summary.content_types, "Content-Type", limit=limit))

    if summary.post_payloads:
        lines.append(SUBSECTION_BAR)
        lines.append(header("HTTP POST Payloads"))
        rows = [["Src", "Dst", "Host", "URI", "Bytes", "Content-Type", "Sample"]]
        for item in summary.post_payloads[:limit]:
            rows.append(
                [
                    str(item.get("src", "-")),
                    str(item.get("dst", "-")),
                    str(item.get("host", "-")) or "-",
                    str(item.get("uri", "-")),
                    str(item.get("bytes", "-")),
                    str(item.get("content_type", "-")) or "-",
                    str(item.get("sample", "-")),
                ]
            )
        lines.append(_format_table(rows))

    if summary.session_tokens:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Session Tokens Observed"))
        lines.append(_counter_table(summary.session_tokens, "Token", limit=limit))

    if summary.conversations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("HTTP Sessions"))

        def _http_requests(conv: object) -> object:
            return _conv_value(conv, "requests") or 0

        def _http_responses(conv: object) -> object:
            return _conv_value(conv, "responses") or 0

        def _http_methods(conv: object) -> object:
            methods = _conv_value(conv, "methods")
            if hasattr(methods, "most_common"):
                return (
                    ",".join(
                        f"{m}({c})" for m, c in methods.most_common(_limit_value(3))
                    )
                    or "-"
                )
            return "-"

        def _http_statuses(conv: object) -> object:
            statuses = _conv_value(conv, "statuses")
            if hasattr(statuses, "most_common"):
                return (
                    ",".join(
                        f"{s}({c})" for s, c in statuses.most_common(_limit_value(3))
                    )
                    or "-"
                )
            return "-"

        lines.append(
            _format_sessions_table(
                summary.conversations,
                limit,
                packet_label="Requests",
                packet_value_fn=_http_requests,
                extra_cols=[
                    ("Responses", _http_responses),
                    ("Methods", _http_methods),
                    ("Statuses", _http_statuses),
                ],
            )
        )

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        vt_limit = _limit_value(8)

        def _format_ip_counts(value: object) -> str:
            if isinstance(value, Counter):
                counter = value
            elif isinstance(value, dict):
                counter = Counter(
                    {str(k): int(v) for k, v in value.items() if v is not None}
                )
            elif isinstance(value, list):
                counter = Counter(str(v) for v in value if v is not None)
            else:
                return "-"
            items = counter.most_common(_limit_value(6))
            if not items:
                return "-"
            return ", ".join(f"{ip}({count})" for ip, count in items)

        def _append_detail(label_text: str, value: str) -> None:
            if value:
                lines.append(muted(f"  {label_text}: {value}"))

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
                _append_detail("Details", _truncate_text(details, 160))

            ip_counts = item.get("ip_counts") or item.get("ips")
            if ip_counts:
                _append_detail("IPs", _format_ip_counts(ip_counts))

            packets = item.get("packets")
            if isinstance(packets, list):
                pkt_count = len([p for p in packets if p not in (None, "")])
                if pkt_count:
                    _append_detail("Packets", f"{pkt_count} packet(s)")

            artifacts = item.get("artifacts")
            if isinstance(artifacts, list) and artifacts:
                _append_detail("Artifacts", f"{len(artifacts)} item(s)")

            vt_findings = item.get("vt_findings")
            if isinstance(vt_findings, list) and vt_findings:
                malicious_total = 0
                suspicious_total = 0
                for entry in vt_findings[:vt_limit]:
                    malicious_total += int(entry.get("malicious", 0) or 0)
                    suspicious_total += int(entry.get("suspicious", 0) or 0)
                _append_detail(
                    "VirusTotal",
                    f"{len(vt_findings)} finding(s), suspicious={suspicious_total}, malicious={malicious_total}",
                )

            evidence = item.get("evidence")
            if isinstance(evidence, list) and evidence:
                _append_detail("Evidence", f"{len(evidence)} item(s)")

    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)
