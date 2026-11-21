"""Rendered output for HTTP analysis.

Default view: findings, suspicious downloads, POST payloads, the hosts and
the URLs requested (frequent and rare), user agents, clients, the method and
status mix, referrer anomalies and session tokens. -v adds the analyzer's
assessment score, the full referrer analysis, server headers, device
fingerprints, content types, every download and file artifact, and sessions.
"""

from __future__ import annotations

from collections import Counter

from ..http import HttpSummary
from ..utils import format_duration
from . import _style as st
from ._common import _conv_value, _filtered_detections, _redact_in_text
from ._kv import counter_line, sessions

_SCANNER_UA = ("sqlmap", "nikto", "nmap", "acunetix", "python-requests", "curl", "wget", "masscan")


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



def _assessment(summary: HttpSummary) -> list[str]:
    """The analyzer's HTTP compromise score (severities, download type
    mismatches, tool user agents, risky methods, referrer tokens, VirusTotal)."""
    score, reasons = 0, []
    dets = list(summary.detections or [])
    sev = Counter(str(d.get("severity", "")).lower() for d in dets)
    if sev["critical"]:
        score += min(4, sev["critical"] * 2)
        reasons.append(f"Critical HTTP findings detected ({sev['critical']})")
    if sev["high"]:
        score += min(3, sev["high"])
        reasons.append(f"High-severity HTTP findings detected ({sev['high']})")
    if sev["warning"] >= 2:
        score += 1
        reasons.append(f"Multiple warning-level HTTP findings detected ({sev['warning']})")
    mismatches = sum(1 for d in summary.downloads if d.get("mismatch"))
    if mismatches:
        score += 3
        reasons.append(f"HTTP download type mismatches observed ({mismatches})")
    ua_hits = sum(int(c) for ua, c in summary.user_agents.items() if any(t in ua.lower() for t in _SCANNER_UA))
    if ua_hits:
        score += 1
        reasons.append(f"Suspicious scanner/tool user-agents observed ({ua_hits})")
    risky = int(summary.method_counts.get("TRACE", 0)) + int(summary.method_counts.get("CONNECT", 0))
    if risky:
        score += 1
        reasons.append(f"Risky HTTP methods observed ({risky})")
    tokens = sum(int(v) for v in summary.referrer_token_counts.values())
    if tokens:
        score += 1
        reasons.append(f"Potential token leakage in referrers ({tokens})")
    vt_mal = sum(int(i.get("malicious", 0) or 0) for d in dets for i in (d.get("vt_findings") or []) if isinstance(i, dict))
    vt_sus = sum(int(i.get("suspicious", 0) or 0) for d in dets for i in (d.get("vt_findings") or []) if isinstance(i, dict))
    if vt_mal:
        score += 3
        reasons.append(f"VirusTotal malicious verdicts present (sum={vt_mal})")
    elif vt_sus:
        score += 1
        reasons.append(f"VirusTotal suspicious verdicts present (sum={vt_sus})")
    verdict = ("YES - high-confidence malicious or compromised HTTP activity" if score >= 7 else
               "LIKELY - suspicious HTTP activity with compromise indicators" if score >= 4 else
               "POSSIBLE - potentially risky HTTP activity; corroborate" if score >= 2 else
               "NO STRONG SIGNAL - no convincing malicious HTTP pattern")
    confidence = "High" if score >= 7 else "Medium" if score >= 4 else "Low"
    return st.kv([("Verdict", verdict), ("Confidence", f"{confidence} (score={score})")]) + st.bullets(
        reasons or ["No high-confidence HTTP threat heuristic crossed threshold"], max_items=None)


def _top_with(counter: Counter, mapping: dict, key: str) -> str:
    sub = mapping.get(key) or Counter()
    if not sub:
        return "-"
    top_name, _ = sub.most_common(1)[0]
    return top_name + (f" (+{len(sub) - 1} more)" if len(sub) > 1 else "")


def render_http_summary(summary: HttpSummary, limit: int = 12, verbose: bool = False) -> str:
    rep = st.Report("HTTP", summary.path)
    detections = _filtered_detections(summary, st.verbose() or verbose)
    findings = [st.finding(d) for d in detections]
    if not summary.total_requests and not summary.total_responses and not st.material(findings):
        return rep.absent("HTTP traffic", summary.errors)
    rows = None if (st.verbose() or verbose) else 8
    severity, text = st.verdict(
        findings,
        high="malicious or compromised HTTP activity indicators: investigate the hosts and downloads below",
        medium="suspicious HTTP activity to review",
    )
    rep.headline(severity, text, st.join([
        f"{st.count(summary.total_requests)} requests / {st.count(summary.total_responses)} responses",
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
        st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else "",
    ]))
    rep.scope(st.join([
        f"{st.plural(summary.unique_clients, 'client')} -> {st.plural(summary.unique_servers, 'server')}",
        st.plural(len(summary.host_counts), "host name"),
    ]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    mismatched = [d for d in summary.downloads if d.get("mismatch")]
    rep.section("Suspicious downloads", st.table(
        ["Flow", "File", "Detected", "Declared", "Bytes", "Status"],
        [[st.flow(d.get("src", "-"), d.get("dst", "-")), _redact_in_text(str(d.get("filename", "-"))),
          st.bad(str(d.get("detected_type", "-"))), d.get("expected_type") or d.get("content_type") or "-",
          st.count(d.get("bytes", 0)), d.get("status", "-")] for d in mismatched],
        align="llllrl", max_rows=rows, widths=(None, 48), noun="download",
    ))
    rep.section("POST payloads", st.table(
        ["Flow", "Host", "URI", "Bytes", "Type", "Sample"],
        [[st.flow(p.get("src", "-"), p.get("dst", "-")), p.get("host") or "-", p.get("uri", "-"), st.count(p.get("bytes", 0)),
          p.get("content_type") or "-", p.get("sample", "-")] for p in summary.post_payloads],
        align="lllrll", max_rows=rows, widths=(None, 32, 48, None, 24, 40), noun="POST",
    ))

    host_ips = getattr(summary, "host_ip_counts", {}) or {}

    def _ips(host: str) -> tuple[str, str]:
        ips = host_ips.get(host) or host_ips.get(host.lower().split(":", 1)[0]) or Counter()
        if not ips:
            return "-", ""
        return st.top(ips, 3), ("multiple IPs" if len(ips) > 1 else "")

    # Ranked artifacts: the top 10 and the bottom 10 (the rarest) by default.
    every = {"max_rows": None} if rows is None else {}
    rep.section("Hosts", st.ranked(
        ["Host", "Requests", "IPs", "Note"],
        [[h, st.count(n), *_ips(h)] for h, n in summary.host_counts.most_common()],
        align="lrll", widths=(48,), noun="host", **every,
    ))
    rep.section("URLs", st.ranked(["URL", "Requests"],
                                  [[u, st.count(n)] for u, n in summary.url_counts.most_common()],
                                  align="lr", widths=(100,), noun="URL", **every))
    rep.section("User agents", st.ranked(["User-Agent", "Requests"],
                                         [[ua, st.count(n)] for ua, n in summary.user_agents.most_common()],
                                         align="lr", widths=(100,), noun="user agent", **every))
    client_hosts = getattr(summary, "client_host_counts", {}) or {}
    rep.section("Clients", st.ranked(["Client", "Requests", "Hosts"],
                                     [[c, st.count(n), _top_with(summary.client_counts, client_hosts, c)]
                                      for c, n in summary.client_counts.most_common()],
                                     align="lrl", noun="client", **every))
    rep.section("Requests and responses", st.kv([
        counter_line("Methods", summary.method_counts, 8),
        ("Statuses", st.top(summary.status_counts, 8, lambda k, v: f"{k} {_http_status_text(k)} ({st.count(v)})".replace(" - (", " ("))),
        counter_line("Versions", summary.version_counts, 4),
    ]))

    anomalies = []
    if summary.referrer_https_to_http:
        anomalies.append(f"Mixed content/downgrade referrers: {summary.referrer_https_to_http}")
    if summary.referrer_token_counts:
        anomalies.append(f"Token-like strings in referrers: {sum(summary.referrer_token_counts.values())}")
    if summary.referrer_ip_hosts:
        anomalies.append(f"IP-literal referrer hosts: {len(summary.referrer_ip_hosts)}")
    if summary.referrer_cross_host and summary.referrer_present and summary.referrer_cross_host / max(1, summary.referrer_present) > 0.7:
        anomalies.append(f"High cross-site referrer rate: {summary.referrer_cross_host}/{summary.referrer_present}")
    rep.section("Referrer anomalies", [f"  {st.caution('!')} {a}" for a in anomalies])
    rep.section("Session tokens", st.ranked(["Token", "Seen"], [[t, st.count(n)] for t, n in summary.session_tokens.most_common()],
                                            align="lr", noun="token", **every))

    # ---- reference material (-v) ----------------------------------------
    rep.section("Assessment", _assessment(summary), detail=True)
    rep.section("Traffic", st.kv([
        ("Requests / responses", f"{summary.total_requests} / {summary.total_responses}"),
        ("Clients / servers", f"{summary.unique_clients} / {summary.unique_servers}"),
        ("Start / end", f"{st.ts(summary.first_seen)} / {st.ts(summary.last_seen)}"),
        ("Duration", format_duration(summary.duration_seconds)),
    ]), detail=True)
    server_hosts = getattr(summary, "server_host_counts", {}) or {}
    rep.section("Servers", st.table(["Server", "Responses", "Hosts"],
                                    [[s, st.count(n), _top_with(summary.server_counts, server_hosts, s)]
                                     for s, n in summary.server_counts.most_common()],
                                    align="lrl", max_rows=None), detail=True)
    rep.section("Referrers", st.kv([
        ("Present / missing", f"{summary.referrer_present} / {summary.referrer_missing}"),
        ("Unique referrers / hosts", f"{len(summary.referrer_counts)} / {len(summary.referrer_host_counts)}"),
        ("Cross-host", str(summary.referrer_cross_host)),
        ("HTTPS→HTTP", str(summary.referrer_https_to_http)),
        ("With tokens", str(sum(summary.referrer_token_counts.values()))),
        ("With IP hosts", str(len(summary.referrer_ip_hosts))),
        counter_line("Schemes", summary.referrer_scheme_counts, None),
        counter_line("Hosts", summary.referrer_host_counts, None),
        counter_line("Paths", summary.referrer_path_counts, None),
        counter_line("Token fingerprints", summary.referrer_token_counts, None),
    ]) + st.table(["Referrer URL", "Requested hosts", "Count"],
                  [[ref, st.top((getattr(summary, "referrer_request_host_counts", {}) or {}).get(ref) or Counter(), 2), st.count(n)]
                   for ref, n in summary.referrer_counts.most_common()], align="llr", max_rows=None), detail=True)
    rep.section("Server software", st.kv([
        counter_line("Server headers", summary.server_headers, None),
        counter_line("Device fingerprints", getattr(summary, "device_fingerprints", None), None),
        counter_line("Content types", summary.content_types, None),
    ]), detail=True)
    rep.section("Downloads", st.table(
        ["Flow", "File", "Detected", "Expected", "Content-Type", "Bytes", "Status", "Packet", "Mismatch"],
        [[st.flow(d.get("src"), d.get("dst")), d.get("filename", "-"), d.get("detected_type", "-"), d.get("expected_type", "-"),
          d.get("content_type", "-"), d.get("bytes", 0), d.get("status", "-"), d.get("packet", "-"),
          "yes" if d.get("mismatch") else "no"] for d in summary.downloads], max_rows=None), detail=True)
    rep.section("File artifacts", st.bullets([str(a) for a in (getattr(summary, "file_artifacts", None) or [])], max_items=None),
                detail=True)

    def _counter_text(conv: object, name: str) -> str:
        value = _conv_value(conv, name)
        return ",".join(f"{k}({c})" for k, c in value.most_common(3)) if hasattr(value, "most_common") else "-"

    rep.section("Sessions", sessions(
        summary.conversations, value_label="Requests", value_fn=lambda c: _conv_value(c, "requests") or 0,
        extra_cols=[("Responses", lambda c: _conv_value(c, "responses") or 0),
                    ("Methods", lambda c: _counter_text(c, "methods")),
                    ("Statuses", lambda c: _counter_text(c, "statuses"))],
        max_rows=None,
    ), detail=True)
    return rep.render()
