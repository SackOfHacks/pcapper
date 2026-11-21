"""Rendered output for webrequests analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations

import ipaddress
import re

from ..webrequests import WebRequestSummary
from . import _style as st
from ._common import _redact_in_text
from ._kv import counter_line

_EXE_RE = re.compile(r"(?i)\.(exe|elf|dll|sys|msi|scr|jar|apk|bin)(?:$|[?#])")


def _host_is_ip_literal(host_value: str) -> bool:
    text = str(host_value or "").strip()
    if not text:
        return False
    if text.startswith("[") and "]" in text:
        text = text[1:text.index("]")]
    elif ":" in text and text.count(":") == 1:
        candidate, maybe_port = text.rsplit(":", 1)
        if maybe_port.isdigit():
            text = candidate
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _status(item: object) -> str:
    if item.response_code is None:
        return "-"
    name = item.response_name if item.response_name and item.response_name != "-" else ""
    return f"{item.response_code} {name}".strip()


def render_webrequests_summary(summary: WebRequestSummary, limit: int = 15, verbose: bool = False, view: str = "minimal") -> str:
    """HTTP requests one per row (minimal / simple) or one block each with
    headers, parameters and body (full): executable downloads and requests to
    bare-IP hosts first, VirusTotal hits next."""
    view_mode = str(view or "minimal").strip().lower()
    if view_mode not in {"minimal", "simple", "full"}:
        view_mode = "minimal"
    rep = st.Report("Web requests", summary.path)
    rep.headline(False, st.plural(summary.matched_requests, "request"), st.join([
        st.caution(f"{summary.suspicious_requests} suspicious") if summary.suspicious_requests else "",
        f"{st.count(summary.http_packets)} HTTP packets", st.top(summary.method_counts, 6),
    ]))
    rep.scope(st.join([
        f"scope {summary.target_ip}" if summary.scoped else "",
        f"search {summary.search_query!r}" if str(getattr(summary, "search_query", "") or "").strip() else "",
        "POST only" if getattr(summary, "post_only", False) else "", "high risk only" if getattr(summary, "high_only", False) else "",
        "hosts " + st.top(summary.host_counts, 4) if summary.host_counts else "",
    ]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    requests = list(summary.requests or [])
    if not requests:
        rep.section("Requests", [f"  {st.dim('no web requests matched the current scope')}"])
        return rep.render()

    interesting = []
    for item in requests:
        reasons = []
        if _EXE_RE.search(item.uri or "") or _EXE_RE.search(item.response_location or ""):
            reasons.append("executable target")
        if _host_is_ip_literal(item.host or ""):
            reasons.append("host is an IP")
        if reasons:
            interesting.append([st.ts(item.ts), item.method, f"{item.host}{item.uri}" if item.host else item.uri,
                                f"{item.dst_ip}:{item.dst_port or '-'}", _status(item), st.caution(", ".join(reasons))])
    rep.section("Interesting", st.table(["Time", "Method", "Request", "Remote", "Status", "Why"], interesting,
                                        widths=(None, None, 80), max_rows=max(limit, 8), noun="request"))
    vt = dict(getattr(summary, "vt_results", None) or {})
    ranked = sorted(vt.items(), key=lambda kv: (int(kv[1].get("malicious", 0) or 0), int(kv[1].get("suspicious", 0) or 0),
                                                int(kv[1].get("reputation", 0) or 0)), reverse=True)
    rep.section("VirusTotal", st.table(
        ["Domain", "Malicious", "Suspicious", "Reputation", "Report"],
        [[d, st.bad(str(i.get("malicious", 0))) if int(i.get("malicious", 0) or 0) else "0", i.get("suspicious", 0),
          i.get("reputation", "-"), i.get("report_url", "-")] for d, i in ranked
         if st.verbose() or int(i.get("malicious", 0) or 0) or int(i.get("suspicious", 0) or 0)],
        align="lrrrl", max_rows=12, noun="domain",
    ) + st.bullets([str(e) for e in (getattr(summary, "vt_errors", None) or [])], max_items=None))

    shown = requests if (st.verbose() or verbose) else requests[:limit]
    if view_mode == "minimal":
        rep.section("Requests", st.table(
            ["Time", "Packet", "Method", "Request", "Remote", "Status", "Referer", "User agent"],
            [[st.ts(i.ts), i.packet_number, i.method, f"{i.host}{i.uri}", f"{i.dst_ip}:{i.dst_port or '-'}", _status(i),
              str(i.headers.get("referer", "") or "-"), str(i.headers.get("user-agent", "") or "-")] for i in shown],
            align="lrllllll", widths=(None, None, None, 62, None, None, 44, 56), max_rows=None, noun="request",
        ) + ([st.more(len(requests) - len(shown), "request")] if len(requests) > len(shown) else []))
    elif view_mode == "simple":
        rep.section("Requests", st.table(
            ["Time", "Packet", "Method", "Host", "URI", "Source", "Destination", "Status", "Risk"],
            [[st.ts(i.ts), i.packet_number, i.method, i.host or "-", i.uri or "-", f"{i.src_ip}:{i.src_port or '-'}",
              f"{i.dst_ip}:{i.dst_port or '-'}", i.response_code if i.response_code is not None else "-",
              f"{i.risk_level} ({i.risk_score})"] for i in shown],
            align="lrlllllll", widths=(None, None, None, 28, 44), max_rows=None, noun="request",
        ) + ([st.more(len(requests) - len(shown), "request")] if len(requests) > len(shown) else []))
    else:
        blocks: list[str] = []
        for idx, item in enumerate(shown, start=1):
            target = f"{item.host}{item.uri}" if item.host else item.uri
            blocks.append(f"  {st.strong(f'[{idx}]')} {st.ts(item.ts)}  {item.method} {target or '-'}")
            blocks += st.kv([
                ("Flow", f"{item.src_ip}:{item.src_port or '-'} -> {item.dst_ip}:{item.dst_port or '-'}"),
                ("Packet", str(item.packet_number)),
                ("Request line", item.request_line or f"{item.method} {item.uri} HTTP/{item.http_version}"),
                ("Status", _status(item)),
                ("Risk", f"{item.risk_level} ({item.risk_score})"),
                ("Reasons", ", ".join(item.risk_reasons) if item.risk_reasons else ""),
                ("Location", item.response_location or ""),
                ("Query params", ", ".join(f"{k}={v}" for k, v in (item.params or []))),
            ], indent=4)
            headers = dict(item.headers or {})
            order = ["host", "referer", "user-agent", "content-type", "content-length", "origin", "cookie", "authorization"]
            keys = [k for k in order if str(headers.get(k, "") or "").strip()] + sorted(
                k for k in headers if k not in order and str(headers.get(k, "") or "").strip())
            if keys:
                blocks.append(f"    {st.dim('headers')}")
                blocks += [f"      {k}: {st.cut(_redact_in_text(str(headers[k])), 220 if st.verbose() else 140)}" for k in keys]
            body = str(item.body or "")
            if body:
                max_chars, max_lines = (6000, 200) if st.verbose() else (1500, 60)
                body_lines = body[:max_chars].splitlines() or [body[:max_chars]]
                blocks.append(f"    {st.dim('body')}")
                blocks += [f"      {_redact_in_text(line)}" for line in body_lines[:max_lines]]
                if len(body) > max_chars or len(body_lines) > max_lines:
                    blocks.append(st.dim(f"      … body truncated ({len(body)} chars)"))
            blocks.append("")
        if len(requests) > len(shown):
            blocks.append(st.more(len(requests) - len(shown), "request"))
        rep.section("Requests", blocks)

    rep.section("Counters", st.kv([
        counter_line("Request ports", getattr(summary, "request_port_counts", None), None),
        counter_line("Proxy ports", getattr(summary, "proxy_port_counts", None), None),
        counter_line("URIs", getattr(summary, "uri_counts", None), None),
        counter_line("Clients", getattr(summary, "client_counts", None), None),
        counter_line("Servers", getattr(summary, "server_counts", None), None),
        counter_line("Risk levels", getattr(summary, "risk_level_counts", None), None),
        ("Packets scanned", str(summary.total_packets)),
    ]), detail=True)
    return rep.render()
