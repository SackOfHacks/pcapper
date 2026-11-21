"""Rendered output for hostname analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations

from collections import Counter, defaultdict

from ..hostname import HostnameSummary
from . import _style as st
from ._common import (
    _redact_in_text,
    _verbose_output,
    set_verbose_output,
)
from ._kv import counter_line


def render_hostname_summary(summary: HostnameSummary, limit: int = 25, verbose: bool = False) -> str:
    """Hostname discovery: which names each IP used or was given (DNS,
    NetBIOS, NTLM, HTTP Host, TLS SNI, DHCP ...), with naming conflicts,
    drift and suspicious names first. A query for one IP or hostname shows
    everything, as -v does."""
    focused = bool(summary.target_ip) or bool(str(getattr(summary, "hostname_query", "") or "").strip())
    restore = None
    if focused and not _verbose_output():
        restore = _verbose_output()
        set_verbose_output(True)
    try:
        return _render(summary, limit)
    finally:
        if restore is not None:
            set_verbose_output(restore)


def _render(summary: HostnameSummary, limit: int) -> str:
    rep = st.Report("Hostnames", summary.path)
    findings = list(summary.findings or [])
    names = {f.hostname for f in findings}
    rep.headline(False, st.plural(len(names), "hostname"), st.join([
        st.plural(sum(f.count for f in findings), "evidence row"),
        f"{st.count(summary.relevant_packets)} of {st.count(summary.total_packets)} packets relevant",
    ]))
    rep.scope(st.join([
        f"target {summary.target_ip}" if summary.target_ip else "",
        f"hostname {summary.hostname_query}" if str(getattr(summary, "hostname_query", "") or "").strip() else "",
        f"port {summary.port_filter}" if getattr(summary, "port_filter", None) else "",
        f"search {summary.search_query!r}" if str(getattr(summary, "search_query", "") or "").strip() else "",
    ]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])

    def _list(value: object, n: int = 6) -> str:
        items = [str(v) for v in value] if isinstance(value, (list, tuple, set)) else [str(value)] if value else []
        return ", ".join(items if st.verbose() else items[:n]) + (st.dim(f", +{len(items) - n}") if len(items) > n and not st.verbose() else "")

    suspicious = [p for p in (getattr(summary, "suspicious_name_profiles", None) or []) if isinstance(p, dict)]
    rep.section("Suspicious names", st.table(
        ["Hostname", "Reasons", "Entropy", "Evidence", "Addresses"],
        [[p.get("hostname", "-"), _list(p.get("reasons", [])), p.get("entropy", "-"), p.get("evidence", "-"), _list(p.get("ips", []))]
         for p in suspicious], max_rows=12, noun="name",
    ))
    conflicts = [p for p in (getattr(summary, "conflict_profiles", None) or []) if isinstance(p, dict)]
    rep.section("Conflicts", st.table(
        ["Type", "Name / IP", "Scope", "Evidence", "Methods"],
        [[p.get("type", "-"), p.get("hostname", "-") if p.get("type") == "hostname_to_many_ips" else p.get("ip", "-"),
          f"{int(p.get('ip_count', 0) or 0)} IPs" if p.get("type") == "hostname_to_many_ips" else f"{int(p.get('host_count', 0) or 0)} names",
          p.get("evidence", "-"), _list(p.get("methods", []), 4)] for p in conflicts],
        max_rows=12, noun="conflict",
    ))
    drift = [p for p in (getattr(summary, "drift_profiles", None) or []) if isinstance(p, dict)]
    rep.section("Drift", st.table(
        ["Hostname", "First", "Last", "Addresses"],
        [[p.get("hostname", "-"), st.ts(p.get("first_seen")), st.ts(p.get("last_seen")), _list(p.get("ips", []), 5)] for p in drift],
        max_rows=10, noun="name",
    ))
    ip_hosts: dict[str, set[str]] = defaultdict(set)
    ip_evidence: Counter[str] = Counter()
    for f in findings:
        if f.mapped_ip:
            ip_hosts[f.mapped_ip].add(f.hostname)
            ip_evidence[f.mapped_ip] += f.count
    rep.section("Addresses", st.table(
        ["IP", "Hostnames", "Evidence"],
        [[ip, _list(sorted(ip_hosts[ip]), 4), st.count(n)] for ip, n in ip_evidence.most_common()],
        align="llr", noun="address", **({"max_rows": None} if limit is None else {"max_rows": st.TOP_ROWS, "tail": st.TOP_ROWS}),
    ))

    def _conf(value: str) -> str:
        return st.good(value) if value == "HIGH" else st.caution(value) if value == "MEDIUM" else st.dim(value)

    rep.section("Evidence", st.table(
        ["Hostname", "IP", "Method", "Protocol", "Confidence", "Seen", "Flow", "Details"],
        [[f.hostname, f.mapped_ip or "-", f.method, f.protocol, _conf(str(f.confidence)), st.count(f.count),
          st.flow(f.src_ip, f.dst_ip), _redact_in_text(str(f.details))] for f in findings],
        align="lllllrll", widths=(48, None, None, None, None, None, None, 60), max_rows=15, noun="row",
    ))

    rep.section("Sources", st.kv([counter_line("Protocols", summary.protocol_counts, None),
                                  counter_line("Methods", summary.method_counts, None)]), detail=True)
    corroboration = [p for p in (getattr(summary, "cross_protocol_corroboration", None) or []) if isinstance(p, dict)]
    rep.section("Corroboration", st.table(
        ["Hostname", "Protocols", "Methods", "Confidence", "Evidence"],
        [[p.get("hostname", "-"), _list(p.get("protocols", []), 4), _list(p.get("methods", []), 3), p.get("confidence", "-"),
          p.get("evidence", "-")] for p in corroboration], max_rows=None,
    ), detail=True)
    macs = getattr(summary, "ip_to_macs", None) or {}
    rep.section("MAC addresses", st.table(["IP", "MACs"], [[ip, ", ".join(sorted(m))] for ip, m in sorted(macs.items())], max_rows=None),
                detail=True)
    rep.section("Assessment", st.kv([("Verdict", str(summary.analyst_verdict or "")),
                                     ("Confidence", str(getattr(summary, "analyst_confidence", "") or ""))])
                + st.bullets([_redact_in_text(str(r)) for r in (getattr(summary, "analyst_reasons", None) or [])], max_items=None),
                detail=True)
    rep.section("False-positive context", st.bullets(
        [_redact_in_text(str(v)) for v in (getattr(summary, "false_positive_context", None) or []) if str(v).strip()],
        max_items=None), detail=True)
    rep.section("Method", st.bullets([
        "DNS A/AAAA and PTR mappings are the strongest hostname-to-IP attribution evidence.",
        "HTTP Host and TLS SNI name the server a client intended and can reveal virtual-host targeting.",
        "NTLM/NetBIOS names are contextual and may reflect client/workstation naming.",
    ], max_items=None), detail=True)
    return rep.render()
