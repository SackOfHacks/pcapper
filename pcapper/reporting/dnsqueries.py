"""Rendered output for --dnsqueries: a capture's DNS lookups as a simple list
-- who asked which resolver, for what name and type, and what came back. The
default view lists each distinct lookup once, at its first sighting, with
how often it repeated (×N); -v lists every query in time order with its
packet number, transaction ID and round-trip time. Under -summarize each
row names its capture; with -ip only that host's lookups are listed."""

from __future__ import annotations

from ..dnsqueries import DnsQuerySummary
from . import _style as st

_NO_RESPONSE = "no response"


def _response(record: dict) -> str:
    """What came back: the answers, the error code, or that nothing did."""
    status = str(record.get("status", ""))
    if status == _NO_RESPONSE:
        return st.dim(_NO_RESPONSE)
    rcode = str(record.get("rcode", "") or "")
    answers = [str(a) for a in record.get("answers") or []]
    if rcode and rcode != "NOERROR":
        text = st.caution(rcode)
    elif answers:
        text = ", ".join(answers)
    else:
        text = "NOERROR, no answers"
    return text + (st.dim(" (query not captured)") if status == "response only" else "")


def _vt(summary: DnsQuerySummary, name: str) -> str:
    info = (summary.vt_results or {}).get(str(name).strip(".").lower())
    if not isinstance(info, dict):
        return "-"
    mal, sus = int(info.get("malicious", 0) or 0), int(info.get("suspicious", 0) or 0)
    text = f"{mal} malicious, {sus} suspicious"
    return st.bad(text) if mal else st.caution(text) if sus else text


def render_dnsqueries_summary(summary: DnsQuerySummary) -> str:
    rep = st.Report("DNS queries", summary.path)
    records = [r for r in (summary.queries or []) if isinstance(r, dict)]
    if not records:
        return rep.absent("DNS lookups", summary.errors)
    names = {str(r.get("name", "")).lower() for r in records if r.get("name") not in (None, "", "-")}
    clients = {str(r.get("client")) for r in records}
    servers = {str(r.get("server")) for r in records}
    nxdomain = sum(1 for r in records if r.get("rcode") == "NXDOMAIN")
    failed = sum(1 for r in records if r.get("rcode") not in ("", "NOERROR", "NXDOMAIN", None))
    unanswered = sum(1 for r in records if r.get("status") == _NO_RESPONSE)
    protocols = sorted({str(r.get("protocol", "DNS")) for r in records})
    rep.headline(False, st.join([
        f"{st.plural(len(records), 'query', 'queries')} for {st.plural(len(names), 'name')}",
        f"{nxdomain} NXDOMAIN" if nxdomain else "",
        f"{failed} other errors" if failed else "",
        f"{unanswered} unanswered" if unanswered else "",
    ]), st.join([
        f"{st.plural(len(clients), 'client')} -> {st.plural(len(servers), 'server')}",
        " · ".join(f"{p} {sum(1 for r in records if r.get('protocol') == p)}" for p in protocols) if protocols != ["DNS"] else "",
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
        st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else "",
    ]))
    if summary.dropped:
        rep.note("NOTE", f"{st.count(summary.dropped)} more lookups not kept (PCAPPER_MAX_DNS_QUERY_RECORDS)")
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])

    by_capture = any(r.get("capture") for r in records)
    mixed = protocols != ["DNS"]
    vt = bool(summary.vt_results)
    ordered = sorted(records, key=lambda r: (str(r.get("capture", "")), r.get("ts") is None, r.get("ts") or 0.0,
                                             int(r.get("packet", 0) or 0)))

    def _cols(*names: str) -> list[str]:
        return list(names)

    if st.verbose():
        header = (["Capture"] if by_capture else []) + _cols("Time", "Packet", "Client", "Server") + (["Proto"] if mixed else []) \
            + _cols("ID", "Type", "Name", "Response", "RTT ms") + (["VirusTotal"] if vt else [])
        rows = [([r.get("capture", "-")] if by_capture else []) + [
            st.ts(r.get("ts")), r.get("packet", "-"), r.get("client", "-"), r.get("server", "-")]
            + ([r.get("protocol", "-")] if mixed else [])
            + [f"0x{int(r.get('id', 0) or 0):04x}", r.get("qtype", "-"), r.get("name", "-"), _response(r),
               f"{r['rtt_ms']:.1f}" if isinstance(r.get("rtt_ms"), (int, float)) else "-"]
            + ([_vt(summary, str(r.get("name", "")))] if vt else []) for r in ordered]
        align = ("l" if by_capture else "") + "lrll" + ("l" if mixed else "") + "llllr" + ("l" if vt else "")
        rep.section("Queries", st.table(header, rows, align=align, max_rows=None, noun="query"))
        return rep.render()

    # Default: each distinct lookup once, at its first sighting, ×N.
    groups: dict[tuple, dict] = {}
    for r in ordered:
        response = _response(r)
        key = (str(r.get("capture", "")), str(r.get("client")), str(r.get("server")), str(r.get("protocol")),
               str(r.get("qtype")), str(r.get("name", "")).lower(), response)
        group = groups.get(key)
        if group is None:
            groups[key] = {"record": r, "response": response, "count": 1}
        else:
            group["count"] += 1
    header = (["Capture"] if by_capture else []) + _cols("First seen", "Client", "Server") + (["Proto"] if mixed else []) \
        + _cols("Type", "Name", "×", "Response") + (["VirusTotal"] if vt else [])
    rows = [([g["record"].get("capture", "-")] if by_capture else []) + [
        st.ts(g["record"].get("ts")), g["record"].get("client", "-"), g["record"].get("server", "-")]
        + ([g["record"].get("protocol", "-")] if mixed else [])
        + [g["record"].get("qtype", "-"), g["record"].get("name", "-"), g["count"], g["response"]]
        + ([_vt(summary, str(g["record"].get("name", "")))] if vt else []) for g in groups.values()]
    align = ("l" if by_capture else "") + "lll" + ("l" if mixed else "") + "llrl" + ("l" if vt else "")
    name_col = (1 if by_capture else 0) + 3 + (1 if mixed else 0) + 1
    widths = [None] * (name_col + 3)
    widths[name_col] = 60
    widths[name_col + 2] = 90
    rep.section("Queries", st.table(header, rows, align=align, max_rows=None, widths=tuple(widths), noun="query"))
    rep.omitted("every query with its packet, txid and round-trip time")
    return rep.render()
