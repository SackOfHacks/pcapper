"""Rendered output for --ip (MAC -> IP lookup)."""

from __future__ import annotations

from ..ipmac import IpLookupSummary
from . import _style as st


def render_ip_lookup_summary(summary: IpLookupSummary) -> str:
    query = summary.query_mac or "all MACs"
    rep = st.Report("MAC -> IP", summary.path)
    hits = list(summary.associations or [])
    rep.headline(False, f"{st.plural(len(hits), 'association')} for {query}", f"{st.count(summary.total_packets)} packets searched")
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    names = summary.ip_hostnames or {}
    rep.section("Associations", st.table(
        (["MAC"] if not summary.query_mac else []) + ["IP", "Hostname", "Discovered by", "Count"],
        [([str(h.mac)] if not summary.query_mac else []) + [str(h.ip), ", ".join(names.get(str(h.ip), [])) or "-",
                                                           str(h.discovery_method), st.count(h.count)] for h in hits],
        align=("l" if not summary.query_mac else "") + "lllr", max_rows=None,
    ))
    return rep.render()
