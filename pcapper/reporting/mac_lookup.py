"""Rendered output for --mac (IP -> MAC lookup)."""

from __future__ import annotations

from ..ipmac import MacLookupSummary, mac_manufacturer
from . import _style as st


def render_mac_lookup_summary(summary: MacLookupSummary) -> str:
    query = summary.query_ip or "all IPs"
    rep = st.Report("IP -> MAC", summary.path)
    hits = list(summary.associations or [])
    rep.headline(False, f"{st.plural(len(hits), 'association')} for {query}", f"{st.count(summary.total_packets)} packets searched")
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Associations", st.table(
        (["IP"] if not summary.query_ip else []) + ["MAC", "Manufacturer", "Discovered by", "Count"],
        [([str(h.ip)] if not summary.query_ip else []) + [str(h.mac), mac_manufacturer(h.mac), str(h.discovery_method),
                                                         st.count(h.count)] for h in hits],
        align=("l" if not summary.query_ip else "") + "lllr", max_rows=None,
    ))
    return rep.render()
