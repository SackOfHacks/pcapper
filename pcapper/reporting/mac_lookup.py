"""Rendered output for mac_lookup analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    danger,
    header,
    muted,
)
from ..ipmac import MacLookupSummary, mac_manufacturer

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _finalize_output,
    _format_kv,
    _format_table,
)


def render_mac_lookup_summary(summary: MacLookupSummary) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"IP -> MAC LOOKUP :: {summary.path.name}"))
    lines.append(SECTION_BAR)
    query_all = not summary.query_ip
    lines.append(_format_kv("Query IP", summary.query_ip or "ALL"))
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        for err in summary.errors:
            lines.append(danger(f"Error: {err}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("IP -> MAC Pairs" if query_all else "MAC Addresses"))
    if not summary.associations:
        lines.append(
            muted(
                "No IP->MAC associations found."
                if query_all
                else "No associated MAC addresses found for the queried IP."
            )
        )
    else:
        if query_all:
            rows = [
                ["IP Address", "MAC Address", "Manufacturer", "Discovery Method", "Count"]
            ]
            for hit in summary.associations:
                rows.append(
                    [
                        str(hit.ip),
                        str(hit.mac),
                        mac_manufacturer(hit.mac),
                        str(hit.discovery_method),
                        str(hit.count),
                    ]
                )
        else:
            rows = [["MAC Address", "Manufacturer", "Discovery Method", "Count"]]
            for hit in summary.associations:
                rows.append(
                    [
                        str(hit.mac),
                        mac_manufacturer(hit.mac),
                        str(hit.discovery_method),
                        str(hit.count),
                    ]
                )
        lines.append(_format_table(rows))
    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)
