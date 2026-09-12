"""Rendered output for ip_lookup analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    danger,
    header,
    muted,
)
from ..ipmac import IpLookupSummary

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _finalize_output,
    _format_kv,
    _format_table,
)


def render_ip_lookup_summary(summary: IpLookupSummary) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"MAC -> IP LOOKUP :: {summary.path.name}"))
    lines.append(SECTION_BAR)
    query_all = not summary.query_mac
    lines.append(_format_kv("Query MAC", summary.query_mac or "ALL"))
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        for err in summary.errors:
            lines.append(danger(f"Error: {err}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("MAC -> IP Pairs" if query_all else "IP Addresses"))
    if not summary.associations:
        lines.append(
            muted(
                "No MAC->IP associations found."
                if query_all
                else "No associated IP addresses found for the queried MAC."
            )
        )
    else:
        if query_all:
            rows = [["MAC Address", "IP Address", "Hostname", "Discovery Method", "Count"]]
            for hit in summary.associations:
                hostnames = list((summary.ip_hostnames or {}).get(str(hit.ip), []))
                hostname_text = ", ".join(hostnames) if hostnames else "-"
                rows.append(
                    [
                        str(hit.mac),
                        str(hit.ip),
                        hostname_text,
                        str(hit.discovery_method),
                        str(hit.count),
                    ]
                )
        else:
            rows = [["IP Address", "Hostname", "Discovery Method", "Count"]]
            for hit in summary.associations:
                hostnames = list((summary.ip_hostnames or {}).get(str(hit.ip), []))
                hostname_text = ", ".join(hostnames) if hostnames else "-"
                rows.append(
                    [
                        str(hit.ip),
                        hostname_text,
                        str(hit.discovery_method),
                        str(hit.count),
                    ]
                )
        lines.append(_format_table(rows))
    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)
