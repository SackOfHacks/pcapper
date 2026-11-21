"""Rendered output for SSDP/UPnP: device discovery on the LAN, and SSDP that
reaches the internet (reflection DDoS, UPnP exposure)."""

from __future__ import annotations

from ..ssdp import SsdpSummary
from ._kv import counter_line, simple_report


def render_ssdp_summary(summary: SsdpSummary, verbose: bool = False) -> str:
    return simple_report(
        "SSDP", summary, packets=summary.ssdp_packets, unit="SSDP packets",
        clients=summary.client_counts, servers=summary.server_counts,
        facts_title="Discovery",
        facts=[("Messages", f"{summary.msearch_count} M-SEARCH · {summary.notify_count} NOTIFY · "
                            f"{summary.response_count} responses"),
               ("Public peers", ", ".join(map(str, summary.public_peers)) if summary.public_peers else ""),
               counter_line("Server banners", summary.server_banner_counts, 6),
               counter_line("Locations", summary.location_counts, 4),
               counter_line("Clients", summary.client_counts, 6), counter_line("Servers", summary.server_counts, 6)],
        details=[("UDP packets", str(summary.udp_packets)), ("Other messages", str(summary.other_count)),
                 counter_line("Targets", summary.target_port_counts, None), counter_line("USN", summary.usn_counts, None),
                 counter_line("ST", summary.st_counts, None), counter_line("NT", summary.nt_counts, None),
                 counter_line("Host headers", summary.host_header_counts, None),
                 ("Multicast destinations", ", ".join(map(str, summary.multicast_destinations or []))),
                 ("Unicast destinations", ", ".join(map(str, summary.unicast_destinations or []))),
                 ("Artifacts", "; ".join(str(a) for a in (summary.artifacts or [])))],
        high="SSDP exposure or reflection abuse: investigate", medium="SSDP activity to review",
    )
