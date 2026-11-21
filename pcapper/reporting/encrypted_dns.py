"""Rendered output for encrypted DNS (DoT, DoH, DoQ): resolution that a
DNS sensor cannot see, and who uses it."""

from __future__ import annotations

from ..encrypted_dns import EncryptedDnsSummary
from ._kv import counter_line, simple_report


def render_encrypted_dns_summary(summary: EncryptedDnsSummary) -> str:
    packets = summary.dot_packets + summary.doh_packets + summary.doq_packets
    return simple_report(
        "Encrypted DNS", summary, packets=packets, unit="encrypted DNS packets",
        clients=summary.clients, servers=summary.servers,
        facts_title="Resolution",
        facts=[("DoT / DoH / DoQ", f"{summary.dot_packets} / {summary.doh_packets} / {summary.doq_packets} packets"),
               counter_line("Clients", summary.clients), counter_line("Resolvers", summary.servers)],
        high="encrypted DNS that bypasses DNS monitoring: confirm the resolvers are sanctioned",
        medium="encrypted DNS to review",
        absent="encrypted DNS (DoT/DoH/DoQ) traffic",
    )
