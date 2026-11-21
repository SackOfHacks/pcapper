"""Rendered output for TCP: scans, lateral movement, egress outliers and
beacon-like cadence first, then the top conversations (with SYN/SYN-ACK/RST/
FIN counts), destination ports and services; session-integrity, teardown and
reliability profiles, endpoint roles and size distributions are -v."""

from __future__ import annotations

from ..tcp import TcpSummary
from . import _style as st
from ._kv import counter_line
from ._transport import SIZE, http_counters, transport_report


def _series(values: object) -> str:
    items = [int(v) for v in (values or []) if isinstance(v, (int, float))]
    return f"{st.sparkline_of(items)}  {', '.join(str(v) for v in items)}" if items else ""


def render_tcp_summary(summary: TcpSummary, limit: int = 12, verbose: bool = False) -> str:
    return transport_report(
        "TCP", summary,
        packets=summary.tcp_packets, total_bytes=summary.tcp_bytes, payload_bytes=summary.tcp_payload_bytes,
        flags=True,
        profiles=[
            ("Recon", "recon_profiles", [("Source", "source", None), ("Port", "port", None), ("Unique ports", "unique_ports", None),
                                         ("Targets", "targets", None), ("Confidence", "confidence", None)], True),
            ("Lateral movement", "lateral_movement_profiles", [("Source", "source", None), ("Targets", "targets", None),
                                                               ("Admin ports", "admin_ports", None), ("Confidence", "confidence", None)], True),
            ("Egress outliers", "egress_outlier_profiles", [("Source", "src", None), ("Destination", "dst", None),
                                                            ("Bytes", "bytes", SIZE), ("Confidence", "confidence", None)], True),
            ("Cadence", "cadence_profiles", [("Flow", "flow", None), ("Packets", "packets", None), ("Duration (s)", "duration_s", None),
                                             ("Packets/s", "pps", None), ("Avg packet", "avg_packet", None)], True),
            ("Role drift", "role_drift_profiles", [("Host", "host", None), ("Destination", "dst", None), ("Port", "port", None),
                                                   ("Reason", "reason", None), ("Confidence", "confidence", None)], True),
            ("Corroborated hosts", "corroborated_findings", [("Host", "host", None), ("Score", "score", None),
                                                             ("Confidence", "confidence", None), ("Reasons", "reasons", None)], True),
            ("Session integrity", "session_integrity_profiles", [("Flow", "flow", None), ("Issue", "issue", None),
                                                                 ("Packets", "packets", None), ("Confidence", "confidence", None)], False),
            ("Teardown", "teardown_profiles", [("Flow", "flow", None), ("RST", "rst", None), ("FIN", "fin", None),
                                               ("Confidence", "confidence", None)], False),
            ("Transport reliability", "transport_abuse_profiles", [("Host", "host", None), ("Type", "type", None),
                                                                   ("Count", "count", None), ("Confidence", "confidence", None)], False),
        ],
        counters=[counter_line("SYN by source", getattr(summary, "syn_counts", None), None),
                  counter_line("RST by source", getattr(summary, "rst_counts", None), None),
                  ("Retransmissions over time", _series(getattr(summary, "retrans_timeseries", None)))]
        + http_counters(summary),
        deterministic=("Deterministic TCP Security Checks", [
            ("handshake_asymmetry_or_recon", "Handshake asymmetry/recon"), ("rst_teardown_abuse", "RST/teardown abuse"),
            ("tcp_periodic_cadence", "TCP periodic cadence"), ("lateral_movement_surface", "Lateral movement surface"),
            ("egress_exfil_outlier", "Egress exfil outlier"), ("transport_window_or_retrans_abuse", "Transport retrans/window abuse"),
        ]),
    )
