"""Rendered output for vpn analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..coloring import (
    header,
    muted,
)
from ..vpn import VpnSummary

from ._common import (
    SUBSECTION_BAR,
    _finalize_output,
    _format_counter,
    _format_kv,
    _limit_value,
    _render_protocol_verdict,
)


def render_vpn_summary(summary: VpnSummary) -> str:
    lines = [header("VPN/TUNNEL ANALYSIS")]
    _render_protocol_verdict(
        lines, label="VPN", detections=getattr(summary, "detections", None)
    )
    lines.append(_format_kv("VPN Packets", str(summary.vpn_packets)))
    lines.append(_format_kv("Services", _format_counter(summary.service_counts, 6)))
    if summary.protocol_counts:
        lines.append(_format_kv("Protocols", _format_counter(summary.protocol_counts, 6)))
    if summary.server_port_counts:
        lines.append(
            _format_kv("Server Ports", _format_counter(summary.server_port_counts, 6))
        )
    if summary.handshake_counts:
        lines.append(_format_kv("Handshakes", _format_counter(summary.handshake_counts, 6)))
    if summary.certificate_count:
        lines.append(_format_kv("Certificates", str(summary.certificate_count)))
        if summary.certificate_subjects:
            lines.append(
                _format_kv(
                    "Cert Subjects",
                    _format_counter(summary.certificate_subjects, 4, key_max=36),
                )
            )
        if summary.certificate_issuers:
            lines.append(
                _format_kv(
                    "Cert Issuers",
                    _format_counter(summary.certificate_issuers, 4, key_max=36),
                )
            )
        if summary.self_signed_cert_count:
            lines.append(
                _format_kv("Self-Signed Certs", str(summary.self_signed_cert_count))
            )
        if summary.weak_cert_count:
            lines.append(_format_kv("Weak Certs", str(summary.weak_cert_count)))
    if summary.threat_counts:
        lines.append(_format_kv("Threats", _format_counter(summary.threat_counts, 5)))
    if summary.anomaly_counts:
        lines.append(_format_kv("Anomalies", _format_counter(summary.anomaly_counts, 5)))
    lines.append(_format_kv("Top Clients", _format_counter(summary.client_counts, 5)))
    lines.append(_format_kv("Top Servers", _format_counter(summary.server_counts, 5)))
    if summary.artifact_correlations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifact/Client/Server Correlation"))
        for relation, count in summary.artifact_correlations.most_common(_limit_value(10)):
            lines.append(muted(f"- {relation} ({count})"))
    return _finalize_output(lines)
