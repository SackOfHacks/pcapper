"""Rendered output for hosts analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations

from ..hosts import HostSummary
from . import _style as st
from ._common import (
    _redact_in_text,
    _render_deterministic_checks,
)


def render_hosts_summary(summary: HostSummary, limit: int = 30, verbose: bool = False) -> str:
    """The host inventory: every IP with its MACs, names, OS guess, traffic
    and the ports it served; priority hosts, lateral-movement and drift
    profiles follow when the analyzer produced them. OS evidence and
    method notes are -v."""
    rep = st.Report("Hosts", summary.path)
    hosts = list(summary.hosts)
    total = summary.total_hosts or len(hosts)
    if not hosts:
        return rep.absent("hosts", summary.errors)
    with_mac = sum(1 for h in hosts if h.mac_addresses)
    with_name = sum(1 for h in hosts if h.hostnames)
    with_os = sum(1 for h in hosts if h.operating_system and h.operating_system.lower() != "unknown")
    rep.headline(False, f"{st.plural(total, 'host')}", st.join([
        f"{with_mac} with MAC", f"{with_name} named", f"{with_os} with OS guess",
        st.size(sum(h.bytes_sent + h.bytes_recv for h in hosts)),
    ]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    verbose_view = st.verbose()

    def _open_ports_text(h: object) -> str:
        items = []
        for p in getattr(h, "open_ports", None) or []:
            label = f"{int(getattr(p, 'port', 0) or 0)}/{str(getattr(p, 'protocol', '') or '-').lower()} {getattr(p, 'service', '') or '-'}"
            if verbose_view and getattr(p, "software", ""):
                label += f" ({p.software})"
            items.append(label)
        if not items:
            return "-"
        return ", ".join(items) if verbose_view else ", ".join(items[:4]) + (st.dim(f", +{len(items) - 4}") if len(items) > 4 else "")

    rep.section("Inventory", st.table(
        ["IP", "MAC", "Hostname", "OS", "Sent", "Received", "Serves"],
        [[h.ip, ", ".join(h.mac_addresses) or "-", _redact_in_text(", ".join(h.hostnames)) or "-", h.operating_system or "unknown",
          f"{st.size(h.bytes_sent)} ({st.count(h.packets_sent)})", f"{st.size(h.bytes_recv)} ({st.count(h.packets_recv)})", _open_ports_text(h)]
         for h in hosts],
        widths=(None, 40, 40, 28, None, None, 60), align="llllrrl", max_rows=limit, noun="host",
    ))

    def _profile(title: str, field: str, header_row: list[str], keys: list[str], default: bool = True) -> None:
        rows = []
        for item in getattr(summary, field, None) or []:
            if not isinstance(item, dict):
                continue
            rows.append([", ".join(str(v) for v in item.get(k)) if isinstance(item.get(k), (list, tuple, set))
                         else item.get(k, "-") for k in keys])
        rep.section(title, st.table(header_row, rows, max_rows=12), detail=not default)

    _profile("Priority hosts", "host_risk_profiles", ["Host", "Score", "Severity", "Confidence", "OS", "Reasons"],
             ["host", "score", "severity", "confidence", "os", "reasons"])
    _profile("Lateral movement", "lateral_movement_profiles", ["Host", "Admin ports", "Count", "Confidence"],
             ["host", "admin_ports", "admin_port_count", "confidence"])
    _profile("Role drift", "role_drift_profiles", ["Host", "Roles", "Hostnames", "Admin ports", "OS"],
             ["host", "roles", "hostnames", "admin_ports", "os"])
    _profile("Identity drift", "identity_drift_profiles", ["Hostname", "Hosts", "Addresses"], ["hostname", "host_count", "hosts"])
    clusters = [[c.get("cluster", "-"), c.get("host", "-"), len(c.get("indicators", []) or []), c.get("target_count", "-"),
                 c.get("confidence", "-")] for c in (getattr(summary, "incident_clusters", None) or []) if isinstance(c, dict)]
    rep.section("Incident clusters", st.table(["Cluster", "Host", "Indicators", "Targets", "Confidence"], clusters, max_rows=12))

    rep.section("Assessment", st.kv([
        ("Verdict", str(summary.analyst_verdict or "")),
        ("Confidence", str(getattr(summary, "analyst_confidence", "") or "")),
    ]) + st.bullets([_redact_in_text(str(r)) for r in (getattr(summary, "analyst_reasons", None) or [])], max_items=None),
        detail=True)
    rep.section("OS evidence", st.table(
        ["IP", "OS guess", "Evidence"], [[h.ip, h.operating_system or "unknown", " | ".join(h.os_evidence)] for h in hosts if h.os_evidence],
        max_rows=None,
    ), detail=True)
    rep.section("Windows", st.table(["IP", "First seen", "Last seen"],
                                    [[h.ip, st.ts(h.first_seen), st.ts(h.last_seen)] for h in hosts], max_rows=None), detail=True)
    rep.section("False-positive context", st.bullets(
        [_redact_in_text(str(v)) for v in (getattr(summary, "false_positive_context", None) or []) if str(v).strip()],
        max_items=None), detail=True)
    rep.section("Method", st.bullets([
        "OS guesses are passive and should be confirmed with endpoint telemetry.",
        "Open ports are inferred from server-side responses or banners; absence does not imply closed.",
        "MACs come from IP/Ethernet/ARP mapping and can change across segments.",
    ], max_items=None), detail=True)
    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic Host Security Checks", [
            ("service_exposure_risk", "Service Exposure Risk"), ("identity_drift_or_collision", "Identity Drift or Collision"),
            ("boundary_cross_zone_exposure", "Boundary Cross-Zone Exposure"), ("ot_it_boundary_crossing", "OT/IT Boundary Crossing"),
            ("evidence_provenance", "Evidence Provenance"),
        ])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
