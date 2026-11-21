"""Rendered output for services analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..services import ServiceSummary
from . import _style as st
from ._common import _render_deterministic_checks
from ._kv import counter_line

if TYPE_CHECKING:
    from ..services import ServiceAsset



def _service_asset_key(asset: ServiceAsset) -> str:
    return f"{asset.ip}:{asset.port}"


def _services_mitre_techniques(summary: ServiceSummary) -> list[str]:
    """Map observed service-exposure findings to ATT&CK technique IDs."""
    checks = dict(getattr(summary, "deterministic_checks", {}) or {})
    tids: list[str] = []

    def _add(tid: str) -> None:
        if tid not in tids:
            tids.append(tid)

    if getattr(summary, "assets", None):
        _add("T1046 Network Service Discovery")
    if checks.get("internet_exposed_surface") or checks.get("public_edge_admin_exposure"):
        _add("T1133 External Remote Services")
    if checks.get("exposed_datastores"):
        _add("T1133 External Remote Services (exposed datastore)")
    if checks.get("lateral_admin_surface"):
        _add("T1021 Remote Services")
    risk_titles = {str(getattr(r, "title", "")) for r in (summary.risks or [])}
    if "Cleartext Service" in risk_titles:
        _add("T1040 Network Sniffing (cleartext credentials)")
    if "Potential UDP Amplification" in risk_titles:
        _add("T1498.002 Reflection Amplification")
    if checks.get("ot_it_boundary_mix") or getattr(summary, "ot_it_crossing_profiles", None):
        _add("ICS T0846 Remote System Discovery")
        _add("ICS T0822 External Remote Services")
    return tids


def render_services_summary(summary: ServiceSummary, verbose: bool = False) -> str:
    """Services observed acting as servers: risks first, then the internet-
    exposed surface and the handshake-confirmed TCP services (address, port,
    service, software banner, clients); inferred/UDP services, prevalence and
    the analyzer's profiles are -v."""
    rep = st.Report("Services", summary.path)
    show_all = st.verbose() or verbose
    confirmed = [a for a in summary.assets if a.protocol == "TCP" and bool(getattr(a, "handshake_confirmed", False))]
    shown = summary.assets if show_all else confirmed
    shown_keys = {_service_asset_key(a) for a in shown}
    risks = list(summary.risks)
    if not show_all:
        risks = [r for r in risks if str(r.severity or "").upper() in {"CRITICAL", "HIGH", "MEDIUM"}
                 and str(r.affected_asset or "").split("/", 1)[0] in shown_keys]
    findings = [st.finding({"severity": r.severity, "title": r.title, "details": r.description,
                            "dst": str(r.affected_asset or "")}) for r in risks]
    if not summary.total_services and not st.material(findings):
        return rep.absent("services", summary.errors)
    severity, text = st.verdict(findings, high="high-risk services exposed: investigate", medium="service risks to review")
    rep.headline(severity, text, st.join([
        st.plural(summary.total_services, "service"), f"{len(confirmed)} confirmed TCP",
        f"{summary.total_services - len(confirmed)} inferred/UDP (-v)" if not show_all and summary.total_services > len(confirmed) else "",
    ]))
    tids = _services_mitre_techniques(summary)
    if tids:
        rep.scope("ATT&CK: " + ", ".join(tids))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))
    # A public server address is an external site in a client capture and
    # internet exposure when the server is yours: the Scope column says
    # which side of the boundary it is on, the analyst knows which applies.
    from ..utils import is_public_ip

    rep.section("Services", st.table(
        ["Address", "Port", "Proto", "Service", "Software", "Clients", "Bytes", "Scope"] + (["Discovery"] if show_all else []),
        [[a.ip, a.port, a.protocol, a.service_name, a.software or "-", st.count(len(a.clients)), st.size(a.bytes),
          "public" if is_public_ip(a.ip) else "private"]
         + ([getattr(a, "discovery_method", "observed")] if show_all else []) for a in shown],
        align="lrlllrrl", widths=(None, None, None, None, 50), max_rows=25, noun="service",
    ) or [f"  {st.dim('no handshake-confirmed TCP services (-v includes inferred and UDP services)')}"])
    exposed = [p for p in (getattr(summary, "boundary_exposure_profiles", None) or []) if isinstance(p, dict)]
    rep.section("Boundary exposure", st.table(
        ["Asset", "Service", "Clients", "Packets"],
        [[p.get("asset", "-"), p.get("service", "-"), st.count(p.get("clients", 0)), st.count(p.get("packets", 0))]
         for p in exposed], align="llrr", max_rows=None, noun="service",
    ), detail=True)

    rep.section("Assessment", st.kv([
        ("Verdict", str(getattr(summary, "analyst_verdict", "") or "")),
        ("Confidence", str(getattr(summary, "analyst_confidence", "") or "")),
    ]) + st.bullets([str(r) for r in (getattr(summary, "analyst_reasons", None) or [])], max_items=None), detail=True)
    rep.section("Prevalence", st.kv([counter_line("Services", summary.hierarchy, None)]), detail=True)
    rep.section("Banners", st.table(["Address", "Port", "Service", "Banner"],
                                    [[a.ip, a.port, a.service_name, a.software] for a in shown if a.software], max_rows=None),
                detail=True)

    def _profile(title: str, field: str, header_row: list[str], keys: list[str]) -> None:
        rows = []
        for p in getattr(summary, field, None) or []:
            if not isinstance(p, dict):
                continue
            rows.append([", ".join(str(v) for v in p.get(k)) if isinstance(p.get(k), (list, tuple, set)) else p.get(k, "-")
                         for k in keys])
        rep.section(title, st.table(header_row, rows, max_rows=None), detail=True)

    _profile("Identity mismatches", "service_mismatch_profiles", ["Asset", "Service", "Software", "Reasons"],
             ["asset", "service", "software", "reasons"])
    _profile("Service drift", "service_drift_profiles", ["Host", "Service", "Ports", "Banners"], ["host", "service", "ports", "banner_count"])
    _profile("Lateral surface", "lateral_surface_profiles", ["Host", "Admin ports", "Count", "Confidence"],
             ["host", "admin_ports", "admin_port_count", "confidence"])
    _profile("OT/IT crossings", "ot_it_crossing_profiles", ["Host", "OT ports", "Admin ports", "Confidence"],
             ["host", "ot_ports", "admin_ports", "confidence"])
    rep.section("False-positive context", st.bullets([str(v) for v in (summary.false_positive_context or []) if str(v).strip()],
                                                     max_items=None), detail=True)
    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic Service Security Checks", [
            ("exposed_datastores", "Exposed databases/datastores"), ("internet_exposed_surface", "Internet-exposed services"),
            ("service_identity_mismatch", "Service identity mismatch"), ("lateral_admin_surface", "Lateral admin surface"),
            ("public_edge_admin_exposure", "Public edge admin exposure"), ("ot_it_boundary_mix", "OT/IT boundary mix"),
            ("udp_amplification_readiness", "UDP amplification readiness"),
            ("legacy_or_weak_service_hygiene", "Legacy/weak hygiene"),
            ("protocol_confusion_false_positive", "Protocol-confusion false-positive context"),
            ("evidence_provenance", "Evidence provenance"),
        ])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
