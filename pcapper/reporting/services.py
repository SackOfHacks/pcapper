"""Rendered output for services analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from typing import TYPE_CHECKING
from ..coloring import (
    danger,
    header,
    muted,
    ok,
    warn,
)
from ..services import ServiceSummary
from ..utils import (
    format_bytes_as_mb,
)
if TYPE_CHECKING:
    from ..services import ServiceAsset

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
)


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
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"SERVICE DISCOVERY & RISK ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        for err in summary.errors:
            lines.append(danger(f"Error: {err}"))

    confirmed_assets = [
        asset
        for asset in summary.assets
        if asset.protocol == "TCP" and bool(getattr(asset, "handshake_confirmed", False))
    ]
    displayed_assets = summary.assets if verbose else confirmed_assets
    displayed_keys = {_service_asset_key(asset) for asset in displayed_assets}

    lines.append(_format_kv("Total Services", str(summary.total_services)))
    lines.append(_format_kv("Confirmed TCP Services", str(len(confirmed_assets))))
    if not verbose:
        hidden_count = max(0, summary.total_services - len(confirmed_assets))
        lines.append(_format_kv("Hidden (Unconfirmed/UDP)", str(hidden_count)))

    # 1. Active Services Inventory
    lines.append(SUBSECTION_BAR)
    lines.append(header("Active Services (Servers)"))

    if not displayed_assets:
        lines.append(
            muted(
                "No handshake-confirmed TCP services identified. Use `-v` to include inferred/UDP service observations."
            )
        )
    else:
        rows = [["Address", "Port", "Proto", "Service", "Software", "Clients", "Vol"]]
        if verbose:
            rows[0].append("Discovery")
        for asset in displayed_assets:
            software = asset.software or "-"
            vol = format_bytes_as_mb(asset.bytes)
            row = [
                asset.ip,
                str(asset.port),
                asset.protocol,
                asset.service_name,
                software,
                str(len(asset.clients)),
                vol,
            ]
            if verbose:
                row.append(str(getattr(asset, "discovery_method", "observed")))
            rows.append(row)
        lines.append(_format_table(rows))

    # Internet-exposed attack surface — public-IP-bound services. High-value
    # triage, shown by default (not gated on -v).
    boundary_profiles = list(getattr(summary, "boundary_exposure_profiles", []) or [])
    if boundary_profiles:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Internet-Exposed Attack Surface (public IPs)"))
        lines.append(
            danger(
                f"{len(boundary_profiles)} service(s) bound to public IP(s) — "
                "reachable from the internet."
            )
        )
        rows = [["Asset", "Service", "Clients", "Packets"]]
        for profile in boundary_profiles[: _limit_value(15)]:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("asset", "-")),
                    str(profile.get("service", "-")),
                    str(profile.get("clients", 0)),
                    str(profile.get("packets", 0)),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    if summary.hierarchy and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Service Prevalence"))
        rows = [["Service", "Count"]]
        for name, count in sorted(
            summary.hierarchy.items(), key=lambda item: item[1], reverse=True
        ):
            rows.append([name, str(count)])
        lines.append(_format_table(rows))

    banners = [asset for asset in displayed_assets if asset.software]
    if banners and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Service Banners"))
        rows = [["Address", "Port", "Service", "Banner"]]
        for asset in banners:
            rows.append(
                [
                    asset.ip,
                    str(asset.port),
                    asset.service_name,
                    asset.software or "-",
                ]
            )
        lines.append(_format_table(rows))

    # 2. Risks / Threats
    lines.append(SUBSECTION_BAR)
    lines.append(header("Cybersecurity Risks"))

    risk_pool = list(summary.risks)
    if not verbose:
        risk_pool = [
            risk
            for risk in risk_pool
            if str(risk.severity or "").upper() in {"CRITICAL", "HIGH", "MEDIUM"}
            and str(risk.affected_asset or "").split("/", 1)[0] in displayed_keys
        ]
    if not risk_pool:
        lines.append(ok("No high-confidence service risks detected."))
    else:
        severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_risks = sorted(
            risk_pool,
            key=lambda x: (
                severity_rank.get(str(x.severity or "").upper(), 99),
                str(x.title or ""),
            ),
        )
        for risk in sorted_risks:
            sev_color = danger if risk.severity in ("CRITICAL", "HIGH") else warn
            if risk.severity == "LOW":
                sev_color = muted
            lines.append(sev_color(f"[{risk.severity}] {risk.title}"))
            lines.append(f"  Target: {risk.affected_asset}")
            lines.append(muted(f"  Details: {risk.description}"))
            lines.append("")

    verdict = str(getattr(summary, "analyst_verdict", "") or "")
    confidence = str(getattr(summary, "analyst_confidence", "") or "").upper()
    reasons = [str(v) for v in list(getattr(summary, "analyst_reasons", []) or [])]
    if verdict:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Analyst Verdict"))
        if confidence:
            lines.append(_format_kv("Verdict", f"{verdict} (confidence: {confidence})"))
        else:
            lines.append(_format_kv("Verdict", verdict))
        if reasons:
            for reason in reasons:
                lines.append(muted(f"- {reason}"))
        tids = _services_mitre_techniques(summary)
        if tids:
            lines.append(muted("  ATT&CK: " + ", ".join(tids)))

    checks = dict(getattr(summary, "deterministic_checks", {}) or {})
    if checks:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Deterministic Service Security Checks"))
        check_labels = {
            "exposed_datastores": "Exposed databases/datastores",
            "internet_exposed_surface": "Internet-exposed services",
            "service_identity_mismatch": "Service identity mismatch",
            "lateral_admin_surface": "Lateral admin surface",
            "public_edge_admin_exposure": "Public edge admin exposure",
            "ot_it_boundary_mix": "OT/IT boundary mix",
            "udp_amplification_readiness": "UDP amplification readiness",
            "legacy_or_weak_service_hygiene": "Legacy/weak hygiene",
            "evidence_provenance": "Evidence provenance",
        }
        for key, label_text in check_labels.items():
            values = [str(v) for v in list(checks.get(key, []) or [])]
            if values:
                lines.append(warn(f"[!] {label_text}: {len(values)}"))
                for item in values:
                    lines.append(muted(f"  - {item}"))
            else:
                lines.append(ok(f"[ ] {label_text}: none"))


    mismatch_profiles = list(getattr(summary, "service_mismatch_profiles", []) or [])
    if mismatch_profiles and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Service Mismatch Profiles"))
        rows = [["Asset", "Service", "Software", "Reasons"]]
        for profile in mismatch_profiles:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("asset", "-")),
                    str(profile.get("service", "-")),
                    str(profile.get("software", "-")),
                    ", ".join(str(v) for v in list(profile.get("reasons", []) or []))
                    or "-",
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    drift_profiles = list(getattr(summary, "service_drift_profiles", []) or [])
    if drift_profiles and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Service Drift Profiles"))
        rows = [["Host", "Service", "Ports", "Banner Count"]]
        for profile in drift_profiles:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("host", "-")),
                    str(profile.get("service", "-")),
                    ",".join(str(v) for v in list(profile.get("ports", []) or []))
                    or "-",
                    str(profile.get("banner_count", 0)),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    lateral_profiles = list(getattr(summary, "lateral_surface_profiles", []) or [])
    if lateral_profiles and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Lateral Surface Profiles"))
        rows = [["Host", "Admin Ports", "Count", "Confidence"]]
        for profile in lateral_profiles:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("host", "-")),
                    ",".join(str(v) for v in list(profile.get("admin_ports", []) or []))
                    or "-",
                    str(profile.get("admin_port_count", 0)),
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    boundary_profiles = list(getattr(summary, "boundary_exposure_profiles", []) or [])
    if boundary_profiles and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Boundary Exposure Profiles"))
        rows = [["Asset", "Service", "Clients", "Packets"]]
        for profile in boundary_profiles:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("asset", "-")),
                    str(profile.get("service", "-")),
                    str(profile.get("clients", 0)),
                    str(profile.get("packets", 0)),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    ot_it_profiles = list(getattr(summary, "ot_it_crossing_profiles", []) or [])
    if ot_it_profiles and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("OT/IT Crossing Profiles"))
        rows = [["Host", "OT Ports", "Admin Ports", "Confidence"]]
        for profile in ot_it_profiles:
            if not isinstance(profile, dict):
                continue
            rows.append(
                [
                    str(profile.get("host", "-")),
                    ",".join(str(v) for v in list(profile.get("ot_ports", []) or []))
                    or "-",
                    ",".join(str(v) for v in list(profile.get("admin_ports", []) or []))
                    or "-",
                    str(profile.get("confidence", "-")),
                ]
            )
        if len(rows) > 1:
            lines.append(_format_table(rows))

    false_positive_context = [
        str(v)
        for v in list(getattr(summary, "false_positive_context", []) or [])
        if str(v).strip()
    ]
    if false_positive_context and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("False-Positive Context"))
        for item in false_positive_context:
            lines.append(muted(f"- {item}"))

    if not verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(
            muted(
                "Default view shows handshake-confirmed TCP services and likely risks only."
            )
        )
        lines.append(
            muted(
                "Use `-v` to include inferred TCP/UDP services, low-severity risks, and full deterministic profile detail."
            )
        )

    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)
