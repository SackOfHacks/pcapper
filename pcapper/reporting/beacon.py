"""Rendered output for beacon analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
import ipaddress
from collections import Counter
from ..beacon import (
    MGMT_PORTS as _BCN_MGMT_PORTS,
    OT_PORTS as _BCN_OT_PORTS,
    TUNNEL_PORTS as _BCN_TUNNEL_PORTS,
    BeaconSummary,
)
from ..coloring import (
    danger,
    header,
    label,
    muted,
    ok,
    warn,
)
from ..services import COMMON_PORTS
from ..utils import (
    format_duration,
    sparkline,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _apply_verbose_limit,
    _filtered_detections,
    _finalize_output,
    _format_kv,
    _format_table,
    _highlight_public_ips,
    _limit_value,
    _redact_in_text,
)


def _beacon_ip_is_public(ip_text: object) -> bool:
    try:
        return ipaddress.ip_address(str(ip_text)).is_global
    except Exception:
        return False


def _beacon_ip_is_private(ip_text: object) -> bool:
    try:
        return ipaddress.ip_address(str(ip_text)).is_private
    except Exception:
        return False


def _beacon_classify(cand) -> dict[str, object]:
    """Classify a beacon candidate for triage: what it most likely is, whether
    it is C2-relevant (vs OT/benign baseline), a severity, and the next action.

    The whole point of the beacon analyzer is periodicity detection, but in OT
    periodicity is the baseline (cyclic polling / I/O), so a hunt tool must
    separate genuine C2 candidates (external, uncommon-port, tunnel) from
    expected internal automation."""
    port_value = getattr(cand, "src_port", None) or getattr(cand, "dst_port", None)
    proto = str(getattr(cand, "proto", ""))
    src = str(getattr(cand, "src_ip", ""))
    dst = str(getattr(cand, "dst_ip", ""))
    score = float(getattr(cand, "score", 0.0) or 0.0)
    count = int(getattr(cand, "count", 0) or 0)
    is_external = _beacon_ip_is_public(src) or _beacon_ip_is_public(dst)
    is_internal = _beacon_ip_is_private(src) and _beacon_ip_is_private(dst)
    is_ot = port_value in _BCN_OT_PORTS
    is_mgmt = port_value in _BCN_MGMT_PORTS
    is_tunnel = port_value in _BCN_TUNNEL_PORTS
    is_l2 = proto.startswith("L2:")
    established_ratio = float(getattr(cand, "established_ratio", 1.0) or 0.0)
    data_bytes = int(getattr(cand, "data_bytes", 0) or 0)
    # A TCP flow that never completed a handshake and carried no payload is a
    # string of failed/refused connection attempts (dead or firewalled C2),
    # NOT a data-bearing channel - even though the SYN cadence looks perfect.
    failed_attempts = proto == "TCP" and established_ratio < 0.1 and data_bytes == 0

    # Defaults
    label = "Periodic flow"
    c2_relevant = False
    severity = "info"
    action = f"--streams -ip {src}   (inspect the conversation payload/SNI)"

    if failed_attempts:
        if is_external:
            label = "Failed/refused connection attempts to public IP (dead or blocked C2)"
            c2_relevant = True
            severity = "high"
            action = (
                f"--streams -ip {src}   (no session established / no payload; confirm "
                f"{dst} is a C2 endpoint and check firewall/proxy deny logs for the retries)"
            )
        else:
            label = "Failed/refused internal connection attempts (no session/payload)"
            c2_relevant = is_mgmt
            severity = "warning" if is_mgmt else "info"
            action = f"--streams -ip {src}   (unanswered connection attempts; check host/service availability)"
    elif is_external and is_ot:
        label = "OT/ICS telemetry beaconing to public IP"
        c2_relevant = True
        severity = "critical"
        action = f"--hostdetails -ip {src}   then --ot-commands; treat OT egress as exposure until proven sanctioned"
    elif is_external and is_tunnel and float(getattr(cand, "avg_bytes", 0.0) or 0.0) <= 400:
        label = "Periodic beacon over tunnel-friendly port (DNS/HTTPS/VPN)"
        c2_relevant = True
        severity = "high" if score >= 0.8 else "warning"
        action = f"--streams -ip {src}   (check for tunneling / covert channel; confirm destination reputation)"
    elif is_external:
        label = "External periodic beacon (private->public)"
        c2_relevant = True
        severity = "critical" if (score >= 0.85 and count >= 30) else "high" if score >= 0.75 else "warning"
        action = f"--streams -ip {src}   then --hostdetails -ip {src}; confirm destination reputation (C2 vs SaaS/update)"
    elif is_internal and is_ot:
        label = "Internal OT cyclic poll (baseline)"
        c2_relevant = False
        severity = "info"
        action = "verify the (src,dst,port) tuple against a process baseline; periodicity here is expected"
    elif is_internal and is_mgmt:
        label = "Internal beacon on admin/mgmt port (lateral/persistence)"
        c2_relevant = True
        severity = "warning"
        action = f"--hostdetails -ip {src}   (confirm whether remote-admin/scheduled task is sanctioned)"
    elif is_l2:
        label = "Layer-2 periodic control signal"
        c2_relevant = False
        severity = "info"
        action = "L2 OT/control traffic; baseline-expected, verify station inventory"
    elif proto == "ICMP":
        label = "ICMP periodic activity"
        c2_relevant = is_external
        severity = "warning" if is_external else "info"
        action = f"--streams -ip {src}   (rule out ping monitoring before ICMP tunnel)"
    elif (
        is_internal
        and port_value
        and port_value not in COMMON_PORTS
        and score >= 0.8
        and count >= 15
    ):
        # Internal periodic flow on a non-service, non-OT, non-admin port is the
        # shape of an internal worm / staged C2 hop - worth a look even though
        # it stays inside the perimeter.
        label = "Internal beacon on uncommon port (possible internal C2/worm)"
        c2_relevant = True
        severity = "warning"
        action = f"--hostdetails -ip {src}   then --streams -ip {src} (identify the listening service/process)"
    else:
        label = "Internal periodic flow"
        c2_relevant = False
        severity = "info"
        action = "establish the service/role; likely automation or monitoring"

    return {
        "label": label,
        "c2_relevant": c2_relevant,
        "severity": severity,
        "action": action,
        "is_external": is_external,
        "score": score,
        "count": count,
    }


_BEACON_SEV_RANK = {"info": 0, "warning": 1, "high": 2, "critical": 3}


def render_beacon_summary(
    summary: BeaconSummary, limit: int = 12, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit)
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"BEACON ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    lines.append(_format_kv("Packets", str(summary.total_packets)))
    lines.append(_format_kv("Candidates", str(summary.candidate_count)))

    def _emit_campaign_rollup_tables() -> None:
        if getattr(summary, "campaign_summaries", None):
            lines.append(SUBSECTION_BAR)
            lines.append(header("Beacon Campaign Summary"))
            rows = [
                [
                    "Campaign",
                    "Host",
                    "Cadence",
                    "Flows",
                    "Destinations",
                    "Channels",
                    "Max Score",
                ]
            ]
            for item in summary.campaign_summaries[:limit]:
                rows.append(
                    [
                        str(item.get("campaign_id", "-")),
                        str(item.get("host", "-")),
                        str(item.get("cadence_family", "-")),
                        str(item.get("flows", "-")),
                        str(item.get("destinations", "-")),
                        str(item.get("channels", "-")),
                        str(item.get("max_score", "-")),
                    ]
                )
            lines.append(_format_table(rows))

        if getattr(summary, "host_rollups", None):
            lines.append(SUBSECTION_BAR)
            lines.append(header("Host-Centric Verdict Rollup"))
            rows = [
                [
                    "Host",
                    "Candidates",
                    "Channels",
                    "Destinations",
                    "Top Cadence",
                    "Max Score",
                ]
            ]
            for item in summary.host_rollups[:limit]:
                channels = item.get("channels", [])
                channel_text = (
                    ",".join(str(v) for v in channels)
                    if isinstance(channels, list)
                    else str(channels)
                )
                rows.append(
                    [
                        str(item.get("host", "-")),
                        str(item.get("candidate_count", "-")),
                        channel_text or "-",
                        str(item.get("destinations", "-")),
                        f"{float(item.get('top_cadence_s', 0.0) or 0.0):.2f}s",
                        str(item.get("max_score", "-")),
                    ]
                )
            lines.append(_format_table(rows))

    candidates = list(getattr(summary, "candidates", []) or [])
    classified = [(cand, _beacon_classify(cand)) for cand in candidates]
    # C2-relevant candidates, ranked by severity then score: the triage queue.
    c2_candidates = sorted(
        (pair for pair in classified if pair[1].get("c2_relevant")),
        key=lambda pair: (
            _BEACON_SEV_RANK.get(str(pair[1].get("severity")), 0),
            float(pair[1].get("score", 0.0) or 0.0),
            int(pair[1].get("count", 0) or 0),
        ),
        reverse=True,
    )

    def _beacon_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        http_posts = list(getattr(summary, "http_post_beacons", []) or [])
        det_cat = getattr(summary, "deterministic_category_checks", {}) or {}
        det_checks = getattr(summary, "deterministic_checks", {}) or {}

        # If every candidate is internal OT-cyclic / benign-service periodicity,
        # the capture is baseline automation: synchronized/low-slow cadence among
        # those flows is the *expected* shape (a SCADA master polling its PLCs),
        # so the campaign-level escalators below must not inflate the verdict.
        baseline_only = bool(classified) and not c2_candidates

        # The strongest C2 signal is a periodic flow crossing to a public peer.
        critical_ext = [p for p in c2_candidates if p[1].get("severity") == "critical"]
        high_ext = [p for p in c2_candidates if p[1].get("severity") == "high"]
        if critical_ext:
            score += 5
            top = critical_ext[0]
            reasons.append(
                f"{len(critical_ext)} critical external/OT beacon(s) "
                f"(e.g. {top[0].src_ip}->{top[0].dst_ip} score={top[1]['score']:.2f})"
            )
        if high_ext:
            score += min(3, len(high_ext) + 1)
            top = high_ext[0]
            reasons.append(
                f"{len(high_ext)} high-severity external beacon(s) "
                f"(e.g. {top[0].src_ip}->{top[0].dst_ip} score={top[1]['score']:.2f})"
            )

        # Persistent, high-volume failed/refused beaconing to a public peer is
        # itself strong infection evidence (an internal host calling home to a
        # dead/blocked C2 on a fixed cadence), even though no session ever
        # established - so it escalates the verdict on its own.
        failed_ext_strong = [
            p
            for p in c2_candidates
            if "failed/refused" in str(p[1].get("label", "")).lower()
            and p[1].get("is_external")
            and int(getattr(p[0], "count", 0) or 0) >= 50
            and float(getattr(p[0], "periodicity_score", 0.0) or 0.0) >= 0.7
        ]
        if failed_ext_strong:
            score += 3
            top = failed_ext_strong[0]
            reasons.append(
                f"Persistent failed C2 beaconing to a public IP "
                f"({top[0].src_ip}->{top[0].dst_ip}, {top[0].count} attempts) — "
                "infected host calling a dead/blocked C2"
            )

        # Campaign-level escalators (suppressed when only baseline OT/service
        # periodicity is present, since that cadence is expected automation).
        if not baseline_only:
            if det_cat.get("multi_target_synchronized"):
                score += 2
                reasons.append(
                    "Synchronized multi-destination cadence (fan-out C2 shape)"
                )
            if det_cat.get("cross_protocol_cadence"):
                score += 2
                reasons.append("Cross-protocol cadence reuse on the same pair")
            if det_cat.get("low_slow_persistence"):
                score += 1
                reasons.append("Low-and-slow persistent periodicity")

        if http_posts:
            max_http_risk = max(
                (int(item.get("risk_score", 0) or 0) for item in http_posts), default=0
            )
            score += 2 if max_http_risk >= 3 else 1
            reasons.append(
                f"HTTP POST check-in channel(s) ({len(http_posts)}; max risk={max_http_risk})"
            )
        if det_checks.get("dns_beaconing_or_tunnel_pattern"):
            score += 1
            reasons.append("DNS failover/tunnel semantics (elevated NXDOMAIN)")

        # Internal mgmt-port persistence is a lateral/persistence lead (weaker
        # than external C2 but still actionable).
        mgmt_internal = [p for p in c2_candidates if "mgmt" in str(p[1].get("label", "")).lower()]
        if mgmt_internal and not critical_ext and not high_ext:
            score += 1
            reasons.append(
                f"{len(mgmt_internal)} internal beacon(s) on admin/mgmt ports (lateral/persistence)"
            )

        # OT-internal cyclic and benign-service periodicity are baseline; they do
        # NOT raise the verdict (recorded under 'Likely Benign' instead).
        if baseline_only:
            reasons.append(
                "Only internal OT-cyclic / benign-service periodicity observed "
                "(baseline, not C2)"
            )

        if score >= 7:
            verdict = "YES - high-confidence C2-style beaconing is present."
            confidence = "High"
        elif score >= 4:
            verdict = "LIKELY - external beaconing indicators with corroboration."
            confidence = "Medium"
        elif score >= 2:
            verdict = "POSSIBLE - weak-to-moderate beaconing indicators present."
            confidence = "Low"
        elif baseline_only:
            verdict = "BASELINE - periodic traffic looks like expected automation, not C2."
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing beaconing activity after filtering."
            confidence = "Low"

        if not reasons:
            reasons.append("No beaconing heuristic crossed a high-confidence threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _beacon_verdict()
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", f"{confidence} (score={verdict_score})"))
    lines.append(muted("Why:"))
    for reason in verdict_reasons[: _limit_value(8)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    # Focus Here First: the C2-relevant candidates with a per-lead action.
    if c2_candidates:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Focus Here First (C2-relevant beacons)"))
        for idx, (cand, info) in enumerate(c2_candidates[: _limit_value(6)], start=1):
            sev = str(info.get("severity", "info")).upper()
            sev_style = (
                danger if sev in {"CRITICAL", "HIGH"} else warn if sev == "WARNING" else muted
            )
            port_value = cand.src_port or cand.dst_port
            cadence = f"{cand.mean_interval:.0f}s" if cand.mean_interval else "-"
            lines.append(
                sev_style(
                    f"{idx}. [{sev}] {_highlight_public_ips(cand.src_ip)} -> "
                    f"{_highlight_public_ips(cand.dst_ip)} {cand.proto}"
                    f"{('/' + str(port_value)) if port_value else ''} - {info['label']}"
                )
            )
            lines.append(
                muted(
                    f"   cadence≈{cadence} jitter={cand.jitter:.2f} count={cand.count} "
                    f"score={cand.score:.2f} {sparkline(cand.timeline)}"
                )
            )
            lines.append(muted(f"   run:  pcapper <capture> {info['action']}"))

    # Likely benign / don't chase: surface the baseline periodicity explicitly.
    benign_labels: Counter[str] = Counter()
    for _cand, info in classified:
        if not info.get("c2_relevant"):
            benign_labels[str(info.get("label"))] += 1
    if benign_labels:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Likely Benign / Don't Chase"))
        for label_text, count in benign_labels.most_common(_limit_value(5)):
            lines.append(muted(f"- {label_text}: {count} flow(s)"))
        lines.append(
            muted(
                "- OT/control periodicity and steady service traffic are the baseline; "
                "confirm against a process/asset baseline before escalating, and treat "
                "anything inside a change window as expected."
            )
        )

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    # ---- Supporting detail (campaigns, rollups, full candidate table) -------
    _emit_campaign_rollup_tables()

    if summary.candidates:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Supporting Detail :: Beacon Candidates (RITA-style scoring)"))
        rows = [
            [
                "Src",
                "Dst",
                "Proto",
                "Count",
                "Duration",
                "Mean",
                "MAD",
                "Avg Bytes",
                "Size MAD",
                "Periodicity",
                "Size",
                "Duration",
                "Count",
                "Score",
            ]
        ]
        for cand in summary.candidates[:limit]:
            if cand.src_port and cand.dst_port:
                proto_label = f"{cand.proto}:{cand.src_port}->{cand.dst_port}"
            elif cand.src_port:
                proto_label = f"{cand.proto}:{cand.src_port}"
            else:
                proto_label = cand.proto
            score_text = f"{cand.score:.2f}"
            if cand.score >= 0.85:
                score_text = danger(score_text)
            elif cand.score >= 0.65:
                score_text = warn(score_text)
            else:
                score_text = ok(score_text)
            duration_text = (
                format_duration(cand.duration_seconds) if cand.duration_seconds else "-"
            )
            rows.append(
                [
                    cand.src_ip,
                    cand.dst_ip,
                    proto_label,
                    str(cand.count),
                    duration_text,
                    f"{cand.mean_interval:.2f}s",
                    f"{cand.mad_interval:.2f}s",
                    f"{cand.avg_bytes:.0f}",
                    f"{cand.mad_bytes:.0f}",
                    f"{cand.periodicity_score:.2f}",
                    f"{cand.size_score:.2f}",
                    f"{cand.duration_score:.2f}",
                    f"{cand.count_score:.2f}",
                    score_text,
                ]
            )
        lines.append(_format_table(rows))
        lines.append(
            muted(
                "Scores: Periodicity=1-MAD/Median interval, Size=1-MAD/Median bytes, "
                "Duration=duration/1h, Count=connections/50. Total score is weighted."
            )
        )

        lines.append(SUBSECTION_BAR)
        lines.append(header("Beacon Timelines"))
        for cand in summary.candidates[:limit]:
            graph = sparkline(cand.timeline)
            lines.append(f"{cand.src_ip} -> {cand.dst_ip}  {graph}")
            if verbose:
                lines.append(
                    muted(
                        "  Mean {mean:.2f}s | Median {median:.2f}s | MAD {mad:.2f}s | "
                        "Avg Bytes {avg_bytes:.0f} | Size MAD {size_mad:.0f} | "
                        "Scores P:{p:.2f} S:{s:.2f} D:{d:.2f} C:{c:.2f} | Total {score:.2f}".format(
                            mean=cand.mean_interval,
                            median=cand.median_interval,
                            mad=cand.mad_interval,
                            avg_bytes=cand.avg_bytes,
                            size_mad=cand.mad_bytes,
                            p=cand.periodicity_score,
                            s=cand.size_score,
                            d=cand.duration_score,
                            c=cand.count_score,
                            score=cand.score,
                        )
                    )
                )

    detections = _filtered_detections(summary, verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for item in detections:
            severity = item.get("severity", "info")
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity == "warning":
                marker = warn("[WARN]")
            elif severity == "critical":
                marker = danger("[CRIT]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))
            top_sources = item.get("top_sources")
            if isinstance(top_sources, list) and top_sources:
                src_text = ", ".join(
                    f"{ip}({count})" for ip, count in top_sources[: _limit_value(6)]
                )
                lines.append(muted(f"  Sources: {src_text}"))
            top_destinations = item.get("top_destinations")
            if isinstance(top_destinations, list) and top_destinations:
                dst_text = ", ".join(
                    f"{ip}({count})"
                    for ip, count in top_destinations[: _limit_value(6)]
                )
                lines.append(muted(f"  Destinations: {dst_text}"))
            evidence_items = item.get("evidence", [])
            if isinstance(evidence_items, list) and evidence_items:
                for evidence in evidence_items[: _limit_value(8)]:
                    lines.append(muted(f"    - {_redact_in_text(str(evidence))}"))

    checks = getattr(summary, "protocol_beacon_checks", {}) or {}
    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Beacon Checks"))
    protocol_labels = [
        ("dns", "DNS"),
        ("http_https", "HTTP/HTTPS"),
        ("icmp", "ICMP"),
        ("ntp", "NTP"),
    ]
    for key, proto_label in protocol_labels:
        evidence = checks.get(key) if isinstance(checks, dict) else []
        evidence_items = [str(item) for item in (evidence or []) if str(item).strip()]
        if evidence_items:
            lines.append(
                danger(
                    f"Yes, there is evidence for {proto_label} beaconing, here is the evidence:"
                )
            )
            for item in evidence_items[: _limit_value(10)]:
                lines.append(muted(f"  - {_redact_in_text(item)}"))
        else:
            lines.append(
                ok(f"No, there is no strong evidence for {proto_label} beaconing.")
            )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic Beacon Category Checks"))
    category_checks = getattr(summary, "deterministic_category_checks", {}) or {}
    category_labels = [
        ("single_target_periodic_c2", "Single-Target Periodic C2"),
        ("multi_target_synchronized", "Multi-Target Synchronized Beaconing"),
        ("cross_protocol_cadence", "Cross-Protocol Cadence Reuse"),
        ("burst_sleep_pattern", "Burst-Sleep Beacon Profile"),
        ("low_slow_persistence", "Low-and-Slow Persistence"),
        ("benign_periodic_likely", "Likely Benign Periodic Pattern"),
    ]

    for key, label_text in category_labels:
        evidence = (
            category_checks.get(key, []) if isinstance(category_checks, dict) else []
        )
        evidence_items = [str(item) for item in (evidence or []) if str(item).strip()]
        lines.append(label(label_text))
        if evidence_items:
            if key == "benign_periodic_likely":
                lines.append(
                    ok(
                        f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"
                    )
                )
            else:
                lines.append(
                    warn(
                        f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"
                    )
                )
            for item in evidence_items[: _limit_value(10 if verbose else 6)]:
                lines.append(muted(f"- {_redact_in_text(item)}"))
        else:
            lines.append(
                ok(
                    f"No, there is no strong evidence for {label_text.lower()} in this capture."
                )
            )

    # (Per-candidate timeline sparklines are shown once under "Beacon Timelines"
    # above and in the Focus Here First queue; the duplicate heatmap was removed.)

    explainability = list(getattr(summary, "explainability", []) or [])
    if explainability:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Explainability"))
        for item in explainability[: _limit_value(12 if verbose else 8)]:
            lines.append(muted(f"- {_redact_in_text(str(item))}"))

    http_post_beacons = list(getattr(summary, "http_post_beacons", []) or [])
    if http_post_beacons:
        lines.append(SUBSECTION_BAR)
        lines.append(header("HTTP POST Beacon Discovery"))
        rows = [
            [
                "Source",
                "Destination",
                "Host",
                "URI(s)",
                "Req",
                "Bytes",
                "Stability",
                "Linked",
                "Risk",
                "Packets",
            ]
        ]
        for item in http_post_beacons[: _limit_value(10)]:
            rows.append(
                [
                    str(item.get("src", "-")),
                    str(item.get("dst", "-")),
                    str(item.get("host", "-")),
                    str(item.get("uri", "-")),
                    str(int(item.get("requests", 0) or 0)),
                    str(int(item.get("bytes", 0) or 0)),
                    f"{float(item.get('size_stability', 0.0) or 0.0):.2f}",
                    f"{float(item.get('linked_beacon_score', 0.0) or 0.0):.2f}",
                    str(int(item.get("risk_score", 0) or 0)),
                    str(item.get("packet_examples", "-")),
                ]
            )
        lines.append(_format_table(rows))
        lines.append(muted("HTTP POST Beacon Evidence Details:"))
        for item in http_post_beacons[: _limit_value(10 if verbose else 6)]:
            reason_values = item.get("risk_reasons", [])
            reason_text = (
                ", ".join(str(v) for v in reason_values[:3])
                if isinstance(reason_values, list) and reason_values
                else "-"
            )
            lines.append(
                muted(
                    f"- {item.get('src')}->{item.get('dst')} host={item.get('host')} risk={int(item.get('risk_score', 0) or 0)} "
                    f"why={_redact_in_text(reason_text)}"
                )
            )
            sample_text = str(item.get("sample", "") or "").strip()
            if sample_text and sample_text != "-":
                lines.append(muted(f"  sample={_redact_in_text(sample_text[:120])}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
