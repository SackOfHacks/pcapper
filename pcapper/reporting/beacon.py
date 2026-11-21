"""Rendered output for beacon analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations

import ipaddress
from collections import Counter

from ..beacon import (
    MGMT_PORTS as _BCN_MGMT_PORTS,
)
from ..beacon import (
    OT_PORTS as _BCN_OT_PORTS,
)
from ..beacon import (
    TUNNEL_PORTS as _BCN_TUNNEL_PORTS,
)
from ..beacon import (
    BeaconSummary,
)
from ..services import COMMON_PORTS
from ..utils import (
    format_duration,
    sparkline,
)
from . import _style as st
from ._common import (
    _redact_in_text,
)
from ._kv import findings_for


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


_SEV_MAP = {"critical": "critical", "high": "high", "warning": "medium", "info": "info"}


def _assessment(summary: BeaconSummary, classified: list, c2: list) -> tuple[str, str, int, list[str]]:
    score = 0
    reasons: list[str] = []
    http_posts = list(getattr(summary, "http_post_beacons", []) or [])
    det_cat = getattr(summary, "deterministic_category_checks", {}) or {}
    det_checks = getattr(summary, "deterministic_checks", {}) or {}
    # Internal OT-cyclic / benign-service periodicity is the expected shape of
    # automation; campaign escalators must not inflate it.
    baseline_only = bool(classified) and not c2
    critical = [p for p in c2 if p[1].get("severity") == "critical"]
    high = [p for p in c2 if p[1].get("severity") == "high"]
    if critical:
        score += 5
        reasons.append(f"{len(critical)} critical external/OT beacon(s) (e.g. {critical[0][0].src_ip}->{critical[0][0].dst_ip} "
                       f"score={critical[0][1]['score']:.2f})")
    if high:
        score += min(3, len(high) + 1)
        reasons.append(f"{len(high)} high-severity external beacon(s) (e.g. {high[0][0].src_ip}->{high[0][0].dst_ip} "
                       f"score={high[0][1]['score']:.2f})")
    failed = [p for p in c2 if "failed/refused" in str(p[1].get("label", "")).lower() and p[1].get("is_external")
              and int(getattr(p[0], "count", 0) or 0) >= 50 and float(getattr(p[0], "periodicity_score", 0.0) or 0.0) >= 0.7]
    if failed:
        score += 3
        reasons.append(f"persistent failed C2 beaconing to a public IP ({failed[0][0].src_ip}->{failed[0][0].dst_ip}, "
                       f"{failed[0][0].count} attempts)")
    if not baseline_only:
        for key, weight, text in (("multi_target_synchronized", 2, "synchronized multi-destination cadence (fan-out C2 shape)"),
                                  ("cross_protocol_cadence", 2, "cross-protocol cadence reuse on the same pair"),
                                  ("low_slow_persistence", 1, "low-and-slow persistent periodicity")):
            if det_cat.get(key):
                score += weight
                reasons.append(text)
    if http_posts:
        max_risk = max((int(i.get("risk_score", 0) or 0) for i in http_posts), default=0)
        score += 2 if max_risk >= 3 else 1
        reasons.append(f"HTTP POST check-in channels ({len(http_posts)}; max risk {max_risk})")
    if det_checks.get("dns_beaconing_or_tunnel_pattern"):
        score += 1
        reasons.append("DNS failover/tunnel semantics (elevated NXDOMAIN)")
    mgmt = [p for p in c2 if "mgmt" in str(p[1].get("label", "")).lower()]
    if mgmt and not critical and not high:
        score += 1
        reasons.append(f"{len(mgmt)} internal beacon(s) on admin/mgmt ports")
    if baseline_only:
        reasons.append("only internal OT-cyclic / benign-service periodicity (baseline, not C2)")
    if score >= 7:
        return "YES - high-confidence C2-style beaconing", "High", score, reasons
    if score >= 4:
        return "LIKELY - external beaconing with corroboration", "Medium", score, reasons
    if score >= 2:
        return "POSSIBLE - weak-to-moderate beaconing indicators", "Low", score, reasons
    if baseline_only:
        return "BASELINE - periodic traffic looks like automation, not C2", "Low", score, reasons
    return "NO STRONG SIGNAL after filtering", "Low", score, reasons


def render_beacon_summary(summary: BeaconSummary, limit: int = 12, verbose: bool = False) -> str:
    """Beaconing (RITA-style periodicity scoring): the C2-relevant candidates
    ranked by severity, with cadence, jitter, timeline and the next command
    to run; OT-cyclic and service periodicity is summarized as baseline.
    The full score table, timelines and the assessment are -v."""
    rep = st.Report("Beacons", summary.path)
    findings = findings_for(summary, ot=False)
    candidates = list(getattr(summary, "candidates", []) or [])
    classified = [(c, _beacon_classify(c)) for c in candidates]
    c2 = sorted((p for p in classified if p[1].get("c2_relevant")),
                key=lambda p: (_BEACON_SEV_RANK.get(str(p[1].get("severity")), 0), float(p[1].get("score", 0.0) or 0.0),
                               int(p[1].get("count", 0) or 0)), reverse=True)
    if not candidates and not st.material(findings):
        return rep.absent("beaconing candidates", summary.errors)
    # The headline weighs the analyzer's detections and its candidate triage
    # together; the candidates themselves are listed once, in "Beacons".
    triage = [st.finding({"severity": _SEV_MAP.get(str(i.get("severity")), "info"), "title": str(i["label"])}) for _c, i in c2]
    severity, text = st.verdict(findings + triage, high="C2-style beaconing: investigate", medium="periodic traffic to review",
                                clean="periodic traffic looks like automation (baseline)")
    if findings:
        text = text.replace(st.plural(len(findings) + len(triage), "finding"), st.plural(len(findings), "finding"))
    rep.headline(severity, text, st.join([
        st.plural(summary.candidate_count, "candidate"), st.bad(f"{len(c2)} C2-relevant") if c2 else "0 C2-relevant",
        f"{len(classified) - len(c2)} baseline", f"{st.count(summary.total_packets)} packets",
    ]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    def _port(c: object) -> str:
        port = c.src_port or c.dst_port
        return f"{c.proto}/{port}" if port else str(c.proto)

    rep.section("Beacons", st.table(
        ["Severity", "Flow", "Proto", "What", "Cadence", "Jitter", "Events", "Score", "Timeline"],
        [[st.badge(_SEV_MAP.get(str(i.get("severity")), "info")), st.flow(c.src_ip, c.dst_ip), _port(c), i["label"],
          f"{c.mean_interval:.0f}s" if c.mean_interval else "-", f"{c.jitter:.2f}", st.count(c.count), f"{c.score:.2f}",
          sparkline(c.timeline)] for c, i in c2],
        align="llllrrrrl", widths=(None, None, None, 44), max_rows=8, noun="beacon",
    ) + [f"  {st.dim('next:')} pcapper <capture> {action}" for action in list(dict.fromkeys(i["action"] for _c, i in c2))[:3]])
    posts = list(getattr(summary, "http_post_beacons", []) or [])
    rep.section("HTTP POST check-ins", st.table(
        ["Source", "Destination", "Host", "URIs", "Requests", "Bytes", "Stability", "Linked", "Risk", "Why"],
        [[i.get("src", "-"), i.get("dst", "-"), i.get("host", "-"), i.get("uri", "-"), int(i.get("requests", 0) or 0),
          st.size(int(i.get("bytes", 0) or 0)), f"{float(i.get('size_stability', 0.0) or 0.0):.2f}",
          f"{float(i.get('linked_beacon_score', 0.0) or 0.0):.2f}", int(i.get("risk_score", 0) or 0),
          _redact_in_text(", ".join(str(r) for r in (i.get("risk_reasons") or [])))] for i in posts],
        align="llllrrrrrl", widths=(None, None, 30, 40), max_rows=8, noun="channel",
    ))
    baseline = Counter(str(i.get("label")) for _c, i in classified if not i.get("c2_relevant"))
    rep.section("Baseline", st.kv([("Not C2", st.top(baseline, 5, fmt=lambda k, v: f"{k} ({v} flows)"))])
                + ([st.dim("  OT/control periodicity and steady service traffic are the baseline: confirm against a process "
                           "baseline before escalating.")] if baseline else []))
    campaigns = list(getattr(summary, "campaign_summaries", None) or [])
    rep.section("Campaigns", st.table(
        ["Campaign", "Host", "Cadence", "Flows", "Destinations", "Channels", "Max score"],
        [[i.get("campaign_id", "-"), i.get("host", "-"), i.get("cadence_family", "-"), i.get("flows", "-"), i.get("destinations", "-"),
          i.get("channels", "-"), i.get("max_score", "-")] for i in campaigns], max_rows=8, noun="campaign",
    ))
    rollups = list(getattr(summary, "host_rollups", None) or [])
    rep.section("Hosts", st.table(
        ["Host", "Candidates", "Channels", "Destinations", "Top cadence", "Max score"],
        [[i.get("host", "-"), i.get("candidate_count", "-"), ",".join(str(v) for v in i.get("channels", []) or []) or "-",
          i.get("destinations", "-"), f"{float(i.get('top_cadence_s', 0.0) or 0.0):.2f}s", i.get("max_score", "-")] for i in rollups],
        max_rows=8, noun="host",
    ))

    verdict, confidence, score, reasons = _assessment(summary, classified, c2)
    rep.section("Assessment", st.kv([("Verdict", verdict), ("Confidence", f"{confidence} (score={score})")])
                + st.bullets([_redact_in_text(r) for r in reasons], max_items=None), detail=True)

    def _proto_label(c: object) -> str:
        if c.src_port and c.dst_port:
            return f"{c.proto}:{c.src_port}->{c.dst_port}"
        return f"{c.proto}:{c.src_port}" if c.src_port else str(c.proto)

    def _score(value: float) -> str:
        text = f"{value:.2f}"
        return st.bad(text) if value >= 0.85 else st.caution(text) if value >= 0.65 else text

    rep.section("Candidates", st.table(
        ["Source", "Destination", "Proto", "Count", "Duration", "Mean", "MAD", "Avg bytes", "Size MAD", "Periodicity", "Size",
         "Duration score", "Count score", "Score", "First", "Last"],
        [[c.src_ip, c.dst_ip, _proto_label(c), c.count, format_duration(c.duration_seconds) if c.duration_seconds else "-",
          f"{c.mean_interval:.2f}s", f"{c.mad_interval:.2f}s", f"{c.avg_bytes:.0f}", f"{c.mad_bytes:.0f}", f"{c.periodicity_score:.2f}",
          f"{c.size_score:.2f}", f"{c.duration_score:.2f}", f"{c.count_score:.2f}", _score(c.score), st.ts(c.first_seen), st.ts(c.last_seen)]
         for c in candidates],
        align="lllrlrrrrrrrrrll", max_rows=None,
    ) + [st.dim("  Periodicity = 1 - MAD/median interval · Size = 1 - MAD/median bytes · Duration = span/1h · Count = events/50 · "
                "total is weighted")], detail=True)
    rep.section("Timelines", [f"  {st.flow(c.src_ip, c.dst_ip)}  {sparkline(c.timeline)}  " + st.dim(
        f"median {c.median_interval:.2f}s · events {c.count} · established {float(getattr(c, 'established_ratio', 0.0) or 0.0):.0%} "
        f"· data {st.size(int(getattr(c, 'data_bytes', 0) or 0))}") for c in candidates], detail=True)
    rep.section("Explainability", st.bullets([_redact_in_text(str(i)) for i in (getattr(summary, "explainability", None) or [])],
                                             max_items=None), detail=True)
    hyp = [f"[{h.get('confidence', '?')}] {h.get('hypothesis', '-')}" for h in (getattr(summary, "threat_hypotheses", None) or [])
           if isinstance(h, dict)]
    rep.section("Threat hypotheses", st.bullets(hyp, max_items=None), detail=True)
    rep.section("Benign context", st.bullets([str(b) for b in (getattr(summary, "benign_context", None) or [])], max_items=None),
                detail=True)
    if st.analysis_sections():
        proto_checks = getattr(summary, "protocol_beacon_checks", {}) or {}
        cat_checks = getattr(summary, "deterministic_category_checks", {}) or {}
        lines: list[str] = []
        for key, label_text in (("dns", "DNS"), ("http_https", "HTTP/HTTPS"), ("icmp", "ICMP"), ("ntp", "NTP"),
                                ("single_target_periodic_c2", "Single-Target Periodic C2"),
                                ("multi_target_synchronized", "Multi-Target Synchronized Beaconing"),
                                ("cross_protocol_cadence", "Cross-Protocol Cadence Reuse"), ("burst_sleep_pattern", "Burst-Sleep"),
                                ("low_slow_persistence", "Low-and-Slow Persistence"), ("benign_periodic_likely", "Likely Benign Periodic")):
            evidence = [str(v) for v in ((proto_checks.get(key) if key in proto_checks else cat_checks.get(key)) or []) if str(v).strip()]
            if evidence:
                lines.append(f"  {st.strong(label_text)}")
                lines += st.bullets([_redact_in_text(e) for e in evidence], max_items=None, indent=4)
        rep.section("Deterministic checks", lines)
    return rep.render()
