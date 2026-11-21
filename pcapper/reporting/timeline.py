"""Rendered output for --timeline (-ip TARGET): one host's activity in time
order. The default view leads with what matters -- the notable events
(malicious- or suspicious-looking, VirusTotal hits, OT control actions) --
then the activity itself with consecutive repeats collapsed (×N), the
attack-stage sequence, beaconing / authentication abuse / lateral movement /
exfiltration / OT impact signals and downloaded files. Every
individual event, the event links and the counters are -v detail."""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from typing import TYPE_CHECKING, Optional

from ..timeline import TimelineSummary
from ..utils import format_duration, format_ts, sparkline
from . import _style as st
from ._common import _redact_in_text, _render_deterministic_checks

if TYPE_CHECKING:
    from ..timeline import TimelineEvent

def _severity_for_event(item: "TimelineEvent") -> str:
    text = f"{item.summary} {item.details}".lower()
    # Inbound remote-access TO the target (SSH/RDP/etc.) is high-risk -- the
    # entry point for an IT->OT pivot. External source escalates to critical
    # (red); internal source is high (suspicious highlight).
    if item.category == "Remote IN":
        return "malicious" if "critical" in text else "suspicious"
    if "handshake incomplete" in text or "final ack missing" in text:
        return "suspicious"
    if "potential port scan" in text:
        return "suspicious"
    if "http post" in text:
        return "suspicious"
    if "file artifact" in text:
        if any(
            token in text
            for token in [
                "(exe/dll)",
                "(archive)",
                ".exe",
                ".dll",
                ".ps1",
                ".vbs",
                ".bat",
                ".scr",
                ".js",
            ]
        ):
            return "malicious"
        return "suspicious"
    if "tcp connect attempt" in text:
        for port in (445, 3389, 22, 23, 135, 139, 5985, 5986):
            if f":{port}" in text:
                return "suspicious"
    if any(
        token in text
        for token in (
            "write",
            "control",
            "start",
            "stop",
            "setpoint",
            "program",
            "firmware",
            "writevar",
            "vartabwrite",
            "plcstop",
            "plchotstart",
            "plccoldstart",
            "requestdownload",
            "downloadblock",
            "startupload",
            "uploadblock",
            "cpupassword",
            "setclock",
        )
    ):
        if item.category in {
            "Modbus",
            "DNP3",
            "IEC-104",
            "S7",
            "CIP",
            "ENIP",
            "BACnet",
            "OPC UA",
            "PROFINET",
        }:
            return "suspicious"
    return "info"


def _dns_base_domain(name: str) -> str:
    parts = [part for part in str(name).strip(".").split(".") if part]
    if len(parts) >= 2:
        return ".".join(parts[-2:]).lower()
    return str(name).strip(".").lower()


def _extract_domains(text: str) -> list[str]:
    if not text:
        return []
    hits = re.findall(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b",
        text,
    )
    ordered: list[str] = []
    seen: set[str] = set()
    for value in hits:
        lowered = value.strip(".").lower()
        if not lowered or lowered in seen:
            continue
        seen.add(lowered)
        ordered.append(lowered)
    return ordered


def _event_tags(item: "TimelineEvent") -> list[str]:
    text = f"{item.category} {item.summary} {item.details}".lower()
    tags: list[str] = []
    if any(
        token in text
        for token in (
            "scan",
            "recon",
            "probe",
            "enumeration",
            "icmp",
            "arp",
            "nbns",
            "mdns",
        )
    ):
        tags.append("Recon")
    if any(
        token in text
        for token in ("dns", "hostname", "domain", "netbios", "whoami", "ipconfig")
    ):
        tags.append("Discovery")
    if any(
        token in text
        for token in (
            "auth",
            "login",
            "credential",
            "ntlm",
            "kerberos",
            "password",
            "cpupassword",
        )
    ):
        tags.append("Credential")
    if any(
        token in text
        for token in (
            "smb",
            "rdp",
            "winrm",
            "wmic",
            "ssh",
            "rpc",
            "lateral",
        )
    ):
        tags.append("Lateral")
    if any(
        token in text
        for token in (
            "powershell",
            "cmd.exe",
            "rundll32",
            "regsvr32",
            "mshta",
            "bitsadmin",
            "wmic",
            "schtasks",
            "msiexec",
        )
    ):
        tags.append("Execution")
        tags.append("LOLBAS")
    if any(token in text for token in ("beacon", "c2", "command and control")):
        tags.append("C2")
    if any(
        token in text
        for token in ("exfil", "tunnel", "dns txt", "http post", "upload")
    ):
        tags.append("Exfil")
    if any(
        token in text
        for token in (
            "write",
            "writevar",
            "vartabwrite",
            "setpoint",
            "operate",
            "trip",
            "shutdown",
            "stop",
            "start",
            "plcstop",
            "plchotstart",
            "plccoldstart",
            "requestdownload",
            "downloadblock",
            "startupload",
            "uploadblock",
            "setclock",
        )
    ) and item.category in {
        "Modbus",
        "DNP3",
        "IEC-104",
        "S7",
        "CIP",
        "ENIP",
        "BACnet",
        "OPC UA",
        "PROFINET",
        "Triconex/SIS",
    }:
        tags.append("OT Control")
    if any(token in text for token in ("dos", "flood", "impact", "disruption")):
        tags.append("Impact")
    if any(
        token in text
        for token in (".exe", ".dll", ".ps1", ".vbs", ".bat", ".scr", ".js")
    ):
        tags.append("Payload")
    if not tags:
        return []
    # Deduplicate while preserving order
    seen: set[str] = set()
    ordered: list[str] = []
    for tag in tags:
        if tag in seen:
            continue
        seen.add(tag)
        ordered.append(tag)
    return ordered[:3]


def _is_high_value_ot_action(item: "TimelineEvent") -> bool:
    if item.category not in {
        "Modbus",
        "DNP3",
        "IEC-104",
        "S7",
        "CIP",
        "ENIP",
        "BACnet",
        "OPC UA",
        "PROFINET",
        "Triconex/SIS",
    }:
        return False
    text = f"{item.summary} {item.details}".lower()
    if any(
        token in text
        for token in (
            "write",
            "writevar",
            "vartabwrite",
            "setpoint",
            "operate",
            "trip",
            "shutdown",
            "plcstop",
            "plchotstart",
            "plccoldstart",
            "requestdownload",
            "downloadblock",
            "startupload",
            "uploadblock",
            "cpupassword",
            "setclock",
            "security",
            "error response",
            "failed",
            "disconnect request",
        )
    ):
        return True
    if "anomaly" in text:
        return True
    return False


class _VirusTotal:
    """VirusTotal results by domain (and registered domain)."""

    def __init__(self, results: object) -> None:
        self.results = dict(results or {})

    def info(self, name: str) -> Optional[dict]:
        key = str(name or "").strip(".").lower()
        if not key or not self.results:
            return None
        info = self.results.get(key) or self.results.get(_dns_base_domain(key))
        return info if isinstance(info, dict) else None

    def match(self, text: str) -> Optional[tuple[str, int, int, int, str]]:
        """The worst VirusTotal verdict among the domains in ``text``."""
        best = None
        for domain in _extract_domains(text):
            info = self.info(domain)
            if not info:
                continue
            candidate = (domain, int(info.get("score", 0) or 0), int(info.get("malicious", 0) or 0),
                         int(info.get("suspicious", 0) or 0), str(info.get("rating", "-") or "-"))
            if best is None or (candidate[2], candidate[3], candidate[1]) > (best[2], best[3], best[1]):
                best = candidate
        return best


def _ips_in_text(text: str) -> list[str]:
    found: list[str] = []
    for token in re.split(r"[\s,;()\[\]{}<>]", text):
        value = token.strip(".,;:|")
        if ":" in value and value.count(":") == 1:
            host, port = value.rsplit(":", 1)
            if port.isdigit():
                value = host
        try:
            ipaddress.ip_address(value.strip("[]"))
        except ValueError:
            continue
        found.append(value.strip("[]"))
    return found


def _paint(text: str, severity: str) -> str:
    return st.bad(text) if severity == "malicious" else st.caution(text) if severity == "suspicious" else text


def render_timeline_summary(summary: TimelineSummary, limit: int = 200, verbose: bool = False) -> str:
    del limit  # every event is kept; the default view collapses repeats instead
    rep = st.Report("Timeline", summary.path)
    vt = _VirusTotal(summary.vt_results)
    rows: list[dict] = []
    last_by_actor: dict[str, tuple[float, str, str]] = {}
    lookups = 0  # routine DNS / mDNS lookups: --dnsqueries lists them
    for event in summary.events:
        severity = _severity_for_event(event)
        text = event.summary
        hit = vt.match(f"{event.summary} {event.details}")
        if hit is not None:
            domain, score, malicious, suspicious, rating = hit
            text = f"[VT {domain}: {malicious} malicious, {suspicious} suspicious, {rating}] {text}"
            if malicious:
                severity = "malicious"
            elif suspicious or score:
                severity = "suspicious"
        if event.category in ("DNS", "mDNS") and severity not in ("malicious", "suspicious"):
            lookups += 1  # a lookup VirusTotal flags stays: resolving a bad domain is an event
            continue
        detail = _redact_in_text(event.details or "")
        link = ""
        if event.ts is not None:
            ips = _ips_in_text(event.details or "")
            actor = next((ip for ip in ips if ip != summary.target_ip), None) if summary.target_ip in ips and len(ips) > 1 \
                else (ips[0] if ips else None)
            if actor:
                prev = last_by_actor.get(actor)
                if prev and 0 <= float(event.ts) - prev[0] <= 600:
                    link = f"linked to {prev[1]}: {st.cut(prev[2], 48)} (+{float(event.ts) - prev[0]:.0f}s)"
                last_by_actor[actor] = (float(event.ts), event.category, event.summary)
        rows.append({"ts": event.ts, "category": event.category, "text": text, "severity": severity, "tags": _event_tags(event),
                     "detail": detail, "link": link, "packet": event.packet_index,
                     "source": event.source if event.source and event.source != "timeline" else "",
                     "notable": severity in ("malicious", "suspicious") or _is_high_value_ot_action(event)})
    malicious = sum(1 for r in rows if r["severity"] == "malicious")
    suspicious = sum(1 for r in rows if r["severity"] == "suspicious")
    notable = [r for r in rows if r["notable"]]

    target = summary.target_ip or "all hosts"
    if malicious or suspicious:
        rep.headline("high" if malicious else "medium", st.join([
            f"{st.plural(len(rows), 'event')} for {target}",
            f"{malicious} malicious-looking" if malicious else "", f"{suspicious} suspicious" if suspicious else ""]))
    else:
        rep.headline(False, f"{st.plural(len(rows), 'event')} for {target}")
    rep.scope(st.join([st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else "",
                       st.duration(summary.duration) if summary.duration else "",
                       f"{st.count(summary.total_packets)} packets" if summary.total_packets else "",
                       st.plural(len(summary.peer_counts or {}), "peer") if summary.peer_counts else ""]))
    if summary.ot_risk_score:
        posture = "HIGH" if summary.ot_risk_score >= 60 else "MEDIUM" if summary.ot_risk_score >= 25 else "LOW"
        rep.scope(f"OT risk {summary.ot_risk_score}/100 ({posture})")
    queried = len(summary.dns_queries or []) or lookups
    if queried:
        rep.note("DNS", f"{st.plural(queried, 'lookup')} not listed here: --dnsqueries"
                        + (f" -ip {summary.target_ip}" if summary.target_ip else "") + " lists them")
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])

    rep.section("OT risk", [] if not (summary.ot_risk_score or summary.ot_protocol_counts) else st.bullets([_redact_in_text(str(f)) for f in (summary.ot_risk_findings or [])], max_items=None)
                + ([f"  {st.dim('storyline:')}"] + st.bullets([_redact_in_text(str(s)) for s in summary.ot_storyline], max_items=None, indent=4)
                   if summary.ot_storyline else []))

    def _event_cell(r: dict, width: Optional[int]) -> str:
        tags = st.dim("[" + "] [".join(r["tags"]) + "] ") if r["tags"] else ""
        return tags + _paint(st.cut(r["text"], width), r["severity"])

    seen_notable: dict[tuple[str, str], list[dict]] = {}
    for r in notable:
        seen_notable.setdefault((r["category"], r["text"]), []).append(r)
    rep.section("Notable events", st.table(
        ["First", "Category", "Event", "Times", "Details", "Packet"],
        [[st.ts(group[0]["ts"]), group[0]["category"], _event_cell(group[0], 60), len(group), st.cut(group[0]["detail"], 70),
          group[0]["packet"] if group[0]["packet"] is not None else "-"] for group in seen_notable.values()],
        align="lllrlr", max_rows=15, noun="event",
    ))

    activity_note: list[str] = []
    if st.verbose():
        activity = [[format_ts(r["ts"]), r["category"], _event_cell(r, None),
                     st.join([r["detail"], r["link"], f"[{r['source']}]" if r["source"] else ""], "  "),
                     r["packet"] if r["packet"] is not None else "-"] for r in rows]
        header = ["Time", "Category", "Event", "Details", "Packet"]
    else:
        # Default view: identical events (same category, event and details)
        # fold into one row at their first sighting -- polling and retries
        # collapse to ×N while every distinct event keeps its place in time.
        patterns: dict[tuple[str, str, str, str], list[dict]] = {}
        for r in rows:
            patterns.setdefault((r["category"], r["text"], r["severity"], r["detail"]), []).append(r)
        activity = [[st.ts(g[0]["ts"]), g[0]["category"],
                     _event_cell(g[0], 56) + (st.dim(f" ×{len(g)}") if len(g) > 1 else ""),
                     st.cut(g[0]["detail"], 64) + (st.dim(f" … last {st.ts(g[-1]['ts'])}") if len(g) > 1 else ""),
                     g[0]["packet"] if g[0]["packet"] is not None else "-"] for g in patterns.values()]
        header = ["First", "Category", "Event", "Details", "Packet"]
        if len(patterns) < len(rows):
            activity_note = [st.dim(f"  {len(rows)} events as {len(patterns)} distinct (repeats folded ×N; -v lists every event in order)")]
    rep.section("Activity", activity_note + st.table(header, activity, align="llllr", max_rows=60, noun="event"))

    rep.section("Stages", st.table(
        ["Stage", "First", "Last", "Events", "Dwell", "Evidence"],
        [[i.get("stage", "-"), st.ts(i.get("first_ts")), st.ts(i.get("last_ts")), i.get("count", "-"), format_duration(i.get("dwell")),
          _redact_in_text(" | ".join(str(v) for v in i.get("evidence", []) or []) if isinstance(i.get("evidence"), list) else str(i.get("evidence", "")))]
         for i in (summary.sequence_timeline or [])],
        align="lllrll", widths=(None, None, None, None, None, 70), max_rows=10, noun="stage",
    ))
    rep.section("Beaconing", st.table(
        ["Peer", "Category", "Signal", "Events", "Mean interval", "Jitter", "CV", "Confidence"],
        [[i.get("peer", "-"), i.get("category", "-"), i.get("summary", "-"), i.get("count", "-"), f"{i.get('mean_interval', '-')}s",
          f"{i.get('jitter', '-')}s", i.get("cv", "-"), str(i.get("confidence", "-")).upper()] for i in (summary.beacon_candidates or [])],
        align="lllrrrrl", widths=(None, None, 40), max_rows=5, noun="candidate",
    ))
    rep.section("Authentication abuse", st.table(
        ["Source", "Target", "Attempts", "Targets", "Confidence"],
        [[i.get("src", "-"), i.get("dst", "-"), i.get("attempts", "-"), i.get("target_count", "-"), str(i.get("confidence", "-")).upper()]
         for i in (summary.auth_abuse_profiles or [])], align="llrrl", max_rows=5, noun="profile",
    ))
    rep.section("Lateral movement", st.table(
        ["Source", "Peers", "Admin hits", "Top peers", "Confidence"],
        [[i.get("src", "-"), i.get("peer_count", "-"), i.get("admin_hits", "-"),
          st.listing(i.get("peers") or [], 4) if isinstance(i.get("peers"), list) else str(i.get("peers", "-")),
          str(i.get("confidence", "-")).upper()] for i in (summary.lateral_movement_paths or [])],
        align="lrrll", max_rows=5, noun="path",
    ))
    rep.section("Exfiltration signals", st.bullets([_redact_in_text(str(i.get("signal", "-"))) for i in (summary.exfiltration_chains or [])],
                                                   max_items=5, noun="signal"))
    rep.section("OT impact", st.table(
        ["Time", "Protocol", "Summary", "Details"],
        [[st.ts(i.get("ts")), i.get("protocol", "-"), i.get("summary", "-"), _redact_in_text(str(i.get("details", "-")))]
         for i in (summary.ot_impact_signals or [])], widths=(None, None, 40, 80), max_rows=5, noun="signal",
    ))

    downloads = [f for f in (summary.file_downloads or []) if str(getattr(f, "dst_ip", "") or "") == str(summary.target_ip)]
    rep.section("Files downloaded", st.table(
        ["Time", "File", "Type", "Size", "From", "Host", "SHA-256 / MD5", "Packet"],
        [[st.ts(f.ts), st.bad(f.filename) if re.search(r"\.(?:exe|dll|scr|ps1|vbs|bat|js|msi|jar|elf)$", str(f.filename or ""), re.I)
          else f.filename, f.file_type or "-", st.size(f.size_bytes) if f.size_bytes is not None else "-", f"{f.src_ip} ({f.protocol})",
          f.hostname or "-", f.sha256 or f.md5 or "-", f.packet_number if f.packet_number is not None else "-"] for f in downloads],
        max_rows=10, noun="file",
    ))
    if summary.vt_lookup_enabled or summary.vt_results or summary.vt_errors:
        vt_items = sorted((summary.vt_results or {}).items(), key=lambda kv: (int(kv[1].get("malicious", 0) or 0),
                                                                              int(kv[1].get("suspicious", 0) or 0),
                                                                              int(kv[1].get("score", 0) or 0)), reverse=True)
        flagged = [kv for kv in vt_items if int(kv[1].get("malicious", 0) or 0) or int(kv[1].get("suspicious", 0) or 0)]
        rep.section("VirusTotal", st.kv([("Lookups", f"{'enabled' if summary.vt_lookup_enabled else 'disabled'} · "
                                                     f"{st.plural(len(vt_items), 'domain')} enriched · {len(flagged)} flagged")])
                    + st.table(["Domain", "Score", "Rating", "Suspicious", "Malicious", "Reputation"],
                               [[d, i.get("score", "-"), i.get("rating", "-"), i.get("suspicious", "-"), i.get("malicious", "-"), i.get("reputation", "-")]
                                for d, i in (vt_items if st.verbose() else flagged)], align="lrlrrr", max_rows=10)
                    + [f"  {st.caution('!')} {e}" for e in (summary.vt_errors or [])])

    if summary.analyst_verdict:
        rep.section("Assessment", st.kv([("Verdict", summary.analyst_verdict),
                                         ("Confidence", (summary.analyst_confidence or "low").strip().lower())])
                    + st.bullets([_redact_in_text(str(r)) for r in (summary.analyst_reasons or [])], max_items=None), detail=True)
    rep.section("Sequence violations", st.bullets([_redact_in_text(str(v)) for v in (summary.sequence_violations or [])], max_items=None),
                detail=True)
    rep.section("Evidence anchors", st.bullets(["  ".join(f"{k}={v}" for k, v in a.items()) if isinstance(a, dict) else str(a)
                                                for a in (getattr(summary, "evidence_anchors", None) or [])], max_items=None), detail=True)
    tag_counts = Counter(t for r in rows for t in r["tags"])
    rep.section("Counters", st.kv([
        ("Window", f"{format_ts(summary.first_seen)} / {format_ts(summary.last_seen)}" if summary.first_seen is not None else ""),
        ("Duration", f"{summary.duration:.1f}s" if summary.duration is not None else ""),
        ("Categories", st.top(Counter(summary.category_counts or {}), None)),
        ("Kill-chain tags", st.top(tag_counts, None)),
        ("Peers", st.top(Counter(summary.peer_counts or {}), None)),
        ("Ports", st.top(Counter({str(k): v for k, v in (summary.port_counts or {}).items()}), None)),
        ("OT protocols", st.top(Counter(summary.ot_protocol_counts or {}), None)),
    ]), detail=True)
    rep.section("OT activity", [f"  {name:<18} {sparkline(bins)}  {sum(bins)}" for name, bins in
                                sorted((summary.ot_activity_bins or {}).items(), key=lambda kv: (-sum(kv[1]), kv[0]))], detail=True)
    rep.section("False-positive context", st.bullets([_redact_in_text(str(b)) for b in (summary.benign_context or [])], max_items=None),
                detail=True)
    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic Timeline Security Checks", [
            ("access_to_execution_sequence", "Access to Execution Sequence"), ("remote_execution_tooling", "Remote Execution Tooling"),
            ("cleartext_remote_admin", "Cleartext Remote Admin"), ("ot_impact_signal", "OT Impact Signal"),
            ("evidence_provenance", "Evidence Provenance"),
        ])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
