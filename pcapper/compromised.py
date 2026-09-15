from __future__ import annotations

from .utils import is_valid_ip as _valid_ip
from .utils import is_public_ip as _is_public_ip
from .utils import is_private_ip as _is_private_ip
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from .beacon import analyze_beacons
from .creds import analyze_creds
from .exfil import analyze_exfil
from .hosts import analyze_hosts
from .pcap_cache import PcapMeta
from .progress import run_with_busy_status
from .secrets import analyze_secrets
from .threats import OT_PORTS, analyze_threats
from .utils import format_bytes_as_mb, memoize_analysis

# The last label must be alphabetic: a real TLD is letters. Without that, the
# numbers in a detection's own prose ("score 0.98", "interval 90.00s",
# "duration 58.50m") were captured as domain IOCs, listed under the host, and
# — being identical for every host with a similar cadence — grouped unrelated
# hosts into phantom campaigns.
IOC_DOMAIN_RE = re.compile(
    r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]{2,})*\.[a-z]{2,63})\b",
    re.IGNORECASE,
)
_HOSTNAME_BLACKLIST = {
    "localdomain",
    "localdomain.local",
    "localhost",
    "localhost.localdomain",
    "local",
    "workgroup",
}
IOC_URL_RE = re.compile(r"https?://[^\s)\]]+", re.IGNORECASE)
IOC_MD5_RE = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)
IOC_SHA1_RE = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
IOC_SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
# The name part must not contain spaces, otherwise the (greedy) match swallows
# the preceding words of a free-text detail string (e.g. "beacon to 1.2.3.4
# host evil.com file update.exe" was captured whole as one "filename").
IOC_FILENAME_RE = re.compile(
    r"\b[\w\-.()\[\]]{1,64}\.(?:exe|dll|sys|scr|cpl|ocx|bat|ps1|vbs|js|jar|zip|rar|7z|gz|iso|img|pdf|doc|docx|xls|xlsx|ppt|pptx)\b",
    re.IGNORECASE,
)

_IPV4_TOKEN_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_TOKEN_RE = re.compile(r"\b[0-9a-fA-F:]{3,}\b")
_FLOW_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\s*->\s*(\d{1,3}(?:\.\d{1,3}){3})\b")
_HASH_RE = re.compile(r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}")

# Info-level evidence is context, not a compromise indicator, so it carries no
# weight toward the listing threshold: with a weight of 1, an HMI polling five
# PLCs (five info-level "periodic OT control-channel" entries) or a client
# sending five API tokens crossed the score-5 threshold on info alone and was
# printed under "Most Likely Compromised Hosts".
SEVERITY_WEIGHT = {
    "critical": 8,
    "high": 5,
    "warning": 3,
    "info": 0,
}


@dataclass(frozen=True)
class CompromisedHost:
    hostname: str
    ip: str
    detection_time: Optional[float]
    explanation: str
    evidence: list[str]
    iocs: list[str]
    severity: str
    score: int
    roles: list[str] = field(default_factory=list)
    is_infra: bool = False


@dataclass(frozen=True)
class CompromiseSummary:
    path: Path
    total_hosts: int
    compromised_hosts: list[CompromisedHost] = field(default_factory=list)
    detections: list[dict[str, object]] = field(default_factory=list)
    incidents: list[dict[str, object]] = field(default_factory=list)
    campaigns: list[dict[str, object]] = field(default_factory=list)
    host_priority: list[dict[str, object]] = field(default_factory=list)
    deterministic_checks: dict[str, list[str]] = field(default_factory=dict)
    benign_context: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _pick_hostname(ip_value: str, candidates: list[str]) -> str:
    for name in candidates or []:
        normalized = name.strip().strip(".").lower()
        if not normalized or normalized in _HOSTNAME_BLACKLIST:
            continue
        if _is_public_ip(ip_value) and "." not in normalized:
            continue
        return name
    return "-"


def _normalize_severity(value: object) -> str:
    text = str(value or "info").lower().strip()
    if text in {"critical", "crit"}:
        return "critical"
    if text in {"high", "severe"}:
        return "high"
    if text in {"warning", "warn", "medium"}:
        return "warning"
    return "info"


def _extract_ips_from_text(text: str) -> set[str]:
    if not text:
        return set()
    hits = set()
    for token in _IPV4_TOKEN_RE.findall(text):
        if _valid_ip(token):
            hits.add(token)
    for token in _IPV6_TOKEN_RE.findall(text):
        if ":" in token and _valid_ip(token):
            hits.add(token)
    return hits


def _extract_iocs(text: str) -> set[str]:
    if not text:
        return set()
    iocs: set[str] = set()
    for match in IOC_URL_RE.findall(text):
        iocs.add(match.rstrip(".,;"))
    for match in IOC_MD5_RE.findall(text):
        iocs.add(match.lower())
    for match in IOC_SHA1_RE.findall(text):
        iocs.add(match.lower())
    for match in IOC_SHA256_RE.findall(text):
        iocs.add(match.lower())
    for match in IOC_DOMAIN_RE.findall(text):
        if _valid_ip(match):
            continue
        iocs.add(match.lower().strip("."))
    for match in IOC_FILENAME_RE.findall(text):
        iocs.add(match)
    return iocs


def _extract_detection_time(entry: dict[str, object]) -> Optional[float]:
    for key in ("ts", "timestamp", "time", "first_seen"):
        value = entry.get(key)
        if isinstance(value, (int, float)):
            return float(value)
    return None


def _extract_ips_from_detection(entry: dict[str, object]) -> set[str]:
    ips: set[str] = set()
    for key in ("src", "dst", "src_ip", "dst_ip", "client_ip", "server_ip", "ip"):
        value = entry.get(key)
        if value and _valid_ip(str(value)):
            ips.add(str(value))
    affected = entry.get("affected_asset")
    if isinstance(affected, str) and ":" in affected:
        candidate = affected.split(":", 1)[0]
        if _valid_ip(candidate):
            ips.add(candidate)
    for key in ("top_sources", "top_destinations"):
        items = entry.get(key)
        if isinstance(items, list):
            for item in items:
                if isinstance(item, (list, tuple)) and item:
                    if _valid_ip(str(item[0])):
                        ips.add(str(item[0]))
    for blob_key in ("details", "summary"):
        blob = entry.get(blob_key)
        if isinstance(blob, str):
            ips.update(_extract_ips_from_text(blob))
    return ips


def _extract_source_ips_from_detection(entry: dict[str, object]) -> set[str]:
    ips: set[str] = set()
    for key in ("src", "src_ip", "client_ip"):
        value = entry.get(key)
        if value and _valid_ip(str(value)):
            ips.add(str(value))

    top_sources = entry.get("top_sources")
    if isinstance(top_sources, list):
        for item in top_sources:
            if isinstance(item, (list, tuple)) and item:
                if _valid_ip(str(item[0])):
                    ips.add(str(item[0]))

    for blob_key in ("details", "summary"):
        blob = entry.get(blob_key)
        if not isinstance(blob, str):
            continue
        for src_value, _dst_value in _FLOW_RE.findall(blob):
            if _valid_ip(src_value):
                ips.add(src_value)

    evidence = entry.get("evidence")
    if isinstance(evidence, list):
        for item in evidence:
            if not isinstance(item, str):
                continue
            for src_value, _dst_value in _FLOW_RE.findall(item):
                if _valid_ip(src_value):
                    ips.add(src_value)

    return ips


def _extract_primary_source_ip(entry: dict[str, object]) -> str | None:
    for key in ("src", "src_ip", "client_ip"):
        value = entry.get(key)
        if value and _valid_ip(str(value)):
            return str(value)
    top_sources = entry.get("top_sources")
    if isinstance(top_sources, list):
        for item in top_sources:
            if isinstance(item, (list, tuple)) and item:
                candidate = str(item[0])
                if _valid_ip(candidate):
                    return candidate
    return None


def _ips_for_compromise_attribution(
    entry: dict[str, object],
    stage: str,
    summary_text: str,
) -> set[str]:
    lower_summary = summary_text.lower()
    primary_source_bias = (
        stage in {"recon", "credential", "lateral", "c2", "exfil", "secrets"}
        or "syn volume" in lower_summary
        or "covert-channel" in lower_summary
        or "exfiltration pattern" in lower_summary
        or "scan" in lower_summary
        or "sweep" in lower_summary
        or "probe" in lower_summary
        or "brute-force" in lower_summary
        or "outbound" in lower_summary
        or "transfer" in lower_summary
    )
    if primary_source_bias:
        source_ips = _extract_source_ips_from_detection(entry)
        if source_ips:
            return source_ips
        primary = _extract_primary_source_ip(entry)
        if primary:
            return {primary}
    return _extract_ips_from_detection(entry)


def _host_priority_key(item: dict[str, object]) -> tuple[int, int, str]:
    """Highest score first; the IP breaks the frequent ties so the order is total."""
    return (
        -int(item.get("score", 0) or 0),
        -int(item.get("stage_count", 0) or 0),
        str(item.get("ip", "")),
    )


def _incident_key(item: dict[str, object]) -> tuple[float, int, str]:
    """Latest incident first; the IP breaks ties between simultaneous clusters."""
    return (
        -float(item.get("first_ts", 0.0) or 0.0),
        -int(item.get("count", 0) or 0),
        str(item.get("ip", "")),
    )


def _score_weight(severity: str) -> int:
    return SEVERITY_WEIGHT.get(severity, 0)


_STAGE_TOKENS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("recon", ("scan", "recon", "sweep", "probe", "probing", "enumeration")),
    (
        "credential",
        ("credential", "creds", "password", "kerberos", "ntlm", "authentication", "login", "logon", "brute"),
    ),
    ("c2", ("beacon", "c2", "command and control", "check-in")),
    ("exfil", ("exfil", "tunnel", "http post", "file exfil", "outbound", "data transfer", "large outbound")),
    ("lateral", ("smb", "rdp", "winrm", "ssh", "lateral")),
    ("secrets", ("secret", "token", "api key")),
)
# Tokens match at a word start only: a bare substring test made "Unauthorized
# command message" a credential-stage event (via "auth") and an "ec2-…
# .amazonaws.com" peer a C2-stage one (via "c2"). Stages feed the multi-stage
# bonus and the "multi-stage compromise sequencing" verdict reason, so a
# mis-tokenised stage inflates the compromise verdict.
_STAGE_PATTERNS: tuple[tuple[str, "re.Pattern[str]"], ...] = tuple(
    (stage, re.compile(r"(?<![a-z0-9])(?:" + "|".join(re.escape(t) for t in tokens) + ")"))
    for stage, tokens in _STAGE_TOKENS
)


def _classify_stage(summary: str, details: str, source: str) -> str:
    blob = f"{summary} {details} {source}".lower()
    for stage, pattern in _STAGE_PATTERNS:
        if pattern.search(blob):
            return stage
    return "other"


def _criticality_boost(host_record: object) -> int:
    ports = set()
    for item in getattr(host_record, "open_ports", []) or []:
        try:
            ports.add(int(getattr(item, "port", 0) or 0))
        except Exception:
            continue
    boost = 0
    if ports & {88, 389, 445, 464, 636, 3268, 3269}:
        boost += 3
    if ports & {3389, 5985, 5986, 22}:
        boost += 1
    return boost


def _add_host_evidence(
    host_state: dict[str, dict[str, object]],
    ip_value: str,
    severity: str,
    summary: str,
    details: str,
    ts: Optional[float],
    evidence: list[str],
    iocs: set[str],
    source: str,
) -> None:
    if not _valid_ip(ip_value):
        return
    entry = host_state.setdefault(
        ip_value,
        {
            "score": 0,
            "severity_counts": Counter(),
            "summaries": [],
            "details": [],
            "evidence": [],
            "evidence_seen": set(),
            "iocs": set(),
            "sources": set(),
            "first_ts": None,
        },
    )

    entry["score"] = int(entry["score"]) + _score_weight(severity)
    entry["severity_counts"][severity] += 1
    if summary and summary not in entry["summaries"]:
        entry["summaries"].append(summary)
    if details and details not in entry["details"]:
        entry["details"].append(details)

    evidence_seen = entry["evidence_seen"]
    for item in evidence:
        text = str(item).strip()
        if not text or text in evidence_seen:
            continue
        evidence_seen.add(text)
        entry["evidence"].append(text)

    entry["iocs"].update(iocs)
    entry["sources"].add(source)

    if ts is not None:
        first_ts = entry["first_ts"]
        if first_ts is None or ts < first_ts:
            entry["first_ts"] = ts


@memoize_analysis
def analyze_compromised(
    path: Path,
    show_status: bool = True,
    vt_lookup: bool = False,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> CompromiseSummary:
    errors: list[str] = []
    view = {"packets": packets, "meta": meta}

    hosts_summary = analyze_hosts(path, show_status=show_status, **view)

    def _busy(desc: str, func, *args, **kwargs):
        return run_with_busy_status(
            path, show_status, f"Compromised: {desc}", func, *args, **kwargs
        )

    threat_summary = _busy(
        "Threats", analyze_threats, path, show_status=False, vt_lookup=vt_lookup
    )
    beacon_summary = _busy("Beacons", analyze_beacons, path, show_status=False, **view)
    exfil_summary = _busy("Exfil", analyze_exfil, path, show_status=False, **view)
    creds_summary = _busy("Creds", analyze_creds, path, show_status=False, **view)
    secrets_summary = _busy("Secrets", analyze_secrets, path, show_status=False, **view)

    errors.extend(getattr(hosts_summary, "errors", []) or [])
    errors.extend(getattr(threat_summary, "errors", []) or [])
    errors.extend(getattr(beacon_summary, "errors", []) or [])
    errors.extend(getattr(exfil_summary, "errors", []) or [])
    errors.extend(getattr(creds_summary, "errors", []) or [])
    errors.extend(getattr(secrets_summary, "errors", []) or [])

    hostnames_by_ip = {host.ip: host.hostnames for host in hosts_summary.hosts}
    host_first_seen = {host.ip: host.first_seen for host in hosts_summary.hosts}

    host_state: dict[str, dict[str, object]] = {}
    detections: list[dict[str, object]] = []
    host_stages: dict[str, set[str]] = defaultdict(set)
    lateral_edges: Counter[tuple[str, str]] = Counter()
    deterministic_checks: dict[str, list[str]] = {
        "credential_abuse": [],
        "beacon_c2": [],
        "exfiltration": [],
        "lateral_movement": [],
        "multi_stage_sequence": [],
        "high_confidence_ioc": [],
        "benign_automation_likely": [],
    }
    detection_by_host: dict[str, list[dict[str, object]]] = defaultdict(list)

    # 1) Threat detections (cross-module)
    for item in getattr(threat_summary, "detections", []) or []:
        if not isinstance(item, dict):
            continue
        severity = _normalize_severity(item.get("severity"))
        # The threat engine has already classified internal-only periodicity
        # on OT ports / to broadcast as baseline (HMI polling, discovery
        # chatter) and says so in the detail text. It is context here, not
        # evidence that the poller is compromised.
        if str(item.get("internal_periodicity", "") or "") in {"broadcast", "ot_baseline"}:
            severity = "info"
        summary = str(item.get("summary", "Threat detection"))
        details = str(item.get("details", ""))
        evidence = []
        if isinstance(item.get("evidence"), list):
            evidence = [str(ev) for ev in item.get("evidence") or []]
        ts = _extract_detection_time(item)
        iocs = set()
        iocs.update(_extract_iocs(summary))
        iocs.update(_extract_iocs(details))
        for ev in evidence:
            iocs.update(_extract_iocs(ev))
        stage = _classify_stage(summary, details, str(item.get("source", "Threats")))
        ips = _ips_for_compromise_attribution(item, stage, summary)
        if not ips:
            continue
        for ip_value in ips:
            host_stages[ip_value].add(stage)
            _add_host_evidence(
                host_state,
                ip_value,
                severity,
                summary,
                details,
                ts,
                evidence,
                iocs,
                str(item.get("source", "Threats")),
            )
            detections.append(
                {
                    "severity": severity,
                    "summary": summary,
                    "details": details,
                    "source": str(item.get("source", "Threats")),
                    "ip": ip_value,
                    "timestamp": ts,
                    "evidence": evidence,
                    "iocs": sorted(iocs)[:10],
                    # Preserve skeptical-filter + hypothesis-lens
                    # annotations that threats.py attached upstream —
                    # the compromise renderer + verdict-summary block
                    # rely on these to classify the finding.
                    "skeptical_downgraded": bool(
                        item.get("skeptical_downgraded", False)
                    ),
                    "skeptical_rule": str(
                        item.get("skeptical_rule", "") or ""
                    ),
                    "skeptical_reason": str(
                        item.get("skeptical_reason", "") or ""
                    ),
                    "skeptical_original_severity": str(
                        item.get("skeptical_original_severity", "") or ""
                    ),
                    "hypothesis_relevance": str(
                        item.get("hypothesis_relevance", "") or ""
                    ),
                }
            )
            detection_by_host[ip_value].append(detections[-1])

            if stage == "lateral" and len(ips) >= 2:
                src_guess = str(item.get("src") or "")
                dst_guess = str(item.get("dst") or "")
                if _valid_ip(src_guess) and _valid_ip(dst_guess):
                    lateral_edges[(src_guess, dst_guess)] += 1

            if stage == "credential":
                deterministic_checks["credential_abuse"].append(
                    f"{ip_value} {summary} ({str(item.get('source', 'Threats'))})"
                )
            if stage == "c2":
                deterministic_checks["beacon_c2"].append(f"{ip_value} {summary}")
            if stage == "exfil":
                deterministic_checks["exfiltration"].append(f"{ip_value} {summary}")
            if stage == "lateral":
                deterministic_checks["lateral_movement"].append(f"{ip_value} {summary}")
            if len(iocs) >= 2:
                deterministic_checks["high_confidence_ioc"].append(
                    f"{ip_value} IOC cluster size={len(iocs)}"
                )

    # 2) Beaconing candidates
    for candidate in getattr(beacon_summary, "candidates", []) or []:
        score = float(getattr(candidate, "score", 0.0) or 0.0)
        if score < 0.80:
            continue
        src_ip = str(getattr(candidate, "src_ip", "") or "")
        dst_ip = str(getattr(candidate, "dst_ip", "") or "")
        if not _valid_ip(src_ip):
            continue
        # Internal-only periodic flow on an OT service port is the OT baseline
        # (HMI/PLC cyclic polling), not C2. Record it as benign-automation
        # context at info severity so it does not push an OT host over the
        # compromise threshold; genuine C2 (a private->public beacon) is
        # unaffected.
        # The beacon analyzer keys a TCP session on its service port and stores
        # it in whichever of src_port/dst_port survived (dst_port is None for
        # every TCP candidate), so the service port is "whichever is set" —
        # reading dst_port alone saw 0, never matched an OT port, and rated an
        # HMI's Modbus polls as HIGH-severity beaconing.
        service_port = 0
        for attr in ("src_port", "dst_port"):
            try:
                value = int(getattr(candidate, attr, 0) or 0)
            except Exception:
                value = 0
            if value:
                service_port = value
                break
        internal_ot_cyclic = (
            _is_private_ip(src_ip)
            and dst_ip
            and _is_private_ip(dst_ip)
            and service_port in OT_PORTS
        )
        if internal_ot_cyclic:
            severity = "info"
            summary = "Periodic OT control-channel (likely baseline polling)"
            message = (
                f"{src_ip}->{dst_ip} {getattr(candidate, 'proto', '-')}/{service_port} "
                f"interval≈{getattr(candidate, 'median_interval', 0.0):.1f}s "
                "(internal OT cyclic; verify against process baseline)"
            )
            deterministic_checks["benign_automation_likely"].append(message)
        else:
            severity = "high" if score >= 0.90 else "warning"
            summary = "Beaconing behavior detected"
        details = (
            f"{src_ip} -> {dst_ip} {getattr(candidate, 'proto', '-')}/"
            f"{service_port or '-'}"
        )
        evidence = [
            f"count={int(getattr(candidate, 'count', 0) or 0)}",
            f"interval={getattr(candidate, 'median_interval', 0.0):.2f}s",
            f"jitter={getattr(candidate, 'jitter', 0.0):.2f}",
            f"score={score:.2f}",
        ]
        ts = getattr(candidate, "first_seen", None)
        iocs = set()
        if dst_ip and _is_public_ip(dst_ip):
            iocs.add(dst_ip)
        _add_host_evidence(
            host_state,
            src_ip,
            severity,
            summary,
            details,
            ts,
            evidence,
            iocs,
            "Beacon",
        )
        detections.append(
            {
                "severity": severity,
                "summary": summary,
                "details": details,
                "source": "Beacon",
                "ip": src_ip,
                "timestamp": ts,
                "evidence": evidence,
                "iocs": sorted(iocs)[:10],
            }
        )
        detection_by_host[src_ip].append(detections[-1])
        if not internal_ot_cyclic:
            host_stages[src_ip].add("c2")
            deterministic_checks["beacon_c2"].append(
                f"{src_ip} beacon score={score:.2f} to {dst_ip}"
            )

    # 3) Exfiltration suspects
    exfil_first = getattr(exfil_summary, "first_seen", None)
    for item in getattr(exfil_summary, "dns_tunnel_suspects", []) or []:
        src_ip = str(item.get("src", "") or "")
        if not _valid_ip(src_ip):
            continue
        summary = "Potential DNS tunneling"
        details = f"{src_ip} queried {item.get('total', 0)} domains (entropy {item.get('avg_entropy', '-')})"
        evidence = [
            f"unique={item.get('unique', 0)}",
            f"long={item.get('long', 0)}",
            f"max_label={item.get('max_label', 0)}",
        ]
        _add_host_evidence(
            host_state,
            src_ip,
            "high",
            summary,
            details,
            exfil_first,
            evidence,
            set(),
            "Exfil",
        )
        detections.append(
            {
                "severity": "high",
                "summary": summary,
                "details": details,
                "source": "Exfil",
                "ip": src_ip,
                "timestamp": exfil_first,
                "evidence": evidence,
            }
        )
        detection_by_host[src_ip].append(detections[-1])
        host_stages[src_ip].add("exfil")
        deterministic_checks["exfiltration"].append(
            f"{src_ip} DNS tunnel suspect unique={item.get('unique', 0)}"
        )

    for item in getattr(exfil_summary, "http_post_suspects", []) or []:
        src_ip = str(item.get("src", "") or "")
        if not _valid_ip(src_ip):
            continue
        dst_ip = str(item.get("dst", "") or "")
        host = str(item.get("host", "") or "")
        uri = str(item.get("uri", "") or "")
        summary = "Suspicious HTTP POST volume"
        details = f"{src_ip} -> {dst_ip} host={host} uri={uri}"
        evidence = [
            f"bytes={format_bytes_as_mb(int(item.get('bytes', 0) or 0))}",
            f"requests={int(item.get('requests', 0) or 0)}",
        ]
        iocs = set()
        if host:
            iocs.add(host)
        if dst_ip and _is_public_ip(dst_ip):
            iocs.add(dst_ip)
        _add_host_evidence(
            host_state,
            src_ip,
            "warning",
            summary,
            details,
            exfil_first,
            evidence,
            iocs,
            "Exfil",
        )
        detections.append(
            {
                "severity": "warning",
                "summary": summary,
                "details": details,
                "source": "Exfil",
                "ip": src_ip,
                "timestamp": exfil_first,
                "evidence": evidence,
                "iocs": sorted(iocs)[:10],
            }
        )
        detection_by_host[src_ip].append(detections[-1])
        host_stages[src_ip].add("exfil")

    for item in getattr(exfil_summary, "file_exfil_suspects", []) or []:
        src_ip = str(item.get("src", "") or "")
        if not _valid_ip(src_ip):
            continue
        dst_ip = str(item.get("dst", "") or "")
        filename = str(item.get("filename", "") or "-")
        summary = "Potential file exfiltration"
        details = f"{src_ip} -> {dst_ip} {item.get('protocol', '-')} file={filename}"
        evidence = [
            f"size={format_bytes_as_mb(int(item.get('size', 0) or 0))}",
            f"note={item.get('note', '-')}",
        ]
        iocs = set()
        if filename and filename != "-":
            iocs.add(filename)
        if dst_ip and _is_public_ip(dst_ip):
            iocs.add(dst_ip)
        _add_host_evidence(
            host_state,
            src_ip,
            "high",
            summary,
            details,
            exfil_first,
            evidence,
            iocs,
            "Exfil",
        )
        detections.append(
            {
                "severity": "high",
                "summary": summary,
                "details": details,
                "source": "Exfil",
                "ip": src_ip,
                "timestamp": exfil_first,
                "evidence": evidence,
                "iocs": sorted(iocs)[:10],
            }
        )
        detection_by_host[src_ip].append(detections[-1])
        host_stages[src_ip].add("exfil")

    # 4) Credential exposure
    for hit in getattr(creds_summary, "hits", []) or []:
        src_ip = str(getattr(hit, "src_ip", "") or "")
        if not _valid_ip(src_ip):
            continue
        dst_ip = str(getattr(hit, "dst_ip", "") or "")
        summary = "Credential exposure in cleartext"
        details = f"{src_ip} -> {dst_ip} {getattr(hit, 'protocol', '-')}/{getattr(hit, 'dst_port', '-')}"
        evidence = [
            f"kind={getattr(hit, 'kind', '-')}",
            f"user={getattr(hit, 'username', '-')}",
        ]
        iocs = set()
        if dst_ip and _is_public_ip(dst_ip):
            iocs.add(dst_ip)
        _add_host_evidence(
            host_state,
            src_ip,
            "warning",
            summary,
            details,
            getattr(hit, "ts", None),
            evidence,
            iocs,
            "Creds",
        )
        detections.append(
            {
                "severity": "warning",
                "summary": summary,
                "details": details,
                "source": "Creds",
                "ip": src_ip,
                "timestamp": getattr(hit, "ts", None),
                "evidence": evidence,
                "iocs": sorted(iocs)[:10],
            }
        )
        detection_by_host[src_ip].append(detections[-1])
        host_stages[src_ip].add("credential")
        deterministic_checks["credential_abuse"].append(
            f"{src_ip} cleartext credential exposure"
        )

    # 5) Secret exposure (tokens/keys)
    for hit in getattr(secrets_summary, "hits", []) or []:
        src_ip = str(getattr(hit, "src_ip", "") or "")
        if not _valid_ip(src_ip):
            continue
        dst_ip = str(getattr(hit, "dst_ip", "") or "")
        summary = "Sensitive token/secret in transit"
        details = f"{src_ip} -> {dst_ip} {getattr(hit, 'protocol', '-')}/{getattr(hit, 'dst_port', '-')}"
        evidence = [
            f"kind={getattr(hit, 'kind', '-')}",
            f"note={getattr(hit, 'note', '-')}",
        ]
        iocs = set()
        if dst_ip and _is_public_ip(dst_ip):
            iocs.add(dst_ip)
        _add_host_evidence(
            host_state,
            src_ip,
            "info",
            summary,
            details,
            getattr(hit, "ts", None),
            evidence,
            iocs,
            "Secrets",
        )
        detections.append(
            {
                "severity": "info",
                "summary": summary,
                "details": details,
                "source": "Secrets",
                "ip": src_ip,
                "timestamp": getattr(hit, "ts", None),
                "evidence": evidence,
                "iocs": sorted(iocs)[:10],
            }
        )
        detection_by_host[src_ip].append(detections[-1])
        host_stages[src_ip].add("secrets")

    compromised_hosts: list[CompromisedHost] = []
    host_record_by_ip = {record.ip: record for record in hosts_summary.hosts}
    # Browser (MS-BRWS) announced identity — a compromised Domain Controller /
    # SQL / critical-infra host is a crown-jewel: annotate and elevate it.
    try:
        from .netbios import analyze_netbios, collect_netbios_host_intel

        _nb_intel = collect_netbios_host_intel(analyze_netbios(path, show_status=False))
    except Exception:
        _nb_intel = {}
    host_priority: list[dict[str, object]] = []
    for ip_value, state in host_state.items():
        score = int(state.get("score", 0) or 0)
        severity_counts: Counter[str] = state.get("severity_counts", Counter())
        stage_count = len(host_stages.get(ip_value, set()))
        score += max(0, stage_count - 1)

        host_record = host_record_by_ip.get(ip_value)
        if host_record is not None:
            score += _criticality_boost(host_record)

        if (
            score < 5
            and severity_counts.get("high", 0) == 0
            and severity_counts.get("critical", 0) == 0
        ):
            continue
        hostname_list = hostnames_by_ip.get(ip_value, [])
        hostname_display = _pick_hostname(ip_value, hostname_list)

        # Browser-announced asset context (roles + crown-jewel elevation).
        nb_facts = _nb_intel.get(ip_value, {})
        nb_roles = [str(r) for r in nb_facts.get("roles", []) or []]
        nb_is_infra = bool(
            nb_facts.get("is_dc")
            or any(
                r in ("Master Browser", "SQL Server", "Domain Master Browser")
                for r in nb_roles
            )
        )
        asset_evidence: list[str] = []
        if nb_facts:
            if not hostname_display and nb_facts.get("hostname"):
                hostname_display = str(nb_facts["hostname"])
            if nb_is_infra:
                infra_label = (
                    "Domain Controller"
                    if nb_facts.get("is_dc")
                    else ", ".join(nb_roles[:3])
                )
                # Built as a plain string rather than a nested f-string: reusing
                # the outer quote character inside an f-string expression is
                # PEP 701, which is 3.12+, and this package supports 3.9.
                nb_domain = nb_facts.get("domain")
                domain_clause = f" in domain {nb_domain}" if nb_domain else ""
                asset_evidence.append(
                    f"ASSET CONTEXT: browser-announced {infra_label}"
                    f"{domain_clause}"
                    " — crown-jewel, prioritize"
                )
                score += 2

        severity = "info"
        if severity_counts.get("critical"):
            severity = "critical"
        elif severity_counts.get("high"):
            severity = "high"
        elif severity_counts.get("warning"):
            severity = "warning"

        summaries = state.get("summaries", [])
        explanation = (
            "; ".join(summaries[:2]) if summaries else "Evidence of compromise"
        )
        evidence = asset_evidence + state.get("details", []) + state.get("evidence", [])
        evidence = [str(item) for item in evidence if str(item).strip()]
        evidence = evidence[:6]

        iocs = set(state.get("iocs", set()))
        iocs = {ioc for ioc in iocs if not (ioc == ip_value)}
        ioc_list = sorted(iocs)[:10]

        detection_time = state.get("first_ts") or host_first_seen.get(ip_value)

        compromised_hosts.append(
            CompromisedHost(
                hostname=hostname_display,
                ip=ip_value,
                detection_time=detection_time,
                explanation=explanation,
                evidence=evidence,
                iocs=ioc_list,
                severity=severity,
                score=score,
                roles=nb_roles,
                is_infra=nb_is_infra,
            )
        )

        host_priority.append(
            {
                "host": hostname_display,
                "ip": ip_value,
                "score": score,
                "stages": sorted(host_stages.get(ip_value, set())),
                "stage_count": stage_count,
                "ioc_count": len(ioc_list),
                "severity": severity,
                "detection_time": detection_time,
            }
        )

        if stage_count >= 3:
            deterministic_checks["multi_stage_sequence"].append(
                f"{ip_value} stages={','.join(sorted(host_stages.get(ip_value, set())))}"
            )

    # The IP is a tiebreaker, not decoration: severity and score alone are not a
    # total order, and two hosts that tie on both — routine, since scores are
    # small integers — then fell back to insertion order, which is not stable
    # across runs. The same capture could produce two different victim orderings
    # in two invocations, which is indefensible in a report that is used as
    # evidence. Sorted with negated numerics rather than reverse=True so the
    # tiebreaker still reads ascending.
    compromised_hosts.sort(
        key=lambda host: (
            -SEVERITY_WEIGHT.get(host.severity, 0),
            -host.score,
            host.ip,
        )
    )

    incidents: list[dict[str, object]] = []
    incident_gap_seconds = 900.0
    for ip_value, items in detection_by_host.items():
        # Info-level entries are context (baseline polling, tokens in
        # transit); a cluster made only of them is not an incident, and the
        # verdict credits every incident cluster.
        sortable = [
            entry
            for entry in items
            if isinstance(entry.get("timestamp"), (int, float))
            and str(entry.get("severity", "info")) != "info"
        ]
        sortable.sort(key=lambda item: float(item.get("timestamp", 0.0) or 0.0))
        if not sortable:
            continue
        cluster: list[dict[str, object]] = [sortable[0]]
        for item in sortable[1:]:
            prev_ts = float(cluster[-1].get("timestamp", 0.0) or 0.0)
            ts = float(item.get("timestamp", 0.0) or 0.0)
            if ts - prev_ts <= incident_gap_seconds:
                cluster.append(item)
            else:
                incidents.append(
                    {
                        "ip": ip_value,
                        "first_ts": float(cluster[0].get("timestamp", 0.0) or 0.0),
                        "last_ts": float(cluster[-1].get("timestamp", 0.0) or 0.0),
                        "count": len(cluster),
                        "stages": sorted(
                            {
                                _classify_stage(
                                    str(v.get("summary", "")),
                                    str(v.get("details", "")),
                                    str(v.get("source", "")),
                                )
                                for v in cluster
                            }
                        ),
                    }
                )
                cluster = [item]
        if cluster:
            incidents.append(
                {
                    "ip": ip_value,
                    "first_ts": float(cluster[0].get("timestamp", 0.0) or 0.0),
                    "last_ts": float(cluster[-1].get("timestamp", 0.0) or 0.0),
                    "count": len(cluster),
                    "stages": sorted(
                        {
                            _classify_stage(
                                str(v.get("summary", "")),
                                str(v.get("details", "")),
                                str(v.get("source", "")),
                            )
                            for v in cluster
                        }
                    ),
                }
            )

    def _is_strong_campaign_ioc(value: str) -> bool:
        # Campaign correlation groups hosts by a shared indicator, so the
        # indicator must be specific enough that sharing it is meaningful. URLs,
        # file hashes, and public IPs qualify. Bare filenames (e.g. "update.exe")
        # and bare internal/benign domains recur across unrelated hosts and
        # would manufacture phantom campaigns, so they are excluded here while
        # remaining visible in each host's IOC list.
        text = str(value or "").strip().lower()
        if not text:
            return False
        if text.startswith(("http://", "https://")):
            return True
        if _HASH_RE.fullmatch(text):
            return True
        if _valid_ip(text):
            return _is_public_ip(text)
        # A domain qualifies only if it is public-routable (has a real TLD and
        # is not an internal/.local/.arpa name).
        if "." in text and not text.endswith((".local", ".arpa", ".lan", ".internal")):
            return bool(IOC_DOMAIN_RE.fullmatch(text))
        return False

    ioc_to_hosts: dict[str, set[str]] = defaultdict(set)
    for host in compromised_hosts:
        for ioc in host.iocs[:20]:
            if ioc and _is_strong_campaign_ioc(str(ioc)):
                ioc_to_hosts[str(ioc)].add(host.ip)

    campaigns: list[dict[str, object]] = []
    campaign_idx = 1
    for ioc, hosts in sorted(
        ioc_to_hosts.items(), key=lambda item: (-len(item[1]), item[0])
    ):
        if len(hosts) < 2:
            continue
        campaigns.append(
            {
                "campaign_id": f"CMP-{campaign_idx:03d}",
                "ioc": ioc,
                "hosts": sorted(hosts),
                "host_count": len(hosts),
            }
        )
        campaign_idx += 1
        if campaign_idx > 25:
            break

    benign_context: list[str] = []
    for ip_value in sorted(host_state.keys()):
        stages = host_stages.get(ip_value, set())
        if stages == {"c2"} and len(detection_by_host.get(ip_value, [])) <= 1:
            message = (
                f"{ip_value} only single C2-like signal without corroboration"
            )
            benign_context.append(message)
            deterministic_checks["benign_automation_likely"].append(message)
        record = host_record_by_ip.get(ip_value)
        if record is not None:
            ports = {
                int(getattr(item, "port", 0) or 0)
                for item in getattr(record, "open_ports", []) or []
            }
            if 123 in ports and stages <= {"c2", "other"}:
                message = (
                    f"{ip_value} periodic behavior may align with NTP/service checks"
                )
                benign_context.append(message)
                deterministic_checks["benign_automation_likely"].append(message)

    host_priority.sort(key=_host_priority_key)
    incidents.sort(key=_incident_key)

    normalized_checks: dict[str, list[str]] = {}
    for key, values in deterministic_checks.items():
        cleaned = [str(v).strip() for v in values if str(v).strip()]
        normalized_checks[key] = sorted(set(cleaned))[:40]

    return CompromiseSummary(
        path=path,
        total_hosts=len(hosts_summary.hosts),
        compromised_hosts=compromised_hosts,
        detections=detections,
        incidents=incidents,
        campaigns=campaigns,
        host_priority=host_priority,
        deterministic_checks=normalized_checks,
        benign_context=benign_context[:20],
        errors=sorted({err for err in errors if err}),
    )


def merge_compromised_summaries(
    summaries: Iterable[CompromiseSummary],
) -> CompromiseSummary:
    summary_list = list(summaries)
    if not summary_list:
        return CompromiseSummary(path=Path("ALL_PCAPS_0"), total_hosts=0)

    merged_hosts: dict[str, dict[str, object]] = {}
    detections: list[dict[str, object]] = []
    incidents: list[dict[str, object]] = []
    campaigns: list[dict[str, object]] = []
    host_priority: list[dict[str, object]] = []
    deterministic_checks: dict[str, list[str]] = defaultdict(list)
    benign_context: list[str] = []
    errors: set[str] = set()
    total_hosts = 0

    for summary in summary_list:
        total_hosts += int(getattr(summary, "total_hosts", 0) or 0)
        errors.update(getattr(summary, "errors", []) or [])
        detections.extend(getattr(summary, "detections", []) or [])
        incidents.extend(getattr(summary, "incidents", []) or [])
        campaigns.extend(getattr(summary, "campaigns", []) or [])
        host_priority.extend(getattr(summary, "host_priority", []) or [])
        benign_context.extend(getattr(summary, "benign_context", []) or [])
        for key, values in (getattr(summary, "deterministic_checks", {}) or {}).items():
            for value in values or []:
                deterministic_checks[str(key)].append(str(value))
        for host in getattr(summary, "compromised_hosts", []) or []:
            entry = merged_hosts.get(host.ip)
            if entry is None:
                entry = {
                    "hostname": host.hostname,
                    "ip": host.ip,
                    "detection_time": host.detection_time,
                    "explanation": [host.explanation],
                    "evidence": set(host.evidence),
                    "iocs": set(host.iocs),
                    "severity": host.severity,
                    "score": host.score,
                    "roles": list(host.roles),
                    "is_infra": bool(host.is_infra),
                }
                merged_hosts[host.ip] = entry
                continue

            if host.detection_time is not None:
                current = entry.get("detection_time")
                if current is None or host.detection_time < current:
                    entry["detection_time"] = host.detection_time
            entry["evidence"].update(host.evidence)
            entry["iocs"].update(host.iocs)
            if host.explanation not in entry["explanation"]:
                entry["explanation"].append(host.explanation)
            if SEVERITY_WEIGHT.get(host.severity, 0) > SEVERITY_WEIGHT.get(
                entry.get("severity", "info"), 0
            ):
                entry["severity"] = host.severity
            entry["score"] = max(int(entry.get("score", 0)), host.score)
            for role in host.roles:
                if role not in entry["roles"]:
                    entry["roles"].append(role)
            entry["is_infra"] = bool(entry.get("is_infra")) or bool(host.is_infra)

    merged_list: list[CompromisedHost] = []
    for ip_value, entry in merged_hosts.items():
        merged_list.append(
            CompromisedHost(
                hostname=str(entry.get("hostname", "-")),
                ip=ip_value,
                detection_time=entry.get("detection_time"),
                explanation="; ".join(entry.get("explanation", [])[:2])
                or "Evidence of compromise",
                evidence=sorted(entry.get("evidence", set()))[:6],
                iocs=sorted(entry.get("iocs", set()))[:10],
                severity=str(entry.get("severity", "info")),
                score=int(entry.get("score", 0) or 0),
                roles=list(entry.get("roles", []) or []),
                is_infra=bool(entry.get("is_infra", False)),
            )
        )

    # Same total order as the single-capture list (severity, score, then IP).
    merged_list.sort(
        key=lambda host: (
            -SEVERITY_WEIGHT.get(host.severity, 0),
            -host.score,
            host.ip,
        )
    )

    host_priority.sort(key=_host_priority_key)
    incidents.sort(key=_incident_key)
    dedup_checks: dict[str, list[str]] = {}
    for key, values in deterministic_checks.items():
        seen: set[str] = set()
        out: list[str] = []
        for value in values:
            if value in seen:
                continue
            seen.add(value)
            out.append(value)
            if len(out) >= 60:
                break
        dedup_checks[key] = out

    return CompromiseSummary(
        path=Path(f"ALL_PCAPS_{len(summary_list)}"),
        total_hosts=total_hosts,
        compromised_hosts=merged_list,
        detections=detections,
        incidents=incidents,
        campaigns=campaigns,
        host_priority=host_priority[:200],
        deterministic_checks=dedup_checks,
        benign_context=sorted(set(benign_context))[:50],
        errors=sorted(errors),
    )
