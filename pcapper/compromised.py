from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
import ipaddress
from pathlib import Path
import re
from typing import Iterable, Optional

from .beacon import analyze_beacons
from .creds import analyze_creds
from .exfil import analyze_exfil
from .hosts import analyze_hosts
from .secrets import analyze_secrets
from .threats import analyze_threats
from .utils import format_bytes_as_mb
from .progress import run_with_busy_status


IOC_DOMAIN_RE = re.compile(r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]{2,})+)\b", re.IGNORECASE)
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
IOC_FILENAME_RE = re.compile(r"\b[\w\-.()\[\] ]+\.(?:exe|dll|sys|scr|cpl|ocx|bat|ps1|vbs|js|jar|zip|rar|7z|gz|iso|img|pdf|doc|docx|xls|xlsx|ppt|pptx)\b", re.IGNORECASE)

SEVERITY_WEIGHT = {
    "critical": 8,
    "high": 5,
    "warning": 3,
    "info": 1,
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


@dataclass(frozen=True)
class CompromiseSummary:
    path: Path
    total_hosts: int
    compromised_hosts: list[CompromisedHost] = field(default_factory=list)
    detections: list[dict[str, object]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _valid_ip(value: str) -> bool:
    if not value:
        return False
    try:
        ip_obj = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip_obj.is_unspecified or ip_obj.is_multicast:
        return False
    return True


def _is_public_ip(value: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip_obj.is_global


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
    for token in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        if _valid_ip(token):
            hits.add(token)
    for token in re.findall(r"\b[0-9a-fA-F:]{3,}\b", text):
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


def _score_weight(severity: str) -> int:
    return SEVERITY_WEIGHT.get(severity, 1)


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
    entry = host_state.setdefault(ip_value, {
        "score": 0,
        "severity_counts": Counter(),
        "summaries": [],
        "details": [],
        "evidence": [],
        "evidence_seen": set(),
        "iocs": set(),
        "sources": set(),
        "first_ts": None,
    })

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


def analyze_compromised(path: Path, show_status: bool = True) -> CompromiseSummary:
    errors: list[str] = []

    hosts_summary = analyze_hosts(path, show_status=show_status)
    def _busy(desc: str, func, *args, **kwargs):
        return run_with_busy_status(path, show_status, f"Compromised: {desc}", func, *args, **kwargs)

    threat_summary = _busy("Threats", analyze_threats, path, show_status=False)
    beacon_summary = _busy("Beacons", analyze_beacons, path, show_status=False)
    exfil_summary = _busy("Exfil", analyze_exfil, path, show_status=False)
    creds_summary = _busy("Creds", analyze_creds, path, show_status=False)
    secrets_summary = _busy("Secrets", analyze_secrets, path, show_status=False)

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

    # 1) Threat detections (cross-module)
    for item in getattr(threat_summary, "detections", []) or []:
        if not isinstance(item, dict):
            continue
        severity = _normalize_severity(item.get("severity"))
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
        ips = _extract_ips_from_detection(item)
        if not ips:
            continue
        for ip_value in ips:
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
            detections.append({
                "severity": severity,
                "summary": summary,
                "details": details,
                "source": str(item.get("source", "Threats")),
                "ip": ip_value,
                "timestamp": ts,
                "evidence": evidence,
                "iocs": sorted(iocs)[:10],
            })

    # 2) Beaconing candidates
    for candidate in getattr(beacon_summary, "candidates", []) or []:
        score = float(getattr(candidate, "score", 0.0) or 0.0)
        if score < 0.80:
            continue
        src_ip = str(getattr(candidate, "src_ip", "") or "")
        dst_ip = str(getattr(candidate, "dst_ip", "") or "")
        if not _valid_ip(src_ip):
            continue
        severity = "high" if score >= 0.90 else "warning"
        summary = "Beaconing behavior detected"
        details = (
            f"{src_ip} -> {dst_ip} {getattr(candidate, 'proto', '-')}/"
            f"{getattr(candidate, 'dst_port', '-')}")
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
        detections.append({
            "severity": severity,
            "summary": summary,
            "details": details,
            "source": "Beacon",
            "ip": src_ip,
            "timestamp": ts,
            "evidence": evidence,
            "iocs": sorted(iocs)[:10],
        })

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
        detections.append({
            "severity": "high",
            "summary": summary,
            "details": details,
            "source": "Exfil",
            "ip": src_ip,
            "timestamp": exfil_first,
            "evidence": evidence,
        })

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
        detections.append({
            "severity": "warning",
            "summary": summary,
            "details": details,
            "source": "Exfil",
            "ip": src_ip,
            "timestamp": exfil_first,
            "evidence": evidence,
            "iocs": sorted(iocs)[:10],
        })

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
        detections.append({
            "severity": "high",
            "summary": summary,
            "details": details,
            "source": "Exfil",
            "ip": src_ip,
            "timestamp": exfil_first,
            "evidence": evidence,
            "iocs": sorted(iocs)[:10],
        })

    # 4) Credential exposure
    for hit in getattr(creds_summary, "hits", []) or []:
        src_ip = str(getattr(hit, "src_ip", "") or "")
        if not _valid_ip(src_ip):
            continue
        dst_ip = str(getattr(hit, "dst_ip", "") or "")
        summary = "Credential exposure in cleartext"
        details = f"{src_ip} -> {dst_ip} {getattr(hit, 'protocol', '-')}/{getattr(hit, 'dst_port', '-') }"
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
        detections.append({
            "severity": "warning",
            "summary": summary,
            "details": details,
            "source": "Creds",
            "ip": src_ip,
            "timestamp": getattr(hit, "ts", None),
            "evidence": evidence,
            "iocs": sorted(iocs)[:10],
        })

    # 5) Secret exposure (tokens/keys)
    for hit in getattr(secrets_summary, "hits", []) or []:
        src_ip = str(getattr(hit, "src_ip", "") or "")
        if not _valid_ip(src_ip):
            continue
        dst_ip = str(getattr(hit, "dst_ip", "") or "")
        summary = "Sensitive token/secret in transit"
        details = f"{src_ip} -> {dst_ip} {getattr(hit, 'protocol', '-')}/{getattr(hit, 'dst_port', '-') }"
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
        detections.append({
            "severity": "info",
            "summary": summary,
            "details": details,
            "source": "Secrets",
            "ip": src_ip,
            "timestamp": getattr(hit, "ts", None),
            "evidence": evidence,
            "iocs": sorted(iocs)[:10],
        })

    compromised_hosts: list[CompromisedHost] = []
    for ip_value, state in host_state.items():
        score = int(state.get("score", 0) or 0)
        severity_counts: Counter[str] = state.get("severity_counts", Counter())
        if score < 5 and severity_counts.get("high", 0) == 0 and severity_counts.get("critical", 0) == 0:
            continue
        hostname_list = hostnames_by_ip.get(ip_value, [])
        hostname_display = _pick_hostname(ip_value, hostname_list)

        severity = "info"
        if severity_counts.get("critical"):
            severity = "critical"
        elif severity_counts.get("high"):
            severity = "high"
        elif severity_counts.get("warning"):
            severity = "warning"

        summaries = state.get("summaries", [])
        explanation = "; ".join(summaries[:2]) if summaries else "Evidence of compromise"
        evidence = state.get("details", []) + state.get("evidence", [])
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
            )
        )

    compromised_hosts.sort(
        key=lambda host: (
            SEVERITY_WEIGHT.get(host.severity, 0),
            host.score,
        ),
        reverse=True,
    )

    return CompromiseSummary(
        path=path,
        total_hosts=len(hosts_summary.hosts),
        compromised_hosts=compromised_hosts,
        detections=detections,
        errors=sorted({err for err in errors if err}),
    )


def merge_compromised_summaries(summaries: Iterable[CompromiseSummary]) -> CompromiseSummary:
    summary_list = list(summaries)
    if not summary_list:
        return CompromiseSummary(path=Path("ALL_PCAPS_0"), total_hosts=0)

    merged_hosts: dict[str, dict[str, object]] = {}
    detections: list[dict[str, object]] = []
    errors: set[str] = set()
    total_hosts = 0

    for summary in summary_list:
        total_hosts += int(getattr(summary, "total_hosts", 0) or 0)
        errors.update(getattr(summary, "errors", []) or [])
        detections.extend(getattr(summary, "detections", []) or [])
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
            if SEVERITY_WEIGHT.get(host.severity, 0) > SEVERITY_WEIGHT.get(entry.get("severity", "info"), 0):
                entry["severity"] = host.severity
            entry["score"] = max(int(entry.get("score", 0)), host.score)

    merged_list: list[CompromisedHost] = []
    for ip_value, entry in merged_hosts.items():
        merged_list.append(
            CompromisedHost(
                hostname=str(entry.get("hostname", "-")),
                ip=ip_value,
                detection_time=entry.get("detection_time"),
                explanation="; ".join(entry.get("explanation", [])[:2]) or "Evidence of compromise",
                evidence=sorted(entry.get("evidence", set()))[:6],
                iocs=sorted(entry.get("iocs", set()))[:10],
                severity=str(entry.get("severity", "info")),
                score=int(entry.get("score", 0) or 0),
            )
        )

    merged_list.sort(
        key=lambda host: (
            SEVERITY_WEIGHT.get(host.severity, 0),
            host.score,
        ),
        reverse=True,
    )

    return CompromiseSummary(
        path=Path(f"ALL_PCAPS_{len(summary_list)}"),
        total_hosts=total_hosts,
        compromised_hosts=merged_list,
        detections=detections,
        errors=sorted(errors),
    )
