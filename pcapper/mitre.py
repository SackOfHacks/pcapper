from __future__ import annotations

import ipaddress
import json
import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .ioc import analyze_iocs
from .threats import analyze_threats

_TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_TACTIC_ID_RE = re.compile(r"\bTA\d{4}\b", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PACKET_RE = re.compile(r"\b(?:pkt|packet)\s*[=:]\s*(\d+)\b", re.IGNORECASE)

_DEFAULT_ATTACK_ENTERPRISE_VERSION = "ATT&CK Enterprise v15.1"
_DEFAULT_ATTACK_ICS_VERSION = "ATT&CK ICS v15.1"
_DEFAULT_MAPPING_PACK_VERSION = "pcapper-mitre-ruleset-1.1"


def _load_mapping_metadata() -> tuple[str, str, str, Optional[str]]:
    metadata_file = os.getenv("PCAPPER_MITRE_METADATA_FILE", "").strip()
    if not metadata_file:
        return (
            _DEFAULT_ATTACK_ENTERPRISE_VERSION,
            _DEFAULT_ATTACK_ICS_VERSION,
            _DEFAULT_MAPPING_PACK_VERSION,
            None,
        )
    try:
        with Path(metadata_file).expanduser().open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            raise ValueError("metadata root is not an object")
        enterprise = str(
            data.get("attack_enterprise_version", _DEFAULT_ATTACK_ENTERPRISE_VERSION)
            or _DEFAULT_ATTACK_ENTERPRISE_VERSION
        )
        ics = str(
            data.get("attack_ics_version", _DEFAULT_ATTACK_ICS_VERSION)
            or _DEFAULT_ATTACK_ICS_VERSION
        )
        pack = str(
            data.get("mapping_pack_version", _DEFAULT_MAPPING_PACK_VERSION)
            or _DEFAULT_MAPPING_PACK_VERSION
        )
        return enterprise, ics, pack, None
    except Exception as exc:
        return (
            _DEFAULT_ATTACK_ENTERPRISE_VERSION,
            _DEFAULT_ATTACK_ICS_VERSION,
            _DEFAULT_MAPPING_PACK_VERSION,
            f"MITRE mapping metadata unavailable: {type(exc).__name__}: {exc}",
        )


(
    ATTACK_ENTERPRISE_VERSION,
    ATTACK_ICS_VERSION,
    MAPPING_PACK_VERSION,
    _MAPPING_METADATA_ERROR,
) = _load_mapping_metadata()

_ENTERPRISE_TACTIC_ORDER: dict[str, int] = {
    "Reconnaissance": 1,
    "Resource Development": 2,
    "Initial Access": 3,
    "Execution": 4,
    "Persistence": 5,
    "Privilege Escalation": 6,
    "Defense Evasion": 7,
    "Credential Access": 8,
    "Discovery": 9,
    "Lateral Movement": 10,
    "Collection": 11,
    "Command and Control": 12,
    "Exfiltration": 13,
    "Impact": 14,
}

_ICS_TACTIC_ORDER: dict[str, int] = {
    "Initial Access": 1,
    "Discovery": 2,
    "Lateral Movement": 3,
    "Command and Control": 4,
    "Impair Process Control": 5,
    "Inhibit Response Function": 6,
    "Impact": 7,
}


@dataclass(frozen=True)
class MitreHit:
    framework: str
    tactic: str
    tactic_id: str
    technique: str
    technique_id: str
    procedure: str
    source: str
    severity: str
    confidence: str
    details: str
    evidence: list[str]
    artifacts: list[str]
    iocs: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    occurrence: int
    matched_keywords: list[str] = field(default_factory=list)
    corroborating_sources: int = 0
    contradictory_signals: list[str] = field(default_factory=list)
    packet_refs: list[str] = field(default_factory=list)
    flow_refs: list[str] = field(default_factory=list)
    host_refs: list[str] = field(default_factory=list)
    rationale: str = ""


@dataclass(frozen=True)
class MitreSummary:
    path: Path
    total_detections: int
    mapped_detections: int
    tactic_counts: Counter[str] = field(default_factory=Counter)
    technique_counts: Counter[str] = field(default_factory=Counter)
    procedure_counts: Counter[str] = field(default_factory=Counter)
    framework_counts: Counter[str] = field(default_factory=Counter)
    ioc_counts: Counter[str] = field(default_factory=Counter)
    artifact_counts: Counter[str] = field(default_factory=Counter)
    attack_path: list[str] = field(default_factory=list)
    hits: list[MitreHit] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    duration_seconds: Optional[float] = None
    attack_enterprise_version: str = ATTACK_ENTERPRISE_VERSION
    attack_ics_version: str = ATTACK_ICS_VERSION
    mapping_pack_version: str = MAPPING_PACK_VERSION
    executive_verdict: str = ""
    executive_confidence: str = "low"
    executive_reasons: list[str] = field(default_factory=list)
    sequence_issues: list[str] = field(default_factory=list)
    alternate_explanations: list[str] = field(default_factory=list)
    host_attack_paths: dict[str, list[str]] = field(default_factory=dict)
    host_roles: dict[str, list[str]] = field(default_factory=dict)
    technique_heat: list[dict[str, object]] = field(default_factory=list)
    investigation_pivots: list[dict[str, object]] = field(default_factory=list)
    checks: dict[str, list[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class _TechniqueRule:
    framework: str
    tactic: str
    tactic_id: str
    technique: str
    technique_id: str
    keywords: tuple[str, ...]
    context: tuple[str, ...] = ()
    excluded: tuple[str, ...] = ()
    min_keyword_hits: int = 1
    min_score: int = 2


_RULES: tuple[_TechniqueRule, ...] = (
    _TechniqueRule(
        "enterprise",
        "Reconnaissance",
        "TA0043",
        "Active Scanning",
        "T1595",
        ("scan", "probing", "sweep", "enumeration"),
        ("ports", "services", "targets"),
        min_score=3,
    ),
    _TechniqueRule(
        "enterprise",
        "Credential Access",
        "TA0006",
        "Brute Force",
        "T1110",
        ("brute", "auth failure", "login fail", "password"),
        ("attempts", "credential"),
        min_score=3,
    ),
    _TechniqueRule(
        "enterprise",
        "Execution",
        "TA0002",
        "PowerShell",
        "T1059.001",
        ("powershell", "encodedcommand", "-enc", "invoke-webrequest"),
        min_score=3,
    ),
    _TechniqueRule(
        "enterprise",
        "Execution",
        "TA0002",
        "Windows Management Instrumentation",
        "T1047",
        ("wmic", "process call create"),
        ("wmi",),
        min_score=3,
    ),
    _TechniqueRule(
        "enterprise",
        "Lateral Movement",
        "TA0008",
        "Remote Services",
        "T1021",
        ("lateral movement", "winrm", "rdp", "smb", "ssh"),
        min_score=3,
    ),
    _TechniqueRule(
        "enterprise",
        "Command and Control",
        "TA0011",
        "Application Layer Protocol",
        "T1071",
        ("beacon", "c2", "command and control"),
        ("dns", "http", "https", "quic"),
        min_score=3,
    ),
    _TechniqueRule(
        "enterprise",
        "Exfiltration",
        "TA0010",
        "Exfiltration Over Alternative Protocol",
        "T1048",
        ("exfil", "dns tunneling", "outbound transfer"),
        ("txt-query", "public_destinations"),
        min_score=3,
    ),
    _TechniqueRule(
        "enterprise",
        "Discovery",
        "TA0007",
        "Network Service Discovery",
        "T1046",
        ("service discovery", "open ports", "banner", "fingerprint"),
        min_score=3,
    ),
    _TechniqueRule(
        "enterprise",
        "Resource Development",
        "TA0042",
        "Stage Capabilities",
        "T1587",
        ("malware", "payload", "tooling"),
        ("artifact",),
        min_score=3,
    ),
    _TechniqueRule(
        "ics",
        "Discovery",
        "TA0102",
        "Network Service Discovery",
        "T0846",
        ("ot reconnaissance", "enip session", "identity request", "plc", "scada"),
        ("discovery",),
        min_score=3,
    ),
    _TechniqueRule(
        "ics",
        "Lateral Movement",
        "TA0109",
        "Remote Services",
        "T0866",
        ("engineering workstation", "ot protocol traffic"),
        ("remote services",),
        min_score=3,
    ),
    _TechniqueRule(
        "ics",
        "Command and Control",
        "TA0108",
        "Standard Application Layer Protocol",
        "T0885",
        (
            "modbus",
            "dnp3",
            "iec-104",
            "s7",
            "opc",
            "bacnet",
            "cip",
            "enip",
            "mms",
            "profinet",
        ),
        min_score=3,
    ),
    _TechniqueRule(
        "ics",
        "Impair Process Control",
        "TA0106",
        "Unauthorized Command Message",
        "T0855",
        ("high-risk ot commands", "control/program operations", "setpoint", "trip"),
        ("write", "operate"),
        min_score=3,
    ),
    _TechniqueRule(
        "ics",
        "Inhibit Response Function",
        "TA0107",
        "Denial of Control",
        "T0813",
        ("safety plc", "sis", "server error response surge"),
        ("flood", "impact", "dos"),
        min_score=3,
    ),
)


_ICS_STRONG_TOKENS: tuple[str, ...] = (
    "ics",
    "scada",
    "plc",
    "modbus",
    "dnp3",
    "iec-104",
    "s7",
    "opc",
    "bacnet",
    "cip",
    "enip",
    "profinet",
    "mms",
    "goose",
    "sv",
)


def _extract_explicit_ids(text: str) -> tuple[list[str], list[str]]:
    tactic_ids = [m.group(0).upper() for m in _TACTIC_ID_RE.finditer(text)]
    technique_ids = [m.group(0).upper() for m in _TECHNIQUE_ID_RE.finditer(text)]
    return tactic_ids, technique_ids


def _contains_token(blob: str, token: str) -> bool:
    if not token:
        return False
    escaped = re.escape(token)
    pattern = rf"(?<![a-z0-9]){escaped}(?![a-z0-9])"
    return re.search(pattern, blob, re.IGNORECASE) is not None


def _rule_from_text(blob: str) -> tuple[_TechniqueRule | None, int]:
    best: tuple[int, _TechniqueRule] | None = None
    for rule in _RULES:
        if any(_contains_token(blob, token) for token in rule.excluded):
            continue
        keyword_hits = sum(1 for token in rule.keywords if _contains_token(blob, token))
        context_hits = sum(1 for token in rule.context if _contains_token(blob, token))
        if keyword_hits < rule.min_keyword_hits:
            continue
        score = (keyword_hits * 3) + context_hits
        if score < rule.min_score:
            continue
        if best is None or score > best[0]:
            best = (score, rule)
    if best is None:
        return None, 0
    return best[1], best[0]


def _matched_keywords(rule: _TechniqueRule | None, blob: str) -> list[str]:
    if rule is None:
        return []
    found = [
        token
        for token in (rule.keywords + rule.context)
        if _contains_token(blob, token)
    ]
    return sorted(set(found))


def _infer_framework(blob: str) -> str:
    if any(_contains_token(blob, token) for token in _ICS_STRONG_TOKENS):
        return "ics"
    return "enterprise"


def _normalize_confidence(value: object) -> str:
    text = str(value or "").strip().lower()
    if text in {"high", "medium", "low"}:
        return text
    if text in {"critical", "warning", "warn", "info"}:
        return (
            "high"
            if text == "critical"
            else ("medium" if text in {"warning", "warn"} else "low")
        )
    return "low"


def _parse_ip(value: str) -> Optional[str]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except Exception:
        return None


def _looks_like_domain(value: str) -> bool:
    text = str(value or "").strip().lower().rstrip(".")
    if not text or len(text) > 253:
        return False
    if text.startswith("ta") or text.startswith("t"):
        return False
    labels = [part for part in text.split(".") if part]
    if len(labels) < 2:
        return False
    if not all(re.fullmatch(r"[a-z0-9-]{1,63}", part) for part in labels):
        return False
    if any(part.startswith("-") or part.endswith("-") for part in labels):
        return False
    if not any(ch.isalpha() for ch in labels[-1]):
        return False
    return True


def _extract_evidence(item: dict[str, object]) -> list[str]:
    evidence = item.get("evidence")
    if isinstance(evidence, list):
        return [str(v) for v in evidence if str(v).strip()]
    if isinstance(evidence, str) and evidence.strip():
        return [evidence.strip()]
    details = str(item.get("details", "") or "").strip()
    if details:
        return [details]
    return []


def _extract_iocs(evidence: list[str]) -> list[str]:
    iocs: set[str] = set()
    for entry in evidence:
        for token in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", entry):
            parsed = _parse_ip(token)
            if parsed:
                iocs.add(parsed)
        for token in re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", entry):
            lowered = token.lower()
            if _looks_like_domain(lowered):
                iocs.add(lowered)
        for token in re.findall(r"\b[0-9a-fA-F]{32,64}\b", entry):
            iocs.add(token.lower())
    return sorted(iocs)


def _extract_artifacts(summary_text: str, details: str) -> list[str]:
    artifacts: set[str] = set()
    blob = f"{summary_text} {details}"
    for match in re.findall(
        r"\b[\w.-]+\.(?:exe|dll|ps1|bat|zip|7z|rar|docm|xlsm|csv|bin|pcap)\b",
        blob,
        re.IGNORECASE,
    ):
        artifacts.add(match)
    return sorted(artifacts)


def _extract_hosts_from_text(text: str) -> set[str]:
    hosts: set[str] = set()
    for ip_token in _IP_RE.findall(text):
        parsed = _parse_ip(ip_token)
        if parsed:
            hosts.add(parsed)
    for token in re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", text):
        lowered = token.lower()
        if _looks_like_domain(lowered):
            hosts.add(lowered)
    return hosts


def _extract_detection_times(
    item: dict[str, object],
    fallback_first: Optional[float],
    fallback_last: Optional[float],
) -> tuple[Optional[float], Optional[float]]:
    hit_first = item.get("first_seen")
    hit_last = item.get("last_seen")
    ts = item.get("ts")
    time_val = item.get("time")

    parsed_first = None
    parsed_last = None
    for value in (hit_first, ts, time_val):
        parsed = None
        try:
            parsed = float(value) if value is not None else None
        except Exception:
            parsed = None
        if parsed is not None:
            parsed_first = parsed
            break
    for value in (hit_last, ts, time_val):
        parsed = None
        try:
            parsed = float(value) if value is not None else None
        except Exception:
            parsed = None
        if parsed is not None:
            parsed_last = parsed
            break

    if parsed_first is None:
        parsed_first = fallback_first
    if parsed_last is None:
        parsed_last = fallback_last
    return parsed_first, parsed_last


def _mapping_gate(
    rule: _TechniqueRule | None,
    rule_score: int,
    tactic_ids: list[str],
    technique_ids: list[str],
    evidence: list[str],
    matched_keywords: list[str],
    confidence: str,
) -> tuple[bool, str]:
    if tactic_ids or technique_ids:
        return True, "explicit ATT&CK ID present"
    if rule is None:
        return False, "no matching ATT&CK rule"
    if rule_score < rule.min_score:
        return False, f"rule score below threshold ({rule_score}<{rule.min_score})"
    if len(matched_keywords) < max(1, rule.min_keyword_hits):
        return False, "insufficient keyword evidence"
    if not evidence and confidence == "low":
        return False, "low confidence without evidence"
    return True, "keyword/context threshold satisfied"


def _collect_provenance(
    item: dict[str, object], evidence: list[str]
) -> tuple[list[str], list[str], list[str]]:
    packet_refs: set[str] = set()
    flow_refs: set[str] = set()
    host_refs: set[str] = set()

    src = str(item.get("src", "") or "").strip()
    dst = str(item.get("dst", "") or "").strip()
    proto = str(item.get("proto", "") or item.get("protocol", "") or "").strip().upper()

    packet_value = item.get("packet")
    if isinstance(packet_value, int):
        packet_refs.add(str(packet_value))

    if src:
        host_refs.add(src)
    if dst:
        host_refs.add(dst)
    if src and dst:
        flow_refs.add(f"{src}->{dst}" + (f" {proto}" if proto else ""))

    for entry in evidence:
        for packet_match in _PACKET_RE.findall(entry):
            packet_refs.add(packet_match)
        for host in _extract_hosts_from_text(entry):
            host_refs.add(host)
        src_match = re.search(r"\bsrc\s*=\s*([^\s,]+)", entry, re.IGNORECASE)
        dst_match = re.search(r"\bdst\s*=\s*([^\s,]+)", entry, re.IGNORECASE)
        proto_match = re.search(r"\bproto\s*=\s*([^\s,]+)", entry, re.IGNORECASE)
        src_val = src_match.group(1) if src_match else ""
        dst_val = dst_match.group(1) if dst_match else ""
        proto_val = proto_match.group(1).upper() if proto_match else ""
        if src_val and dst_val:
            flow_refs.add(
                f"{src_val}->{dst_val}" + (f" {proto_val}" if proto_val else "")
            )

    return sorted(packet_refs), sorted(flow_refs), sorted(host_refs)


def _tactic_stage_index(framework: str, tactic: str) -> int:
    if framework == "ics":
        return _ICS_TACTIC_ORDER.get(tactic, 99)
    return _ENTERPRISE_TACTIC_ORDER.get(tactic, 99)


def _host_role_from_hit(hit: MitreHit) -> str:
    tactic = hit.tactic
    if tactic in {"Reconnaissance", "Discovery"}:
        return "recon"
    if tactic in {"Credential Access"}:
        return "credential"
    if tactic in {"Lateral Movement"}:
        return "pivot"
    if tactic in {"Command and Control"}:
        return "c2"
    if tactic in {"Exfiltration"}:
        return "exfil"
    if tactic in {"Impair Process Control", "Inhibit Response Function", "Impact"}:
        return "impact"
    return "other"


def _confidence_rank(confidence: str) -> int:
    if confidence == "high":
        return 3
    if confidence == "medium":
        return 2
    return 1


def _confidence_text(rank: int) -> str:
    if rank >= 3:
        return "high"
    if rank == 2:
        return "medium"
    return "low"


def _executive_assessment(
    total_detections: int,
    hits: list[MitreHit],
    sequence_issues: list[str],
) -> tuple[str, str, list[str]]:
    reasons: list[str] = []
    score = 0

    mapped_ratio = len(hits) / max(total_detections, 1)
    if mapped_ratio >= 0.6:
        score += 2
        reasons.append(f"High ATT&CK mapping coverage ({mapped_ratio * 100.0:.1f}%)")
    elif mapped_ratio >= 0.3:
        score += 1
        reasons.append(
            f"Moderate ATT&CK mapping coverage ({mapped_ratio * 100.0:.1f}%)"
        )

    high_conf_hits = sum(1 for hit in hits if hit.confidence == "high")
    if high_conf_hits >= 3:
        score += 2
        reasons.append(f"Multiple high-confidence TTPs ({high_conf_hits})")
    elif high_conf_hits:
        score += 1
        reasons.append(f"At least one high-confidence TTP ({high_conf_hits})")

    corroborated_hits = sum(1 for hit in hits if hit.corroborating_sources >= 2)
    if corroborated_hits >= 2:
        score += 2
        reasons.append(f"Cross-source corroboration on {corroborated_hits} TTPs")
    elif corroborated_hits:
        score += 1
        reasons.append("Limited cross-source corroboration present")

    if sequence_issues:
        score -= 1
        reasons.append(f"Sequence plausibility issues present ({len(sequence_issues)})")

    if score >= 5:
        return "LIKELY INTRUSION", "high", reasons
    if score >= 3:
        return "POSSIBLE INTRUSION", "medium", reasons
    return (
        "LOW-CONFIDENCE SIGNAL",
        "low",
        reasons if reasons else ["Insufficient corroboration"],
    )


def _fallback_from_explicit_ids(
    tactic_ids: list[str],
    technique_ids: list[str],
    framework: str,
    summary_text: str,
) -> tuple[str, str, str, str] | None:
    if not tactic_ids and not technique_ids:
        return None
    tactic_id = (
        tactic_ids[0] if tactic_ids else ("TA0108" if framework == "ics" else "TA0007")
    )
    technique_id = (
        technique_ids[0]
        if technique_ids
        else ("T0885" if framework == "ics" else "T1046")
    )
    tactic = "Mapped Tactic"
    technique = "Mapped Technique"
    for rule in _RULES:
        if rule.tactic_id == tactic_id:
            tactic = rule.tactic
            break
    for rule in _RULES:
        if rule.technique_id == technique_id:
            technique = rule.technique
            break
    if tactic == "Mapped Tactic" and framework == "ics":
        tactic = "ICS ATT&CK"
    if tactic == "Mapped Tactic" and framework != "ics":
        tactic = "Enterprise ATT&CK"
    if technique == "Mapped Technique":
        technique = summary_text[:100] if summary_text else "Technique Heuristic"
    return tactic, tactic_id, technique, technique_id


def merge_mitre_summaries(summaries: list[MitreSummary]) -> MitreSummary:
    if not summaries:
        return MitreSummary(
            path=Path("ALL_PCAPS"), total_detections=0, mapped_detections=0
        )

    tactic_counts: Counter[str] = Counter()
    technique_counts: Counter[str] = Counter()
    procedure_counts: Counter[str] = Counter()
    framework_counts: Counter[str] = Counter()
    ioc_counts: Counter[str] = Counter()
    artifact_counts: Counter[str] = Counter()
    attack_path: list[str] = []
    hits: list[MitreHit] = []
    errors: list[str] = []
    sequence_issues: list[str] = []
    alternate_explanations: list[str] = []
    host_attack_paths: dict[str, list[str]] = defaultdict(list)
    host_roles: dict[str, set[str]] = defaultdict(set)
    technique_heat_rows: list[dict[str, object]] = []
    investigation_pivots: list[dict[str, object]] = []
    merged_checks: dict[str, list[str]] = defaultdict(list)

    total_detections = 0
    mapped_detections = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    for summary in summaries:
        total_detections += int(summary.total_detections)
        mapped_detections += int(summary.mapped_detections)
        tactic_counts.update(summary.tactic_counts)
        technique_counts.update(summary.technique_counts)
        procedure_counts.update(summary.procedure_counts)
        framework_counts.update(summary.framework_counts)
        ioc_counts.update(summary.ioc_counts)
        artifact_counts.update(summary.artifact_counts)
        attack_path.extend(summary.attack_path)
        hits.extend(summary.hits)
        errors.extend(summary.errors)
        sequence_issues.extend(summary.sequence_issues)
        alternate_explanations.extend(summary.alternate_explanations)
        technique_heat_rows.extend(summary.technique_heat)
        investigation_pivots.extend(summary.investigation_pivots)
        for host, chain in summary.host_attack_paths.items():
            host_attack_paths[host].extend(chain)
        for host, roles in summary.host_roles.items():
            for role in roles:
                host_roles[host].add(role)
        for key, values in summary.checks.items():
            for value in values:
                merged_checks[key].append(value)
        if summary.first_seen is not None:
            first_seen = (
                summary.first_seen
                if first_seen is None
                else min(first_seen, summary.first_seen)
            )
        if summary.last_seen is not None:
            last_seen = (
                summary.last_seen
                if last_seen is None
                else max(last_seen, summary.last_seen)
            )

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    executive_verdict, executive_confidence, executive_reasons = _executive_assessment(
        total_detections,
        hits,
        sequence_issues,
    )

    dedup_checks: dict[str, list[str]] = {}
    for key, values in merged_checks.items():
        seen: set[str] = set()
        deduped: list[str] = []
        for value in values:
            text = str(value)
            if text in seen:
                continue
            seen.add(text)
            deduped.append(text)
            if len(deduped) >= 80:
                break
        dedup_checks[key] = deduped

    return MitreSummary(
        path=Path("ALL_PCAPS"),
        total_detections=total_detections,
        mapped_detections=mapped_detections,
        tactic_counts=tactic_counts,
        technique_counts=technique_counts,
        procedure_counts=procedure_counts,
        framework_counts=framework_counts,
        ioc_counts=ioc_counts,
        artifact_counts=artifact_counts,
        attack_path=attack_path,
        hits=hits,
        errors=sorted(set(errors)),
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
        executive_verdict=executive_verdict,
        executive_confidence=executive_confidence,
        executive_reasons=executive_reasons,
        sequence_issues=sorted(set(sequence_issues)),
        alternate_explanations=sorted(set(alternate_explanations))[:40],
        host_attack_paths={
            key: value[:120]
            for key, value in sorted(
                host_attack_paths.items(), key=lambda item: item[0]
            )
        },
        host_roles={
            key: sorted(value)
            for key, value in sorted(host_roles.items(), key=lambda item: item[0])
        },
        technique_heat=technique_heat_rows[:300],
        investigation_pivots=investigation_pivots[:300],
        checks=dedup_checks,
    )


def analyze_mitre(
    path: Path,
    show_status: bool = True,
    ioc_file: Path | None = None,
    threat_summary=None,
) -> MitreSummary:
    if threat_summary is None:
        threat_summary = analyze_threats(path, show_status=show_status)

    ioc_summary = None
    ioc_errors: list[str] = []
    if ioc_file:
        try:
            ioc_summary = analyze_iocs(path, ioc_file, show_status=show_status)
        except Exception as exc:
            ioc_errors.append(f"IOC mapping unavailable: {type(exc).__name__}: {exc}")

    tactic_counts: Counter[str] = Counter()
    technique_counts: Counter[str] = Counter()
    procedure_counts: Counter[str] = Counter()
    framework_counts: Counter[str] = Counter()
    ioc_counts: Counter[str] = Counter()
    artifact_counts: Counter[str] = Counter()
    attack_path: list[str] = []
    hits: list[MitreHit] = []
    checks: dict[str, list[str]] = {
        "cross_signal_corroboration": [],
        "sequence_plausibility": [],
        "ics_process_impact": [],
        "host_boundary_activity": [],
    }
    sequence_issues: list[str] = []
    alternate_explanations: list[str] = []
    gate_reason_by_occurrence: dict[int, str] = {}

    previous_node = "Initial Access"

    for idx, item in enumerate(threat_summary.detections, start=1):
        summary_text = str(item.get("summary", "") or "").strip()
        details = str(item.get("details", "") or "").strip()
        if not summary_text and not details:
            continue

        blob = f"{summary_text} {details}".lower()
        tactic_ids, technique_ids = _extract_explicit_ids(blob)
        rule, rule_score = _rule_from_text(blob)
        framework = _infer_framework(blob)

        if rule:
            framework = rule.framework
            tactic = rule.tactic
            tactic_id = rule.tactic_id
            technique = rule.technique
            technique_id = rule.technique_id
        else:
            fallback = _fallback_from_explicit_ids(
                tactic_ids,
                technique_ids,
                framework,
                summary_text,
            )
            if fallback is None:
                checks["sequence_plausibility"].append(
                    f"Detection {idx} left unmapped: no ATT&CK IDs and no high-confidence keyword rule"
                )
                continue
            tactic, tactic_id, technique, technique_id = fallback

        matched_keywords = _matched_keywords(rule, blob)
        evidence = _extract_evidence(item)
        iocs = _extract_iocs(evidence)
        artifacts = _extract_artifacts(summary_text, details)
        packet_refs, flow_refs, host_refs = _collect_provenance(item, evidence)

        confidence = _normalize_confidence(item.get("confidence"))
        allowed, gate_reason = _mapping_gate(
            rule,
            rule_score,
            tactic_ids,
            technique_ids,
            evidence,
            matched_keywords,
            confidence,
        )
        if not allowed:
            checks["sequence_plausibility"].append(
                f"Detection {idx} left unmapped: {gate_reason}"
            )
            continue
        gate_reason_by_occurrence[idx] = gate_reason

        hit_first, hit_last = _extract_detection_times(
            item,
            threat_summary.first_seen,
            threat_summary.last_seen,
        )

        contradictory_signals: list[str] = []

        if framework == "ics" and tactic in {
            "Impair Process Control",
            "Inhibit Response Function",
            "Impact",
        }:
            checks["ics_process_impact"].append(
                f"Potential process/safety impact from {technique_id} at occurrence {idx}"
            )

        if len(host_refs) >= 2:
            checks["host_boundary_activity"].append(
                f"Multi-host evidence for {technique_id}: {', '.join(host_refs[:4])}"
            )

        hit = MitreHit(
            framework=framework,
            tactic=tactic,
            tactic_id=tactic_id,
            technique=technique,
            technique_id=technique_id,
            procedure=summary_text or "Detection Procedure",
            source=str(item.get("source", "threats") or "threats"),
            severity=str(item.get("severity", "info") or "info").lower(),
            confidence=confidence,
            details=details,
            evidence=evidence,
            artifacts=artifacts,
            iocs=iocs,
            first_seen=hit_first,
            last_seen=hit_last,
            occurrence=idx,
            matched_keywords=matched_keywords,
            contradictory_signals=contradictory_signals,
            packet_refs=packet_refs,
            flow_refs=flow_refs,
            host_refs=host_refs,
        )
        hits.append(hit)

        tactic_counts[f"{tactic} ({tactic_id})"] += 1
        technique_counts[f"{technique} ({technique_id})"] += 1
        procedure_counts[hit.procedure] += 1
        framework_counts[framework] += 1
        for value in iocs:
            ioc_counts[value] += 1
        for value in artifacts:
            artifact_counts[value] += 1

    if hits:
        source_by_technique: dict[str, set[str]] = defaultdict(set)
        for hit in hits:
            source_by_technique[hit.technique_id].add(hit.source)

        enriched_hits: list[MitreHit] = []
        for hit in hits:
            corroborating_sources = len(
                source_by_technique.get(hit.technique_id, set())
            )
            contradictions = list(hit.contradictory_signals)
            if hit.confidence == "high" and corroborating_sources < 2:
                contradictions.append("High confidence without source corroboration")

            if corroborating_sources >= 2:
                checks["cross_signal_corroboration"].append(
                    f"{hit.technique_id} corroborated by {corroborating_sources} sources"
                )

            rationale_parts = [
                f"Technique mapped via {'keyword' if hit.matched_keywords else 'fallback'} logic",
                f"keywords={','.join(hit.matched_keywords[:5]) or '-'}",
                f"evidence_items={len(hit.evidence)}",
                f"sources_for_technique={corroborating_sources}",
                f"mapping_gate={gate_reason_by_occurrence.get(hit.occurrence, '-')}",
            ]
            if contradictions:
                rationale_parts.append("contradictions=" + ",".join(contradictions[:3]))

            enriched_hits.append(
                MitreHit(
                    framework=hit.framework,
                    tactic=hit.tactic,
                    tactic_id=hit.tactic_id,
                    technique=hit.technique,
                    technique_id=hit.technique_id,
                    procedure=hit.procedure,
                    source=hit.source,
                    severity=hit.severity,
                    confidence=hit.confidence,
                    details=hit.details,
                    evidence=hit.evidence,
                    artifacts=hit.artifacts,
                    iocs=hit.iocs,
                    first_seen=hit.first_seen,
                    last_seen=hit.last_seen,
                    occurrence=hit.occurrence,
                    matched_keywords=hit.matched_keywords,
                    corroborating_sources=corroborating_sources,
                    contradictory_signals=contradictions,
                    packet_refs=hit.packet_refs,
                    flow_refs=hit.flow_refs,
                    host_refs=hit.host_refs,
                    rationale="; ".join(rationale_parts),
                )
            )
        hits = enriched_hits

    hits_sorted = sorted(
        hits,
        key=lambda item: (
            item.first_seen is None,
            item.first_seen if item.first_seen is not None else 0.0,
            item.occurrence,
        ),
    )
    host_attack_paths: dict[str, list[str]] = defaultdict(list)
    host_roles: dict[str, set[str]] = defaultdict(set)
    stage_by_host: dict[str, int] = defaultdict(int)
    for hit in hits_sorted:
        node = f"{hit.tactic} [{hit.technique_id}]"
        hosts = hit.host_refs[:8] if hit.host_refs else ["GLOBAL"]
        for host in hosts:
            stage_index = _tactic_stage_index(hit.framework, hit.tactic)
            prev = stage_by_host.get(host, 0)
            if stage_index < prev:
                msg = (
                    f"Host {host} sequence regression: {hit.tactic}({stage_index}) "
                    f"after stage {prev}"
                )
                sequence_issues.append(msg)
                checks["sequence_plausibility"].append(msg)
            stage_by_host[host] = max(prev, stage_index)
            host_attack_paths[host].append(node)
            host_roles[host].add(_host_role_from_hit(hit))
            if previous_node != node:
                attack_path.append(f"{previous_node} -> {node}")
                previous_node = node

    technique_rollup: dict[str, dict[str, object]] = {}
    for hit in hits:
        row = technique_rollup.setdefault(
            hit.technique_id,
            {
                "framework": hit.framework,
                "tactic": hit.tactic,
                "technique": hit.technique,
                "technique_id": hit.technique_id,
                "count": 0,
                "hosts": set(),
                "evidence_count": 0,
                "sources": set(),
                "first_seen": hit.first_seen,
                "last_seen": hit.last_seen,
                "confidence_rank": 0,
            },
        )
        row["count"] = int(row.get("count", 0) or 0) + 1
        row["evidence_count"] = int(row.get("evidence_count", 0) or 0) + len(
            hit.evidence
        )
        hosts = row.get("hosts")
        if isinstance(hosts, set):
            for host in hit.host_refs:
                hosts.add(host)
        sources = row.get("sources")
        if isinstance(sources, set):
            sources.add(hit.source)
        first_seen = row.get("first_seen")
        last_seen = row.get("last_seen")
        if isinstance(hit.first_seen, (int, float)):
            if first_seen is None or hit.first_seen < first_seen:
                row["first_seen"] = hit.first_seen
        if isinstance(hit.last_seen, (int, float)):
            if last_seen is None or hit.last_seen > last_seen:
                row["last_seen"] = hit.last_seen
        row["confidence_rank"] = max(
            int(row.get("confidence_rank", 0) or 0), _confidence_rank(hit.confidence)
        )

    technique_heat: list[dict[str, object]] = []
    for row in technique_rollup.values():
        hosts = row.get("hosts")
        sources = row.get("sources")
        host_count = len(hosts) if isinstance(hosts, set) else 0
        source_count = len(sources) if isinstance(sources, set) else 0
        technique_heat.append(
            {
                "framework": str(row.get("framework", "enterprise")),
                "tactic": str(row.get("tactic", "-")),
                "technique": str(row.get("technique", "-")),
                "technique_id": str(row.get("technique_id", "-")),
                "count": int(row.get("count", 0) or 0),
                "host_count": host_count,
                "source_count": source_count,
                "evidence_count": int(row.get("evidence_count", 0) or 0),
                "first_seen": row.get("first_seen"),
                "last_seen": row.get("last_seen"),
                "confidence": _confidence_text(int(row.get("confidence_rank", 0) or 0)),
            }
        )
    technique_heat.sort(
        key=lambda item: (
            int(item.get("count", 0) or 0),
            int(item.get("host_count", 0) or 0),
            int(item.get("source_count", 0) or 0),
        ),
        reverse=True,
    )

    investigation_pivots: list[dict[str, object]] = []
    for hit in hits[:200]:
        investigation_pivots.append(
            {
                "technique_id": hit.technique_id,
                "tactic": hit.tactic,
                "source": hit.source,
                "hosts": hit.host_refs[:6],
                "flows": hit.flow_refs[:4],
                "packets": hit.packet_refs[:6],
                "iocs": hit.iocs[:6],
                "artifacts": hit.artifacts[:6],
            }
        )

    low_conf_count = sum(1 for hit in hits if hit.confidence == "low")
    single_source_count = sum(1 for hit in hits if hit.corroborating_sources <= 1)
    if low_conf_count >= 3:
        alternate_explanations.append(
            "Multiple low-confidence mappings could reflect noisy scanning or baseline variability."
        )
    if single_source_count >= 3:
        alternate_explanations.append(
            "Several mappings are single-source and should be corroborated with endpoint or IDS telemetry."
        )
    if not sequence_issues:
        alternate_explanations.append(
            "No ATT&CK sequence order regression was detected in this capture."
        )

    if ioc_summary is not None:
        for value, count in ioc_summary.ip_hits.items():
            ioc_counts[value] += int(count)
        for value, count in ioc_summary.domain_hits.items():
            ioc_counts[value] += int(count)
        for value, count in ioc_summary.hash_hits.items():
            ioc_counts[value] += int(count)
        for value, count in ioc_summary.mitre_counts.items():
            technique_counts[f"IOC: {value}"] += int(count)

    duration_seconds = None
    if threat_summary.first_seen is not None and threat_summary.last_seen is not None:
        duration_seconds = max(
            0.0, threat_summary.last_seen - threat_summary.first_seen
        )

    executive_verdict, executive_confidence, executive_reasons = _executive_assessment(
        len(threat_summary.detections),
        hits,
        sequence_issues,
    )

    all_errors = (
        list(threat_summary.errors)
        + list(ioc_errors)
        + (list(ioc_summary.errors) if ioc_summary else [])
    )
    if _MAPPING_METADATA_ERROR:
        all_errors.append(_MAPPING_METADATA_ERROR)

    return MitreSummary(
        path=path,
        total_detections=len(threat_summary.detections),
        mapped_detections=len(hits),
        tactic_counts=tactic_counts,
        technique_counts=technique_counts,
        procedure_counts=procedure_counts,
        framework_counts=framework_counts,
        ioc_counts=ioc_counts,
        artifact_counts=artifact_counts,
        attack_path=attack_path,
        hits=hits,
        errors=all_errors,
        first_seen=threat_summary.first_seen,
        last_seen=threat_summary.last_seen,
        duration_seconds=duration_seconds,
        executive_verdict=executive_verdict,
        executive_confidence=executive_confidence,
        executive_reasons=executive_reasons,
        sequence_issues=sequence_issues,
        alternate_explanations=alternate_explanations,
        host_attack_paths={
            key: value[:120]
            for key, value in sorted(
                host_attack_paths.items(), key=lambda item: item[0]
            )
        },
        host_roles={
            key: sorted(value)
            for key, value in sorted(host_roles.items(), key=lambda item: item[0])
        },
        technique_heat=technique_heat,
        investigation_pivots=investigation_pivots,
        checks={key: values[:80] for key, values in checks.items()},
    )
