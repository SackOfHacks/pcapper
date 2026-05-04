from __future__ import annotations

import ipaddress
import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

try:
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.packet import Packet, Raw
except Exception:  # pragma: no cover
    IP = TCP = UDP = Raw = None  # type: ignore

from .pcap_cache import get_reader
from .utils import extract_packet_endpoints

SUSPICIOUS_PATTERNS = [
    (re.compile(r"password\s*[:=]", re.IGNORECASE), "Credential exposure"),
    (re.compile(r"passwd\s*[:=]", re.IGNORECASE), "Credential exposure"),
    (re.compile(r"api[_-]?key\s*[:=]", re.IGNORECASE), "API key exposure"),
    (re.compile(r"secret\s*[:=]", re.IGNORECASE), "Secret exposure"),
    (re.compile(r"authorization:\s*bearer\s+", re.IGNORECASE), "Bearer token"),
    (re.compile(r"token\s*[:=]", re.IGNORECASE), "Token exposure"),
    (
        re.compile(r"BEGIN (RSA|EC|DSA) PRIVATE KEY", re.IGNORECASE),
        "Private key material",
    ),
    (re.compile(r"ssh-rsa|ssh-ed25519", re.IGNORECASE), "SSH key material"),
    (
        re.compile(r"/bin/(sh|bash)|cmd\.exe|powershell", re.IGNORECASE),
        "Command execution",
    ),
    (re.compile(r"curl\s+http|wget\s+http", re.IGNORECASE), "Download/exfil tooling"),
    (re.compile(r"^GET\s+|^POST\s+|^PUT\s+", re.IGNORECASE), "HTTP request"),
]

URL_PATTERN = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
DOMAIN_PATTERN = re.compile(r"\b([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\b")
FLAG_PATTERN = re.compile(r"\b(?:flag|ctf|picoctf)\{[^}]{1,220}\}", re.IGNORECASE)
BASE64_LONG_PATTERN = re.compile(r"\b(?:[A-Za-z0-9+/]{40,}={0,2})\b")
HEX_BLOB_PATTERN = re.compile(r"\b(?:0x)?[A-Fa-f0-9]{32,}\b")
JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9._-]{8,}\.[A-Za-z0-9._-]{8,}\b"
)
AWS_KEY_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
NTLM_HASH_PATTERN = re.compile(r"\b[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}\b")
PRIVATE_KEY_PATTERN = re.compile(
    r"BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY", re.IGNORECASE
)
CRED_USER_PATTERN = re.compile(
    r"\b(?:user(?:name)?|login|uid|account)\s*[:=]\s*([^\s;,&]{1,128})", re.IGNORECASE
)
CRED_PASS_PATTERN = re.compile(
    r"\b(?:password|passwd|pass|pwd)\s*[:=]\s*([^\s;,&]{1,128})", re.IGNORECASE
)
EXFIL_PATTERN = re.compile(
    r"\b(?:multipart/form-data|content-disposition:\s*attachment|/upload|/exfil|/dump|ftp put|stor\s+|scp\s+)\b",
    re.IGNORECASE,
)
C2_PATTERN = re.compile(
    r"\b(?:beacon|callback|c2|cnc|reverse[_ -]?shell|meterpreter|powershell\s+-enc|scheduledtask|schtasks)\b",
    re.IGNORECASE,
)
LOL_PATTERN = re.compile(
    r"\b(?:powershell(?:\.exe)?|cmd(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|mshta(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|certutil(?:\.exe)?|bitsadmin(?:\.exe)?)\b",
    re.IGNORECASE,
)
OT_WRITE_PATTERN = re.compile(
    r"\b(?:write\s+(?:single|multiple)\s+(?:coil|register)|function\s*(?:05|06|15|16)|programdownload|programupload|set_attribute|operate|select before operate|force)\b",
    re.IGNORECASE,
)
OT_PROTO_PATTERN = re.compile(
    r"\b(?:modbus|dnp3|iec[- ]?104|s7comm|siemens s7|bacnet|profinet|ethernet/ip|enip|cip|opc ua|mms|iec 61850|goose|sv)\b",
    re.IGNORECASE,
)
MALWARE_FILE_PATTERN = re.compile(
    r"\b[^\s]{1,120}\.(?:exe|dll|ps1|vbs|js|hta|bat|scr|lnk|jar)\b", re.IGNORECASE
)
try:
    MAX_PAYLOAD_SCAN = int(os.getenv("PCAPPER_STRINGS_MAX_BYTES", "16384"))
except Exception:
    MAX_PAYLOAD_SCAN = 16384
if MAX_PAYLOAD_SCAN < 0:
    MAX_PAYLOAD_SCAN = 0


@dataclass(frozen=True)
class StringArtifact:
    value: str
    count: int


@dataclass(frozen=True)
class StringsSummary:
    path: Path
    total_packets: int
    strings_found: int
    unique_strings: int
    top_strings: List[StringArtifact]
    bottom_strings: List[StringArtifact]
    suspicious_strings: List[StringArtifact]
    suspicious_details: List[Dict[str, object]]
    urls: List[StringArtifact]
    emails: List[StringArtifact]
    domains: List[StringArtifact]
    client_strings: Dict[str, List[StringArtifact]]
    server_strings: Dict[str, List[StringArtifact]]
    anomalies: List[str]
    deterministic_checks: Dict[str, List[str]]
    threat_hypotheses: List[Dict[str, object]]
    ot_findings: List[str]
    ctf_indicators: List[str]
    errors: List[str]


def _get_ip_pair(pkt: Packet) -> Tuple[str, str]:
    src_ip, dst_ip = extract_packet_endpoints(pkt)
    return src_ip or "0.0.0.0", dst_ip or "0.0.0.0"


def _extract_ascii_strings(
    data: bytes, min_len: int = 4, max_len: int = 200
) -> List[str]:
    results: List[str] = []
    current = bytearray()
    for b in data:
        if 32 <= b <= 126:
            current.append(b)
        else:
            if len(current) >= min_len:
                value = current.decode("latin-1", errors="ignore")
                results.append(value[:max_len])
            current = bytearray()
    if len(current) >= min_len:
        value = current.decode("latin-1", errors="ignore")
        results.append(value[:max_len])
    return results


def _extract_utf16le_strings(
    data: bytes, min_len: int = 4, max_len: int = 200
) -> List[str]:
    results: List[str] = []
    current = bytearray()
    i = 0
    while i + 1 < len(data):
        ch = data[i]
        if 32 <= ch <= 126 and data[i + 1] == 0x00:
            current.append(ch)
            i += 2
        else:
            if len(current) >= min_len:
                value = current.decode("latin-1", errors="ignore")
                results.append(value[:max_len])
            current = bytearray()
            i += 2
    if len(current) >= min_len:
        value = current.decode("latin-1", errors="ignore")
        results.append(value[:max_len])
    return results


def _match_suspicious(value: str) -> Optional[str]:
    for pattern, reason in SUSPICIOUS_PATTERNS:
        if pattern.search(value):
            return reason
    return None


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return not (
            ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
        )
    except Exception:
        return False


def _append_check(
    checks: Dict[str, List[str]], key: str, evidence: str, max_items: int = 20
) -> None:
    bucket = checks.setdefault(key, [])
    if evidence in bucket:
        return
    if len(bucket) >= max_items:
        return
    bucket.append(evidence)


def analyze_strings(
    path: Path, show_status: bool = True, max_unique: int = 5000
) -> StringsSummary:
    if TCP is None:
        return StringsSummary(
            path=path,
            total_packets=0,
            strings_found=0,
            unique_strings=0,
            top_strings=[],
            bottom_strings=[],
            suspicious_strings=[],
            suspicious_details=[],
            urls=[],
            emails=[],
            domains=[],
            client_strings={},
            server_strings={},
            anomalies=["Scapy not available"],
            deterministic_checks={},
            threat_hypotheses=[],
            ot_findings=[],
            ctf_indicators=[],
            errors=[],
        )

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path, show_status=show_status
        )
    except Exception as e:
        return StringsSummary(
            path=path,
            total_packets=0,
            strings_found=0,
            unique_strings=0,
            top_strings=[],
            bottom_strings=[],
            suspicious_strings=[],
            suspicious_details=[],
            urls=[],
            emails=[],
            domains=[],
            client_strings={},
            server_strings={},
            anomalies=[f"Error opening pcap: {e}"],
            deterministic_checks={},
            threat_hypotheses=[],
            ot_findings=[],
            ctf_indicators=[],
            errors=[],
        )

    size_bytes = size_bytes

    total_packets = 0
    string_counter: Counter[str] = Counter()
    suspicious_counter: Counter[str] = Counter()
    suspicious_reasons: Dict[str, Set[str]] = defaultdict(set)
    suspicious_srcs: Dict[str, Counter[str]] = defaultdict(Counter)
    suspicious_dsts: Dict[str, Counter[str]] = defaultdict(Counter)
    url_counter: Counter[str] = Counter()
    email_counter: Counter[str] = Counter()
    domain_counter: Counter[str] = Counter()
    client_map: Dict[str, Counter[str]] = defaultdict(Counter)
    server_map: Dict[str, Counter[str]] = defaultdict(Counter)
    errors: List[str] = []

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            total_packets += 1
            payload = b""
            if Raw in pkt:
                payload = bytes(pkt[Raw])
            elif TCP in pkt or UDP in pkt:
                try:
                    payload = (
                        bytes(pkt[TCP].payload)
                        if TCP in pkt
                        else bytes(pkt[UDP].payload)
                    )
                except Exception:
                    payload = b""

            if not payload:
                continue
            if MAX_PAYLOAD_SCAN == 0:
                continue
            if len(payload) > MAX_PAYLOAD_SCAN:
                payload = payload[:MAX_PAYLOAD_SCAN]

            src, dst = _get_ip_pair(pkt)

            for value in _extract_ascii_strings(payload) + _extract_utf16le_strings(
                payload
            ):
                if not value:
                    continue
                if len(string_counter) < max_unique or value in string_counter:
                    string_counter[value] += 1
                    client_map[src][value] += 1
                    server_map[dst][value] += 1

                reason = _match_suspicious(value)
                if reason:
                    suspicious_counter[value] += 1
                    suspicious_reasons[value].add(reason)
                    suspicious_srcs[value][src] += 1
                    suspicious_dsts[value][dst] += 1

                for url in URL_PATTERN.findall(value):
                    url_counter[url] += 1
                for email in EMAIL_PATTERN.findall(value):
                    email_counter[email] += 1
                for domain in DOMAIN_PATTERN.findall(value):
                    domain_counter[domain] += 1

    except Exception as e:
        errors.append(str(e))
    finally:
        status.finish()
        reader.close()

    anomalies: List[str] = []
    if suspicious_counter:
        anomalies.append("Suspicious string indicators detected.")
    if any(key.lower().startswith("bearer ") for key in string_counter.keys()):
        anomalies.append("Bearer tokens observed in cleartext.")

    def _top_artifacts(counter: Counter[str], limit: int = 15) -> List[StringArtifact]:
        return [StringArtifact(value=k, count=v) for k, v in counter.most_common(limit)]

    def _bottom_artifacts(
        counter: Counter[str], limit: int = 15
    ) -> List[StringArtifact]:
        items = sorted(counter.items(), key=lambda kv: (kv[1], kv[0]))[:limit]
        return [StringArtifact(value=k, count=v) for k, v in items]

    client_strings = {
        ip: _top_artifacts(counter, 8)
        for ip, counter in sorted(
            client_map.items(), key=lambda item: sum(item[1].values()), reverse=True
        )[:5]
    }
    server_strings = {
        ip: _top_artifacts(counter, 8)
        for ip, counter in sorted(
            server_map.items(), key=lambda item: sum(item[1].values()), reverse=True
        )[:5]
    }

    suspicious_details: List[Dict[str, object]] = []
    for value, count in suspicious_counter.most_common(20):
        reasons = sorted(suspicious_reasons.get(value, set()))
        top_src = suspicious_srcs.get(value, Counter()).most_common(3)
        top_dst = suspicious_dsts.get(value, Counter()).most_common(3)
        suspicious_details.append(
            {
                "value": value,
                "count": count,
                "reasons": reasons,
                "top_sources": top_src,
                "top_destinations": top_dst,
            }
        )

    for item in suspicious_details:
        reasons = ", ".join(item.get("reasons", [])) or "Unknown reason"
        top_src = (
            ", ".join(f"{ip}({count})" for ip, count in item.get("top_sources", []))
            or "-"
        )
        top_dst = (
            ", ".join(
                f"{ip}({count})" for ip, count in item.get("top_destinations", [])
            )
            or "-"
        )
        anomalies.append(
            f"Suspicious string: {item.get('value', '-')}; reason: {reasons}; src: {top_src}; dst: {top_dst}"
        )

    deterministic_checks: Dict[str, List[str]] = {
        "cleartext_credentials": [],
        "token_or_key_exposure": [],
        "private_key_material": [],
        "command_execution_or_lolbin": [],
        "download_stager_or_exfil": [],
        "c2_or_beacon_markers": [],
        "malware_or_payload_filenames": [],
        "ot_ics_protocol_markers": [],
        "ot_ics_control_write_ops": [],
        "ctf_flag_or_challenge_markers": [],
        "obfuscation_or_encoded_blobs": [],
        "external_ioc_indicators": [],
    }
    ot_findings: List[str] = []
    ctf_indicators: List[str] = []
    credential_user_counter: Counter[str] = Counter()
    credential_pass_counter: Counter[str] = Counter()

    for value, count in string_counter.items():
        text = str(value)
        lowered = text.lower()
        evidence = f"{text[:160]} (count={count})"

        user_match = CRED_USER_PATTERN.search(text)
        pass_match = CRED_PASS_PATTERN.search(text)
        if user_match or pass_match:
            _append_check(deterministic_checks, "cleartext_credentials", evidence)
            if user_match:
                credential_user_counter[user_match.group(1)] += count
            if pass_match:
                credential_pass_counter[pass_match.group(1)] += count
        if (
            AWS_KEY_PATTERN.search(text)
            or JWT_PATTERN.search(text)
            or NTLM_HASH_PATTERN.search(text)
        ):
            _append_check(deterministic_checks, "token_or_key_exposure", evidence)
        if PRIVATE_KEY_PATTERN.search(text):
            _append_check(deterministic_checks, "private_key_material", evidence)
        if (
            LOL_PATTERN.search(text)
            or "/bin/sh" in lowered
            or "powershell -enc" in lowered
        ):
            _append_check(deterministic_checks, "command_execution_or_lolbin", evidence)
        if EXFIL_PATTERN.search(text) or "http://" in lowered or "https://" in lowered:
            _append_check(deterministic_checks, "download_stager_or_exfil", evidence)
        if C2_PATTERN.search(text):
            _append_check(deterministic_checks, "c2_or_beacon_markers", evidence)
        if MALWARE_FILE_PATTERN.search(text):
            _append_check(
                deterministic_checks, "malware_or_payload_filenames", evidence
            )
        if OT_PROTO_PATTERN.search(text):
            _append_check(deterministic_checks, "ot_ics_protocol_markers", evidence)
            if len(ot_findings) < 20 and text not in ot_findings:
                ot_findings.append(text[:200])
        if OT_WRITE_PATTERN.search(text):
            _append_check(deterministic_checks, "ot_ics_control_write_ops", evidence)
        if FLAG_PATTERN.search(text):
            _append_check(
                deterministic_checks, "ctf_flag_or_challenge_markers", evidence
            )
            if len(ctf_indicators) < 20 and text not in ctf_indicators:
                ctf_indicators.append(text[:200])
        if BASE64_LONG_PATTERN.search(text) or HEX_BLOB_PATTERN.search(text):
            _append_check(
                deterministic_checks, "obfuscation_or_encoded_blobs", evidence
            )

    for url_item in url_counter:
        try:
            parsed = urlsplit(url_item)
            host = (parsed.hostname or "").strip()
            if host and _is_public_ip(host):
                _append_check(
                    deterministic_checks,
                    "external_ioc_indicators",
                    f"URL with public IP host: {url_item}",
                )
        except Exception:
            continue

    if credential_user_counter:
        top_users = ", ".join(
            f"{u}({c})" for u, c in credential_user_counter.most_common(5)
        )
        anomalies.append(f"Cleartext username markers discovered: {top_users}")
    if credential_pass_counter:
        top_pass = ", ".join(
            f"{p}({c})" for p, c in credential_pass_counter.most_common(5)
        )
        anomalies.append(f"Cleartext password markers discovered: {top_pass}")

    threat_hypotheses: List[Dict[str, Any]] = []
    if (
        deterministic_checks["cleartext_credentials"]
        and deterministic_checks["command_execution_or_lolbin"]
    ):
        threat_hypotheses.append(
            {
                "hypothesis": "Credential theft with possible post-auth command execution",
                "confidence": "high",
                "evidence_count": len(deterministic_checks["cleartext_credentials"])
                + len(deterministic_checks["command_execution_or_lolbin"]),
            }
        )
    if (
        deterministic_checks["download_stager_or_exfil"]
        and deterministic_checks["c2_or_beacon_markers"]
    ):
        threat_hypotheses.append(
            {
                "hypothesis": "Potential staged malware delivery or callback activity",
                "confidence": "medium",
                "evidence_count": len(deterministic_checks["download_stager_or_exfil"])
                + len(deterministic_checks["c2_or_beacon_markers"]),
            }
        )
    if (
        deterministic_checks["ot_ics_protocol_markers"]
        and deterministic_checks["ot_ics_control_write_ops"]
    ):
        threat_hypotheses.append(
            {
                "hypothesis": "OT/ICS control-plane write/programming activity observed",
                "confidence": "high",
                "evidence_count": len(deterministic_checks["ot_ics_protocol_markers"])
                + len(deterministic_checks["ot_ics_control_write_ops"]),
            }
        )
    if deterministic_checks["ctf_flag_or_challenge_markers"]:
        threat_hypotheses.append(
            {
                "hypothesis": "CTF flag/challenge markers present in cleartext strings",
                "confidence": "medium",
                "evidence_count": len(
                    deterministic_checks["ctf_flag_or_challenge_markers"]
                ),
            }
        )

    return StringsSummary(
        path=path,
        total_packets=total_packets,
        strings_found=sum(string_counter.values()),
        unique_strings=len(string_counter),
        top_strings=_top_artifacts(string_counter, 20),
        bottom_strings=_bottom_artifacts(string_counter, 20),
        suspicious_strings=_top_artifacts(suspicious_counter, 20),
        suspicious_details=suspicious_details,
        urls=_top_artifacts(url_counter, 15),
        emails=_top_artifacts(email_counter, 15),
        domains=_top_artifacts(domain_counter, 15),
        client_strings=client_strings,
        server_strings=server_strings,
        anomalies=anomalies,
        deterministic_checks=deterministic_checks,
        threat_hypotheses=threat_hypotheses,
        ot_findings=ot_findings,
        ctf_indicators=ctf_indicators,
        errors=errors,
    )


def merge_strings_summaries(summaries: List[StringsSummary]) -> StringsSummary:
    if not summaries:
        return StringsSummary(
            path=Path("ALL_PCAPS"),
            total_packets=0,
            strings_found=0,
            unique_strings=0,
            top_strings=[],
            bottom_strings=[],
            suspicious_strings=[],
            suspicious_details=[],
            urls=[],
            emails=[],
            domains=[],
            client_strings={},
            server_strings={},
            anomalies=[],
            deterministic_checks={},
            threat_hypotheses=[],
            ot_findings=[],
            ctf_indicators=[],
            errors=[],
        )

    def _counter_from_artifacts(items: List[StringArtifact]) -> Counter[str]:
        counter: Counter[str] = Counter()
        for item in items:
            counter[item.value] += int(item.count)
        return counter

    def _to_artifacts(counter: Counter[str], limit: int) -> List[StringArtifact]:
        return [StringArtifact(value=k, count=v) for k, v in counter.most_common(limit)]

    total_packets = sum(item.total_packets for item in summaries)
    strings_found = sum(item.strings_found for item in summaries)
    unique_strings = sum(item.unique_strings for item in summaries)

    top_counter: Counter[str] = Counter()
    bottom_counter: Counter[str] = Counter()
    suspicious_counter: Counter[str] = Counter()
    url_counter: Counter[str] = Counter()
    email_counter: Counter[str] = Counter()
    domain_counter: Counter[str] = Counter()
    client_counters: Dict[str, Counter[str]] = defaultdict(Counter)
    server_counters: Dict[str, Counter[str]] = defaultdict(Counter)

    detail_map: Dict[str, Dict[str, object]] = {}
    anomalies: List[str] = []
    seen_anomalies: Set[str] = set()
    deterministic_checks: Dict[str, List[str]] = {}
    threat_rollup: Dict[str, Dict[str, object]] = {}
    ot_findings: List[str] = []
    seen_ot: Set[str] = set()
    ctf_indicators: List[str] = []
    seen_ctf: Set[str] = set()
    errors: List[str] = []

    confidence_rank = {"low": 1, "medium": 2, "high": 3}

    for summary in summaries:
        top_counter.update(_counter_from_artifacts(summary.top_strings))
        bottom_counter.update(_counter_from_artifacts(summary.bottom_strings))
        suspicious_counter.update(_counter_from_artifacts(summary.suspicious_strings))
        url_counter.update(_counter_from_artifacts(summary.urls))
        email_counter.update(_counter_from_artifacts(summary.emails))
        domain_counter.update(_counter_from_artifacts(summary.domains))

        for ip, items in summary.client_strings.items():
            client_counters[ip].update(_counter_from_artifacts(items))
        for ip, items in summary.server_strings.items():
            server_counters[ip].update(_counter_from_artifacts(items))

        for item in summary.suspicious_details:
            value = str(item.get("value", ""))
            if not value:
                continue
            bucket = detail_map.setdefault(
                value,
                {
                    "value": value,
                    "count": 0,
                    "reasons": set(),
                    "top_sources": Counter(),
                    "top_destinations": Counter(),
                },
            )
            bucket["count"] = int(bucket.get("count", 0)) + int(item.get("count", 0))
            reasons = item.get("reasons", []) or []
            if isinstance(reasons, list):
                cast_reasons = bucket.get("reasons")
                if isinstance(cast_reasons, set):
                    cast_reasons.update(str(r) for r in reasons if str(r).strip())

            src_counter = bucket.get("top_sources")
            if isinstance(src_counter, Counter):
                for src, count in item.get("top_sources", []) or []:
                    src_counter[str(src)] += int(count)

            dst_counter = bucket.get("top_destinations")
            if isinstance(dst_counter, Counter):
                for dst, count in item.get("top_destinations", []) or []:
                    dst_counter[str(dst)] += int(count)

        for text in summary.anomalies:
            value = str(text)
            if value not in seen_anomalies:
                seen_anomalies.add(value)
                anomalies.append(value)

        for key, evidence_list in summary.deterministic_checks.items():
            bucket = deterministic_checks.setdefault(key, [])
            for evidence in evidence_list:
                if evidence not in bucket:
                    bucket.append(evidence)

        for hypothesis in summary.threat_hypotheses:
            name = str(hypothesis.get("hypothesis", "")).strip()
            if not name:
                continue
            existing = threat_rollup.get(name)
            current_conf = str(hypothesis.get("confidence", "medium")).lower()
            current_count = int(hypothesis.get("evidence_count", 0) or 0)
            if existing is None:
                threat_rollup[name] = {
                    "hypothesis": name,
                    "confidence": current_conf,
                    "evidence_count": current_count,
                }
                continue
            existing["evidence_count"] = int(existing.get("evidence_count", 0)) + current_count
            prev_conf = str(existing.get("confidence", "medium")).lower()
            if confidence_rank.get(current_conf, 2) > confidence_rank.get(prev_conf, 2):
                existing["confidence"] = current_conf

        for finding in summary.ot_findings:
            value = str(finding)
            if value and value not in seen_ot and len(ot_findings) < 20:
                seen_ot.add(value)
                ot_findings.append(value)

        for indicator in summary.ctf_indicators:
            value = str(indicator)
            if value and value not in seen_ctf and len(ctf_indicators) < 20:
                seen_ctf.add(value)
                ctf_indicators.append(value)

        errors.extend(summary.errors)

    suspicious_details: List[Dict[str, object]] = []
    for value, bucket in sorted(
        detail_map.items(),
        key=lambda kv: int(kv[1].get("count", 0)),
        reverse=True,
    )[:20]:
        reasons = sorted(str(r) for r in (bucket.get("reasons") or set()))
        src_counter = bucket.get("top_sources")
        dst_counter = bucket.get("top_destinations")
        suspicious_details.append(
            {
                "value": value,
                "count": int(bucket.get("count", 0)),
                "reasons": reasons,
                "top_sources": (
                    src_counter.most_common(3) if isinstance(src_counter, Counter) else []
                ),
                "top_destinations": (
                    dst_counter.most_common(3) if isinstance(dst_counter, Counter) else []
                ),
            }
        )

    client_strings = {
        ip: _to_artifacts(counter, 8)
        for ip, counter in sorted(
            client_counters.items(),
            key=lambda item: sum(item[1].values()),
            reverse=True,
        )[:5]
    }
    server_strings = {
        ip: _to_artifacts(counter, 8)
        for ip, counter in sorted(
            server_counters.items(),
            key=lambda item: sum(item[1].values()),
            reverse=True,
        )[:5]
    }

    threat_hypotheses = sorted(
        threat_rollup.values(),
        key=lambda item: int(item.get("evidence_count", 0)),
        reverse=True,
    )

    return StringsSummary(
        path=Path("ALL_PCAPS"),
        total_packets=total_packets,
        strings_found=strings_found,
        unique_strings=unique_strings,
        top_strings=_to_artifacts(top_counter, 20),
        bottom_strings=_to_artifacts(bottom_counter, 20),
        suspicious_strings=_to_artifacts(suspicious_counter, 20),
        suspicious_details=suspicious_details,
        urls=_to_artifacts(url_counter, 15),
        emails=_to_artifacts(email_counter, 15),
        domains=_to_artifacts(domain_counter, 15),
        client_strings=client_strings,
        server_strings=server_strings,
        anomalies=anomalies,
        deterministic_checks=deterministic_checks,
        threat_hypotheses=threat_hypotheses,
        ot_findings=ot_findings,
        ctf_indicators=ctf_indicators,
        errors=errors,
    )
