from __future__ import annotations

import ipaddress
import os
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from .bacnet import BACNET_PORT
from .cip import ENIP_COMMANDS
from .creds import analyze_creds
from .dnp3 import DNP3_PORT, analyze_dnp3
from .dns import _vt_lookup_domains
from .files import analyze_files
from .iec104 import IEC104_PORT, analyze_iec104
from .modbus import EXCEPTION_CODES as MODBUS_EXC_CODES
from .modbus import FUNC_NAMES as MODBUS_FUNC_NAMES
from .modbus import MODBUS_TCP_PORT
from .opc import OPC_TYPES, OPC_UA_PORT
from .ot_risk import compute_ot_risk_posture, dedupe_findings
from .pcap_cache import get_reader
from .powershell import PS_COMMAND_RE
from .profinet import PROFINET_PORTS
from .progress import build_statusbar, run_with_busy_status
from .s7 import S7_PORT, analyze_s7
from .telnet import TELNET_PORTS
from .utils import counter_inc, decode_payload, safe_float, extract_packet_endpoints
from .winrm import WINRM_PORTS, WSMAN_RE
from .wmic import WMIC_COMMAND_RE

try:
    from scapy.layers.dns import DNS, DNSQR  # type: ignore
    from scapy.layers.inet import (  # type: ignore
        ICMP,  # type: ignore
        IP,
        TCP,
        UDP,
    )
    from scapy.layers.inet6 import (  # type: ignore
        ICMPv6EchoReply,
        ICMPv6EchoRequest,
        ICMPv6ND_NA,
        ICMPv6ND_NS,
        IPv6,  # type: ignore
    )
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore
    DNS = None  # type: ignore
    DNSQR = None  # type: ignore
    ICMP = None  # type: ignore
    ICMPv6EchoRequest = None  # type: ignore
    ICMPv6EchoReply = None  # type: ignore
    ICMPv6ND_NS = None  # type: ignore
    ICMPv6ND_NA = None  # type: ignore

try:
    from scapy.layers.netbios import (  # type: ignore
        NBNS,
        NBNSQueryRequest,
        NBNSQueryResponse,
    )
except Exception:  # pragma: no cover
    NBNS = None  # type: ignore
    NBNSQueryRequest = None  # type: ignore
    NBNSQueryResponse = None  # type: ignore


@dataclass(frozen=True)
class TimelineEvent:
    ts: Optional[float]
    category: str
    summary: str
    details: str
    packet_index: Optional[int] = None
    source: str = "timeline"


@dataclass(frozen=True)
class DNSQueryDetail:
    ts: Optional[float]
    name: str
    qtype: Optional[str]
    src_ip: str
    dst_ip: str
    protocol: str
    dst_port: Optional[int]


@dataclass(frozen=True)
class FileDownloadDetail:
    ts: Optional[float]
    packet_number: Optional[int]
    protocol: str
    src_ip: str
    dst_ip: str
    filename: str
    file_type: str
    size_bytes: Optional[int]
    hostname: Optional[str]
    content_type: Optional[str]
    sha256: Optional[str]
    md5: Optional[str]


@dataclass(frozen=True)
class TimelineSummary:
    path: Path
    target_ip: str
    total_packets: int
    events: list[TimelineEvent]
    errors: list[str]
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    duration: Optional[float] = None
    category_counts: dict[str, int] = field(default_factory=dict)
    peer_counts: dict[str, int] = field(default_factory=dict)
    port_counts: dict[int, int] = field(default_factory=dict)
    ot_protocol_counts: dict[str, int] = field(default_factory=dict)
    ot_activity_bins: dict[str, list[int]] = field(default_factory=dict)
    ot_activity_bin_count: int = 0
    non_ot_activity_bins: list[int] = field(default_factory=list)
    non_ot_activity_bin_count: int = 0
    ot_risk_score: int = 0
    ot_risk_findings: list[str] = field(default_factory=list)
    ot_storyline: list[str] = field(default_factory=list)
    dns_queries: list[DNSQueryDetail] = field(default_factory=list)
    file_downloads: list[FileDownloadDetail] = field(default_factory=list)
    analyst_verdict: str = ""
    analyst_confidence: str = "low"
    analyst_reasons: list[str] = field(default_factory=list)
    deterministic_checks: dict[str, list[str]] = field(default_factory=dict)
    sequence_timeline: list[dict[str, object]] = field(default_factory=list)
    sequence_violations: list[str] = field(default_factory=list)
    beacon_candidates: list[dict[str, object]] = field(default_factory=list)
    auth_abuse_profiles: list[dict[str, object]] = field(default_factory=list)
    lateral_movement_paths: list[dict[str, object]] = field(default_factory=list)
    exfiltration_chains: list[dict[str, object]] = field(default_factory=list)
    ot_impact_signals: list[dict[str, object]] = field(default_factory=list)
    evidence_anchors: list[dict[str, object]] = field(default_factory=list)
    benign_context: list[str] = field(default_factory=list)
    vt_lookup_enabled: bool = False
    vt_results: dict[str, dict[str, object]] = field(default_factory=dict)
    vt_errors: list[str] = field(default_factory=list)


_DNS_QTYPE_NAMES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    50: "NSEC3",
    51: "NSEC3PARAM",
    65: "HTTPS",
    99: "SPF",
    252: "AXFR",
    255: "ANY",
}


def _dns_qtype_label(qtype: object) -> str:
    if qtype is None:
        return "-"
    try:
        code = int(qtype)
    except Exception:
        return str(qtype)
    name = _DNS_QTYPE_NAMES.get(code, f"TYPE{code}")
    return f"{name} ({code})"


def _dns_base_domain(name: str) -> str:
    labels = [part for part in str(name or "").strip(".").lower().split(".") if part]
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return ".".join(labels)


def merge_timeline_summaries(summaries: Iterable[TimelineSummary]) -> TimelineSummary:
    summary_list = list(summaries)
    if not summary_list:
        return TimelineSummary(
            path=Path("ALL_PCAPS_0"),
            target_ip="-",
            total_packets=0,
            events=[],
            errors=[],
            first_seen=None,
            last_seen=None,
            duration=None,
            category_counts={},
            peer_counts={},
            port_counts={},
            ot_protocol_counts={},
            ot_activity_bins={},
            ot_activity_bin_count=0,
            non_ot_activity_bins=[],
            non_ot_activity_bin_count=0,
            ot_risk_score=0,
            ot_risk_findings=[],
            ot_storyline=[],
            dns_queries=[],
            file_downloads=[],
            analyst_verdict="",
            analyst_confidence="low",
            analyst_reasons=[],
            deterministic_checks={},
            sequence_timeline=[],
            sequence_violations=[],
            beacon_candidates=[],
            auth_abuse_profiles=[],
            lateral_movement_paths=[],
            exfiltration_chains=[],
            ot_impact_signals=[],
            evidence_anchors=[],
            benign_context=[],
            vt_lookup_enabled=False,
            vt_results={},
            vt_errors=[],
        )

    target_ip = summary_list[0].target_ip
    total_packets = sum(item.total_packets for item in summary_list)
    merged_events: list[TimelineEvent] = []
    for item in summary_list:
        merged_events.extend(item.events)
    merged_events.sort(key=lambda event: (event.ts is None, event.ts))

    seen_errors: set[str] = set()
    errors: list[str] = []
    for item in summary_list:
        for err in item.errors:
            if err in seen_errors:
                continue
            seen_errors.add(err)
            errors.append(err)

    first_seen = None
    last_seen = None
    category_counts: Counter[str] = Counter()
    peer_counts: Counter[str] = Counter()
    port_counts: Counter[int] = Counter()
    ot_protocol_counts: Counter[str] = Counter()
    ot_activity_bins: dict[str, list[int]] = {}
    ot_bin_count = 0
    non_ot_bins: list[int] = []
    non_ot_bin_count = 0
    merged_dns_queries: list[DNSQueryDetail] = []
    merged_file_downloads: list[FileDownloadDetail] = []
    seen_dns_keys: set[tuple[str, str, str, Optional[int], str]] = set()
    seen_file_keys: set[tuple[str, str, str, str, str]] = set()
    merged_reasons: list[str] = []
    merged_checks: dict[str, list[str]] = {}
    merged_sequence_timeline: list[dict[str, object]] = []
    merged_sequence_violations: list[str] = []
    merged_beacons: list[dict[str, object]] = []
    merged_auth_abuse: list[dict[str, object]] = []
    merged_lateral_paths: list[dict[str, object]] = []
    merged_exfil_chains: list[dict[str, object]] = []
    merged_ot_impact: list[dict[str, object]] = []
    merged_anchors: list[dict[str, object]] = []
    merged_benign: list[str] = []
    merged_vt_enabled = False
    merged_vt_results: dict[str, dict[str, object]] = {}
    merged_vt_errors: list[str] = []

    for item in summary_list:
        if item.first_seen is not None:
            first_seen = (
                item.first_seen
                if first_seen is None
                else min(first_seen, item.first_seen)
            )
        if item.last_seen is not None:
            last_seen = (
                item.last_seen if last_seen is None else max(last_seen, item.last_seen)
            )
        category_counts.update(item.category_counts or {})
        peer_counts.update(item.peer_counts or {})
        port_counts.update(item.port_counts or {})
        ot_protocol_counts.update(item.ot_protocol_counts or {})
        if item.ot_activity_bins:
            ot_bin_count = max(ot_bin_count, item.ot_activity_bin_count)
            for proto, bins in item.ot_activity_bins.items():
                merged = ot_activity_bins.setdefault(proto, [0] * len(bins))
                if len(merged) < len(bins):
                    merged.extend([0] * (len(bins) - len(merged)))
                for idx, val in enumerate(bins):
                    merged[idx] += val
        if item.non_ot_activity_bins:
            non_ot_bin_count = max(non_ot_bin_count, item.non_ot_activity_bin_count)
            if not non_ot_bins:
                non_ot_bins = [0] * len(item.non_ot_activity_bins)
            if len(non_ot_bins) < len(item.non_ot_activity_bins):
                non_ot_bins.extend(
                    [0] * (len(item.non_ot_activity_bins) - len(non_ot_bins))
                )
            for idx, val in enumerate(item.non_ot_activity_bins):
                non_ot_bins[idx] += val
        if item.dns_queries:
            for entry in item.dns_queries:
                key = (
                    entry.src_ip,
                    entry.dst_ip,
                    entry.name.lower(),
                    entry.dst_port,
                    entry.protocol,
                )
                if key in seen_dns_keys:
                    continue
                seen_dns_keys.add(key)
                merged_dns_queries.append(entry)
        if item.file_downloads:
            for entry in item.file_downloads:
                key = (
                    entry.protocol,
                    entry.src_ip,
                    entry.dst_ip,
                    entry.filename,
                    entry.file_type,
                )
                if key in seen_file_keys:
                    continue
                seen_file_keys.add(key)
                merged_file_downloads.append(entry)
        if item.analyst_reasons:
            for reason in item.analyst_reasons:
                if reason not in merged_reasons:
                    merged_reasons.append(reason)
        if item.deterministic_checks:
            for key, values in item.deterministic_checks.items():
                bucket = merged_checks.setdefault(key, [])
                for value in values:
                    if value not in bucket:
                        bucket.append(value)
        if item.sequence_timeline:
            merged_sequence_timeline.extend(item.sequence_timeline)
        if item.sequence_violations:
            for value in item.sequence_violations:
                if value not in merged_sequence_violations:
                    merged_sequence_violations.append(value)
        if item.beacon_candidates:
            merged_beacons.extend(item.beacon_candidates)
        if item.auth_abuse_profiles:
            merged_auth_abuse.extend(item.auth_abuse_profiles)
        if item.lateral_movement_paths:
            merged_lateral_paths.extend(item.lateral_movement_paths)
        if item.exfiltration_chains:
            merged_exfil_chains.extend(item.exfiltration_chains)
        if item.ot_impact_signals:
            merged_ot_impact.extend(item.ot_impact_signals)
        if item.evidence_anchors:
            merged_anchors.extend(item.evidence_anchors)
        if item.benign_context:
            for value in item.benign_context:
                if value not in merged_benign:
                    merged_benign.append(value)
        if item.vt_lookup_enabled:
            merged_vt_enabled = True
        if item.vt_results:
            for key, value in item.vt_results.items():
                key_text = str(key).strip().lower()
                if not key_text:
                    continue
                if key_text not in merged_vt_results:
                    merged_vt_results[key_text] = dict(value)
                    continue
                current = merged_vt_results[key_text]
                try:
                    cur_mal = int(current.get("malicious", 0) or 0)
                    cur_sus = int(current.get("suspicious", 0) or 0)
                except Exception:
                    cur_mal = 0
                    cur_sus = 0
                try:
                    new_mal = int(value.get("malicious", 0) or 0)
                    new_sus = int(value.get("suspicious", 0) or 0)
                except Exception:
                    new_mal = 0
                    new_sus = 0
                if (new_mal, new_sus) > (cur_mal, cur_sus):
                    merged_vt_results[key_text] = dict(value)
        if item.vt_errors:
            for err in item.vt_errors:
                err_text = str(err).strip()
                if err_text and err_text not in merged_vt_errors:
                    merged_vt_errors.append(err_text)

    duration = None
    if first_seen is not None and last_seen is not None:
        duration = max(0.0, last_seen - first_seen)

    merged = TimelineSummary(
        path=Path(f"ALL_PCAPS_{len(summary_list)}"),
        target_ip=target_ip,
        total_packets=total_packets,
        events=merged_events,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration=duration,
        category_counts=dict(category_counts),
        peer_counts=dict(peer_counts),
        port_counts=dict(port_counts),
        ot_protocol_counts=dict(ot_protocol_counts),
        ot_activity_bins=ot_activity_bins,
        ot_activity_bin_count=ot_bin_count,
        non_ot_activity_bins=non_ot_bins,
        non_ot_activity_bin_count=non_ot_bin_count,
        dns_queries=sorted(
            merged_dns_queries, key=lambda item: (item.ts is None, item.ts)
        ),
        file_downloads=sorted(
            merged_file_downloads, key=lambda item: (item.ts is None, item.ts)
        ),
    )
    risk_score, risk_findings = _compute_ot_risk_posture(merged.events, target_ip)
    storyline = _compute_ot_storyline(
        merged.events, target_ip, merged.ot_protocol_counts, risk_score, risk_findings
    )
    merged_enrichment = _build_timeline_enrichment(
        merged.events,
        target_ip,
        merged.file_downloads,
        risk_score,
        risk_findings,
    )
    merged = TimelineSummary(
        path=merged.path,
        target_ip=merged.target_ip,
        total_packets=merged.total_packets,
        events=merged.events,
        errors=merged.errors,
        first_seen=merged.first_seen,
        last_seen=merged.last_seen,
        duration=merged.duration,
        category_counts=merged.category_counts,
        peer_counts=merged.peer_counts,
        port_counts=merged.port_counts,
        ot_protocol_counts=merged.ot_protocol_counts,
        ot_activity_bins=merged.ot_activity_bins,
        ot_activity_bin_count=merged.ot_activity_bin_count,
        non_ot_activity_bins=merged.non_ot_activity_bins,
        non_ot_activity_bin_count=merged.non_ot_activity_bin_count,
        ot_risk_score=risk_score,
        ot_risk_findings=risk_findings,
        ot_storyline=storyline,
        dns_queries=merged.dns_queries,
        file_downloads=merged.file_downloads,
        analyst_verdict=str(merged_enrichment.get("analyst_verdict", "")),
        analyst_confidence=str(merged_enrichment.get("analyst_confidence", "low")),
        analyst_reasons=[
            str(v)
            for v in list(
                merged_enrichment.get("analyst_reasons", merged_reasons) or []
            )
        ],
        deterministic_checks={
            str(k): [str(v) for v in list(values or [])]
            for k, values in dict(
                merged_enrichment.get("deterministic_checks", merged_checks) or {}
            ).items()
        },
        sequence_timeline=list(
            merged_enrichment.get("sequence_timeline", merged_sequence_timeline) or []
        ),
        sequence_violations=[
            str(v)
            for v in list(
                merged_enrichment.get(
                    "sequence_violations", merged_sequence_violations
                )
                or []
            )
        ],
        beacon_candidates=list(
            merged_enrichment.get("beacon_candidates", merged_beacons) or []
        ),
        auth_abuse_profiles=list(
            merged_enrichment.get("auth_abuse_profiles", merged_auth_abuse) or []
        ),
        lateral_movement_paths=list(
            merged_enrichment.get("lateral_movement_paths", merged_lateral_paths)
            or []
        ),
        exfiltration_chains=list(
            merged_enrichment.get("exfiltration_chains", merged_exfil_chains) or []
        ),
        ot_impact_signals=list(
            merged_enrichment.get("ot_impact_signals", merged_ot_impact) or []
        ),
        evidence_anchors=list(
            merged_enrichment.get("evidence_anchors", merged_anchors) or []
        ),
        benign_context=[
            str(v)
            for v in list(
                merged_enrichment.get("benign_context", merged_benign) or []
            )
        ],
        vt_lookup_enabled=merged_vt_enabled,
        vt_results=merged_vt_results,
        vt_errors=merged_vt_errors,
    )
    return merged


EMAIL_PORT_SERVICES: dict[int, str] = {
    25: "SMTP",
    465: "SMTPS",
    587: "SMTP Submission",
    2525: "SMTP Alternate",
    110: "POP3",
    995: "POP3S",
    143: "IMAP",
    993: "IMAPS",
}

OT_PORT_PROTOCOLS: dict[int, str] = {
    MODBUS_TCP_PORT: "Modbus",
    DNP3_PORT: "DNP3",
    IEC104_PORT: "IEC-104",
    S7_PORT: "S7",
    44818: "ENIP",
    2222: "CIP",
    BACNET_PORT: "BACnet",
    OPC_UA_PORT: "OPC UA",
    1911: "Niagara Fox",
    4911: "Niagara Fox",
    9600: "FINS",
    5094: "HART-IP",
    18245: "SRTP",
    18246: "SRTP",
    1962: "PCWorx",
    5006: "MELSEC",
    5007: "MELSEC",
    20547: "ProConOS",
    2455: "CODESYS",
    1217: "CODESYS",
    5683: "CoAP",
    5684: "CoAP",
    1502: "Triconex/SIS",
}

for _port in PROFINET_PORTS:
    OT_PORT_PROTOCOLS[_port] = "PROFINET"

OT_CATEGORIES = {
    "Modbus",
    "DNP3",
    "IEC-104",
    "S7",
    "ENIP",
    "CIP",
    "BACnet",
    "OPC UA",
    "PROFINET",
    "Niagara Fox",
    "FINS",
    "HART-IP",
    "SRTP",
    "PCWorx",
    "MELSEC",
    "ProConOS",
    "CODESYS",
    "CoAP",
    "Triconex/SIS",
}

NON_OT_CATEGORIES = {
    "Connection",
    "DNS",
    "Email",
    "File Transfer",
    "FTP",
    "HTTP",
    "ICMP",
    "LDAP",
    "MS Domain",
    "NetBIOS",
    "PowerShell",
    "RPC",
    "Recon",
    "SMB",
    "SNMP",
    "Telnet",
    "WMIC",
    "WinRM",
    "mDNS",
}

TIMELINE_CATEGORIES = tuple(sorted(OT_CATEGORIES | NON_OT_CATEGORIES, key=str.casefold))


FTP_CONTROL_PORTS = {21, 2100, 2121, 8021}
FTP_COMMANDS = {
    "USER",
    "PASS",
    "ACCT",
    "CWD",
    "CDUP",
    "PWD",
    "XPWD",
    "LIST",
    "NLST",
    "MLSD",
    "MLST",
    "RETR",
    "STOR",
    "APPE",
    "DELE",
    "RMD",
    "MKD",
    "RNFR",
    "RNTO",
    "TYPE",
    "SYST",
    "FEAT",
    "STAT",
    "NOOP",
    "QUIT",
    "PASV",
    "EPSV",
    "PORT",
    "EPRT",
    "AUTH",
    "PBSZ",
    "PROT",
    "SITE",
    "OPTS",
    "HOST",
}
FTP_RESPONSE_RE = re.compile(r"^(\d{3})(?:[ -].*)?$")


def _decode_payload_line(payload: bytes | None) -> str:
    if not payload:
        return ""
    text = decode_payload(payload, encoding="latin-1")
    if not text:
        return ""
    first = text.split("\r\n", 1)[0].split("\n", 1)[0].strip()
    return first[:200]


def _extract_email_action(service: str, first_line: str) -> str | None:
    if not first_line:
        return None
    upper = first_line.upper()

    if service.startswith("SMTP"):
        smtp_cmds = (
            "EHLO",
            "HELO",
            "MAIL FROM",
            "RCPT TO",
            "DATA",
            "STARTTLS",
            "AUTH",
            "QUIT",
            "NOOP",
            "RSET",
            "VRFY",
            "EXPN",
        )
        for cmd in smtp_cmds:
            if upper.startswith(cmd):
                return cmd
        if re.match(r"^\d{3}\b", upper):
            return f"SMTP reply {upper[:3]}"

    if service.startswith("IMAP"):
        imap_cmds = (
            "LOGIN",
            "AUTHENTICATE",
            "SELECT",
            "EXAMINE",
            "FETCH",
            "UID",
            "SEARCH",
            "STORE",
            "COPY",
            "APPEND",
            "IDLE",
            "LOGOUT",
            "STARTTLS",
            "CAPABILITY",
        )
        parts = upper.split()
        if parts:
            if parts[0] in {"*", "+"} and len(parts) >= 2:
                token = parts[1]
                if token in {"OK", "NO", "BAD", "BYE", "PREAUTH"}:
                    return f"IMAP reply {token}"
            if len(parts) >= 2:
                token = parts[1]
                if token in imap_cmds:
                    return token

    if service.startswith("POP3"):
        pop3_cmds = (
            "USER",
            "PASS",
            "APOP",
            "AUTH",
            "STAT",
            "LIST",
            "RETR",
            "DELE",
            "TOP",
            "UIDL",
            "CAPA",
            "STLS",
            "QUIT",
        )
        for cmd in pop3_cmds:
            if upper.startswith(cmd):
                return cmd
        if upper.startswith("+OK"):
            return "POP3 reply +OK"
        if upper.startswith("-ERR"):
            return "POP3 reply -ERR"

    return None


def _extract_email_command(service: str, first_line: str) -> str | None:
    action = _extract_email_action(service, first_line)
    if action:
        return action
    if not first_line:
        return None
    upper = first_line.upper()
    if service.startswith("SMTP"):
        if upper.startswith(
            (
                "EHLO",
                "HELO",
                "MAIL FROM",
                "RCPT TO",
                "DATA",
                "STARTTLS",
                "AUTH",
                "QUIT",
                "NOOP",
                "RSET",
                "VRFY",
                "EXPN",
            )
        ):
            return first_line
    if service.startswith("IMAP"):
        parts = upper.split()
        if len(parts) >= 2 and parts[1].isalpha():
            return first_line
    if service.startswith("POP3"):
        if upper.startswith(
            (
                "USER",
                "PASS",
                "APOP",
                "AUTH",
                "STAT",
                "LIST",
                "RETR",
                "DELE",
                "TOP",
                "UIDL",
                "CAPA",
                "STLS",
                "QUIT",
                "+OK",
                "-ERR",
            )
        ):
            return first_line
    return None


def _extract_ftp_command(first_line: str) -> str | None:
    if not first_line:
        return None
    line = first_line.strip()
    if not line:
        return None

    if FTP_RESPONSE_RE.match(line):
        return None

    command = line.split(" ", 1)[0].upper()
    if command not in FTP_COMMANDS:
        return None
    return line[:200]


def _extract_powershell_command(payload: bytes | None) -> str | None:
    if not payload:
        return None
    text = decode_payload(payload, encoding="latin-1")
    if not text:
        return None
    match = PS_COMMAND_RE.search(text[:2000])
    if not match:
        return None
    return match.group(0).strip()[:200]


def _extract_wmic_command(payload: bytes | None) -> str | None:
    if not payload:
        return None
    text = decode_payload(payload, encoding="latin-1")
    if not text:
        return None
    match = WMIC_COMMAND_RE.search(text[:2000])
    if not match:
        return None
    return match.group(0).strip()[:200]


WINRM_COMMAND_RE = re.compile(
    r"(?:\bwinrs\b[^\r\n]{0,200}|<Command>([^<]{1,200})</Command>|CommandLine>\s*([^<]{1,200}))",
    re.IGNORECASE,
)


def _extract_winrm_command(payload: bytes | None) -> str | None:
    if not payload:
        return None
    text = decode_payload(payload, encoding="latin-1")
    if not text:
        return None
    match = WINRM_COMMAND_RE.search(text[:4000])
    if not match:
        return None
    if match.group(1):
        return match.group(1).strip()[:200]
    if match.group(2):
        return match.group(2).strip()[:200]
    return match.group(0).strip()[:200]


TELNET_COMMAND_RE = re.compile(
    r"^[#>$]\s*([A-Za-z0-9._:/\\-]+(?:\s+[^\r\n]{0,160})?)$",
    re.IGNORECASE | re.MULTILINE,
)
TELNET_COMMAND_FALLBACK_RE = re.compile(
    r"^\s*([A-Za-z0-9._:/\\-]{2,}(?:\s+[^\r\n]{0,160})?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
TELNET_COMMON_COMMANDS = {
    "whoami",
    "id",
    "uname",
    "ls",
    "dir",
    "pwd",
    "cd",
    "cat",
    "type",
    "ps",
    "who",
    "w",
    "hostname",
    "systeminfo",
    "ipconfig",
    "ifconfig",
    "netstat",
    "route",
    "tracert",
    "traceroute",
    "ping",
}


def _extract_telnet_command(payload: bytes | None) -> str | None:
    if not payload:
        return None
    text = decode_payload(payload, encoding="latin-1")
    if not text:
        return None
    view = text[:2000]
    match = TELNET_COMMAND_RE.search(view)
    if match:
        return match.group(1).strip()[:200]

    for line in view.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lower = stripped.lower()
        if "login:" in lower or "password:" in lower:
            continue
        if stripped[0] in "$#>":
            stripped = stripped[1:].strip()
            if stripped:
                return stripped[:200]
        head = stripped.split(" ", 1)[0].lower()
        if head in TELNET_COMMON_COMMANDS or "whoami" in lower:
            return stripped[:200]

    match = TELNET_COMMAND_FALLBACK_RE.search(view)
    if match:
        candidate = match.group(1).strip()
        if candidate and candidate.lower() not in {"login:", "password:"}:
            return candidate[:200]
    return None


def _rpc_packet_type(payload: bytes | None) -> str | None:
    if not payload or len(payload) < 6:
        return None
    try:
        if payload[0] != 0x05:
            return None
        ptype = payload[2]
    except Exception:
        return None
    return {
        0x00: "request",
        0x02: "response",
        0x0B: "bind",
        0x0C: "bind_ack",
        0x0D: "bind_nak",
        0x0E: "alter_context",
        0x0F: "alter_context_resp",
    }.get(ptype)


def _snmp_pdu_type(payload: bytes | None) -> str | None:
    if not payload or len(payload) < 10:
        return None
    if payload[0] != 0x30:
        return None
    length, idx = _read_ber_length(payload, 1)
    if length is None or idx >= len(payload):
        return None
    if idx >= len(payload) or payload[idx] != 0x02:
        return None
    ver_len, idx = _read_ber_length(payload, idx + 1)
    if ver_len is None or idx + ver_len > len(payload):
        return None
    idx += ver_len
    if idx >= len(payload) or payload[idx] != 0x04:
        return None
    comm_len, idx = _read_ber_length(payload, idx + 1)
    if comm_len is None or idx + comm_len > len(payload):
        return None
    idx += comm_len
    if idx >= len(payload):
        return None
    pdu = payload[idx]
    return {
        0xA0: "GetRequest",
        0xA1: "GetNextRequest",
        0xA2: "GetResponse",
        0xA3: "SetRequest",
        0xA4: "Trap",
        0xA5: "GetBulkRequest",
        0xA6: "InformRequest",
        0xA7: "SNMPv2-Trap",
        0xA8: "Report",
    }.get(pdu)


def _parse_modbus_command(
    payload: bytes | None,
) -> tuple[int, str, bool, int | None, str | None] | None:
    if not payload or len(payload) < 8:
        return None
    try:
        unit_id = payload[6]
        func_code = payload[7]
    except Exception:
        return None
    is_exception = func_code >= 0x80
    base_code = func_code & 0x7F
    name = MODBUS_FUNC_NAMES.get(base_code, f"Function {base_code}")
    exc_code = None
    exc_desc = None
    if is_exception and len(payload) >= 9:
        exc_code = payload[8]
        exc_desc = MODBUS_EXC_CODES.get(exc_code)
    return func_code, name, is_exception, unit_id, exc_desc


def _parse_enip_command(payload: bytes | None) -> tuple[int, str | None] | None:
    if not payload or len(payload) < 2:
        return None
    cmd = int.from_bytes(payload[:2], "little", signed=False)
    return cmd, ENIP_COMMANDS.get(cmd)


def _parse_opcua_message(payload: bytes | None) -> str | None:
    if not payload or len(payload) < 3:
        return None
    return OPC_TYPES.get(payload[:3])


def _iec104_frame_type(payload: bytes | None) -> str | None:
    if not payload or len(payload) < 6:
        return None
    if payload[0] != 0x68:
        return None
    ctrl = payload[2:6]
    if (ctrl[0] & 0x01) == 0:
        return "I-frame"
    if (ctrl[0] & 0x03) == 1:
        return "S-frame"
    if (ctrl[0] & 0x03) == 3:
        return "U-frame"
    return None


def _dnp3_frame_seen(payload: bytes | None) -> bool:
    if not payload:
        return False
    return payload.find(b"\x05\x64") != -1


def _s7comm_seen(payload: bytes | None) -> bool:
    if not payload:
        return False
    if len(payload) >= 4 and payload[:2] == b"\x03\x00":
        return b"\x32" in payload
    return False


def _extract_ip_candidates(text: str) -> set[str]:
    candidates: set[str] = set()
    for token in re.findall(r"(?:\\d{1,3}\\.){3}\\d{1,3}", text):
        candidates.add(token)
    return candidates


def _compute_ot_activity_bins(
    events: list[TimelineEvent],
    first_seen: Optional[float],
    last_seen: Optional[float],
    bins: int = 24,
) -> tuple[dict[str, list[int]], int]:
    if not events or first_seen is None or last_seen is None or last_seen <= first_seen:
        return {}, 0
    duration = max(1.0, last_seen - first_seen)
    bin_size = duration / bins
    protocol_bins: dict[str, list[int]] = {}
    for event in events:
        if event.ts is None:
            continue
        if event.category not in OT_CATEGORIES:
            continue
        idx = int((event.ts - first_seen) / bin_size)
        if idx >= bins:
            idx = bins - 1
        if idx < 0:
            idx = 0
        bucket = protocol_bins.setdefault(event.category, [0] * bins)
        bucket[idx] += 1
    return protocol_bins, bins


def _compute_non_ot_activity_bins(
    events: list[TimelineEvent],
    first_seen: Optional[float],
    last_seen: Optional[float],
    bins: int = 24,
) -> tuple[list[int], int]:
    if not events or first_seen is None or last_seen is None or last_seen <= first_seen:
        return [], 0
    duration = max(1.0, last_seen - first_seen)
    bin_size = duration / bins
    bucket = [0] * bins
    for event in events:
        if event.ts is None:
            continue
        if event.category in OT_CATEGORIES:
            continue
        idx = int((event.ts - first_seen) / bin_size)
        if idx >= bins:
            idx = bins - 1
        if idx < 0:
            idx = 0
        bucket[idx] += 1
    return bucket, bins


def _compute_ot_risk_posture(
    events: list[TimelineEvent], target_ip: str
) -> tuple[int, list[str]]:
    if not events:
        return 0, []
    public_peers: set[str] = set()
    control_hits = 0
    transfer_hits = 0
    anomaly_hits = 0

    control_tokens = (
        "write",
        "control",
        "setpoint",
        "start",
        "stop",
        "program",
        "download",
        "upload",
        "firmware",
        "plcstop",
        "plchotstart",
        "plccoldstart",
        "writevar",
    )
    for event in events:
        if event.category not in OT_CATEGORIES:
            continue
        detail = f"{event.summary} {event.details}".lower()
        if any(token in detail for token in control_tokens):
            control_hits += 1
        if any(
            token in detail
            for token in ("download", "upload", "file operation", "program transfer")
        ):
            transfer_hits += 1
        if "anomaly" in detail or "restart" in detail or "command" in detail:
            if "error" not in detail:
                anomaly_hits += 1
        for ip_text in _extract_ip_candidates(event.details):
            if ip_text == target_ip:
                continue
            try:
                if ipaddress.ip_address(ip_text).is_global:
                    public_peers.add(ip_text)
            except Exception:
                continue

    score, findings = compute_ot_risk_posture(
        public_ot_flows=len(public_peers),
        control_hits=control_hits,
        anomaly_hits=anomaly_hits,
    )
    if transfer_hits:
        findings.append(f"OT program/file transfer indicators ({transfer_hits}).")
    return score, dedupe_findings(findings, limit=6)


def _compute_ot_storyline(
    events: list[TimelineEvent],
    target_ip: str,
    ot_protocol_counts: dict[str, int],
    risk_score: int,
    risk_findings: list[str],
) -> list[str]:
    if not ot_protocol_counts:
        return [f"No OT/ICS protocols observed for {target_ip}."]
    top_protocols = sorted(
        ot_protocol_counts.items(), key=lambda item: (-item[1], item[0])
    )
    proto_text = ", ".join(f"{name} ({count})" for name, count in top_protocols[:4])
    storyline = [f"OT protocols observed: {proto_text}."]
    if risk_score:
        storyline.append(f"OT risk posture scored {risk_score}/100.")
    if risk_findings:
        storyline.append("Key signals: " + "; ".join(risk_findings[:3]))
    control_hits = 0
    for event in events:
        if event.category not in OT_CATEGORIES:
            continue
        detail = f"{event.summary} {event.details}".lower()
        if any(
            token in detail
            for token in (
                "write",
                "control",
                "setpoint",
                "start",
                "stop",
                "program",
                "download",
                "upload",
                "firmware",
            )
        ):
            control_hits += 1
    if control_hits:
        storyline.append(
            f"Control or program-change indications seen ({control_hits})."
        )
    return storyline


def _first_ts_for_category(
    events: list[TimelineEvent], category: str
) -> Optional[float]:
    timestamps = [
        event.ts
        for event in events
        if event.category == category and event.ts is not None
    ]
    return min(timestamps) if timestamps else None


def _extract_event_ips(text: str) -> list[str]:
    found: list[str] = []
    for token in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", text):
        if token not in found:
            found.append(token)
    return found


def _extract_event_flow(
    event: TimelineEvent, target_ip: str
) -> tuple[str | None, str | None, int | None]:
    details = event.details
    match = re.search(
        r"((?:\d{1,3}\.){3}\d{1,3})\s*->\s*((?:\d{1,3}\.){3}\d{1,3})(?::(\d+))?",
        details,
    )
    if not match:
        return None, None, None
    src, dst, port_text = match.group(1), match.group(2), match.group(3)
    port = int(port_text) if port_text and port_text.isdigit() else None
    actor = src
    peer = dst
    if src == target_ip:
        actor, peer = src, dst
    elif dst == target_ip:
        actor, peer = dst, src
    return actor, peer, port


def _classify_timeline_stage(event: TimelineEvent) -> str | None:
    text = f"{event.category} {event.summary} {event.details}".lower()
    if any(
        token in text
        for token in (
            "scan",
            "recon",
            "probe",
            "icmp",
            "nbns",
            "mdns",
            "potential port scan",
        )
    ):
        return "Recon"
    if any(
        token in text
        for token in (
            "auth",
            "login",
            "kerberos",
            "ntlm",
            "ldap",
            "domain service",
            "credential",
            "password",
            "user ",
        )
    ):
        return "Access"
    if any(
        token in text
        for token in (
            "powershell",
            "wmic",
            "winrm",
            "telnet command",
            "execute",
            "cmd.exe",
            "rundll32",
            "mshta",
        )
    ):
        return "Execution"
    if any(token in text for token in ("beacon", "c2", "command and control")):
        return "C2"
    if any(
        token in text
        for token in ("http post", "stor ", "appe ", "upload", "file artifact", "exfil")
    ):
        return "Exfil"
    if event.category in OT_CATEGORIES and any(
        token in text
        for token in (
            "write",
            "setpoint",
            "program",
            "firmware",
            "start",
            "stop",
            "trip",
            "shutdown",
            "operate",
        )
    ):
        return "Impact"
    return None


def _build_timeline_enrichment(
    events: list[TimelineEvent],
    target_ip: str,
    file_downloads: list[FileDownloadDetail],
    ot_risk_score: int,
    ot_risk_findings: list[str],
) -> dict[str, object]:
    _ = (events, target_ip, file_downloads, ot_risk_score, ot_risk_findings)
    return {}

def _read_ber_length(payload: bytes, offset: int) -> tuple[Optional[int], int]:
    if offset >= len(payload):
        return None, offset
    first = payload[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    num_bytes = first & 0x7F
    if num_bytes == 0 or offset + num_bytes > len(payload):
        return None, offset
    length = int.from_bytes(payload[offset : offset + num_bytes], "big")
    offset += num_bytes
    return length, offset


def _icmp_label(pkt) -> str | None:
    if ICMP is not None and pkt.haslayer(ICMP):  # type: ignore[truthy-bool]
        try:
            icmp = pkt[ICMP]  # type: ignore[index]
            itype = int(getattr(icmp, "type", -1))
            code = int(getattr(icmp, "code", -1))
        except Exception:
            return "ICMP"
        if itype == 8:
            return "ICMP Echo Request"
        if itype == 0:
            return "ICMP Echo Reply"
        if itype == 3:
            return f"ICMP Destination Unreachable (code {code})"
        if itype == 11:
            return f"ICMP Time Exceeded (code {code})"
        return f"ICMP type {itype} code {code}"
    if ICMPv6EchoRequest is not None and pkt.haslayer(ICMPv6EchoRequest):  # type: ignore[truthy-bool]
        return "ICMPv6 Echo Request"
    if ICMPv6EchoReply is not None and pkt.haslayer(ICMPv6EchoReply):  # type: ignore[truthy-bool]
        return "ICMPv6 Echo Reply"
    if ICMPv6ND_NS is not None and pkt.haslayer(ICMPv6ND_NS):  # type: ignore[truthy-bool]
        return "ICMPv6 Neighbor Solicitation"
    if ICMPv6ND_NA is not None and pkt.haslayer(ICMPv6ND_NA):  # type: ignore[truthy-bool]
        return "ICMPv6 Neighbor Advertisement"
    return None


def _nbns_info(pkt) -> tuple[str, str]:
    action = "NetBIOS activity"
    name = "-"
    if NBNSQueryRequest is not None and pkt.haslayer(NBNSQueryRequest):  # type: ignore[truthy-bool]
        action = "NBNS name query"
    elif NBNSQueryResponse is not None and pkt.haslayer(NBNSQueryResponse):  # type: ignore[truthy-bool]
        action = "NBNS name response"
    if NBNS is not None and pkt.haslayer(NBNS):  # type: ignore[truthy-bool]
        try:
            nb = pkt[NBNS]  # type: ignore[index]
            qd = getattr(nb, "qd", None)
            qname = getattr(qd, "qname", None)
            if qname is not None:
                name = str(qname).strip(".")
        except Exception:
            name = "-"
    return action, name


def _netbios_session_hint(payload: bytes | None) -> str | None:
    if not payload:
        return None
    if b"NTLMSSP" in payload or b"\xfeSMB" in payload or b"\xffSMB" in payload:
        return "NetBIOS/SMB session setup"
    return None


def analyze_timeline(
    path: Path,
    target_ip: str,
    show_status: bool = True,
    timeline_bins: int = 24,
    timeline_storyline_off: bool = False,
    categories: set[str] | None = None,
    vt_lookup: bool = False,
) -> TimelineSummary:
    errors: list[str] = []
    events: list[TimelineEvent] = []

    def _busy(desc: str, func, *args, **kwargs):
        return run_with_busy_status(
            path, show_status, f"Timeline: {desc}", func, *args, **kwargs
        )

    file_summary = _busy("Files", analyze_files, path, show_status=False)
    artifacts_for_ip = [
        art
        for art in file_summary.artifacts
        if art.src_ip == target_ip or art.dst_ip == target_ip
    ]
    artifact_indices = {
        art.packet_index for art in artifacts_for_ip if art.packet_index
    }
    creds_summary = _busy("Credentials", analyze_creds, path, show_status=False)

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, show_status=show_status
    )

    total_packets = 0
    idx = 0
    index_ts: dict[int, float] = {}
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    peer_counts: Counter[str] = Counter()
    port_counts: Counter[int] = Counter()
    ot_protocol_counts: Counter[str] = Counter()
    seen_ot_flows: set[tuple[str, str, str, int]] = set()
    seen_ot_commands: set[tuple[str, str, str, int, str]] = set()
    seen_udp_flows: set[tuple[str, int]] = set()
    seen_domain_flows: set[tuple[str, int, str, str]] = set()
    seen_ldap_flows: set[tuple[str, int, str, str]] = set()
    seen_email_flows: set[tuple[str, int, str, str, str]] = set()
    seen_email_actions: set[tuple[str, int, str, str, str, str]] = set()
    seen_telnet_flows: set[tuple[str, int, str, str]] = set()
    scan_ports: dict[str, set[int]] = defaultdict(set)
    scan_first: dict[str, float] = {}
    scan_last: dict[str, float] = {}
    seen_ps_commands: set[tuple[str, str, int, str]] = set()
    seen_wmic_commands: set[tuple[str, str, int, str]] = set()
    seen_winrm_commands: set[tuple[str, str, int, str]] = set()
    seen_telnet_commands: set[tuple[str, str, int, str]] = set()
    seen_ftp_commands: set[tuple[str, str, int, str]] = set()
    seen_rpc_events: set[tuple[str, str, int, str]] = set()
    seen_mdns_events: set[tuple[str, str, str]] = set()
    seen_nbns_events: set[tuple[str, str, str]] = set()
    seen_snmp_events: set[tuple[str, str, int, str]] = set()
    seen_netbios_sessions: set[tuple[str, str, int]] = set()
    dns_queries: list[DNSQueryDetail] = []
    file_downloads: list[FileDownloadDetail] = []
    seen_dns_queries: set[tuple[str, str, int, str, str, Optional[int]]] = set()
    seen_file_downloads: set[tuple[str, str, str, str, str]] = set()
    tcp_handshakes: dict[
        tuple[str, str, int, int], list[dict[str, Optional[float]]]
    ] = defaultdict(list)
    seen_event_keys: set[tuple] = set()
    seen_tcp_syns: set[tuple[str, str, int, int, int]] = set()
    seen_tcp_synacks: set[tuple[str, str, int, int, int, int]] = set()

    def _new_handshake(
        syn_ts: Optional[float] = None, synack_ts: Optional[float] = None
    ) -> dict[str, Optional[float]]:
        return {"syn": syn_ts, "synack": synack_ts, "ack": None}

    def _find_handshake_for_synack(
        items: list[dict[str, Optional[float]]],
    ) -> dict[str, Optional[float]] | None:
        for handshake in reversed(items):
            if handshake["syn"] is not None and handshake["synack"] is None:
                return handshake
        for handshake in reversed(items):
            if handshake["synack"] is None:
                return handshake
        return None

    def _find_handshake_for_ack(
        items: list[dict[str, Optional[float]]],
    ) -> dict[str, Optional[float]] | None:
        for handshake in reversed(items):
            if handshake["synack"] is not None and handshake["ack"] is None:
                return handshake
        return None

    def _layer_signature(layer, limit: int = 48) -> bytes:
        if layer is None:
            return b""
        try:
            raw = bytes(layer)
        except Exception:
            return b""
        return raw[:limit]

    def _icmp_signature(pkt) -> tuple[str, bytes]:
        if ICMP is not None and pkt.haslayer(ICMP):  # type: ignore[truthy-bool]
            return ("icmp4", _layer_signature(pkt[ICMP]))  # type: ignore[index]
        if ICMPv6EchoRequest is not None and pkt.haslayer(ICMPv6EchoRequest):  # type: ignore[truthy-bool]
            return ("icmp6-echo-request", _layer_signature(pkt[ICMPv6EchoRequest]))  # type: ignore[index]
        if ICMPv6EchoReply is not None and pkt.haslayer(ICMPv6EchoReply):  # type: ignore[truthy-bool]
            return ("icmp6-echo-reply", _layer_signature(pkt[ICMPv6EchoReply]))  # type: ignore[index]
        if ICMPv6ND_NS is not None and pkt.haslayer(ICMPv6ND_NS):  # type: ignore[truthy-bool]
            return ("icmp6-nd-ns", _layer_signature(pkt[ICMPv6ND_NS]))  # type: ignore[index]
        if ICMPv6ND_NA is not None and pkt.haslayer(ICMPv6ND_NA):  # type: ignore[truthy-bool]
            return ("icmp6-nd-na", _layer_signature(pkt[ICMPv6ND_NA]))  # type: ignore[index]
        return ("icmp", b"")

    def _emit_event(
        ts: Optional[float],
        category: str,
        summary: str,
        details: str,
        dedupe_key: tuple | None = None,
        packet_index: Optional[int] = None,
        source: str = "timeline",
    ) -> None:
        if dedupe_key is None:
            time_bucket = int(ts) if ts is not None else None
            dedupe_key = ("event", category, summary, details, time_bucket)
        if dedupe_key in seen_event_keys:
            return
        seen_event_keys.add(dedupe_key)
        event_packet = packet_index
        if event_packet is None and idx > 0:
            event_packet = idx
        events.append(
            TimelineEvent(
                ts=ts,
                category=category,
                summary=summary,
                details=details,
                packet_index=event_packet,
                source=source,
            )
        )

    domain_ports = {88, 464, 445, 139, 135, 593, 3268, 3269}
    ldap_ports = {389, 636, 3268, 3269}

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            idx += 1
            total_packets += 1
            ts = safe_float(getattr(pkt, "time", None))

            src_ip, dst_ip = extract_packet_endpoints(pkt)

            if idx in artifact_indices and ts is not None:
                index_ts[idx] = ts

            if not src_ip or not dst_ip:
                continue

            if src_ip == target_ip or dst_ip == target_ip:
                if ts is not None:
                    if first_seen is None or ts < first_seen:
                        first_seen = ts
                    if last_seen is None or ts > last_seen:
                        last_seen = ts
                peer_ip = dst_ip if src_ip == target_ip else src_ip
                if peer_ip:
                    counter_inc(peer_counts, peer_ip)

            if src_ip == target_ip or dst_ip == target_ip:
                label = _icmp_label(pkt)
                if label:
                    dedupe_key = ("icmp", src_ip, dst_ip, label, _icmp_signature(pkt))
                    _emit_event(
                        ts=ts,
                        category="ICMP",
                        summary=label,
                        details=f"{src_ip} -> {dst_ip}",
                        dedupe_key=dedupe_key,
                    )

            if DNS is not None and DNSQR is not None and pkt.haslayer(DNS):  # type: ignore[truthy-bool]
                dns_layer = pkt[DNS]  # type: ignore[index]
                if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                    udp_layer = pkt[UDP]  # type: ignore[index]
                    sport = int(getattr(udp_layer, "sport", 0) or 0)
                    dport = int(getattr(udp_layer, "dport", 0) or 0)
                    if sport == 5353 or dport == 5353:
                        try:
                            qd = dns_layer.qd  # type: ignore[attr-defined]
                            qname = getattr(qd, "qname", b"")
                            qtype = getattr(qd, "qtype", None)
                            qtype_label = _dns_qtype_label(qtype)
                            name = (
                                qname.decode("utf-8", errors="ignore").rstrip(".")
                                if isinstance(qname, (bytes, bytearray))
                                else str(qname)
                            )
                        except Exception:
                            name = "-"
                            qtype = None
                            qtype_label = "-"
                        direction = (
                            "query" if getattr(dns_layer, "qr", 1) == 0 else "response"
                        )
                        key = (direction, name, str(qtype))
                        if key not in seen_mdns_events and (
                            src_ip == target_ip or dst_ip == target_ip
                        ):
                            seen_mdns_events.add(key)
                            _emit_event(
                                ts=ts,
                                category="mDNS",
                                summary=f"mDNS {direction}",
                                details=f"{src_ip} -> {dst_ip} {name} ({qtype_label})",
                            )
                if getattr(dns_layer, "qr", 1) == 0 and src_ip == target_ip:
                    try:
                        qd = dns_layer.qd  # type: ignore[attr-defined]
                        qname = getattr(qd, "qname", b"")
                        qtype = getattr(qd, "qtype", None)
                        qtype_label = _dns_qtype_label(qtype)
                        name = (
                            qname.decode("utf-8", errors="ignore").rstrip(".")
                            if isinstance(qname, (bytes, bytearray))
                            else str(qname)
                        )
                        dns_id = int(getattr(dns_layer, "id", 0) or 0)
                        transport = "-"
                        dst_port: Optional[int] = None
                        if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                            udp_layer = pkt[UDP]  # type: ignore[index]
                            dst_port = int(getattr(udp_layer, "dport", 0) or 0) or None
                            transport = "UDP"
                        elif TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                            tcp_layer = pkt[TCP]  # type: ignore[index]
                            dst_port = int(getattr(tcp_layer, "dport", 0) or 0) or None
                            transport = "TCP"
                        qname_lower = name.lower()
                        dedupe_key = (
                            "dns-query",
                            src_ip,
                            dst_ip,
                            dns_id,
                            qname_lower,
                            qtype,
                        )
                        _emit_event(
                            ts=ts,
                            category="DNS",
                            summary="DNS query",
                            details=f"{target_ip} queried {name} ({qtype_label})",
                            dedupe_key=dedupe_key,
                        )
                        query_key = (
                            src_ip,
                            dst_ip,
                            dns_id,
                            qname_lower,
                            str(qtype),
                            dst_port,
                        )
                        if query_key not in seen_dns_queries:
                            seen_dns_queries.add(query_key)
                            dns_queries.append(
                                DNSQueryDetail(
                                    ts=ts,
                                    name=name,
                                    qtype=qtype_label if qtype is not None else None,
                                    src_ip=src_ip,
                                    dst_ip=dst_ip,
                                    protocol=transport,
                                    dst_port=dst_port,
                                )
                            )
                        if any(
                            token in qname_lower
                            for token in (
                                "_ldap._tcp",
                                "_kerberos._tcp",
                                "_gc._tcp",
                                "_msdcs",
                            )
                        ):
                            dedupe_key = (
                                "domain-discovery",
                                src_ip,
                                dst_ip,
                                dns_id,
                                qname_lower,
                                qtype,
                            )
                            _emit_event(
                                ts=ts,
                                category="MS Domain",
                                summary="Domain service discovery",
                                details=f"{target_ip} queried {name}",
                                dedupe_key=dedupe_key,
                            )
                    except Exception:
                        pass

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp_layer = pkt[TCP]  # type: ignore[index]
                flags = getattr(tcp_layer, "flags", None)
                is_syn = False
                is_ack = False
                is_rst = False
                is_fin = False
                if isinstance(flags, str):
                    flag_text = flags
                else:
                    flag_text = None
                flag_bits: Optional[int] = None
                if flag_text is None and flags is not None:
                    try:
                        flag_bits = int(flags)
                    except Exception:
                        try:
                            flag_text = str(flags)
                        except Exception:
                            flag_text = None
                if flag_text is not None:
                    is_syn = "S" in flag_text
                    is_ack = "A" in flag_text
                    is_rst = "R" in flag_text
                    is_fin = "F" in flag_text
                elif flag_bits is not None:
                    is_syn = (flag_bits & 0x02) != 0
                    is_ack = (flag_bits & 0x10) != 0
                    is_rst = (flag_bits & 0x04) != 0
                    is_fin = (flag_bits & 0x01) != 0
                is_synack = is_syn and is_ack
                is_syn_only = is_syn and not is_ack
                is_final_ack = is_ack and not is_syn and not is_rst and not is_fin
                sport = int(getattr(tcp_layer, "sport", 0) or 0)
                dport = int(getattr(tcp_layer, "dport", 0) or 0)
                seq = int(getattr(tcp_layer, "seq", 0) or 0)
                ack = int(getattr(tcp_layer, "ack", 0) or 0)
                payload = None
                try:
                    payload = bytes(tcp_layer.payload)
                except Exception:
                    payload = None
                if (src_ip == target_ip or dst_ip == target_ip) and sport and dport:
                    if is_syn_only:
                        syn_key = (src_ip, dst_ip, sport, dport, seq)
                        if syn_key not in seen_tcp_syns:
                            seen_tcp_syns.add(syn_key)
                            key = (src_ip, dst_ip, sport, dport)
                            tcp_handshakes[key].append(_new_handshake(syn_ts=ts))
                    elif is_synack:
                        synack_key = (src_ip, dst_ip, sport, dport, seq, ack)
                        if synack_key not in seen_tcp_synacks:
                            seen_tcp_synacks.add(synack_key)
                            key = (dst_ip, src_ip, dport, sport)
                            bucket = tcp_handshakes[key]
                            handshake = _find_handshake_for_synack(bucket)
                            if handshake is None:
                                handshake = _new_handshake()
                                bucket.append(handshake)
                            handshake["synack"] = ts
                    elif is_final_ack:
                        key = (src_ip, dst_ip, sport, dport)
                        bucket = tcp_handshakes.get(key)
                        if bucket:
                            handshake = _find_handshake_for_ack(bucket)
                            if handshake is not None:
                                handshake["ack"] = ts
                if src_ip == target_ip or dst_ip == target_ip:
                    port_key = dport if src_ip == target_ip else sport
                    if port_key:
                        counter_inc(port_counts, port_key)
                        proto = OT_PORT_PROTOCOLS.get(port_key)
                        if proto:
                            ot_protocol_counts[proto] += 1
                            direction = "outbound" if src_ip == target_ip else "inbound"
                            peer_ip = dst_ip if src_ip == target_ip else src_ip
                            if peer_ip:
                                cmd_event_added = False
                                if proto == "Modbus" and port_key == MODBUS_TCP_PORT:
                                    parsed = _parse_modbus_command(payload)
                                    if parsed:
                                        (
                                            func_code,
                                            func_name,
                                            is_exc,
                                            unit_id,
                                            exc_desc,
                                        ) = parsed
                                        label = f"Modbus {func_name}"
                                        if is_exc:
                                            label = f"Modbus exception {func_name}"
                                        key = (
                                            proto,
                                            direction,
                                            peer_ip,
                                            port_key,
                                            label,
                                        )
                                        if key not in seen_ot_commands:
                                            seen_ot_commands.add(key)
                                            detail = f"{target_ip} -> {peer_ip}:{port_key} unit {unit_id} {func_name}"
                                            if is_exc and exc_desc:
                                                detail += f" (Exception: {exc_desc})"
                                            _emit_event(
                                                ts=ts,
                                                category="Modbus",
                                                summary=label,
                                                details=detail,
                                            )
                                            cmd_event_added = True
                                elif proto in {"ENIP", "CIP"} and port_key in {
                                    44818,
                                    2222,
                                }:
                                    enip = _parse_enip_command(payload)
                                    if enip:
                                        cmd, name = enip
                                        label = name or f"ENIP cmd 0x{cmd:04x}"
                                        key = (
                                            proto,
                                            direction,
                                            peer_ip,
                                            port_key,
                                            label,
                                        )
                                        if key not in seen_ot_commands:
                                            seen_ot_commands.add(key)
                                            _emit_event(
                                                ts=ts,
                                                category=proto,
                                                summary=f"{proto} {label}",
                                                details=f"{target_ip} -> {peer_ip}:{port_key}",
                                            )
                                            cmd_event_added = True
                                elif proto == "OPC UA" and port_key == OPC_UA_PORT:
                                    msg = _parse_opcua_message(payload)
                                    if msg:
                                        label = f"OPC UA {msg}"
                                        key = (
                                            proto,
                                            direction,
                                            peer_ip,
                                            port_key,
                                            label,
                                        )
                                        if key not in seen_ot_commands:
                                            seen_ot_commands.add(key)
                                            _emit_event(
                                                ts=ts,
                                                category="OPC UA",
                                                summary=label,
                                                details=f"{target_ip} -> {peer_ip}:{port_key}",
                                            )
                                            cmd_event_added = True
                                elif proto == "IEC-104" and port_key == IEC104_PORT:
                                    frame = _iec104_frame_type(payload)
                                    if frame:
                                        label = f"IEC-104 {frame}"
                                        key = (
                                            proto,
                                            direction,
                                            peer_ip,
                                            port_key,
                                            label,
                                        )
                                        if key not in seen_ot_commands:
                                            seen_ot_commands.add(key)
                                            _emit_event(
                                                ts=ts,
                                                category="IEC-104",
                                                summary=label,
                                                details=f"{target_ip} -> {peer_ip}:{port_key}",
                                            )
                                            cmd_event_added = True
                                elif proto == "DNP3" and port_key == DNP3_PORT:
                                    if _dnp3_frame_seen(payload):
                                        label = "DNP3 frame"
                                        key = (
                                            proto,
                                            direction,
                                            peer_ip,
                                            port_key,
                                            label,
                                        )
                                        if key not in seen_ot_commands:
                                            seen_ot_commands.add(key)
                                            _emit_event(
                                                ts=ts,
                                                category="DNP3",
                                                summary=label,
                                                details=f"{target_ip} -> {peer_ip}:{port_key}",
                                            )
                                            cmd_event_added = True
                                elif proto == "S7" and port_key == S7_PORT:
                                    if _s7comm_seen(payload):
                                        label = "S7comm packet"
                                        key = (
                                            proto,
                                            direction,
                                            peer_ip,
                                            port_key,
                                            label,
                                        )
                                        if key not in seen_ot_commands:
                                            seen_ot_commands.add(key)
                                            _emit_event(
                                                ts=ts,
                                                category="S7",
                                                summary=label,
                                                details=f"{target_ip} -> {peer_ip}:{port_key}",
                                            )
                                            cmd_event_added = True

                                if not cmd_event_added:
                                    flow_key = (proto, direction, peer_ip, port_key)
                                    if flow_key not in seen_ot_flows:
                                        seen_ot_flows.add(flow_key)
                                        _emit_event(
                                            ts=ts,
                                            category=proto,
                                            summary=f"{proto} flow",
                                            details=f"{target_ip} -> {peer_ip}:{port_key}",
                                        )
                if src_ip == target_ip:
                    if dport in TELNET_PORTS:
                        key = (dst_ip, dport, "TCP", "outbound")
                        if key not in seen_telnet_flows:
                            seen_telnet_flows.add(key)
                            _emit_event(
                                ts=ts,
                                category="Telnet",
                                summary="Telnet connection",
                                details=f"{target_ip} -> {dst_ip}:{dport}",
                            )
                    if dport in {139, 445}:
                        hint = _netbios_session_hint(payload)
                        if hint:
                            key = (src_ip, dst_ip, dport)
                            if key not in seen_netbios_sessions:
                                seen_netbios_sessions.add(key)
                                _emit_event(
                                    ts=ts,
                                    category="NetBIOS",
                                    summary=hint,
                                    details=f"{target_ip} -> {dst_ip}:{dport}",
                                )
                    rpc_type = _rpc_packet_type(payload)
                    if rpc_type and dport in {135, 445, 593}:
                        key = (src_ip, dst_ip, dport, rpc_type)
                        if key not in seen_rpc_events:
                            seen_rpc_events.add(key)
                            _emit_event(
                                ts=ts,
                                category="RPC",
                                summary=f"RPC {rpc_type}",
                                details=f"{target_ip} -> {dst_ip}:{dport}",
                            )
                    ps_cmd = _extract_powershell_command(payload)
                    if ps_cmd:
                        key = (src_ip, dst_ip, dport, ps_cmd)
                        if key not in seen_ps_commands:
                            seen_ps_commands.add(key)
                            _emit_event(
                                ts=ts,
                                category="PowerShell",
                                summary="PowerShell command",
                                details=f"{target_ip} -> {dst_ip}:{dport} {ps_cmd}",
                            )
                    wmic_cmd = _extract_wmic_command(payload)
                    if wmic_cmd:
                        key = (src_ip, dst_ip, dport, wmic_cmd)
                        if key not in seen_wmic_commands:
                            seen_wmic_commands.add(key)
                            _emit_event(
                                ts=ts,
                                category="WMIC",
                                summary="WMIC command",
                                details=f"{target_ip} -> {dst_ip}:{dport} {wmic_cmd}",
                            )
                    payload_text = (
                        decode_payload(payload, encoding="latin-1") if payload else ""
                    )
                    if payload and (
                        dport in WINRM_PORTS
                        or (payload_text and WSMAN_RE.search(payload_text))
                    ):
                        winrm_cmd = _extract_winrm_command(payload)
                        if winrm_cmd:
                            key = (src_ip, dst_ip, dport, winrm_cmd)
                            if key not in seen_winrm_commands:
                                seen_winrm_commands.add(key)
                                _emit_event(
                                    ts=ts,
                                    category="WinRM",
                                    summary="WinRM command",
                                    details=f"{target_ip} -> {dst_ip}:{dport} {winrm_cmd}",
                                )
                    if payload and dport in TELNET_PORTS:
                        telnet_cmd = _extract_telnet_command(payload)
                        if telnet_cmd:
                            key = (src_ip, dst_ip, dport, telnet_cmd)
                            if key not in seen_telnet_commands:
                                seen_telnet_commands.add(key)
                                _emit_event(
                                    ts=ts,
                                    category="Telnet",
                                    summary="Telnet command",
                                    details=f"{target_ip} -> {dst_ip}:{dport} {telnet_cmd}",
                                )
                    if payload and dport in FTP_CONTROL_PORTS:
                        ftp_cmd = _extract_ftp_command(_decode_payload_line(payload))
                        if ftp_cmd:
                            key = (src_ip, dst_ip, dport, ftp_cmd)
                            if key not in seen_ftp_commands:
                                seen_ftp_commands.add(key)
                                _emit_event(
                                    ts=ts,
                                    category="FTP",
                                    summary="FTP command",
                                    details=f"{target_ip} -> {dst_ip}:{dport} {ftp_cmd}",
                                )
                    if payload and payload.startswith(b"POST "):
                        try:
                            line = payload.split(b"\r\n", 1)[0].decode(
                                "latin-1", errors="ignore"
                            )
                            host = "-"
                            for header in payload.split(b"\r\n"):
                                if header.lower().startswith(b"host:"):
                                    host = (
                                        header.decode("latin-1", errors="ignore")
                                        .split(":", 1)[1]
                                        .strip()
                                    )
                                    break
                            dedupe_key = (
                                "http-post",
                                src_ip,
                                dst_ip,
                                dport,
                                seq,
                                line,
                                host,
                            )
                            _emit_event(
                                ts=ts,
                                category="HTTP",
                                summary="HTTP POST",
                                details=f"{target_ip} -> {dst_ip}:{dport} {line} Host: {host}",
                                dedupe_key=dedupe_key,
                            )
                        except Exception:
                            dedupe_key = ("http-post", src_ip, dst_ip, dport, seq)
                            _emit_event(
                                ts=ts,
                                category="HTTP",
                                summary="HTTP POST",
                                details=f"{target_ip} -> {dst_ip}:{dport}",
                                dedupe_key=dedupe_key,
                            )
                    if dport in EMAIL_PORT_SERVICES:
                        service = EMAIL_PORT_SERVICES[dport]
                        flow_key = (dst_ip, dport, "TCP", "outbound", service)
                        if flow_key not in seen_email_flows:
                            seen_email_flows.add(flow_key)
                            _emit_event(
                                ts=ts,
                                category="Email",
                                summary=f"{service} connection",
                                details=f"{target_ip} -> {dst_ip}:{dport}",
                            )
                        first_line = _decode_payload_line(payload)
                        command = _extract_email_command(service, first_line)
                        if command:
                            action_key = (
                                dst_ip,
                                dport,
                                "TCP",
                                "outbound",
                                service,
                                command,
                            )
                            if action_key not in seen_email_actions:
                                seen_email_actions.add(action_key)
                                _emit_event(
                                    ts=ts,
                                    category="Email",
                                    summary=f"{service} command",
                                    details=f"{target_ip} -> {dst_ip}:{dport} {command}",
                                )
                    if dport in ldap_ports:
                        key = (dst_ip, dport, "TCP", "outbound")
                        if key not in seen_ldap_flows:
                            seen_ldap_flows.add(key)
                            _emit_event(
                                ts=ts,
                                category="LDAP",
                                summary="LDAP connection",
                                details=f"{target_ip} -> {dst_ip}:{dport}",
                            )
                    if dport in domain_ports:
                        key = (dst_ip, dport, "TCP", "outbound")
                        if key not in seen_domain_flows:
                            seen_domain_flows.add(key)
                            _emit_event(
                                ts=ts,
                                category="MS Domain",
                                summary="Domain service access",
                                details=f"{target_ip} -> {dst_ip}:{dport}",
                            )
                    if is_syn_only and dport:
                        dedupe_key = ("tcp-syn", src_ip, dst_ip, sport, dport, seq)
                        _emit_event(
                            ts=ts,
                            category="Connection",
                            summary="TCP connect attempt",
                            details=f"{target_ip} -> {dst_ip}:{dport} (SYN)",
                            dedupe_key=dedupe_key,
                        )
                        scan_ports[dst_ip].add(dport)
                        if ts is not None:
                            scan_first.setdefault(dst_ip, ts)
                            scan_last[dst_ip] = ts
                    if is_synack and sport:
                        dedupe_key = (
                            "tcp-synack",
                            src_ip,
                            dst_ip,
                            sport,
                            dport,
                            seq,
                            ack,
                        )
                        _emit_event(
                            ts=ts,
                            category="Connection",
                            summary="TCP SYN-ACK",
                            details=f"{target_ip} -> {dst_ip}:{sport} (SYN-ACK)",
                            dedupe_key=dedupe_key,
                        )
                elif dst_ip == target_ip:
                    if sport in TELNET_PORTS:
                        key = (src_ip, sport, "TCP", "inbound")
                        if key not in seen_telnet_flows:
                            seen_telnet_flows.add(key)
                            _emit_event(
                                ts=ts,
                                category="Telnet",
                                summary="Telnet connection",
                                details=f"{src_ip} -> {target_ip}:{sport}",
                            )
                    if is_syn_only and dport:
                        dedupe_key = ("tcp-syn", src_ip, dst_ip, sport, dport, seq)
                        _emit_event(
                            ts=ts,
                            category="Connection",
                            summary="TCP connect attempt",
                            details=f"{src_ip} -> {target_ip}:{dport} (SYN)",
                            dedupe_key=dedupe_key,
                        )
                    if is_synack and sport:
                        dedupe_key = (
                            "tcp-synack",
                            src_ip,
                            dst_ip,
                            sport,
                            dport,
                            seq,
                            ack,
                        )
                        _emit_event(
                            ts=ts,
                            category="Connection",
                            summary="TCP SYN-ACK",
                            details=f"{src_ip} -> {target_ip}:{sport} (SYN-ACK)",
                            dedupe_key=dedupe_key,
                        )
                    if sport in {139, 445}:
                        hint = _netbios_session_hint(payload)
                        if hint:
                            key = (src_ip, dst_ip, sport)
                            if key not in seen_netbios_sessions:
                                seen_netbios_sessions.add(key)
                                _emit_event(
                                    ts=ts,
                                    category="NetBIOS",
                                    summary=hint,
                                    details=f"{src_ip} -> {target_ip}:{sport}",
                                )
                    rpc_type = _rpc_packet_type(payload)
                    if rpc_type and sport in {135, 445, 593}:
                        key = (src_ip, dst_ip, sport, rpc_type)
                        if key not in seen_rpc_events:
                            seen_rpc_events.add(key)
                            _emit_event(
                                ts=ts,
                                category="RPC",
                                summary=f"RPC {rpc_type}",
                                details=f"{src_ip} -> {target_ip}:{sport}",
                            )
                    ps_cmd = _extract_powershell_command(payload)
                    if ps_cmd:
                        key = (src_ip, dst_ip, sport, ps_cmd)
                        if key not in seen_ps_commands:
                            seen_ps_commands.add(key)
                            _emit_event(
                                ts=ts,
                                category="PowerShell",
                                summary="PowerShell command",
                                details=f"{src_ip} -> {target_ip}:{sport} {ps_cmd}",
                            )
                    wmic_cmd = _extract_wmic_command(payload)
                    if wmic_cmd:
                        key = (src_ip, dst_ip, sport, wmic_cmd)
                        if key not in seen_wmic_commands:
                            seen_wmic_commands.add(key)
                            _emit_event(
                                ts=ts,
                                category="WMIC",
                                summary="WMIC command",
                                details=f"{src_ip} -> {target_ip}:{sport} {wmic_cmd}",
                            )
                    payload_text = (
                        decode_payload(payload, encoding="latin-1") if payload else ""
                    )
                    if payload and (
                        sport in WINRM_PORTS
                        or (payload_text and WSMAN_RE.search(payload_text))
                    ):
                        winrm_cmd = _extract_winrm_command(payload)
                        if winrm_cmd:
                            key = (src_ip, dst_ip, sport, winrm_cmd)
                            if key not in seen_winrm_commands:
                                seen_winrm_commands.add(key)
                                _emit_event(
                                    ts=ts,
                                    category="WinRM",
                                    summary="WinRM command",
                                    details=f"{src_ip} -> {target_ip}:{sport} {winrm_cmd}",
                                )
                    if payload and sport in TELNET_PORTS:
                        telnet_cmd = _extract_telnet_command(payload)
                        if telnet_cmd:
                            key = (src_ip, dst_ip, sport, telnet_cmd)
                            if key not in seen_telnet_commands:
                                seen_telnet_commands.add(key)
                                _emit_event(
                                    ts=ts,
                                    category="Telnet",
                                    summary="Telnet command",
                                    details=f"{src_ip} -> {target_ip}:{sport} {telnet_cmd}",
                                )
                    if payload and sport in FTP_CONTROL_PORTS:
                        ftp_cmd = _extract_ftp_command(_decode_payload_line(payload))
                        if ftp_cmd:
                            key = (src_ip, dst_ip, sport, ftp_cmd)
                            if key not in seen_ftp_commands:
                                seen_ftp_commands.add(key)
                                _emit_event(
                                    ts=ts,
                                    category="FTP",
                                    summary="FTP command",
                                    details=f"{src_ip} -> {target_ip}:{sport} {ftp_cmd}",
                                )
                    if sport in EMAIL_PORT_SERVICES:
                        service = EMAIL_PORT_SERVICES[sport]
                        flow_key = (src_ip, sport, "TCP", "inbound", service)
                        if flow_key not in seen_email_flows:
                            seen_email_flows.add(flow_key)
                            _emit_event(
                                ts=ts,
                                category="Email",
                                summary=f"{service} connection",
                                details=f"{src_ip} -> {target_ip}:{sport}",
                            )
                        first_line = _decode_payload_line(payload)
                        command = _extract_email_command(service, first_line)
                        if command:
                            action_key = (
                                src_ip,
                                sport,
                                "TCP",
                                "inbound",
                                service,
                                command,
                            )
                            if action_key not in seen_email_actions:
                                seen_email_actions.add(action_key)
                                _emit_event(
                                    ts=ts,
                                    category="Email",
                                    summary=f"{service} command",
                                    details=f"{src_ip} -> {target_ip}:{sport} {command}",
                                )
                    if sport in ldap_ports:
                        key = (src_ip, sport, "TCP", "inbound")
                        if key not in seen_ldap_flows:
                            seen_ldap_flows.add(key)
                            _emit_event(
                                ts=ts,
                                category="LDAP",
                                summary="LDAP connection",
                                details=f"{src_ip} -> {target_ip}:{sport}",
                            )
                    if sport in domain_ports:
                        key = (src_ip, sport, "TCP", "inbound")
                        if key not in seen_domain_flows:
                            seen_domain_flows.add(key)
                            _emit_event(
                                ts=ts,
                                category="MS Domain",
                                summary="Domain service access",
                                details=f"{src_ip} -> {target_ip}:{sport}",
                            )

            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp_layer = pkt[UDP]  # type: ignore[index]
                sport = int(getattr(udp_layer, "sport", 0) or 0)
                dport = int(getattr(udp_layer, "dport", 0) or 0)
                payload = None
                try:
                    payload = bytes(udp_layer.payload)
                except Exception:
                    payload = None
                if src_ip == target_ip or dst_ip == target_ip:
                    port_key = dport if src_ip == target_ip else sport
                    if port_key:
                        counter_inc(port_counts, port_key)
                        proto = OT_PORT_PROTOCOLS.get(port_key)
                        if proto:
                            ot_protocol_counts[proto] += 1
                            direction = "outbound" if src_ip == target_ip else "inbound"
                            peer_ip = dst_ip if src_ip == target_ip else src_ip
                            if peer_ip:
                                cmd_event_added = False
                                if proto == "DNP3" and port_key == DNP3_PORT:
                                    if _dnp3_frame_seen(payload):
                                        label = "DNP3 frame"
                                        key = (
                                            proto,
                                            direction,
                                            peer_ip,
                                            port_key,
                                            label,
                                        )
                                        if key not in seen_ot_commands:
                                            seen_ot_commands.add(key)
                                            _emit_event(
                                                ts=ts,
                                                category="DNP3",
                                                summary=label,
                                                details=f"{target_ip} -> {peer_ip}:{port_key}",
                                            )
                                            cmd_event_added = True
                                if not cmd_event_added:
                                    flow_key = (proto, direction, peer_ip, port_key)
                                    if flow_key not in seen_ot_flows:
                                        seen_ot_flows.add(flow_key)
                                        _emit_event(
                                            ts=ts,
                                            category=proto,
                                            summary=f"{proto} flow",
                                            details=f"{target_ip} -> {peer_ip}:{port_key}",
                                        )
                if src_ip == target_ip:
                    if dport:
                        key = (dst_ip, dport)
                        if key not in seen_udp_flows:
                            seen_udp_flows.add(key)
                            _emit_event(
                                ts=ts,
                                category="Connection",
                                summary="UDP flow",
                                details=f"{target_ip} -> {dst_ip}:{dport}",
                            )
                        rpc_type = _rpc_packet_type(payload)
                        if rpc_type and dport in {135, 445, 593}:
                            key = (src_ip, dst_ip, dport, rpc_type)
                            if key not in seen_rpc_events:
                                seen_rpc_events.add(key)
                                _emit_event(
                                    ts=ts,
                                    category="RPC",
                                    summary=f"RPC {rpc_type}",
                                    details=f"{target_ip} -> {dst_ip}:{dport}",
                                )
                        if dport in {137, 138, 139}:
                            action, name = _nbns_info(pkt)
                            key = ("outbound", action, name)
                            if key not in seen_nbns_events:
                                seen_nbns_events.add(key)
                                _emit_event(
                                    ts=ts,
                                    category="NetBIOS",
                                    summary=action,
                                    details=f"{target_ip} -> {dst_ip}:{dport} {name}",
                                )
                        if dport in {161, 162}:
                            snmp_type = _snmp_pdu_type(payload)
                            if snmp_type:
                                key = (src_ip, dst_ip, dport, snmp_type)
                                if key not in seen_snmp_events:
                                    seen_snmp_events.add(key)
                                    _emit_event(
                                        ts=ts,
                                        category="SNMP",
                                        summary=f"SNMP {snmp_type}",
                                        details=f"{target_ip} -> {dst_ip}:{dport}",
                                    )
                        if dport in ldap_ports:
                            key = (dst_ip, dport, "UDP", "outbound")
                            if key not in seen_ldap_flows:
                                seen_ldap_flows.add(key)
                                _emit_event(
                                    ts=ts,
                                    category="LDAP",
                                    summary="LDAP activity",
                                    details=f"{target_ip} -> {dst_ip}:{dport}",
                                )
                        if dport in domain_ports:
                            key = (dst_ip, dport, "UDP", "outbound")
                            if key not in seen_domain_flows:
                                seen_domain_flows.add(key)
                                _emit_event(
                                    ts=ts,
                                    category="MS Domain",
                                    summary="Domain service activity",
                                    details=f"{target_ip} -> {dst_ip}:{dport}",
                                )
                elif dst_ip == target_ip:
                    rpc_type = _rpc_packet_type(payload)
                    if rpc_type and sport in {135, 445, 593}:
                        key = (src_ip, dst_ip, sport, rpc_type)
                        if key not in seen_rpc_events:
                            seen_rpc_events.add(key)
                            _emit_event(
                                ts=ts,
                                category="RPC",
                                summary=f"RPC {rpc_type}",
                                details=f"{src_ip} -> {target_ip}:{sport}",
                            )
                    if sport in {137, 138, 139}:
                        action, name = _nbns_info(pkt)
                        key = ("inbound", action, name)
                        if key not in seen_nbns_events:
                            seen_nbns_events.add(key)
                            _emit_event(
                                ts=ts,
                                category="NetBIOS",
                                summary=action,
                                details=f"{src_ip} -> {target_ip}:{sport} {name}",
                            )
                    if sport in {161, 162}:
                        snmp_type = _snmp_pdu_type(payload)
                        if snmp_type:
                            key = (src_ip, dst_ip, sport, snmp_type)
                            if key not in seen_snmp_events:
                                seen_snmp_events.add(key)
                                _emit_event(
                                    ts=ts,
                                    category="SNMP",
                                    summary=f"SNMP {snmp_type}",
                                    details=f"{src_ip} -> {target_ip}:{sport}",
                                )
                    if sport in ldap_ports:
                        key = (src_ip, sport, "UDP", "inbound")
                        if key not in seen_ldap_flows:
                            seen_ldap_flows.add(key)
                            _emit_event(
                                ts=ts,
                                category="LDAP",
                                summary="LDAP activity",
                                details=f"{src_ip} -> {target_ip}:{sport}",
                            )
                    if sport in domain_ports:
                        key = (src_ip, sport, "UDP", "inbound")
                        if key not in seen_domain_flows:
                            seen_domain_flows.add(key)
                            _emit_event(
                                ts=ts,
                                category="MS Domain",
                                summary="Domain service activity",
                                details=f"{src_ip} -> {target_ip}:{sport}",
                            )
    finally:
        status.finish()
        reader.close()

    for art in artifacts_for_ip:
        ts = index_ts.get(art.packet_index)
        details = f"{art.protocol} {art.filename} ({art.file_type}) {art.src_ip} -> {art.dst_ip}"
        category = "File Transfer"
        if art.protocol.upper().startswith("SMB"):
            category = "SMB"
        dedupe_key = (
            "file-artifact",
            art.protocol,
            art.filename,
            art.file_type,
            art.src_ip,
            art.dst_ip,
            art.packet_index or 0,
        )
        _emit_event(
            ts=ts,
            category=category,
            summary="File artifact",
            details=details,
            dedupe_key=dedupe_key,
            packet_index=art.packet_index,
            source="files",
        )
        if art.dst_ip == target_ip:
            file_key = (
                art.protocol,
                art.src_ip,
                art.dst_ip,
                art.filename,
                art.file_type,
            )
            if file_key not in seen_file_downloads:
                seen_file_downloads.add(file_key)
                file_downloads.append(
                    FileDownloadDetail(
                        ts=ts,
                        packet_number=art.packet_index,
                        protocol=art.protocol,
                        src_ip=art.src_ip,
                        dst_ip=art.dst_ip,
                        filename=art.filename,
                        file_type=art.file_type,
                        size_bytes=art.size_bytes,
                        hostname=art.hostname,
                        content_type=art.content_type,
                        sha256=art.sha256,
                        md5=art.md5,
                    )
                )

    smtp_cred_seen: set[tuple[int, str, str, str, str, str]] = set()
    for hit in creds_summary.hits:
        kind_upper = str(hit.kind or "").upper()
        if "SMTP" not in kind_upper:
            continue
        if hit.src_ip != target_ip and hit.dst_ip != target_ip:
            continue
        secret_text = str(hit.secret or "").strip()
        user_text = str(hit.username or "").strip()
        evidence_text = str(hit.evidence or "").strip()
        dedupe_key = (
            int(hit.packet_number or 0),
            str(hit.src_ip),
            str(hit.dst_ip),
            str(hit.kind),
            user_text,
            secret_text,
        )
        if dedupe_key in smtp_cred_seen:
            continue
        smtp_cred_seen.add(dedupe_key)
        packet_ts = index_ts.get(int(hit.packet_number or 0))
        if packet_ts is None:
            packet_ts = hit.ts
        details = (
            f"{hit.src_ip} -> {hit.dst_ip} {hit.protocol} "
            f"{hit.kind} user={user_text or '-'} secret={secret_text or '-'}"
        )
        if evidence_text:
            details = f"{details} evidence={evidence_text}"
        _emit_event(
            ts=packet_ts,
            category="Email",
            summary="SMTP credential artifact",
            details=details,
            dedupe_key=("smtp-cred",) + dedupe_key,
            packet_index=hit.packet_number,
            source="creds",
        )

    for dst_ip, ports in scan_ports.items():
        if len(ports) >= 100:
            first = scan_first.get(dst_ip)
            last = scan_last.get(dst_ip, first)
            duration = "-"
            if first is not None and last is not None:
                duration = f"{max(0.0, last - first):.1f}s"
            _emit_event(
                ts=last,
                category="Recon",
                summary="Potential port scan",
                details=f"{target_ip} -> {dst_ip} touched {len(ports)} ports over {duration}",
            )

    for (
        client_ip,
        server_ip,
        client_port,
        server_port,
    ), handshakes in tcp_handshakes.items():
        for handshake in handshakes:
            if handshake["syn"] is None or handshake["synack"] is None:
                continue
            if handshake["ack"] is not None:
                continue
            detail = (
                f"{client_ip}:{client_port} -> {server_ip}:{server_port} "
                "(SYN/SYN-ACK seen, final ACK missing)"
            )
            dedupe_key = (
                "tcp-handshake-incomplete",
                client_ip,
                server_ip,
                client_port,
                server_port,
                handshake["syn"],
                handshake["synack"],
            )
            _emit_event(
                ts=handshake["synack"],
                category="Connection",
                summary="TCP handshake incomplete",
                details=detail,
                dedupe_key=dedupe_key,
            )

    if "DNP3" in ot_protocol_counts:
        dnp3_summary = _busy("DNP3", analyze_dnp3, path, show_status=False)
        errors.extend(dnp3_summary.errors)
        seen_msgs: set[tuple[str, str, str, int, int]] = set()
        for msg in dnp3_summary.messages:
            if msg.src_ip != target_ip and msg.dst_ip != target_ip:
                continue
            key = (msg.src_ip, msg.dst_ip, msg.func_name, msg.src_addr, msg.dst_addr)
            if key in seen_msgs:
                continue
            seen_msgs.add(key)
            _emit_event(
                ts=msg.ts,
                category="DNP3",
                summary=f"DNP3 {msg.func_name}",
                details=f"{msg.src_ip} -> {msg.dst_ip} addr {msg.src_addr}->{msg.dst_addr}",
            )
            if len(seen_msgs) >= 200:
                break
        for anomaly in dnp3_summary.anomalies:
            if anomaly.src != target_ip and anomaly.dst != target_ip:
                continue
            _emit_event(
                ts=anomaly.ts,
                category="DNP3",
                summary=anomaly.title,
                details=f"{anomaly.description} ({anomaly.src} -> {anomaly.dst})",
                source="dnp3",
            )

    if "IEC-104" in ot_protocol_counts:
        iec_summary = _busy("IEC-104", analyze_iec104, path, show_status=False)
        errors.extend(iec_summary.errors)
        for anomaly in iec_summary.anomalies:
            if anomaly.src != target_ip and anomaly.dst != target_ip:
                continue
            _emit_event(
                ts=anomaly.ts,
                category="IEC-104",
                summary=anomaly.title,
                details=f"{anomaly.description} ({anomaly.src} -> {anomaly.dst})",
                source="iec104",
            )
        for artifact in iec_summary.artifacts:
            if artifact.src != target_ip and artifact.dst != target_ip:
                continue
            _emit_event(
                ts=artifact.ts,
                category="IEC-104",
                summary=f"IEC-104 artifact ({artifact.kind})",
                details=f"{artifact.detail} ({artifact.src} -> {artifact.dst})",
                source="iec104",
            )
        if iec_summary.command_events:
            seen_cmds: set[tuple[str, str, str, int]] = set()
            for cmd_event in iec_summary.command_events:
                if cmd_event.src != target_ip and cmd_event.dst != target_ip:
                    continue
                key = (
                    cmd_event.src,
                    cmd_event.dst,
                    cmd_event.command,
                    int(cmd_event.ts or 0),
                )
                if key in seen_cmds:
                    continue
                seen_cmds.add(key)
                _emit_event(
                    ts=cmd_event.ts,
                    category="IEC-104",
                    summary=f"IEC-104 {cmd_event.command}",
                    details=f"{cmd_event.src} -> {cmd_event.dst}",
                    source="iec104",
                )

    if "S7" in ot_protocol_counts:
        s7_summary = _busy("S7", analyze_s7, path, show_status=False)
        errors.extend(s7_summary.errors)
        for anomaly in s7_summary.anomalies:
            if anomaly.src != target_ip and anomaly.dst != target_ip:
                continue
            _emit_event(
                ts=anomaly.ts,
                category="S7",
                summary=anomaly.title,
                details=f"{anomaly.description} ({anomaly.src} -> {anomaly.dst})",
                source="s7",
            )
        for artifact in s7_summary.artifacts:
            if artifact.src != target_ip and artifact.dst != target_ip:
                continue
            _emit_event(
                ts=artifact.ts,
                category="S7",
                summary=f"S7 artifact ({artifact.kind})",
                details=f"{artifact.detail} ({artifact.src} -> {artifact.dst})",
                source="s7",
            )
        if s7_summary.command_events:
            seen_cmds: set[tuple[str, str, str, int]] = set()
            for cmd_event in s7_summary.command_events:
                if cmd_event.src != target_ip and cmd_event.dst != target_ip:
                    continue
                key = (
                    cmd_event.src,
                    cmd_event.dst,
                    cmd_event.command,
                    int(cmd_event.ts or 0),
                )
                if key in seen_cmds:
                    continue
                seen_cmds.add(key)
                _emit_event(
                    ts=cmd_event.ts,
                    category="S7",
                    summary=f"S7 {cmd_event.command}",
                    details=f"{cmd_event.src} -> {cmd_event.dst}",
                    source="s7",
                )

    if categories is not None:
        events = [event for event in events if event.category in categories]
        if ot_protocol_counts:
            ot_protocol_counts = Counter(
                {
                    name: count
                    for name, count in ot_protocol_counts.items()
                    if name in categories
                }
            )

    events.sort(key=lambda item: (item.ts is None, item.ts))
    category_counts = Counter(event.category for event in events)
    duration = None
    if first_seen is not None and last_seen is not None:
        duration = max(0.0, last_seen - first_seen)
    ot_activity_bins, ot_bin_count = _compute_ot_activity_bins(
        events, first_seen, last_seen, bins=max(4, timeline_bins)
    )
    non_ot_bins, non_ot_bin_count = _compute_non_ot_activity_bins(
        events, first_seen, last_seen, bins=max(4, timeline_bins)
    )
    ot_risk_score, ot_risk_findings = _compute_ot_risk_posture(events, target_ip)
    ot_storyline = (
        []
        if timeline_storyline_off
        else _compute_ot_storyline(
            events,
            target_ip,
            dict(ot_protocol_counts),
            ot_risk_score,
            ot_risk_findings,
        )
    )
    enrichment = _build_timeline_enrichment(
        events, target_ip, file_downloads, ot_risk_score, ot_risk_findings
    )

    timeline_vt_results: dict[str, dict[str, object]] = {}
    timeline_vt_errors: list[str] = []
    if vt_lookup:
        api_key = os.environ.get("VT_API_KEY")
        if not api_key:
            timeline_vt_errors.append(
                "VT_API_KEY is not set; skipping VirusTotal lookups."
            )
        else:
            lookup_domains: list[str] = []
            seen_lookup: set[str] = set()
            for query in dns_queries:
                raw_name = str(query.name or "").strip(".").lower()
                if not raw_name:
                    continue
                for candidate in (raw_name, _dns_base_domain(raw_name)):
                    if not candidate or candidate in seen_lookup:
                        continue
                    seen_lookup.add(candidate)
                    lookup_domains.append(candidate)
            try:
                with build_statusbar(
                    path, enabled=show_status, desc="VirusTotal lookups"
                ) as vt_status:
                    vt_status.update(0)

                    def _vt_progress(done: int, total: int, _domain: str) -> None:
                        pct = 100 if total <= 0 else int((done / total) * 100)
                        vt_status.update(pct)

                    vt_results, vt_errors = _vt_lookup_domains(
                        lookup_domains, api_key, progress_cb=_vt_progress
                    )
                timeline_vt_results = {
                    str(name).strip().lower(): dict(result)
                    for name, result in dict(vt_results or {}).items()
                    if str(name).strip()
                }
                timeline_vt_errors = [
                    str(err) for err in list(vt_errors or []) if str(err).strip()
                ]
            except Exception as exc:
                timeline_vt_errors.append(
                    f"VirusTotal lookup failed: {type(exc).__name__}: {exc}"
                )

    return TimelineSummary(
        path=path,
        target_ip=target_ip,
        total_packets=total_packets,
        events=events,
        errors=errors + file_summary.errors + creds_summary.errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration=duration,
        category_counts=dict(category_counts),
        peer_counts=dict(peer_counts),
        port_counts=dict(port_counts),
        ot_protocol_counts=dict(ot_protocol_counts),
        ot_activity_bins=ot_activity_bins,
        ot_activity_bin_count=ot_bin_count,
        non_ot_activity_bins=non_ot_bins,
        non_ot_activity_bin_count=non_ot_bin_count,
        ot_risk_score=ot_risk_score,
        ot_risk_findings=ot_risk_findings,
        ot_storyline=ot_storyline,
        dns_queries=sorted(dns_queries, key=lambda item: (item.ts is None, item.ts)),
        file_downloads=sorted(
            file_downloads, key=lambda item: (item.ts is None, item.ts)
        ),
        analyst_verdict=str(enrichment.get("analyst_verdict", "")),
        analyst_confidence=str(enrichment.get("analyst_confidence", "low")),
        analyst_reasons=[
            str(v) for v in list(enrichment.get("analyst_reasons", []) or [])
        ],
        deterministic_checks={
            str(k): [str(v) for v in list(values or [])]
            for k, values in dict(
                enrichment.get("deterministic_checks", {}) or {}
            ).items()
        },
        sequence_timeline=list(enrichment.get("sequence_timeline", []) or []),
        sequence_violations=[
            str(v) for v in list(enrichment.get("sequence_violations", []) or [])
        ],
        beacon_candidates=list(enrichment.get("beacon_candidates", []) or []),
        auth_abuse_profiles=list(enrichment.get("auth_abuse_profiles", []) or []),
        lateral_movement_paths=list(
            enrichment.get("lateral_movement_paths", []) or []
        ),
        exfiltration_chains=list(enrichment.get("exfiltration_chains", []) or []),
        ot_impact_signals=list(enrichment.get("ot_impact_signals", []) or []),
        evidence_anchors=list(enrichment.get("evidence_anchors", []) or []),
        benign_context=[
            str(v) for v in list(enrichment.get("benign_context", []) or [])
        ],
        vt_lookup_enabled=bool(vt_lookup),
        vt_results=timeline_vt_results,
        vt_errors=timeline_vt_errors,
    )
