from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from collections import Counter, defaultdict
from functools import lru_cache
import ipaddress
import math
import re

from .pcap_cache import get_reader
from .utils import safe_float, counter_inc, setdict_add
from .icmp import analyze_icmp
from .dns import analyze_dns
from .beacon import analyze_beacons
from .files import analyze_files
from .modbus import analyze_modbus
from .dnp3 import analyze_dnp3
from .iec104 import analyze_iec104
from .bacnet import analyze_bacnet
from .enip import analyze_enip
from .profinet import analyze_profinet
from .s7 import analyze_s7
from .opc import analyze_opc
from .ethercat import analyze_ethercat
from .fins import analyze_fins
from .crimson import analyze_crimson
from .pcworx import analyze_pcworx
from .melsec import analyze_melsec
from .cip import analyze_cip
from .odesys import analyze_odesys
from .niagara import analyze_niagara
from .mms import analyze_mms
from .srtp import analyze_srtp
from .df1 import analyze_df1
from .pccc import analyze_pccc
from .csp import analyze_csp
from .modicon import analyze_modicon
from .yokogawa import analyze_yokogawa
from .honeywell import analyze_honeywell
from .mqtt import analyze_mqtt
from .coap import analyze_coap
from .hart import analyze_hart
from .prconos import analyze_prconos
from .iccp import analyze_iccp
from .creds import analyze_creds
from .http import analyze_http
from .tls import analyze_tls
from .ldap import analyze_ldap
from .kerberos import analyze_kerberos
from .ntlm import analyze_ntlm
from .syslog import analyze_syslog
from .arp import analyze_arp
from .dhcp import analyze_dhcp
from .exfil import analyze_exfil
from .quic import analyze_quic
from .encrypted_dns import analyze_encrypted_dns
from .vpn import analyze_vpn
from .smb import analyze_smb
from .rdp import analyze_rdp
from .winrm import analyze_winrm
from .wmic import analyze_wmic
from .powershell import analyze_powershell
from .ssh import analyze_ssh
from .smtp import analyze_smtp
from .rpc import analyze_rpc
from .snmp import analyze_snmp
from .tcp import analyze_tcp
from .udp import analyze_udp
from .goose import analyze_goose
from .sv import analyze_sv
from .ptp import analyze_ptp
from .lldp_dcp import analyze_lldp_dcp
from .opc_classic import analyze_opc_classic
from .ot_risk import compute_ot_risk_posture, dedupe_findings

ENIP_PORTS = {44818, 2222, 2221}
DNP3_PORT = 20000
ENIP_COMMAND_SET = {
    0x0001, 0x0004, 0x0063, 0x0064, 0x0065, 0x0066,
    0x0067, 0x0068, 0x0069, 0x006A, 0x006B, 0x006C,
    0x006D, 0x006F, 0x0070,
}
CIP_SERVICE_CODE_SET = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
    0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x4B, 0x4C, 0x4D, 0x4E,
    0x4F, 0x50, 0x51, 0x52, 0x54, 0x55, 0x5C, 0x73, 0x74, 0x75,
    0x91,
}

OT_PORTS: dict[int, str] = {
    319: "PTP",
    320: "PTP",
    502: "Modbus",
    20000: "DNP3",
    2404: "IEC-104",
    102: "S7/MMS/ICCP",
    44818: "EtherNet/IP",
    2222: "CIP/ENIP-IO",
    2221: "CIP Security",
    47808: "BACnet",
    34962: "Profinet",
    34963: "Profinet",
    34964: "Profinet",
    4840: "OPC UA",
    789: "Crimson",
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
    1883: "MQTT",
    8883: "MQTT-TLS",
    34378: "Yokogawa Vnet/IP",
    34379: "Yokogawa Vnet/IP",
    34380: "Yokogawa Vnet/IP",
}

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.layers.dns import DNS, DNSQR  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore
    DNS = None  # type: ignore
    DNSQR = None  # type: ignore
    Raw = None  # type: ignore


@dataclass(frozen=True)
class ThreatSummary:
    path: Path
    detections: list[dict[str, object]]
    errors: list[str]
    total_packets: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    duration: Optional[float] = None
    ot_protocol_counts: dict[str, int] = None  # type: ignore[assignment]
    public_ot_pairs: list[tuple[str, str, str]] = None  # type: ignore[assignment]
    ot_peer_internal: list[tuple[str, int]] = None  # type: ignore[assignment]
    ot_peer_external: list[tuple[str, int]] = None  # type: ignore[assignment]
    ot_risk_score: int = 0
    ot_risk_findings: list[str] = None  # type: ignore[assignment]
    storyline: list[str] = None  # type: ignore[assignment]


def merge_threats_summaries(summaries: list[ThreatSummary]) -> ThreatSummary:
    if not summaries:
        return ThreatSummary(
            path=Path("ALL_PCAPS"),
            detections=[],
            errors=[],
            total_packets=0,
            first_seen=None,
            last_seen=None,
            duration=None,
            ot_protocol_counts={},
            public_ot_pairs=[],
            ot_peer_internal=[],
            ot_peer_external=[],
            ot_risk_score=0,
            ot_risk_findings=[],
            storyline=[],
        )

    merged_detections: list[dict[str, object]] = []
    merged_errors: list[str] = []
    total_packets = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    ot_protocol_counts: Counter[str] = Counter()
    public_ot_pairs: list[tuple[str, str, str]] = []
    ot_peer_internal: Counter[str] = Counter()
    ot_peer_external: Counter[str] = Counter()
    risk_scores: list[int] = []
    risk_findings: list[str] = []
    storyline: list[str] = []
    for summary in summaries:
        merged_detections.extend(summary.detections)
        merged_errors.extend(summary.errors)
        total_packets += summary.total_packets
        if summary.first_seen is not None:
            first_seen = summary.first_seen if first_seen is None else min(first_seen, summary.first_seen)
        if summary.last_seen is not None:
            last_seen = summary.last_seen if last_seen is None else max(last_seen, summary.last_seen)
        ot_protocol_counts.update(summary.ot_protocol_counts or {})
        if summary.public_ot_pairs:
            public_ot_pairs.extend(summary.public_ot_pairs)
        if summary.ot_peer_internal:
            ot_peer_internal.update(dict(summary.ot_peer_internal))
        if summary.ot_peer_external:
            ot_peer_external.update(dict(summary.ot_peer_external))
        if summary.ot_risk_score:
            risk_scores.append(summary.ot_risk_score)
        if summary.ot_risk_findings:
            risk_findings.extend(summary.ot_risk_findings)
        if summary.storyline:
            storyline.extend(summary.storyline)

    deduped_errors = sorted(set(merged_errors))
    duration = None
    if first_seen is not None and last_seen is not None:
        duration = max(0.0, last_seen - first_seen)
    return ThreatSummary(
        path=Path("ALL_PCAPS"),
        detections=merged_detections,
        errors=deduped_errors,
        total_packets=total_packets,
        first_seen=first_seen,
        last_seen=last_seen,
        duration=duration,
        ot_protocol_counts=dict(ot_protocol_counts),
        public_ot_pairs=public_ot_pairs,
        ot_peer_internal=ot_peer_internal.most_common(10),
        ot_peer_external=ot_peer_external.most_common(10),
        ot_risk_score=max(risk_scores) if risk_scores else 0,
        ot_risk_findings=_dedupe_evidence(risk_findings, limit=6),
        storyline=_dedupe_evidence(storyline, limit=6),
    )


def _normalize_severity(value: object) -> str:
    text = str(value).upper()
    if text == "CRITICAL":
        return "critical"
    if text == "HIGH":
        return "high"
    if text in {"MEDIUM", "WARN", "WARNING"}:
        return "warning"
    return "info"


def _append_ot_anomalies(
    detections: list[dict[str, object]],
    source: str,
    anomalies: list[object],
) -> None:
    seen: set[tuple[str, str, str, str]] = set()
    for anomaly in anomalies:
        title = str(getattr(anomaly, "title", "OT Anomaly"))
        description = str(getattr(anomaly, "description", ""))
        src = str(getattr(anomaly, "src", "") or "")
        dst = str(getattr(anomaly, "dst", "") or "")
        key = (title, description, src, dst)
        if key in seen:
            continue
        seen.add(key)
        details = description
        if src or dst:
            details = f"{description} ({src or '?'} -> {dst or '?'})"
        item: dict[str, object] = {
            "source": source,
            "severity": _normalize_severity(getattr(anomaly, "severity", "info")),
            "summary": title,
            "details": details,
        }
        if src:
            item["top_sources"] = [(src, 1)]
        if dst:
            item["top_destinations"] = [(dst, 1)]
        detections.append(item)


def _append_detection_items(
    detections: list[dict[str, object]],
    source: str,
    items: list[dict[str, object]] | None,
) -> None:
    if not items:
        return
    for item in items:
        if not isinstance(item, dict):
            continue
        detections.append({
            "source": source,
            **item,
        })


def _append_anomaly_items(
    detections: list[dict[str, object]],
    source: str,
    anomalies: list[object] | None,
) -> None:
    if not anomalies:
        return
    for anomaly in anomalies:
        if isinstance(anomaly, dict):
            severity = _normalize_severity(anomaly.get("severity", "info"))
            summary = str(anomaly.get("title") or anomaly.get("summary") or "Anomaly")
            details = str(anomaly.get("details") or anomaly.get("description") or "")
            item: dict[str, object] = {
                "source": source,
                "severity": severity,
                "summary": summary,
                "details": details,
            }
            src = anomaly.get("src") or anomaly.get("source_ip")
            dst = anomaly.get("dst") or anomaly.get("dest_ip")
            if src:
                item["top_sources"] = [(str(src), 1)]
            if dst:
                item["top_destinations"] = [(str(dst), 1)]
            detections.append(item)
            continue

        title = str(getattr(anomaly, "title", "") or getattr(anomaly, "summary", "") or "Anomaly")
        details = str(getattr(anomaly, "details", "") or getattr(anomaly, "description", "") or "")
        severity = _normalize_severity(getattr(anomaly, "severity", "info"))
        item = {
            "source": source,
            "severity": severity,
            "summary": title,
            "details": details,
        }
        src = getattr(anomaly, "src", None)
        dst = getattr(anomaly, "dst", None)
        if src:
            item["top_sources"] = [(str(src), 1)]
        if dst:
            item["top_destinations"] = [(str(dst), 1)]
        detections.append(item)


_ARP_THREAT_SEVERITY = {
    "ARP Spoofing": "high",
    "Poisoning Indicators": "high",
    "Address Impersonation": "high",
    "Failover/Poisoning Signal": "high",
    "ARP Sweep": "warning",
    "Layer2 Flooding": "warning",
}


_DHCP_THREAT_SEVERITY = {
    "Rogue DHCP Server": "high",
    "DHCP Starvation": "high",
    "DHCP NAK Flooding": "warning",
    "Lease Brute Force/Enumeration": "warning",
    "DHCP Probing/Scanning": "warning",
    "DHCP Beaconing": "info",
    "DHCP Option Exfiltration": "warning",
    "Public DHCP Infrastructure Exposure": "high",
}


_OT_COMMAND_KEYWORDS: dict[str, str] = {
    "plcstop": "critical",
    "plccoldstart": "high",
    "plchotstart": "high",
    "stopdt": "high",
    "startdt": "warning",
    "stop": "high",
    "start": "warning",
    "restart": "high",
    "reset": "high",
    "download": "high",
    "upload": "warning",
    "program": "high",
    "firmware": "critical",
    "write": "warning",
    "setpoint": "high",
    "override": "high",
    "control": "warning",
    "delete": "high",
    "erase": "critical",
}


def _collect_ot_command_hits(commands: Counter[str]) -> tuple[Counter[str], str]:
    hits: Counter[str] = Counter()
    severity_rank = {"critical": 0, "high": 1, "warning": 2, "info": 3}
    max_sev = "info"
    for cmd, count in commands.items():
        cmd_lower = str(cmd).lower()
        for token, sev in _OT_COMMAND_KEYWORDS.items():
            if token in cmd_lower:
                hits[cmd] += int(count)
                if severity_rank.get(sev, 99) < severity_rank.get(max_sev, 99):
                    max_sev = sev
                break
    return hits, max_sev


def _counter_total(value: object) -> int:
    if isinstance(value, Counter):
        return int(sum(value.values()))
    return 0


def _protocol_packet_count(summary: object) -> int:
    packet_keys = [
        "enip_packets",
        "cip_packets",
        "modbus_packets",
        "dnp3_packets",
        "iec104_packets",
        "bacnet_packets",
        "profinet_packets",
        "s7_packets",
        "opc_packets",
        "ethercat_packets",
        "fins_packets",
        "crimson_packets",
        "pcworx_packets",
        "melsec_packets",
        "odesys_packets",
        "niagara_packets",
        "mms_packets",
        "srtp_packets",
        "df1_packets",
        "pccc_packets",
        "csp_packets",
        "modicon_packets",
        "yokogawa_packets",
        "honeywell_packets",
        "mqtt_packets",
        "coap_packets",
        "hart_packets",
        "prconos_packets",
        "iccp_packets",
    ]
    for key in packet_keys:
        value = getattr(summary, key, None)
        if isinstance(value, int) and value > 0:
            return value

    for key, value in vars(summary).items():
        if key.endswith("_packets") and key != "total_packets" and isinstance(value, int) and value > 0:
            return value
    return 0


def _ot_presence_confident(source: str, summary: object, anomalies: list[object]) -> bool:
    packet_count = _protocol_packet_count(summary)
    requests = int(getattr(summary, "requests", 0) or 0)
    responses = int(getattr(summary, "responses", 0) or 0)
    artifacts_count = len(getattr(summary, "artifacts", []) or [])
    anomalies_count = len(anomalies)

    semantic_signal = 0
    semantic_signal += _counter_total(getattr(summary, "enip_commands", Counter()))
    semantic_signal += _counter_total(getattr(summary, "cip_services", Counter()))
    semantic_signal += _counter_total(getattr(summary, "suspicious_services", Counter()))
    semantic_signal += _counter_total(getattr(summary, "high_risk_services", Counter()))
    semantic_signal += _counter_total(getattr(summary, "status_codes", Counter()))

    if source in {"CIP", "EtherNet/IP"}:
        session_count = len(getattr(summary, "sessions", Counter()) or [])
        identity_count = len(getattr(summary, "identities", []) or [])
        if packet_count >= 12 and semantic_signal >= 8 and (requests + responses) >= 8:
            return True
        if packet_count >= 8 and session_count >= 2 and semantic_signal >= 6:
            return True
        if packet_count >= 6 and identity_count >= 1 and semantic_signal >= 4:
            return True
        if packet_count >= 10 and anomalies_count >= 3 and semantic_signal >= 8:
            return True
        return False

    if packet_count >= 8:
        return True
    if packet_count >= 4 and anomalies_count >= 3:
        return True
    if packet_count >= 4 and artifacts_count >= 5:
        return True
    return False


def _payload_bytes(pkt) -> bytes:
    if Raw is not None and pkt.haslayer(Raw):
        try:
            return bytes(pkt[Raw].load)
        except Exception:
            return b""
    if TCP is not None and pkt.haslayer(TCP):
        try:
            return bytes(pkt[TCP].payload)
        except Exception:
            return b""
    if UDP is not None and pkt.haslayer(UDP):
        try:
            return bytes(pkt[UDP].payload)
        except Exception:
            return b""
    return b""


def _strict_enip_cip_marker(payload: bytes) -> tuple[bool, bool]:
    if len(payload) < 24:
        return False, False

    command = int.from_bytes(payload[0:2], "little")
    if command not in ENIP_COMMAND_SET:
        return False, False

    length = int.from_bytes(payload[2:4], "little")
    if length <= 0 or length > len(payload) - 24:
        return False, False

    encap_data = payload[24:24 + length]
    if not encap_data:
        return True, False

    cip_like = False
    if command in {0x006F, 0x0070} and len(encap_data) >= 10:
        scan = encap_data[: min(96, len(encap_data))]
        for idx in range(len(scan)):
            if (scan[idx] & 0x7F) in CIP_SERVICE_CODE_SET:
                cip_like = True
                break

    return True, cip_like


def _strict_dnp3_marker(payload: bytes) -> bool:
    if len(payload) < 10:
        return False
    idx = payload.find(b"\x05\x64")
    if idx == -1 or len(payload) - idx < 10:
        return False
    frame_len = int(payload[idx + 2])
    return 5 <= frame_len <= 255


AUTH_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    389: "LDAP",
    445: "SMB",
    3389: "RDP",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
}

LATERAL_PORTS: dict[int, str] = {
    135: "MSRPC",
    139: "NetBIOS-SSN",
    445: "SMB",
    3389: "RDP",
    5985: "WinRM",
    5986: "WinRM TLS",
    22: "SSH",
    5900: "VNC",
    1433: "MSSQL",
}

WEB_PORTS = {80, 443, 8080, 8000, 8443}

FAILED_AUTH_PATTERNS = [
    "authentication failed",
    "login failed",
    "invalid password",
    "incorrect password",
    "access denied",
    "535 5.7.8",
    "-err",
    "auth failed",
    "authorization failed",
]

SUSPICIOUS_PAYLOAD_MARKERS = [
    "powershell",
    "cmd.exe",
    "/bin/sh",
    "mimikatz",
    "whoami",
    "net user",
    "certutil",
    "wget ",
    "curl ",
    "nc ",
]

FAILED_AUTH_PATTERNS_BYTES = [pattern.encode("utf-8", errors="ignore") for pattern in FAILED_AUTH_PATTERNS]
SUSPICIOUS_PAYLOAD_MARKERS_BYTES = [pattern.encode("utf-8", errors="ignore") for pattern in SUSPICIOUS_PAYLOAD_MARKERS]


@lru_cache(maxsize=100000)
def _is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except Exception:
        return False


@lru_cache(maxsize=100000)
def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except Exception:
        return False


def _ot_risk_posture_from_detections(
    detections: list[dict[str, object]],
    public_ot_flows: int,
    control_hits: int,
) -> tuple[int, list[str]]:
    high_sev_ot = 0
    high_sev_general = 0
    for item in detections:
        source = str(item.get("source", "")).lower()
        severity = str(item.get("severity", "info")).lower()
        summary = str(item.get("summary", "")).lower()
        if severity not in {"high", "critical"}:
            continue
        is_ot = "ot/ics" in source or any(token in summary for token in ("modbus", "dnp3", "iec-104", "s7", "enip", "cip", "opc", "bacnet"))
        if is_ot:
            high_sev_ot += 1
        else:
            high_sev_general += 1

    score, findings = compute_ot_risk_posture(
        public_ot_flows=public_ot_flows,
        control_hits=control_hits,
        anomaly_hits=high_sev_ot,
        high_sev_ot=high_sev_ot,
        high_sev_general=high_sev_general,
    )
    return score, dedupe_findings(findings, limit=6)


def _threats_storyline(
    detections: list[dict[str, object]],
    ot_protocol_counts: dict[str, int],
    risk_score: int,
    risk_findings: list[str],
) -> list[str]:
    if not detections:
        return ["No notable threat detections observed."]
    top_protocols = sorted(ot_protocol_counts.items(), key=lambda item: (-item[1], item[0]))[:4]
    storyline: list[str] = []
    if top_protocols:
        proto_text = ", ".join(f"{name} ({count})" for name, count in top_protocols)
        storyline.append(f"OT protocols present: {proto_text}.")
    if risk_score:
        storyline.append(f"OT risk posture scored {risk_score}/100.")
    if risk_findings:
        storyline.append("Key signals: " + "; ".join(risk_findings[:3]))

    severity_order = {"critical": 0, "high": 1, "warning": 2, "info": 3}
    sorted_dets = sorted(
        detections,
        key=lambda item: (severity_order.get(str(item.get("severity", "info")).lower(), 99)),
    )
    top = sorted_dets[:3]
    if top:
        examples = "; ".join(str(item.get("summary", "")) for item in top if item.get("summary"))
        if examples:
            storyline.append(f"Top detections: {examples}.")
    return storyline


def _tcp_is_syn(flags: object) -> bool:
    if isinstance(flags, int):
        return (flags & 0x02) != 0 and (flags & 0x10) == 0
    text = str(flags)
    return "S" in text and "A" not in text


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


def _dedupe_evidence(values: list[str], limit: int = 8) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        normalized = value.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        output.append(normalized)
        if len(output) >= limit:
            break
    return output


def _filename_from_summary(summary_text: str) -> str:
    prefix = "File extension/type mismatch:"
    if summary_text.startswith(prefix):
        return summary_text.split(":", 1)[1].strip()
    return ""


def _http_detection_evidence(item: dict[str, object], http_summary) -> list[str]:
    summary_text = str(item.get("summary", ""))
    evidence: list[str] = []

    if summary_text == "HTTP file type discrepancies":
        mismatch_downloads = [entry for entry in http_summary.downloads if entry.get("mismatch")]
        for entry in mismatch_downloads[:8]:
            filename = str(entry.get("filename", "-"))
            src = str(entry.get("src", "-"))
            dst = str(entry.get("dst", "-"))
            expected = str(entry.get("expected_type", "-"))
            detected = str(entry.get("detected_type", "-"))
            ctype = str(entry.get("content_type", "-") or "-")
            evidence.append(
                f"{filename} {src}->{dst} expected={expected} detected={detected} ctype={ctype}"
            )

    elif summary_text == "Suspicious file artifacts observed":
        for filename, count in http_summary.file_artifacts.most_common(8):
            evidence.append(f"{filename} ({count})")

    elif summary_text == "Potential tokens in HTTP referrers":
        for token, count in http_summary.referrer_token_counts.most_common(8):
            evidence.append(f"{token} ({count})")
        for referrer, host_counter in list(http_summary.referrer_request_host_counts.items())[:4]:
            top_hosts = ", ".join(f"{host}({host_count})" for host, host_count in host_counter.most_common(2))
            evidence.append(f"referrer={referrer} hosts={top_hosts}")

    elif summary_text == "Suspicious user agents observed":
        for agent, count in http_summary.user_agents.most_common(8):
            evidence.append(f"UA {agent} ({count})")

    elif summary_text == "Long URLs observed":
        long_urls = [url for url in http_summary.url_counts if len(url) > 200]
        for url in long_urls[:6]:
            evidence.append(url)

    elif summary_text == "High HTTP error rate":
        for code, count in http_summary.status_counts.most_common(6):
            if str(code).startswith(("4", "5")):
                evidence.append(f"HTTP {code}: {count}")

    if http_summary.host_counts:
        top_hosts = ", ".join(f"{host}({count})" for host, count in http_summary.host_counts.most_common(4))
        evidence.append(f"hosts={top_hosts}")
    return _dedupe_evidence(evidence, limit=10)


def _file_detection_evidence(item: dict[str, object], artifacts_by_name: dict[str, list[object]]) -> list[str]:
    summary_text = str(item.get("summary", ""))
    evidence: list[str] = []

    filename = _filename_from_summary(summary_text)
    if filename:
        for artifact in artifacts_by_name.get(filename.lower(), [])[:3]:
            evidence.append(
                f"{artifact.protocol} {artifact.src_ip}->{artifact.dst_ip} type={artifact.file_type} size={artifact.size_bytes or '-'}"
            )

    details_text = str(item.get("details", ""))
    if details_text:
        evidence.append(details_text)

    return _dedupe_evidence(evidence, limit=8)


def analyze_threats(path: Path, show_status: bool = True) -> ThreatSummary:
    errors: list[str] = []
    detections: list[dict[str, object]] = []
    public_ot_pairs: set[tuple[str, str, str]] = set()
    ot_peer_internal: Counter[str] = Counter()
    ot_peer_external: Counter[str] = Counter()

    # Aggregate detections from specialized modules
    icmp_summary = analyze_icmp(path, show_status=show_status)
    dns_summary = analyze_dns(path, show_status=show_status)
    beacon_summary = analyze_beacons(path, show_status=show_status)
    files_summary = analyze_files(path, show_status=show_status)
    http_summary = analyze_http(path, show_status=show_status)
    creds_summary = analyze_creds(path, show_status=show_status)
    tls_summary = analyze_tls(path, show_status=show_status)
    ldap_summary = analyze_ldap(path, show_status=show_status)
    kerberos_summary = analyze_kerberos(path, show_status=show_status)
    ntlm_summary = analyze_ntlm(path, show_status=show_status)
    syslog_summary = analyze_syslog(path, show_status=show_status)
    arp_summary = analyze_arp(path, show_status=show_status)
    dhcp_summary = analyze_dhcp(path, show_status=show_status)
    exfil_summary = analyze_exfil(path, show_status=show_status)
    quic_summary = analyze_quic(path, show_status=show_status)
    edns_summary = analyze_encrypted_dns(path, show_status=show_status)
    vpn_summary = analyze_vpn(path, show_status=show_status)
    smb_summary = analyze_smb(path, show_status=show_status)
    rdp_summary = analyze_rdp(path, show_status=show_status)
    winrm_summary = analyze_winrm(path, show_status=show_status)
    wmic_summary = analyze_wmic(path, show_status=show_status)
    powershell_summary = analyze_powershell(path, show_status=show_status)
    ssh_summary = analyze_ssh(path, show_status=show_status)
    smtp_summary = analyze_smtp(path, show_status=show_status)
    rpc_summary = analyze_rpc(path, show_status=show_status)
    snmp_summary = analyze_snmp(path, show_status=show_status)
    tcp_summary = analyze_tcp(path, show_status=show_status)
    udp_summary = analyze_udp(path, show_status=show_status)
    goose_summary = analyze_goose(path, show_status=show_status)
    sv_summary = analyze_sv(path, show_status=show_status)
    ptp_summary = analyze_ptp(path, show_status=show_status)
    lldp_summary = analyze_lldp_dcp(path, show_status=show_status)
    opc_classic_summary = analyze_opc_classic(path, show_status=show_status)

    artifacts_by_name: dict[str, list[object]] = defaultdict(list)
    for artifact in files_summary.artifacts:
        name = str(getattr(artifact, "filename", "") or "").lower()
        if name:
            artifacts_by_name[name].append(artifact)

    ot_summaries = {
        "Modbus": analyze_modbus(path, show_status=show_status),
        "DNP3": analyze_dnp3(path, show_status=show_status),
        "IEC-104": analyze_iec104(path, show_status=show_status),
        "BACnet": analyze_bacnet(path, show_status=show_status),
        "EtherNet/IP": analyze_enip(path, show_status=show_status),
        "Profinet": analyze_profinet(path, show_status=show_status),
        "S7": analyze_s7(path, show_status=show_status),
        "OPC UA": analyze_opc(path, show_status=show_status),
        "EtherCAT": analyze_ethercat(path, show_status=show_status),
        "FINS": analyze_fins(path, show_status=show_status),
        "Crimson": analyze_crimson(path, show_status=show_status),
        "PCWorx": analyze_pcworx(path, show_status=show_status),
        "MELSEC": analyze_melsec(path, show_status=show_status),
        "CIP": analyze_cip(path, show_status=show_status),
        "ODESYS": analyze_odesys(path, show_status=show_status),
        "Niagara": analyze_niagara(path, show_status=show_status),
        "MMS": analyze_mms(path, show_status=show_status),
        "SRTP": analyze_srtp(path, show_status=show_status),
        "DF1": analyze_df1(path, show_status=show_status),
        "PCCC": analyze_pccc(path, show_status=show_status),
        "CSP": analyze_csp(path, show_status=show_status),
        "Modicon": analyze_modicon(path, show_status=show_status),
        "Yokogawa": analyze_yokogawa(path, show_status=show_status),
        "Honeywell": analyze_honeywell(path, show_status=show_status),
        "MQTT": analyze_mqtt(path, show_status=show_status),
        "CoAP": analyze_coap(path, show_status=show_status),
        "HART-IP": analyze_hart(path, show_status=show_status),
        "ProConOS": analyze_prconos(path, show_status=show_status),
        "ICCP": analyze_iccp(path, show_status=show_status),
    }
    ot_protocol_counts: Counter[str] = Counter()

    ot_candidates: dict[str, list[object]] = {}
    for source, summary in ot_summaries.items():
        anomalies = getattr(summary, "anomalies", None)
        if isinstance(anomalies, list) and anomalies:
            ot_candidates[source] = anomalies
        for err in getattr(summary, "errors", []) or []:
            errors.append(f"{source}: {err}")

    for item in icmp_summary.detections:
        detections.append({
            "source": "ICMP",
            **item,
        })
    for item in dns_summary.detections:
        detections.append({
            "source": "DNS",
            **item,
        })
    for item in beacon_summary.detections:
        detections.append({
            "source": "Beacon",
            **item,
        })
    for item in http_summary.detections:
        enriched = {
            "source": "HTTP",
            **item,
        }
        http_evidence = _http_detection_evidence(enriched, http_summary)
        if http_evidence:
            enriched["evidence"] = http_evidence
        detections.append(enriched)

    _append_detection_items(detections, "TLS", tls_summary.detections)
    _append_detection_items(detections, "LDAP", ldap_summary.detections)
    _append_detection_items(detections, "Kerberos", kerberos_summary.detections)
    _append_detection_items(detections, "Syslog", syslog_summary.detections)
    _append_detection_items(detections, "Exfil", exfil_summary.detections)
    _append_detection_items(detections, "QUIC", quic_summary.detections)
    _append_detection_items(detections, "Encrypted DNS", edns_summary.detections)
    _append_detection_items(detections, "VPN", vpn_summary.detections)
    _append_detection_items(detections, "RDP", rdp_summary.detections)
    _append_detection_items(detections, "WinRM", winrm_summary.detections)
    _append_detection_items(detections, "WMIC", wmic_summary.detections)
    _append_detection_items(detections, "PowerShell", powershell_summary.detections)
    _append_detection_items(detections, "SSH", ssh_summary.detections)
    _append_detection_items(detections, "SMTP", smtp_summary.detections)
    _append_detection_items(detections, "RPC", rpc_summary.detections)
    _append_detection_items(detections, "SNMP", snmp_summary.detections)
    _append_detection_items(detections, "TCP", tcp_summary.detections)
    _append_detection_items(detections, "UDP", udp_summary.detections)
    _append_detection_items(detections, "GOOSE", goose_summary.detections)
    _append_detection_items(detections, "SV", sv_summary.detections)
    _append_detection_items(detections, "PTP", ptp_summary.detections)
    _append_detection_items(detections, "LLDP/DCP", lldp_summary.detections)
    _append_detection_items(detections, "OPC Classic", opc_classic_summary.detections)

    _append_anomaly_items(detections, "NTLM", ntlm_summary.anomalies)
    _append_anomaly_items(detections, "Syslog", syslog_summary.anomalies)
    _append_anomaly_items(detections, "SMB", smb_summary.anomalies)
    _append_anomaly_items(detections, "RDP", rdp_summary.anomalies)
    _append_anomaly_items(detections, "WinRM", winrm_summary.anomalies)
    _append_anomaly_items(detections, "WMIC", wmic_summary.anomalies)
    _append_anomaly_items(detections, "PowerShell", powershell_summary.anomalies)
    _append_anomaly_items(detections, "SSH", ssh_summary.anomalies)
    _append_anomaly_items(detections, "SMTP", smtp_summary.anomalies)
    _append_anomaly_items(detections, "RPC", rpc_summary.anomalies)
    _append_anomaly_items(detections, "SNMP", snmp_summary.anomalies)

    if smb_summary.lateral_movement:
        detections.append({
            "source": "SMB",
            "severity": "warning",
            "summary": "SMB lateral movement indicators",
            "details": f"{len(smb_summary.lateral_movement)} lateral movement signals.",
            "evidence": _dedupe_evidence(
                [str(item) for item in smb_summary.lateral_movement[:8]],
                limit=8,
            ),
        })
    if smb_summary.versions and smb_summary.versions.get("SMB1"):
        detections.append({
            "source": "SMB",
            "severity": "critical",
            "summary": "Legacy SMBv1 usage observed",
            "details": f"{smb_summary.versions.get('SMB1')} SMBv1 packet(s) detected.",
        })

    if arp_summary.threats:
        for threat, count in arp_summary.threats.items():
            detections.append({
                "source": "ARP",
                "severity": _ARP_THREAT_SEVERITY.get(threat, "warning"),
                "summary": threat,
                "details": f"{count} event(s) flagged.",
            })
    _append_anomaly_items(detections, "ARP", arp_summary.anomalies)

    if dhcp_summary.threat_summary:
        for threat, count in dhcp_summary.threat_summary.items():
            detections.append({
                "source": "DHCP",
                "severity": _DHCP_THREAT_SEVERITY.get(threat, "warning"),
                "summary": threat,
                "details": f"{count} event(s) flagged.",
            })
    _append_anomaly_items(detections, "DHCP", dhcp_summary.anomalies)

    if creds_summary.matches:
        hits_by_src: Counter[str] = Counter(hit.src_ip for hit in creds_summary.hits)
        hits_by_dst: Counter[str] = Counter(hit.dst_ip for hit in creds_summary.hits)
        cred_evidence: list[str] = []
        for hit in creds_summary.hits[:8]:
            secret = (hit.secret or "-")
            if len(secret) > 40:
                secret = f"{secret[:40]}..."
            cred_evidence.append(
                f"{hit.kind} {hit.src_ip}->{hit.dst_ip} user={hit.username or '-'} secret={secret} evidence={hit.evidence}"
            )

        detections.append({
            "source": "Creds",
            "severity": "critical" if creds_summary.matches >= 20 else "warning",
            "summary": "Credential exposure artifacts observed",
            "details": f"{creds_summary.matches} credential/token artifact(s) detected across {len(creds_summary.kind_counts)} method(s).",
            "top_sources": hits_by_src.most_common(5),
            "top_destinations": hits_by_dst.most_common(5),
            "evidence": _dedupe_evidence(cred_evidence, limit=8),
        })

    errors.extend(http_summary.errors)
    errors.extend(creds_summary.errors)
    errors.extend(tls_summary.errors)
    errors.extend(ldap_summary.errors)
    errors.extend(kerberos_summary.errors)
    errors.extend(ntlm_summary.errors)
    errors.extend(syslog_summary.errors)
    errors.extend(arp_summary.errors)
    errors.extend(dhcp_summary.errors)
    errors.extend(exfil_summary.errors)
    errors.extend(quic_summary.errors)
    errors.extend(edns_summary.errors)
    errors.extend(vpn_summary.errors)
    errors.extend(smb_summary.errors)
    errors.extend(rdp_summary.errors)
    errors.extend(winrm_summary.errors)
    errors.extend(wmic_summary.errors)
    errors.extend(powershell_summary.errors)
    errors.extend(ssh_summary.errors)
    errors.extend(smtp_summary.errors)
    errors.extend(rpc_summary.errors)
    errors.extend(snmp_summary.errors)
    errors.extend(tcp_summary.errors)
    errors.extend(udp_summary.errors)
    errors.extend(goose_summary.errors)
    errors.extend(sv_summary.errors)
    errors.extend(ptp_summary.errors)
    errors.extend(lldp_summary.errors)
    errors.extend(opc_classic_summary.errors)

    smb1_sources: Counter[str] = Counter()
    smb1_destinations: Counter[str] = Counter()
    smb1_detected = False
    for item in files_summary.detections:
        enriched = {
            "source": "Files",
            **item,
        }
        file_evidence = _file_detection_evidence(enriched, artifacts_by_name)
        if file_evidence:
            enriched["evidence"] = file_evidence
        detections.append(enriched)
        if str(item.get("summary", "")).lower().startswith("smbv1 detected"):
            smb1_detected = True
            for ip, count in item.get("top_sources", []) or []:
                smb1_sources[ip] += count
            for ip, count in item.get("top_destinations", []) or []:
                smb1_destinations[ip] += count

    for art in files_summary.artifacts:
        if str(getattr(art, "protocol", "")).upper() == "SMB1":
            smb1_detected = True
            if art.src_ip:
                smb1_sources[art.src_ip] += 1
            if art.dst_ip:
                smb1_destinations[art.dst_ip] += 1

    if beacon_summary.candidates:
        for candidate in beacon_summary.candidates[:10]:
            duration = 0.0
            if candidate.first_seen is not None and candidate.last_seen is not None:
                duration = max(0.0, candidate.last_seen - candidate.first_seen)
            if candidate.src_port and candidate.dst_port:
                proto_label = f"{candidate.proto}:{candidate.src_port}->{candidate.dst_port}"
            elif candidate.dst_port:
                proto_label = f"{candidate.proto}:{candidate.dst_port}"
            else:
                proto_label = candidate.proto
            detections.append({
                "source": "Beacon",
                "severity": "info",
                "summary": "Beacon candidate flow",
                "details": f"{candidate.src_ip} -> {candidate.dst_ip} ({proto_label}) {candidate.count} events, "
                           f"mean {candidate.mean_interval:.2f}s, jitter {candidate.jitter:.2f}, duration {duration:.0f}s, "
                           f"top interval {candidate.top_interval}s, avg bytes {candidate.avg_bytes:.0f}",
                "top_sources": [(candidate.src_ip, candidate.count)],
                "top_destinations": [(candidate.dst_ip, candidate.count)],
            })

    # Suspicious file download detection
    suspicious_exts = {
        ".exe", ".dll", ".ps1", ".bat", ".vbs", ".js", ".scr",
        ".sys", ".lnk", ".zip", ".rar", ".7z", ".iso", ".img",
    }
    suspicious_artifacts: list[dict[str, object]] = []
    src_counts_files: Counter[str] = Counter()
    dst_counts_files: Counter[str] = Counter()
    for art in files_summary.artifacts:
        fname = art.filename.lower()
        ext = f".{fname.split('.')[-1]}" if "." in fname else ""
        is_suspicious = ext in suspicious_exts
        if not is_suspicious and "extracted_pe" in fname:
            is_suspicious = True
        ftype = getattr(art, "file_type", "UNKNOWN")
        if ftype in ("EXE/DLL", "ARCHIVE"):
            is_suspicious = True
        if is_suspicious:
            suspicious_artifacts.append({
                "filename": art.filename,
                "protocol": art.protocol,
                "file_type": ftype,
                "src": art.src_ip,
                "dst": art.dst_ip,
                "size": art.size_bytes,
            })
            if art.src_ip:
                src_counts_files[art.src_ip] += 1
            if art.dst_ip:
                dst_counts_files[art.dst_ip] += 1

    if suspicious_artifacts:
        suspicious_evidence = [
            f"{str(entry.get('filename', '-'))} {str(entry.get('src', '-'))}->{str(entry.get('dst', '-'))} {str(entry.get('file_type', 'UNKNOWN'))}"
            for entry in suspicious_artifacts[:10]
        ]
        detections.append({
            "source": "Files",
            "severity": "warning",
            "summary": "Potential malicious file downloads detected",
            "details": f"{len(suspicious_artifacts)} suspicious file(s) observed (executables/scripts/archives).",
            "top_sources": src_counts_files.most_common(3),
            "top_destinations": dst_counts_files.most_common(3),
            "evidence": _dedupe_evidence(suspicious_evidence, limit=10),
        })
        for item in suspicious_artifacts[:10]:
            fname = str(item.get("filename", ""))
            ftype = str(item.get("file_type", "UNKNOWN"))
            ext = f".{fname.lower().split('.')[-1]}" if "." in fname else ""
            expected_type = None
            if ext in {".exe", ".dll", ".sys", ".scr"}:
                expected_type = "EXE/DLL"
            elif ext in {".zip", ".rar", ".7z", ".iso", ".img"}:
                expected_type = "ARCHIVE"
            elif ext in {".pdf"}:
                expected_type = "PDF"
            elif ext in {".doc", ".docx"}:
                expected_type = "DOC"
            elif ext in {".xls", ".xlsx"}:
                expected_type = "XLS"
            elif ext in {".ppt", ".pptx"}:
                expected_type = "PPT"
            elif ext in {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff"}:
                expected_type = "IMAGE"
            elif ext in {".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm"}:
                expected_type = "VIDEO"

            mismatch = False
            if expected_type and ftype not in ("UNKNOWN", expected_type):
                mismatch = True

            detections.append({
                "source": "Files",
                "severity": "high" if mismatch else "info",
                "summary": "Suspicious file artifact" + (" (type mismatch)" if mismatch else ""),
                "details": f"{item['protocol']} {item['filename']} ({item['file_type']}) {item['src']} -> {item['dst']}",
            })

    if smb1_detected:
        detections.append({
            "source": "Files",
            "severity": "critical",
            "summary": "SMBv1 hosts detected",
            "details": "Hosts observed communicating with legacy SMBv1.",
            "top_sources": smb1_sources.most_common(10),
            "top_destinations": smb1_destinations.most_common(10),
        })

    reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)

    src_counts: Counter[str] = Counter()
    dst_counts: Counter[str] = Counter()
    syn_counts: Counter[str] = Counter()
    udp_target_counts: Counter[str] = Counter()

    pair_ports: dict[tuple[str, str], set[int]] = defaultdict(set)
    src_ports: dict[str, set[int]] = defaultdict(set)
    src_targets: dict[str, set[str]] = defaultdict(set)
    auth_attempts: Counter[tuple[str, str, str]] = Counter()
    auth_failures: Counter[tuple[str, str, str]] = Counter()
    lateral_targets: dict[str, set[str]] = defaultdict(set)

    outbound_bytes_public: Counter[tuple[str, str]] = Counter()
    outbound_public_dests_by_src: dict[str, set[str]] = defaultdict(set)
    suspicious_payload_sources: Counter[str] = Counter()

    dns_tunnel_sources: Counter[str] = Counter()
    dns_txt_query_sources: Counter[str] = Counter()
    strict_ot_counts: Counter[str] = Counter()
    strict_ot_pairs: dict[str, set[tuple[str, str]]] = defaultdict(set)
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    total_packets = 0
    control_command_total = 0

    try:
        for pkt in reader:
            total_packets += 1
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            src_ip = None
            dst_ip = None
            if IP is not None and pkt.haslayer(IP):
                ip_layer = pkt[IP]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))
            elif IPv6 is not None and pkt.haslayer(IPv6):
                ip_layer = pkt[IPv6]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))

            if not src_ip or not dst_ip:
                continue

            counter_inc(src_counts, src_ip)
            counter_inc(dst_counts, dst_ip)
            setdict_add(src_targets, src_ip, dst_ip)

            pkt_len = int(len(pkt)) if hasattr(pkt, "__len__") else 0
            if _is_private_ip(src_ip) and _is_public_ip(dst_ip):
                outbound_bytes_public[(src_ip, dst_ip)] += pkt_len
                setdict_add(outbound_public_dests_by_src, src_ip, dst_ip)

            payload_data = _payload_bytes(pkt)
            payload_lower = payload_data.lower() if payload_data else b""
            if payload_lower and any(marker in payload_lower for marker in SUSPICIOUS_PAYLOAD_MARKERS_BYTES):
                counter_inc(suspicious_payload_sources, src_ip)

            if DNS is not None and DNSQR is not None and pkt.haslayer(DNS):
                dns_layer = pkt[DNS]
                if int(getattr(dns_layer, "qr", 0) or 0) == 0:
                    qd = getattr(dns_layer, "qd", None)
                    if qd is not None:
                        qname_raw = getattr(qd, "qname", b"")
                        qname = qname_raw.decode("utf-8", errors="ignore") if isinstance(qname_raw, (bytes, bytearray)) else str(qname_raw)
                        qname = qname.strip(".").lower()
                        qtype = int(getattr(qd, "qtype", 0) or 0)
                        labels = [label for label in qname.split(".") if label]
                        longest_label = max((len(label) for label in labels), default=0)
                        if len(qname) >= 60 or longest_label >= 32 or _entropy(qname) >= 3.8:
                            counter_inc(dns_tunnel_sources, src_ip)
                        if qtype == 16:
                            counter_inc(dns_txt_query_sources, src_ip)

            if TCP is not None and pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                dport = int(getattr(tcp_layer, "dport", 0) or 0)
                sport = int(getattr(tcp_layer, "sport", 0) or 0)

                if (dport in OT_PORTS or sport in OT_PORTS):
                    proto = OT_PORTS.get(dport) or OT_PORTS.get(sport) or "OT"
                    if _is_public_ip(src_ip) or _is_public_ip(dst_ip):
                        public_ot_pairs.add((proto, src_ip, dst_ip))
                        if _is_public_ip(src_ip):
                            counter_inc(ot_peer_external, src_ip)
                        if _is_public_ip(dst_ip):
                            counter_inc(ot_peer_external, dst_ip)
                    if _is_private_ip(src_ip):
                        counter_inc(ot_peer_internal, src_ip)
                    if _is_private_ip(dst_ip):
                        counter_inc(ot_peer_internal, dst_ip)
                    counter_inc(ot_protocol_counts, proto)

                if sport in ENIP_PORTS or dport in ENIP_PORTS:
                    enip_ok, cip_ok = _strict_enip_cip_marker(payload_data)
                    if enip_ok:
                        strict_ot_counts["EtherNet/IP"] += 1
                        setdict_add(strict_ot_pairs, "EtherNet/IP", (src_ip, dst_ip))
                    if cip_ok:
                        strict_ot_counts["CIP"] += 1
                        setdict_add(strict_ot_pairs, "CIP", (src_ip, dst_ip))

                if sport == DNP3_PORT or dport == DNP3_PORT:
                    if _strict_dnp3_marker(payload_data):
                        strict_ot_counts["DNP3"] += 1
                        setdict_add(strict_ot_pairs, "DNP3", (src_ip, dst_ip))

                if dport:
                    setdict_add(pair_ports, (src_ip, dst_ip), dport)
                    setdict_add(src_ports, src_ip, dport)

                flags = getattr(tcp_layer, "flags", None)
                if flags is not None and _tcp_is_syn(flags):
                    counter_inc(syn_counts, src_ip)
                    if dport in AUTH_PORTS:
                        counter_inc(auth_attempts, (src_ip, dst_ip, AUTH_PORTS[dport]))

                service = AUTH_PORTS.get(dport) or AUTH_PORTS.get(sport)
                if service and payload_lower and any(pattern in payload_lower for pattern in FAILED_AUTH_PATTERNS_BYTES):
                    counter_inc(auth_failures, (src_ip, dst_ip, service))

                lateral_service = LATERAL_PORTS.get(dport)
                if lateral_service and _is_private_ip(src_ip) and _is_private_ip(dst_ip):
                    setdict_add(lateral_targets, src_ip, dst_ip)

                if dport in WEB_PORTS and payload_lower.startswith((b"post ", b"put ")):
                    if _is_private_ip(src_ip) and _is_public_ip(dst_ip):
                        outbound_bytes_public[(src_ip, dst_ip)] += pkt_len

            if UDP is not None and pkt.haslayer(UDP):
                udp_layer = pkt[UDP]
                dport = int(getattr(udp_layer, "dport", 0) or 0)
                sport = int(getattr(udp_layer, "sport", 0) or 0)

                if (dport in OT_PORTS or sport in OT_PORTS):
                    proto = OT_PORTS.get(dport) or OT_PORTS.get(sport) or "OT"
                    if _is_public_ip(src_ip) or _is_public_ip(dst_ip):
                        public_ot_pairs.add((proto, src_ip, dst_ip))
                        if _is_public_ip(src_ip):
                            counter_inc(ot_peer_external, src_ip)
                        if _is_public_ip(dst_ip):
                            counter_inc(ot_peer_external, dst_ip)
                    if _is_private_ip(src_ip):
                        counter_inc(ot_peer_internal, src_ip)
                    if _is_private_ip(dst_ip):
                        counter_inc(ot_peer_internal, dst_ip)
                    counter_inc(ot_protocol_counts, proto)

                if sport in ENIP_PORTS or dport in ENIP_PORTS:
                    enip_ok, cip_ok = _strict_enip_cip_marker(payload_data)
                    if enip_ok:
                        strict_ot_counts["EtherNet/IP"] += 1
                        setdict_add(strict_ot_pairs, "EtherNet/IP", (src_ip, dst_ip))
                    if cip_ok:
                        strict_ot_counts["CIP"] += 1
                        setdict_add(strict_ot_pairs, "CIP", (src_ip, dst_ip))

                if sport == DNP3_PORT or dport == DNP3_PORT:
                    if _strict_dnp3_marker(payload_data):
                        strict_ot_counts["DNP3"] += 1
                        setdict_add(strict_ot_pairs, "DNP3", (src_ip, dst_ip))

                if dport:
                    counter_inc(udp_target_counts, dst_ip)
                    setdict_add(src_ports, src_ip, dport)

    finally:
        status.finish()
        reader.close()

    duration_seconds = max(0.0, (last_seen or 0.0) - (first_seen or 0.0)) if first_seen is not None and last_seen is not None else None

    # Add layer-2 OT/ICS protocol presence not captured by port heuristics
    if goose_summary.goose_packets:
        ot_protocol_counts["GOOSE"] += goose_summary.goose_packets
    if sv_summary.sv_packets:
        ot_protocol_counts["SV"] += sv_summary.sv_packets
    if ptp_summary.ptp_packets:
        ot_protocol_counts["PTP"] += ptp_summary.ptp_packets
    if lldp_summary.lldp_packets:
        ot_protocol_counts["LLDP"] += lldp_summary.lldp_packets
    if lldp_summary.dcp_packets:
        ot_protocol_counts["DCP"] += lldp_summary.dcp_packets
    if opc_classic_summary.opc_packets:
        ot_protocol_counts["OPC Classic"] += opc_classic_summary.opc_packets

    for source, anomalies in ot_candidates.items():
        summary_obj = ot_summaries.get(source)
        if summary_obj is None:
            continue

        strict_count = strict_ot_counts.get(source, 0)
        strict_pair_count = len(strict_ot_pairs.get(source, set()))

        if source in {"CIP", "EtherNet/IP"}:
            if strict_count < 3 or strict_pair_count < 1:
                continue
        elif source == "DNP3":
            if strict_count < 2:
                continue

        high_anoms = [
            anomaly for anomaly in anomalies
            if _normalize_severity(getattr(anomaly, "severity", "info")) in {"high", "critical"}
        ]

        if high_anoms:
            _append_ot_anomalies(detections, source, high_anoms)
        if _ot_presence_confident(source, summary_obj, anomalies):
            _append_ot_anomalies(detections, source, anomalies)

    # OT command/control activity across protocols
    for source, summary_obj in ot_summaries.items():
        commands = getattr(summary_obj, "commands", None)
        if isinstance(commands, Counter) and commands:
            hits, severity = _collect_ot_command_hits(commands)
            if hits:
                evidence = [f"{cmd}({count})" for cmd, count in hits.most_common(10)]
                detections.append({
                    "source": source,
                    "severity": severity,
                    "summary": "OT control/engineering command activity",
                    "details": f"{sum(hits.values())} control-like command(s) observed in {source}.",
                    "evidence": _dedupe_evidence(evidence, limit=10),
                })

        func_counts = getattr(summary_obj, "func_counts", None)
        if isinstance(func_counts, Counter):
            func_hits, func_sev = _collect_ot_command_hits(func_counts)
            if func_hits:
                detections.append({
                    "source": source,
                    "severity": func_sev,
                    "summary": "OT protocol function operations observed",
                    "details": f"{sum(func_hits.values())} control-like function call(s) detected.",
                    "evidence": _dedupe_evidence(
                        [f"{name}({count})" for name, count in func_hits.most_common(10)],
                        limit=8,
                    ),
                })
            diag_total = sum(count for name, count in func_counts.items() if "diagnostic" in name.lower())
            if diag_total:
                detections.append({
                    "source": source,
                    "severity": "warning",
                    "summary": "OT diagnostic/maintenance operations observed",
                    "details": f"{diag_total} diagnostic function call(s) detected.",
                    "evidence": _dedupe_evidence(
                        [f"{name}({count})" for name, count in func_counts.items() if "diagnostic" in name.lower()],
                        limit=6,
                    ),
                })

        if hasattr(summary_obj, "source_risky_commands"):
            risky = getattr(summary_obj, "source_risky_commands", Counter())
            if isinstance(risky, Counter) and risky:
                detections.append({
                    "source": source,
                    "severity": "high",
                    "summary": "High-risk OT commands observed",
                    "details": f"{sum(risky.values())} risky command(s) issued.",
                    "top_sources": risky.most_common(8),
                })
        if hasattr(summary_obj, "source_enum_commands"):
            enum_cmds = getattr(summary_obj, "source_enum_commands", Counter())
            if isinstance(enum_cmds, Counter) and enum_cmds:
                detections.append({
                    "source": source,
                    "severity": "warning",
                    "summary": "OT enumeration activity observed",
                    "details": f"{sum(enum_cmds.values())} enumeration command(s) issued.",
                    "top_sources": enum_cmds.most_common(8),
                })
        if hasattr(summary_obj, "high_risk_services"):
            high_risk_services = getattr(summary_obj, "high_risk_services", Counter())
            if isinstance(high_risk_services, Counter) and high_risk_services:
                detections.append({
                    "source": source,
                    "severity": "high",
                    "summary": "High-risk OT services observed",
                    "details": f"{sum(high_risk_services.values())} high-risk service invocation(s).",
                    "evidence": _dedupe_evidence(
                        [f"{name}({count})" for name, count in high_risk_services.most_common(8)],
                        limit=8,
                    ),
                })
        if hasattr(summary_obj, "suspicious_services"):
            suspicious_services = getattr(summary_obj, "suspicious_services", Counter())
            if isinstance(suspicious_services, Counter) and suspicious_services:
                detections.append({
                    "source": source,
                    "severity": "warning",
                    "summary": "Suspicious OT service usage",
                    "details": f"{sum(suspicious_services.values())} suspicious service invocation(s).",
                    "evidence": _dedupe_evidence(
                        [f"{name}({count})" for name, count in suspicious_services.most_common(8)],
                        limit=8,
                    ),
                })

    if ot_protocol_counts:
        proto_text = ", ".join(f"{name} ({count})" for name, count in ot_protocol_counts.most_common(8))
        detections.append({
            "source": "OT/ICS",
            "severity": "info",
            "summary": "OT protocol activity observed",
            "details": proto_text or "-",
        })

    if public_ot_pairs:
        top_pairs = sorted(public_ot_pairs)[:10]
        evidence = [f"{proto} {src}->{dst}" for proto, src, dst in top_pairs]
        detections.append({
            "source": "OT/ICS",
            "severity": "high",
            "summary": "OT protocol traffic involving public IPs",
            "details": f"{len(public_ot_pairs)} OT flow(s) included public addressing.",
            "evidence": _dedupe_evidence(evidence, limit=10),
        })

    control_tokens = ("write", "control", "setpoint", "start", "stop", "download", "upload", "program", "firmware")
    control_commands: Counter[str] = Counter()
    for source, summary_obj in ot_summaries.items():
        commands = getattr(summary_obj, "commands", None)
        if not isinstance(commands, Counter):
            continue
        for cmd, count in commands.items():
            cmd_text = str(cmd).lower()
            if any(token in cmd_text for token in control_tokens):
                control_commands[f"{source}:{cmd}"] += int(count)
                control_command_total += int(count)
    if control_commands:
        top_cmds = [f"{cmd} ({count})" for cmd, count in control_commands.most_common(10)]
        detections.append({
            "source": "OT/ICS",
            "severity": "high" if sum(control_commands.values()) >= 5 else "warning",
            "summary": "OT control/program operations observed",
            "details": f"{sum(control_commands.values())} control-like command(s) detected.",
            "evidence": _dedupe_evidence(top_cmds, limit=10),
        })

    vertical_scan_hits: list[tuple[str, str, int]] = []
    for (src_ip, dst_ip), ports in pair_ports.items():
        if len(ports) >= 40:
            vertical_scan_hits.append((src_ip, dst_ip, len(ports)))
    if vertical_scan_hits:
        top = sorted(vertical_scan_hits, key=lambda item: item[2], reverse=True)[:5]
        detections.append({
            "source": "Recon",
            "severity": "high" if top[0][2] >= 120 else "warning",
            "summary": "Vertical port scanning/probing detected",
            "details": f"{len(vertical_scan_hits)} src->dst pair(s) touched >=40 destination ports.",
            "top_sources": [(item[0], item[2]) for item in top],
            "top_destinations": [(item[1], item[2]) for item in top],
        })

    horizontal_scan_hits = [(src, len(targets), len(src_ports.get(src, set()))) for src, targets in src_targets.items() if len(targets) >= 30]
    if horizontal_scan_hits:
        top = sorted(horizontal_scan_hits, key=lambda item: (item[1], item[2]), reverse=True)[:5]
        detections.append({
            "source": "Recon",
            "severity": "high" if top[0][1] >= 100 else "warning",
            "summary": "Horizontal host scanning/probing detected",
            "details": "Sources contacted many distinct targets.",
            "top_sources": [(src, targets) for src, targets, _ in top],
        })

    if syn_counts:
        top_src, top_count = syn_counts.most_common(1)[0]
        if top_count >= 1500:
            detections.append({
                "source": "TCP",
                "severity": "warning",
                "summary": "High SYN volume",
                "details": f"Source {top_src} sent {top_count} SYN packets.",
                "top_sources": syn_counts.most_common(5),
            })

    brute_force_hits = [(src, dst, service, count) for (src, dst, service), count in auth_attempts.items() if count >= 20]
    if brute_force_hits:
        top = sorted(brute_force_hits, key=lambda item: item[3], reverse=True)[:8]
        auth_evidence = [f"{src}->{dst} {service} attempts={count}" for src, dst, service, count in top]
        detections.append({
            "source": "Auth",
            "severity": "high",
            "summary": "Potential brute-force authentication attempts",
            "details": "; ".join(f"{src}->{dst} {service} ({count} attempts)" for src, dst, service, count in top[:3]),
            "top_sources": Counter(src for src, _, _, _ in top).most_common(5),
            "top_destinations": Counter(dst for _, dst, _, _ in top).most_common(5),
            "evidence": _dedupe_evidence(auth_evidence, limit=8),
        })

    auth_failure_hits = [(src, dst, service, count) for (src, dst, service), count in auth_failures.items() if count >= 5]
    if auth_failure_hits:
        top = sorted(auth_failure_hits, key=lambda item: item[3], reverse=True)[:8]
        failure_evidence = [f"{src}->{dst} {service} fail_indicators={count}" for src, dst, service, count in top]
        detections.append({
            "source": "Auth",
            "severity": "warning",
            "summary": "Repeated authentication failures observed",
            "details": "; ".join(f"{src}->{dst} {service} ({count} fail indicators)" for src, dst, service, count in top[:3]),
            "top_sources": Counter(src for src, _, _, _ in top).most_common(5),
            "top_destinations": Counter(dst for _, dst, _, _ in top).most_common(5),
            "evidence": _dedupe_evidence(failure_evidence, limit=8),
        })

    lateral_hits = [(src, len(targets)) for src, targets in lateral_targets.items() if len(targets) >= 12]
    if lateral_hits:
        detections.append({
            "source": "Lateral",
            "severity": "warning",
            "summary": "Potential lateral movement",
            "details": "Private source(s) reached many internal hosts over admin/lateral protocols (SMB/RDP/WinRM/etc).",
            "top_sources": sorted(lateral_hits, key=lambda item: item[1], reverse=True)[:8],
        })

    if udp_target_counts:
        top_dst, top_count = udp_target_counts.most_common(1)[0]
        if top_count >= 5000:
            detections.append({
                "source": "UDP",
                "severity": "warning",
                "summary": "Potential UDP flood",
                "details": f"Destination {top_dst} received {top_count} UDP packets.",
                "top_destinations": udp_target_counts.most_common(5),
            })

    if dst_counts and duration_seconds and duration_seconds > 0:
        top_dst, top_dst_count = dst_counts.most_common(1)[0]
        rate = top_dst_count / duration_seconds
        if rate >= 5000:
            detections.append({
                "source": "Traffic",
                "severity": "warning",
                "summary": "High traffic concentration on a target",
                "details": f"{top_dst} received {top_dst_count} packets (~{rate:.1f} pkt/s).",
                "top_destinations": dst_counts.most_common(5),
            })

    exfil_pairs = [
        (src, dst, byte_count)
        for (src, dst), byte_count in outbound_bytes_public.items()
        if byte_count >= 20 * 1024 * 1024
    ]
    if exfil_pairs:
        top = sorted(exfil_pairs, key=lambda item: item[2], reverse=True)[:8]
        exfil_evidence = [f"{src}->{dst} bytes={count}" for src, dst, count in top]
        detections.append({
            "source": "Exfil",
            "severity": "high",
            "summary": "Potential large outbound data transfer",
            "details": "; ".join(f"{src}->{dst} {count / (1024*1024):.1f}MB" for src, dst, count in top[:3]),
            "top_sources": Counter(src for src, _, _ in top).most_common(5),
            "top_destinations": Counter(dst for _, dst, _ in top).most_common(5),
            "evidence": _dedupe_evidence(exfil_evidence, limit=8),
        })

    broad_egress = [(src, len(dsts)) for src, dsts in outbound_public_dests_by_src.items() if len(dsts) >= 15]
    if broad_egress:
        detections.append({
            "source": "Exfil",
            "severity": "warning",
            "summary": "Broad outbound external communication",
            "details": "Source(s) communicated with many public destinations.",
            "top_sources": sorted(broad_egress, key=lambda item: item[1], reverse=True)[:8],
        })

    if dns_tunnel_sources:
        top = dns_tunnel_sources.most_common(8)
        if top[0][1] >= 20:
            detections.append({
                "source": "DNS",
                "severity": "warning",
                "summary": "Potential DNS tunneling/exfil indicators",
                "details": "High-entropy or oversized DNS query labels observed.",
                "top_sources": top,
                "evidence": _dedupe_evidence([f"{src} suspicious_dns_queries={count}" for src, count in top], limit=8),
            })

    if dns_txt_query_sources:
        top = dns_txt_query_sources.most_common(8)
        if top[0][1] >= 20:
            detections.append({
                "source": "DNS",
                "severity": "info",
                "summary": "High TXT-query activity",
                "details": "Frequent TXT DNS queries can indicate tunneling/staging or telemetry channels.",
                "top_sources": top,
                "evidence": _dedupe_evidence([f"{src} txt_queries={count}" for src, count in top], limit=8),
            })

    if suspicious_payload_sources:
        detections.append({
            "source": "Payload",
            "severity": "warning",
            "summary": "Suspicious command/tooling markers in payloads",
            "details": "Payload markers matched common offensive tooling/command execution strings.",
            "top_sources": suspicious_payload_sources.most_common(10),
            "evidence": _dedupe_evidence([f"{src} marker_hits={count}" for src, count in suspicious_payload_sources.most_common(10)], limit=10),
        })

    risk_score, risk_findings = _ot_risk_posture_from_detections(
        detections,
        public_ot_flows=len(public_ot_pairs),
        control_hits=control_command_total,
    )
    storyline = _threats_storyline(detections, dict(ot_protocol_counts), risk_score, risk_findings)

    return ThreatSummary(
        path=path,
        detections=detections,
        errors=errors,
        total_packets=total_packets,
        first_seen=first_seen,
        last_seen=last_seen,
        duration=duration_seconds,
        ot_protocol_counts=dict(ot_protocol_counts),
        public_ot_pairs=sorted(public_ot_pairs),
        ot_peer_internal=ot_peer_internal.most_common(10),
        ot_peer_external=ot_peer_external.most_common(10),
        ot_risk_score=risk_score,
        ot_risk_findings=risk_findings,
        storyline=storyline,
    )
