from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import ipaddress
from pathlib import Path
import re
from typing import Iterable, Optional

from .analyzer import analyze_pcap
from .arp import analyze_arp
from .beacon import analyze_beacons
from .dhcp import analyze_dhcp
from .exfil import analyze_exfil
from .files import analyze_files
from .hostname import analyze_hostname
from .ips import analyze_ips
from .kerberos import analyze_kerberos
from .netbios import analyze_netbios
from .rpc import analyze_rpc
from .services import analyze_services
from .smb import analyze_smb
from .threats import analyze_threats
from .timeline import analyze_timeline
from .progress import run_with_busy_status


@dataclass(frozen=True)
class HostDetailsSummary:
    path: Path
    target_ip: str
    operating_system: str
    os_evidence: list[str]
    total_packets: int
    relevant_packets: int
    packets_sent: int
    packets_recv: int
    bytes_sent: int
    bytes_recv: int
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]
    mac_addresses: list[str]
    hostnames: list[str]
    hostname_findings: list[dict[str, object]]
    user_evidence: list[dict[str, object]]
    file_transfers: list[dict[str, object]]
    dns_queries: list[dict[str, object]]
    timeline_events: list[dict[str, object]]
    peer_counts: Counter[str]
    protocol_counts: Counter[str]
    port_counts: Counter[int]
    conversations: list[dict[str, object]]
    services: list[dict[str, object]]
    attack_categories: Counter[str]
    detections: list[dict[str, object]]
    artifacts: list[str]
    errors: list[str]


_ATTACK_KEYWORDS: dict[str, tuple[str, ...]] = {
    "beaconing": ("beacon", "periodic", "c2", "command and control"),
    "exfiltration": ("exfil", "dns tunnel", "data leak", "large post", "staging"),
    "scanning_probe": ("scan", "probing", "enumeration", "discovery"),
    "bruteforce_auth": (
        "brute",
        "password",
        "auth failed",
        "login failed",
        "credential",
        "ntlm",
        "kerberos",
    ),
    "lateral_movement": ("lateral", "pivot", "smb", "rdp", "winrm", "psexec"),
    "malware_tooling": ("mimikatz", "powershell", "cmd.exe", "wmic", "certutil", "rundll32"),
    "dos_impact": ("flood", "dos", "impact", "disruption"),
    "ot_ics": (
        "modbus",
        "dnp3",
        "iec104",
        "bacnet",
        "enip",
        "profinet",
        "s7",
        "opc",
        "hart",
        "iccp",
    ),
}

_USER_UNKNOWN = {"", "-", "unknown", "n/a", "none"}
_WINDOWS_BUILTIN_PRINCIPALS = {
    "access control assistance operators",
    "account operators",
    "administrator",
    "administrators",
    "allowed rodc password replication group",
    "anonymous",
    "authenticated users",
    "backup operators",
    "cert publishers",
    "cloneable domain controllers",
    "cryptographic operators",
    "denied rodc password replication group",
    "distributed com users",
    "dnsadmins",
    "dnsupdateproxy",
    "domain admins",
    "domain computers",
    "domain controllers",
    "domain guests",
    "domain users",
    "enterprise admins",
    "enterprise key admins",
    "enterprise read-only domain controllers",
    "event log readers",
    "everyone",
    "group policy creator owners",
    "guest",
    "guests",
    "hyper-v administrators",
    "iis iusrs",
    "incoming forest trust builders",
    "key admins",
    "network configuration operators",
    "performance log users",
    "performance monitor users",
    "power users",
    "pre windows 2000 compatible access",
    "print operators",
    "protected users",
    "ras and ias servers",
    "read only domain controllers",
    "remote desktop users",
    "remote management users",
    "replicator",
    "schema admins",
    "server operators",
    "storage replica administrators",
    "users",
    "windows authorization access group",
}


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def _mentions_target(value: object, target_ip: str) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return target_ip in value
    if isinstance(value, (list, tuple, set)):
        return any(_mentions_target(item, target_ip) for item in value)
    if isinstance(value, dict):
        return any(_mentions_target(item, target_ip) for item in value.values())
    return target_ip in str(value)


def _add_categories(counter: Counter[str], summary_text: str, details_text: str) -> None:
    blob = f"{summary_text} {details_text}".lower()
    for category, tokens in _ATTACK_KEYWORDS.items():
        if any(token in blob for token in tokens):
            counter[category] += 1


def _severity_rank(value: str) -> int:
    normalized = value.lower()
    if normalized == "critical":
        return 0
    if normalized == "high":
        return 1
    if normalized in {"warning", "warn", "medium"}:
        return 2
    return 3


def _extract_detection_filename(summary_text: str, details_text: str) -> str | None:
    file_match = re.search(r"(?:(?:mismatch|suspicious|file)\s*:?\s*)([\w.\-()\[\] ]+\.[a-zA-Z0-9]{1,8})", summary_text, re.IGNORECASE)
    if file_match:
        return file_match.group(1).strip()
    fallback = re.search(r"([\w.\-()\[\] ]+\.[a-zA-Z0-9]{1,8})", details_text)
    if fallback:
        return fallback.group(1).strip()
    return None


def _artifact_evidence_for_filename(filename: str, file_summary, target_ip: str) -> list[str]:
    if not filename:
        return []
    evidence: list[str] = []
    lowered = filename.lower()
    for artifact in getattr(file_summary, "artifacts", []) or []:
        art_name = str(getattr(artifact, "filename", "") or "")
        if not art_name:
            continue
        if art_name.lower() != lowered and lowered not in art_name.lower() and art_name.lower() not in lowered:
            continue
        src = str(getattr(artifact, "src_ip", "-"))
        dst = str(getattr(artifact, "dst_ip", "-"))
        if target_ip not in {src, dst}:
            continue
        sport = getattr(artifact, "src_port", None)
        dport = getattr(artifact, "dst_port", None)
        proto = str(getattr(artifact, "protocol", "-"))
        note = str(getattr(artifact, "note", "") or "")
        flow = f"{src}:{sport if sport is not None else '-'} -> {dst}:{dport if dport is not None else '-'}"
        line = f"file={art_name} flow={flow} proto={proto}"
        if note:
            line = f"{line} note={note}"
        evidence.append(line)
        if len(evidence) >= 6:
            break
    return evidence


def _extract_mac_values(target_ip: str, arp_summary, dhcp_summary) -> list[str]:
    macs: set[str] = set()

    for convo in getattr(arp_summary, "conversations", []) or []:
        if convo.src_ip == target_ip and convo.src_mac:
            macs.add(convo.src_mac.lower())
        if convo.dst_ip == target_ip and convo.dst_mac:
            macs.add(convo.dst_mac.lower())

    for session in getattr(dhcp_summary, "sessions", []) or []:
        if (session.client_ip == target_ip or session.server_ip == target_ip) and session.client_mac:
            macs.add(str(session.client_mac).lower())

    return sorted(mac for mac in macs if mac and mac != "00:00:00:00:00:00")


def _normalize_user(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = str(value).strip()
    if not cleaned:
        return None
    if cleaned.lower() in _USER_UNKNOWN:
        return None
    return cleaned


def _is_builtin_windows_principal(value: str | None) -> bool:
    if not value:
        return False
    cleaned = str(value).strip().lower()
    cleaned = cleaned.replace("_", " ").replace("-", " ")
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned in _WINDOWS_BUILTIN_PRINCIPALS


def _split_user_domain(value: str | None) -> tuple[str | None, str | None]:
    user = _normalize_user(value)
    if not user:
        return None, None
    if "\\" in user:
        domain, _, uname = user.partition("\\")
        return _normalize_user(uname), _normalize_user(domain)
    if "@" in user:
        uname, _, dom = user.partition("@")
        return _normalize_user(uname), _normalize_user(dom)
    return user, None


def _parse_ldap_identity(identity: str) -> tuple[str | None, str | None, str | None]:
    if not identity:
        return None, None, None
    username = None
    full_name = None
    domain_parts: list[str] = []
    tokens = [tok.strip() for tok in identity.split(",") if "=" in tok]
    for token in tokens:
        key, _, val = token.partition("=")
        key = key.strip().lower()
        val = val.strip()
        if not val:
            continue
        if key == "dc":
            domain_parts.append(val)
            continue
        if key in {"samaccountname", "uid", "userprincipalname", "mail"}:
            if not username:
                username = val
            continue
        if key == "cn":
            if not full_name and (" " in val or "," in val):
                full_name = val
            if not username:
                username = val
            continue
    domain = ".".join(domain_parts) if domain_parts else None
    return _normalize_user(username), _normalize_user(full_name), _normalize_user(domain)


def _infer_operating_system(
    hostnames: set[str],
    services: list[dict[str, object]],
    dhcp_summary,
) -> tuple[str, list[str]]:
    os_scores: Counter[str] = Counter()
    evidence: list[str] = []
    evidence_seen: set[str] = set()

    def _add_evidence(label: str) -> None:
        if label in evidence_seen:
            return
        evidence_seen.add(label)
        evidence.append(label)

    ics_protocol_markers = {
        "modbus",
        "dnp3",
        "iec-104",
        "iec104",
        "bacnet",
        "ethernet/ip",
        "enip",
        "profinet",
        "s7",
        "opc",
        "opc ua",
        "fins",
        "melsec",
        "pcworx",
        "hart",
        "iccp",
        "niagara",
        "srtp",
        "yokogawa",
        "honeywell",
        "codesys",
        "odesys",
    }
    appliance_markers = {
        "router",
        "switch",
        "firewall",
        "gateway",
        "sensor",
        "camera",
        "iot",
        "embedded",
    }
    rtos_markers = {"vxworks", "qnx", "freertos", "threadx", "ecos", "rtos"}
    plc_markers = {
        "siemens",
        "allen-bradley",
        "rockwell",
        "schneider",
        "omron",
        "mitsubishi",
        "yokogawa",
        "honeywell",
        "ge",
        "abb",
        "plc",
        "hmi",
        "dcs",
    }

    for name in hostnames:
        lower = name.lower()
        if any(token in lower for token in ("win", "wks", "pc-", "desktop-", "server-")):
            os_scores["Windows"] += 2
            _add_evidence(f"hostname:{name} -> windows-like naming")
        if any(token in lower for token in ("ubuntu", "debian", "centos", "kali", "linux")):
            os_scores["Linux/Unix"] += 2
            _add_evidence(f"hostname:{name} -> linux-like naming")
        if any(token in lower for token in ("macbook", "imac", "apple", "darwin")):
            os_scores["macOS"] += 2
            _add_evidence(f"hostname:{name} -> mac-like naming")

    for service in services:
        software = str(service.get("software", "")).lower()
        service_name = str(service.get("service", "")).lower()
        blob = f"{software} {service_name}"

        if any(marker in blob for marker in ics_protocol_markers):
            os_scores["OT/ICS Device (Embedded/Appliance)"] += 4
            _add_evidence(f"service:{service.get('service', '-')} -> OT/ICS protocol marker")
        if any(marker in blob for marker in appliance_markers):
            os_scores["Network/IoT Appliance"] += 3
            _add_evidence(f"service:{service.get('service', '-')} -> appliance marker")
        if any(marker in blob for marker in rtos_markers):
            os_scores["Embedded RTOS"] += 5
            _add_evidence(f"software:{service.get('software', '-')} -> RTOS marker")
        if any(marker in blob for marker in plc_markers):
            os_scores["OT/ICS Device (Embedded/Appliance)"] += 4
            _add_evidence(f"software/service:{service.get('software', '-')}/{service.get('service', '-')} -> PLC/HMI vendor marker")

        if any(token in blob for token in ("microsoft", "windows", "iis", "exchange")):
            os_scores["Windows"] += 3
            _add_evidence(f"software:{service.get('software', '-')} -> windows server marker")
        if any(token in blob for token in ("ubuntu", "debian", "centos", "red hat", "linux kernel")):
            os_scores["Linux/Unix"] += 3
            _add_evidence(f"software:{service.get('software', '-')} -> linux marker")
        if any(token in blob for token in ("darwin", "mac os", "macos", "apple")):
            os_scores["macOS"] += 3
            _add_evidence(f"software:{service.get('software', '-')} -> macOS marker")
        if "openssh" in blob and "windows" not in blob:
            os_scores["Linux/Unix"] += 1
            _add_evidence("software:OpenSSH without windows marker")

    for vendor_class, count in getattr(dhcp_summary, "vendor_classes", Counter()).most_common(20):
        text = str(vendor_class).lower()
        if "msft" in text or "microsoft" in text:
            os_scores["Windows"] += max(1, int(count // 5) + 1)
            _add_evidence(f"dhcp_vendor:{vendor_class} -> windows marker")
        if any(token in text for token in ("android", "ios", "iphone", "ipad")):
            os_scores["Mobile"] += max(1, int(count // 5) + 1)
            _add_evidence(f"dhcp_vendor:{vendor_class} -> mobile marker")
        if any(token in text for token in ("linux", "ubuntu", "debian")):
            os_scores["Linux/Unix"] += max(1, int(count // 5) + 1)
            _add_evidence(f"dhcp_vendor:{vendor_class} -> linux marker")
        if any(token in text for token in ("plc", "hmi", "scada", "dcs", "siemens", "rockwell", "schneider", "omron", "yokogawa", "honeywell", "mitsubishi")):
            os_scores["OT/ICS Device (Embedded/Appliance)"] += max(1, int(count // 4) + 1)
            _add_evidence(f"dhcp_vendor:{vendor_class} -> OT/ICS vendor marker")
        if any(token in text for token in ("vxworks", "qnx", "freertos", "rtos")):
            os_scores["Embedded RTOS"] += max(1, int(count // 4) + 1)
            _add_evidence(f"dhcp_vendor:{vendor_class} -> RTOS marker")

    for hostname in hostnames:
        text = hostname.lower()
        if any(token in text for token in ("plc", "hmi", "scada", "rtu", "dcs", "histori", "opc")):
            os_scores["OT/ICS Device (Embedded/Appliance)"] += 3
            _add_evidence(f"hostname:{hostname} -> OT/ICS naming marker")
        if any(token in text for token in ("router", "switch", "fw", "firewall", "gateway", "sensor", "camera")):
            os_scores["Network/IoT Appliance"] += 2
            _add_evidence(f"hostname:{hostname} -> network/appliance marker")

    if not os_scores:
        return "Unknown", ["no reliable passive OS indicators observed"]

    # If OT/ICS/embedded indicators exist and no strong desktop/server OS dominates,
    # prefer the OT-oriented classification for operationally useful triage.
    ot_score = os_scores.get("OT/ICS Device (Embedded/Appliance)", 0)
    rtos_score = os_scores.get("Embedded RTOS", 0)
    windows_score = os_scores.get("Windows", 0)
    linux_score = os_scores.get("Linux/Unix", 0)
    mac_score = os_scores.get("macOS", 0)
    if (ot_score >= 4 or rtos_score >= 4) and max(windows_score, linux_score, mac_score) <= max(ot_score, rtos_score):
        if rtos_score > ot_score:
            return "Embedded RTOS", evidence[:8]
        return "OT/ICS Device (Embedded/Appliance)", evidence[:8]

    return os_scores.most_common(1)[0][0], evidence[:8]


def merge_hostdetails_summaries(summaries: Iterable[HostDetailsSummary]) -> HostDetailsSummary:
    summary_list = list(summaries)
    if not summary_list:
        return HostDetailsSummary(
            path=Path("ALL_PCAPS_0"),
            target_ip="-",
            operating_system="Unknown",
            os_evidence=[],
            total_packets=0,
            relevant_packets=0,
            packets_sent=0,
            packets_recv=0,
            bytes_sent=0,
            bytes_recv=0,
            first_seen=None,
            last_seen=None,
            duration_seconds=0.0,
            mac_addresses=[],
            hostnames=[],
            hostname_findings=[],
            user_evidence=[],
            file_transfers=[],
            dns_queries=[],
            timeline_events=[],
            peer_counts=Counter(),
            protocol_counts=Counter(),
            port_counts=Counter(),
            conversations=[],
            services=[],
            attack_categories=Counter(),
            detections=[],
            artifacts=[],
            errors=[],
        )

    target_ip = summary_list[0].target_ip
    os_counter: Counter[str] = Counter()
    os_evidence_seen: set[str] = set()
    os_evidence: list[str] = []
    total_packets = 0
    relevant_packets = 0
    packets_sent = 0
    packets_recv = 0
    bytes_sent = 0
    bytes_recv = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    duration_seconds = 0.0

    macs: set[str] = set()
    hostnames: set[str] = set()
    hostname_findings: list[dict[str, object]] = []
    hostname_seen: dict[tuple[str, str, str, str, str, str], int] = {}
    user_evidence: list[dict[str, object]] = []
    user_seen: set[tuple[str, str, str, str, str]] = set()
    file_transfers: list[dict[str, object]] = []
    file_seen: set[tuple[str, ...]] = set()
    dns_queries: list[dict[str, object]] = []
    dns_seen: set[tuple[object, ...]] = set()
    timeline_events: list[dict[str, object]] = []
    timeline_seen: set[tuple[object, ...]] = set()
    peer_counts: Counter[str] = Counter()
    protocol_counts: Counter[str] = Counter()
    port_counts: Counter[int] = Counter()
    attack_categories: Counter[str] = Counter()

    convo_seen: set[tuple[str, str, str, str]] = set()
    conversations: list[dict[str, object]] = []
    svc_seen: set[tuple[str, str, int, str]] = set()
    services: list[dict[str, object]] = []
    detection_seen: dict[tuple[str, str, str], int] = {}
    detections: list[dict[str, object]] = []
    artifact_seen: set[str] = set()
    artifacts: list[str] = []
    error_seen: set[str] = set()
    errors: list[str] = []

    for summary in summary_list:
        total_packets += summary.total_packets
        relevant_packets += summary.relevant_packets
        packets_sent += summary.packets_sent
        packets_recv += summary.packets_recv
        bytes_sent += summary.bytes_sent
        bytes_recv += summary.bytes_recv

        if summary.first_seen is not None and (first_seen is None or summary.first_seen < first_seen):
            first_seen = summary.first_seen
        if summary.last_seen is not None and (last_seen is None or summary.last_seen > last_seen):
            last_seen = summary.last_seen
        if summary.duration_seconds is not None:
            duration_seconds += summary.duration_seconds

        macs.update(summary.mac_addresses)
        hostnames.update(summary.hostnames)
        for finding in summary.hostname_findings:
            key = (
                str(finding.get("hostname", "")),
                str(finding.get("mapped_ip", "")),
                str(finding.get("method", "")),
                str(finding.get("protocol", "")),
                str(finding.get("src_ip", "")),
                str(finding.get("dst_ip", "")),
            )
            idx = hostname_seen.get(key)
            if idx is None:
                hostname_seen[key] = len(hostname_findings)
                hostname_findings.append(dict(finding))
            else:
                existing = hostname_findings[idx]
                existing["count"] = int(existing.get("count", 0) or 0) + int(finding.get("count", 0) or 0)
                first_seen_val = existing.get("first_seen")
                new_first = finding.get("first_seen")
                if new_first is not None and (first_seen_val is None or new_first < first_seen_val):
                    existing["first_seen"] = new_first
                last_seen_val = existing.get("last_seen")
                new_last = finding.get("last_seen")
                if new_last is not None and (last_seen_val is None or new_last > last_seen_val):
                    existing["last_seen"] = new_last

        for item in summary.user_evidence:
            key = (
                str(item.get("username", "")),
                str(item.get("domain", "")),
                str(item.get("full_name", "")),
                str(item.get("method", "")),
                str(item.get("location", "")),
            )
            if key in user_seen:
                continue
            user_seen.add(key)
            user_evidence.append(dict(item))

        for item in summary.file_transfers:
            key = (
                str(item.get("direction", "")),
                str(item.get("kind", "")),
                str(item.get("protocol", "")),
                str(item.get("src_ip", "")),
                str(item.get("dst_ip", "")),
                str(item.get("src_port", "")),
                str(item.get("dst_port", "")),
                str(item.get("filename", "")),
                str(item.get("size_bytes", "")),
                str(item.get("bytes", "")),
                str(item.get("note", "")),
                str(item.get("file_type", "")),
                str(item.get("hostname", "")),
                str(item.get("content_type", "")),
                str(item.get("sha256", "")),
                str(item.get("md5", "")),
                str(item.get("first_seen", "")),
                str(item.get("last_seen", "")),
                str(item.get("packet_index", "")),
            )
            if key in file_seen:
                continue
            file_seen.add(key)
            file_transfers.append(dict(item))

        for query in summary.dns_queries:
            key = (
                query.get("ts"),
                query.get("name"),
                query.get("qtype"),
                query.get("src_ip"),
                query.get("dst_ip"),
                query.get("protocol"),
                query.get("dst_port"),
            )
            if key in dns_seen:
                continue
            dns_seen.add(key)
            dns_queries.append(dict(query))

        for event in summary.timeline_events:
            key = (
                event.get("ts"),
                event.get("category"),
                event.get("summary"),
                event.get("details"),
            )
            if key in timeline_seen:
                continue
            timeline_seen.add(key)
            timeline_events.append(dict(event))
        peer_counts.update(summary.peer_counts)
        protocol_counts.update(summary.protocol_counts)
        port_counts.update(summary.port_counts)
        attack_categories.update(summary.attack_categories)
        if summary.operating_system and summary.operating_system != "Unknown":
            os_counter[summary.operating_system] += 1
        for item in summary.os_evidence:
            if item in os_evidence_seen:
                continue
            os_evidence_seen.add(item)
            os_evidence.append(item)

        for convo in summary.conversations:
            key = (
                str(convo.get("direction", "-")),
                str(convo.get("peer", "-")),
                str(convo.get("protocol", "-")),
                str(convo.get("ports", "-")),
            )
            if key in convo_seen:
                continue
            convo_seen.add(key)
            conversations.append(convo)

        for service in summary.services:
            key = (
                str(service.get("role", "-")),
                str(service.get("asset", "-")),
                int(service.get("port", 0) or 0),
                str(service.get("protocol", "-")),
            )
            if key in svc_seen:
                continue
            svc_seen.add(key)
            services.append(service)

        for item in summary.detections:
            key = (
                str(item.get("severity", "info")),
                str(item.get("summary", "")),
                str(item.get("details", "")),
            )
            existing_idx = detection_seen.get(key)
            if existing_idx is None:
                detection_seen[key] = len(detections)
                detections.append(item)
                continue

            merged = dict(detections[existing_idx])
            existing_evidence = [str(value) for value in (merged.get("evidence", []) or []) if str(value).strip()]
            new_evidence = [str(value) for value in (item.get("evidence", []) or []) if str(value).strip()]
            seen_ev: set[str] = set(existing_evidence)
            for value in new_evidence:
                if value not in seen_ev:
                    seen_ev.add(value)
                    existing_evidence.append(value)
            if existing_evidence:
                merged["evidence"] = existing_evidence[:12]

            def _merge_top(field: str) -> None:
                top_counter: Counter[str] = Counter()
                for ip, count in (merged.get(field, []) or []):
                    top_counter[str(ip)] += int(count)
                for ip, count in (item.get(field, []) or []):
                    top_counter[str(ip)] += int(count)
                if top_counter:
                    merged[field] = top_counter.most_common(6)

            _merge_top("top_sources")
            _merge_top("top_destinations")
            detections[existing_idx] = merged

        for artifact in summary.artifacts:
            if artifact in artifact_seen:
                continue
            artifact_seen.add(artifact)
            artifacts.append(artifact)

        for err in summary.errors:
            if err in error_seen:
                continue
            error_seen.add(err)
            errors.append(err)

    conversations.sort(key=lambda item: int(item.get("bytes", 0) or 0), reverse=True)
    services.sort(key=lambda item: int(item.get("packets", 0) or 0), reverse=True)
    detections.sort(key=lambda item: _severity_rank(str(item.get("severity", "info"))))
    hostname_findings.sort(key=lambda item: int(item.get("count", 0) or 0), reverse=True)
    dns_queries.sort(key=lambda item: (item.get("ts") is None, item.get("ts")))
    timeline_events.sort(key=lambda item: (item.get("ts") is None, item.get("ts")))
    file_transfers.sort(
        key=lambda item: (
            item.get("first_seen") is None,
            float(item.get("first_seen") or 0.0),
            0 if str(item.get("kind", "")) == "artifact" else 1,
            -int(item.get("bytes") or item.get("size_bytes") or 0),
        )
    )

    return HostDetailsSummary(
        path=Path(f"ALL_PCAPS_{len(summary_list)}"),
        target_ip=target_ip,
        operating_system=os_counter.most_common(1)[0][0] if os_counter else "Unknown",
        os_evidence=os_evidence[:10],
        total_packets=total_packets,
        relevant_packets=relevant_packets,
        packets_sent=packets_sent,
        packets_recv=packets_recv,
        bytes_sent=bytes_sent,
        bytes_recv=bytes_recv,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
        mac_addresses=sorted(macs),
        hostnames=sorted(hostnames),
        hostname_findings=hostname_findings,
        user_evidence=user_evidence,
        file_transfers=file_transfers,
        dns_queries=dns_queries,
        timeline_events=timeline_events,
        peer_counts=peer_counts,
        protocol_counts=protocol_counts,
        port_counts=port_counts,
        conversations=conversations,
        services=services,
        attack_categories=attack_categories,
        detections=detections,
        artifacts=artifacts,
        errors=errors,
    )


def analyze_hostdetails(path: Path, target_ip: str, show_status: bool = True) -> HostDetailsSummary:
    errors: list[str] = []
    if not _valid_ip(target_ip):
        return HostDetailsSummary(
            path=path,
            target_ip=target_ip,
            operating_system="Unknown",
            os_evidence=["invalid target IP"],
            total_packets=0,
            relevant_packets=0,
            packets_sent=0,
            packets_recv=0,
            bytes_sent=0,
            bytes_recv=0,
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
            mac_addresses=[],
            hostnames=[],
            hostname_findings=[],
            user_evidence=[],
            file_transfers=[],
            dns_queries=[],
            timeline_events=[],
            peer_counts=Counter(),
            protocol_counts=Counter(),
            port_counts=Counter(),
            conversations=[],
            services=[],
            attack_categories=Counter(),
            detections=[],
            artifacts=[],
            errors=[f"Invalid target IP: {target_ip}"],
        )

    peer_counts: Counter[str] = Counter()
    protocol_counts: Counter[str] = Counter()
    port_counts: Counter[int] = Counter()
    attack_categories: Counter[str] = Counter()
    detections: list[dict[str, object]] = []
    seen_detections: set[tuple[str, str, str, str]] = set()
    artifacts: list[str] = []
    seen_artifacts: set[str] = set()
    hostname_findings: list[dict[str, object]] = []
    user_evidence: list[dict[str, object]] = []
    user_seen: set[tuple[str, str, str, str, str]] = set()
    known_usernames: set[str] = set()
    file_transfers: list[dict[str, object]] = []
    file_seen: set[tuple[str, ...]] = set()
    dns_queries: list[dict[str, object]] = []
    timeline_events: list[dict[str, object]] = []

    def add_artifact(text: str) -> None:
        message = text.strip()
        if not message or message in seen_artifacts:
            return
        seen_artifacts.add(message)
        artifacts.append(message)

    def add_detection(
        source: str,
        severity: str,
        summary_text: str,
        details_text: str,
        evidence: list[str] | None = None,
        top_sources: list[tuple[object, object]] | None = None,
        top_destinations: list[tuple[object, object]] | None = None,
    ) -> None:
        key = (source, severity.lower(), summary_text, details_text)
        if key in seen_detections:
            return
        seen_detections.add(key)
        payload: dict[str, object] = {
            "source": source,
            "severity": severity.lower(),
            "summary": summary_text,
            "details": details_text,
        }
        if evidence:
            payload["evidence"] = [str(item) for item in evidence if str(item).strip()][:10]
        if top_sources:
            payload["top_sources"] = [(str(ip), int(count)) for ip, count in top_sources[:6]]
        if top_destinations:
            payload["top_destinations"] = [(str(ip), int(count)) for ip, count in top_destinations[:6]]
        detections.append(
            payload
        )
        _add_categories(attack_categories, summary_text, details_text)

    def add_user_evidence(
        username: str | None,
        domain: str | None,
        full_name: str | None,
        method: str,
        location: str,
        details: str = "",
    ) -> None:
        user = _normalize_user(username)
        full = _normalize_user(full_name)
        if not user and not full:
            return
        if not _mentions_target(location, target_ip):
            return
        if user and _is_builtin_windows_principal(user):
            return
        if full and _is_builtin_windows_principal(full):
            return
        dom = _normalize_user(domain)
        user_key = user or full or "-"
        key = (user_key, dom or "-", full or "-", method, location)
        if key in user_seen:
            return
        user_seen.add(key)
        if user:
            known_usernames.add(user.lower())
        user_evidence.append({
            "username": user or "-",
            "domain": dom or "-",
            "full_name": full or "-",
            "method": method,
            "location": location,
            "details": details,
        })

    def add_file_transfer(
        *,
        direction: str,
        kind: str,
        protocol: str,
        src_ip: str,
        dst_ip: str,
        src_port: Optional[int],
        dst_port: Optional[int],
        filename: str,
        size_bytes: Optional[int],
        bytes_count: Optional[int],
        packets: Optional[int],
        first_seen: Optional[float],
        last_seen: Optional[float],
        note: str,
        file_type: str,
        hostname: str | None,
        content_type: str | None,
        sha256: str | None,
        md5: str | None,
        packet_index: Optional[int] = None,
    ) -> None:
        key = (
            direction,
            kind,
            protocol,
            src_ip,
            dst_ip,
            str(src_port),
            str(dst_port),
            filename,
            str(size_bytes),
            str(bytes_count),
            note,
            file_type,
            hostname or "",
            content_type or "",
            sha256 or "",
            md5 or "",
            str(first_seen),
            str(last_seen),
            str(packet_index),
        )
        if key in file_seen:
            return
        file_seen.add(key)
        file_transfers.append({
            "direction": direction,
            "kind": kind,
            "protocol": protocol,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "filename": filename,
            "size_bytes": size_bytes,
            "bytes": bytes_count,
            "packets": packets,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "note": note,
            "file_type": file_type,
            "hostname": hostname,
            "content_type": content_type,
            "sha256": sha256,
            "md5": md5,
            "packet_index": packet_index,
        })

    def file_direction(src_ip: str, dst_ip: str) -> str:
        if src_ip == target_ip and dst_ip == target_ip:
            return "loopback"
        if src_ip == target_ip:
            return "upload"
        if dst_ip == target_ip:
            return "download"
        return "transit"

    def _busy(desc: str, func, *args, **kwargs):
        return run_with_busy_status(path, show_status, f"Host details: {desc}", func, *args, **kwargs)

    base_summary = analyze_pcap(path, show_status=show_status)
    ips_summary = _busy("IPs", analyze_ips, path, show_status=False)
    hostname_summary = _busy("Hostnames", analyze_hostname, path, target_ip, show_status=False, include_related=True)
    services_summary = _busy("Services", analyze_services, path, show_status=False)
    smb_summary = _busy("SMB", analyze_smb, path, show_status=False)
    kerberos_summary = _busy("Kerberos", analyze_kerberos, path, show_status=False)
    netbios_summary = _busy("NetBIOS", analyze_netbios, path, show_status=False)
    rpc_summary = _busy("RPC", analyze_rpc, path, show_status=False)
    beacon_summary = _busy("Beacons", analyze_beacons, path, show_status=False)
    exfil_summary = _busy("Exfil", analyze_exfil, path, show_status=False)
    file_summary = _busy("Files", analyze_files, path, show_status=False)
    threats_summary = _busy("Threats", analyze_threats, path, show_status=False)
    timeline_summary = _busy("Timeline", analyze_timeline, path, target_ip, show_status=False)
    arp_summary = _busy("ARP", analyze_arp, path, show_status=False)
    dhcp_summary = _busy("DHCP", analyze_dhcp, path, show_status=False)

    errors.extend(getattr(ips_summary, "errors", []))
    errors.extend(getattr(hostname_summary, "errors", []))
    errors.extend(getattr(services_summary, "errors", []))
    errors.extend(getattr(smb_summary, "errors", []))
    errors.extend(getattr(kerberos_summary, "errors", []))
    errors.extend(getattr(netbios_summary, "errors", []))
    errors.extend(getattr(rpc_summary, "errors", []))
    errors.extend(getattr(beacon_summary, "errors", []))
    errors.extend(getattr(exfil_summary, "errors", []))
    errors.extend(getattr(file_summary, "errors", []))
    errors.extend(getattr(threats_summary, "errors", []))
    errors.extend(getattr(timeline_summary, "errors", []))
    errors.extend(getattr(arp_summary, "errors", []))
    errors.extend(getattr(dhcp_summary, "errors", []))

    endpoint = next((item for item in ips_summary.endpoints if item.ip == target_ip), None)
    packets_sent = endpoint.packets_sent if endpoint else 0
    packets_recv = endpoint.packets_recv if endpoint else 0
    bytes_sent = endpoint.bytes_sent if endpoint else 0
    bytes_recv = endpoint.bytes_recv if endpoint else 0

    if endpoint:
        for peer in endpoint.peers:
            peer_counts[peer] += 1
        for proto in endpoint.protocols:
            protocol_counts[proto] += 1
        for port in endpoint.ports:
            port_counts[int(port)] += 1

    conversations: list[dict[str, object]] = []
    relevant_packets = 0
    for conv in ips_summary.conversations:
        if conv.src != target_ip and conv.dst != target_ip:
            continue
        direction = "outbound" if conv.src == target_ip else "inbound"
        peer = conv.dst if conv.src == target_ip else conv.src
        peer_counts[peer] += conv.packets
        protocol_counts[conv.protocol] += conv.packets
        for port in conv.ports:
            port_counts[int(port)] += conv.packets
        relevant_packets += conv.packets
        conversations.append(
            {
                "direction": direction,
                "peer": peer,
                "src_ip": conv.src,
                "dst_ip": conv.dst,
                "protocol": conv.protocol,
                "packets": conv.packets,
                "bytes": conv.bytes,
                "first_seen": conv.first_seen,
                "last_seen": conv.last_seen,
                "ports": ",".join(str(port) for port in conv.ports[:8]) if conv.ports else "-",
            }
        )

    hostnames: set[str] = set()
    for finding in hostname_summary.findings:
        involves_target = finding.mapped_ip == target_ip or finding.src_ip == target_ip or finding.dst_ip == target_ip
        if finding.mapped_ip == target_ip:
            hostnames.add(finding.hostname)
        if involves_target:
            hostname_findings.append({
                "hostname": finding.hostname,
                "mapped_ip": finding.mapped_ip,
                "method": finding.method,
                "protocol": finding.protocol,
                "confidence": finding.confidence,
                "details": finding.details,
                "src_ip": finding.src_ip,
                "dst_ip": finding.dst_ip,
                "first_seen": finding.first_seen,
                "last_seen": finding.last_seen,
                "count": finding.count,
            })

    for query in timeline_summary.dns_queries:
        dns_queries.append({
            "ts": query.ts,
            "name": query.name,
            "qtype": query.qtype,
            "src_ip": query.src_ip,
            "dst_ip": query.dst_ip,
            "protocol": query.protocol,
            "dst_port": query.dst_port,
        })

    for event in timeline_summary.events:
        timeline_events.append({
            "ts": event.ts,
            "category": event.category,
            "summary": event.summary,
            "details": event.details,
        })

    services: list[dict[str, object]] = []
    for asset in services_summary.assets:
        if asset.ip != target_ip and target_ip not in asset.clients:
            continue
        role = "server" if asset.ip == target_ip else "client"
        peer_hint = ", ".join(sorted(asset.clients)[:4]) if asset.clients else "-"
        services.append(
            {
                "role": role,
                "asset": f"{asset.ip}:{asset.port}",
                "service": asset.service_name,
                "protocol": asset.protocol,
                "port": asset.port,
                "packets": asset.packets,
                "bytes": asset.bytes,
                "peers": peer_hint,
                "software": asset.software or "-",
            }
        )
        protocol_counts[asset.protocol] += asset.packets
        port_counts[int(asset.port)] += asset.packets

    for risk in services_summary.risks:
        if target_ip not in str(risk.affected_asset):
            continue
        add_detection("Services", risk.severity, risk.title, risk.description)

    cname_items: list[dict[str, object]] = []
    cname_users_by_domain: dict[str, set[str]] = {}
    for item in getattr(kerberos_summary, "principal_evidence", []) or []:
        src_ip = str(item.get("src_ip", ""))
        dst_ip = str(item.get("dst_ip", ""))
        if target_ip not in {src_ip, dst_ip}:
            continue
        if str(item.get("kind", "")) != "CNameString":
            continue
        principal = str(item.get("principal", ""))
        if not principal:
            continue
        user, dom = _split_user_domain(principal)
        if not user:
            continue
        dom_key = dom or "-"
        cname_users_by_domain.setdefault(dom_key, set()).add(user)
        cname_items.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": item.get("dst_port", "-"),
            "protocol": item.get("protocol", "-"),
            "principal": principal,
            "user": user,
            "domain": dom,
            "dom_key": dom_key,
        })

    for item in cname_items:
        user = str(item.get("user", ""))
        dom = item.get("domain")
        dom_key = str(item.get("dom_key", "-"))
        if user and user[-1].isdigit():
            base_user = user.rstrip("0123456789")
            if len(base_user) >= 3 and base_user in cname_users_by_domain.get(dom_key, set()):
                user = base_user
        dst_port = item.get("dst_port", "-")
        proto = item.get("protocol", "-")
        location = f"{item.get('src_ip', '-')} -> {item.get('dst_ip', '-')}:{dst_port} {proto}"
        add_user_evidence(
            username=user,
            domain=dom if isinstance(dom, str) else None,
            full_name=None,
            method="Kerberos CNameString",
            location=location,
            details=str(item.get("principal", "")),
        )

    for item in getattr(rpc_summary, "samr_fullnames", []) or []:
        src_ip = str(item.get("src_ip", ""))
        dst_ip = str(item.get("dst_ip", ""))
        if target_ip not in {src_ip, dst_ip}:
            continue
        full_name = str(item.get("full_name", "")).strip()
        if not full_name:
            continue
        details_bits: list[str] = []
        opnum = item.get("opnum")
        if opnum is not None and str(opnum).isdigit():
            details_bits.append(f"opnum={opnum}")
        location = f"{src_ip} -> {dst_ip} SAMR QueryUserInfo"
        add_user_evidence(
            username=None,
            domain=None,
            full_name=full_name,
            method="SAMR QueryUserInfo",
            location=location,
            details=" ".join(details_bits),
        )

    for item in beacon_summary.candidates:
        if item.src_ip != target_ip and item.dst_ip != target_ip:
            continue
        summary_text = "Potential beaconing pattern"
        details = (
            f"{item.src_ip} -> {item.dst_ip} {item.proto} score={item.score:.2f} "
            f"count={item.count} median_interval={item.median_interval:.2f}s"
        )
        severity = "warning" if item.score < 0.85 else "high"
        add_detection("Beacon", severity, summary_text, details)

    for item in exfil_summary.outbound_flows:
        src = str(item.get("src", ""))
        dst = str(item.get("dst", ""))
        if src != target_ip and dst != target_ip:
            continue
        add_artifact(
            f"Outbound flow {src} -> {dst} {item.get('proto', '-')}:{item.get('dst_port', '-')} "
            f"bytes={item.get('bytes', 0)} packets={item.get('packets', 0)}"
        )
        if src == target_ip:
            add_detection(
                "Exfil",
                "warning",
                "Host involved in private-to-public outbound flow",
                f"{src} -> {dst} {item.get('proto', '-')}:{item.get('dst_port', '-')}",
                evidence=[
                    f"flow={src} -> {dst}",
                    f"proto={item.get('proto', '-')} dport={item.get('dst_port', '-')}",
                    f"bytes={item.get('bytes', 0)} packets={item.get('packets', 0)}",
                ],
            )

    for item in exfil_summary.dns_tunnel_suspects:
        if str(item.get("src", "")) != target_ip:
            continue
        add_detection(
            "Exfil",
            "high",
            "Potential DNS tunneling",
            f"src={target_ip} queries={item.get('total')} unique={item.get('unique')} avg_entropy={item.get('avg_entropy')}",
            evidence=[
                f"src={target_ip}",
                f"query_total={item.get('total')} unique={item.get('unique')}",
                f"avg_entropy={item.get('avg_entropy')} max_label={item.get('max_label')}",
            ],
        )

    for item in exfil_summary.http_post_suspects:
        src = str(item.get("src", ""))
        dst = str(item.get("dst", ""))
        if src != target_ip and dst != target_ip:
            continue
        add_detection(
            "Exfil",
            "warning",
            "Large HTTP POST transfer",
            f"{src} -> {dst} host={item.get('host', '-')} bytes={item.get('bytes', 0)} requests={item.get('requests', 1)}",
            evidence=[
                f"flow={src} -> {dst}",
                f"host={item.get('host', '-')} uri={item.get('uri', '-')}",
                f"bytes={item.get('bytes', 0)} requests={item.get('requests', 1)}",
            ],
        )

    for detection in threats_summary.detections:
        if not _mentions_target(detection, target_ip):
            continue
        evidence_values = [str(item) for item in (detection.get("evidence", []) or []) if str(item).strip()]
        filename = _extract_detection_filename(
            str(detection.get("summary", "Threat signal")),
            str(detection.get("details", "")),
        )
        if filename:
            evidence_values.extend(_artifact_evidence_for_filename(filename, file_summary, target_ip))
        dedup_evidence: list[str] = []
        seen_evidence: set[str] = set()
        for item in evidence_values:
            if item in seen_evidence:
                continue
            seen_evidence.add(item)
            dedup_evidence.append(item)
        add_detection(
            str(detection.get("source", "Threats")),
            str(detection.get("severity", "info")),
            str(detection.get("summary", "Threat signal")),
            str(detection.get("details", "")),
            evidence=dedup_evidence,
            top_sources=[(ip, count) for ip, count in (detection.get("top_sources", []) or [])],
            top_destinations=[(ip, count) for ip, count in (detection.get("top_destinations", []) or [])],
        )

    for event in timeline_summary.events:
        text = f"{event.summary} {event.details}".lower()
        if any(token in text for token in ("scan", "probe", "brute", "failed", "post", "artifact", "connect attempt")):
            add_detection(
                "Timeline",
                "warning",
                event.summary,
                event.details,
                evidence=[f"category={event.category}", f"target_ip={target_ip}"],
            )
        add_artifact(f"{event.category}: {event.summary} :: {event.details}")

    for anomaly in arp_summary.anomalies:
        if target_ip not in f"{anomaly.src} {anomaly.dst} {anomaly.description}":
            continue
        add_detection("ARP", anomaly.severity, anomaly.title, anomaly.description)

    for anomaly in dhcp_summary.anomalies:
        if target_ip not in f"{anomaly.src} {anomaly.dst} {anomaly.description}":
            continue
        add_detection("DHCP", anomaly.severity, anomaly.title, anomaly.description)

    if dhcp_summary.probe_sources.get(target_ip, 0) > 0:
        add_detection(
            "DHCP",
            "warning",
            "DHCP probing behavior",
            f"Host generated {dhcp_summary.probe_sources[target_ip]} probe-like DHCP events",
        )
    if dhcp_summary.brute_force_sources.get(target_ip, 0) > 0:
        add_detection(
            "DHCP",
            "warning",
            "DHCP brute-force indicators",
            f"Host generated {dhcp_summary.brute_force_sources[target_ip]} brute-force style DHCP bursts",
        )

    for artifact in getattr(file_summary, "artifacts", []) or []:
        src_ip = str(getattr(artifact, "src_ip", "") or "")
        dst_ip = str(getattr(artifact, "dst_ip", "") or "")
        if target_ip not in {src_ip, dst_ip}:
            continue
        add_file_transfer(
            direction=file_direction(src_ip, dst_ip),
            kind="artifact",
            protocol=str(getattr(artifact, "protocol", "-")),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=getattr(artifact, "src_port", None),
            dst_port=getattr(artifact, "dst_port", None),
            filename=str(getattr(artifact, "filename", "-") or "-"),
            size_bytes=getattr(artifact, "size_bytes", None),
            bytes_count=getattr(artifact, "size_bytes", None),
            packets=None,
            first_seen=None,
            last_seen=None,
            note=str(getattr(artifact, "note", "") or ""),
            file_type=str(getattr(artifact, "file_type", "") or ""),
            hostname=getattr(artifact, "hostname", None),
            content_type=getattr(artifact, "content_type", None),
            sha256=getattr(artifact, "sha256", None),
            md5=getattr(artifact, "md5", None),
            packet_index=getattr(artifact, "packet_index", None),
        )

    for transfer in getattr(file_summary, "candidates", []) or []:
        src_ip = str(getattr(transfer, "src_ip", "") or "")
        dst_ip = str(getattr(transfer, "dst_ip", "") or "")
        if target_ip not in {src_ip, dst_ip}:
            continue
        add_file_transfer(
            direction=file_direction(src_ip, dst_ip),
            kind="candidate",
            protocol=str(getattr(transfer, "protocol", "-")),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=getattr(transfer, "src_port", None),
            dst_port=getattr(transfer, "dst_port", None),
            filename="-",
            size_bytes=None,
            bytes_count=getattr(transfer, "bytes", None),
            packets=getattr(transfer, "packets", None),
            first_seen=getattr(transfer, "first_seen", None),
            last_seen=getattr(transfer, "last_seen", None),
            note=str(getattr(transfer, "note", "") or ""),
            file_type="",
            hostname=None,
            content_type=None,
            sha256=None,
            md5=None,
        )

    mac_addresses = _extract_mac_values(target_ip, arp_summary, dhcp_summary)

    dedup_errors: list[str] = []
    seen_errors: set[str] = set()
    for err in errors:
        if err in seen_errors:
            continue
        seen_errors.add(err)
        dedup_errors.append(err)

    detections.sort(key=lambda item: _severity_rank(str(item.get("severity", "info"))))
    conversations.sort(key=lambda item: int(item.get("bytes", 0) or 0), reverse=True)
    services.sort(key=lambda item: int(item.get("packets", 0) or 0), reverse=True)
    operating_system, os_evidence = _infer_operating_system(hostnames, services, dhcp_summary)
    hostname_findings.sort(key=lambda item: int(item.get("count", 0) or 0), reverse=True)
    file_transfers.sort(
        key=lambda item: (
            item.get("first_seen") is None,
            float(item.get("first_seen") or 0.0),
            0 if str(item.get("kind", "")) == "artifact" else 1,
            -int(item.get("bytes") or item.get("size_bytes") or 0),
        )
    )

    return HostDetailsSummary(
        path=path,
        target_ip=target_ip,
        operating_system=operating_system,
        os_evidence=os_evidence,
        total_packets=base_summary.packet_count,
        relevant_packets=relevant_packets,
        packets_sent=packets_sent,
        packets_recv=packets_recv,
        bytes_sent=bytes_sent,
        bytes_recv=bytes_recv,
        first_seen=base_summary.start_ts,
        last_seen=base_summary.end_ts,
        duration_seconds=base_summary.duration_seconds,
        mac_addresses=mac_addresses,
        hostnames=sorted(hostnames),
        hostname_findings=hostname_findings,
        user_evidence=user_evidence,
        file_transfers=file_transfers,
        dns_queries=dns_queries,
        timeline_events=timeline_events,
        peer_counts=peer_counts,
        protocol_counts=protocol_counts,
        port_counts=port_counts,
        conversations=conversations,
        services=services,
        attack_categories=attack_categories,
        detections=detections,
        artifacts=artifacts[:200],
        errors=dedup_errors,
    )
