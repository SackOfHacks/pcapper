from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from .analyzer import analyze_pcap
from .arp import analyze_arp
from .dhcp import analyze_dhcp
from .files import analyze_files
from .hostname import analyze_hostname
from .ips import analyze_ips
from .netbios import analyze_netbios
from .progress import run_with_busy_status
from .services import analyze_services
from .timeline import analyze_timeline
from .webrequests import analyze_webrequests


@dataclass(frozen=True)
class HostDetailsSummary:
    path: Path
    target_ip: str
    hostname_query: str | None
    port_filter: int | None
    search_query: str | None
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
    web_requests: list[dict[str, object]]
    timeline_events: list[dict[str, object]]
    peer_counts: Counter[str]
    protocol_counts: Counter[str]
    port_counts: Counter[int]
    conversations: list[dict[str, object]]
    services: list[dict[str, object]]
    attack_categories: Counter[str]
    detections: list[dict[str, object]]
    artifacts: list[str]
    deterministic_checks: dict[str, list[str]]
    sequence_violations: list[str]
    attack_path_steps: list[str]
    peer_risk: Counter[str]
    evidence_anchors: list[dict[str, object]]
    host_verdict: str
    host_confidence: str
    host_verdict_score: int
    host_verdict_reasons: list[str]
    errors: list[str]


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def _canonical_ip(value: str | None) -> str | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except Exception:
        return None


def _host_window(
    conversations: list[dict[str, object]],
    timeline_events: list[dict[str, object]],
    dns_queries: list[dict[str, object]],
    file_transfers: list[dict[str, object]],
) -> tuple[Optional[float], Optional[float]]:
    points: list[float] = []
    for row in conversations:
        for key in ("first_seen", "last_seen"):
            value = row.get(key)
            if isinstance(value, (int, float)):
                points.append(float(value))
    for row in timeline_events:
        value = row.get("ts")
        if isinstance(value, (int, float)):
            points.append(float(value))
    for row in dns_queries:
        value = row.get("ts")
        if isinstance(value, (int, float)):
            points.append(float(value))
    for row in file_transfers:
        for key in ("first_seen", "last_seen"):
            value = row.get(key)
            if isinstance(value, (int, float)):
                points.append(float(value))
    if not points:
        return None, None
    return min(points), max(points)


def _extract_mac_values(target_ip: str, arp_summary, dhcp_summary) -> list[str]:
    macs: set[str] = set()

    for convo in getattr(arp_summary, "conversations", []) or []:
        if convo.src_ip == target_ip and convo.src_mac:
            macs.add(convo.src_mac.lower())
        if convo.dst_ip == target_ip and convo.dst_mac:
            macs.add(convo.dst_mac.lower())

    for session in getattr(dhcp_summary, "sessions", []) or []:
        if (
            session.client_ip == target_ip or session.server_ip == target_ip
        ) and session.client_mac:
            macs.add(str(session.client_mac).lower())

    return sorted(mac for mac in macs if mac and mac != "00:00:00:00:00:00")


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
        if any(
            token in lower for token in ("win", "wks", "pc-", "desktop-", "server-")
        ):
            os_scores["Windows"] += 2
            _add_evidence(f"hostname:{name} -> windows-like naming")
        if any(
            token in lower for token in ("ubuntu", "debian", "centos", "kali", "linux")
        ):
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
            _add_evidence(
                f"service:{service.get('service', '-')} -> OT/ICS protocol marker"
            )
        if any(marker in blob for marker in appliance_markers):
            os_scores["Network/IoT Appliance"] += 3
            _add_evidence(f"service:{service.get('service', '-')} -> appliance marker")
        if any(marker in blob for marker in rtos_markers):
            os_scores["Embedded RTOS"] += 5
            _add_evidence(f"software:{service.get('software', '-')} -> RTOS marker")
        if any(marker in blob for marker in plc_markers):
            os_scores["OT/ICS Device (Embedded/Appliance)"] += 4
            _add_evidence(
                f"software/service:{service.get('software', '-')}/{service.get('service', '-')} -> PLC/HMI vendor marker"
            )

        if any(token in blob for token in ("microsoft", "windows", "iis", "exchange")):
            os_scores["Windows"] += 3
            _add_evidence(
                f"software:{service.get('software', '-')} -> windows server marker"
            )
        if any(
            token in blob
            for token in ("ubuntu", "debian", "centos", "red hat", "linux kernel")
        ):
            os_scores["Linux/Unix"] += 3
            _add_evidence(f"software:{service.get('software', '-')} -> linux marker")
        if any(token in blob for token in ("darwin", "mac os", "macos", "apple")):
            os_scores["macOS"] += 3
            _add_evidence(f"software:{service.get('software', '-')} -> macOS marker")
        if "openssh" in blob and "windows" not in blob:
            os_scores["Linux/Unix"] += 1
            _add_evidence("software:OpenSSH without windows marker")

    for vendor_class, count in getattr(
        dhcp_summary, "vendor_classes", Counter()
    ).most_common(20):
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
        if any(
            token in text
            for token in (
                "plc",
                "hmi",
                "scada",
                "dcs",
                "siemens",
                "rockwell",
                "schneider",
                "omron",
                "yokogawa",
                "honeywell",
                "mitsubishi",
            )
        ):
            os_scores["OT/ICS Device (Embedded/Appliance)"] += max(
                1, int(count // 4) + 1
            )
            _add_evidence(f"dhcp_vendor:{vendor_class} -> OT/ICS vendor marker")
        if any(token in text for token in ("vxworks", "qnx", "freertos", "rtos")):
            os_scores["Embedded RTOS"] += max(1, int(count // 4) + 1)
            _add_evidence(f"dhcp_vendor:{vendor_class} -> RTOS marker")

    for hostname in hostnames:
        text = hostname.lower()
        if any(
            token in text
            for token in ("plc", "hmi", "scada", "rtu", "dcs", "histori", "opc")
        ):
            os_scores["OT/ICS Device (Embedded/Appliance)"] += 3
            _add_evidence(f"hostname:{hostname} -> OT/ICS naming marker")
        if any(
            token in text
            for token in (
                "router",
                "switch",
                "fw",
                "firewall",
                "gateway",
                "sensor",
                "camera",
            )
        ):
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
    if (ot_score >= 4 or rtos_score >= 4) and max(
        windows_score, linux_score, mac_score
    ) <= max(ot_score, rtos_score):
        if rtos_score > ot_score:
            return "Embedded RTOS", evidence[:8]
        return "OT/ICS Device (Embedded/Appliance)", evidence[:8]

    return os_scores.most_common(1)[0][0], evidence[:8]


def merge_hostdetails_summaries(
    summaries: Iterable[HostDetailsSummary],
) -> HostDetailsSummary:
    summary_list = list(summaries)
    if not summary_list:
        return HostDetailsSummary(
            path=Path("ALL_PCAPS_0"),
            target_ip="-",
            hostname_query=None,
            port_filter=None,
            search_query=None,
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
            web_requests=[],
            timeline_events=[],
            peer_counts=Counter(),
            protocol_counts=Counter(),
            port_counts=Counter(),
            conversations=[],
            services=[],
            attack_categories=Counter(),
            detections=[],
            artifacts=[],
            deterministic_checks={},
            sequence_violations=[],
            attack_path_steps=[],
            peer_risk=Counter(),
            evidence_anchors=[],
            host_verdict="NO STRONG SIGNAL - NO CONVINCING HIGH-CONFIDENCE HOST ABUSE PATTERN",
            host_confidence="low",
            host_verdict_score=0,
            host_verdict_reasons=[],
            errors=[],
        )

    target_ip = summary_list[0].target_ip
    hostname_query = summary_list[0].hostname_query
    port_filter = summary_list[0].port_filter
    search_query = summary_list[0].search_query
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
    web_requests: list[dict[str, object]] = []
    web_seen: set[tuple[object, ...]] = set()
    timeline_events: list[dict[str, object]] = []
    timeline_seen: set[tuple[object, ...]] = set()
    peer_counts: Counter[str] = Counter()
    protocol_counts: Counter[str] = Counter()
    port_counts: Counter[int] = Counter()
    attack_categories: Counter[str] = Counter()
    deterministic_checks: dict[str, list[str]] = defaultdict(list)
    sequence_violations: list[str] = []
    attack_path_steps: list[str] = []
    peer_risk: Counter[str] = Counter()
    evidence_anchors: list[dict[str, object]] = []
    host_verdict = "NO STRONG SIGNAL - NO CONVINCING HIGH-CONFIDENCE HOST ABUSE PATTERN"
    host_confidence = "low"
    host_verdict_score = 0
    host_verdict_reasons: list[str] = []

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

        if summary.first_seen is not None and (
            first_seen is None or summary.first_seen < first_seen
        ):
            first_seen = summary.first_seen
        if summary.last_seen is not None and (
            last_seen is None or summary.last_seen > last_seen
        ):
            last_seen = summary.last_seen
        # Duration is normalized later from merged first/last seen.

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
                existing["count"] = int(existing.get("count", 0) or 0) + int(
                    finding.get("count", 0) or 0
                )
                first_seen_val = existing.get("first_seen")
                new_first = finding.get("first_seen")
                if new_first is not None and (
                    first_seen_val is None or new_first < first_seen_val
                ):
                    existing["first_seen"] = new_first
                last_seen_val = existing.get("last_seen")
                new_last = finding.get("last_seen")
                if new_last is not None and (
                    last_seen_val is None or new_last > last_seen_val
                ):
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

        for req in summary.web_requests:
            key = (
                req.get("ts"),
                req.get("src_ip"),
                req.get("dst_ip"),
                req.get("src_port"),
                req.get("dst_port"),
                req.get("method"),
                req.get("host"),
                req.get("uri"),
                req.get("response_code"),
            )
            if key in web_seen:
                continue
            web_seen.add(key)
            web_requests.append(dict(req))

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
        for key, values in (summary.deterministic_checks or {}).items():
            for value in values or []:
                deterministic_checks[str(key)].append(str(value))
        for value in summary.sequence_violations or []:
            text = str(value)
            if text and text not in sequence_violations:
                sequence_violations.append(text)
        for value in summary.attack_path_steps or []:
            text = str(value)
            if text and text not in attack_path_steps:
                attack_path_steps.append(text)
        peer_risk.update(summary.peer_risk or Counter())
        for row in summary.evidence_anchors or []:
            if row not in evidence_anchors:
                evidence_anchors.append(dict(row))
        if int(summary.host_verdict_score or 0) > host_verdict_score:
            host_verdict_score = int(summary.host_verdict_score or 0)
            host_verdict = str(summary.host_verdict or host_verdict)
            host_confidence = str(summary.host_confidence or host_confidence)
            host_verdict_reasons = [
                str(v) for v in (summary.host_verdict_reasons or [])
            ]
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
            existing_evidence = [
                str(value)
                for value in (merged.get("evidence", []) or [])
                if str(value).strip()
            ]
            new_evidence = [
                str(value)
                for value in (item.get("evidence", []) or [])
                if str(value).strip()
            ]
            seen_ev: set[str] = set(existing_evidence)
            for value in new_evidence:
                if value not in seen_ev:
                    seen_ev.add(value)
                    existing_evidence.append(value)
            if existing_evidence:
                merged["evidence"] = existing_evidence[:12]

            def _merge_top(field: str) -> None:
                top_counter: Counter[str] = Counter()
                for ip, count in merged.get(field, []) or []:
                    top_counter[str(ip)] += int(count)
                for ip, count in item.get(field, []) or []:
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
    hostname_findings.sort(
        key=lambda item: int(item.get("count", 0) or 0), reverse=True
    )
    dns_queries.sort(key=lambda item: (item.get("ts") is None, item.get("ts")))
    web_requests.sort(key=lambda item: (item.get("ts") is None, item.get("ts")))
    timeline_events.sort(key=lambda item: (item.get("ts") is None, item.get("ts")))
    file_transfers.sort(
        key=lambda item: (
            item.get("first_seen") is None,
            float(item.get("first_seen") or 0.0),
            0 if str(item.get("kind", "")) == "artifact" else 1,
            -int(item.get("bytes") or item.get("size_bytes") or 0),
        )
    )

    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, float(last_seen) - float(first_seen))

    dedup_checks: dict[str, list[str]] = {}
    for key, values in deterministic_checks.items():
        dedup_checks[key] = list(
            dict.fromkeys([str(v) for v in values if str(v).strip()])
        )[:80]

    return HostDetailsSummary(
        path=Path(f"ALL_PCAPS_{len(summary_list)}"),
        target_ip=target_ip,
        hostname_query=hostname_query,
        port_filter=port_filter,
        search_query=search_query,
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
        web_requests=web_requests,
        timeline_events=timeline_events,
        peer_counts=peer_counts,
        protocol_counts=protocol_counts,
        port_counts=port_counts,
        conversations=conversations,
        services=services,
        attack_categories=attack_categories,
        detections=detections,
        artifacts=artifacts,
        deterministic_checks=dedup_checks,
        sequence_violations=sequence_violations[:40],
        attack_path_steps=attack_path_steps[:16],
        peer_risk=peer_risk,
        evidence_anchors=evidence_anchors[:150],
        host_verdict=host_verdict,
        host_confidence=host_confidence,
        host_verdict_score=host_verdict_score,
        host_verdict_reasons=host_verdict_reasons[:16],
        errors=errors,
    )


def analyze_hostdetails(
    path: Path,
    target_ip: str,
    show_status: bool = True,
    *,
    hostname_query: str | None = None,
    port_filter: int | None = None,
    search_query: str | None = None,
    services_summary=None,
    smb_summary=None,
    file_summary=None,
    threats_summary=None,
    timeline_summary=None,
) -> HostDetailsSummary:
    hostname_query_text = str(hostname_query or "").strip()
    search_query_text = str(search_query or "").strip()
    errors: list[str] = []
    if not _valid_ip(target_ip):
        return HostDetailsSummary(
            path=path,
            target_ip=target_ip,
            hostname_query=hostname_query_text or None,
            port_filter=port_filter,
            search_query=search_query_text or None,
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
            web_requests=[],
            timeline_events=[],
            peer_counts=Counter(),
            protocol_counts=Counter(),
            port_counts=Counter(),
            conversations=[],
            services=[],
            attack_categories=Counter(),
            detections=[],
            artifacts=[],
            deterministic_checks={},
            sequence_violations=[],
            attack_path_steps=[],
            peer_risk=Counter(),
            evidence_anchors=[],
            host_verdict="NO STRONG SIGNAL - NO CONVINCING HIGH-CONFIDENCE HOST ABUSE PATTERN",
            host_confidence="low",
            host_verdict_score=0,
            host_verdict_reasons=[],
            errors=[f"Invalid target IP: {target_ip}"],
        )

    peer_counts: Counter[str] = Counter()
    protocol_counts: Counter[str] = Counter()
    port_counts: Counter[int] = Counter()
    attack_categories: Counter[str] = Counter()
    detections: list[dict[str, object]] = []
    artifacts: list[str] = []
    hostname_findings: list[dict[str, object]] = []
    user_evidence: list[dict[str, object]] = []
    file_transfers: list[dict[str, object]] = []
    file_seen: set[tuple[str, ...]] = set()
    dns_queries: list[dict[str, object]] = []
    web_requests: list[dict[str, object]] = []
    timeline_events: list[dict[str, object]] = []

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
        file_transfers.append(
            {
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
            }
        )

    def file_direction(src_ip: str, dst_ip: str) -> str:
        if src_ip == target_ip and dst_ip == target_ip:
            return "loopback"
        if src_ip == target_ip:
            return "upload"
        if dst_ip == target_ip:
            return "download"
        return "transit"

    def _busy(desc: str, func, *args, **kwargs):
        return run_with_busy_status(
            path, show_status, f"Host details: {desc}", func, *args, **kwargs
        )

    base_summary = analyze_pcap(path, show_status=show_status)
    ips_summary = _busy("IPs", analyze_ips, path, show_status=False)
    # Hostdetails identity should only include names mapped to the target IP itself.
    hostname_summary = _busy(
        "Hostnames",
        analyze_hostname,
        path,
        target_ip,
        show_status=False,
        include_related=False,
        hostname_query=hostname_query_text or None,
        port_filter=port_filter,
        search_query=search_query_text or None,
    )
    services_summary = (
        services_summary
        if services_summary is not None
        else _busy("Services", analyze_services, path, show_status=False)
    )
    netbios_summary = _busy("NetBIOS", analyze_netbios, path, show_status=False)
    webrequests_summary = _busy(
        "Web requests",
        analyze_webrequests,
        path,
        target_ip=target_ip,
        show_status=False,
    )
    file_summary = (
        file_summary
        if file_summary is not None
        else _busy("Files", analyze_files, path, show_status=False)
    )
    timeline_summary = (
        timeline_summary
        if timeline_summary is not None
        else _busy("Timeline", analyze_timeline, path, target_ip, show_status=False)
    )
    arp_summary = _busy("ARP", analyze_arp, path, show_status=False)
    dhcp_summary = _busy("DHCP", analyze_dhcp, path, show_status=False)

    errors.extend(getattr(ips_summary, "errors", []))
    errors.extend(getattr(hostname_summary, "errors", []))
    errors.extend(getattr(services_summary, "errors", []))
    errors.extend(getattr(netbios_summary, "errors", []))
    errors.extend(getattr(webrequests_summary, "errors", []))
    errors.extend(getattr(file_summary, "errors", []))
    errors.extend(getattr(timeline_summary, "errors", []))
    errors.extend(getattr(arp_summary, "errors", []))
    errors.extend(getattr(dhcp_summary, "errors", []))

    endpoint = next(
        (item for item in ips_summary.endpoints if item.ip == target_ip), None
    )
    packets_sent = endpoint.packets_sent if endpoint else 0
    packets_recv = endpoint.packets_recv if endpoint else 0
    bytes_sent = endpoint.bytes_sent if endpoint else 0
    bytes_recv = endpoint.bytes_recv if endpoint else 0

    # Endpoint peer/protocol/port presence is intentionally not merged into packet-volume counters.

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
                "ports": ",".join(str(port) for port in conv.ports[:8])
                if conv.ports
                else "-",
            }
        )

    hostnames: set[str] = set()
    target_canonical = _canonical_ip(target_ip) or target_ip
    for finding in hostname_summary.findings:
        mapped_canonical = _canonical_ip(finding.mapped_ip) or finding.mapped_ip
        src_canonical = _canonical_ip(finding.src_ip) or finding.src_ip
        dst_canonical = _canonical_ip(finding.dst_ip) or finding.dst_ip
        involves_target = (
            mapped_canonical == target_canonical
            or src_canonical == target_canonical
            or dst_canonical == target_canonical
        )
        if mapped_canonical == target_canonical:
            hostnames.add(finding.hostname)
        if involves_target:
            hostname_findings.append(
                {
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
                }
            )

    # Recover NetBIOS-resolved identity for the exact target host (NBNS/NBSTAT only).
    target_netbios_host = None
    for nb_host_ip, nb_host in getattr(netbios_summary, "hosts", {}).items():
        nb_canonical = _canonical_ip(nb_host_ip) or str(nb_host_ip)
        if nb_canonical == target_canonical:
            target_netbios_host = nb_host
            break

    if target_netbios_host is not None:
        nb_name_counts: Counter[tuple[str, int, str, str, str]] = Counter()
        for nb_name in getattr(target_netbios_host, "names", []) or []:
            name_value = str(getattr(nb_name, "name", "") or "").strip()
            if not name_value:
                continue
            suffix_value = int(getattr(nb_name, "suffix", 0) or 0)
            scope_value = str(getattr(nb_name, "scope", "UNKNOWN") or "UNKNOWN")
            source_value = str(getattr(nb_name, "source", "NBNS") or "NBNS")
            type_value = str(getattr(nb_name, "type_str", "") or "")
            hostnames.add(name_value)
            nb_name_counts[
                (name_value, suffix_value, scope_value, source_value, type_value)
            ] += 1

        for (
            name_value,
            suffix_value,
            scope_value,
            source_value,
            type_value,
        ), count in nb_name_counts.items():
            confidence = "high" if source_value.upper() == "NBSTAT" else "medium"
            details = f"NetBIOS {source_value} name {name_value}<{suffix_value:02X}> ({scope_value})"
            if type_value:
                details = f"{details} type={type_value}"
            hostname_findings.append(
                {
                    "hostname": name_value,
                    "mapped_ip": target_ip,
                    "method": "netbios",
                    "protocol": "NBNS",
                    "confidence": confidence,
                    "details": details,
                    "src_ip": target_ip,
                    "dst_ip": "-",
                    "first_seen": None,
                    "last_seen": None,
                    "count": int(count),
                }
            )

    for query in timeline_summary.dns_queries:
        dns_queries.append(
            {
                "ts": query.ts,
                "name": query.name,
                "qtype": query.qtype,
                "src_ip": query.src_ip,
                "dst_ip": query.dst_ip,
                "protocol": query.protocol,
                "dst_port": query.dst_port,
            }
        )

    for req in getattr(webrequests_summary, "requests", []) or []:
        src_ip = str(getattr(req, "src_ip", "") or "")
        if src_ip != target_ip:
            continue
        web_requests.append(
            {
                "ts": getattr(req, "ts", None),
                "src_ip": src_ip,
                "dst_ip": str(getattr(req, "dst_ip", "") or ""),
                "src_port": getattr(req, "src_port", None),
                "dst_port": getattr(req, "dst_port", None),
                "method": str(getattr(req, "method", "") or ""),
                "host": str(getattr(req, "host", "") or ""),
                "uri": str(getattr(req, "uri", "") or ""),
                "http_version": str(getattr(req, "http_version", "") or ""),
                "response_code": getattr(req, "response_code", None),
                "response_name": str(getattr(req, "response_name", "") or ""),
                "risk_level": str(getattr(req, "risk_level", "") or ""),
                "risk_score": int(getattr(req, "risk_score", 0) or 0),
            }
        )

    for event in timeline_summary.events:
        timeline_events.append(
            {
                "ts": event.ts,
                "category": event.category,
                "summary": event.summary,
                "details": event.details,
                "packet_index": getattr(event, "packet_index", None),
                "source": getattr(event, "source", "timeline"),
            }
        )

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

    # Legacy threat/detection enrichment removed after hostdetails output revamp.

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

    def _row_matches_port(row: dict[str, object], port: int | None) -> bool:
        if not isinstance(port, int) or port <= 0:
            return True
        for key in ("port", "src_port", "dst_port"):
            value = row.get(key)
            if isinstance(value, int) and value == port:
                return True
            if isinstance(value, str):
                text = value.strip()
                if text.isdigit() and int(text) == port:
                    return True
        ports_blob = str(row.get("ports", "") or "")
        if ports_blob:
            for token in ports_blob.split(","):
                token = token.strip()
                if token.isdigit() and int(token) == port:
                    return True
        return False

    def _row_matches_search(row: dict[str, object], query: str) -> bool:
        if not query:
            return True
        haystack = " ".join(str(v) for v in row.values()).lower()
        return query in haystack

    # Hostdetails filters intentionally narrow output artifacts/rows while keeping
    # baseline host identity and host-level packet/byte counters for context.
    if port_filter is not None:
        conversations = [
            item for item in conversations if _row_matches_port(item, port_filter)
        ]
        services = [item for item in services if _row_matches_port(item, port_filter)]
        web_requests = [
            item for item in web_requests if _row_matches_port(item, port_filter)
        ]
        dns_queries = [
            item for item in dns_queries if _row_matches_port(item, port_filter)
        ]
        file_transfers = [
            item for item in file_transfers if _row_matches_port(item, port_filter)
        ]

    hostname_filter_lc = hostname_query_text.lower()
    if hostname_filter_lc:
        hostname_findings = [
            item
            for item in hostname_findings
            if hostname_filter_lc in str(item.get("hostname", "")).lower()
        ]
        hostnames = {
            value
            for value in hostnames
            if hostname_filter_lc in str(value).lower()
        }
        web_requests = [
            item
            for item in web_requests
            if hostname_filter_lc in str(item.get("host", "")).lower()
        ]
        file_transfers = [
            item
            for item in file_transfers
            if hostname_filter_lc in str(item.get("hostname", "")).lower()
        ]

    search_token = search_query_text.lower()
    if search_token:
        hostname_findings = [
            item for item in hostname_findings if _row_matches_search(item, search_token)
        ]
        dns_queries = [item for item in dns_queries if _row_matches_search(item, search_token)]
        web_requests = [
            item for item in web_requests if _row_matches_search(item, search_token)
        ]
        file_transfers = [
            item for item in file_transfers if _row_matches_search(item, search_token)
        ]
        timeline_events = [
            item for item in timeline_events if _row_matches_search(item, search_token)
        ]
        conversations = [
            item for item in conversations if _row_matches_search(item, search_token)
        ]
        services = [item for item in services if _row_matches_search(item, search_token)]
        hostnames = {
            value
            for value in hostnames
            if search_token in str(value).lower()
        }

    mac_addresses = _extract_mac_values(target_ip, arp_summary, dhcp_summary)

    dedup_errors: list[str] = []
    seen_errors: set[str] = set()
    for err in errors:
        if err in seen_errors:
            continue
        seen_errors.add(err)
        dedup_errors.append(err)

    conversations.sort(key=lambda item: int(item.get("bytes", 0) or 0), reverse=True)
    services.sort(key=lambda item: int(item.get("packets", 0) or 0), reverse=True)
    operating_system, os_evidence = _infer_operating_system(
        hostnames, services, dhcp_summary
    )
    hostname_findings.sort(
        key=lambda item: int(item.get("count", 0) or 0), reverse=True
    )
    web_requests.sort(key=lambda item: (item.get("ts") is None, item.get("ts")))
    file_transfers.sort(
        key=lambda item: (
            item.get("first_seen") is None,
            float(item.get("first_seen") or 0.0),
            0 if str(item.get("kind", "")) == "artifact" else 1,
            -int(item.get("bytes") or item.get("size_bytes") or 0),
        )
    )

    host_first_seen, host_last_seen = _host_window(
        conversations, timeline_events, dns_queries, file_transfers
    )
    if host_first_seen is None:
        host_first_seen = base_summary.start_ts
    if host_last_seen is None:
        host_last_seen = base_summary.end_ts
    host_duration_seconds = None
    if host_first_seen is not None and host_last_seen is not None:
        host_duration_seconds = max(0.0, float(host_last_seen) - float(host_first_seen))

    deterministic_checks: dict[str, list[str]] = {}
    sequence_violations: list[str] = []
    attack_path_steps: list[str] = []
    peer_risk: Counter[str] = Counter()
    evidence_anchors: list[dict[str, object]] = []
    host_verdict = "NO STRONG SIGNAL - NO CONVINCING HIGH-CONFIDENCE HOST ABUSE PATTERN"
    host_confidence = "low"
    host_verdict_score = 0
    host_verdict_reasons: list[str] = []

    return HostDetailsSummary(
        path=path,
        target_ip=target_ip,
        hostname_query=hostname_query_text or None,
        port_filter=port_filter,
        search_query=search_query_text or None,
        operating_system=operating_system,
        os_evidence=os_evidence,
        total_packets=base_summary.packet_count,
        relevant_packets=relevant_packets,
        packets_sent=packets_sent,
        packets_recv=packets_recv,
        bytes_sent=bytes_sent,
        bytes_recv=bytes_recv,
        first_seen=host_first_seen,
        last_seen=host_last_seen,
        duration_seconds=host_duration_seconds,
        mac_addresses=mac_addresses,
        hostnames=sorted(hostnames),
        hostname_findings=hostname_findings,
        user_evidence=user_evidence,
        file_transfers=file_transfers,
        dns_queries=dns_queries,
        web_requests=web_requests,
        timeline_events=timeline_events,
        peer_counts=peer_counts,
        protocol_counts=protocol_counts,
        port_counts=port_counts,
        conversations=conversations,
        services=services,
        attack_categories=attack_categories,
        detections=detections,
        artifacts=artifacts[:200],
        deterministic_checks=deterministic_checks,
        sequence_violations=sequence_violations,
        attack_path_steps=attack_path_steps,
        peer_risk=peer_risk,
        evidence_anchors=evidence_anchors,
        host_verdict=host_verdict,
        host_confidence=host_confidence,
        host_verdict_score=host_verdict_score,
        host_verdict_reasons=host_verdict_reasons,
        errors=dedup_errors,
    )
