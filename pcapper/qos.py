from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from .pcap_cache import get_reader
from .utils import safe_float

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.layers.l2 import Dot1Q  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore
    Dot1Q = None  # type: ignore
    Raw = None  # type: ignore

try:
    from scapy.layers.dot11 import Dot11, Dot11QoS  # type: ignore
except Exception:  # pragma: no cover
    Dot11 = None  # type: ignore
    Dot11QoS = None  # type: ignore


SECRET_PATTERN = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization|bearer|private[_-]?key)\b"
)
SECRET_KV_PATTERN = re.compile(
    r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|bearer)\b\s*[:=]\s*([^\s&;\"']{2,220})"
)

DSCP_NAMES = {
    0: "CS0",
    8: "CS1",
    10: "AF11",
    12: "AF12",
    14: "AF13",
    16: "CS2",
    18: "AF21",
    20: "AF22",
    22: "AF23",
    24: "CS3",
    26: "AF31",
    28: "AF32",
    30: "AF33",
    32: "CS4",
    34: "AF41",
    36: "AF42",
    38: "AF43",
    40: "CS5",
    46: "EF",
    48: "CS6",
    56: "CS7",
}

ECN_NAMES = {
    0: "Not-ECT",
    1: "ECT(1)",
    2: "ECT(0)",
    3: "CE",
}

HIGH_PRIORITY_DSCP = {46, 48, 56}
NETWORK_CONTROL_PORTS = {22, 53, 67, 68, 123, 161, 162, 179, 500, 4500}


@dataclass(frozen=True)
class QosSummary:
    path: Path
    total_packets: int
    total_ip_packets: int
    qos_packets: int
    ip_qos_packets: int
    wireless_qos_packets: int
    wireless_qos_open_packets: int
    wireless_qos_protected_packets: int
    high_priority_packets: int
    dscp_counts: Counter[str]
    ecn_counts: Counter[str]
    vlan_pcp_counts: Counter[int]
    wmm_tid_counts: Counter[int]
    wlan_tid_direction_counts: Counter[str]
    src_counts: Counter[str]
    dst_counts: Counter[str]
    wlan_src_counts: Counter[str]
    wlan_dst_counts: Counter[str]
    service_counts: Counter[str]
    flow_rows: list[dict[str, object]]
    wlan_flow_rows: list[dict[str, object]]
    plaintext_hits: list[dict[str, object]]
    detections: list[dict[str, object]]
    deterministic_checks: dict[str, list[str]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


def _dscp_label(value: int) -> str:
    name = DSCP_NAMES.get(value, f"DSCP{value}")
    return f"{name}({value})"


def _parse_l3(pkt) -> tuple[Optional[str], Optional[str], Optional[int]]:
    if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
        ip = pkt[IP]  # type: ignore[index]
        tos = int(getattr(ip, "tos", 0) or 0)
        return str(ip.src), str(ip.dst), tos
    if IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
        ip6 = pkt[IPv6]  # type: ignore[index]
        tc = int(getattr(ip6, "tc", 0) or 0)
        return str(ip6.src), str(ip6.dst), tc
    return None, None, None


def _payload_text(pkt) -> str:
    payload = b""
    if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
        try:
            payload = bytes(pkt[Raw].load)  # type: ignore[index]
        except Exception:
            payload = b""
    if not payload:
        try:
            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                payload = bytes(getattr(pkt[TCP], "payload", b"") or b"")  # type: ignore[index]
            elif UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                payload = bytes(getattr(pkt[UDP], "payload", b"") or b"")  # type: ignore[index]
        except Exception:
            payload = b""
    if not payload:
        return ""
    return payload[:8192].decode("utf-8", errors="ignore")


def analyze_qos(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
    filter_ip: str | None = None,
) -> QosSummary:
    if IP is None and IPv6 is None:
        return QosSummary(
            path=path,
            total_packets=0,
            total_ip_packets=0,
            qos_packets=0,
            ip_qos_packets=0,
            wireless_qos_packets=0,
            wireless_qos_open_packets=0,
            wireless_qos_protected_packets=0,
            high_priority_packets=0,
            dscp_counts=Counter(),
            ecn_counts=Counter(),
            vlan_pcp_counts=Counter(),
            wmm_tid_counts=Counter(),
            wlan_tid_direction_counts=Counter(),
            src_counts=Counter(),
            dst_counts=Counter(),
            wlan_src_counts=Counter(),
            wlan_dst_counts=Counter(),
            service_counts=Counter(),
            flow_rows=[],
            wlan_flow_rows=[],
            plaintext_hits=[],
            detections=[],
            deterministic_checks={},
            errors=[
                "Scapy IP layers unavailable; QoS analysis requires IP/IPv6 decoding."
            ],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, packets=packets, meta=meta, show_status=show_status
    )

    total_packets = 0
    total_ip_packets = 0
    qos_packets = 0
    ip_qos_packets = 0
    wireless_qos_packets = 0
    wireless_qos_open_packets = 0
    wireless_qos_protected_packets = 0
    high_priority_packets = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    errors: list[str] = []

    dscp_counts: Counter[str] = Counter()
    ecn_counts: Counter[str] = Counter()
    vlan_pcp_counts: Counter[int] = Counter()
    wmm_tid_counts: Counter[int] = Counter()
    wlan_tid_direction_counts: Counter[str] = Counter()
    src_counts: Counter[str] = Counter()
    dst_counts: Counter[str] = Counter()
    wlan_src_counts: Counter[str] = Counter()
    wlan_dst_counts: Counter[str] = Counter()
    service_counts: Counter[str] = Counter()
    plaintext_hits: list[dict[str, object]] = []
    flow_state: dict[tuple[str, str, str, int, int], dict[str, object]] = defaultdict(
        lambda: {"packets": 0, "bytes": 0, "dscp": set(), "pcp": set(), "tid": set()}
    )
    wlan_flow_state: dict[tuple[str, str], dict[str, object]] = defaultdict(
        lambda: {"packets": 0, "open": 0, "protected": 0, "tid": Counter()}
    )
    src_dscp_sets: dict[str, set[int]] = defaultdict(set)
    detection_seen: set[tuple[object, ...]] = set()

    checks: dict[str, list[str]] = {
        "qos_marking_presence": [],
        "high_priority_usage": [],
        "flow_marking_inconsistency": [],
        "dscp_sprawl_or_tunneling": [],
        "ecn_congestion_signal": [],
        "plaintext_or_secret_exposure": [],
        "possible_misconfiguration": [],
        "wireless_qos_presence": [],
        "wireless_qos_encryption_posture": [],
    }
    detections: list[dict[str, object]] = []

    try:
        for pkt_num, pkt in enumerate(reader, start=1):
            total_packets += 1
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    status.update(int(min(100, (pos / size_bytes) * 100)))
                except Exception:
                    pass

            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            wmm_tid_from_wireless: Optional[int] = None
            if Dot11QoS is not None and pkt.haslayer(Dot11QoS):  # type: ignore[truthy-bool]
                wireless_qos_packets += 1
                qos_packets += 1
                tid = 0
                try:
                    tid = int(getattr(pkt[Dot11QoS], "TID", 0) or 0) & 0x0F  # type: ignore[index]
                except Exception:
                    tid = 0
                wmm_tid_from_wireless = tid
                wmm_tid_counts[tid] += 1

                src_mac = "-"
                dst_mac = "-"
                protected = False
                if Dot11 is not None and pkt.haslayer(Dot11):  # type: ignore[truthy-bool]
                    dot11 = pkt[Dot11]  # type: ignore[index]
                    src_mac = str(getattr(dot11, "addr2", "") or "-")
                    dst_mac = str(getattr(dot11, "addr1", "") or "-")
                    try:
                        fc = int(getattr(dot11, "FCfield", 0) or 0)
                        protected = bool(fc & 0x40)
                    except Exception:
                        protected = False
                wlan_src_counts[src_mac] += 1
                wlan_dst_counts[dst_mac] += 1
                if protected:
                    wireless_qos_protected_packets += 1
                else:
                    wireless_qos_open_packets += 1
                if tid >= 6:
                    high_priority_packets += 1
                    checks["high_priority_usage"].append(
                        f"packet={pkt_num} {src_mac}->{dst_mac} wireless TID={tid} ({'protected' if protected else 'open'})"
                    )
                wlan_tid_direction_counts[f"TID{tid} {src_mac}->{dst_mac}"] += 1
                wstate = wlan_flow_state[(src_mac, dst_mac)]
                wstate["packets"] = int(wstate.get("packets", 0) or 0) + 1
                if protected:
                    wstate["protected"] = int(wstate.get("protected", 0) or 0) + 1
                else:
                    wstate["open"] = int(wstate.get("open", 0) or 0) + 1
                tid_ctr = wstate.get("tid", Counter())
                if isinstance(tid_ctr, Counter):
                    tid_ctr[tid] += 1

            src_ip, dst_ip, tos_tc = _parse_l3(pkt)
            if src_ip is None or dst_ip is None or tos_tc is None:
                continue
            total_ip_packets += 1

            if filter_ip and filter_ip != src_ip and filter_ip != dst_ip:
                continue

            dscp = int((tos_tc >> 2) & 0x3F)
            ecn = int(tos_tc & 0x03)

            pcp = 0
            if Dot1Q is not None and pkt.haslayer(Dot1Q):  # type: ignore[truthy-bool]
                try:
                    pcp = int(getattr(pkt[Dot1Q], "prio", 0) or 0)  # type: ignore[index]
                except Exception:
                    pcp = 0

            wmm_tid: Optional[int] = wmm_tid_from_wireless

            qos_marked = dscp > 0 or pcp > 0 or wmm_tid is not None
            if not qos_marked:
                continue

            qos_packets += 1
            ip_qos_packets += 1
            dscp_counts[_dscp_label(dscp)] += 1
            ecn_counts[ECN_NAMES.get(ecn, f"ECN{ecn}")] += 1
            if pcp > 0:
                vlan_pcp_counts[pcp] += 1

            src_counts[src_ip] += 1
            dst_counts[dst_ip] += 1
            src_dscp_sets[src_ip].add(dscp)

            proto = "IP"
            sport = 0
            dport = 0
            payload_len = 0
            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp = pkt[TCP]  # type: ignore[index]
                proto = "TCP"
                sport = int(getattr(tcp, "sport", 0) or 0)
                dport = int(getattr(tcp, "dport", 0) or 0)
                try:
                    payload_len = len(bytes(getattr(tcp, "payload", b"") or b""))
                except Exception:
                    payload_len = 0
            elif UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp = pkt[UDP]  # type: ignore[index]
                proto = "UDP"
                sport = int(getattr(udp, "sport", 0) or 0)
                dport = int(getattr(udp, "dport", 0) or 0)
                try:
                    payload_len = len(bytes(getattr(udp, "payload", b"") or b""))
                except Exception:
                    payload_len = 0
            service_counts[f"{proto}/{dport}"] += 1

            if (
                dscp in HIGH_PRIORITY_DSCP
                or pcp >= 5
                or (wmm_tid is not None and wmm_tid >= 5)
            ):
                high_priority_packets += 1
                checks["high_priority_usage"].append(
                    f"packet={pkt_num} {src_ip}->{dst_ip} dscp={_dscp_label(dscp)} pcp={pcp} tid={wmm_tid if wmm_tid is not None else '-'}"
                )

            if ecn == 3:
                checks["ecn_congestion_signal"].append(
                    f"packet={pkt_num} {src_ip}->{dst_ip} CE-marked with dscp={_dscp_label(dscp)}"
                )

            flow_key = (src_ip, dst_ip, proto, sport, dport)
            state = flow_state[flow_key]
            state["packets"] = int(state.get("packets", 0) or 0) + 1
            state["bytes"] = int(state.get("bytes", 0) or 0) + int(max(0, payload_len))
            dscp_set = state.get("dscp", set())
            if isinstance(dscp_set, set):
                dscp_set.add(dscp)
            pcp_set = state.get("pcp", set())
            if isinstance(pcp_set, set):
                pcp_set.add(pcp)
            tid_set = state.get("tid", set())
            if isinstance(tid_set, set) and wmm_tid is not None:
                tid_set.add(wmm_tid)

            text = _payload_text(pkt)
            if text and SECRET_PATTERN.search(text):
                secret_value = "-"
                kv_match = SECRET_KV_PATTERN.search(text)
                if kv_match:
                    secret_value = str(kv_match.group(1) or "-")[:220]
                hit_key = (pkt_num, src_ip, dst_ip, secret_value)
                if hit_key not in detection_seen:
                    detection_seen.add(hit_key)
                    plaintext_hits.append(
                        {
                            "packet": pkt_num,
                            "src": src_ip,
                            "dst": dst_ip,
                            "protocol": proto,
                            "dscp": _dscp_label(dscp),
                            "indicator": "Credential/secret keyword",
                            "value": secret_value,
                        }
                    )
                    checks["plaintext_or_secret_exposure"].append(
                        f"packet={pkt_num} {src_ip}->{dst_ip} secret keyword in payload (dscp={_dscp_label(dscp)})"
                    )

    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        reader.close()

    if qos_packets > 0:
        checks["qos_marking_presence"].append(
            f"qos_packets_total={qos_packets} (ip={ip_qos_packets}, wireless={wireless_qos_packets})"
        )
    if ip_qos_packets == 0 and total_ip_packets > 0:
        checks["possible_misconfiguration"].append(
            "No DSCP/PCP/WMM QoS markings found on IP traffic."
        )
    if wireless_qos_packets > 0:
        checks["wireless_qos_presence"].append(
            f"802.11 QoS frames observed: {wireless_qos_packets} (open={wireless_qos_open_packets}, protected={wireless_qos_protected_packets})"
        )
        if wireless_qos_protected_packets > wireless_qos_open_packets:
            checks["wireless_qos_encryption_posture"].append(
                "Wireless QoS traffic is predominantly protected/encrypted (content visibility may be limited)."
            )
        elif wireless_qos_open_packets > 0:
            checks["wireless_qos_encryption_posture"].append(
                "Wireless QoS includes open/plaintext frames; inspect payload for sensitive data."
            )

    for src, dscps in src_dscp_sets.items():
        if len(dscps) >= 6:
            checks["dscp_sprawl_or_tunneling"].append(
                f"{src} used {len(dscps)} distinct DSCP values ({', '.join(sorted(_dscp_label(v) for v in dscps)[:8])})"
            )

    for (src, dst, proto, sport, dport), state in flow_state.items():
        dset = state.get("dscp", set())
        if (
            isinstance(dset, set)
            and len(dset) >= 2
            and int(state.get("packets", 0) or 0) >= 4
        ):
            checks["flow_marking_inconsistency"].append(
                f"{src}:{sport}->{dst}:{dport}/{proto} DSCP changed across flow ({', '.join(sorted(_dscp_label(v) for v in dset)[:6])})"
            )

    high_on_non_control = 0
    for (src, dst, proto, sport, dport), state in flow_state.items():
        dset = state.get("dscp", set())
        if not isinstance(dset, set):
            continue
        if (
            any(v in HIGH_PRIORITY_DSCP for v in dset)
            and dport not in NETWORK_CONTROL_PORTS
        ):
            high_on_non_control += int(state.get("packets", 0) or 0)
            checks["possible_misconfiguration"].append(
                f"{src}:{sport}->{dst}:{dport}/{proto} high-priority DSCP on non-control service"
            )
    if high_on_non_control and ip_qos_packets:
        checks["possible_misconfiguration"].append(
            f"high-priority packets on non-control services: {high_on_non_control}/{ip_qos_packets}"
        )

    flow_rows: list[dict[str, object]] = []
    for (src, dst, proto, sport, dport), state in flow_state.items():
        dset = state.get("dscp", set())
        pset = state.get("pcp", set())
        tset = state.get("tid", set())
        flow_rows.append(
            {
                "src": src,
                "dst": dst,
                "proto": proto,
                "sport": sport,
                "dport": dport,
                "packets": int(state.get("packets", 0) or 0),
                "bytes": int(state.get("bytes", 0) or 0),
                "dscp": ", ".join(sorted(_dscp_label(v) for v in dset))
                if isinstance(dset, set) and dset
                else "-",
                "pcp": ", ".join(str(v) for v in sorted(pset))
                if isinstance(pset, set) and pset
                else "-",
                "tid": ", ".join(str(v) for v in sorted(tset))
                if isinstance(tset, set) and tset
                else "-",
            }
        )
    flow_rows.sort(key=lambda item: int(item.get("packets", 0) or 0), reverse=True)

    wlan_flow_rows: list[dict[str, object]] = []
    for (src, dst), state in wlan_flow_state.items():
        tid_ctr = state.get("tid", Counter())
        tid_text = "-"
        if isinstance(tid_ctr, Counter) and tid_ctr:
            tid_text = ", ".join(
                f"{tid}({count})" for tid, count in tid_ctr.most_common(6)
            )
        wlan_flow_rows.append(
            {
                "src": src,
                "dst": dst,
                "packets": int(state.get("packets", 0) or 0),
                "open": int(state.get("open", 0) or 0),
                "protected": int(state.get("protected", 0) or 0),
                "tid": tid_text,
            }
        )
    wlan_flow_rows.sort(key=lambda item: int(item.get("packets", 0) or 0), reverse=True)

    for key, values in list(checks.items()):
        checks[key] = list(dict.fromkeys(values))

    if checks["dscp_sprawl_or_tunneling"]:
        detections.append(
            {
                "severity": "warning",
                "summary": "DSCP sprawl / potential QoS signaling abuse detected",
                "details": "; ".join(checks["dscp_sprawl_or_tunneling"][:6]),
            }
        )
    if checks["flow_marking_inconsistency"]:
        detections.append(
            {
                "severity": "warning",
                "summary": "QoS marking inconsistency across directional flows",
                "details": "; ".join(checks["flow_marking_inconsistency"][:6]),
            }
        )
    if checks["plaintext_or_secret_exposure"]:
        detections.append(
            {
                "severity": "high",
                "summary": "Plaintext secret exposure discovered in QoS-marked traffic",
                "details": "; ".join(checks["plaintext_or_secret_exposure"][:6]),
            }
        )
    if checks["possible_misconfiguration"]:
        detections.append(
            {
                "severity": "warning",
                "summary": "Potential QoS policy misconfiguration observed",
                "details": "; ".join(checks["possible_misconfiguration"][:6]),
            }
        )
    if checks["ecn_congestion_signal"]:
        detections.append(
            {
                "severity": "info",
                "summary": "ECN congestion-experienced packets observed",
                "details": "; ".join(checks["ecn_congestion_signal"][:6]),
            }
        )
    if checks["wireless_qos_presence"]:
        detections.append(
            {
                "severity": "info",
                "summary": "Wireless 802.11 QoS (WMM) traffic observed",
                "details": "; ".join(checks["wireless_qos_presence"][:6]),
            }
        )
    if checks["wireless_qos_encryption_posture"]:
        detections.append(
            {
                "severity": "info",
                "summary": "Wireless QoS encryption posture assessed",
                "details": "; ".join(checks["wireless_qos_encryption_posture"][:6]),
            }
        )

    duration = (
        (last_seen - first_seen)
        if first_seen is not None and last_seen is not None
        else None
    )
    return QosSummary(
        path=path,
        total_packets=total_packets,
        total_ip_packets=total_ip_packets,
        qos_packets=qos_packets,
        ip_qos_packets=ip_qos_packets,
        wireless_qos_packets=wireless_qos_packets,
        wireless_qos_open_packets=wireless_qos_open_packets,
        wireless_qos_protected_packets=wireless_qos_protected_packets,
        high_priority_packets=high_priority_packets,
        dscp_counts=dscp_counts,
        ecn_counts=ecn_counts,
        vlan_pcp_counts=vlan_pcp_counts,
        wmm_tid_counts=wmm_tid_counts,
        wlan_tid_direction_counts=wlan_tid_direction_counts,
        src_counts=src_counts,
        dst_counts=dst_counts,
        wlan_src_counts=wlan_src_counts,
        wlan_dst_counts=wlan_dst_counts,
        service_counts=service_counts,
        flow_rows=flow_rows,
        wlan_flow_rows=wlan_flow_rows,
        plaintext_hits=plaintext_hits,
        detections=detections,
        deterministic_checks=checks,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )


def merge_qos_summaries(summaries: Iterable[QosSummary]) -> QosSummary:
    items = list(summaries)
    if not items:
        return QosSummary(
            path=Path("ALL_PCAPS"),
            total_packets=0,
            total_ip_packets=0,
            qos_packets=0,
            ip_qos_packets=0,
            wireless_qos_packets=0,
            wireless_qos_open_packets=0,
            wireless_qos_protected_packets=0,
            high_priority_packets=0,
            dscp_counts=Counter(),
            ecn_counts=Counter(),
            vlan_pcp_counts=Counter(),
            wmm_tid_counts=Counter(),
            wlan_tid_direction_counts=Counter(),
            src_counts=Counter(),
            dst_counts=Counter(),
            wlan_src_counts=Counter(),
            wlan_dst_counts=Counter(),
            service_counts=Counter(),
            flow_rows=[],
            wlan_flow_rows=[],
            plaintext_hits=[],
            detections=[],
            deterministic_checks={},
            errors=[],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    dscp_counts: Counter[str] = Counter()
    ecn_counts: Counter[str] = Counter()
    vlan_pcp_counts: Counter[int] = Counter()
    wmm_tid_counts: Counter[int] = Counter()
    wlan_tid_direction_counts: Counter[str] = Counter()
    src_counts: Counter[str] = Counter()
    dst_counts: Counter[str] = Counter()
    wlan_src_counts: Counter[str] = Counter()
    wlan_dst_counts: Counter[str] = Counter()
    service_counts: Counter[str] = Counter()
    flow_rows: list[dict[str, object]] = []
    wlan_flow_rows: list[dict[str, object]] = []
    plaintext_hits: list[dict[str, object]] = []
    detections: list[dict[str, object]] = []
    checks: dict[str, list[str]] = defaultdict(list)
    errors: list[str] = []

    total_packets = 0
    total_ip_packets = 0
    qos_packets = 0
    ip_qos_packets = 0
    wireless_qos_packets = 0
    wireless_qos_open_packets = 0
    wireless_qos_protected_packets = 0
    high_priority_packets = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    for item in items:
        total_packets += int(item.total_packets)
        total_ip_packets += int(item.total_ip_packets)
        qos_packets += int(item.qos_packets)
        ip_qos_packets += int(getattr(item, "ip_qos_packets", 0) or 0)
        wireless_qos_packets += int(getattr(item, "wireless_qos_packets", 0) or 0)
        wireless_qos_open_packets += int(
            getattr(item, "wireless_qos_open_packets", 0) or 0
        )
        wireless_qos_protected_packets += int(
            getattr(item, "wireless_qos_protected_packets", 0) or 0
        )
        high_priority_packets += int(item.high_priority_packets)
        dscp_counts.update(item.dscp_counts)
        ecn_counts.update(item.ecn_counts)
        vlan_pcp_counts.update(item.vlan_pcp_counts)
        wmm_tid_counts.update(item.wmm_tid_counts)
        wlan_tid_direction_counts.update(
            getattr(item, "wlan_tid_direction_counts", Counter())
        )
        src_counts.update(item.src_counts)
        dst_counts.update(item.dst_counts)
        wlan_src_counts.update(getattr(item, "wlan_src_counts", Counter()))
        wlan_dst_counts.update(getattr(item, "wlan_dst_counts", Counter()))
        service_counts.update(item.service_counts)
        flow_rows.extend(item.flow_rows)
        wlan_flow_rows.extend(getattr(item, "wlan_flow_rows", []))
        plaintext_hits.extend(item.plaintext_hits)
        detections.extend(item.detections)
        errors.extend(item.errors)
        for key, values in (item.deterministic_checks or {}).items():
            for value in values or []:
                checks[str(key)].append(str(value))
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

    duration = (
        (last_seen - first_seen)
        if first_seen is not None and last_seen is not None
        else None
    )
    return QosSummary(
        path=Path("ALL_PCAPS"),
        total_packets=total_packets,
        total_ip_packets=total_ip_packets,
        qos_packets=qos_packets,
        ip_qos_packets=ip_qos_packets,
        wireless_qos_packets=wireless_qos_packets,
        wireless_qos_open_packets=wireless_qos_open_packets,
        wireless_qos_protected_packets=wireless_qos_protected_packets,
        high_priority_packets=high_priority_packets,
        dscp_counts=dscp_counts,
        ecn_counts=ecn_counts,
        vlan_pcp_counts=vlan_pcp_counts,
        wmm_tid_counts=wmm_tid_counts,
        wlan_tid_direction_counts=wlan_tid_direction_counts,
        src_counts=src_counts,
        dst_counts=dst_counts,
        wlan_src_counts=wlan_src_counts,
        wlan_dst_counts=wlan_dst_counts,
        service_counts=service_counts,
        flow_rows=flow_rows,
        wlan_flow_rows=wlan_flow_rows,
        plaintext_hits=plaintext_hits,
        detections=detections,
        deterministic_checks={k: list(dict.fromkeys(v)) for k, v in checks.items()},
        errors=sorted(set(errors)),
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
