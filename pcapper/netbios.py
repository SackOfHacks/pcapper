from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import re

try:
    from scapy.layers.inet import TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw, Packet
    from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse, NBNSNodeStatusResponse
except ImportError:
    # Use raw parsing if imports fail or layers missing
    TCP = UDP = Raw = None
    NBNSQueryRequest = NBNSQueryResponse = NBNSNodeStatusResponse = None

from .pcap_cache import get_reader
from .utils import safe_float

# NetBIOS Suffix Types commonly seen
SUFFIX_MAP = {
    0x00: "Workstation/Service",
    0x03: "Messenger Service",
    0x06: "RAS Server Service",
    0x1B: "Domain Master Browser",
    0x1C: "Domain Controllers",
    0x1D: "Master Browser",
    0x1E: "Browser Service Elections",
    0x1F: "NetDDE Service",
    0x20: "File Server Service",
    0x21: "RAS Client Service",
    0xDC: "Domain Controller",
    0xE0: "Master Browser",
}

NBNS_RCODE_MAP = {
    0: "NoError",
    1: "FormErr",
    2: "ServFail",
    3: "NXDomain",
    4: "NotImp",
    5: "Refused",
}

SMB2_CMD_MAP = {
    0x00: "Negotiate", 0x01: "Session Setup", 0x02: "Logoff",
    0x03: "Tree Connect", 0x04: "Tree Disconnect", 0x05: "Create",
    0x06: "Close", 0x07: "Flush", 0x08: "Read", 0x09: "Write",
    0x0A: "Lock", 0x0B: "Ioctl", 0x0C: "Cancel", 0x0D: "Echo",
    0x0E: "Query Dir", 0x0F: "Change Notify", 0x10: "Query Info",
    0x11: "Set Info", 0x12: "Oplock Break",
}

SMB1_CMD_MAP = {
    0x72: "Negotiate",
    0x73: "Session Setup",
    0x75: "Tree Connect",
    0xA2: "NT Create",
    0x2D: "Open",
    0x2E: "Read",
    0x2F: "Write",
}

SUSPICIOUS_SMB_TOKENS = {
    "Write",
    "Set Info",
    "Ioctl",
    "Create",
    "Tree Connect",
    "Session Setup",
}

HIGH_RISK_NBNS_CODES = {"Refused", "ServFail", "FormErr"}


def _parse_ntlm_type3(payload: bytes) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    signature = b"NTLMSSP\x00"
    idx = payload.find(signature)
    if idx == -1 or len(payload) < idx + 64:
        return None, None, None
    try:
        msg_type = int.from_bytes(payload[idx + 8:idx + 12], "little")
        if msg_type != 3:
            return None, None, None
        def _read_field(offset: int) -> Tuple[int, int]:
            length = int.from_bytes(payload[offset:offset + 2], "little")
            field_offset = int.from_bytes(payload[offset + 4:offset + 8], "little")
            return length, field_offset
        domain_len, domain_off = _read_field(idx + 28)
        user_len, user_off = _read_field(idx + 36)
        workstation_len, workstation_off = _read_field(idx + 44)
        domain = payload[idx + domain_off:idx + domain_off + domain_len].decode("utf-16le", errors="ignore") if domain_len else None
        user = payload[idx + user_off:idx + user_off + user_len].decode("utf-16le", errors="ignore") if user_len else None
        workstation = payload[idx + workstation_off:idx + workstation_off + workstation_len].decode("utf-16le", errors="ignore") if workstation_len else None
        return user or None, domain or None, workstation or None
    except Exception:
        return None, None, None


def _parse_smb_command(payload: bytes) -> Optional[str]:
    if payload.startswith(b"\xfeSMB") and len(payload) >= 16:
        cmd = int.from_bytes(payload[12:14], "little")
        return f"SMB2:{SMB2_CMD_MAP.get(cmd, f'0x{cmd:02X}') }"
    if payload.startswith(b"\xffSMB") and len(payload) >= 5:
        cmd = payload[4]
        return f"SMB1:{SMB1_CMD_MAP.get(cmd, f'0x{cmd:02X}') }"
    return None

@dataclass
class NetbiosName:
    name: str
    suffix: int
    type_str: str

@dataclass
class NetbiosHost:
    ip: str
    names: List[NetbiosName] = field(default_factory=list)
    mac: Optional[str] = None
    is_master_browser: bool = False
    is_domain_controller: bool = False
    group_name: Optional[str] = None

@dataclass
class NetbiosAnomaly:
    timestamp: float
    src_ip: str
    dst_ip: str
    type: str # Conflict, Spoof, Malformed, BroadcastStorm
    details: str
    severity: str = "LOW"


@dataclass
class NetbiosConversation:
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int
    dst_port: int
    packets: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    requests: int = 0
    responses: int = 0
    response_codes: Counter[str] = field(default_factory=Counter)


@dataclass
class NetbiosSession:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    packets: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

@dataclass
class NetbiosAnalysis:
    path: Path
    duration: float = 0.0
    total_bytes: int = 0
    total_packets: int = 0
    hosts: Dict[str, NetbiosHost] = field(default_factory=dict) # Keyed by IP
    conversations: List[NetbiosConversation] = field(default_factory=list)
    sessions: List[NetbiosSession] = field(default_factory=list)
    endpoint_bytes_sent: Counter[str] = field(default_factory=Counter)
    endpoint_bytes_recv: Counter[str] = field(default_factory=Counter)
    protocol_packets: Counter[str] = field(default_factory=Counter)
    src_counts: Counter[str] = field(default_factory=Counter)
    dst_counts: Counter[str] = field(default_factory=Counter)
    request_counts: Counter[str] = field(default_factory=Counter)
    response_counts: Counter[str] = field(default_factory=Counter)
    response_codes: Counter[str] = field(default_factory=Counter)
    service_counts: Counter[str] = field(default_factory=Counter)
    service_endpoints: Dict[str, Counter[str]] = field(default_factory=dict)
    nbss_message_types: Counter[str] = field(default_factory=Counter)
    smb_versions: Counter[str] = field(default_factory=Counter)
    smb_commands: Counter[str] = field(default_factory=Counter)
    suspicious_smb_commands: Counter[str] = field(default_factory=Counter)
    smb_users: Counter[str] = field(default_factory=Counter)
    smb_domains: Counter[str] = field(default_factory=Counter)
    smb_sources: Counter[str] = field(default_factory=Counter)
    smb_destinations: Counter[str] = field(default_factory=Counter)
    smb_clients: Counter[str] = field(default_factory=Counter)
    smb_servers: Counter[str] = field(default_factory=Counter)
    exfil_candidates: Counter[str] = field(default_factory=Counter)
    beacon_candidates: Counter[str] = field(default_factory=Counter)
    scanning_sources: Counter[str] = field(default_factory=Counter)
    brute_force_sources: Counter[str] = field(default_factory=Counter)
    probe_sources: Counter[str] = field(default_factory=Counter)
    threat_summary: Counter[str] = field(default_factory=Counter)
    plaintext_observed: Counter[str] = field(default_factory=Counter)
    artifacts: List[str] = field(default_factory=list)
    files_discovered: List[str] = field(default_factory=list)
    observed_users: Counter[str] = field(default_factory=Counter)
    anomalies: List[NetbiosAnomaly] = field(default_factory=list)
    name_conflicts: int = 0
    browser_elections: int = 0
    unique_names: Set[str] = field(default_factory=set)
    errors: List[str] = field(default_factory=list)

def decode_netbios_name(encoded_name: bytes) -> str:
    """
    Decodes a standard 32-byte Level 1 encoded NetBIOS name.
    """
    if len(encoded_name) < 32:
        return "<BAD_ENCODING>"
    
    try:
        # NetBIOS Name Encoding: 2 characters for each byte
        # Simplistic decoding for now or use scapy's if available.
        # usually stored as 16 chars (padded spaces)
        # Actually scapy usually handles this, so we might extract from layer
        pass
    except Exception:
        pass
    return encoded_name.decode('utf-8', errors='replace').strip()

def get_netbios_suffix_desc(suffix: int) -> str:
    return SUFFIX_MAP.get(suffix, f"Unknown (0x{suffix:02X})")


def _scan_filenames(data: bytes) -> List[str]:
    found = set()
    pattern = r"[\w\-.()\[\] ]+\.(?:exe|dll|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|txt|bat|ps1|mkv|mp4|avi|mov|wmv|flv|webm|jpg|jpeg|png|gif|bmp|tiff|iso|img|tar|gz|7z|rar)"
    try:
        text = data.decode("utf-16-le", errors="ignore")
        found.update(re.findall(pattern, text, re.IGNORECASE))
    except Exception:
        pass
    try:
        text = data.decode("latin-1", errors="ignore")
        found.update(re.findall(pattern, text, re.IGNORECASE))
    except Exception:
        pass
    return list(found)


def _extract_plaintext(data: bytes, max_items: int = 8) -> List[str]:
    if not data:
        return []
    tokens = []
    for match in re.findall(r"[ -~]{8,}", data.decode("latin-1", errors="ignore")):
        cleaned = " ".join(match.split())
        if cleaned:
            tokens.append(cleaned[:96])
        if len(tokens) >= max_items:
            break
    return tokens

def analyze_netbios(pcap_path: Path, show_status: bool = True) -> NetbiosAnalysis:
    analysis = NetbiosAnalysis(path=pcap_path)

    if not pcap_path.exists():
        return analysis

    start_time: Optional[float] = None
    last_time: Optional[float] = None

    conversations: Dict[Tuple[str, str, str, int, int], NetbiosConversation] = {}
    sessions: Dict[Tuple[str, str, int, int], NetbiosSession] = {}
    service_endpoints: Dict[str, Counter[str]] = defaultdict(Counter)
    artifacts: Set[str] = set()
    file_set: Set[str] = set()

    packet_rate_tracker: Dict[int, Counter[str]] = defaultdict(Counter)
    storm_flagged: Set[str] = set()

    name_registry: Dict[str, Set[str]] = defaultdict(set)
    response_name_registry: Dict[str, Set[str]] = defaultdict(set)
    src_nbns_names: Dict[str, Set[str]] = defaultdict(set)
    src_nbns_targets: Dict[str, Set[str]] = defaultdict(set)

    smb_write_bytes: Counter[str] = Counter()
    smb_write_commands: Counter[str] = Counter()
    smb_session_setup_attempts: Counter[str] = Counter()
    smb_negative_sessions: Counter[str] = Counter()
    src_distinct_destinations: Dict[str, Set[str]] = defaultdict(set)

    keepalive_last_ts: Dict[str, float] = {}
    keepalive_intervals: Dict[str, List[float]] = defaultdict(list)

    max_anomalies = 250

    def _update_time(obj, ts_val: float) -> None:
        if obj.first_seen is None or ts_val < obj.first_seen:
            obj.first_seen = ts_val
        if obj.last_seen is None or ts_val > obj.last_seen:
            obj.last_seen = ts_val

    def _append_anomaly(severity: str, kind: str, details: str, src: str, dst: str, ts: float) -> None:
        if len(analysis.anomalies) >= max_anomalies:
            return
        analysis.anomalies.append(
            NetbiosAnomaly(
                timestamp=ts,
                src_ip=src,
                dst_ip=dst,
                type=kind,
                details=details,
                severity=severity,
            )
        )

    try:
        reader, status_bar, stream, size_bytes, _file_type = get_reader(
            pcap_path, show_status=show_status
        )
    except Exception as exc:
        analysis.errors.append(f"Error opening pcap: {exc}")
        return analysis

    try:
        with status_bar as pbar:
            for pkt in reader:
                if not pkt:
                    continue

                if stream is not None and size_bytes:
                    try:
                        pos = stream.tell()
                        pbar.update(int(min(100, (pos / size_bytes) * 100)))
                    except Exception:
                        pass

                ts = safe_float(getattr(pkt, "time", None))
                if ts is None:
                    ts = 0.0
                if start_time is None or ts < start_time:
                    start_time = ts
                if last_time is None or ts > last_time:
                    last_time = ts

                pkt_len = int(len(pkt)) if hasattr(pkt, "__len__") else 0

                src_ip = "0.0.0.0"
                dst_ip = "0.0.0.0"
                if pkt.haslayer("IP"):
                    src_ip = str(pkt["IP"].src)
                    dst_ip = str(pkt["IP"].dst)
                elif IPv6 is not None and pkt.haslayer(IPv6):
                    src_ip = str(pkt[IPv6].src)
                    dst_ip = str(pkt[IPv6].dst)

                sport = 0
                dport = 0
                proto_label = "OTHER"
                is_nb = False
                if UDP is not None and pkt.haslayer(UDP):
                    sport = int(pkt[UDP].sport)
                    dport = int(pkt[UDP].dport)
                    proto_label = "UDP"
                    if sport in (137, 138) or dport in (137, 138):
                        is_nb = True
                elif TCP is not None and pkt.haslayer(TCP):
                    sport = int(pkt[TCP].sport)
                    dport = int(pkt[TCP].dport)
                    proto_label = "TCP"
                    if sport == 139 or dport == 139:
                        is_nb = True

                if not is_nb:
                    continue

                analysis.total_packets += 1
                analysis.total_bytes += pkt_len
                analysis.protocol_packets[proto_label] += 1
                analysis.src_counts[src_ip] += 1
                analysis.dst_counts[dst_ip] += 1
                analysis.endpoint_bytes_sent[src_ip] += pkt_len
                analysis.endpoint_bytes_recv[dst_ip] += pkt_len
                src_distinct_destinations[src_ip].add(dst_ip)

                if src_ip not in analysis.hosts:
                    analysis.hosts[src_ip] = NetbiosHost(ip=src_ip)
                if Ether is not None and pkt.haslayer(Ether) and analysis.hosts[src_ip].mac is None:
                    try:
                        analysis.hosts[src_ip].mac = str(pkt[Ether].src)
                    except Exception:
                        pass

                convo_key = (src_ip, dst_ip, proto_label, sport, dport)
                convo = conversations.get(convo_key)
                if convo is None:
                    convo = NetbiosConversation(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol=proto_label,
                        src_port=sport,
                        dst_port=dport,
                    )
                    conversations[convo_key] = convo
                convo.packets += 1
                _update_time(convo, ts)

                if sport == 137 or dport == 137:
                    analysis.service_counts["NBNS (Name Service)"] += 1
                    service_endpoints["NBNS (Name Service)"][f"{src_ip}->{dst_ip}"] += 1
                if sport == 138 or dport == 138:
                    analysis.service_counts["Datagram Service"] += 1
                    service_endpoints["Datagram Service"][f"{src_ip}->{dst_ip}"] += 1
                if proto_label == "TCP" and (sport == 139 or dport == 139):
                    analysis.service_counts["Session Service"] += 1
                    service_endpoints["Session Service"][f"{src_ip}->{dst_ip}"] += 1

                payload = b""
                if Raw is not None and pkt.haslayer(Raw):
                    try:
                        payload = bytes(pkt[Raw].load)
                    except Exception:
                        payload = b""

                if payload:
                    for token in _extract_plaintext(payload):
                        analysis.plaintext_observed[token] += 1
                        artifacts.add(token)
                    for name in _scan_filenames(payload):
                        file_set.add(name)

                # NBNS: request handling
                if pkt.haslayer("NBNSQueryRequest"):
                    analysis.request_counts["NBNS Query"] += 1
                    convo.requests += 1
                    try:
                        qlayer = pkt["NBNSQueryRequest"]
                        qname = getattr(qlayer, "QUESTION_NAME", None)
                        if qname is None:
                            qname = getattr(qlayer, "qname", None)
                        if isinstance(qname, bytes):
                            qname_str = qname.decode("latin-1", errors="ignore").strip()
                        else:
                            qname_str = str(qname).strip() if qname is not None else ""
                        if qname_str:
                            src_nbns_names[src_ip].add(qname_str)
                            src_nbns_targets[src_ip].add(dst_ip)
                            analysis.observed_users[qname_str] += 1
                            analysis.unique_names.add(qname_str)
                            artifacts.add(qname_str)
                            name_registry[qname_str].add(src_ip)
                            if len(name_registry[qname_str]) > 1:
                                analysis.name_conflicts += 1
                                _append_anomaly(
                                    "HIGH",
                                    "NameConflict",
                                    f"Multiple hosts claimed query name {qname_str}: {', '.join(sorted(name_registry[qname_str]))}",
                                    src_ip,
                                    dst_ip,
                                    ts,
                                )
                    except Exception as exc:
                        analysis.errors.append(f"NBNS query parse: {exc}")

                # NBNS: response handling
                if pkt.haslayer("NBNSQueryResponse"):
                    analysis.response_counts["NBNS Response"] += 1
                    convo.responses += 1
                    try:
                        nbns = pkt["NBNSQueryResponse"]
                        rcode = getattr(nbns, "RCODE", None)
                        if rcode is None:
                            rcode = getattr(nbns, "rcode", None)
                        if rcode is None and hasattr(nbns, "FLAGS"):
                            try:
                                rcode = int(nbns.FLAGS) & 0x000F
                            except Exception:
                                rcode = None
                        if rcode is not None:
                            code_name = NBNS_RCODE_MAP.get(int(rcode), f"RCODE_{rcode}")
                            analysis.response_codes[code_name] += 1
                            convo.response_codes[code_name] += 1
                            if code_name in HIGH_RISK_NBNS_CODES:
                                _append_anomaly(
                                    "MEDIUM",
                                    "NBNS Failure",
                                    f"NBNS response code {code_name} observed.",
                                    src_ip,
                                    dst_ip,
                                    ts,
                                )

                        rr_name = getattr(nbns, "RR_NAME", None)
                        if isinstance(rr_name, bytes):
                            rr_name = rr_name.decode("latin-1", errors="ignore").strip()
                        rr_name = str(rr_name).strip() if rr_name else ""
                        if rr_name:
                            response_name_registry[rr_name].add(src_ip)
                            if len(response_name_registry[rr_name]) > 1:
                                analysis.threat_summary["NBNS Response Spoofing"] += 1
                                _append_anomaly(
                                    "HIGH",
                                    "NBNS Spoofing",
                                    f"Name {rr_name} resolved by multiple IPs: {', '.join(sorted(response_name_registry[rr_name]))}",
                                    src_ip,
                                    dst_ip,
                                    ts,
                                )
                    except Exception as exc:
                        analysis.errors.append(f"NBNS response parse: {exc}")

                # Browser datagram heuristics (UDP/138)
                if proto_label == "UDP" and (sport == 138 or dport == 138) and payload:
                    if b"__MSBROWSE__" in payload or b"BROWSE" in payload.upper():
                        analysis.browser_elections += 1
                        analysis.request_counts["Browser Election"] += 1
                    if payload[:1] in {b"\x08", b"\x0c"}:
                        analysis.browser_elections += 1

                # Session/SMB tracking (TCP/139)
                if proto_label == "TCP" and (sport == 139 or dport == 139):
                    sess_key = (src_ip, dst_ip, sport, dport)
                    sess = sessions.get(sess_key)
                    if sess is None:
                        sess = NetbiosSession(src_ip=src_ip, dst_ip=dst_ip, src_port=sport, dst_port=dport)
                        sessions[sess_key] = sess
                    sess.packets += 1
                    _update_time(sess, ts)

                    is_client_to_server = dport == 139
                    if is_client_to_server:
                        analysis.smb_clients[src_ip] += 1
                        analysis.smb_servers[dst_ip] += 1

                    if payload and len(payload) >= 4:
                        msg_type = payload[0]
                        nbss_type_map = {
                            0x00: "Session Message",
                            0x81: "Session Request",
                            0x82: "Positive Session Response",
                            0x83: "Negative Session Response",
                            0x84: "Retarget Session Response",
                            0x85: "Session Keepalive",
                        }
                        msg_name = nbss_type_map.get(msg_type, f"Type 0x{msg_type:02X}")
                        analysis.nbss_message_types[msg_name] += 1

                        flow_key = f"{src_ip}:{sport}->{dst_ip}:{dport}"
                        if msg_type == 0x85:
                            previous = keepalive_last_ts.get(flow_key)
                            if previous is not None and ts > previous:
                                keepalive_intervals[flow_key].append(ts - previous)
                            keepalive_last_ts[flow_key] = ts

                        if msg_type == 0x83:
                            smb_negative_sessions[src_ip] += 1

                        if msg_type == 0x00 and len(payload) > 4:
                            nbss_payload = payload[4:]
                            if nbss_payload.startswith(b"\xffSMB"):
                                analysis.smb_versions["SMB1"] += 1
                            if nbss_payload.startswith(b"\xfeSMB"):
                                analysis.smb_versions["SMB2/3"] += 1

                            cmd_name = _parse_smb_command(nbss_payload)
                            if cmd_name:
                                analysis.smb_commands[cmd_name] += 1
                                if any(token in cmd_name for token in SUSPICIOUS_SMB_TOKENS):
                                    analysis.suspicious_smb_commands[cmd_name] += 1
                                if "Session Setup" in cmd_name and is_client_to_server:
                                    smb_session_setup_attempts[src_ip] += 1
                                if "Write" in cmd_name and is_client_to_server:
                                    smb_write_commands[src_ip] += 1
                                    smb_write_bytes[src_ip] += len(nbss_payload)

                            user, domain, workstation = _parse_ntlm_type3(nbss_payload)
                            if user:
                                analysis.smb_users[user] += 1
                                analysis.smb_sources[src_ip] += 1
                                analysis.smb_destinations[dst_ip] += 1
                            if domain:
                                analysis.smb_domains[domain] += 1
                            if workstation:
                                analysis.observed_users[workstation] += 1

                            for name in _scan_filenames(nbss_payload):
                                file_set.add(name)

                # Broadcast storm heuristic
                ts_sec = int(ts)
                packet_rate_tracker[ts_sec][src_ip] += 1
                if packet_rate_tracker[ts_sec][src_ip] > 200 and src_ip not in storm_flagged:
                    storm_flagged.add(src_ip)
                    analysis.threat_summary["Broadcast/Name Storm"] += 1
                    _append_anomaly(
                        "MEDIUM",
                        "BroadcastStorm",
                        f"High NetBIOS packet rate from {src_ip} in one second.",
                        src_ip,
                        dst_ip,
                        ts,
                    )

    except Exception as exc:
        analysis.errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        try:
            reader.close()
        except Exception:
            pass

    if start_time is not None and last_time is not None:
        analysis.duration = max(0.0, last_time - start_time)

    # Post detections
    for src_ip, names in src_nbns_names.items():
        if len(names) >= 30:
            analysis.scanning_sources[src_ip] += len(names)
            analysis.threat_summary["NBNS Name Scanning"] += 1
            _append_anomaly(
                "MEDIUM",
                "NBNS Scan",
                f"{src_ip} queried {len(names)} unique NetBIOS names.",
                src_ip,
                "-",
                0.0,
            )

    for src_ip, targets in src_distinct_destinations.items():
        if len(targets) >= 25:
            analysis.probe_sources[src_ip] += len(targets)
            analysis.threat_summary["Host Probing"] += 1
            _append_anomaly(
                "MEDIUM",
                "NetBIOS Probe Sweep",
                f"{src_ip} contacted {len(targets)} distinct NetBIOS peers.",
                src_ip,
                "-",
                0.0,
            )

    for src_ip, attempts in smb_session_setup_attempts.items():
        negatives = smb_negative_sessions.get(src_ip, 0)
        if attempts >= 20 and negatives >= 5:
            analysis.brute_force_sources[src_ip] += attempts
            analysis.threat_summary["SMB Brute-Force Indicators"] += 1
            _append_anomaly(
                "HIGH",
                "SMB Brute Force",
                f"{src_ip} had {attempts} Session Setup attempts and {negatives} negative responses.",
                src_ip,
                "-",
                0.0,
            )

    for src_ip, total_bytes in smb_write_bytes.items():
        if total_bytes >= 5_000_000 or smb_write_commands.get(src_ip, 0) >= 150:
            analysis.exfil_candidates[src_ip] += total_bytes
            analysis.threat_summary["Potential Exfiltration"] += 1
            _append_anomaly(
                "HIGH",
                "SMB Write Burst",
                f"{src_ip} transmitted {total_bytes / (1024 * 1024):.2f} MB via SMB write-like commands.",
                src_ip,
                "-",
                0.0,
            )

    for flow_key, intervals in keepalive_intervals.items():
        if len(intervals) < 8:
            continue
        avg = sum(intervals) / len(intervals)
        if avg <= 0:
            continue
        variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
        cv = (variance ** 0.5) / avg
        if cv <= 0.20 and 1.0 <= avg <= 120.0:
            analysis.beacon_candidates[flow_key] += len(intervals)
            analysis.threat_summary["Beaconing Pattern"] += 1
            _append_anomaly(
                "MEDIUM",
                "Session Keepalive Beacon",
                f"Regular keepalive cadence on {flow_key} (avg {avg:.2f}s, cv {cv:.2f}).",
                flow_key,
                "-",
                0.0,
            )

    analysis.conversations = sorted(conversations.values(), key=lambda item: item.packets, reverse=True)
    analysis.sessions = sorted(sessions.values(), key=lambda item: item.packets, reverse=True)
    analysis.service_endpoints = dict(service_endpoints)
    analysis.files_discovered = sorted(file_set)[:200]
    analysis.artifacts = sorted(artifacts)[:300]

    return analysis
