from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    from scapy.layers.inet import TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether
    from scapy.layers.netbios import (
        NBNSNodeStatusResponse,
        NBNSQueryRequest,
        NBNSQueryResponse,
    )
    from scapy.packet import Raw
except ImportError:
    # Use raw parsing if imports fail or layers missing
    TCP = UDP = Raw = None
    NBNSQueryRequest = NBNSQueryResponse = NBNSNodeStatusResponse = None

from .pcap_cache import get_reader
from .utils import extract_packet_endpoints, safe_float

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
    0x00: "Negotiate",
    0x01: "Session Setup",
    0x02: "Logoff",
    0x03: "Tree Connect",
    0x04: "Tree Disconnect",
    0x05: "Create",
    0x06: "Close",
    0x07: "Flush",
    0x08: "Read",
    0x09: "Write",
    0x0A: "Lock",
    0x0B: "Ioctl",
    0x0C: "Cancel",
    0x0D: "Echo",
    0x0E: "Query Dir",
    0x0F: "Change Notify",
    0x10: "Query Info",
    0x11: "Set Info",
    0x12: "Oplock Break",
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


def _parse_ntlm_type3(
    payload: bytes,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    signature = b"NTLMSSP\x00"
    idx = payload.find(signature)
    if idx == -1 or len(payload) < idx + 64:
        return None, None, None
    try:
        msg_type = int.from_bytes(payload[idx + 8 : idx + 12], "little")
        if msg_type != 3:
            return None, None, None

        def _read_field(offset: int) -> Tuple[int, int]:
            length = int.from_bytes(payload[offset : offset + 2], "little")
            field_offset = int.from_bytes(payload[offset + 4 : offset + 8], "little")
            return length, field_offset

        domain_len, domain_off = _read_field(idx + 28)
        user_len, user_off = _read_field(idx + 36)
        workstation_len, workstation_off = _read_field(idx + 44)
        domain = (
            payload[idx + domain_off : idx + domain_off + domain_len].decode(
                "utf-16le", errors="ignore"
            )
            if domain_len
            else None
        )
        user = (
            payload[idx + user_off : idx + user_off + user_len].decode(
                "utf-16le", errors="ignore"
            )
            if user_len
            else None
        )
        workstation = (
            payload[
                idx + workstation_off : idx + workstation_off + workstation_len
            ].decode("utf-16le", errors="ignore")
            if workstation_len
            else None
        )
        return user or None, domain or None, workstation or None
    except Exception:
        return None, None, None


def _parse_smb_command(payload: bytes) -> Optional[str]:
    if payload.startswith(b"\xfeSMB") and len(payload) >= 16:
        cmd = int.from_bytes(payload[12:14], "little")
        return f"SMB2:{SMB2_CMD_MAP.get(cmd, f'0x{cmd:02X}')}"
    if payload.startswith(b"\xffSMB") and len(payload) >= 5:
        cmd = payload[4]
        return f"SMB1:{SMB1_CMD_MAP.get(cmd, f'0x{cmd:02X}')}"
    return None


@dataclass
class NetbiosName:
    name: str
    suffix: int
    type_str: str
    scope: str = "UNKNOWN"  # UNIQUE/GROUP/UNKNOWN
    status: str = "Registered"
    source: str = "NBNS"


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
    type: str  # Conflict, Spoof, Malformed, BroadcastStorm
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
    hosts: Dict[str, NetbiosHost] = field(default_factory=dict)  # Keyed by IP
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
    user_evidence: List[Dict[str, object]] = field(default_factory=list)
    anomalies: List[NetbiosAnomaly] = field(default_factory=list)
    name_conflicts: int = 0
    browser_elections: int = 0
    unique_names: Set[str] = field(default_factory=set)
    deterministic_checks: Dict[str, List[str]] = field(default_factory=dict)
    threat_hypotheses: List[Dict[str, object]] = field(default_factory=list)
    benign_context: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def decode_netbios_name(encoded_name: bytes) -> str:
    """
    Decodes a standard 32-byte Level 1 encoded NetBIOS name.
    """
    if len(encoded_name) < 32:
        return "<BAD_ENCODING>"

    try:
        raw = encoded_name[:32]
        out = bytearray()
        for idx in range(0, 32, 2):
            c1 = raw[idx]
            c2 = raw[idx + 1]
            if not (65 <= c1 <= 80 and 65 <= c2 <= 80):  # "A".."P"
                return encoded_name.decode("utf-8", errors="replace").strip()
            high = c1 - 65
            low = c2 - 65
            out.append((high << 4) | low)
        return out.decode("latin-1", errors="ignore").strip()
    except Exception:
        return encoded_name.decode("utf-8", errors="replace").strip()


def get_netbios_suffix_desc(suffix: int) -> str:
    return SUFFIX_MAP.get(suffix, f"Unknown (0x{suffix:02X})")


def _scope_from_suffix(suffix: int) -> str:
    if suffix in {0x1C, 0x1D, 0x1E}:
        return "GROUP"
    return "UNIQUE"


def _parse_name_text(raw_name: object) -> Tuple[str, Optional[int]]:
    if raw_name is None:
        return "", None
    if isinstance(raw_name, bytes):
        text = raw_name.decode("latin-1", errors="ignore").strip()
    else:
        text = str(raw_name).strip()
    if not text:
        return "", None

    candidate = "".join(
        ch for ch in text.rstrip(".") if ch.isprintable() or ch in {"\x01", "\x02"}
    )
    if "__MSBROWSE__" in candidate.upper():
        return "__MSBROWSE__", 0x01
    match = re.match(r"^(.*)<([0-9A-Fa-f]{2})>$", candidate)
    if match:
        name = match.group(1).strip()
        suffix = int(match.group(2), 16)
        return name[:15], suffix

    if len(candidate) >= 32 and all(("A" <= ch <= "P") for ch in candidate[:32]):
        decoded = decode_netbios_name(candidate[:32].encode("latin-1", errors="ignore"))
        if decoded and decoded != "<BAD_ENCODING>":
            if len(decoded) >= 16:
                return decoded[:15].strip(), ord(decoded[15])
            return decoded[:15].strip(), None

    return candidate[:15].strip(), None


def _infer_suffix_from_name(name: str) -> Optional[int]:
    upper = str(name or "").upper().strip()
    if not upper:
        return None
    if upper == "__MSBROWSE__":
        return 0x01
    if upper in {"WORKGROUP", "MSHOME", "DOMAIN"}:
        return 0x00
    return None


def _nb_name_status(flags: int) -> str:
    if flags & 0x2000:
        return "Conflict"
    if flags & 0x4000:
        return "Deregistered"
    if flags & 0x1000:
        return "Registered"
    if flags & 0x0800:
        return "Permanent"
    return "Registered"


def _extract_node_status_entries(layer_obj: object) -> List[Tuple[str, int, str, str]]:
    entries: List[Tuple[str, int, str, str]] = []
    blob = getattr(layer_obj, "NODE_NAME", b"")
    if not isinstance(blob, (bytes, bytearray)):
        return entries
    data = bytes(blob)
    for idx in range(0, len(data), 18):
        chunk = data[idx : idx + 18]
        if len(chunk) < 18:
            break
        name = chunk[:15].decode("latin-1", errors="ignore").strip()
        suffix = int(chunk[15])
        flags = int.from_bytes(chunk[16:18], "big")
        scope = "GROUP" if (flags & 0x8000) else "UNIQUE"
        status = _nb_name_status(flags)
        if name:
            entries.append((name[:15], suffix, scope, status))
    return entries


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
    user_evidence_seen: Set[Tuple[str, str, str, str, int, int]] = set()

    keepalive_last_ts: Dict[str, float] = {}
    keepalive_intervals: Dict[str, List[float]] = defaultdict(list)
    host_name_seen: Dict[str, Set[Tuple[str, int, str, str]]] = defaultdict(set)

    max_anomalies = 250

    def _update_time(obj, ts_val: float) -> None:
        if obj.first_seen is None or ts_val < obj.first_seen:
            obj.first_seen = ts_val
        if obj.last_seen is None or ts_val > obj.last_seen:
            obj.last_seen = ts_val

    def _append_anomaly(
        severity: str, kind: str, details: str, src: str, dst: str, ts: float
    ) -> None:
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

    def _add_host_name(
        host_ip: str, name: str, suffix: int, scope: str, status: str, source: str
    ) -> None:
        if not name:
            return
        if host_ip not in analysis.hosts:
            analysis.hosts[host_ip] = NetbiosHost(ip=host_ip)
        norm_name = name[:15].strip()
        norm_scope = scope.upper() if scope else _scope_from_suffix(suffix)
        norm_status = status or "Registered"
        key = (norm_name.lower(), int(suffix), norm_scope, norm_status)
        if key in host_name_seen[host_ip]:
            return
        host_name_seen[host_ip].add(key)
        analysis.hosts[host_ip].names.append(
            NetbiosName(
                name=norm_name,
                suffix=int(suffix),
                type_str=get_netbios_suffix_desc(int(suffix)),
                scope=norm_scope,
                status=norm_status,
                source=source,
            )
        )
        if int(suffix) in {0x1B, 0x1C, 0xDC}:
            analysis.hosts[host_ip].is_domain_controller = True
        if int(suffix) in {0x1D, 0x1E, 0xE0}:
            analysis.hosts[host_ip].is_master_browser = True
        if norm_scope == "GROUP" and analysis.hosts[host_ip].group_name is None:
            analysis.hosts[host_ip].group_name = norm_name

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

                src_ip, dst_ip = extract_packet_endpoints(pkt)
                if not src_ip or not dst_ip:
                    src_ip = "0.0.0.0"
                    dst_ip = "0.0.0.0"

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
                if (
                    Ether is not None
                    and pkt.haslayer(Ether)
                    and analysis.hosts[src_ip].mac is None
                ):
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
                            parsed_name, parsed_suffix = _parse_name_text(qname_str)
                            display_name = qname_str
                            if parsed_name:
                                display_name = (
                                    f"{parsed_name}<{parsed_suffix:02X}>"
                                    if parsed_suffix is not None
                                    else parsed_name
                                )
                            src_nbns_names[src_ip].add(display_name)
                            src_nbns_targets[src_ip].add(dst_ip)
                            analysis.observed_users[display_name] += 1
                            analysis.unique_names.add(display_name)
                            artifacts.add(display_name)
                            name_registry[display_name].add(src_ip)
                            if len(name_registry[display_name]) > 1:
                                analysis.name_conflicts += 1
                                _append_anomaly(
                                    "HIGH",
                                    "NameConflict",
                                    f"Multiple hosts claimed query name {display_name}: {', '.join(sorted(name_registry[display_name]))}",
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
                        parsed_name, parsed_suffix = _parse_name_text(rr_name)
                        if parsed_name and parsed_suffix is None:
                            parsed_suffix = _infer_suffix_from_name(parsed_name)
                        rr_name_text = (
                            f"{parsed_name}<{parsed_suffix:02X}>"
                            if (parsed_name and parsed_suffix is not None)
                            else parsed_name
                        )
                        if rr_name_text:
                            response_name_registry[rr_name_text].add(src_ip)
                            if len(response_name_registry[rr_name_text]) > 1:
                                analysis.threat_summary["NBNS Response Spoofing"] += 1
                                _append_anomaly(
                                    "HIGH",
                                    "NBNS Spoofing",
                                    f"Name {rr_name_text} resolved by multiple IPs: {', '.join(sorted(response_name_registry[rr_name_text]))}",
                                    src_ip,
                                    dst_ip,
                                    ts,
                                )
                        if parsed_name:
                            addr_entries = getattr(nbns, "ADDR_ENTRY", []) or []
                            entry_scope = _scope_from_suffix(
                                parsed_suffix if parsed_suffix is not None else 0x00
                            )
                            if isinstance(addr_entries, list) and addr_entries:
                                try:
                                    g_raw = getattr(addr_entries[0], "G", None)
                                    if isinstance(g_raw, int):
                                        if int(g_raw) == 1:
                                            entry_scope = "GROUP"
                                        elif int(g_raw) == 0:
                                            entry_scope = "UNIQUE"
                                    else:
                                        g_value = str(g_raw or "").lower()
                                        if "group" in g_value:
                                            entry_scope = "GROUP"
                                        elif "unique" in g_value:
                                            entry_scope = "UNIQUE"
                                except Exception:
                                    pass
                            if parsed_name.upper() == "__MSBROWSE__":
                                entry_scope = "GROUP"
                            _add_host_name(
                                src_ip,
                                parsed_name,
                                int(
                                    parsed_suffix if parsed_suffix is not None else 0x00
                                ),
                                entry_scope,
                                "Registered",
                                "NBNS Response",
                            )
                    except Exception as exc:
                        analysis.errors.append(f"NBNS response parse: {exc}")

                if NBNSNodeStatusResponse is not None and pkt.haslayer(
                    NBNSNodeStatusResponse
                ):
                    try:
                        node_status = pkt[NBNSNodeStatusResponse]
                        entries = _extract_node_status_entries(node_status)
                        for name, suffix, scope, status in entries:
                            _add_host_name(
                                src_ip, name, suffix, scope, status, "NBSTAT"
                            )
                            analysis.unique_names.add(f"{name}<{suffix:02X}>")
                    except Exception as exc:
                        analysis.errors.append(f"NBNS node status parse: {exc}")

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
                        sess = NetbiosSession(
                            src_ip=src_ip, dst_ip=dst_ip, src_port=sport, dst_port=dport
                        )
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
                                if any(
                                    token in cmd_name for token in SUSPICIOUS_SMB_TOKENS
                                ):
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
                                key = (src_ip, dst_ip, user, domain or "", sport, dport)
                                if key not in user_evidence_seen:
                                    user_evidence_seen.add(key)
                                    analysis.user_evidence.append(
                                        {
                                            "src_ip": src_ip,
                                            "dst_ip": dst_ip,
                                            "src_port": sport,
                                            "dst_port": dport,
                                            "username": user,
                                            "domain": domain,
                                            "workstation": workstation,
                                            "method": "NetBIOS SMB Session Setup",
                                            "details": cmd_name or "SMB over NetBIOS",
                                        }
                                    )
                            if domain:
                                analysis.smb_domains[domain] += 1
                            if workstation:
                                analysis.observed_users[workstation] += 1

                            for name in _scan_filenames(nbss_payload):
                                file_set.add(name)

                # Broadcast storm heuristic
                ts_sec = int(ts)
                packet_rate_tracker[ts_sec][src_ip] += 1
                if (
                    packet_rate_tracker[ts_sec][src_ip] > 200
                    and src_ip not in storm_flagged
                ):
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
        cv = (variance**0.5) / avg
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

    analysis.conversations = sorted(
        conversations.values(), key=lambda item: item.packets, reverse=True
    )
    analysis.sessions = sorted(
        sessions.values(), key=lambda item: item.packets, reverse=True
    )
    analysis.service_endpoints = dict(service_endpoints)
    analysis.files_discovered = sorted(file_set)[:200]
    analysis.artifacts = sorted(artifacts)[:300]

    def _is_public_ip(value: str) -> bool:
        try:
            return ipaddress.ip_address(str(value)).is_global
        except Exception:
            return False

    deterministic_checks: Dict[str, List[str]] = {
        "nbns_spoofing_or_conflict": [],
        "nbns_scan_or_probe_fanout": [],
        "nbns_broadcast_storm": [],
        "smb_auth_abuse_over_netbios": [],
        "smb_write_exfil_over_netbios": [],
        "netbios_beaconing_pattern": [],
        "role_claim_anomaly": [],
        "public_netbios_exposure": [],
    }
    threat_hypotheses: List[Dict[str, object]] = []
    benign_context: List[str] = []

    spoof_hits = int(analysis.threat_summary.get("NBNS Response Spoofing", 0) or 0)
    if spoof_hits > 0:
        deterministic_checks["nbns_spoofing_or_conflict"].append(
            f"NBNS response spoofing indicators count={spoof_hits}"
        )
    if int(analysis.name_conflicts or 0) > 0:
        deterministic_checks["nbns_spoofing_or_conflict"].append(
            f"NetBIOS name conflicts observed count={int(analysis.name_conflicts or 0)}"
        )

    for src_ip, count in analysis.scanning_sources.most_common(15):
        deterministic_checks["nbns_scan_or_probe_fanout"].append(
            f"NBNS scan-like source {src_ip} queried names={int(count)}"
        )
    for src_ip, count in analysis.probe_sources.most_common(15):
        deterministic_checks["nbns_scan_or_probe_fanout"].append(
            f"NetBIOS probe sweep source {src_ip} target_count={int(count)}"
        )

    storm_hits = int(analysis.threat_summary.get("Broadcast/Name Storm", 0) or 0)
    if storm_hits > 0:
        deterministic_checks["nbns_broadcast_storm"].append(
            f"Broadcast/name storm indicators count={storm_hits}"
        )

    for src_ip, count in analysis.brute_force_sources.most_common(15):
        deterministic_checks["smb_auth_abuse_over_netbios"].append(
            f"SMB SessionSetup brute-force indicator source {src_ip} attempts={int(count)}"
        )

    for src_ip, total_bytes in analysis.exfil_candidates.most_common(15):
        deterministic_checks["smb_write_exfil_over_netbios"].append(
            f"SMB write-heavy flow source {src_ip} bytes={int(total_bytes)}"
        )

    for flow_key, count in analysis.beacon_candidates.most_common(15):
        deterministic_checks["netbios_beaconing_pattern"].append(
            f"Periodic keepalive cadence flow={flow_key} intervals={int(count)}"
        )

    dc_hosts = [
        ip
        for ip, host in analysis.hosts.items()
        if getattr(host, "is_domain_controller", False)
    ]
    browser_hosts = [
        ip
        for ip, host in analysis.hosts.items()
        if getattr(host, "is_master_browser", False)
    ]
    if dc_hosts:
        deterministic_checks["role_claim_anomaly"].append(
            f"Domain-controller role suffixes observed on hosts={', '.join(sorted(dc_hosts)[:8])}"
        )
    if browser_hosts:
        deterministic_checks["role_claim_anomaly"].append(
            f"Master-browser role suffixes observed on hosts={', '.join(sorted(browser_hosts)[:8])}"
        )

    for ip_value, count in analysis.src_counts.items():
        if _is_public_ip(ip_value):
            deterministic_checks["public_netbios_exposure"].append(
                f"NetBIOS source on public IP {ip_value} packets={int(count)}"
            )
    for ip_value, count in analysis.dst_counts.items():
        if _is_public_ip(ip_value):
            deterministic_checks["public_netbios_exposure"].append(
                f"NetBIOS destination on public IP {ip_value} packets={int(count)}"
            )

    if (
        deterministic_checks["nbns_spoofing_or_conflict"]
        and deterministic_checks["nbns_scan_or_probe_fanout"]
    ):
        threat_hypotheses.append(
            {
                "hypothesis": "Possible NBNS poisoning campaign coupled with active name reconnaissance",
                "confidence": "high",
                "evidence": len(deterministic_checks["nbns_spoofing_or_conflict"])
                + len(deterministic_checks["nbns_scan_or_probe_fanout"]),
            }
        )
    if (
        deterministic_checks["smb_auth_abuse_over_netbios"]
        and deterministic_checks["smb_write_exfil_over_netbios"]
    ):
        threat_hypotheses.append(
            {
                "hypothesis": "Credential abuse followed by SMB write-heavy activity over NetBIOS",
                "confidence": "high",
                "evidence": len(deterministic_checks["smb_auth_abuse_over_netbios"])
                + len(deterministic_checks["smb_write_exfil_over_netbios"]),
            }
        )
    if deterministic_checks["public_netbios_exposure"]:
        threat_hypotheses.append(
            {
                "hypothesis": "Legacy NetBIOS service surface exposed on public network path",
                "confidence": "high",
                "evidence": len(deterministic_checks["public_netbios_exposure"]),
            }
        )

    if not deterministic_checks["nbns_spoofing_or_conflict"]:
        benign_context.append("No strong NBNS spoofing/name-conflict cluster observed")
    if not deterministic_checks["smb_auth_abuse_over_netbios"]:
        benign_context.append("No substantial SMB auth abuse over NetBIOS observed")
    if not deterministic_checks["public_netbios_exposure"]:
        benign_context.append("No public Internet NetBIOS endpoint exposure observed")

    analysis.deterministic_checks = {k: v[:80] for k, v in deterministic_checks.items()}
    analysis.threat_hypotheses = threat_hypotheses[:24]
    analysis.benign_context = benign_context[:24]

    return analysis
