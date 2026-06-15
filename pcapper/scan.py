from __future__ import annotations


import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .pcap_cache import PcapMeta, get_reader
from .services import COMMON_PORTS, _OT_SERVICE_PORTS
from .utils import (
    extract_packet_endpoints,
    is_private_ip,
    is_public_ip,
    memoize_analysis,
    safe_float,
    tcp_flags_int as _tcp_flags_int,
)

try:
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, Ether
    from scapy.packet import Raw
except Exception:  # pragma: no cover
    ICMP = IP = TCP = UDP = IPv6 = ARP = Ether = Raw = None


AUTH_PORTS = {21, 22, 23, 25, 110, 143, 389, 445, 587, 993, 995, 3389}
_SCANNER_MARKERS = {
    "nmap": "Nmap",
    "masscan": "Masscan",
    "zmap": "ZMap",
    "rustscan": "RustScan",
    "nikto": "Nikto",
    "sqlmap": "SQLMap",
    "nessus": "Nessus",
    "openvas": "OpenVAS/Greenbone",
    "acunetix": "Acunetix",
    "hydra": "Hydra",
    "medusa": "Medusa",
}


@dataclass
class ScanTargetResult:
    target_ip: str
    open_ports: list[int] = field(default_factory=list)
    banner_samples: list[str] = field(default_factory=list)
    brute_force_attempts: int = 0
    brute_force_failures: int = 0
    brute_force_success_hints: int = 0
    credential_samples: list[str] = field(default_factory=list)


@dataclass
class ScanSourceResult:
    scanner_ip: str
    scan_type: str
    unique_targets: int
    unique_ports: int
    syn_packets: int
    first_seen: Optional[float]
    last_seen: Optional[float]
    mac_addresses: list[str] = field(default_factory=list)
    possible_os: str = "-"
    hostname_hints: list[str] = field(default_factory=list)
    scanner_software_guess: str = "-"
    top_ports: list[int] = field(default_factory=list)
    targets: list[ScanTargetResult] = field(default_factory=list)
    # Threat-hunt / IR context.
    techniques: list[str] = field(default_factory=list)
    probe_packets: int = 0
    scanner_scope: str = "-"  # internal / external
    target_scope: str = "-"  # internal / external / mixed
    duration_seconds: float = 0.0
    packets_per_second: float = 0.0
    open_responses: int = 0  # SYN/ACK received -> open service
    closed_responses: int = 0  # RST received -> port closed
    filtered_responses: int = 0  # ICMP unreachable -> filtered
    responsive_targets: int = 0  # targets that answered at all
    ot_ports: list[int] = field(default_factory=list)
    ot_targets: list[str] = field(default_factory=list)


@dataclass
class ScanSummary:
    path: Path
    total_packets: int = 0
    relevant_packets: int = 0
    scan_sources: list[ScanSourceResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def scanner_count(self) -> int:
        return len(self.scan_sources)


def _extract_ip_pair(pkt) -> tuple[str, str]:
    src_ip, dst_ip = extract_packet_endpoints(pkt)
    return src_ip or "0.0.0.0", dst_ip or "0.0.0.0"


def _extract_ports(pkt) -> tuple[Optional[int], Optional[int]]:
    if TCP is not None and pkt.haslayer(TCP):
        try:
            return int(pkt[TCP].sport), int(pkt[TCP].dport)
        except Exception:
            return None, None
    if UDP is not None and pkt.haslayer(UDP):
        try:
            return int(pkt[UDP].sport), int(pkt[UDP].dport)
        except Exception:
            return None, None
    return None, None


def _extract_payload(pkt) -> bytes:
    if TCP is not None and pkt.haslayer(TCP):
        try:
            tcp_layer = pkt[TCP]
            ip_layer = (
                pkt[IP]
                if (IP is not None and pkt.haslayer(IP))
                else (pkt[IPv6] if (IPv6 is not None and pkt.haslayer(IPv6)) else None)
            )
            if ip_layer is not None:
                tcp_hlen = int(getattr(tcp_layer, "dataofs", 0) or 0) * 4
                if tcp_hlen <= 0:
                    tcp_hlen = 20
                payload_len = 0
                if hasattr(ip_layer, "ihl") and hasattr(ip_layer, "len"):
                    ip_hlen = int(getattr(ip_layer, "ihl", 0) or 0) * 4
                    total = int(getattr(ip_layer, "len", 0) or 0)
                    if ip_hlen > 0 and total > 0:
                        payload_len = max(0, total - ip_hlen - tcp_hlen)
                elif hasattr(ip_layer, "plen"):
                    plen = int(getattr(ip_layer, "plen", 0) or 0)
                    if plen > 0:
                        payload_len = max(0, plen - tcp_hlen)
                if payload_len <= 0:
                    return b""
                payload = bytes(getattr(tcp_layer, "payload", b"") or b"")
                return payload[:payload_len]
        except Exception:
            return b""
    if Raw is not None and pkt.haslayer(Raw):
        try:
            return bytes(pkt[Raw].load)
        except Exception:
            return b""
    return b""


def _tcp_is_syn(flags: object) -> bool:
    try:
        if isinstance(flags, str):
            return "S" in flags and "A" not in flags
        return (int(flags) & 0x02) and not (int(flags) & 0x10)
    except Exception:
        return False


def _tcp_is_synack(flags: object) -> bool:
    try:
        if isinstance(flags, str):
            return "S" in flags and "A" in flags
        return (int(flags) & 0x12) == 0x12
    except Exception:
        return False


def _tcp_is_rst(flags: object) -> bool:
    value = _tcp_flags_int(flags)
    return bool(value & 0x04)


# Map a client-side TCP packet's flag combination to the nmap scan technique it
# implements. RST is a response (not a probe); SYN/ACK is a response. The
# stealth flavors (fin/null/xmas/maimon/ack) are flag combinations a normal
# client never sends to *open* a connection — but FIN+ACK is also a normal
# teardown and a bare ACK is normal mid-stream traffic, so the caller must gate
# those on "no SYN was seen for this flow and the probe carries no payload".
def _tcp_scan_flavor(flags: object) -> Optional[str]:
    v = _tcp_flags_int(flags)
    syn = bool(v & 0x02)
    ack = bool(v & 0x10)
    fin = bool(v & 0x01)
    rst = bool(v & 0x04)
    psh = bool(v & 0x08)
    urg = bool(v & 0x20)
    if rst:
        return None
    if syn and not ack:
        return "syn"
    if syn and ack:
        return None  # SYN/ACK is a response
    if fin and psh and urg and not (syn or ack):
        return "xmas"
    if fin and ack and not (syn or psh or urg):
        return "maimon"
    if fin and not (syn or ack or psh or urg):
        return "fin"
    if not (syn or ack or fin or psh or urg):
        return "null"
    if ack and not (syn or fin):
        return "ack"  # ACK / Window scan (firewall-state mapping)
    return None


# Stealth flavors that require gating (could be normal teardown / mid-stream).
_GATED_FLAVORS = {"fin", "null", "xmas", "maimon", "ack"}

_TECHNIQUE_LABELS = {
    "syn": "TCP SYN half-open (-sS)",
    "connect": "TCP connect (-sT)",
    "fin": "TCP FIN stealth (-sF)",
    "null": "TCP NULL stealth (-sN)",
    "xmas": "TCP XMAS stealth (-sX)",
    "maimon": "TCP Maimon (-sM)",
    "ack": "TCP ACK/Window firewall-mapping (-sA/-sW)",
    "udp": "UDP (-sU)",
    "arp": "ARP host sweep (-PR)",
    "icmp": "ICMP echo ping sweep (-sn/-PE)",
}


def _tcp_is_final_handshake_ack(flags: object) -> bool:
    value = _tcp_flags_int(flags)
    # Final handshake ACK must include ACK and exclude SYN/RST/FIN.
    return (
        bool(value & 0x10)
        and not bool(value & 0x02)
        and not bool(value & 0x04)
        and not bool(value & 0x01)
    )


def _canonical_tcp_pair(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
) -> tuple[tuple[str, int, str, int], bool]:
    left = (src_ip, src_port)
    right = (dst_ip, dst_port)
    if left <= right:
        return (src_ip, src_port, dst_ip, dst_port), True
    return (dst_ip, dst_port, src_ip, src_port), False


def _infer_server_from_seen_traffic(
    a_ip: str,
    a_port: int,
    b_ip: str,
    b_port: int,
    syn_ab: int,
    syn_ba: int,
) -> Optional[tuple[str, int, str]]:
    if syn_ab > 0 and syn_ba == 0:
        return b_ip, b_port, a_ip
    if syn_ba > 0 and syn_ab == 0:
        return a_ip, a_port, b_ip

    a_known = a_port in COMMON_PORTS
    b_known = b_port in COMMON_PORTS
    if a_known and not b_known:
        return a_ip, a_port, b_ip
    if b_known and not a_known:
        return b_ip, b_port, a_ip

    if a_port <= 1024 and b_port >= 49152:
        return a_ip, a_port, b_ip
    if b_port <= 1024 and a_port >= 49152:
        return b_ip, b_port, a_ip

    return None


def _seen_traffic_supports_service_presence(
    flow_stats: dict[str, int],
    server_is_left: bool,
) -> bool:
    packets_server = int(
        flow_stats.get("packets_ab" if server_is_left else "packets_ba", 0) or 0
    )
    packets_client = int(
        flow_stats.get("packets_ba" if server_is_left else "packets_ab", 0) or 0
    )
    payload_server = int(
        flow_stats.get("payload_bytes_ab" if server_is_left else "payload_bytes_ba", 0)
        or 0
    )

    if packets_server <= 0 or packets_client <= 0:
        return False
    # For scan/open-port inference, require explicit responder payload evidence.
    if payload_server > 0:
        return True
    return False


def _extract_banner(payload: bytes, port: int | None) -> Optional[str]:
    if not payload:
        return None
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return None
    if not text.strip():
        return None

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return None
    first = lines[0]
    first_l = first.lower()

    if first.startswith("SSH-"):
        return first[:120]
    if first_l.startswith("http/"):
        for line in lines[1:12]:
            if line.lower().startswith("server:"):
                return f"{first[:60]} | {line[:60]}"
        return first[:120]
    if first_l.startswith(("220 ", "220-", "* ok", "+ok", "ftp", "smtp")):
        return first[:120]
    if port in {21, 22, 23, 25, 80, 110, 143, 443, 445, 587, 993, 995, 3389}:
        printable = re.sub(r"\s+", " ", first)
        if printable:
            return printable[:120]
    return None


def _has_auth_attempt(payload: bytes) -> bool:
    if not payload:
        return False
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return False
    return bool(
        re.search(
            r"(?i)\b(?:user|username|login|pass|password|auth|binddn|ntlm)\b", text
        )
    )


def _auth_result(payload: bytes) -> tuple[int, int]:
    if not payload:
        return 0, 0
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return 0, 0
    fail = (
        1
        if re.search(
            r"(?i)\b(?:fail|failed|invalid|denied|incorrect|unauthorized|535|530)\b",
            text,
        )
        else 0
    )
    success = (
        1
        if re.search(r"(?i)\b(?:ok|success|authenticated|logged in|230 )\b", text)
        else 0
    )
    return fail, success


def _extract_creds(payload: bytes) -> list[str]:
    if not payload:
        return []
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return []
    samples: list[str] = []
    for m in re.findall(
        r"(?i)\b(?:user(?:name)?|login|account)\s*[=:]\s*([^\s,;]+)", text
    ):
        samples.append(f"user={m}")
    for m in re.findall(
        r"(?i)\b(?:pass(?:word)?|pwd|secret|token)\s*[=:]\s*([^\s,;]+)", text
    ):
        samples.append(f"secret={m}")
    deduped: list[str] = []
    seen: set[str] = set()
    for item in samples:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item[:80])
    return deduped[:6]


def _extract_hostname_hints(payload: bytes) -> list[str]:
    if not payload:
        return []
    try:
        text = payload.decode("latin-1", errors="ignore")
    except Exception:
        return []
    if not text.strip():
        return []

    hints: list[str] = []
    for match in re.findall(
        r"(?im)^\s*(?:EHLO|HELO)\s+([A-Za-z0-9._-]{1,255})\s*$", text
    ):
        hints.append(str(match).strip().rstrip("."))
    for match in re.findall(r"(?im)^\s*Host:\s*([A-Za-z0-9._-]{1,255})\s*$", text):
        hints.append(str(match).strip().rstrip("."))
    for match in re.findall(
        r"(?i)\b([a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9][a-z0-9-]{0,62}){1,6})\b", text
    ):
        token = str(match).strip().rstrip(".").lower()
        if token.endswith((".arpa", ".invalid")):
            continue
        if "." not in token:
            continue
        if not any(ch.isalpha() for ch in token):
            continue
        parts = [p for p in token.split(".") if p]
        if not parts or any(part.isdigit() for part in parts):
            continue
        if token.startswith("lm") and "x0" in token:
            continue
        if token.startswith("lanman"):
            continue
        hints.append(token)

    out: list[str] = []
    seen: set[str] = set()
    for hint in hints:
        if len(hint) < 3:
            continue
        if hint in seen:
            continue
        seen.add(hint)
        out.append(hint[:96])
    return out[:10]


def _extract_scanner_markers(payload: bytes) -> list[str]:
    if not payload:
        return []
    try:
        text = payload.decode("latin-1", errors="ignore").lower()
    except Exception:
        return []
    hits: list[str] = []
    for marker, label in _SCANNER_MARKERS.items():
        if marker in text:
            hits.append(label)
    return hits


def _guess_os_from_ttl(ttl_counts: Counter[int]) -> str:
    if not ttl_counts:
        return "-"
    ttl, _count = ttl_counts.most_common(1)[0]
    if ttl <= 0:
        return "-"
    if ttl <= 64:
        return f"Linux/Unix-like (TTL~{ttl})"
    if ttl <= 128:
        return f"Windows-like (TTL~{ttl})"
    return f"Network/embedded device (TTL~{ttl})"


def _guess_scanner_tool(
    scan_type: str,
    unique_targets: int,
    unique_ports: int,
    syn_packets: int,
    probe_packets: int,
    top_ports: list[int],
    markers: Counter[str],
) -> str:
    if markers:
        labels = [name for name, _count in markers.most_common(3)]
        return ", ".join(labels)

    low_common = {
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        111,
        135,
        139,
        143,
        443,
        445,
        993,
        995,
        3389,
        5900,
    }
    top = set(top_ports[:10])
    if scan_type == "vertical" and syn_packets > 300 and unique_ports >= 500:
        return "Heuristic: high-speed scanner (Masscan/ZMap-like)"
    if scan_type == "horizontal" and probe_packets >= 50 and unique_targets >= 32:
        return "Nmap (heuristic: -sn host discovery sweep)"
    if (
        scan_type == "mixed"
        and probe_packets >= 50
        and unique_targets >= 32
        and unique_ports >= 20
    ):
        return "Nmap (heuristic: -sn sweep + port scan)"
    if scan_type == "horizontal" and unique_targets >= 30 and (top & low_common):
        return "Heuristic: Nmap-style service discovery sweep"
    if unique_targets >= 20 and unique_ports >= 100:
        return "Heuristic: automated recon scanner"
    return "Heuristic: custom/manual scanning activity"


def _is_scanner_source(
    unique_targets: int,
    unique_ports: int,
    syn_packets: int,
    probe_packets: int,
    max_ports_single_target: int,
) -> bool:
    if max_ports_single_target >= 20:
        return True
    if unique_targets >= 10:
        return True
    if probe_packets >= 25 and unique_targets >= 8:
        return True
    if unique_ports >= 30:
        return True
    if syn_packets >= 150 and unique_ports >= 10:
        return True
    return False


def _record_probe(
    src_ip: str,
    dst_ip: str,
    dport: int,
    ts: Optional[float],
    src_targets: dict[str, set[str]],
    src_ports: dict[str, set[int]],
    src_dst_ports: dict[tuple[str, str], set[int]],
    src_dst_packets: Counter[tuple[str, str]],
    src_first_seen: dict[str, float],
    src_last_seen: dict[str, float],
    src_ot_ports: dict[str, set[int]],
    src_ot_targets: dict[str, set[str]],
) -> None:
    """Accumulate one scan probe (any technique) into the shared per-source
    target/port spread used for scanner detection and reporting."""
    src_targets[src_ip].add(dst_ip)
    src_ports[src_ip].add(dport)
    src_dst_ports[(src_ip, dst_ip)].add(dport)
    src_dst_packets[(src_ip, dst_ip)] += 1
    if dport in _OT_SERVICE_PORTS:
        src_ot_ports[src_ip].add(dport)
        src_ot_targets[src_ip].add(dst_ip)
    if ts is not None:
        src_first_seen[src_ip] = min(ts, src_first_seen.get(src_ip, ts))
        src_last_seen[src_ip] = max(ts, src_last_seen.get(src_ip, ts))


@memoize_analysis
def analyze_scan(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> ScanSummary:
    summary = ScanSummary(path=path)

    src_targets: dict[str, set[str]] = defaultdict(set)
    src_ports: dict[str, set[int]] = defaultdict(set)
    src_syn: Counter[str] = Counter()
    src_mac_counts: dict[str, Counter[str]] = defaultdict(Counter)
    src_ttl_counts: dict[str, Counter[int]] = defaultdict(Counter)
    src_hostname_hints: dict[str, Counter[str]] = defaultdict(Counter)
    src_tool_markers: dict[str, Counter[str]] = defaultdict(Counter)
    src_first_seen: dict[str, float] = {}
    src_last_seen: dict[str, float] = {}
    src_dst_ports: dict[tuple[str, str], set[int]] = defaultdict(set)
    src_dst_packets: Counter[tuple[str, str]] = Counter()
    src_probe_targets: dict[str, set[str]] = defaultdict(set)
    src_probe_packets: Counter[str] = Counter()
    # Per-source scan-technique spread: flavor -> distinct (target, port) probed.
    src_flavor_probes: dict[tuple[str, str], set[tuple[str, int]]] = defaultdict(set)
    src_flavor_packets: Counter[tuple[str, str]] = Counter()
    # Responses received BY a host (it is the scanner being answered).
    recv_synack: Counter[str] = Counter()
    recv_rst: Counter[str] = Counter()
    recv_icmp_unreach: Counter[str] = Counter()
    responsive_pairs: set[tuple[str, str]] = set()  # (scanner, target) answered
    # OT/ICS service ports probed.
    src_ot_ports: dict[str, set[int]] = defaultdict(set)
    src_ot_targets: dict[str, set[str]] = defaultdict(set)
    syn_seen: set[tuple[str, str, int, int]] = set()
    syn_ack_seen: set[tuple[str, str, int, int]] = set()
    handshake_complete: set[tuple[str, str, int, int]] = set()
    seen_tcp_flows: dict[tuple[str, int, str, int], dict[str, int]] = {}

    open_ports_by_pair: dict[tuple[str, str], set[int]] = defaultdict(
        set
    )  # (scanner, target) -> open ports
    banner_by_pair: dict[tuple[str, str], list[str]] = defaultdict(
        list
    )  # (scanner, target)
    brute_attempts: Counter[tuple[str, str]] = Counter()  # (scanner, target)
    brute_fails: Counter[tuple[str, str]] = Counter()
    brute_success: Counter[tuple[str, str]] = Counter()
    creds_by_pair: dict[tuple[str, str], list[str]] = defaultdict(list)

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path, packets=packets, meta=meta, show_status=show_status
        )
    except Exception as exc:
        summary.errors.append(f"Error opening pcap: {exc}")
        return summary

    try:
        for pkt in reader:
            summary.total_packets += 1
            if stream is not None and size_bytes:
                try:
                    status.update(int(min(100, (stream.tell() / size_bytes) * 100)))
                except Exception:
                    pass

            src_ip, dst_ip = _extract_ip_pair(pkt)
            if src_ip == "-" or dst_ip == "-":
                continue
            if Ether is not None and pkt.haslayer(Ether):
                try:
                    src_mac = str(getattr(pkt[Ether], "src", "") or "").lower()
                    if src_mac:
                        src_mac_counts[src_ip][src_mac] += 1
                except Exception:
                    pass
            if IP is not None and pkt.haslayer(IP):
                try:
                    ttl = int(getattr(pkt[IP], "ttl", 0) or 0)
                    if ttl > 0:
                        src_ttl_counts[src_ip][ttl] += 1
                except Exception:
                    pass
            sport, dport = _extract_ports(pkt)
            payload = _extract_payload(pkt)
            ts = safe_float(getattr(pkt, "time", None))
            for hint in _extract_hostname_hints(payload):
                src_hostname_hints[src_ip][hint] += 1
            for marker in _extract_scanner_markers(payload):
                src_tool_markers[src_ip][marker] += 1

            if TCP is not None and pkt.haslayer(TCP):
                flags = getattr(pkt[TCP], "flags", None)
                tcp_sport = sport if sport is not None else None
                tcp_dport = dport if dport is not None else None
                if tcp_sport is not None and tcp_dport is not None:
                    flow_key = (src_ip, dst_ip, int(tcp_sport), int(tcp_dport))
                    reverse_key = (dst_ip, src_ip, int(tcp_dport), int(tcp_sport))
                    pair_key, src_is_left = _canonical_tcp_pair(
                        src_ip, int(tcp_sport), dst_ip, int(tcp_dport)
                    )
                    flow_stats = seen_tcp_flows.get(pair_key)
                    if flow_stats is None:
                        flow_stats = {
                            "packets_ab": 0,
                            "packets_ba": 0,
                            "syn_ab": 0,
                            "syn_ba": 0,
                            "payload_bytes_ab": 0,
                            "payload_bytes_ba": 0,
                            "rst_ab": 0,
                            "rst_ba": 0,
                        }
                        seen_tcp_flows[pair_key] = flow_stats
                    if src_is_left:
                        flow_stats["packets_ab"] += 1
                    else:
                        flow_stats["packets_ba"] += 1
                    payload_len = len(_extract_payload(pkt))
                    if src_is_left:
                        flow_stats["payload_bytes_ab"] += int(payload_len)
                    else:
                        flow_stats["payload_bytes_ba"] += int(payload_len)
                    flags_int = _tcp_flags_int(flags)
                    if _tcp_is_rst(flags):
                        if src_is_left:
                            flow_stats["rst_ab"] += 1
                        else:
                            flow_stats["rst_ba"] += 1
                        # RST+ACK is a closed-port response back to the prober;
                        # a bare RST is usually the scanner tearing a half-open
                        # connection, so only the former counts as "closed".
                        if (flags_int & 0x10) and dst_ip != src_ip:
                            recv_rst[dst_ip] += 1
                            responsive_pairs.add((dst_ip, src_ip))
                    if _tcp_is_syn(flags):
                        syn_seen.add(flow_key)
                        if src_is_left:
                            flow_stats["syn_ab"] += 1
                        else:
                            flow_stats["syn_ba"] += 1
                    elif _tcp_is_synack(flags):
                        # SYN/ACK is an open-port response back to the scanner.
                        recv_synack[dst_ip] += 1
                        responsive_pairs.add((dst_ip, src_ip))
                        if reverse_key in syn_seen:
                            syn_ack_seen.add(reverse_key)
                    elif _tcp_is_final_handshake_ack(flags):
                        if flow_key in syn_seen and flow_key in syn_ack_seen:
                            handshake_complete.add(flow_key)

                # Classify the client-side probe by flag combination so stealth
                # scans (FIN/NULL/XMAS/Maimon/ACK) and connect scans are detected
                # alongside SYN scans rather than silently ignored.
                if dport is not None:
                    flavor = _tcp_scan_flavor(flags)
                    payload_len = len(payload)
                    probe_flow = (src_ip, dst_ip, int(sport or 0), int(dport))
                    probe_reverse = (dst_ip, src_ip, int(dport), int(sport or 0))
                    if flavor == "syn":
                        accept = True
                    elif flavor in _GATED_FLAVORS:
                        # Genuine probe only if the connection was never
                        # SYN-initiated in EITHER direction (so server-side
                        # FIN+ACK teardowns and mid-session ACKs of an
                        # established flow are not mistaken for stealth scans)
                        # and the packet carries no payload.
                        accept = (
                            probe_flow not in syn_seen
                            and probe_reverse not in syn_seen
                            and payload_len == 0
                        )
                    else:
                        accept = False
                    if accept:
                        _record_probe(
                            src_ip,
                            dst_ip,
                            int(dport),
                            ts,
                            src_targets,
                            src_ports,
                            src_dst_ports,
                            src_dst_packets,
                            src_first_seen,
                            src_last_seen,
                            src_ot_ports,
                            src_ot_targets,
                        )
                        src_flavor_probes[(src_ip, flavor)].add((dst_ip, int(dport)))
                        src_flavor_packets[(src_ip, flavor)] += 1
                        if flavor == "syn":
                            src_syn[src_ip] += 1
            elif UDP is not None and pkt.haslayer(UDP):
                # UDP scan: a host firing UDP datagrams at many ports/targets.
                if dport is not None:
                    _record_probe(
                        src_ip,
                        dst_ip,
                        int(dport),
                        ts,
                        src_targets,
                        src_ports,
                        src_dst_ports,
                        src_dst_packets,
                        src_first_seen,
                        src_last_seen,
                        src_ot_ports,
                        src_ot_targets,
                    )
                    src_flavor_probes[(src_ip, "udp")].add((dst_ip, int(dport)))
                    src_flavor_packets[(src_ip, "udp")] += 1
            elif ICMP is not None and pkt.haslayer(ICMP):
                try:
                    icmp_type = int(getattr(pkt[ICMP], "type", -1))
                except Exception:
                    icmp_type = -1
                if icmp_type == 8:
                    src_probe_targets[src_ip].add(dst_ip)
                    src_probe_packets[src_ip] += 1
                    src_flavor_probes[(src_ip, "icmp")].add((dst_ip, 0))
                    src_flavor_packets[(src_ip, "icmp")] += 1
                    if ts is not None:
                        src_first_seen[src_ip] = min(ts, src_first_seen.get(src_ip, ts))
                        src_last_seen[src_ip] = max(ts, src_last_seen.get(src_ip, ts))
                elif icmp_type == 3:
                    # Destination/port unreachable -> filtered/closed signal to
                    # the host that sent the probe (the scanner = dst_ip here).
                    recv_icmp_unreach[dst_ip] += 1

            if ARP is not None and pkt.haslayer(ARP):
                try:
                    op = int(getattr(pkt[ARP], "op", 0) or 0)
                except Exception:
                    op = 0
                if op == 1:
                    src_probe_targets[src_ip].add(dst_ip)
                    src_probe_packets[src_ip] += 1
                    src_flavor_probes[(src_ip, "arp")].add((dst_ip, 0))
                    src_flavor_packets[(src_ip, "arp")] += 1
                    if ts is not None:
                        src_first_seen[src_ip] = min(ts, src_first_seen.get(src_ip, ts))
                        src_last_seen[src_ip] = max(ts, src_last_seen.get(src_ip, ts))

            if sport is not None:
                banner = _extract_banner(payload, sport)
                if banner:
                    pair = (dst_ip, src_ip)
                    lst = banner_by_pair[pair]
                    if banner not in lst and len(lst) < 8:
                        lst.append(banner)

            if dport in AUTH_PORTS and _has_auth_attempt(payload):
                pair = (src_ip, dst_ip)
                brute_attempts[pair] += 1
                for sample in _extract_creds(payload):
                    if (
                        sample not in creds_by_pair[pair]
                        and len(creds_by_pair[pair]) < 8
                    ):
                        creds_by_pair[pair].append(sample)

            if sport in AUTH_PORTS:
                fail, success = _auth_result(payload)
                if fail or success:
                    pair = (dst_ip, src_ip)
                    brute_fails[pair] += fail
                    brute_success[pair] += success

        # Handshake-confirmed open ports require responder payload evidence.
        for client_ip, server_ip, client_port, server_port in handshake_complete:
            open_ports_by_pair[(client_ip, server_ip)].add(int(server_port))

        # Fallback for capture-gapped sessions:
        # if handshake isn't present, treat bidirectional seen traffic as possible open service.
        for pair_key, flow_stats in seen_tcp_flows.items():
            a_ip, a_port, b_ip, b_port = pair_key
            flow_key = (a_ip, b_ip, a_port, b_port)
            reverse_key = (b_ip, a_ip, b_port, a_port)
            if flow_key in handshake_complete or reverse_key in handshake_complete:
                continue
            if (
                int(flow_stats.get("packets_ab", 0)) <= 0
                or int(flow_stats.get("packets_ba", 0)) <= 0
            ):
                continue
            inferred = _infer_server_from_seen_traffic(
                a_ip=a_ip,
                a_port=a_port,
                b_ip=b_ip,
                b_port=b_port,
                syn_ab=int(flow_stats.get("syn_ab", 0) or 0),
                syn_ba=int(flow_stats.get("syn_ba", 0) or 0),
            )
            if inferred is None:
                continue
            server_ip, server_port, client_ip = inferred
            server_is_left = server_ip == a_ip and server_port == a_port
            if not _seen_traffic_supports_service_presence(
                flow_stats, server_is_left=server_is_left
            ):
                continue
            open_ports_by_pair[(client_ip, server_ip)].add(int(server_port))

    except Exception as exc:
        summary.errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        status.finish()
        try:
            reader.close()
        except Exception:
            pass

    results: list[ScanSourceResult] = []
    included_scanners: set[str] = set()
    scanner_ips = set(src_targets) | set(src_probe_targets)
    for scanner in scanner_ips:
        syn_targets = src_targets.get(scanner, set())
        probe_targets = src_probe_targets.get(scanner, set())
        targets = set(syn_targets) | set(probe_targets)
        unique_targets = len(targets)
        unique_ports = len(src_ports.get(scanner, set()))
        syn_packets = int(src_syn.get(scanner, 0))
        probe_packets = int(src_probe_packets.get(scanner, 0))
        max_ports_single_target = 0
        for target in targets:
            max_ports_single_target = max(
                max_ports_single_target,
                len(src_dst_ports.get((scanner, target), set())),
            )

        if not _is_scanner_source(
            unique_targets,
            unique_ports,
            syn_packets,
            probe_packets,
            max_ports_single_target,
        ):
            continue

        # Flavor-agnostic classification: a port scan (vertical) is many ports
        # on a target via ANY technique, not only SYN — so stealth/UDP scans are
        # detected too.
        has_vertical = max_ports_single_target >= 20
        # A TCP horizontal "scan" that matters for IR is a LATERAL sweep of many
        # INTERNAL hosts. A workstation contacting 100+ EXTERNAL hosts is just
        # web browsing / CDN / telemetry (the Ursnif victim hit 121 external web
        # servers + its DC). So gate the TCP horizontal branch on internal-target
        # breadth; ICMP/ARP sweeps (probe_targets) still always flag.
        internal_targets = sum(1 for t in targets if is_private_ip(t))
        has_horizontal = len(probe_targets) >= 10 or (
            internal_targets >= 10 and not has_vertical
        )

        common_mac_addresses = [
            mac
            for mac, _count in src_mac_counts.get(scanner, Counter()).most_common(4)
        ]
        common_os = _guess_os_from_ttl(src_ttl_counts.get(scanner, Counter()))
        common_hostname_hints = [
            name
            for name, _count in src_hostname_hints.get(scanner, Counter()).most_common(6)
        ]

        # Techniques used (by flag combination / protocol), connect vs half-open.
        scanner_handshakes = sum(
            1 for (c, _s, _cp, _sp) in handshake_complete if c == scanner
        )
        techniques: list[str] = []
        for flavor in ("syn", "fin", "null", "xmas", "maimon", "ack", "udp", "arp", "icmp"):
            spread = len(src_flavor_probes.get((scanner, flavor), set()))
            if spread < 5:
                continue
            label = _TECHNIQUE_LABELS[flavor]
            # A -sS half-open scan RSTs after the SYN/ACK and never completes a
            # handshake; a -sT connect scan completes the handshake on each open
            # port. So any completed handshakes during a SYN sweep => connect.
            if flavor == "syn" and scanner_handshakes >= 2:
                label = _TECHNIQUE_LABELS["connect"]
            techniques.append(label)

        def _scope(ip: str) -> str:
            if is_private_ip(ip):
                return "internal"
            if is_public_ip(ip):
                return "external"
            return "-"

        def _scope_of(target_set: set[str]) -> str:
            scopes = {_scope(t) for t in target_set} - {"-"}
            if scopes == {"internal"}:
                return "internal"
            if scopes == {"external"}:
                return "external"
            return "mixed" if scopes else "-"

        scanner_scope = _scope(scanner)
        first_ts = src_first_seen.get(scanner)
        last_ts = src_last_seen.get(scanner)
        duration = (
            float(last_ts) - float(first_ts)
            if first_ts is not None and last_ts is not None and last_ts > first_ts
            else 0.0
        )
        total_probe_packets = (
            sum(c for (s, _d), c in src_dst_packets.items() if s == scanner)
            + probe_packets
        )
        pps = (total_probe_packets / duration) if duration > 0 else 0.0
        open_resp = int(recv_synack.get(scanner, 0))
        closed_resp = int(recv_rst.get(scanner, 0))
        filtered_resp = int(recv_icmp_unreach.get(scanner, 0))
        responsive = sum(1 for (s, _t) in responsive_pairs if s == scanner)
        ot_ports_hit = sorted(src_ot_ports.get(scanner, set()))
        ot_targets_hit = sorted(src_ot_targets.get(scanner, set()))

        def _decorate(res: ScanSourceResult, target_set: set[str]) -> ScanSourceResult:
            res.techniques = list(techniques)
            res.probe_packets = total_probe_packets
            res.scanner_scope = scanner_scope
            res.target_scope = _scope_of(target_set)
            res.duration_seconds = round(duration, 3)
            res.packets_per_second = round(pps, 1)
            res.open_responses = open_resp
            res.closed_responses = closed_resp
            res.filtered_responses = filtered_resp
            res.responsive_targets = responsive
            res.ot_ports = ot_ports_hit
            res.ot_targets = ot_targets_hit
            return res

        def _build_targets(target_set: set[str]) -> list[ScanTargetResult]:
            rows: list[ScanTargetResult] = []
            for target in sorted(target_set):
                pair = (scanner, target)
                rows.append(
                    ScanTargetResult(
                        target_ip=target,
                        open_ports=sorted(open_ports_by_pair.get(pair, set()))[:50],
                        banner_samples=banner_by_pair.get(pair, [])[:8],
                        brute_force_attempts=int(brute_attempts.get(pair, 0)),
                        brute_force_failures=int(brute_fails.get(pair, 0)),
                        brute_force_success_hints=int(brute_success.get(pair, 0)),
                        credential_samples=creds_by_pair.get(pair, [])[:6],
                    )
                )
            return sorted(rows, key=lambda item: (-(len(item.open_ports)), item.target_ip))

        def _build_port_popularity(target_set: set[str]) -> Counter[int]:
            popularity: Counter[int] = Counter()
            for target in target_set:
                for p in src_dst_ports.get((scanner, target), set()):
                    popularity[int(p)] += 1
            return popularity

        if has_vertical:
            vertical_targets = set(targets)
            vertical_ports = _build_port_popularity(vertical_targets)
            results.append(
                _decorate(
                    ScanSourceResult(
                        scanner_ip=scanner,
                        scan_type="vertical",
                        unique_targets=len(vertical_targets),
                        unique_ports=unique_ports,
                        syn_packets=syn_packets,
                        first_seen=src_first_seen.get(scanner),
                        last_seen=src_last_seen.get(scanner),
                        mac_addresses=common_mac_addresses,
                        possible_os=common_os,
                        hostname_hints=common_hostname_hints,
                        scanner_software_guess=_guess_scanner_tool(
                            scan_type="vertical",
                            unique_targets=len(vertical_targets),
                            unique_ports=unique_ports,
                            syn_packets=syn_packets,
                            probe_packets=0,
                            top_ports=[p for p, _ in vertical_ports.most_common(12)],
                            markers=src_tool_markers.get(scanner, Counter()),
                        ),
                        top_ports=[p for p, _ in vertical_ports.most_common(12)],
                        targets=_build_targets(vertical_targets),
                    ),
                    vertical_targets,
                )
            )
            included_scanners.add(scanner)

        if has_horizontal:
            horizontal_targets = set(probe_targets) if probe_targets else set(targets)
            horizontal_ports = _build_port_popularity(horizontal_targets)
            horizontal_syn = 0 if probe_targets else syn_packets
            results.append(
                _decorate(
                    ScanSourceResult(
                        scanner_ip=scanner,
                        scan_type="horizontal",
                        unique_targets=len(horizontal_targets),
                        unique_ports=len(horizontal_ports),
                        syn_packets=horizontal_syn,
                        first_seen=src_first_seen.get(scanner),
                        last_seen=src_last_seen.get(scanner),
                        mac_addresses=common_mac_addresses,
                        possible_os=common_os,
                        hostname_hints=common_hostname_hints,
                        scanner_software_guess=_guess_scanner_tool(
                            scan_type="horizontal",
                            unique_targets=len(horizontal_targets),
                            unique_ports=len(horizontal_ports),
                            syn_packets=horizontal_syn,
                            probe_packets=probe_packets,
                            top_ports=[p for p, _ in horizontal_ports.most_common(12)],
                            markers=src_tool_markers.get(scanner, Counter()),
                        ),
                        top_ports=[p for p, _ in horizontal_ports.most_common(12)],
                        targets=_build_targets(horizontal_targets),
                    ),
                    horizontal_targets,
                )
            )
            included_scanners.add(scanner)

    summary.scan_sources = sorted(
        results,
        key=lambda item: (item.unique_ports, item.unique_targets, item.syn_packets),
        reverse=True,
    )
    summary.relevant_packets = sum(
        sum(c for (s, _d), c in src_dst_packets.items() if s == scanner)
        + int(src_probe_packets.get(scanner, 0))
        for scanner in included_scanners
    )
    return summary


def merge_scan_summaries(summaries: list[ScanSummary]) -> ScanSummary:
    if not summaries:
        return ScanSummary(path=Path("ALL_PCAPS_0"))

    merged = ScanSummary(path=Path(f"ALL_PCAPS_{len(summaries)}"))
    merged.total_packets = sum(item.total_packets for item in summaries)
    merged.relevant_packets = sum(item.relevant_packets for item in summaries)
    for item in summaries:
        merged.errors.extend(item.errors)

    by_scanner: dict[tuple[str, str], ScanSourceResult] = {}
    for summary in summaries:
        for src in summary.scan_sources:
            key = (src.scanner_ip, src.scan_type)
            current = by_scanner.get(key)
            if current is None:
                by_scanner[key] = ScanSourceResult(
                    scanner_ip=src.scanner_ip,
                    scan_type=src.scan_type,
                    unique_targets=src.unique_targets,
                    unique_ports=src.unique_ports,
                    syn_packets=src.syn_packets,
                    first_seen=src.first_seen,
                    last_seen=src.last_seen,
                    mac_addresses=list(src.mac_addresses),
                    possible_os=src.possible_os,
                    hostname_hints=list(src.hostname_hints),
                    scanner_software_guess=src.scanner_software_guess,
                    top_ports=list(src.top_ports),
                    targets=list(src.targets),
                    techniques=list(src.techniques),
                    probe_packets=src.probe_packets,
                    scanner_scope=src.scanner_scope,
                    target_scope=src.target_scope,
                    duration_seconds=src.duration_seconds,
                    packets_per_second=src.packets_per_second,
                    open_responses=src.open_responses,
                    closed_responses=src.closed_responses,
                    filtered_responses=src.filtered_responses,
                    responsive_targets=src.responsive_targets,
                    ot_ports=list(src.ot_ports),
                    ot_targets=list(src.ot_targets),
                )
                continue

            current.unique_targets = max(current.unique_targets, src.unique_targets)
            current.unique_ports = max(current.unique_ports, src.unique_ports)
            current.syn_packets += src.syn_packets
            if src.first_seen is not None:
                current.first_seen = (
                    src.first_seen
                    if current.first_seen is None
                    else min(current.first_seen, src.first_seen)
                )
            if src.last_seen is not None:
                current.last_seen = (
                    src.last_seen
                    if current.last_seen is None
                    else max(current.last_seen, src.last_seen)
                )

            top_ports = list(
                dict.fromkeys((current.top_ports or []) + (src.top_ports or []))
            )
            current.top_ports = top_ports[:12]
            current.mac_addresses = list(
                dict.fromkeys((current.mac_addresses or []) + (src.mac_addresses or []))
            )[:6]
            current.hostname_hints = list(
                dict.fromkeys(
                    (current.hostname_hints or []) + (src.hostname_hints or [])
                )
            )[:8]
            if (
                not current.possible_os or current.possible_os == "-"
            ) and src.possible_os:
                current.possible_os = src.possible_os
            if (
                current.scanner_software_guess.startswith("Heuristic:")
                and src.scanner_software_guess
                and not src.scanner_software_guess.startswith("Heuristic:")
            ):
                current.scanner_software_guess = src.scanner_software_guess

            current.techniques = list(
                dict.fromkeys((current.techniques or []) + (src.techniques or []))
            )
            current.probe_packets += src.probe_packets
            current.open_responses += src.open_responses
            current.closed_responses += src.closed_responses
            current.filtered_responses += src.filtered_responses
            current.responsive_targets += src.responsive_targets
            current.packets_per_second = max(
                current.packets_per_second, src.packets_per_second
            )
            if current.first_seen is not None and current.last_seen is not None:
                current.duration_seconds = round(
                    max(0.0, current.last_seen - current.first_seen), 3
                )
            if src.scanner_scope and src.scanner_scope != "-":
                current.scanner_scope = src.scanner_scope
            if src.target_scope and src.target_scope != "-":
                current.target_scope = (
                    src.target_scope
                    if current.target_scope in ("-", src.target_scope)
                    else "mixed"
                )
            current.ot_ports = sorted(set(current.ot_ports) | set(src.ot_ports))
            current.ot_targets = sorted(set(current.ot_targets) | set(src.ot_targets))

            by_target: dict[str, ScanTargetResult] = {
                item.target_ip: item for item in current.targets
            }
            for row in src.targets:
                existing = by_target.get(row.target_ip)
                if existing is None:
                    by_target[row.target_ip] = ScanTargetResult(
                        target_ip=row.target_ip,
                        open_ports=list(row.open_ports),
                        banner_samples=list(row.banner_samples),
                        brute_force_attempts=row.brute_force_attempts,
                        brute_force_failures=row.brute_force_failures,
                        brute_force_success_hints=row.brute_force_success_hints,
                        credential_samples=list(row.credential_samples),
                    )
                    continue
                existing.open_ports = sorted(
                    set(existing.open_ports).union(row.open_ports)
                )[:50]
                existing.banner_samples = list(
                    dict.fromkeys(existing.banner_samples + row.banner_samples)
                )[:8]
                existing.credential_samples = list(
                    dict.fromkeys(existing.credential_samples + row.credential_samples)
                )[:6]
                existing.brute_force_attempts += row.brute_force_attempts
                existing.brute_force_failures += row.brute_force_failures
                existing.brute_force_success_hints += row.brute_force_success_hints
            current.targets = sorted(
                by_target.values(),
                key=lambda item: (-(len(item.open_ports)), item.target_ip),
            )

    merged.scan_sources = sorted(
        by_scanner.values(),
        key=lambda item: (item.unique_ports, item.unique_targets, item.syn_packets),
        reverse=True,
    )
    return merged
