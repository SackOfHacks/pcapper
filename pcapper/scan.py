from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .pcap_cache import PcapMeta, get_reader
from .services import COMMON_PORTS
from .utils import safe_float

try:
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw
except Exception:  # pragma: no cover
    IP = TCP = UDP = IPv6 = Ether = Raw = None


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
    if IP is not None and pkt.haslayer(IP):
        return str(pkt[IP].src), str(pkt[IP].dst)
    if IPv6 is not None and pkt.haslayer(IPv6):
        return str(pkt[IPv6].src), str(pkt[IPv6].dst)
    return "-", "-"


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


def _tcp_flags_int(flags: object) -> int:
    try:
        if isinstance(flags, str):
            value = 0
            if "F" in flags:
                value |= 0x01
            if "S" in flags:
                value |= 0x02
            if "R" in flags:
                value |= 0x04
            if "P" in flags:
                value |= 0x08
            if "A" in flags:
                value |= 0x10
            if "U" in flags:
                value |= 0x20
            if "E" in flags:
                value |= 0x40
            if "C" in flags:
                value |= 0x80
            return value
        return int(flags)
    except Exception:
        return 0


def _tcp_is_synack(flags: object) -> bool:
    try:
        if isinstance(flags, str):
            return "S" in flags and "A" in flags
        return (int(flags) & 0x12) == 0x12
    except Exception:
        return False


def _tcp_is_ack_no_syn(flags: object) -> bool:
    try:
        if isinstance(flags, str):
            return "A" in flags and "S" not in flags
        value = int(flags)
        return bool(value & 0x10) and not bool(value & 0x02)
    except Exception:
        return False


def _tcp_is_rst(flags: object) -> bool:
    value = _tcp_flags_int(flags)
    return bool(value & 0x04)


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
    if scan_type == "horizontal" and unique_targets >= 30 and (top & low_common):
        return "Heuristic: Nmap-style service discovery sweep"
    if unique_targets >= 20 and unique_ports >= 100:
        return "Heuristic: automated recon scanner"
    return "Heuristic: custom/manual scanning activity"


def _is_scanner_source(
    unique_targets: int,
    unique_ports: int,
    syn_packets: int,
    max_ports_single_target: int,
) -> bool:
    if max_ports_single_target >= 20:
        return True
    if unique_targets >= 10:
        return True
    if unique_ports >= 30:
        return True
    if syn_packets >= 150 and unique_ports >= 10:
        return True
    return False


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
                    if _tcp_is_rst(flags):
                        if src_is_left:
                            flow_stats["rst_ab"] += 1
                        else:
                            flow_stats["rst_ba"] += 1
                    if _tcp_is_syn(flags):
                        syn_seen.add(flow_key)
                        if src_is_left:
                            flow_stats["syn_ab"] += 1
                        else:
                            flow_stats["syn_ba"] += 1
                    elif _tcp_is_synack(flags):
                        if reverse_key in syn_seen:
                            syn_ack_seen.add(reverse_key)
                    elif _tcp_is_final_handshake_ack(flags):
                        if flow_key in syn_seen and flow_key in syn_ack_seen:
                            handshake_complete.add(flow_key)

                if _tcp_is_syn(flags) and dport is not None:
                    src_targets[src_ip].add(dst_ip)
                    src_ports[src_ip].add(int(dport))
                    src_dst_ports[(src_ip, dst_ip)].add(int(dport))
                    src_dst_packets[(src_ip, dst_ip)] += 1
                    src_syn[src_ip] += 1
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
    for scanner, targets in src_targets.items():
        unique_targets = len(targets)
        unique_ports = len(src_ports.get(scanner, set()))
        syn_packets = int(src_syn.get(scanner, 0))
        max_ports_single_target = 0
        for target in targets:
            max_ports_single_target = max(
                max_ports_single_target,
                len(src_dst_ports.get((scanner, target), set())),
            )

        if not _is_scanner_source(
            unique_targets, unique_ports, syn_packets, max_ports_single_target
        ):
            continue

        has_vertical = max_ports_single_target >= 20
        has_horizontal = unique_targets >= 10
        scan_type = "mixed"
        if has_vertical and not has_horizontal:
            scan_type = "vertical"
        elif has_horizontal and not has_vertical:
            scan_type = "horizontal"

        target_rows: list[ScanTargetResult] = []
        for target in sorted(targets):
            pair = (scanner, target)
            open_ports = sorted(open_ports_by_pair.get(pair, set()))
            banners = banner_by_pair.get(pair, [])
            attempts = int(brute_attempts.get(pair, 0))
            fails = int(brute_fails.get(pair, 0))
            success = int(brute_success.get(pair, 0))
            creds = creds_by_pair.get(pair, [])
            target_rows.append(
                ScanTargetResult(
                    target_ip=target,
                    open_ports=open_ports[:50],
                    banner_samples=banners[:8],
                    brute_force_attempts=attempts,
                    brute_force_failures=fails,
                    brute_force_success_hints=success,
                    credential_samples=creds[:6],
                )
            )

        port_popularity: Counter[int] = Counter()
        for target in targets:
            for p in src_dst_ports.get((scanner, target), set()):
                port_popularity[int(p)] += 1

        results.append(
            ScanSourceResult(
                scanner_ip=scanner,
                scan_type=scan_type,
                unique_targets=unique_targets,
                unique_ports=unique_ports,
                syn_packets=syn_packets,
                first_seen=src_first_seen.get(scanner),
                last_seen=src_last_seen.get(scanner),
                mac_addresses=[
                    mac
                    for mac, _count in src_mac_counts.get(
                        scanner, Counter()
                    ).most_common(4)
                ],
                possible_os=_guess_os_from_ttl(src_ttl_counts.get(scanner, Counter())),
                hostname_hints=[
                    name
                    for name, _count in src_hostname_hints.get(
                        scanner, Counter()
                    ).most_common(6)
                ],
                scanner_software_guess=_guess_scanner_tool(
                    scan_type=scan_type,
                    unique_targets=unique_targets,
                    unique_ports=unique_ports,
                    syn_packets=syn_packets,
                    top_ports=[p for p, _ in port_popularity.most_common(12)],
                    markers=src_tool_markers.get(scanner, Counter()),
                ),
                top_ports=[p for p, _ in port_popularity.most_common(12)],
                targets=sorted(
                    target_rows,
                    key=lambda item: (-(len(item.open_ports)), item.target_ip),
                ),
            )
        )

    summary.scan_sources = sorted(
        results,
        key=lambda item: (item.unique_ports, item.unique_targets, item.syn_packets),
        reverse=True,
    )
    summary.relevant_packets = sum(item.syn_packets for item in summary.scan_sources)
    return summary


def merge_scan_summaries(summaries: list[ScanSummary]) -> ScanSummary:
    if not summaries:
        return ScanSummary(path=Path("ALL_PCAPS_0"))

    merged = ScanSummary(path=Path(f"ALL_PCAPS_{len(summaries)}"))
    merged.total_packets = sum(item.total_packets for item in summaries)
    merged.relevant_packets = sum(item.relevant_packets for item in summaries)
    for item in summaries:
        merged.errors.extend(item.errors)

    by_scanner: dict[str, ScanSourceResult] = {}
    for summary in summaries:
        for src in summary.scan_sources:
            current = by_scanner.get(src.scanner_ip)
            if current is None:
                by_scanner[src.scanner_ip] = ScanSourceResult(
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
