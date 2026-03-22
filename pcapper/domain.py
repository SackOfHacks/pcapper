from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .pcap_cache import PcapMeta, get_reader
from .utils import detect_file_type, safe_float
from .dns import analyze_dns
from .netbios import analyze_netbios
from .ntlm import analyze_ntlm
from .files import analyze_files
from .progress import run_with_busy_status

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore


DOMAIN_PORTS = {53, 88, 135, 139, 389, 445, 464, 593, 3268, 3269, 636}
KERBEROS_PORTS = {88, 464}
LDAP_PORTS = {389, 636, 3268, 3269}
SMB_PORTS = {445, 139}
RPC_PORTS = {135, 593}
DNS_PORTS = {53}


def _port_to_domain_service(port: int) -> str:
    if port in KERBEROS_PORTS:
        return "Kerberos"
    if port in LDAP_PORTS:
        return "LDAP"
    if port in SMB_PORTS:
        return "SMB"
    if port in RPC_PORTS:
        return "RPC"
    if port in DNS_PORTS:
        return "DNS"
    return f"Port {port}"


@dataclass(frozen=True)
class DomainConversation:
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str
    packets: int


@dataclass(frozen=True)
class DomainAnalysis:
    path: Path
    duration: float
    total_packets: int
    domains: Counter[str]
    dc_hosts: Counter[str]
    servers: Counter[str]
    clients: Counter[str]
    service_counts: Counter[str]
    response_codes: Counter[str]
    request_counts: Counter[str]
    urls: Counter[str]
    user_agents: Counter[str]
    users: Counter[str]
    credentials: Counter[str]
    computer_names: Counter[str]
    files: List[str]
    conversations: List[DomainConversation]
    anomalies: List[str]
    detections: List[Dict[str, object]]
    errors: List[str]
    deterministic_checks: Dict[str, List[str]] = field(default_factory=dict)
    dc_role_drift: List[Dict[str, object]] = field(default_factory=list)
    kerberos_abuse_profiles: List[Dict[str, object]] = field(default_factory=list)
    dcsync_signals: List[Dict[str, object]] = field(default_factory=list)
    ldap_bind_risks: List[Dict[str, object]] = field(default_factory=list)
    ntlm_relay_signals: List[str] = field(default_factory=list)
    sequence_violations: List[Dict[str, object]] = field(default_factory=list)
    host_attack_paths: List[Dict[str, object]] = field(default_factory=list)
    incident_clusters: List[Dict[str, object]] = field(default_factory=list)
    campaign_indicators: List[Dict[str, object]] = field(default_factory=list)
    benign_context: List[str] = field(default_factory=list)


_DOMAIN_SKIP_SUFFIXES = (".in-addr.arpa", ".ip6.arpa")
_CRED_USER_PATTERNS = [
    re.compile(r"(?i)\b(user(name)?|login|uid|cn|samaccountname|userprincipalname)\b\s*[:=]\s*([^\s'\";]{2,})"),
]
_CRED_PASS_PATTERNS = [
    re.compile(r"(?i)\b(pass(word)?|passwd|pwd)\b\s*[:=]\s*([^\s'\";]{4,})"),
]


def _base_domain(name: str) -> str:
    name = name.strip(".")
    if not name:
        return name
    parts = [part for part in name.split(".") if part]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return name


def _extract_ascii_strings(data: bytes, min_len: int = 4, max_len: int = 200) -> List[str]:
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


def _extract_utf16le_strings(data: bytes, min_len: int = 4, max_len: int = 200) -> List[str]:
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


def _parse_http_request(payload: bytes) -> Tuple[Optional[str], Optional[str]]:
    try:
        header, _ = payload.split(b"\r\n\r\n", 1)
    except Exception:
        return None, None
    try:
        lines = header.split(b"\r\n")
        if not lines:
            return None, None
        req_line = lines[0].decode("latin-1", errors="ignore")
        parts = req_line.split(" ")
        if len(parts) < 2:
            return None, None
        path = parts[1]
        host = None
        ua = None
        for line in lines[1:]:
            if line.lower().startswith(b"host:"):
                host = line.split(b":", 1)[1].strip().decode("latin-1", errors="ignore")
            if line.lower().startswith(b"user-agent:"):
                ua = line.split(b":", 1)[1].strip().decode("latin-1", errors="ignore")
        if host:
            url = f"{host}{path}"
        else:
            url = path
        return url, ua
    except Exception:
        return None, None


def analyze_domain(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> DomainAnalysis:
    errors: List[str] = []
    detections: List[Dict[str, object]] = []
    anomalies: List[str] = []

    def _busy(desc: str, func, *args, **kwargs):
        return run_with_busy_status(path, show_status, f"Domain: {desc}", func, *args, **kwargs)

    dns_summary = _busy("DNS", analyze_dns, path, show_status=False, packets=packets, meta=meta)
    netbios_summary = _busy("NetBIOS", analyze_netbios, path, show_status=False)
    ntlm_summary = _busy("NTLM", analyze_ntlm, path, show_status=False)
    files_summary = _busy("Files", analyze_files, path, show_status=False)

    domains = Counter()
    for qname, count in dns_summary.qname_counts.items():
        qname_lower = qname.lower().strip(".")
        if any(qname_lower.endswith(suffix) for suffix in _DOMAIN_SKIP_SUFFIXES):
            continue
        base = _base_domain(qname_lower)
        if base:
            domains[base] += count

    dc_hosts = Counter()
    for ip, host in netbios_summary.hosts.items():
        if host.is_domain_controller:
            dc_hosts[ip] += 1

    users = Counter(ntlm_summary.raw_users)
    computer_names = Counter(ntlm_summary.raw_workstations)

    for name in netbios_summary.unique_names:
        if name:
            computer_names[name] += 1

    response_codes = Counter()
    response_codes.update(netbios_summary.response_codes)
    response_codes.update(ntlm_summary.status_codes)

    request_counts = Counter()
    request_counts.update(netbios_summary.request_counts)
    request_counts.update(ntlm_summary.request_counts)

    files = [art.filename for art in files_summary.artifacts]

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, packets=packets, meta=meta, show_status=show_status
    )

    total_packets = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    servers = Counter()
    clients = Counter()
    service_counts = Counter()
    urls = Counter()
    user_agents = Counter()
    convos: Dict[Tuple[str, str, int, str], int] = defaultdict(int)
    credentials = Counter()
    server_service_hits: Dict[str, Counter[str]] = defaultdict(Counter)
    src_service_hits: Dict[str, Counter[str]] = defaultdict(Counter)
    pair_ports: Dict[Tuple[str, str], set[int]] = defaultdict(set)
    pair_packets: Counter[Tuple[str, str]] = Counter()
    ldap_simple_bind_hits: Counter[Tuple[str, str]] = Counter()
    ldap_anonymous_bind_hits: Counter[Tuple[str, str]] = Counter()
    kerberos_targets_by_src: Dict[str, set[str]] = defaultdict(set)

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
            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            src_ip = None
            dst_ip = None
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                ip_layer = pkt[IP]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                ip_layer = pkt[IPv6]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))

            if not src_ip or not dst_ip:
                continue

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp_layer = pkt[TCP]  # type: ignore[index]
                sport = int(getattr(tcp_layer, "sport", 0) or 0)
                dport = int(getattr(tcp_layer, "dport", 0) or 0)
                if dport in DOMAIN_PORTS or sport in DOMAIN_PORTS:
                    if dport in DOMAIN_PORTS:
                        server_ip = dst_ip
                        client_ip = src_ip
                        server_port = dport
                    else:
                        server_ip = src_ip
                        client_ip = dst_ip
                        server_port = sport

                    service_name = _port_to_domain_service(server_port)
                    servers[server_ip] += 1
                    clients[client_ip] += 1
                    service_counts[f"TCP/{server_port}"] += 1
                    convos[(client_ip, server_ip, server_port, "TCP")] += 1
                    server_service_hits[server_ip][service_name] += 1
                    src_service_hits[client_ip][service_name] += 1
                    pair_ports[(client_ip, server_ip)].add(server_port)
                    pair_packets[(client_ip, server_ip)] += 1
                    if server_port in KERBEROS_PORTS:
                        kerberos_targets_by_src[client_ip].add(server_ip)

                payload = bytes(getattr(tcp_layer, "payload", b""))
                if payload and payload.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ")):
                    url, ua = _parse_http_request(payload)
                    if url:
                        urls[url] += 1
                    if ua:
                        user_agents[ua] += 1

                if payload:
                    for value in _extract_ascii_strings(payload) + _extract_utf16le_strings(payload):
                        if not value:
                            continue
                        value_lower = value.lower()
                        if dport in LDAP_PORTS or sport in LDAP_PORTS:
                            pair_key = (src_ip, dst_ip) if dport in LDAP_PORTS else (dst_ip, src_ip)
                            if "simple" in value_lower and "bind" in value_lower:
                                ldap_simple_bind_hits[pair_key] += 1
                            if "anonymous" in value_lower and "bind" in value_lower:
                                ldap_anonymous_bind_hits[pair_key] += 1
                        for pattern in _CRED_USER_PATTERNS:
                            match = pattern.search(value)
                            if match:
                                user_val = match.group(3)
                                users[user_val] += 1
                        for pattern in _CRED_PASS_PATTERNS:
                            match = pattern.search(value)
                            if match:
                                credentials[match.group(0)] += 1

            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp_layer = pkt[UDP]  # type: ignore[index]
                sport = int(getattr(udp_layer, "sport", 0) or 0)
                dport = int(getattr(udp_layer, "dport", 0) or 0)
                if dport in DOMAIN_PORTS or sport in DOMAIN_PORTS:
                    if dport in DOMAIN_PORTS:
                        server_ip = dst_ip
                        client_ip = src_ip
                        server_port = dport
                    else:
                        server_ip = src_ip
                        client_ip = dst_ip
                        server_port = sport

                    service_name = _port_to_domain_service(server_port)
                    servers[server_ip] += 1
                    clients[client_ip] += 1
                    service_counts[f"UDP/{server_port}"] += 1
                    convos[(client_ip, server_ip, server_port, "UDP")] += 1
                    server_service_hits[server_ip][service_name] += 1
                    src_service_hits[client_ip][service_name] += 1
                    pair_ports[(client_ip, server_ip)].add(server_port)
                    pair_packets[(client_ip, server_ip)] += 1
                    if server_port in KERBEROS_PORTS:
                        kerberos_targets_by_src[client_ip].add(server_ip)
    finally:
        status.finish()
        reader.close()

    duration = 0.0
    if first_seen is not None and last_seen is not None:
        duration = max(0.0, last_seen - first_seen)

    conversations = [
        DomainConversation(src, dst, port, proto, count)
        for (src, dst, port, proto), count in convos.items()
    ]
    conversations.sort(key=lambda c: c.packets, reverse=True)

    if ntlm_summary.anomalies:
        anomalies.extend([a.title for a in ntlm_summary.anomalies])
    if netbios_summary.anomalies:
        anomalies.extend([a.type for a in netbios_summary.anomalies])

    if dc_hosts:
        detections.append({
            "severity": "info",
            "summary": "Domain Controllers observed",
            "details": ", ".join(dc_hosts.keys()),
            "source": "Domain",
        })
    if users:
        detections.append({
            "severity": "info",
            "summary": "Domain users observed",
            "details": ", ".join([u for u, _ in users.most_common(10)]),
            "source": "Domain",
        })
    if credentials:
        detections.append({
            "severity": "warning",
            "summary": "Potential credentials observed",
            "details": ", ".join([c for c, _ in credentials.most_common(5)]),
            "source": "Domain",
        })

    deterministic_checks: Dict[str, List[str]] = {
        "dc_role_consistency": [],
        "kerberos_ticket_abuse": [],
        "dcsync_replication_activity": [],
        "ldap_bind_risk": [],
        "ntlm_downgrade_or_relay_exposure": [],
        "auth_sequence_plausibility": [],
        "name_resolution_poisoning_context": [],
        "privileged_account_spread": [],
    }
    dc_role_drift: List[Dict[str, object]] = []
    kerberos_abuse_profiles: List[Dict[str, object]] = []
    dcsync_signals: List[Dict[str, object]] = []
    ldap_bind_risks: List[Dict[str, object]] = []
    ntlm_relay_signals: List[str] = []
    sequence_violations: List[Dict[str, object]] = []
    host_attack_paths: List[Dict[str, object]] = []
    incident_clusters: List[Dict[str, object]] = []
    campaign_indicators: List[Dict[str, object]] = []
    benign_context: List[str] = []

    dc_set = set(dc_hosts.keys())

    for server_ip, svc_counter in server_service_hits.items():
        infra_services = [name for name in ("Kerberos", "LDAP", "SMB", "RPC") if int(svc_counter.get(name, 0)) > 0]
        if len(infra_services) >= 2 and int(servers.get(server_ip, 0)) >= 20:
            if server_ip not in dc_set:
                item = {
                    "server": server_ip,
                    "services": infra_services,
                    "packets": int(servers.get(server_ip, 0)),
                    "observed_as_dc": False,
                }
                dc_role_drift.append(item)
                deterministic_checks["dc_role_consistency"].append(
                    f"{server_ip} exposes multi-role domain services ({', '.join(infra_services)}) but is not flagged as a DC"
                )

    for src_ip, svc_counter in src_service_hits.items():
        kerberos_hits = int(svc_counter.get("Kerberos", 0))
        target_count = len(kerberos_targets_by_src.get(src_ip, set()))
        if kerberos_hits >= 20 and target_count >= 3:
            profile = {
                "src": src_ip,
                "kerberos_requests": kerberos_hits,
                "target_dcs": target_count,
                "targets": sorted(kerberos_targets_by_src.get(src_ip, set())),
            }
            kerberos_abuse_profiles.append(profile)
            deterministic_checks["kerberos_ticket_abuse"].append(
                f"{src_ip} generated {kerberos_hits} Kerberos requests across {target_count} targets"
            )

    for (src_ip, dst_ip), ports in pair_ports.items():
        if dst_ip not in dc_set or src_ip in dc_set:
            continue
        if (135 in ports or 593 in ports) and 445 in ports and bool(set(ports).intersection(LDAP_PORTS)):
            signal = {
                "src": src_ip,
                "dc": dst_ip,
                "ports": sorted(ports),
                "packets": int(pair_packets.get((src_ip, dst_ip), 0)),
            }
            dcsync_signals.append(signal)
            deterministic_checks["dcsync_replication_activity"].append(
                f"{src_ip} contacted DC {dst_ip} over RPC+SMB+LDAP (ports={','.join(str(p) for p in sorted(ports))})"
            )

    cleartext_ldap_pairs = []
    for (src_ip, dst_ip), ports in pair_ports.items():
        if 389 in ports:
            cleartext_ldap_pairs.append((src_ip, dst_ip, int(pair_packets.get((src_ip, dst_ip), 0))))
    cleartext_ldap_pairs.sort(key=lambda item: item[2], reverse=True)
    for src_ip, dst_ip, pkt_count in cleartext_ldap_pairs[:8]:
        item = {
            "src": src_ip,
            "dst": dst_ip,
            "type": "cleartext_ldap",
            "packets": pkt_count,
        }
        ldap_bind_risks.append(item)
        deterministic_checks["ldap_bind_risk"].append(
            f"Cleartext LDAP observed: {src_ip}->{dst_ip} packets={pkt_count}"
        )

    for (src_ip, dst_ip), count in ldap_simple_bind_hits.most_common(8):
        ldap_bind_risks.append({
            "src": src_ip,
            "dst": dst_ip,
            "type": "simple_bind",
            "hits": int(count),
        })
        deterministic_checks["ldap_bind_risk"].append(
            f"Possible LDAP simple bind strings on {src_ip}->{dst_ip} hits={int(count)}"
        )
    for (src_ip, dst_ip), count in ldap_anonymous_bind_hits.most_common(8):
        ldap_bind_risks.append({
            "src": src_ip,
            "dst": dst_ip,
            "type": "anonymous_bind",
            "hits": int(count),
        })
        deterministic_checks["ldap_bind_risk"].append(
            f"Possible LDAP anonymous bind strings on {src_ip}->{dst_ip} hits={int(count)}"
        )

    ntlm_versions = getattr(ntlm_summary, "versions", Counter())
    ntlm_v1_hits = int(ntlm_versions.get("NTLMv1", 0)) + int(ntlm_versions.get("v1", 0))
    if ntlm_v1_hits > 0:
        msg = f"NTLMv1 authentication observed ({ntlm_v1_hits})"
        ntlm_relay_signals.append(msg)
        deterministic_checks["ntlm_downgrade_or_relay_exposure"].append(msg)
    for item in getattr(ntlm_summary, "anomalies", []):
        title = str(getattr(item, "title", "") or "")
        if "Anonymous NTLM" in title or "NTLMv1" in title:
            evidence = f"{title}: {str(getattr(item, 'description', '') or '')}"
            ntlm_relay_signals.append(evidence)
            deterministic_checks["ntlm_downgrade_or_relay_exposure"].append(evidence)

    ntlm_src_counts = getattr(ntlm_summary, "src_counts", Counter())
    for src_ip, svc_counter in src_service_hits.items():
        lateral_hits = int(svc_counter.get("SMB", 0)) + int(svc_counter.get("RPC", 0))
        auth_signal = int(svc_counter.get("Kerberos", 0)) + int(ntlm_src_counts.get(src_ip, 0))
        if lateral_hits >= 15 and auth_signal == 0:
            violation = {
                "src": src_ip,
                "lateral_hits": lateral_hits,
                "auth_signals": auth_signal,
                "reason": "SMB/RPC activity without clear auth precursor",
            }
            sequence_violations.append(violation)
            deterministic_checks["auth_sequence_plausibility"].append(
                f"{src_ip} produced SMB/RPC activity ({lateral_hits}) without visible auth precursor"
            )

    high_risk_nbns = [
        a for a in getattr(netbios_summary, "anomalies", [])
        if str(getattr(a, "severity", "")).upper() in {"HIGH", "CRITICAL"}
    ]
    if high_risk_nbns:
        for item in high_risk_nbns[:8]:
            deterministic_checks["name_resolution_poisoning_context"].append(
                f"{item.type} {item.src_ip}->{item.dst_ip}: {item.details}"
            )

    user_to_hosts: Dict[str, set[str]] = defaultdict(set)
    for sess in getattr(ntlm_summary, "sessions", []):
        username = str(getattr(sess, "username", "") or "").strip()
        src_ip = str(getattr(sess, "src_ip", "") or "").strip()
        if username and src_ip and username.lower() != "unknown":
            user_to_hosts[username].add(src_ip)
    for username, hosts in user_to_hosts.items():
        if len(hosts) >= 3:
            deterministic_checks["privileged_account_spread"].append(
                f"Account {username} used from {len(hosts)} hosts ({', '.join(sorted(hosts)[:6])})"
            )

    indicators_by_src: Dict[str, List[str]] = defaultdict(list)
    targets_by_src: Dict[str, set[str]] = defaultdict(set)
    for item in kerberos_abuse_profiles:
        src_ip = str(item.get("src", ""))
        indicators_by_src[src_ip].append("Kerberos ticketing burst across multiple targets")
        for target in item.get("targets", []):
            targets_by_src[src_ip].add(str(target))
    for item in dcsync_signals:
        src_ip = str(item.get("src", ""))
        indicators_by_src[src_ip].append("Replication-like RPC+SMB+LDAP sequence to DC")
        targets_by_src[src_ip].add(str(item.get("dc", "")))
    for item in sequence_violations:
        src_ip = str(item.get("src", ""))
        indicators_by_src[src_ip].append(str(item.get("reason", "Sequence plausibility issue")))

    for src_ip, indicators in indicators_by_src.items():
        unique_indicators = list(dict.fromkeys([v for v in indicators if v]))
        if not unique_indicators:
            continue
        confidence = "high" if len(unique_indicators) >= 2 else "medium"
        host_attack_paths.append({
            "host": src_ip,
            "steps": unique_indicators,
            "targets": sorted(targets_by_src.get(src_ip, set())),
            "confidence": confidence,
        })
        incident_clusters.append({
            "cluster": f"cluster-{src_ip}",
            "host": src_ip,
            "indicators": unique_indicators,
            "target_count": len(targets_by_src.get(src_ip, set())),
            "confidence": confidence,
        })

    shared_dc_sources: Dict[str, set[str]] = defaultdict(set)
    for signal in dcsync_signals:
        shared_dc_sources[str(signal.get("dc", ""))].add(str(signal.get("src", "")))
    for dc_ip, source_hosts in shared_dc_sources.items():
        if len(source_hosts) >= 2:
            campaign_indicators.append({
                "indicator": "Shared DC target for replication-like behavior",
                "value": dc_ip,
                "hosts": sorted(source_hosts),
            })

    for username, hosts in user_to_hosts.items():
        if len(hosts) >= 2:
            campaign_indicators.append({
                "indicator": "Shared account across hosts",
                "value": username,
                "hosts": sorted(hosts),
            })

    if not deterministic_checks["dc_role_consistency"]:
        benign_context.append("No strong DC role drift signal based on observed service mix")
    if not deterministic_checks["auth_sequence_plausibility"]:
        benign_context.append("No major domain auth sequence plausibility violations detected")

    if deterministic_checks["kerberos_ticket_abuse"]:
        detections.append({
            "severity": "warning",
            "summary": "Kerberos ticket abuse indicators",
            "details": "; ".join(deterministic_checks["kerberos_ticket_abuse"][:3]),
            "source": "Domain",
        })
    if deterministic_checks["dcsync_replication_activity"]:
        detections.append({
            "severity": "high",
            "summary": "Replication-like access pattern to Domain Controllers",
            "details": "; ".join(deterministic_checks["dcsync_replication_activity"][:3]),
            "source": "Domain",
        })
    if deterministic_checks["ntlm_downgrade_or_relay_exposure"]:
        detections.append({
            "severity": "warning",
            "summary": "NTLM downgrade/relay exposure",
            "details": "; ".join(deterministic_checks["ntlm_downgrade_or_relay_exposure"][:3]),
            "source": "Domain",
        })

    return DomainAnalysis(
        path=path,
        duration=duration,
        total_packets=total_packets,
        domains=domains,
        dc_hosts=dc_hosts,
        servers=servers,
        clients=clients,
        service_counts=service_counts,
        response_codes=response_codes,
        request_counts=request_counts,
        urls=urls,
        user_agents=user_agents,
        users=users,
        credentials=credentials,
        computer_names=computer_names,
        files=files,
        conversations=conversations,
        anomalies=anomalies,
        detections=detections,
        errors=errors,
        deterministic_checks=deterministic_checks,
        dc_role_drift=dc_role_drift,
        kerberos_abuse_profiles=kerberos_abuse_profiles,
        dcsync_signals=dcsync_signals,
        ldap_bind_risks=ldap_bind_risks,
        ntlm_relay_signals=ntlm_relay_signals,
        sequence_violations=sequence_violations,
        host_attack_paths=host_attack_paths,
        incident_clusters=incident_clusters,
        campaign_indicators=campaign_indicators,
        benign_context=benign_context,
    )
