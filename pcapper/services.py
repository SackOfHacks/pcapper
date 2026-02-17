from __future__ import annotations

from collections import defaultdict, Counter
from dataclasses import dataclass, field
import ipaddress
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import re

try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.packet import Raw, Packet
    from scapy.utils import PcapReader, PcapNgReader
except ImportError:
    IP = TCP = UDP = Ether = IPv6 = ARP = ICMP = DNS = Raw = None

from .pcap_cache import get_reader
from .utils import detect_file_type, safe_float

# --- Dataclasses ---

@dataclass
class ServiceAsset:
    ip: str
    port: int
    protocol: str # TCP/UDP
    service_name: str # e.g. "HTTP", "SSH"
    software: Optional[str] = None # e.g. "Apache/2.4", "OpenSSH 8.2"
    packets: int = 0
    bytes: int = 0
    clients: Set[str] = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0

@dataclass
class ServiceRisk:
    severity: str # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    affected_asset: str # IP:Port

@dataclass
class ServiceSummary:
    path: Path
    total_services: int
    assets: List[ServiceAsset]
    risks: List[ServiceRisk]
    hierarchy: Dict[str, int] # Service Name -> Count
    errors: List[str]


def merge_services_summaries(
    summaries: List[ServiceSummary] | Tuple[ServiceSummary, ...] | Set[ServiceSummary],
) -> ServiceSummary:
    summary_list = list(summaries)
    if not summary_list:
        return ServiceSummary(
            path=Path("ALL_PCAPS_0"),
            total_services=0,
            assets=[],
            risks=[],
            hierarchy={},
            errors=[],
        )

    assets_map: Dict[Tuple[str, int, str], ServiceAsset] = {}
    risks: List[ServiceRisk] = []
    cleartext_hits: Dict[Tuple[str, str], Set[int]] = defaultdict(set)
    nonstandard_hits: Dict[Tuple[str, str], Set[int]] = defaultdict(set)
    hierarchy: Counter[str] = Counter()
    errors: List[str] = []

    for summary in summary_list:
        risks.extend(summary.risks)
        hierarchy.update(summary.hierarchy)
        errors.extend(summary.errors)
        for asset in summary.assets:
            key = (asset.ip, asset.port, asset.protocol)
            existing = assets_map.get(key)
            if existing is None:
                assets_map[key] = ServiceAsset(
                    ip=asset.ip,
                    port=asset.port,
                    protocol=asset.protocol,
                    service_name=asset.service_name,
                    software=asset.software,
                    packets=asset.packets,
                    bytes=asset.bytes,
                    clients=set(asset.clients),
                    first_seen=asset.first_seen,
                    last_seen=asset.last_seen,
                )
            else:
                existing.packets += asset.packets
                existing.bytes += asset.bytes
                existing.clients.update(asset.clients)
                existing.first_seen = min(existing.first_seen, asset.first_seen)
                existing.last_seen = max(existing.last_seen, asset.last_seen)
                if not existing.software and asset.software:
                    existing.software = asset.software

    assets = sorted(
        assets_map.values(),
        key=lambda item: (item.ip, item.port, item.protocol),
    )

    return ServiceSummary(
        path=Path("ALL_PCAPS"),
        total_services=len(assets),
        assets=assets,
        risks=risks,
        hierarchy=dict(hierarchy),
        errors=errors,
    )

# --- Constants ---

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 
    53: "DNS", 69: "TFTP", 80: "HTTP", 88: "Kerberos",
    110: "POP3", 123: "NTP", 135: "RPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 
    445: "SMB", 514: "Syslog", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP", 
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt", 
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
    102: "S7/MMS/ICCP", 502: "Modbus/TCP", 9600: "FINS", 20000: "DNP3",
    2404: "IEC-104", 47808: "BACnet/IP", 44818: "EtherNet/IP", 2222: "ENIP-IO",
    34962: "PROFINET", 34963: "PROFINET", 34964: "PROFINET", 4840: "OPC UA",
    1911: "Niagara Fox", 4911: "Niagara Fox", 5094: "HART-IP",
    18245: "GE SRTP", 18246: "GE SRTP", 20547: "ProConOS", 1962: "PCWorx",
    5006: "MELSEC", 5007: "MELSEC", 5683: "CoAP", 5684: "CoAP",
    2455: "ODESYS", 1217: "ODESYS", 34378: "Yokogawa Vnet/IP",
    34379: "Yokogawa Vnet/IP", 34380: "Yokogawa Vnet/IP"
}

# --- Logic ---

def _get_banner(payload: bytes, port: int) -> Optional[str]:
    # Try different decode
    try:
        text = payload.decode('utf-8', errors='ignore')
    except:
        return None
        
    if not text: return None

    # SSH
    if port == 22 or text.startswith("SSH-"):
        m = re.match(r"(SSH-[\d.]+-[\w_.]+)", text)
        if m: return m.group(1)
        
    # HTTP Server
    if port in (80, 8080, 8000) or "HTTP/" in text:
        # Response header?
        m = re.search(r"Server:\s*([^\r\n]+)", text, re.IGNORECASE)
        if m: return m.group(1).strip()
    
    # FTP / SMTP
    if port in (21, 25) or text.startswith("220 "):
        if text.startswith("220 "):
            return text[4:].strip()
            
    return None


def _guess_service(payload: bytes, port: int) -> tuple[Optional[str], Optional[str]]:
    try:
        text = payload.decode("utf-8", errors="ignore")
    except Exception:
        return None, None

    if not text:
        return None, None

    if text.startswith("SSH-"):
        banner = _get_banner(payload, port)
        return "SSH", banner

    if text.startswith("HTTP/") or "HTTP/" in text[:16] or "Server:" in text:
        banner = _get_banner(payload, port)
        return "HTTP", banner

    if text.startswith("220 "):
        banner = _get_banner(payload, port)
        if "SMTP" in text.upper() or port == 25:
            return "SMTP", banner
        return "FTP", banner

    return None, None

def analyze_services(path: Path, show_status: bool = True) -> ServiceSummary:
    if IP is None:
         return ServiceSummary(path, 0, [], [], {}, ["Scapy unavailable"])

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path, show_status=show_status
        )
    except Exception as exc:
        return ServiceSummary(path, 0, [], [], {}, [f"Error: {exc}"])
    size_bytes = size_bytes

    # Map: (IP, Port, Proto) -> ServiceAsset
    services: Dict[Tuple[str, int, str], ServiceAsset] = {}
    risks: List[ServiceRisk] = []
    errors: List[str] = []
    cleartext_hits: Dict[Tuple[str, str], Set[int]] = defaultdict(set)
    nonstandard_hits: Dict[Tuple[str, str], Set[int]] = defaultdict(set)
    
    # To identify servers in TCP, we look for SYN-ACK (Flags=0x12) from them
    # OR we look for well-known ports responding
    # OR we look for banners
    
    # We will track provisional services if we see traffic *to* a well known port
    # But confirmed services are better.
    
    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            ts = safe_float(getattr(pkt, "time", 0))
            if IP in pkt:
                ip_layer = pkt[IP]
            elif IPv6 in pkt:
                ip_layer = pkt[IPv6]
            else:
                continue
                
            src = ip_layer.src
            dst = ip_layer.dst
            pkt_len = len(pkt)
            
            # TCP
            if TCP in pkt:
                tcp = pkt[TCP]
                sport = tcp.sport
                dport = tcp.dport
                flags = tcp.flags
                
                # Check for SYN-ACK (Agreement that Sport is a Service)
                # S=0x02, A=0x10. SA=0x12
                # Scapy flags are sometimes str, sometimes int.
                is_syn_ack = False
                if isinstance(flags, str):
                    is_syn_ack = 'S' in flags and 'A' in flags
                else:
                    is_syn_ack = (flags & 0x12) == 0x12
                
                if is_syn_ack:
                    # src is the Server
                    k = (src, sport, "TCP")
                    if k not in services:
                        s_name = COMMON_PORTS.get(sport, f"TCP/{sport}")
                        services[k] = ServiceAsset(src, sport, "TCP", s_name, first_seen=ts, last_seen=ts)
                    s = services[k]
                    s.clients.add(dst)
                    s.packets += 1
                    s.bytes += pkt_len
                    s.last_seen = ts
                    continue

                # Provisional service: client traffic to a well-known port
                if dport in COMMON_PORTS:
                    k = (dst, dport, "TCP")
                    if k not in services:
                        s_name = COMMON_PORTS.get(dport, f"TCP/{dport}")
                        services[k] = ServiceAsset(dst, dport, "TCP", s_name, first_seen=ts, last_seen=ts)
                    s = services[k]
                    s.clients.add(src)
                    s.packets += 1
                    s.bytes += pkt_len
                    s.last_seen = ts
                
                # Check payloads for banners (from src)
                if Raw in pkt:
                    payload = bytes(pkt[Raw])
                    if payload:
                        guessed_service, banner = _guess_service(payload, sport)
                        if not guessed_service:
                            continue
                        if sport in COMMON_PORTS or sport <= 1024:
                            s_name = COMMON_PORTS.get(sport, guessed_service or f"TCP/{sport}")
                            k = (src, sport, "TCP")
                        elif dport in COMMON_PORTS:
                            s_name = COMMON_PORTS.get(dport, guessed_service or f"TCP/{dport}")
                            k = (dst, dport, "TCP")
                        else:
                            continue

                        if k not in services:
                            services[k] = ServiceAsset(k[0], k[1], "TCP", s_name, first_seen=ts, last_seen=ts)
                        s = services[k]
                        if guessed_service and s.service_name.startswith("TCP/"):
                            s.service_name = guessed_service
                        s.packets += 1
                        s.bytes += pkt_len
                        s.last_seen = ts
                        if k[0] == src:
                            s.clients.add(dst)
                        else:
                            s.clients.add(src)

                        if banner and not s.software:
                            s.software = banner
            
            # UDP
            elif UDP in pkt:
                udp = pkt[UDP]
                sport = udp.sport
                dport = udp.dport
                
                # UDP is stateless. Logic: Traffic FROM a well known port (DNS, NTP) is a service
                if sport in COMMON_PORTS:
                    k = (src, sport, "UDP")
                    if k not in services:
                        s_name = COMMON_PORTS.get(sport, f"UDP/{sport}")
                        services[k] = ServiceAsset(src, sport, "UDP", s_name, first_seen=ts, last_seen=ts)
                    
                    s = services[k]
                    s.clients.add(dst)
                    s.packets += 1
                    s.bytes += pkt_len
                    s.last_seen = ts
                    
                    # DNS Answer?
                    if sport == 53 and DNS in pkt and pkt[DNS].qr == 1:
                        # It's a DNS Server
                        pass
                elif dport in COMMON_PORTS:
                    # Provisional UDP service (one-way client -> server)
                    k = (dst, dport, "UDP")
                    if k not in services:
                        s_name = COMMON_PORTS.get(dport, f"UDP/{dport}")
                        services[k] = ServiceAsset(dst, dport, "UDP", s_name, first_seen=ts, last_seen=ts)
                    s = services[k]
                    s.clients.add(src)
                    s.packets += 1
                    s.bytes += pkt_len
                    s.last_seen = ts

    except Exception as e:
        errors.append(str(e))
    finally:
        status.finish()
        reader.close()

    # Risk Assessment
    def _is_public_ip(value: str) -> bool:
        try:
            ip_addr = ipaddress.ip_address(value)
        except ValueError:
            return False
        return ip_addr.is_global

    risky_cleartext = {
        "Telnet": "HIGH",
        "FTP": "HIGH",
        "TFTP": "HIGH",
        "HTTP": "MEDIUM",
        "POP3": "MEDIUM",
        "IMAP": "MEDIUM",
        "LDAP": "MEDIUM",
        "SNMP": "MEDIUM",
        "VNC": "MEDIUM",
    }
    admin_services = {"SSH", "RDP", "SMB", "VNC", "Telnet", "WinRM"}
    udp_amplifiers = {"DNS", "NTP", "SNMP"}
    for k, asset in services.items():
        # Cleartext protocols
        if asset.service_name in risky_cleartext:
            cleartext_hits[(asset.ip, asset.service_name)].add(asset.port)
        
        # Old versions (Simple check)
        if asset.software:
            sw = asset.software.lower()
            if "apache/1." in sw or "php/4." in sw:
                risks.append(ServiceRisk(
                    "CRITICAL", "Obsolete Software", 
                    f"Legacy software detected: {asset.software}", 
                    f"{asset.ip}:{asset.port}"
                ))
                
        nonstandard_ports = {
            "HTTP": {80, 8080, 8000, 8443},
            "HTTPS": {443, 8443},
            "SSH": {22, 2222},
            "RDP": {3389},
            "SMB": {445, 139},
            "FTP": {21},
            "SMTP": {25},
        }
        for svc, ports in nonstandard_ports.items():
            if svc in asset.service_name and asset.port not in ports:
                nonstandard_hits[(asset.ip, svc)].add(asset.port)

        if _is_public_ip(asset.ip) and any(svc in asset.service_name for svc in admin_services):
            risks.append(ServiceRisk(
                "HIGH",
                "Public Admin Service",
                f"Administrative service {asset.service_name} exposed on a public IP.",
                f"{asset.ip}:{asset.port}",
            ))

        if asset.protocol == "UDP" and _is_public_ip(asset.ip) and asset.service_name in udp_amplifiers:
            risks.append(ServiceRisk(
                "MEDIUM",
                "Potential UDP Amplification",
                f"Public {asset.service_name} over UDP can be abused for amplification if open.",
                f"{asset.ip}:{asset.port}",
            ))

    for (ip_value, svc), ports in cleartext_hits.items():
        port_list = ", ".join(str(port) for port in sorted(ports))
        details = f"Unencrypted {svc} service detected. Credentials/Data at risk."
        if port_list:
            details = f"{details} Ports: {port_list}."
        risks.append(ServiceRisk(
            risky_cleartext.get(svc, "MEDIUM"),
            "Cleartext Service",
            details,
            f"{ip_value}:{sorted(ports)[0]}",
        ))

    for (ip_value, svc), ports in nonstandard_hits.items():
        port_list = ", ".join(str(port) for port in sorted(ports))
        details = f"{svc} detected on non-standard ports: {port_list}."
        risks.append(ServiceRisk(
            "LOW",
            "Non-Standard Port",
            details,
            f"{ip_value}:{sorted(ports)[0]}",
        ))

    # Hierarchy
    hier = Counter()
    for s in services.values():
        hier[s.service_name] += 1

    return ServiceSummary(
        path=path,
        total_services=len(services),
        assets=sorted(list(services.values()), key=lambda x: x.ip),
        risks=risks,
        hierarchy=dict(hier),
        errors=errors
    )
