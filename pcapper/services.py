from __future__ import annotations

from collections import defaultdict, Counter
from dataclasses import dataclass, field
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

from .progress import build_statusbar
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

# --- Constants ---

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 
    53: "DNS", 69: "TFTP", 80: "HTTP", 88: "Kerberos",
    110: "POP3", 123: "NTP", 135: "RPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 
    445: "SMB", 514: "Syslog", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP", 
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt", 
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB"
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

    ftype = detect_file_type(path)
    try:
        reader = PcapNgReader(str(path)) if ftype == "pcapng" else PcapReader(str(path))
    except Exception as e:
        return ServiceSummary(path, 0, [], [], {}, [f"Error: {e}"])

    size_bytes = 0
    try:
        size_bytes = path.stat().st_size
    except Exception:
        pass
        
    status = build_statusbar(path, enabled=show_status)
    stream = None
    for attr in ("fd", "f", "fh", "_fh", "_file", "file"):
        candidate = getattr(reader, attr, None)
        if candidate is not None:
            stream = candidate
            break

    # Map: (IP, Port, Proto) -> ServiceAsset
    services: Dict[Tuple[str, int, str], ServiceAsset] = {}
    risks: List[ServiceRisk] = []
    errors: List[str] = []
    
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
                
                # Check payloads for banners (from src)
                if Raw in pkt:
                    payload = bytes(pkt[Raw])
                    if payload:
                        guessed_service, banner = _guess_service(payload, sport)
                        is_known_port = sport in COMMON_PORTS and sport < 10000
                        if is_known_port or guessed_service:
                            s_name = COMMON_PORTS.get(sport, guessed_service or f"TCP/{sport}")
                            k = (src, sport, "TCP")
                            if k not in services:
                                services[k] = ServiceAsset(src, sport, "TCP", s_name, first_seen=ts, last_seen=ts)

                            s = services[k]
                            if guessed_service and s.service_name.startswith("TCP/"):
                                s.service_name = guessed_service
                            s.packets += 1
                            s.bytes += pkt_len
                            s.last_seen = ts
                            s.clients.add(dst)

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

    except Exception as e:
        errors.append(str(e))
    finally:
        status.finish()
        reader.close()

    # Risk Assessment
    for k, asset in services.items():
        # Cleartext protocols
        if asset.service_name in ("FTP", "Telnet", "HTTP"):
            risks.append(ServiceRisk(
                "HIGH", "Cleartext Service", 
                f"Unencrypted {asset.service_name} service detected. Credentials/Data at risk.",
                f"{asset.ip}:{asset.port}"
            ))
        
        # Old versions (Simple check)
        if asset.software:
            sw = asset.software.lower()
            if "apache/1." in sw or "php/4." in sw:
                risks.append(ServiceRisk(
                    "CRITICAL", "Obsolete Software", 
                    f"Legacy software detected: {asset.software}", 
                    f"{asset.ip}:{asset.port}"
                ))
                
        # Non-standard ports
        if asset.port == 2222 and "SSH" in asset.service_name:
             risks.append(ServiceRisk("LOW", "Non-Standard SSH", "SSH on port 2222", f"{asset.ip}:{asset.port}"))

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
                risks.append(ServiceRisk(
                    "LOW",
                    "Non-Standard Port",
                    f"{svc} detected on non-standard port {asset.port}.",
                    f"{asset.ip}:{asset.port}",
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
