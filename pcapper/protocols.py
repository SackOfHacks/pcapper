from __future__ import annotations

from collections import defaultdict, Counter
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.dns import DNS
    from scapy.packet import Raw, Packet
    from scapy.utils import PcapReader, PcapNgReader
except ImportError:
    IP = TCP = UDP = Ether = IPv6 = ARP = ICMP = DNS = Raw = None

from .pcap_cache import get_reader
from .utils import detect_file_type, safe_float
# from .services import get_service_name - Removed

# --- Dataclasses ---

@dataclass
class ProtocolStat:
    name: str
    packets: int = 0
    bytes: int = 0
    sub_protocols: Dict[str, 'ProtocolStat'] = field(default_factory=dict)
    
@dataclass
class Conversation:
    src: str
    dst: str
    protocol: str
    packets: int
    bytes: int
    start_ts: float
    end_ts: float
    ports: Set[int]

@dataclass
class Endpoint:
    address: str
    packets_sent: int = 0
    packets_recv: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    protocols: Set[str] = field(default_factory=set)

@dataclass
class Anomaly:
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    type: str
    description: str
    packet_index: int
    src: Optional[str] = None
    dst: Optional[str] = None

@dataclass
class ProtocolSummary:
    path: Path
    total_packets: int
    duration: float
    hierarchy: ProtocolStat
    conversations: List[Conversation]
    endpoints: List[Endpoint]
    anomalies: List[Anomaly]
    top_protocols: List[Tuple[str, int]]
    port_protocols: List[Tuple[str, int]]
    ethertype_protocols: List[Tuple[str, int]]
    errors: List[str]

# --- Analysis ---

INDUSTRIAL_PORTS = {
    102: "S7/MMS/ICCP",
    502: "Modbus/TCP",
    9600: "FINS",
    20000: "DNP3",
    2404: "IEC-104",
    47808: "BACnet/IP",
    44818: "EtherNet/IP",
    2222: "ENIP-IO",
    34962: "PROFINET",
    34963: "PROFINET",
    34964: "PROFINET",
    4840: "OPC UA",
    1911: "Niagara Fox",
    4911: "Niagara Fox",
    5094: "HART-IP",
    18245: "GE SRTP",
    18246: "GE SRTP",
    20547: "ProConOS",
    1962: "PCWorx",
    5006: "MELSEC",
    5007: "MELSEC",
    5683: "CoAP",
    5684: "CoAP",
    2455: "ODESYS",
    1217: "ODESYS",
    34378: "Yokogawa Vnet/IP",
    34379: "Yokogawa Vnet/IP",
    34380: "Yokogawa Vnet/IP",
}

ETHERTYPE_PROTOCOLS = {
    0x88A4: "EtherCAT",
    0x8892: "PROFINET RT",
    0x88B8: "IEC 61850 GOOSE",
    0x88BA: "IEC 61850 SV",
    0x88F7: "HSR/PRP",
}

KNOWN_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    88: "Kerberos", 110: "POP3", 123: "NTP", 135: "RPC",
    137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 162: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 514: "Syslog", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
    5353: "mDNS",
}
KNOWN_PORTS.update(INDUSTRIAL_PORTS)

OSCILLATION_REPEAT_CAP = 3

def _get_proto_name(pkt: Packet) -> str:
    # Heuristic based on layers
    if IP in pkt:
        proto_num = pkt[IP].proto
        if proto_num == 6 and TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            return KNOWN_PORTS.get(sport) or KNOWN_PORTS.get(dport) or "TCP"
        elif proto_num == 17 and UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            return KNOWN_PORTS.get(sport) or KNOWN_PORTS.get(dport) or "UDP"
        elif proto_num == 1:
            return "ICMP"
        return "IP"
    elif IPv6 in pkt:
        return "IPv6"
    elif ARP in pkt:
        return "ARP"
    
    # Fallback to layer name
    try:
        # Try to find the highest layer
        layer = pkt
        while layer.payload and layer.payload.name != "NoPayload":
            layer = layer.payload
        return layer.name
    except:
        return "Unknown"

def analyze_protocols(path: Path, show_status: bool = True) -> ProtocolSummary:
    if IP is None:
         return ProtocolSummary(path, 0, 0, ProtocolStat("Root"), [], [], [], [], [], [], ["Scapy not available"])

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path, show_status=show_status
        )
    except Exception as e:
        return ProtocolSummary(path, 0, 0, ProtocolStat("Root"), [], [], [], [], [], [], [f"Error opening pcap: {e}"])
    size_bytes = size_bytes

    # Stats containers
    hierarchy = ProtocolStat("Root")
    convs: Dict[Tuple[str, str, str], Conversation] = {}
    eps: Dict[str, Endpoint] = defaultdict(lambda: Endpoint("", 0, 0, 0, 0, set()))
    anomalies: List[Anomaly] = []
    broadcast_frames = 0
    arp_ip_macs: Dict[str, Set[str]] = defaultdict(set)
    gratuitous_arp = 0
    tcp_syn_sources: Counter[str] = Counter()
    tcp_syn_ports: Dict[str, Set[int]] = defaultdict(set)
    tcp_rst_sources: Counter[str] = Counter()
    tcp_null_scan: Counter[str] = Counter()
    tcp_fin_scan: Counter[str] = Counter()
    tcp_xmas_scan: Counter[str] = Counter()
    ip_fragments = 0
    icmp_large_payloads: List[Tuple[str, str, int]] = []
    
    start_ts = None
    end_ts = None
    pkt_idx = 0
    port_protocol_counts: Counter[str] = Counter()
    ethertype_protocol_counts: Counter[str] = Counter()
    
    errors = []

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            pkt_idx += 1
            ts = safe_float(getattr(pkt, "time", 0))
            if start_ts is None: start_ts = ts
            end_ts = ts
            
            pkt_len = len(pkt)
            port_protocol_counts[_get_proto_name(pkt)] += 1
            if Ether in pkt:
                try:
                    ethertype = int(pkt[Ether].type)
                except Exception:
                    ethertype = None
                if ethertype is not None:
                    label = ETHERTYPE_PROTOCOLS.get(ethertype)
                    if label:
                        ethertype_protocol_counts[label] += 1
            
            # 1. Hierarchy Update
            # Traverse layers while avoiding double-counting VLAN-tagged traffic.
            current_node = hierarchy
            current_node.packets += 1
            current_node.bytes += pkt_len

            layer = pkt
            prev_effective_layer: str | None = None
            effective_path_layers: List[str] = []
            oscillation_repeats = 0
            visited_layer_ids: Set[int] = set()
            depth = 0
            while layer:
                depth += 1
                if depth > 256:
                    break
                layer_id = id(layer)
                if layer_id in visited_layer_ids:
                    break
                visited_layer_ids.add(layer_id)
                try:
                    lname = layer.name
                    if not lname:  # Fallback
                        lname = layer.__class__.__name__
                except Exception:
                    lname = "Unknown"

                if lname not in {"NoPayload", "Raw", "Padding"}:
                    if lname in {"802.1Q", "Dot1Q"}:
                        # Count VLAN tags, but do not make them the parent of L3/L4.
                        vlan_parent = current_node
                        if vlan_parent.name != "Ethernet":
                            vlan_parent = hierarchy.sub_protocols.get("Ethernet", vlan_parent)
                        if lname not in vlan_parent.sub_protocols:
                            vlan_parent.sub_protocols[lname] = ProtocolStat(lname)
                        vlan_node = vlan_parent.sub_protocols[lname]
                        vlan_node.packets += 1
                        vlan_node.bytes += pkt_len
                    else:
                        if lname == prev_effective_layer:
                            layer = layer.payload
                            continue
                        if (
                            len(effective_path_layers) >= 3
                            and effective_path_layers[-3] == effective_path_layers[-1]
                            and effective_path_layers[-2] == lname
                            and effective_path_layers[-3] != effective_path_layers[-2]
                        ):
                            oscillation_repeats += 1
                            if oscillation_repeats >= OSCILLATION_REPEAT_CAP:
                                break
                        else:
                            oscillation_repeats = 0
                        if lname not in current_node.sub_protocols:
                            current_node.sub_protocols[lname] = ProtocolStat(lname)
                        current_node = current_node.sub_protocols[lname]
                        current_node.packets += 1
                        current_node.bytes += pkt_len
                        prev_effective_layer = lname
                        effective_path_layers.append(lname)
                layer = layer.payload

            # 2. Extract Endpoints & Conversations
            src = None
            dst = None
            proto = "Ethernet"
            ports = set()
            
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = "IP"
                if TCP in pkt:
                    proto = KNOWN_PORTS.get(pkt[TCP].sport) or KNOWN_PORTS.get(pkt[TCP].dport) or "TCP"
                    ports.add(pkt[TCP].sport)
                    ports.add(pkt[TCP].dport)
                elif UDP in pkt:
                    proto = KNOWN_PORTS.get(pkt[UDP].sport) or KNOWN_PORTS.get(pkt[UDP].dport) or "UDP"
                    ports.add(pkt[UDP].sport)
                    ports.add(pkt[UDP].dport)
                elif ICMP in pkt:
                    proto = "ICMP"
            elif IPv6 in pkt:
                src = pkt[IPv6].src
                dst = pkt[IPv6].dst
                proto = "IPv6"
            elif ARP in pkt:
                src = pkt[ARP].psrc
                dst = pkt[ARP].pdst
                proto = "ARP"
                try:
                    hwsrc = str(pkt[ARP].hwsrc)
                    psrc = str(pkt[ARP].psrc)
                    if psrc and hwsrc:
                        arp_ip_macs[psrc].add(hwsrc)
                    op = getattr(pkt[ARP], "op", None)
                    if op == 2 and psrc == dst:
                        gratuitous_arp += 1
                except Exception:
                    pass
            elif Ether in pkt:
                # Fallback L2
                src = pkt[Ether].src
                dst = pkt[Ether].dst

            if Ether in pkt:
                try:
                    eth_dst = str(pkt[Ether].dst).lower()
                    if eth_dst == "ff:ff:ff:ff:ff:ff":
                        broadcast_frames += 1
                except Exception:
                    pass
            
            if src and dst:
                # Endpoints
                e_src = eps[src]
                e_src.address = src
                e_src.packets_sent += 1
                e_src.bytes_sent += pkt_len
                e_src.protocols.add(proto)
                
                e_dst = eps[dst]
                e_dst.address = dst
                e_dst.packets_recv += 1
                e_dst.bytes_recv += pkt_len
                e_dst.protocols.add(proto)
                
                # Conversations (Order insensitive Key)
                key = tuple(sorted([src, dst])) + (proto,)
                if key not in convs:
                    convs[key] = Conversation(
                        src=src, dst=dst, protocol=proto, packets=0, bytes=0,
                        start_ts=ts, end_ts=ts, ports=set()
                    )
                c = convs[key]
                c.packets += 1
                c.bytes += pkt_len
                c.end_ts = ts
                c.ports.update(ports)

            # 3. Anomaly Detection (Basic)
            if IP in pkt:
                try:
                    ip_layer = pkt[IP]
                    if getattr(ip_layer, "frag", 0) or getattr(ip_layer, "flags", 0):
                        if getattr(ip_layer, "frag", 0) > 0 or str(getattr(ip_layer, "flags", "")).lower().find("mf") >= 0:
                            ip_fragments += 1
                except Exception:
                    pass

            # Cleartext Credentials
            if TCP in pkt and Raw in pkt:
                payload = bytes(pkt[Raw])
                # FTP/Telnet/HTTP Basic Auth check (very basic)
                if (pkt[TCP].dport == 21 or pkt[TCP].sport == 21) or \
                   (pkt[TCP].dport == 23 or pkt[TCP].sport == 23):
                     if b"USER" in payload or b"PASS" in payload:
                         anomalies.append(Anomaly("HIGH", "Cleartext Creds", f"Potential {proto} cleartext credentials", pkt_idx, src, dst))
                
                if b"Authorization: Basic" in payload:
                     anomalies.append(Anomaly("MEDIUM", "Basic Auth", "HTTP Basic Auth used (Base64 cleartext)", pkt_idx, src, dst))

                try:
                    text = payload.decode("utf-8", errors="ignore")
                except Exception:
                    text = ""

                if text:
                    # HTTP query/body credentials
                    cred_patterns = [
                        r"(?i)(password|passwd|pwd|pass)=([^&\s]{3,})",
                        r"(?i)(username|user|login|email)=([^&\s]{3,})",
                        r"(?i)(api[_-]?key|token|session)=([^&\s]{8,})",
                    ]
                    for pattern in cred_patterns:
                        match = re.search(pattern, text)
                        if match:
                            key = match.group(1)
                            anomalies.append(Anomaly("MEDIUM", "Credential Leakage", f"Potential {key} disclosure in cleartext payload", pkt_idx, src, dst))
                            break

                    # SMTP/IMAP/POP3 auth indicators
                    if re.search(r"(?i)AUTH\s+LOGIN", text) or re.search(r"(?i)AUTH\s+PLAIN", text):
                        anomalies.append(Anomaly("MEDIUM", "Cleartext Auth", "SMTP/IMAP auth sequence observed", pkt_idx, src, dst))

                    # FTP explicit USER/PASS lines
                    if re.search(r"(?i)^USER\s+\S+", text) and re.search(r"(?i)^PASS\s+\S+", text):
                        anomalies.append(Anomaly("HIGH", "Cleartext Creds", "FTP USER/PASS observed", pkt_idx, src, dst))

            if TCP in pkt:
                try:
                    flags = pkt[TCP].flags
                except Exception:
                    flags = None

                syn = ack = fin = rst = psh = urg = False
                if isinstance(flags, str):
                    syn = "S" in flags
                    ack = "A" in flags
                    fin = "F" in flags
                    rst = "R" in flags
                    psh = "P" in flags
                    urg = "U" in flags
                elif isinstance(flags, int):
                    syn = bool(flags & 0x02)
                    ack = bool(flags & 0x10)
                    fin = bool(flags & 0x01)
                    rst = bool(flags & 0x04)
                    psh = bool(flags & 0x08)
                    urg = bool(flags & 0x20)

                if syn and not ack and src:
                    tcp_syn_sources[src] += 1
                    try:
                        tcp_syn_ports[src].add(int(pkt[TCP].dport))
                    except Exception:
                        pass

                if rst and src:
                    tcp_rst_sources[src] += 1

                if flags == 0 and src:
                    tcp_null_scan[src] += 1

                if fin and not (syn or ack or rst) and src:
                    tcp_fin_scan[src] += 1

                if fin and psh and urg and src:
                    tcp_xmas_scan[src] += 1

            if ICMP in pkt and Raw in pkt:
                payload = bytes(pkt[Raw])
                if len(payload) >= 512:
                    icmp_large_payloads.append((src or "-", dst or "-", len(payload)))

            # Non-Standard Ports for known protocols? 
            # (Hard without deep inspection, skipping for now to keep it safe)
            
            # Syn Scan? (Lots of SYNs from one source) - post process

    except Exception as e:
        errors.append(str(e))
    finally:
        status.finish()
        reader.close()

    duration = (end_ts - start_ts) if (start_ts and end_ts) else 0.0

    # Post-process anomalies
    for ip_addr, macs in arp_ip_macs.items():
        if len(macs) >= 2:
            anomalies.append(Anomaly(
                "HIGH",
                "ARP Spoofing",
                f"Multiple MACs for {ip_addr}: {', '.join(sorted(macs))}",
                0,
                ip_addr,
                None,
            ))

    if gratuitous_arp > 50:
        anomalies.append(Anomaly(
            "MEDIUM",
            "Gratuitous ARP",
            f"High gratuitous ARP volume: {gratuitous_arp} packets",
            0,
        ))

    if pkt_idx and broadcast_frames / pkt_idx > 0.3:
        anomalies.append(Anomaly(
            "MEDIUM",
            "Broadcast Storm",
            f"Broadcast frames are {broadcast_frames}/{pkt_idx} packets.",
            0,
        ))

    # TCP scan heuristics
    for ip, count in tcp_syn_sources.items():
        unique_ports = len(tcp_syn_ports.get(ip, set()))
        if count > 200 or unique_ports > 100:
            anomalies.append(Anomaly(
                "MEDIUM",
                "Port Scan",
                f"Potential SYN scan activity ({count} SYNs, {unique_ports} ports) from {ip}",
                0,
                ip,
                None,
            ))

    for ip, count in tcp_null_scan.items():
        if count >= 10:
            anomalies.append(Anomaly(
                "MEDIUM",
                "TCP Null Scan",
                f"Null scan pattern observed ({count} packets) from {ip}",
                0,
                ip,
                None,
            ))

    for ip, count in tcp_fin_scan.items():
        if count >= 10:
            anomalies.append(Anomaly(
                "MEDIUM",
                "TCP FIN Scan",
                f"FIN scan pattern observed ({count} packets) from {ip}",
                0,
                ip,
                None,
            ))

    for ip, count in tcp_xmas_scan.items():
        if count >= 10:
            anomalies.append(Anomaly(
                "MEDIUM",
                "TCP Xmas Scan",
                f"Xmas scan pattern observed ({count} packets) from {ip}",
                0,
                ip,
                None,
            ))

    for ip, count in tcp_rst_sources.items():
        if count > 500:
            anomalies.append(Anomaly(
                "LOW",
                "TCP Reset Flood",
                f"High TCP RST volume ({count} packets) from {ip}",
                0,
                ip,
                None,
            ))

    if ip_fragments > 50:
        anomalies.append(Anomaly(
            "MEDIUM",
            "IP Fragmentation",
            f"Elevated IP fragmentation observed ({ip_fragments} fragments)",
            0,
        ))

    if len(icmp_large_payloads) > 10:
        src, dst, size = max(icmp_large_payloads, key=lambda item: item[2])
        anomalies.append(Anomaly(
            "MEDIUM",
            "Large ICMP Payloads",
            f"Large ICMP payloads observed ({len(icmp_large_payloads)} packets, max {size} bytes)",
            0,
            src,
            dst,
        ))

    # Calculate Top Protocols
    # Flatten hierarchy counts? Or just use root children?
    # Let's use layer occurrences
    layer_counts = Counter()
    def traverse(node):
        layer_counts[node.name] += node.packets
        for child in node.sub_protocols.values():
            traverse(child)
    traverse(hierarchy)
    # Remove Root
    del layer_counts["Root"]
    
    return ProtocolSummary(
        path=path,
        total_packets=pkt_idx,
        duration=duration,
        hierarchy=hierarchy,
        conversations=list(convs.values()),
        endpoints=list(eps.values()),
        anomalies=anomalies,
        top_protocols=layer_counts.most_common(10),
        port_protocols=port_protocol_counts.most_common(12),
        ethertype_protocols=ethertype_protocol_counts.most_common(12),
        errors=errors
    )
