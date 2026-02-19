from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import ipaddress

from .pcap_cache import get_reader
from .utils import safe_float

try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.layers.l2 import Ether, LLC  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    ICMP = None  # type: ignore
    IPv6 = None  # type: ignore
    Ether = None  # type: ignore
    LLC = None  # type: ignore
    Raw = None  # type: ignore


ROUTING_PORTS = {
    179: "BGP",
    520: "RIP",
    521: "RIPng",
    1985: "HSRP",
    3222: "GLBP",
}

ROUTING_IP_PROTOS = {
    89: "OSPF",
    88: "EIGRP",
    112: "VRRP",
    103: "PIM",
    2: "IGMP",
    124: "IS-IS",
}

OSPF_TYPES = {
    1: "Hello",
    2: "DBDesc",
    3: "LSReq",
    4: "LSUpd",
    5: "LSAck",
}

BGP_TYPES = {
    1: "OPEN",
    2: "UPDATE",
    3: "NOTIFICATION",
    4: "KEEPALIVE",
}

BGP_ORIGIN = {
    0: "IGP",
    1: "EGP",
    2: "INCOMPLETE",
}

BGP_PATH_ATTR = {
    1: "ORIGIN",
    2: "AS_PATH",
    3: "NEXT_HOP",
    4: "MULTI_EXIT_DISC",
    5: "LOCAL_PREF",
    6: "ATOMIC_AGGREGATE",
    7: "AGGREGATOR",
    8: "COMMUNITY",
    9: "ORIGINATOR_ID",
    10: "CLUSTER_LIST",
    14: "MP_REACH_NLRI",
    15: "MP_UNREACH_NLRI",
}
RIP_COMMANDS = {
    1: "Request",
    2: "Response",
    3: "TraceOn",
    4: "TraceOff",
    5: "Poll",
    6: "PollEntry",
}

OSPF_LSA_TYPES = {
    1: "Router",
    2: "Network",
    3: "Summary-IP",
    4: "Summary-ASBR",
    5: "AS-External",
    6: "Group-Membership",
    7: "NSSA-External",
    8: "External-Attributes",
    9: "Opaque-Link",
    10: "Opaque-Area",
    11: "Opaque-AS",
}

ISIS_PDU_TYPES = {
    15: "L1 LSP",
    16: "L2 LSP",
    17: "L1 CSNP",
    18: "L2 CSNP",
    19: "L1 PSNP",
    20: "L2 PSNP",
    24: "L1 IIH",
    25: "L2 IIH",
    26: "P2P IIH",
}

ISIS_TLV_NAMES = {
    1: "Area Addresses",
    6: "IS Neighbors (LAN)",
    8: "LSP Entries",
    9: "Authentication (old)",
    10: "Authentication",
    22: "Extended IS Reachability",
    128: "IP Internal Reachability",
    130: "IP External Reachability",
    132: "IP Interface Address",
    135: "Extended IP Reachability",
    137: "Dynamic Hostname",
    232: "IPv6 Interface Address",
    236: "IPv6 Reachability",
    242: "Router Capabilities",
}

PIM_TYPES = {
    0: "Hello",
    1: "Register",
    2: "Register-Stop",
    3: "Join/Prune",
    4: "Bootstrap",
    5: "Assert",
    6: "Graft",
    7: "Graft-Ack",
    8: "Candidate-RP-Advertisement",
}

PIM_OPT_TYPES = {
    1: "Holdtime",
    2: "LAN Prune Delay",
    19: "DR Priority",
    24: "Generation ID",
    28: "State Refresh Capable",
}

@dataclass(frozen=True)
class RoutingArtifact:
    kind: str
    detail: str
    src: str | None = None
    dst: str | None = None


@dataclass(frozen=True)
class RoutingSession:
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    packets: int
    first_seen: Optional[float]
    last_seen: Optional[float]
    details: str | None = None


@dataclass(frozen=True)
class RoutingSummary:
    path: Path
    total_packets: int
    routing_packets: int
    protocol_counts: Counter[str]
    message_counts: Counter[str]
    endpoint_counts: Counter[str]
    router_id_counts: Counter[str]
    lsa_type_counts: Counter[str]
    lsa_adv_router_counts: Counter[str]
    lsa_id_counts: Counter[str]
    lsa_maxage_count: int
    lsa_seq_high_count: int
    asn_counts: Counter[str]
    bgp_prefix_counts: Counter[str]
    bgp_withdraw_counts: Counter[str]
    bgp_next_hop_counts: Counter[str]
    bgp_path_attr_counts: Counter[str]
    bgp_as_path_counts: Counter[str]
    isis_system_id_counts: Counter[str]
    isis_area_counts: Counter[str]
    isis_hostname_counts: Counter[str]
    isis_neighbor_counts: Counter[str]
    isis_reachability_counts: Counter[str]
    isis_tlv_counts: Counter[str]
    isis_lsp_id_counts: Counter[str]
    isis_lsp_seq_high_count: int
    pim_type_counts: Counter[str]
    pim_group_counts: Counter[str]
    pim_source_counts: Counter[str]
    pim_options_counts: Counter[str]
    pim_dr_priority_counts: Counter[str]
    auth_counts: Counter[str]
    vrid_counts: Counter[str]
    hsrp_group_counts: Counter[str]
    sessions: list[RoutingSession]
    detections: list[dict[str, object]]
    insights: list[str]
    artifacts: list[RoutingArtifact]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


def _ip_text(raw: bytes) -> str:
    try:
        return str(ipaddress.IPv4Address(raw))
    except Exception:
        return "0.0.0.0"


def _parse_ospf(payload: bytes) -> dict[str, object]:
    if len(payload) < 16:
        return {}
    version = payload[0]
    msg_type = payload[1]
    length = int.from_bytes(payload[2:4], "big") if len(payload) >= 4 else None
    router_id = _ip_text(payload[4:8]) if len(payload) >= 8 else None
    area_id = _ip_text(payload[8:12]) if len(payload) >= 12 else None
    auth_type = int.from_bytes(payload[14:16], "big") if len(payload) >= 16 else None
    auth_data = payload[16:24] if len(payload) >= 24 else b""
    lsa_count = None
    if msg_type == 4 and len(payload) >= 28:
        lsa_count = int.from_bytes(payload[24:28], "big")
    return {
        "version": version,
        "type": msg_type,
        "length": length,
        "router_id": router_id,
        "area_id": area_id,
        "auth_type": auth_type,
        "auth_data": auth_data,
        "lsa_count": lsa_count,
    }


def _parse_ospf_lsas(payload: bytes) -> list[dict[str, object]]:
    if len(payload) < 28:
        return []
    lsa_count = int.from_bytes(payload[24:28], "big")
    lsas: list[dict[str, object]] = []
    offset = 28
    max_lsas = min(lsa_count, 4096)
    for _ in range(max_lsas):
        if offset + 20 > len(payload):
            break
        age = int.from_bytes(payload[offset:offset + 2], "big")
        options = payload[offset + 2]
        lsa_type = payload[offset + 3]
        ls_id_raw = payload[offset + 4:offset + 8]
        adv_raw = payload[offset + 8:offset + 12]
        seq = int.from_bytes(payload[offset + 12:offset + 16], "big")
        checksum = int.from_bytes(payload[offset + 16:offset + 18], "big")
        length = int.from_bytes(payload[offset + 18:offset + 20], "big")
        if length < 20 or offset + length > len(payload):
            break
        body = payload[offset + 20:offset + length]
        details: dict[str, object] = {}
        lsid_int = int.from_bytes(ls_id_raw, "big")

        if lsa_type == 1 and len(body) >= 4:
            flags = body[0]
            link_count = int.from_bytes(body[2:4], "big")
            details["flags"] = flags
            details["link_count"] = link_count
            links = []
            link_offset = 4
            for _link in range(min(link_count, 6)):
                if link_offset + 12 > len(body):
                    break
                link_id = _ip_text(body[link_offset:link_offset + 4])
                link_data = _ip_text(body[link_offset + 4:link_offset + 8])
                link_type = body[link_offset + 8]
                metric = int.from_bytes(body[link_offset + 10:link_offset + 12], "big")
                links.append({
                    "id": link_id,
                    "data": link_data,
                    "type": link_type,
                    "metric": metric,
                })
                link_offset += 12
            if links:
                details["links"] = links
        elif lsa_type == 2 and len(body) >= 4:
            netmask = _ip_text(body[0:4])
            routers: list[str] = []
            offset2 = 4
            while offset2 + 4 <= len(body) and len(routers) < 8:
                routers.append(_ip_text(body[offset2:offset2 + 4]))
                offset2 += 4
            details["netmask"] = netmask
            if routers:
                details["attached_routers"] = routers
        elif lsa_type in {3, 4} and len(body) >= 4:
            netmask = _ip_text(body[0:4])
            metric = int.from_bytes(body[4:7], "big") if len(body) >= 7 else None
            details["netmask"] = netmask
            if metric is not None:
                details["metric"] = metric
        elif lsa_type in {5, 7} and len(body) >= 16:
            netmask = _ip_text(body[0:4])
            metric_field = int.from_bytes(body[4:8], "big")
            ext_type = "E2" if (metric_field & 0x80000000) else "E1"
            metric = metric_field & 0x00FFFFFF
            forwarding = _ip_text(body[8:12])
            tag = int.from_bytes(body[12:16], "big")
            details["netmask"] = netmask
            details["metric"] = metric
            details["external_type"] = ext_type
            details["forwarding"] = forwarding
            details["tag"] = tag
        elif lsa_type in {9, 10, 11}:
            opaque_type = (lsid_int >> 24) & 0xFF
            opaque_id = lsid_int & 0x00FFFFFF
            details["opaque_type"] = opaque_type
            details["opaque_id"] = opaque_id

        lsas.append({
            "age": age,
            "options": options,
            "type": lsa_type,
            "ls_id": _ip_text(ls_id_raw),
            "adv_router": _ip_text(adv_raw),
            "seq": seq,
            "checksum": checksum,
            "length": length,
            "details": details,
        })
        offset += length
    return lsas


def _parse_eigrp(payload: bytes) -> dict[str, object]:
    if len(payload) < 20:
        return {}
    version = payload[0]
    opcode = payload[1]
    asn = int.from_bytes(payload[16:20], "big")
    return {"version": version, "opcode": opcode, "asn": asn}


def _parse_vrrp(payload: bytes) -> dict[str, object]:
    if len(payload) < 4:
        return {}
    first = payload[0]
    version = (first >> 4) & 0x0F
    msg_type = first & 0x0F
    vrid = payload[1]
    priority = payload[2]
    auth_type = payload[4] if len(payload) >= 5 else None
    advert_int = payload[5] if len(payload) >= 6 else None
    return {
        "version": version,
        "type": msg_type,
        "vrid": vrid,
        "priority": priority,
        "auth_type": auth_type,
        "advert_int": advert_int,
    }


def _parse_rip(payload: bytes) -> dict[str, object]:
    if len(payload) < 4:
        return {}
    cmd = payload[0]
    version = payload[1]
    auth_type = None
    auth_data = b""
    metric16 = False
    if version >= 2 and len(payload) >= 24:
        afi = int.from_bytes(payload[4:6], "big")
        if afi == 0xFFFF:
            auth_type = int.from_bytes(payload[6:8], "big")
            auth_data = payload[8:24]
    # Inspect first route entry metric if present (skip auth entry).
    entry_offset = 4
    if version >= 2 and len(payload) >= 24:
        afi = int.from_bytes(payload[4:6], "big")
        if afi == 0xFFFF:
            entry_offset = 24
    if len(payload) >= entry_offset + 20:
        metric = int.from_bytes(payload[entry_offset + 16:entry_offset + 20], "big")
        metric16 = (metric == 16)
    return {
        "cmd": cmd,
        "version": version,
        "auth_type": auth_type,
        "auth_data": auth_data,
        "metric16": metric16,
    }


def _parse_bgp_messages(payload: bytes) -> list[dict[str, object]]:
    messages: list[dict[str, object]] = []
    idx = 0
    marker = b"\xff" * 16
    while idx + 19 <= len(payload):
        if payload[idx:idx + 16] != marker:
            next_idx = payload.find(marker, idx + 1)
            if next_idx == -1:
                break
            idx = next_idx
            continue
        length = int.from_bytes(payload[idx + 16:idx + 18], "big")
        if length < 19 or idx + length > len(payload):
            break
        msg_type = payload[idx + 18]
        body = payload[idx + 19:idx + length]
        entry: dict[str, object] = {"type": msg_type}
        if msg_type == 1 and len(body) >= 10:
            entry.update({
                "version": body[0],
                "asn": int.from_bytes(body[1:3], "big"),
                "hold_time": int.from_bytes(body[3:5], "big"),
                "bgp_id": _ip_text(body[5:9]),
                "opt_len": body[9],
            })
        elif msg_type == 2:
            update = _parse_bgp_update(body)
            entry.update(update)
        elif msg_type == 3 and len(body) >= 2:
            entry.update({
                "error_code": body[0],
                "error_subcode": body[1],
            })
        messages.append(entry)
        idx += length
    return messages


def _parse_bgp_prefixes(prefix_bytes: bytes) -> list[str]:
    prefixes: list[str] = []
    idx = 0
    while idx < len(prefix_bytes):
        plen = prefix_bytes[idx]
        idx += 1
        octets = (plen + 7) // 8
        if idx + octets > len(prefix_bytes):
            break
        raw = prefix_bytes[idx:idx + octets]
        idx += octets
        if octets == 0:
            prefixes.append("0.0.0.0/0")
            continue
        if octets <= 4:
            padded = raw + b"\x00" * (4 - octets)
            prefixes.append(f"{_ip_text(padded)}/{plen}")
        else:
            try:
                padded = raw + b"\x00" * (16 - octets)
                prefixes.append(f"{ipaddress.IPv6Address(padded)}/{plen}")
            except Exception:
                continue
    return prefixes


def _parse_bgp_as_path(attr_bytes: bytes) -> list[str]:
    segments: list[str] = []
    idx = 0
    while idx + 2 <= len(attr_bytes):
        seg_type = attr_bytes[idx]
        seg_len = attr_bytes[idx + 1]
        idx += 2
        seg_asns = []
        for _ in range(seg_len):
            if idx + 2 > len(attr_bytes):
                break
            asn = int.from_bytes(attr_bytes[idx:idx + 2], "big")
            idx += 2
            seg_asns.append(str(asn))
        seg_label = "AS_SEQUENCE" if seg_type == 2 else "AS_SET" if seg_type == 1 else f"TYPE{seg_type}"
        if seg_asns:
            segments.append(f"{seg_label}({','.join(seg_asns)})")
    return segments


def _parse_bgp_update(body: bytes) -> dict[str, object]:
    if len(body) < 4:
        return {}
    idx = 0
    withdrawn_len = int.from_bytes(body[idx:idx + 2], "big")
    idx += 2
    withdrawn_bytes = body[idx:idx + withdrawn_len]
    idx += withdrawn_len
    if idx + 2 > len(body):
        return {"withdrawn": _parse_bgp_prefixes(withdrawn_bytes)}
    attr_len = int.from_bytes(body[idx:idx + 2], "big")
    idx += 2
    attr_bytes = body[idx:idx + attr_len]
    idx += attr_len
    nlri_bytes = body[idx:]

    withdrawn = _parse_bgp_prefixes(withdrawn_bytes)
    nlri = _parse_bgp_prefixes(nlri_bytes)

    attrs: list[dict[str, object]] = []
    attr_idx = 0
    next_hop = None
    origin = None
    as_path: list[str] = []
    communities: list[str] = []
    mp_reach: list[str] = []
    mp_unreach: list[str] = []
    while attr_idx + 2 <= len(attr_bytes):
        flags = attr_bytes[attr_idx]
        code = attr_bytes[attr_idx + 1]
        attr_idx += 2
        extended_len = bool(flags & 0x10)
        if extended_len:
            if attr_idx + 2 > len(attr_bytes):
                break
            length = int.from_bytes(attr_bytes[attr_idx:attr_idx + 2], "big")
            attr_idx += 2
        else:
            if attr_idx + 1 > len(attr_bytes):
                break
            length = attr_bytes[attr_idx]
            attr_idx += 1
        if attr_idx + length > len(attr_bytes):
            break
        value = attr_bytes[attr_idx:attr_idx + length]
        attr_idx += length
        name = BGP_PATH_ATTR.get(code, f"ATTR_{code}")
        attrs.append({"code": code, "name": name})
        if code == 1 and value:
            origin = BGP_ORIGIN.get(value[0], f"ORIGIN_{value[0]}")
        elif code == 2:
            as_path = _parse_bgp_as_path(value)
        elif code == 3 and len(value) >= 4:
            next_hop = _ip_text(value[:4])
        elif code == 8:
            for i in range(0, len(value), 4):
                if i + 4 > len(value):
                    break
                communities.append(f"{int.from_bytes(value[i:i+2],'big')}:{int.from_bytes(value[i+2:i+4],'big')}")
        elif code == 14 and len(value) >= 5:
            afi = int.from_bytes(value[0:2], "big")
            safi = value[2]
            nh_len = value[3]
            pos = 4
            if pos + nh_len <= len(value):
                nh_raw = value[pos:pos + nh_len]
                pos += nh_len
                try:
                    if afi == 1 and nh_len >= 4:
                        next_hop = _ip_text(nh_raw[:4])
                    elif afi == 2 and nh_len >= 16:
                        next_hop = str(ipaddress.IPv6Address(nh_raw[:16]))
                except Exception:
                    pass
            if pos < len(value):
                pos += 1  # skip SNPA
            mp_reach = _parse_bgp_prefixes(value[pos:])
        elif code == 15 and len(value) >= 3:
            pos = 3
            if pos < len(value):
                mp_unreach = _parse_bgp_prefixes(value[pos:])

    return {
        "withdrawn": withdrawn,
        "nlri": nlri,
        "attrs": attrs,
        "next_hop": next_hop,
        "origin": origin,
        "as_path": as_path,
        "communities": communities,
        "mp_reach": mp_reach,
        "mp_unreach": mp_unreach,
    }


def _isis_system_id(raw: bytes) -> str:
    if len(raw) < 6:
        return raw.hex()
    hexval = raw[:6].hex()
    return f"{hexval[0:4]}.{hexval[4:8]}.{hexval[8:12]}"


def _isis_lsp_id(raw: bytes) -> str:
    if len(raw) < 8:
        return raw.hex()
    sysid = _isis_system_id(raw[:6])
    return f"{sysid}.{raw[6]:02x}-{raw[7]:02x}"


def _parse_isis_tlvs(payload: bytes) -> dict[str, object]:
    idx = 0
    tlv_counts: Counter[str] = Counter()
    areas: list[str] = []
    hostnames: list[str] = []
    ipv4_addrs: list[str] = []
    ipv6_addrs: list[str] = []
    neighbors: list[str] = []
    auth_values: list[str] = []
    reachability: list[tuple[str, int]] = []
    router_caps: list[str] = []

    while idx + 2 <= len(payload):
        tlv_type = payload[idx]
        tlv_len = payload[idx + 1]
        idx += 2
        if idx + tlv_len > len(payload):
            break
        value = payload[idx:idx + tlv_len]
        idx += tlv_len
        tlv_name = ISIS_TLV_NAMES.get(tlv_type, f"TLV {tlv_type}")
        tlv_counts[tlv_name] += 1

        if tlv_type == 1:  # Area Addresses
            pos = 0
            while pos < len(value):
                alen = value[pos]
                pos += 1
                if pos + alen > len(value):
                    break
                area = value[pos:pos + alen].hex()
                areas.append(area)
                pos += alen
        elif tlv_type == 6:  # IS Neighbors (LAN)
            pos = 0
            while pos + 6 <= len(value):
                neighbors.append(_isis_system_id(value[pos:pos + 6]))
                pos += 6
        elif tlv_type == 10 or tlv_type == 9:  # Authentication
            if value:
                try:
                    text = value.decode("latin-1", errors="ignore").strip("\x00")
                except Exception:
                    text = ""
                if text and all(32 <= ord(ch) <= 126 for ch in text):
                    auth_values.append(text)
                else:
                    auth_values.append(value.hex())
        elif tlv_type == 132:  # IPv4 Interface Address
            pos = 0
            while pos + 4 <= len(value):
                ipv4_addrs.append(_ip_text(value[pos:pos + 4]))
                pos += 4
        elif tlv_type == 232:  # IPv6 Interface Address
            pos = 0
            while pos + 16 <= len(value):
                try:
                    ipv6_addrs.append(str(ipaddress.IPv6Address(value[pos:pos + 16])))
                except Exception:
                    pass
                pos += 16
        elif tlv_type == 137:  # Dynamic Hostname
            try:
                host = value.decode("utf-8", errors="ignore").strip()
                if host:
                    hostnames.append(host)
            except Exception:
                pass
        elif tlv_type == 135:  # Extended IP Reachability
            pos = 0
            while pos + 5 <= len(value):
                metric = int.from_bytes(value[pos:pos + 4], "big")
                plen = value[pos + 4]
                pos += 5
                octets = (plen + 7) // 8
                if pos + octets > len(value):
                    break
                prefix_raw = value[pos:pos + octets]
                pos += octets
                if octets <= 4:
                    prefix = _ip_text(prefix_raw + b"\x00" * (4 - octets))
                    reachability.append((f"{prefix}/{plen}", metric))
        elif tlv_type == 236:  # IPv6 Reachability
            pos = 0
            while pos + 6 <= len(value):
                metric = int.from_bytes(value[pos:pos + 4], "big")
                plen = value[pos + 4]
                pos += 6  # skip metric + plen + flags
                octets = (plen + 7) // 8
                if pos + octets > len(value):
                    break
                prefix_raw = value[pos:pos + octets]
                pos += octets
                try:
                    prefix = str(ipaddress.IPv6Address(prefix_raw + b"\x00" * (16 - octets)))
                    reachability.append((f"{prefix}/{plen}", metric))
                except Exception:
                    continue
        elif tlv_type == 242 and len(value) >= 4:  # Router Capabilities
            router_id = _ip_text(value[0:4])
            router_caps.append(router_id)

    return {
        "tlv_counts": tlv_counts,
        "areas": areas,
        "hostnames": hostnames,
        "ipv4_addrs": ipv4_addrs,
        "ipv6_addrs": ipv6_addrs,
        "neighbors": neighbors,
        "auth_values": auth_values,
        "reachability": reachability,
        "router_caps": router_caps,
    }


def _parse_isis_pdu(payload: bytes) -> dict[str, object]:
    if len(payload) < 8 or payload[0] != 0x83:
        return {}
    header_len = payload[1]
    pdu_type = payload[4]
    max_area = payload[7]
    details: dict[str, object] = {
        "pdu_type": pdu_type,
        "header_len": header_len,
        "max_area": max_area,
    }
    tlv_offset = header_len if header_len and header_len <= len(payload) else 8

    if pdu_type in {24, 25, 26} and len(payload) >= 20:
        details["circuit_type"] = payload[8]
        details["source_id"] = _isis_system_id(payload[9:15])
        details["hold_time"] = int.from_bytes(payload[15:17], "big")
        details["local_circuit_id"] = payload[19]
    elif pdu_type in {15, 16} and len(payload) >= 27:
        details["lsp_lifetime"] = int.from_bytes(payload[8:10], "big")
        details["lsp_id"] = _isis_lsp_id(payload[10:18])
        details["lsp_seq"] = int.from_bytes(payload[18:22], "big")
        details["lsp_checksum"] = int.from_bytes(payload[22:24], "big")
        details["lsp_flags"] = payload[24]
    elif pdu_type in {17, 18} and len(payload) >= 32:
        details["source_id"] = _isis_system_id(payload[10:16])
        details["start_lsp_id"] = _isis_lsp_id(payload[16:24])
        details["end_lsp_id"] = _isis_lsp_id(payload[24:32])
    elif pdu_type in {19, 20} and len(payload) >= 16:
        details["source_id"] = _isis_system_id(payload[10:16])

    if tlv_offset < len(payload):
        details["tlvs"] = _parse_isis_tlvs(payload[tlv_offset:])
    return details


def _parse_pim_hello_options(data: bytes) -> dict[str, object]:
    idx = 0
    opts: Counter[str] = Counter()
    holdtime = None
    dr_priority = None
    gen_id = None
    while idx + 4 <= len(data):
        opt_type = int.from_bytes(data[idx:idx + 2], "big")
        opt_len = int.from_bytes(data[idx + 2:idx + 4], "big")
        idx += 4
        if idx + opt_len > len(data):
            break
        value = data[idx:idx + opt_len]
        idx += opt_len
        name = PIM_OPT_TYPES.get(opt_type, f"Opt {opt_type}")
        opts[name] += 1
        if opt_type == 1 and len(value) >= 2:
            holdtime = int.from_bytes(value[:2], "big")
        elif opt_type == 19 and len(value) >= 4:
            dr_priority = int.from_bytes(value[:4], "big")
        elif opt_type == 24 and len(value) >= 4:
            gen_id = int.from_bytes(value[:4], "big")
    return {
        "options": opts,
        "holdtime": holdtime,
        "dr_priority": dr_priority,
        "gen_id": gen_id,
    }


def _parse_pim_group_prefix(data: bytes) -> tuple[str | None, int, int]:
    if len(data) < 2:
        return None, 0, 0
    family = int.from_bytes(data[0:2], "big")
    if len(data) < 4:
        return None, family, 0
    enc = data[2]
    mask_len = data[3]
    plen = (mask_len + 7) // 8
    if len(data) < 4 + plen:
        return None, family, 0
    addr_raw = data[4:4 + plen]
    addr = None
    try:
        if family == 1:
            addr = _ip_text(addr_raw + b"\x00" * (4 - plen))
        elif family == 2:
            addr = str(ipaddress.IPv6Address(addr_raw + b"\x00" * (16 - plen)))
    except Exception:
        addr = None
    length = 4 + plen
    return (f"{addr}/{mask_len}" if addr else None), family, length


def _parse_pim_source_prefix(data: bytes) -> tuple[str | None, int, int, int]:
    if len(data) < 2:
        return None, 0, 0, 0
    family = int.from_bytes(data[0:2], "big")
    if len(data) < 4:
        return None, family, 0, 0
    flags = data[2]
    mask_len = data[3]
    plen = (mask_len + 7) // 8
    if len(data) < 4 + plen:
        return None, family, flags, 0
    addr_raw = data[4:4 + plen]
    addr = None
    try:
        if family == 1:
            addr = _ip_text(addr_raw + b"\x00" * (4 - plen))
        elif family == 2:
            addr = str(ipaddress.IPv6Address(addr_raw + b"\x00" * (16 - plen)))
    except Exception:
        addr = None
    length = 4 + plen
    return (f"{addr}/{mask_len}" if addr else None), family, flags, length


def _parse_pim_join_prune(body: bytes) -> dict[str, object]:
    if len(body) < 8:
        return {}
    idx = 0
    upstream = _ip_text(body[idx:idx + 4])
    idx += 4
    idx += 2  # reserved
    group_count = int.from_bytes(body[idx:idx + 2], "big")
    idx += 2
    groups: list[dict[str, object]] = []
    for _ in range(min(group_count, 64)):
        group_prefix, family, glen = _parse_pim_group_prefix(body[idx:])
        if glen == 0:
            break
        idx += glen
        if idx + 4 > len(body):
            break
        joined = int.from_bytes(body[idx:idx + 2], "big")
        pruned = int.from_bytes(body[idx + 2:idx + 4], "big")
        idx += 4
        sources: list[dict[str, object]] = []
        total_src = joined + pruned
        for _src in range(min(total_src, 64)):
            src_prefix, sfamily, flags, slen = _parse_pim_source_prefix(body[idx:])
            if slen == 0:
                break
            idx += slen
            sources.append({
                "source": src_prefix,
                "family": sfamily,
                "flags": flags,
            })
        groups.append({
            "group": group_prefix,
            "family": family,
            "join_count": joined,
            "prune_count": pruned,
            "sources": sources,
        })
    return {
        "upstream": upstream,
        "groups": groups,
    }


def _parse_pim(payload: bytes) -> dict[str, object]:
    if len(payload) < 4:
        return {}
    first = payload[0]
    version = (first >> 4) & 0x0F
    msg_type = first & 0x0F
    checksum = int.from_bytes(payload[2:4], "big")
    body = payload[4:]
    info: dict[str, object] = {
        "version": version,
        "type": msg_type,
        "checksum": checksum,
    }
    if msg_type == 0:
        info["hello"] = _parse_pim_hello_options(body)
    elif msg_type == 3:
        info["join_prune"] = _parse_pim_join_prune(body)
    return info


def _parse_hsrp(payload: bytes) -> dict[str, object]:
    if len(payload) < 20:
        return {}
    version = payload[0]
    opcode = payload[1]
    state = payload[2]
    hello_time = payload[3]
    hold_time = payload[4]
    priority = payload[5]
    group = payload[6]
    auth = payload[8:16]
    vip = _ip_text(payload[16:20])
    return {
        "version": version,
        "opcode": opcode,
        "state": state,
        "hello": hello_time,
        "hold": hold_time,
        "priority": priority,
        "group": group,
        "auth": auth,
        "vip": vip,
    }


def _public_ip(ip_text: str) -> bool:
    try:
        return ipaddress.ip_address(ip_text).is_global
    except Exception:
        return False


def analyze_routing(path: Path, show_status: bool = True) -> RoutingSummary:
    if IP is None and IPv6 is None:
        return RoutingSummary(
            path=path,
            total_packets=0,
            routing_packets=0,
            protocol_counts=Counter(),
            message_counts=Counter(),
            endpoint_counts=Counter(),
            router_id_counts=Counter(),
            lsa_type_counts=Counter(),
            lsa_adv_router_counts=Counter(),
            lsa_id_counts=Counter(),
            lsa_maxage_count=0,
            lsa_seq_high_count=0,
            asn_counts=Counter(),
            bgp_prefix_counts=Counter(),
            bgp_withdraw_counts=Counter(),
            bgp_next_hop_counts=Counter(),
            bgp_path_attr_counts=Counter(),
            bgp_as_path_counts=Counter(),
            isis_system_id_counts=Counter(),
            isis_area_counts=Counter(),
            isis_hostname_counts=Counter(),
            isis_neighbor_counts=Counter(),
            isis_reachability_counts=Counter(),
            isis_tlv_counts=Counter(),
            isis_lsp_id_counts=Counter(),
        isis_lsp_seq_high_count=0,
        pim_type_counts=Counter(),
        pim_group_counts=Counter(),
        pim_source_counts=Counter(),
        pim_options_counts=Counter(),
        pim_dr_priority_counts=Counter(),
        auth_counts=Counter(),
            vrid_counts=Counter(),
            hsrp_group_counts=Counter(),
            sessions=[],
            detections=[],
            insights=[],
            artifacts=[],
            errors=["Scapy IP/IPv6 unavailable"],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    reader, status, stream, size_bytes, _file_type = get_reader(path, show_status=show_status)

    total_packets = 0
    routing_packets = 0
    protocol_counts: Counter[str] = Counter()
    message_counts: Counter[str] = Counter()
    endpoint_counts: Counter[str] = Counter()
    router_id_counts: Counter[str] = Counter()
    lsa_type_counts: Counter[str] = Counter()
    lsa_adv_router_counts: Counter[str] = Counter()
    lsa_id_counts: Counter[str] = Counter()
    lsa_maxage_count = 0
    lsa_seq_high_count = 0
    asn_counts: Counter[str] = Counter()
    bgp_prefix_counts: Counter[str] = Counter()
    bgp_withdraw_counts: Counter[str] = Counter()
    bgp_next_hop_counts: Counter[str] = Counter()
    bgp_path_attr_counts: Counter[str] = Counter()
    bgp_as_path_counts: Counter[str] = Counter()
    isis_system_id_counts: Counter[str] = Counter()
    isis_area_counts: Counter[str] = Counter()
    isis_hostname_counts: Counter[str] = Counter()
    isis_neighbor_counts: Counter[str] = Counter()
    isis_reachability_counts: Counter[str] = Counter()
    isis_tlv_counts: Counter[str] = Counter()
    isis_lsp_id_counts: Counter[str] = Counter()
    isis_lsp_seq_high_count = 0
    pim_type_counts: Counter[str] = Counter()
    pim_group_counts: Counter[str] = Counter()
    pim_source_counts: Counter[str] = Counter()
    pim_options_counts: Counter[str] = Counter()
    pim_dr_priority_counts: Counter[str] = Counter()
    auth_counts: Counter[str] = Counter()
    vrid_counts: Counter[str] = Counter()
    hsrp_group_counts: Counter[str] = Counter()
    sessions_map: dict[tuple[str, str, str, int, int], dict[str, object]] = {}
    artifacts: list[RoutingArtifact] = []
    detections: list[dict[str, object]] = []
    insights: list[str] = []
    errors: list[str] = []
    public_endpoints: set[str] = set()
    router_id_sources: dict[str, set[str]] = {}
    bgp_id_sources: dict[str, set[str]] = {}
    vrid_sources: dict[int, set[str]] = {}
    hsrp_sources: dict[int, set[str]] = {}
    bgp_notifications = 0
    ospf_lsa_updates = 0
    icmp_redirects = 0
    lsa_id_sources: dict[tuple[str, str], set[str]] = {}
    max_lsa_artifacts = 600

    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    def _update_session(protocol: str, src: str, dst: str, sport: int, dport: int, ts: Optional[float], detail: str | None = None) -> None:
        key = (protocol, src, dst, sport, dport)
        session = sessions_map.get(key)
        if session is None:
            session = {
                "protocol": protocol,
                "src_ip": src,
                "dst_ip": dst,
                "src_port": sport,
                "dst_port": dport,
                "packets": 0,
                "first_seen": ts,
                "last_seen": ts,
                "details": detail,
            }
            sessions_map[key] = session
        session["packets"] = int(session.get("packets", 0)) + 1
        if ts is not None:
            first_ts = session.get("first_seen")
            last_ts = session.get("last_seen")
            session["first_seen"] = ts if first_ts is None or ts < first_ts else first_ts
            session["last_seen"] = ts if last_ts is None or ts > last_ts else last_ts
        if detail and not session.get("details"):
            session["details"] = detail

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    status.update(int(min(100, (pos / size_bytes) * 100)))
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
            proto_val = None
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                ip_layer = pkt[IP]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))
                proto_val = int(getattr(ip_layer, "proto", 0) or 0)
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                ip_layer = pkt[IPv6]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))
                proto_val = int(getattr(ip_layer, "nh", 0) or 0)
            src_label = src_ip
            dst_label = dst_ip
            if (not src_label or not dst_label) and Ether is not None and pkt.haslayer(Ether):  # type: ignore[truthy-bool]
                eth = pkt[Ether]  # type: ignore[index]
                src_label = str(getattr(eth, "src", ""))
                dst_label = str(getattr(eth, "dst", ""))

            if not src_label or not dst_label:
                continue

            if src_ip and _public_ip(src_ip):
                public_endpoints.add(src_ip)
            if dst_ip and _public_ip(dst_ip):
                public_endpoints.add(dst_ip)

            # ICMP redirect detection
            if ICMP is not None and pkt.haslayer(ICMP):  # type: ignore[truthy-bool]
                try:
                    icmp_layer = pkt[ICMP]  # type: ignore[index]
                    icmp_type = int(getattr(icmp_layer, "type", -1))
                    if icmp_type == 5:
                        routing_packets += 1
                        protocol_counts["ICMP Redirect"] += 1
                        icmp_redirects += 1
                        message_counts["ICMP Redirect"] += 1
                        endpoint_counts[src_label] += 1
                        endpoint_counts[dst_label] += 1
                        _update_session("ICMP Redirect", src_label, dst_label, 0, 0, ts, None)
                except Exception:
                    pass

            # IP protocol-based routing protocols
            if proto_val in ROUTING_IP_PROTOS:
                proto_name = ROUTING_IP_PROTOS[proto_val]
                routing_packets += 1
                protocol_counts[proto_name] += 1
                endpoint_counts[src_label] += 1
                endpoint_counts[dst_label] += 1
                payload = b""
                try:
                    if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                        payload = bytes(pkt[IP].payload)  # type: ignore[index]
                    elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                        payload = bytes(pkt[IPv6].payload)  # type: ignore[index]
                except Exception:
                    payload = b""

                if proto_name == "OSPF":
                    info = _parse_ospf(payload)
                    msg_type = info.get("type")
                    msg_name = OSPF_TYPES.get(msg_type, f"Type {msg_type}") if msg_type is not None else "OSPF"
                    message_counts[f"OSPF {msg_name}"] += 1
                    if msg_name == "LSUpd":
                        ospf_lsa_updates += 1
                        lsas = _parse_ospf_lsas(payload)
                        for lsa in lsas:
                            lsa_type = int(lsa.get("type", 0) or 0)
                            lsa_type_name = OSPF_LSA_TYPES.get(lsa_type, f"Type {lsa_type}")
                            lsa_type_counts[lsa_type_name] += 1
                            adv_router = str(lsa.get("adv_router", ""))
                            ls_id = str(lsa.get("ls_id", ""))
                            if adv_router:
                                lsa_adv_router_counts[adv_router] += 1
                                if ls_id:
                                    lsa_id_sources.setdefault((lsa_type_name, ls_id), set()).add(adv_router)
                            if ls_id:
                                lsa_id_counts[ls_id] += 1
                            age_val = int(lsa.get("age", 0) or 0)
                            if age_val >= 3600:
                                lsa_maxage_count += 1
                            seq_val = int(lsa.get("seq", 0) or 0)
                            if seq_val >= 0x7FFFFF00:
                                lsa_seq_high_count += 1
                            if len(artifacts) < max_lsa_artifacts:
                                details = lsa.get("details") or {}
                                detail_bits = [
                                    f"type={lsa_type_name}",
                                    f"id={ls_id}" if ls_id else None,
                                    f"adv={adv_router}" if adv_router else None,
                                    f"age={age_val}",
                                    f"seq=0x{seq_val:08x}",
                                ]
                                if isinstance(details, dict):
                                    if details.get("link_count") is not None:
                                        detail_bits.append(f"links={details.get('link_count')}")
                                    if details.get("netmask"):
                                        detail_bits.append(f"mask={details.get('netmask')}")
                                    if details.get("metric") is not None:
                                        detail_bits.append(f"metric={details.get('metric')}")
                                    if details.get("external_type"):
                                        detail_bits.append(f"ext={details.get('external_type')}")
                                    if details.get("opaque_type") is not None:
                                        detail_bits.append(f"opaque_type={details.get('opaque_type')}")
                                detail_text = " ".join(bit for bit in detail_bits if bit)
                                artifacts.append(RoutingArtifact("ospf_lsa", detail_text, src_ip, dst_ip))
                    router_id = info.get("router_id")
                    area_id = info.get("area_id")
                    auth_type = info.get("auth_type")
                    auth_data = info.get("auth_data", b"")
                    lsa_count = info.get("lsa_count")
                    if router_id:
                        router_id_counts[str(router_id)] += 1
                    router_id_sources.setdefault(str(router_id), set()).add(src_label)
                    artifacts.append(RoutingArtifact("ospf_router_id", f"{router_id}", src_label, dst_label))
                if area_id:
                    artifacts.append(RoutingArtifact("ospf_area", f"{area_id}", src_label, dst_label))
                if lsa_count is not None:
                    artifacts.append(RoutingArtifact("ospf_lsa_count", f"{lsa_count}", src_label, dst_label))
                    if auth_type is not None:
                        auth_label = {0: "None", 1: "Simple", 2: "Cryptographic"}.get(auth_type, f"Type {auth_type}")
                        auth_counts[f"OSPF {auth_label}"] += 1
                        if auth_type == 1 and auth_data:
                            pwd = auth_data.decode("latin-1", errors="ignore").strip("\x00")
                            artifacts.append(RoutingArtifact("ospf_auth", f"OSPF simple auth password: {pwd}", src_label, dst_label))
                        elif auth_type == 0:
                            detections.append({
                                "severity": "warning",
                                "summary": "OSPF without authentication",
                                "details": f"{src_label} -> {dst_label} area {area_id or '-'}",
                            })
                    _update_session("OSPF", src_label, dst_label, 0, 0, ts, msg_name)

                elif proto_name == "EIGRP":
                    info = _parse_eigrp(payload)
                    opcode = info.get("opcode")
                    message_counts[f"EIGRP opcode {opcode if opcode is not None else '?'}"] += 1
                    asn = info.get("asn")
                    if asn is not None:
                        asn_counts[str(asn)] += 1
                        artifacts.append(RoutingArtifact("eigrp_asn", f"{asn}", src_label, dst_label))
                    _update_session("EIGRP", src_label, dst_label, 0, 0, ts, f"opcode {opcode}")

                elif proto_name == "VRRP":
                    info = _parse_vrrp(payload)
                    vrid = info.get("vrid")
                    priority = info.get("priority")
                    message_counts["VRRP Advertisement"] += 1
                    if vrid is not None:
                        vrid_counts[str(vrid)] += 1
                        vrid_sources.setdefault(int(vrid), set()).add(src_label)
                        artifacts.append(RoutingArtifact("vrrp_vrid", f"{vrid}", src_label, dst_label))
                    if priority is not None:
                        artifacts.append(RoutingArtifact("vrrp_priority", f"{priority}", src_label, dst_label))
                    auth_type = info.get("auth_type")
                    if auth_type:
                        auth_counts[f"VRRP Auth {auth_type}"] += 1
                    _update_session("VRRP", src_label, dst_label, 0, 0, ts, f"vrid {vrid}")

                elif proto_name == "IS-IS":
                    info = _parse_isis_pdu(payload)
                    pdu_type = info.get("pdu_type")
                    pdu_name = ISIS_PDU_TYPES.get(pdu_type, f"PDU {pdu_type}") if pdu_type is not None else "IS-IS"
                    message_counts[f"IS-IS {pdu_name}"] += 1
                    tlvs = info.get("tlvs") or {}
                    if info.get("source_id"):
                        sysid = str(info.get("source_id"))
                        isis_system_id_counts[sysid] += 1
                        artifacts.append(RoutingArtifact("isis_system_id", sysid, src_label, dst_label))
                    if info.get("lsp_id"):
                        lsp_id = str(info.get("lsp_id"))
                        isis_lsp_id_counts[lsp_id] += 1
                        artifacts.append(RoutingArtifact("isis_lsp_id", lsp_id, src_label, dst_label))
                    if info.get("lsp_seq") is not None:
                        seq_val = int(info.get("lsp_seq") or 0)
                        if seq_val >= 0xFFFFFF00:
                            isis_lsp_seq_high_count += 1
                    if isinstance(tlvs, dict):
                        for name, count in (tlvs.get("tlv_counts") or Counter()).items():
                            isis_tlv_counts[str(name)] += int(count)
                        for area in tlvs.get("areas", []):
                            isis_area_counts[str(area)] += 1
                        for host in tlvs.get("hostnames", []):
                            isis_hostname_counts[str(host)] += 1
                            artifacts.append(RoutingArtifact("isis_hostname", str(host), src_label, dst_label))
                        for addr in tlvs.get("ipv4_addrs", []):
                            artifacts.append(RoutingArtifact("isis_ipv4", str(addr), src_label, dst_label))
                        for addr in tlvs.get("ipv6_addrs", []):
                            artifacts.append(RoutingArtifact("isis_ipv6", str(addr), src_label, dst_label))
                        for nbr in tlvs.get("neighbors", []):
                            isis_neighbor_counts[str(nbr)] += 1
                        for prefix, metric in tlvs.get("reachability", []):
                            isis_reachability_counts[f"{prefix} (m{metric})"] += 1
                        for rid in tlvs.get("router_caps", []):
                            artifacts.append(RoutingArtifact("isis_router_cap_id", str(rid), src_label, dst_label))
                        auth_vals = tlvs.get("auth_values", [])
                        if auth_vals:
                            auth_counts["ISIS Auth"] += 1
                            for auth_val in auth_vals:
                                artifacts.append(RoutingArtifact("isis_auth", f"ISIS auth: {auth_val}", src_label, dst_label))
                                if isinstance(auth_val, str) and all(32 <= ord(ch) <= 126 for ch in auth_val):
                                    detections.append({
                                        "severity": "warning",
                                        "summary": "ISIS plaintext authentication",
                                        "details": f"{src_label} -> {dst_label} value '{auth_val}'",
                                    })
                    _update_session("IS-IS", src_label, dst_label, 0, 0, ts, pdu_name)
                elif proto_name == "PIM":
                    info = _parse_pim(payload)
                    msg_type = info.get("type")
                    msg_name = PIM_TYPES.get(msg_type, f"Type {msg_type}") if msg_type is not None else "PIM"
                    pim_type_counts[msg_name] += 1
                    message_counts[f"PIM {msg_name}"] += 1
                    if info.get("hello"):
                        hello = info.get("hello") or {}
                        opts = hello.get("options") or Counter()
                        for name, count in opts.items():
                            pim_options_counts[str(name)] += int(count)
                        hold = hello.get("holdtime")
                        dr_pri = hello.get("dr_priority")
                        gen_id = hello.get("gen_id")
                        if hold is not None:
                            artifacts.append(RoutingArtifact("pim_holdtime", f"{hold}", src_label, dst_label))
                        if dr_pri is not None:
                            pim_dr_priority_counts[str(dr_pri)] += 1
                            artifacts.append(RoutingArtifact("pim_dr_priority", f"{dr_pri}", src_label, dst_label))
                        if gen_id is not None:
                            artifacts.append(RoutingArtifact("pim_gen_id", f"{gen_id}", src_label, dst_label))
                    if info.get("join_prune"):
                        jp = info.get("join_prune") or {}
                        upstream = jp.get("upstream")
                        if upstream:
                            artifacts.append(RoutingArtifact("pim_upstream", f"{upstream}", src_label, dst_label))
                        for grp in jp.get("groups", []):
                            group = grp.get("group")
                            if group:
                                pim_group_counts[str(group)] += 1
                                artifacts.append(RoutingArtifact("pim_group", str(group), src_label, dst_label))
                            for src in grp.get("sources", []):
                                src_prefix = src.get("source")
                                if src_prefix:
                                    pim_source_counts[str(src_prefix)] += 1
                                    artifacts.append(RoutingArtifact("pim_source", str(src_prefix), src_label, dst_label))
                            if int(grp.get("prune_count") or 0) > 0:
                                detections.append({
                                    "severity": "info",
                                    "summary": "PIM prune activity observed",
                                    "details": f"{src_label} -> {dst_label} group {group or '-'} prunes {grp.get('prune_count')}",
                                })
                    _update_session("PIM", src_label, dst_label, 0, 0, ts, msg_name)
                else:
                    message_counts[proto_name] += 1
                    _update_session(proto_name, src_label, dst_label, 0, 0, ts, None)

                continue

            # L2 IS-IS (CLNS over Ethernet/LLC)
            isis_payload = None
            if Ether is not None and pkt.haslayer(Ether):  # type: ignore[truthy-bool]
                eth = pkt[Ether]  # type: ignore[index]
                if int(getattr(eth, "type", 0) or 0) == 0xFEFE:
                    try:
                        isis_payload = bytes(eth.payload)
                    except Exception:
                        isis_payload = None
            if isis_payload is None and LLC is not None and pkt.haslayer(LLC):  # type: ignore[truthy-bool]
                llc = pkt[LLC]  # type: ignore[index]
                try:
                    dsap = int(getattr(llc, "dsap", 0) or 0)
                    ssap = int(getattr(llc, "ssap", 0) or 0)
                except Exception:
                    dsap = ssap = 0
                if dsap == 0xFE and ssap == 0xFE:
                    try:
                        isis_payload = bytes(llc.payload)
                    except Exception:
                        isis_payload = None
            if isis_payload is None and Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                try:
                    raw_payload = bytes(pkt[Raw])  # type: ignore[index]
                    if raw_payload and raw_payload[0] == 0x83:
                        isis_payload = raw_payload
                except Exception:
                    isis_payload = None

            if isis_payload:
                info = _parse_isis_pdu(isis_payload)
                if info:
                    routing_packets += 1
                    protocol_counts["IS-IS"] += 1
                    endpoint_counts[src_label] += 1
                    endpoint_counts[dst_label] += 1
                    pdu_type = info.get("pdu_type")
                    pdu_name = ISIS_PDU_TYPES.get(pdu_type, f"PDU {pdu_type}") if pdu_type is not None else "IS-IS"
                    message_counts[f"IS-IS {pdu_name}"] += 1
                    tlvs = info.get("tlvs") or {}
                    if info.get("source_id"):
                        sysid = str(info.get("source_id"))
                        isis_system_id_counts[sysid] += 1
                        artifacts.append(RoutingArtifact("isis_system_id", sysid, src_label, dst_label))
                    if info.get("lsp_id"):
                        lsp_id = str(info.get("lsp_id"))
                        isis_lsp_id_counts[lsp_id] += 1
                        artifacts.append(RoutingArtifact("isis_lsp_id", lsp_id, src_label, dst_label))
                    if info.get("lsp_seq") is not None:
                        seq_val = int(info.get("lsp_seq") or 0)
                        if seq_val >= 0xFFFFFF00:
                            isis_lsp_seq_high_count += 1
                    if isinstance(tlvs, dict):
                        for name, count in (tlvs.get("tlv_counts") or Counter()).items():
                            isis_tlv_counts[str(name)] += int(count)
                        for area in tlvs.get("areas", []):
                            isis_area_counts[str(area)] += 1
                        for host in tlvs.get("hostnames", []):
                            isis_hostname_counts[str(host)] += 1
                            artifacts.append(RoutingArtifact("isis_hostname", str(host), src_label, dst_label))
                        for addr in tlvs.get("ipv4_addrs", []):
                            artifacts.append(RoutingArtifact("isis_ipv4", str(addr), src_label, dst_label))
                        for addr in tlvs.get("ipv6_addrs", []):
                            artifacts.append(RoutingArtifact("isis_ipv6", str(addr), src_label, dst_label))
                        for nbr in tlvs.get("neighbors", []):
                            isis_neighbor_counts[str(nbr)] += 1
                        for prefix, metric in tlvs.get("reachability", []):
                            isis_reachability_counts[f"{prefix} (m{metric})"] += 1
                        for rid in tlvs.get("router_caps", []):
                            artifacts.append(RoutingArtifact("isis_router_cap_id", str(rid), src_label, dst_label))
                        auth_vals = tlvs.get("auth_values", [])
                        if auth_vals:
                            auth_counts["ISIS Auth"] += 1
                            for auth_val in auth_vals:
                                artifacts.append(RoutingArtifact("isis_auth", f"ISIS auth: {auth_val}", src_label, dst_label))
                                if isinstance(auth_val, str) and all(32 <= ord(ch) <= 126 for ch in auth_val):
                                    detections.append({
                                        "severity": "warning",
                                        "summary": "ISIS plaintext authentication",
                                        "details": f"{src_label} -> {dst_label} value '{auth_val}'",
                                    })
                    _update_session("IS-IS", src_label, dst_label, 0, 0, ts, pdu_name)

            # Port-based routing protocols (BGP/RIP/HSRP/GLBP)
            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp = pkt[TCP]  # type: ignore[index]
                sport = int(getattr(tcp, "sport", 0) or 0)
                dport = int(getattr(tcp, "dport", 0) or 0)
                if sport in ROUTING_PORTS or dport in ROUTING_PORTS:
                    proto_name = ROUTING_PORTS.get(sport) or ROUTING_PORTS.get(dport)
                    if proto_name == "BGP":
                        routing_packets += 1
                        protocol_counts["BGP"] += 1
                        endpoint_counts[src_label] += 1
                        endpoint_counts[dst_label] += 1
                        payload = b""
                        try:
                            payload = bytes(tcp.payload)
                        except Exception:
                            payload = b""
                        for msg in _parse_bgp_messages(payload):
                            msg_type = msg.get("type")
                            msg_name = BGP_TYPES.get(msg_type, f"Type {msg_type}")
                            message_counts[f"BGP {msg_name}"] += 1
                            if msg_name == "NOTIFICATION":
                                bgp_notifications += 1
                            if msg_name == "OPEN":
                                asn = msg.get("asn")
                                bgp_id = msg.get("bgp_id")
                                hold_time = msg.get("hold_time")
                                if asn is not None:
                                    asn_counts[str(asn)] += 1
                                    artifacts.append(RoutingArtifact("bgp_asn", f"{asn}", src_label, dst_label))
                                if bgp_id:
                                    router_id_counts[str(bgp_id)] += 1
                                    bgp_id_sources.setdefault(str(bgp_id), set()).add(src_label)
                                    artifacts.append(RoutingArtifact("bgp_router_id", f"{bgp_id}", src_label, dst_label))
                                if hold_time is not None:
                                    artifacts.append(RoutingArtifact("bgp_hold_time", f"{hold_time}", src_label, dst_label))
                            if msg_name == "UPDATE":
                                withdrawn = msg.get("withdrawn") or []
                                nlri = msg.get("nlri") or []
                                origin = msg.get("origin")
                                next_hop = msg.get("next_hop")
                                as_path = msg.get("as_path") or []
                                attrs = msg.get("attrs") or []
                                mp_reach = msg.get("mp_reach") or []
                                mp_unreach = msg.get("mp_unreach") or []
                                for prefix in withdrawn:
                                    bgp_withdraw_counts[str(prefix)] += 1
                                for prefix in nlri:
                                    bgp_prefix_counts[str(prefix)] += 1
                                for prefix in mp_reach:
                                    bgp_prefix_counts[str(prefix)] += 1
                                for prefix in mp_unreach:
                                    bgp_withdraw_counts[str(prefix)] += 1
                                for attr in attrs:
                                    name = str(attr.get("name", ""))
                                    if name:
                                        bgp_path_attr_counts[name] += 1
                                if next_hop:
                                    bgp_next_hop_counts[str(next_hop)] += 1
                                if as_path:
                                    bgp_as_path_counts[" ".join(as_path)] += 1
                                if origin:
                                    artifacts.append(RoutingArtifact("bgp_origin", f"{origin}", src_label, dst_label))
                                if next_hop:
                                    artifacts.append(RoutingArtifact("bgp_next_hop", f"{next_hop}", src_label, dst_label))
                                for prefix in nlri[:5]:
                                    artifacts.append(RoutingArtifact("bgp_nlri", str(prefix), src_label, dst_label))
                                for prefix in withdrawn[:5]:
                                    artifacts.append(RoutingArtifact("bgp_withdraw", str(prefix), src_label, dst_label))
                        _update_session("BGP", src_label, dst_label, sport, dport, ts, None)
                    continue

            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp = pkt[UDP]  # type: ignore[index]
                sport = int(getattr(udp, "sport", 0) or 0)
                dport = int(getattr(udp, "dport", 0) or 0)
                if sport in ROUTING_PORTS or dport in ROUTING_PORTS:
                    proto_name = ROUTING_PORTS.get(sport) or ROUTING_PORTS.get(dport)
                    routing_packets += 1
                    protocol_counts[proto_name] += 1
                    endpoint_counts[src_label] += 1
                    endpoint_counts[dst_label] += 1
                    payload = b""
                    try:
                        payload = bytes(udp.payload)
                    except Exception:
                        payload = b""
                    if proto_name in {"RIP", "RIPng"}:
                        info = _parse_rip(payload)
                        cmd = info.get("cmd")
                        cmd_name = RIP_COMMANDS.get(cmd, f"Cmd {cmd}") if cmd is not None else "RIP"
                        message_counts[f"{proto_name} {cmd_name}"] += 1
                        if info.get("metric16"):
                            detections.append({
                                "severity": "warning",
                                "summary": f"{proto_name} route withdrawal observed",
                                "details": f"{src_label} -> {dst_label} metric 16 (unreachable) entry",
                            })
                        auth_type = info.get("auth_type")
                        auth_data = info.get("auth_data", b"")
                        if auth_type is not None:
                            auth_counts[f"{proto_name} auth {auth_type}"] += 1
                            if auth_type == 2 and auth_data:
                                pwd = auth_data.decode("latin-1", errors="ignore").strip("\x00")
                                artifacts.append(RoutingArtifact("rip_auth", f"{proto_name} simple auth password: {pwd}", src_label, dst_label))
                            elif auth_type == 0:
                                detections.append({
                                    "severity": "warning",
                                    "summary": f"{proto_name} without authentication",
                                    "details": f"{src_label} -> {dst_label}",
                                })
                        _update_session(proto_name, src_label, dst_label, sport, dport, ts, cmd_name)
                    elif proto_name == "HSRP":
                        info = _parse_hsrp(payload)
                        group = info.get("group")
                        state = info.get("state")
                        auth_data = info.get("auth", b"")
                        message_counts["HSRP Hello"] += 1
                        if group is not None:
                            hsrp_group_counts[str(group)] += 1
                            hsrp_sources.setdefault(int(group), set()).add(src_label)
                            artifacts.append(RoutingArtifact("hsrp_group", f"{group}", src_label, dst_label))
                        if state is not None:
                            artifacts.append(RoutingArtifact("hsrp_state", f"{state}", src_label, dst_label))
                        if auth_data:
                            auth_counts["HSRP Auth"] += 1
                            auth_text = auth_data.decode("latin-1", errors="ignore").strip("\x00")
                            artifacts.append(RoutingArtifact("hsrp_auth", f"HSRP auth password: {auth_text}", src_label, dst_label))
                        _update_session("HSRP", src_label, dst_label, sport, dport, ts, f"group {group}")
                    else:
                        message_counts[proto_name] += 1
                        _update_session(proto_name, src_label, dst_label, sport, dport, ts, None)

    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        reader.close()

    duration = (last_seen - first_seen) if first_seen is not None and last_seen is not None else None

    # Post-analysis detections/insights
    if routing_packets:
        ratio = routing_packets / max(1, total_packets)
        if ratio >= 0.25:
            insights.append(f"Routing-control traffic is {ratio:.1%} of total packets (control-plane heavy capture).")
    if public_endpoints:
        detections.append({
            "severity": "high",
            "summary": "Routing protocol traffic with public IPs",
            "details": f"Public endpoints observed: {', '.join(sorted(public_endpoints)[:6])}",
        })
    if bgp_withdraw_counts:
        top_withdrawn = ", ".join([p for p, _ in bgp_withdraw_counts.most_common(5)])
        detections.append({
            "severity": "info",
            "summary": "BGP withdrawals observed",
            "details": f"Top withdrawn prefixes: {top_withdrawn}",
        })
    if bgp_prefix_counts:
        top_announced = ", ".join([p for p, _ in bgp_prefix_counts.most_common(5)])
        detections.append({
            "severity": "info",
            "summary": "BGP announcements observed",
            "details": f"Top announced prefixes: {top_announced}",
        })
    if bgp_notifications >= 3:
        detections.append({
            "severity": "high",
            "summary": "BGP instability detected",
            "details": f"{bgp_notifications} BGP NOTIFICATION messages observed.",
        })
    if ospf_lsa_updates >= 200:
        detections.append({
            "severity": "warning",
            "summary": "Elevated OSPF LSA updates",
            "details": f"{ospf_lsa_updates} OSPF LS Update messages observed.",
        })
    if icmp_redirects >= 5:
        detections.append({
            "severity": "warning",
            "summary": "ICMP redirect activity",
            "details": f"{icmp_redirects} ICMP redirect messages observed.",
        })
    if isis_lsp_seq_high_count:
        detections.append({
            "severity": "warning",
            "summary": "IS-IS LSP sequence nearing max",
            "details": f"{isis_lsp_seq_high_count} IS-IS LSPs with high sequence values observed.",
        })
    if protocol_counts.get("IS-IS") and not auth_counts.get("ISIS Auth"):
        detections.append({
            "severity": "warning",
            "summary": "IS-IS without authentication",
            "details": "IS-IS traffic observed without authentication TLVs.",
        })
    if protocol_counts.get("PIM") and not pim_type_counts:
        detections.append({
            "severity": "warning",
            "summary": "PIM traffic observed but no messages decoded",
            "details": "PIM packets detected but parsing failed (check capture integrity).",
        })
    if lsa_maxage_count:
        detections.append({
            "severity": "warning",
            "summary": "OSPF MaxAge LSAs observed",
            "details": f"{lsa_maxage_count} LSAs with age >= 3600 (MaxAge) detected.",
        })
    if lsa_seq_high_count:
        detections.append({
            "severity": "warning",
            "summary": "OSPF LSA sequence nearing max",
            "details": f"{lsa_seq_high_count} LSAs with high sequence values observed.",
        })

    for router_id, sources in router_id_sources.items():
        if len(sources) > 1:
            detections.append({
                "severity": "warning",
                "summary": "Duplicate OSPF router ID observed",
                "details": f"Router ID {router_id} seen from {', '.join(sorted(sources))}",
            })
    for router_id, sources in bgp_id_sources.items():
        if len(sources) > 1:
            detections.append({
                "severity": "warning",
                "summary": "Duplicate BGP router ID observed",
                "details": f"BGP ID {router_id} seen from {', '.join(sorted(sources))}",
            })
    for vrid, sources in vrid_sources.items():
        if len(sources) > 1:
            detections.append({
                "severity": "info",
                "summary": "VRRP redundancy group seen from multiple routers",
                "details": f"VRID {vrid} advertised by {', '.join(sorted(sources))}",
            })
    for group, sources in hsrp_sources.items():
        if len(sources) > 1:
            detections.append({
                "severity": "info",
                "summary": "HSRP group seen from multiple routers",
                "details": f"Group {group} advertised by {', '.join(sorted(sources))}",
            })
    for key, sources in lsa_id_sources.items():
        if len(sources) > 1:
            lsa_type, ls_id = key
            detections.append({
                "severity": "warning",
                "summary": "OSPF LSA ID advertised by multiple routers",
                "details": f"{lsa_type} LSA {ls_id} seen from {', '.join(sorted(sources))}",
            })

    sessions: list[RoutingSession] = []
    for session in sessions_map.values():
        sessions.append(RoutingSession(
            protocol=str(session.get("protocol", "-")),
            src_ip=str(session.get("src_ip", "-")),
            dst_ip=str(session.get("dst_ip", "-")),
            src_port=int(session.get("src_port", 0) or 0),
            dst_port=int(session.get("dst_port", 0) or 0),
            packets=int(session.get("packets", 0) or 0),
            first_seen=session.get("first_seen"),
            last_seen=session.get("last_seen"),
            details=session.get("details"),
        ))

    return RoutingSummary(
        path=path,
        total_packets=total_packets,
        routing_packets=routing_packets,
        protocol_counts=protocol_counts,
        message_counts=message_counts,
        endpoint_counts=endpoint_counts,
        router_id_counts=router_id_counts,
        lsa_type_counts=lsa_type_counts,
        lsa_adv_router_counts=lsa_adv_router_counts,
        lsa_id_counts=lsa_id_counts,
        lsa_maxage_count=lsa_maxage_count,
        lsa_seq_high_count=lsa_seq_high_count,
        asn_counts=asn_counts,
        bgp_prefix_counts=bgp_prefix_counts,
        bgp_withdraw_counts=bgp_withdraw_counts,
        bgp_next_hop_counts=bgp_next_hop_counts,
        bgp_path_attr_counts=bgp_path_attr_counts,
        bgp_as_path_counts=bgp_as_path_counts,
        isis_system_id_counts=isis_system_id_counts,
        isis_area_counts=isis_area_counts,
        isis_hostname_counts=isis_hostname_counts,
        isis_neighbor_counts=isis_neighbor_counts,
        isis_reachability_counts=isis_reachability_counts,
        isis_tlv_counts=isis_tlv_counts,
        isis_lsp_id_counts=isis_lsp_id_counts,
        isis_lsp_seq_high_count=isis_lsp_seq_high_count,
        pim_type_counts=pim_type_counts,
        pim_group_counts=pim_group_counts,
        pim_source_counts=pim_source_counts,
        pim_options_counts=pim_options_counts,
        pim_dr_priority_counts=pim_dr_priority_counts,
        auth_counts=auth_counts,
        vrid_counts=vrid_counts,
        hsrp_group_counts=hsrp_group_counts,
        sessions=sessions,
        detections=detections,
        insights=insights,
        artifacts=artifacts,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )


def merge_routing_summaries(summaries: list[RoutingSummary]) -> RoutingSummary:
    if not summaries:
        return RoutingSummary(
            path=Path("ALL_PCAPS_0"),
            total_packets=0,
            routing_packets=0,
            protocol_counts=Counter(),
            message_counts=Counter(),
            endpoint_counts=Counter(),
            router_id_counts=Counter(),
            lsa_type_counts=Counter(),
            lsa_adv_router_counts=Counter(),
            lsa_id_counts=Counter(),
            lsa_maxage_count=0,
            lsa_seq_high_count=0,
            asn_counts=Counter(),
            bgp_prefix_counts=Counter(),
            bgp_withdraw_counts=Counter(),
            bgp_next_hop_counts=Counter(),
            bgp_path_attr_counts=Counter(),
            bgp_as_path_counts=Counter(),
            isis_system_id_counts=Counter(),
            isis_area_counts=Counter(),
            isis_hostname_counts=Counter(),
            isis_neighbor_counts=Counter(),
            isis_reachability_counts=Counter(),
            isis_tlv_counts=Counter(),
            isis_lsp_id_counts=Counter(),
        isis_lsp_seq_high_count=0,
        pim_type_counts=Counter(),
        pim_group_counts=Counter(),
        pim_source_counts=Counter(),
        pim_options_counts=Counter(),
        pim_dr_priority_counts=Counter(),
        auth_counts=Counter(),
            vrid_counts=Counter(),
            hsrp_group_counts=Counter(),
            sessions=[],
            detections=[],
            insights=[],
            artifacts=[],
            errors=[],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    total_packets = sum(item.total_packets for item in summaries)
    routing_packets = sum(item.routing_packets for item in summaries)
    protocol_counts = Counter()
    message_counts = Counter()
    endpoint_counts = Counter()
    router_id_counts = Counter()
    lsa_type_counts = Counter()
    lsa_adv_router_counts = Counter()
    lsa_id_counts = Counter()
    lsa_maxage_count = 0
    lsa_seq_high_count = 0
    asn_counts = Counter()
    bgp_prefix_counts = Counter()
    bgp_withdraw_counts = Counter()
    bgp_next_hop_counts = Counter()
    bgp_path_attr_counts = Counter()
    bgp_as_path_counts = Counter()
    auth_counts = Counter()
    isis_system_id_counts = Counter()
    isis_area_counts = Counter()
    isis_hostname_counts = Counter()
    isis_neighbor_counts = Counter()
    isis_reachability_counts = Counter()
    isis_tlv_counts = Counter()
    isis_lsp_id_counts = Counter()
    isis_lsp_seq_high_count = 0
    pim_type_counts = Counter()
    pim_group_counts = Counter()
    pim_source_counts = Counter()
    pim_options_counts = Counter()
    pim_dr_priority_counts = Counter()
    vrid_counts = Counter()
    hsrp_group_counts = Counter()
    sessions: list[RoutingSession] = []
    detections: list[dict[str, object]] = []
    insights: list[str] = []
    artifacts: list[RoutingArtifact] = []
    errors: list[str] = []
    first_seen = None
    last_seen = None

    for item in summaries:
        protocol_counts.update(item.protocol_counts)
        message_counts.update(item.message_counts)
        endpoint_counts.update(item.endpoint_counts)
        router_id_counts.update(item.router_id_counts)
        lsa_type_counts.update(item.lsa_type_counts)
        lsa_adv_router_counts.update(item.lsa_adv_router_counts)
        lsa_id_counts.update(item.lsa_id_counts)
        lsa_maxage_count += int(item.lsa_maxage_count or 0)
        lsa_seq_high_count += int(item.lsa_seq_high_count or 0)
        asn_counts.update(item.asn_counts)
        bgp_prefix_counts.update(item.bgp_prefix_counts)
        bgp_withdraw_counts.update(item.bgp_withdraw_counts)
        bgp_next_hop_counts.update(item.bgp_next_hop_counts)
        bgp_path_attr_counts.update(item.bgp_path_attr_counts)
        bgp_as_path_counts.update(item.bgp_as_path_counts)
        isis_system_id_counts.update(item.isis_system_id_counts)
        isis_area_counts.update(item.isis_area_counts)
        isis_hostname_counts.update(item.isis_hostname_counts)
        isis_neighbor_counts.update(item.isis_neighbor_counts)
        isis_reachability_counts.update(item.isis_reachability_counts)
        isis_tlv_counts.update(item.isis_tlv_counts)
        isis_lsp_id_counts.update(item.isis_lsp_id_counts)
        isis_lsp_seq_high_count += int(item.isis_lsp_seq_high_count or 0)
        pim_type_counts.update(item.pim_type_counts)
        pim_group_counts.update(item.pim_group_counts)
        pim_source_counts.update(item.pim_source_counts)
        pim_options_counts.update(item.pim_options_counts)
        pim_dr_priority_counts.update(item.pim_dr_priority_counts)
        auth_counts.update(item.auth_counts)
        vrid_counts.update(item.vrid_counts)
        hsrp_group_counts.update(item.hsrp_group_counts)
        sessions.extend(item.sessions)
        detections.extend(item.detections)
        insights.extend(item.insights)
        artifacts.extend(item.artifacts)
        errors.extend(item.errors)
        if item.first_seen is not None:
            first_seen = item.first_seen if first_seen is None else min(first_seen, item.first_seen)
        if item.last_seen is not None:
            last_seen = item.last_seen if last_seen is None else max(last_seen, item.last_seen)

    duration = (last_seen - first_seen) if first_seen is not None and last_seen is not None else None
    return RoutingSummary(
        path=Path(f"ALL_PCAPS_{len(summaries)}"),
        total_packets=total_packets,
        routing_packets=routing_packets,
        protocol_counts=protocol_counts,
        message_counts=message_counts,
        endpoint_counts=endpoint_counts,
        router_id_counts=router_id_counts,
        lsa_type_counts=lsa_type_counts,
        lsa_adv_router_counts=lsa_adv_router_counts,
        lsa_id_counts=lsa_id_counts,
        lsa_maxage_count=lsa_maxage_count,
        lsa_seq_high_count=lsa_seq_high_count,
        asn_counts=asn_counts,
        bgp_prefix_counts=bgp_prefix_counts,
        bgp_withdraw_counts=bgp_withdraw_counts,
        bgp_next_hop_counts=bgp_next_hop_counts,
        bgp_path_attr_counts=bgp_path_attr_counts,
        bgp_as_path_counts=bgp_as_path_counts,
        isis_system_id_counts=isis_system_id_counts,
        isis_area_counts=isis_area_counts,
        isis_hostname_counts=isis_hostname_counts,
        isis_neighbor_counts=isis_neighbor_counts,
        isis_reachability_counts=isis_reachability_counts,
        isis_tlv_counts=isis_tlv_counts,
        isis_lsp_id_counts=isis_lsp_id_counts,
        isis_lsp_seq_high_count=isis_lsp_seq_high_count,
        pim_type_counts=pim_type_counts,
        pim_group_counts=pim_group_counts,
        pim_source_counts=pim_source_counts,
        pim_options_counts=pim_options_counts,
        pim_dr_priority_counts=pim_dr_priority_counts,
        auth_counts=auth_counts,
        vrid_counts=vrid_counts,
        hsrp_group_counts=hsrp_group_counts,
        sessions=sessions,
        detections=detections,
        insights=insights,
        artifacts=artifacts,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
