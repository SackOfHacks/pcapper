from __future__ import annotations

from collections import Counter, defaultdict, OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import math
import os
import json
import time
import urllib.error
import urllib.request
import ipaddress
import re

from .pcap_cache import PcapMeta, get_reader

from .utils import safe_float, detect_file_type, decode_payload, counter_inc, set_add_cap, setdict_add

try:
    from scapy.layers.dns import DNS, DNSQR, DNSRR  # type: ignore
    from scapy.layers.inet import IP, UDP, TCP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    DNS = None  # type: ignore
    DNSQR = None  # type: ignore
    DNSRR = None  # type: ignore
    IP = None  # type: ignore
    UDP = None  # type: ignore
    TCP = None  # type: ignore
    IPv6 = None  # type: ignore

MAX_DNS_UNIQUE = int(os.getenv("PCAPPER_MAX_DNS_UNIQUE", "50000"))
MAX_VT_CACHE = int(os.getenv("PCAPPER_VT_CACHE_SIZE", "2048"))
MAX_VT_LOOKUPS = int(os.getenv("PCAPPER_VT_MAX_LOOKUPS", "500"))
VT_TIMEOUT = float(os.getenv("PCAPPER_VT_TIMEOUT", "8"))


_VT_CACHE: "OrderedDict[str, dict[str, object]]" = OrderedDict()


PUBLIC_DNS_RESOLVERS: dict[str, str] = {
    "8.8.8.8": "Google",
    "8.8.4.4": "Google",
    "2001:4860:4860::8888": "Google",
    "2001:4860:4860::8844": "Google",
    "1.1.1.1": "Cloudflare",
    "1.0.0.1": "Cloudflare",
    "2606:4700:4700::1111": "Cloudflare",
    "2606:4700:4700::1001": "Cloudflare",
    "9.9.9.9": "Quad9",
    "149.112.112.112": "Quad9",
    "2620:fe::fe": "Quad9",
    "2620:fe::9": "Quad9",
    "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS",
    "2620:119:35::35": "OpenDNS",
    "2620:119:53::53": "OpenDNS",
    "64.6.64.6": "Verisign",
    "64.6.65.6": "Verisign",
    "94.140.14.14": "AdGuard",
    "94.140.15.15": "AdGuard",
}

INTERNAL_TLDS = {
    "local",
    "lan",
    "localdomain",
    "home",
    "corp",
    "internal",
    "intranet",
}

OT_KEYWORDS = [
    "plc",
    "hmi",
    "scada",
    "dcs",
    "rtu",
    "rtac",
    "ied",
    "opc",
    "opcu",
    "modbus",
    "dnp3",
    "iec",
    "profinet",
    "ethernetip",
    "enip",
    "s7",
    "s7comm",
    "bacnet",
    "mms",
    "goose",
    "ethercat",
    "srtp",
    "niagara",
    "citect",
    "factorytalk",
    "wonderware",
    "wincc",
    "ignition",
    "triconex",
    "tricon",
    "yokogawa",
    "honeywell",
    "schneider",
    "siemens",
    "rockwell",
    "allenbradley",
    "gefanuc",
    "emerson",
    "abb",
    "omron",
]

OT_KEYWORD_RE = re.compile("|".join(re.escape(token) for token in OT_KEYWORDS), re.IGNORECASE)


@dataclass(frozen=True)
class DnsSummary:
    path: Path
    total_packets: int
    total_bytes: int
    query_packets: int
    response_packets: int
    udp_packets: int
    tcp_packets: int
    mdns_packets: int
    mdns_query_packets: int
    mdns_response_packets: int
    mdns_error_responses: int
    mdns_qname_counts: Counter[str]
    mdns_service_counts: Counter[str]
    mdns_client_counts: Counter[str]
    mdns_server_counts: Counter[str]
    unique_mdns_clients: int
    unique_mdns_servers: int
    packet_length_stats: list[dict[str, object]]
    multicast_streams: list[dict[str, object]]
    type_counts: Counter[str]
    rcode_counts: Counter[str]
    qname_counts: Counter[str]
    client_counts: Counter[str]
    server_counts: Counter[str]
    qtype_counts: Counter[int]
    mdns_qtype_counts: Counter[int]
    base_domain_counts: Counter[str]
    ot_qname_counts: Counter[str]
    ot_keyword_counts: Counter[str]
    public_resolver_counts: Counter[str]
    local_unicast_qname_counts: Counter[str]
    answers_by_qname: dict[str, set[str]]
    base_domain_answers: dict[str, set[str]]
    zone_transfer_requests: set[str]
    txt_query_names: set[str]
    tld_counts: Counter[str]
    opcode_counts: Counter[int]
    flag_counts: Counter[str]
    edns0_opt_count: int
    llmnr_packets: int
    llmnr_query_packets: int
    llmnr_response_packets: int
    llmnr_client_counts: Counter[str]
    llmnr_server_counts: Counter[str]
    query_size_stats: dict[str, object]
    response_size_stats: dict[str, object]
    vt_results: dict[str, dict[str, object]]
    unique_clients: int
    unique_servers: int
    unique_qnames: int
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]
    detections: list[dict[str, str | list[tuple[str, int]] | int]]
    errors: list[str]


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


def _size_stats(values: list[int]) -> dict[str, object]:
    if not values:
        return {}
    vals = sorted(values)
    count = len(vals)
    avg = sum(vals) / count if count else 0.0
    mid = count // 2
    median = vals[mid] if count % 2 == 1 else int((vals[mid - 1] + vals[mid]) / 2)
    p95_idx = int(0.95 * (count - 1)) if count > 1 else 0
    p95 = vals[p95_idx]
    return {
        "count": count,
        "min": vals[0],
        "max": vals[-1],
        "avg": avg,
        "median": median,
        "p95": p95,
    }


def _base_domain(name: str) -> str:
    parts = [part for part in name.strip(".").split(".") if part]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return name.strip(".")


def _tld(name: str) -> str:
    parts = [part for part in name.strip(".").split(".") if part]
    if parts:
        return parts[-1].lower()
    return "-"


def _vt_rating(stats: dict[str, object]) -> str:
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    if malicious > 0:
        return "malicious"
    if suspicious > 0:
        return "suspicious"
    if harmless > 0:
        return "clean"
    return "unknown"


def _vt_lookup_domain(domain: str, api_key: str) -> tuple[Optional[dict[str, object]], Optional[str]]:
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=VT_TIMEOUT) as resp:
            if resp.status != 200:
                return None, f"VT lookup failed for {domain}: HTTP {resp.status}"
            payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None, None
        return None, f"VT lookup failed for {domain}: HTTP {exc.code}"
    except urllib.error.URLError as exc:
        return None, f"VT lookup failed for {domain}: {exc.reason}"
    except Exception as exc:
        return None, f"VT lookup failed for {domain}: {type(exc).__name__}: {exc}"

    attrs = payload.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) or {}
    result = {
        "domain": domain,
        "malicious": int(stats.get("malicious", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "harmless": int(stats.get("harmless", 0) or 0),
        "undetected": int(stats.get("undetected", 0) or 0),
        "timeout": int(stats.get("timeout", 0) or 0),
        "reputation": attrs.get("reputation", 0),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "report_url": f"https://www.virustotal.com/gui/domain/{domain}",
    }
    result["score"] = int(result["malicious"]) + int(result["suspicious"])
    result["rating"] = _vt_rating(stats)
    return result, None


def _vt_lookup_domains(domains: list[str], api_key: str) -> tuple[dict[str, dict[str, object]], list[str]]:
    results: dict[str, dict[str, object]] = {}
    errors: list[str] = []
    if not domains:
        return results, errors

    max_lookups = MAX_VT_LOOKUPS
    if max_lookups <= 0:
        max_lookups = len(domains)

    for idx, domain in enumerate(domains):
        if idx >= max_lookups:
            errors.append(
                f"VT lookups capped at {max_lookups} domains (set PCAPPER_VT_MAX_LOOKUPS to raise)."
            )
            break
        if not domain or domain in results:
            continue
        cached = _VT_CACHE.get(domain)
        if cached is not None:
            _VT_CACHE.move_to_end(domain)
            results[domain] = cached
            continue
        vt_result, err = _vt_lookup_domain(domain, api_key)
        if vt_result:
            results[domain] = vt_result
            _VT_CACHE[domain] = vt_result
            if len(_VT_CACHE) > MAX_VT_CACHE:
                _VT_CACHE.popitem(last=False)
        if err:
            errors.append(err)
        if idx > 0:
            time.sleep(0.05)
    return results, errors


def analyze_dns(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
    vt_lookup: bool = False,
) -> DnsSummary:
    errors: list[str] = []
    if DNS is None:
        errors.append("Scapy DNS layers unavailable; install scapy for DNS analysis.")
        return DnsSummary(
            path=path,
            total_packets=0,
            total_bytes=0,
            query_packets=0,
            response_packets=0,
            udp_packets=0,
            tcp_packets=0,
            mdns_packets=0,
            mdns_query_packets=0,
            mdns_response_packets=0,
            mdns_error_responses=0,
            mdns_qname_counts=Counter(),
            mdns_service_counts=Counter(),
            mdns_client_counts=Counter(),
            mdns_server_counts=Counter(),
            unique_mdns_clients=0,
            unique_mdns_servers=0,
            packet_length_stats=[],
            multicast_streams=[],
            type_counts=Counter(),
            rcode_counts=Counter(),
            qname_counts=Counter(),
            client_counts=Counter(),
            server_counts=Counter(),
            qtype_counts=Counter(),
            mdns_qtype_counts=Counter(),
            base_domain_counts=Counter(),
            ot_qname_counts=Counter(),
            ot_keyword_counts=Counter(),
            public_resolver_counts=Counter(),
            local_unicast_qname_counts=Counter(),
            answers_by_qname={},
            base_domain_answers={},
            zone_transfer_requests=set(),
            txt_query_names=set(),
            tld_counts=Counter(),
            opcode_counts=Counter(),
            flag_counts=Counter(),
            edns0_opt_count=0,
            llmnr_packets=0,
            llmnr_query_packets=0,
            llmnr_response_packets=0,
            llmnr_client_counts=Counter(),
            llmnr_server_counts=Counter(),
            query_size_stats={},
            response_size_stats={},
            vt_results={},
            unique_clients=0,
            unique_servers=0,
            unique_qnames=0,
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
            detections=[],
            errors=errors,
        )

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, packets=packets, meta=meta, show_status=show_status
    )

    size_bytes = size_bytes

    total_packets = 0
    total_bytes = 0
    query_packets = 0
    response_packets = 0
    udp_packets = 0
    tcp_packets = 0
    mdns_packets = 0
    mdns_query_packets = 0
    mdns_response_packets = 0
    mdns_error_responses = 0
    mdns_unicast_packets = 0
    udp_multicast_packets = 0
    multicast_streams: dict[tuple[str, str, int], dict[str, object]] = defaultdict(lambda: {
        "count": 0,
        "bytes": 0,
        "sources": Counter(),
        "first_seen": None,
        "last_seen": None,
    })
    mdns_qname_counts: Counter[str] = Counter()
    mdns_service_counts: Counter[str] = Counter()
    mdns_client_counts: Counter[str] = Counter()
    mdns_server_counts: Counter[str] = Counter()

    type_counts: Counter[str] = Counter()
    rcode_counts: Counter[str] = Counter()
    qname_counts: Counter[str] = Counter()
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    qtype_counts: Counter[int] = Counter()
    mdns_qtype_counts: Counter[int] = Counter()

    qname_entropy: Counter[str] = Counter()
    qname_lengths: Counter[str] = Counter()
    base_domain_counts: Counter[str] = Counter()
    ot_qname_counts: Counter[str] = Counter()
    ot_keyword_counts: Counter[str] = Counter()
    local_unicast_qname_counts: Counter[str] = Counter()
    tld_counts: Counter[str] = Counter()
    answers_by_qname: dict[str, set[str]] = defaultdict(set)
    base_domain_answers: dict[str, set[str]] = defaultdict(set)
    zone_transfer_requests: set[str] = set()
    txt_query_names: set[str] = set()
    client_unique_qnames: dict[str, set[str]] = defaultdict(set)
    client_entropy_scores: dict[str, list[float]] = defaultdict(list)
    client_long_queries: Counter[str] = Counter()
    client_txt_queries: Counter[str] = Counter()
    client_nxdomain: Counter[str] = Counter()
    base_domain_priv_pub: dict[str, set[str]] = defaultdict(set)
    opcode_counts: Counter[int] = Counter()
    flag_counts: Counter[str] = Counter()
    edns0_opt_count = 0
    llmnr_packets = 0
    llmnr_query_packets = 0
    llmnr_response_packets = 0
    llmnr_client_counts: Counter[str] = Counter()
    llmnr_server_counts: Counter[str] = Counter()
    query_sizes: list[int] = []
    response_sizes: list[int] = []

    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    packet_len_buckets = [
        (0, 100, "0-100"),
        (101, 300, "101-300"),
        (301, 600, "301-600"),
        (601, 1200, "601-1200"),
        (1201, 2000, "1201-2000"),
        (2001, 65535, "2001+"),
    ]
    bucket_counts: dict[str, int] = defaultdict(int)
    bucket_sizes: dict[str, list[int]] = defaultdict(list)
    bucket_times: dict[str, list[float]] = defaultdict(list)

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            if not pkt.haslayer(DNS):  # type: ignore[truthy-bool]
                continue

            total_packets += 1
            pkt_len = int(len(pkt)) if hasattr(pkt, "__len__") else 0
            total_bytes += pkt_len
            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                for low, high, label in packet_len_buckets:
                    if low <= pkt_len <= high:
                        bucket_counts[label] += 1
                        bucket_sizes[label].append(pkt_len)
                        bucket_times[label].append(ts)
                        break

            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp_packets += 1
            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp_packets += 1

            dns_layer = pkt[DNS]  # type: ignore[index]
            if getattr(dns_layer, "qr", 0) == 0:
                query_packets += 1
                query_sizes.append(pkt_len)
            else:
                response_packets += 1
                response_sizes.append(pkt_len)

            rcode = getattr(dns_layer, "rcode", None)
            if rcode is not None:
                counter_inc(rcode_counts, str(rcode))
            opcode = getattr(dns_layer, "opcode", None)
            if opcode is not None:
                counter_inc(opcode_counts, int(opcode))
            if getattr(dns_layer, "rd", 0):
                counter_inc(flag_counts, "RD")
            if getattr(dns_layer, "ra", 0):
                counter_inc(flag_counts, "RA")
            if getattr(dns_layer, "aa", 0):
                counter_inc(flag_counts, "AA")
            if getattr(dns_layer, "tc", 0):
                counter_inc(flag_counts, "TC")
            if getattr(dns_layer, "ad", 0):
                counter_inc(flag_counts, "AD")
            if getattr(dns_layer, "cd", 0):
                counter_inc(flag_counts, "CD")

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

            is_mdns = False
            is_llmnr = False
            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp_layer = pkt[UDP]  # type: ignore[index]
                sport = int(getattr(udp_layer, "sport", 0) or 0)
                dport = int(getattr(udp_layer, "dport", 0) or 0)
                if sport == 5353 or dport == 5353:
                    is_mdns = True
                if sport == 5355 or dport == 5355:
                    is_llmnr = True
            if dst_ip in ("224.0.0.251", "ff02::fb"):
                is_mdns = True
            if dst_ip in ("224.0.0.252", "ff02::1:3"):
                is_llmnr = True

            if src_ip and dst_ip:
                if getattr(dns_layer, "qr", 0) == 0:
                    counter_inc(client_counts, src_ip)
                    counter_inc(server_counts, dst_ip)
                else:
                    counter_inc(client_counts, dst_ip)
                    counter_inc(server_counts, src_ip)
                    if rcode is not None and int(rcode) == 3:
                        counter_inc(client_nxdomain, dst_ip)

                if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                    if dst_ip.startswith("224.") or dst_ip.startswith("ff02::"):
                        udp_multicast_packets += 1
                        udp_layer = pkt[UDP]  # type: ignore[index]
                        dport = int(getattr(udp_layer, "dport", 0) or 0)
                        key = (dst_ip, "UDP", dport)
                        stream = multicast_streams[key]
                        stream["count"] = int(stream["count"]) + 1
                        stream["bytes"] = int(stream["bytes"]) + pkt_len
                        counter_inc(stream["sources"], src_ip)  # type: ignore[index]
                        if ts is not None:
                            if stream["first_seen"] is None or ts < stream["first_seen"]:  # type: ignore[operator]
                                stream["first_seen"] = ts
                            if stream["last_seen"] is None or ts > stream["last_seen"]:  # type: ignore[operator]
                                stream["last_seen"] = ts

                if is_mdns:
                    mdns_packets += 1
                    if dst_ip not in ("224.0.0.251", "ff02::fb"):
                        mdns_unicast_packets += 1
                    if getattr(dns_layer, "qr", 0) == 0:
                        mdns_query_packets += 1
                        counter_inc(mdns_client_counts, src_ip)
                        counter_inc(mdns_server_counts, dst_ip)
                    else:
                        mdns_response_packets += 1
                        counter_inc(mdns_client_counts, dst_ip)
                        counter_inc(mdns_server_counts, src_ip)
                        if rcode is not None and int(rcode) != 0:
                            mdns_error_responses += 1
                if is_llmnr:
                    llmnr_packets += 1
                    if getattr(dns_layer, "qr", 0) == 0:
                        llmnr_query_packets += 1
                        counter_inc(llmnr_client_counts, src_ip)
                        counter_inc(llmnr_server_counts, dst_ip)
                    else:
                        llmnr_response_packets += 1
                        counter_inc(llmnr_client_counts, dst_ip)
                        counter_inc(llmnr_server_counts, src_ip)

            qd_records = getattr(dns_layer, "qd", None)
            qdcount = int(getattr(dns_layer, "qdcount", 0) or 0)
            if qd_records is not None and qdcount > 0:
                try:
                    qd_items = list(qd_records)
                except Exception:
                    qd_items = [qd_records]
                for qd in qd_items:
                    if not getattr(qd, "qname", None):
                        continue
                    raw_name = qd.qname
                    name = decode_payload(
                        raw_name if isinstance(raw_name, (bytes, bytearray)) else str(raw_name).encode("utf-8", errors="ignore"),
                        encoding="utf-8",
                    )
                    name = name.strip(".")
                    if name:
                        counter_inc(qname_counts, name)
                        counter_inc(base_domain_counts, _base_domain(name))
                        tld = _tld(name)
                        counter_inc(tld_counts, tld)
                        if tld in INTERNAL_TLDS and not is_mdns:
                            counter_inc(local_unicast_qname_counts, name)
                        lower_name = name.lower()
                        if OT_KEYWORD_RE.search(lower_name):
                            counter_inc(ot_qname_counts, name)
                            for keyword in OT_KEYWORDS:
                                if keyword in lower_name:
                                    counter_inc(ot_keyword_counts, keyword)
                        if name in qname_entropy or len(qname_entropy) < MAX_DNS_UNIQUE:
                            entropy_val = int(_shannon_entropy(name) * 100)
                            qname_entropy[name] = entropy_val
                            if src_ip:
                                client_entropy_scores[src_ip].append(entropy_val / 100.0)
                        if name in qname_lengths or len(qname_lengths) < MAX_DNS_UNIQUE:
                            qname_lengths[name] = len(name)
                        if is_mdns:
                            counter_inc(mdns_qname_counts, name)
                        if src_ip and getattr(dns_layer, "qr", 0) == 0:
                            setdict_add(client_unique_qnames, src_ip, name, max_values=MAX_DNS_UNIQUE)
                            if len(name) >= 50:
                                counter_inc(client_long_queries, src_ip)
                    qtype = getattr(qd, "qtype", None)
                    if qtype is not None:
                        counter_inc(qtype_counts, int(qtype))
                        counter_inc(type_counts, str(qtype))
                        if is_mdns:
                            counter_inc(mdns_qtype_counts, int(qtype))
                        if int(qtype) in {251, 252} and name:
                            set_add_cap(zone_transfer_requests, name, max_size=MAX_DNS_UNIQUE)
                        if int(qtype) == 16 and name:
                            set_add_cap(txt_query_names, name, max_size=MAX_DNS_UNIQUE)
                            if src_ip:
                                counter_inc(client_txt_queries, src_ip)
                        if is_mdns and int(qtype) == 33 and name:
                            counter_inc(mdns_service_counts, name)

            ar_records = getattr(dns_layer, "ar", None)
            if ar_records is not None:
                try:
                    for rr in ar_records:
                        if getattr(rr, "type", None) == 41:
                            edns0_opt_count += 1
                except Exception:
                    pass

            if getattr(dns_layer, "qr", 0) == 1:
                an_records = getattr(dns_layer, "an", None)
                if an_records is not None:
                    try:
                        # Iterate directly over parsed records instead of using header count
                        for rr in an_records:
                            rrtype = getattr(rr, "type", None)
                            rrname = getattr(rr, "rrname", None)
                            rdata = getattr(rr, "rdata", None)
                            if rrname is not None and rdata is not None:
                                rrname_bytes = rrname if isinstance(rrname, (bytes, bytearray)) else str(rrname).encode("utf-8", errors="ignore")
                                rrname_str = decode_payload(rrname_bytes, encoding="utf-8").strip(".")
                                setdict_add(answers_by_qname, rrname_str, str(rdata), max_values=MAX_DNS_UNIQUE)
                                if rrtype in {1, 28}:  # A or AAAA
                                    setdict_add(base_domain_answers, _base_domain(rrname_str), str(rdata), max_values=MAX_DNS_UNIQUE)
                                    try:
                                        ip_val = ipaddress.ip_address(str(rdata))
                                        if ip_val.is_private:
                                            base_domain_priv_pub[_base_domain(rrname_str)].add("private")
                                        elif ip_val.is_global:
                                            base_domain_priv_pub[_base_domain(rrname_str)].add("public")
                                    except Exception:
                                        pass
                                if is_mdns:
                                    if rrtype == 33:
                                        counter_inc(mdns_service_counts, rrname_str)
                                    if rrtype == 12:
                                        try:
                                            service_name = str(rdata).strip(".")
                                        except Exception:
                                            service_name = str(rdata)
                                        if service_name and ("_tcp" in service_name or "_udp" in service_name):
                                            counter_inc(mdns_service_counts, service_name)
                    except Exception:
                        pass

            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts
    finally:
        status.finish()
        reader.close()

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    packet_length_stats: list[dict[str, object]] = []
    for low, high, label in packet_len_buckets:
        count = bucket_counts.get(label, 0)
        if count == 0:
            continue
        sizes = bucket_sizes.get(label, [])
        avg_size = sum(sizes) / len(sizes) if sizes else 0.0
        min_size = min(sizes) if sizes else 0
        max_size = max(sizes) if sizes else 0
        pct = (count / total_packets) * 100 if total_packets else 0.0
        rate = (count / duration_seconds) if duration_seconds and duration_seconds > 0 else 0.0

        burst_rate = 0.0
        burst_start = None
        times = sorted(bucket_times.get(label, []))
        if times:
            left = 0
            for right in range(len(times)):
                while times[right] - times[left] > 1.0:
                    left += 1
                window_count = right - left + 1
                if window_count > burst_rate:
                    burst_rate = float(window_count)
                    burst_start = times[left]

        packet_length_stats.append({
            "bucket": label,
            "count": count,
            "avg": avg_size,
            "min": min_size,
            "max": max_size,
            "rate": rate,
            "pct": pct,
            "burst_rate": burst_rate,
            "burst_start": burst_start,
        })

    query_size_stats = _size_stats(query_sizes)
    response_size_stats = _size_stats(response_sizes)
    public_resolver_counts: Counter[str] = Counter(
        {ip: count for ip, count in server_counts.items() if ip in PUBLIC_DNS_RESOLVERS}
    )

    detections: list[dict[str, str | list[tuple[str, int]] | int]] = []
    if total_packets == 0:
        detections.append({
            "type": "no_dns",
            "severity": "info",
            "summary": "No DNS traffic detected",
            "details": "DNS not observed in capture.",
        })
    else:
        if duration_seconds and duration_seconds > 0:
            pps = total_packets / duration_seconds
            if pps > 2000:
                detections.append({
                    "type": "dns_flood",
                    "severity": "warning",
                    "summary": f"High DNS rate observed ({pps:.1f} pkt/s)",
                    "details": "Excessive DNS traffic may indicate abuse or misconfiguration.",
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                })

        nxdomain = rcode_counts.get("3", 0)
        if nxdomain > 100 and total_packets > 0 and (nxdomain / total_packets) > 0.3:
            detections.append({
                "type": "dns_nxdomain",
                "severity": "warning",
                "summary": f"High NXDOMAIN rate ({nxdomain} responses)",
                "details": "Potential DGA, misconfiguration, or scanning.",
                "top_clients": client_counts.most_common(3),
                "top_servers": server_counts.most_common(3),
            })

        servfail = rcode_counts.get("2", 0)
        if servfail > 50 and total_packets > 0 and (servfail / total_packets) > 0.2:
            detections.append({
                "type": "dns_servfail",
                "severity": "warning",
                "summary": f"High SERVFAIL rate ({servfail} responses)",
                "details": "Resolver errors or upstream issues observed.",
                "top_clients": client_counts.most_common(3),
                "top_servers": server_counts.most_common(3),
            })

        refused = rcode_counts.get("5", 0)
        if refused > 50 and total_packets > 0 and (refused / total_packets) > 0.2:
            detections.append({
                "type": "dns_refused",
                "severity": "warning",
                "summary": f"High REFUSED rate ({refused} responses)",
                "details": "Possible scanning or access control enforcement.",
                "top_clients": client_counts.most_common(3),
                "top_servers": server_counts.most_common(3),
            })

        suspicious_qnames = [
            name for name, count in qname_counts.items()
            if qname_lengths.get(name, 0) > 50 or (qname_entropy.get(name, 0) / 100) > 4.0
        ]
        if len(suspicious_qnames) > 30:
            detections.append({
                "type": "dns_tunnel_indicator",
                "severity": "warning",
                "summary": "Potential DNS tunneling behavior",
                "details": "Many long/high-entropy query names detected.",
                "top_clients": client_counts.most_common(3),
                "top_servers": server_counts.most_common(3),
            })

        client_suspects: list[str] = []
        for client, total in client_counts.items():
            if total < 20:
                continue
            unique = len(client_unique_qnames.get(client, set()))
            ratio = unique / max(total, 1)
            entropies = client_entropy_scores.get(client, [])
            avg_entropy = sum(entropies) / max(len(entropies), 1) if entropies else 0.0
            long_q = client_long_queries.get(client, 0)
            nx_count = client_nxdomain.get(client, 0)
            if ratio >= 0.8 and avg_entropy >= 3.6 and (long_q >= 5 or nx_count >= 10):
                client_suspects.append(
                    f"{client} unique_ratio={ratio:.2f} entropy={avg_entropy:.2f} long={long_q} nxdomain={nx_count}"
                )
        if client_suspects:
            detections.append({
                "type": "dns_client_dga",
                "severity": "warning",
                "summary": "Clients with DGA/tunnel-like DNS patterns",
                "details": "; ".join(client_suspects[:6]),
                "top_clients": client_counts.most_common(3),
                "top_servers": server_counts.most_common(3),
            })

        for base, count in base_domain_counts.items():
            if count > 1000:
                detections.append({
                    "type": "dns_domain_concentration",
                    "severity": "info",
                    "summary": f"High query volume for {base} ({count} queries)",
                    "details": "Check for beaconing or resolver issues.",
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                })
                break

        for qname, answers in answers_by_qname.items():
            if len(answers) >= 6:
                detections.append({
                    "type": "dns_poisoning_indicator",
                    "severity": "warning",
                    "summary": f"Multiple answers observed for {qname}",
                    "details": f"Observed {len(answers)} distinct answers; verify expected CDN/rotation.",
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                })
                break

        for base, answers in base_domain_answers.items():
            if len(answers) >= 10:
                detections.append({
                    "type": "dns_fast_flux",
                    "severity": "warning",
                    "summary": f"Fast-flux indicator for {base}",
                    "details": f"Observed {len(answers)} unique A/AAAA answers.",
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                })
                break

        rebinding_domains = [
            base for base, flags in base_domain_priv_pub.items()
            if "private" in flags and "public" in flags
        ]
        if rebinding_domains:
            sample = ", ".join(sorted(rebinding_domains)[:5])
            detections.append({
                "type": "dns_rebinding",
                "severity": "warning",
                "summary": "Potential DNS rebinding behavior",
                "details": f"Domains with both private and public answers: {sample}",
                "top_clients": client_counts.most_common(3),
                "top_servers": server_counts.most_common(3),
            })

        if zone_transfer_requests:
            sample = ", ".join(sorted(list(zone_transfer_requests))[:5])
            detections.append({
                "type": "dns_zone_transfer",
                "severity": "warning",
                "summary": "Zone transfer attempt detected",
                "details": f"AXFR/IXFR requested for: {sample}",
                "top_clients": client_counts.most_common(3),
                "top_servers": server_counts.most_common(3),
            })

        txt_queries = qtype_counts.get(16, 0)
        if txt_queries > 100 and total_packets > 0 and (txt_queries / total_packets) > 0.2:
            txt_sample = ", ".join(sorted(list(txt_query_names))[:5])
            txt_details = "TXT-heavy traffic can indicate data exfiltration or policy misuse."
            if txt_sample:
                txt_details += f" Sample TXT names: {txt_sample}"
            detections.append({
                "type": "dns_txt_exfil",
                "severity": "warning",
                "summary": f"High TXT query volume ({txt_queries} queries)",
                "details": txt_details,
                "top_clients": client_counts.most_common(3),
                "top_servers": server_counts.most_common(3),
            })

        ptr_queries = qtype_counts.get(12, 0)
        if ptr_queries > 50 and total_packets > 0 and (ptr_queries / total_packets) > 0.2:
            ptr_names = [
                name for name in qname_counts.keys()
                if name.endswith("in-addr.arpa") or name.endswith("ip6.arpa")
            ]
            ptr_sample = ", ".join(sorted(ptr_names)[:5])
            details = "High PTR/reverse lookup volume may indicate scanning or asset discovery."
            if ptr_sample:
                details += f" Sample PTR names: {ptr_sample}"
            detections.append({
                "type": "dns_ptr_sweep",
                "severity": "warning",
                "summary": f"High PTR query volume ({ptr_queries} queries)",
                "details": details,
                "top_clients": client_counts.most_common(3),
                "top_servers": server_counts.most_common(3),
            })

        any_queries = qtype_counts.get(255, 0)
        if any_queries > 20:
            detections.append({
                "type": "dns_any_abuse",
                "severity": "warning",
                "summary": f"ANY query usage observed ({any_queries})",
                "details": "ANY queries can indicate reconnaissance or amplification abuse.",
                "top_clients": client_counts.most_common(3),
                "top_servers": server_counts.most_common(3),
            })

        common_qtypes = {1, 2, 5, 6, 12, 15, 16, 28, 33, 41, 255}
        unusual_qtypes = [(qtype, count) for qtype, count in qtype_counts.items() if qtype not in common_qtypes]
        if unusual_qtypes:
            unusual_total = sum(count for _, count in unusual_qtypes)
            if unusual_total >= 20:
                top_unusual = ", ".join(
                    f"{qtype}({count})" for qtype, count in sorted(unusual_qtypes, key=lambda x: x[1], reverse=True)[:6]
                )
                detections.append({
                    "type": "dns_unusual_qtypes",
                    "severity": "info",
                    "summary": "Unusual DNS query record types observed",
                    "details": f"Uncommon qtypes: {top_unusual}",
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                })

        if opcode_counts:
            non_query = sum(count for opcode, count in opcode_counts.items() if int(opcode) != 0)
            if non_query:
                detections.append({
                    "type": "dns_opcode",
                    "severity": "warning",
                    "summary": "Non-standard DNS opcodes observed",
                    "details": ", ".join(f"{opcode}({count})" for opcode, count in opcode_counts.items() if int(opcode) != 0),
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                })

        notify_count = int(opcode_counts.get(4, 0) or 0)
        update_count = int(opcode_counts.get(5, 0) or 0)
        if notify_count or update_count:
            details = []
            if notify_count:
                details.append(f"NOTIFY({notify_count})")
            if update_count:
                details.append(f"UPDATE({update_count})")
            detections.append({
                "type": "dns_dynamic_updates",
                "severity": "warning",
                "summary": "DNS zone change opcodes observed",
                "details": "Dynamic updates/notifications observed: " + ", ".join(details),
                "top_clients": client_counts.most_common(3),
                "top_servers": server_counts.most_common(3),
            })

        if tcp_packets and total_packets > 0:
            tcp_ratio = tcp_packets / max(total_packets, 1)
            if tcp_ratio >= 0.2 and total_packets >= 200:
                detections.append({
                    "type": "dns_tcp_heavy",
                    "severity": "info",
                    "summary": "Elevated DNS-over-TCP usage",
                    "details": f"TCP DNS accounts for {tcp_ratio * 100:.1f}% of packets.",
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                })

        if query_size_stats:
            query_p95 = int(query_size_stats.get("p95", 0) or 0)
            if query_p95 > 300:
                detections.append({
                    "type": "dns_large_queries",
                    "severity": "warning",
                    "summary": "Large DNS query payloads observed",
                    "details": f"Query p95 size {query_p95} bytes; max {query_size_stats.get('max')} bytes.",
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                })

        if response_size_stats:
            stats = response_size_stats
            if int(stats.get("p95", 0) or 0) > 1232:
                detections.append({
                    "type": "dns_large_responses",
                    "severity": "warning",
                    "summary": "Large DNS responses observed",
                    "details": f"Response p95 size {stats.get('p95')} bytes; max {stats.get('max')} bytes.",
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                })

        tc_count = int(flag_counts.get("TC", 0) or 0)
        if tc_count > 10 and total_packets > 0 and (tc_count / total_packets) > 0.02:
            detections.append({
                "type": "dns_truncation",
                "severity": "info",
                "summary": "Truncated DNS responses observed",
                "details": f"TC flag set in {tc_count} packets; may indicate large responses or fragmentation.",
                "top_clients": client_counts.most_common(3),
                "top_servers": server_counts.most_common(3),
            })

        if public_resolver_counts:
            resolver_details = ", ".join(
                f"{ip}({count})[{PUBLIC_DNS_RESOLVERS.get(ip, '-')}]"
                for ip, count in public_resolver_counts.most_common(5)
            )
            detections.append({
                "type": "dns_public_resolvers",
                "severity": "warning",
                "summary": "Public DNS resolvers observed",
                "details": f"Public resolvers: {resolver_details}. In OT/ICS networks, direct public DNS usage is often a policy violation.",
                "top_clients": client_counts.most_common(3),
            })

        if local_unicast_qname_counts:
            sample = ", ".join(sorted(list(local_unicast_qname_counts))[:5])
            detections.append({
                "type": "dns_local_unicast",
                "severity": "info",
                "summary": "Unicast queries for local TLDs observed",
                "details": f"Local-only TLDs (e.g., .local/.lan) queried via unicast DNS: {sample}",
                "top_clients": client_counts.most_common(3),
                "top_servers": server_counts.most_common(3),
            })

        if ot_qname_counts:
            keyword_text = ", ".join(
                f"{kw}({count})" for kw, count in ot_keyword_counts.most_common(5)
            )
            sample = ", ".join(name for name, _count in ot_qname_counts.most_common(5))
            details = "OT/ICS-related naming observed"
            if keyword_text:
                details += f"; keywords: {keyword_text}"
            if sample:
                details += f"; sample: {sample}"
            detections.append({
                "type": "dns_ot_naming",
                "severity": "info",
                "summary": "OT/ICS asset naming detected in DNS",
                "details": details,
                "top_clients": client_counts.most_common(3),
                "top_servers": server_counts.most_common(3),
            })

        if mdns_packets > 0:
            detections.append({
                "type": "mdns_present",
                "severity": "info",
                "summary": f"mDNS traffic observed ({mdns_packets} packets)",
                "details": "mDNS/Bonjour discovery seen; in OT/ICS networks this can expand broadcast attack surface.",
                "top_clients": mdns_client_counts.most_common(3),
                "top_servers": mdns_server_counts.most_common(3),
            })

            if mdns_packets > 1000:
                detections.append({
                    "type": "mdns_chatty",
                    "severity": "warning",
                    "summary": "High mDNS volume",
                    "details": f"Observed {mdns_packets} mDNS packets; potential chatter or misconfiguration.",
                    "top_clients": mdns_client_counts.most_common(3),
                })

            for name, count in mdns_qname_counts.items():
                if name.endswith(".local") and count > 200:
                    detections.append({
                        "type": "mdns_burst",
                        "severity": "warning",
                        "summary": f"High mDNS query volume for {name}",
                        "details": "Investigate for discovery storms or spoofing.",
                        "top_clients": mdns_client_counts.most_common(3),
                    })
                    break

            if mdns_unicast_packets > 0:
                detections.append({
                    "type": "mdns_unicast",
                    "severity": "warning",
                    "summary": "Unicast mDNS traffic detected",
                    "details": f"Observed {mdns_unicast_packets} mDNS packets sent via unicast; review for abuse or misconfiguration.",
                    "top_clients": mdns_client_counts.most_common(3),
                    "top_servers": mdns_server_counts.most_common(3),
                })

            if udp_multicast_packets > 0:
                detections.append({
                    "type": "udp_multicast_streams",
                    "severity": "warning",
                    "summary": "UDP multicast streams detected",
                    "details": f"Observed {udp_multicast_packets} UDP multicast DNS packets; review for discovery abuse.",
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                })

            allowed_types = {1, 28, 12, 16, 33}
            unusual_mdns = [(t, c) for t, c in mdns_qtype_counts.items() if t not in allowed_types]
            if unusual_mdns:
                top_unusual = ", ".join(f"{t}({c})" for t, c in sorted(unusual_mdns, key=lambda x: x[1], reverse=True)[:5])
                detections.append({
                    "type": "mdns_unusual_qtypes",
                    "severity": "warning",
                    "summary": "Unusual mDNS query record types detected",
                    "details": f"Observed uncommon mDNS qtypes: {top_unusual}",
                    "top_clients": mdns_client_counts.most_common(3),
                })

            mdns_txt_queries = mdns_qtype_counts.get(16, 0)
            if mdns_txt_queries > 0:
                detections.append({
                    "type": "mdns_txt_records",
                    "severity": "warning",
                    "summary": "mDNS TXT Record Analysis",
                    "details": f"Observed {mdns_txt_queries} mDNS TXT queries; review for metadata leakage or abuse.",
                    "top_clients": mdns_client_counts.most_common(3),
                    "top_servers": mdns_server_counts.most_common(3),
                })

        if llmnr_packets > 0:
            detections.append({
                "type": "llmnr_present",
                "severity": "warning",
                "summary": f"LLMNR traffic observed ({llmnr_packets} packets)",
                "details": "LLMNR can be abused for spoofing/poisoning; in OT/ICS environments it is a common lateral movement risk.",
                "top_clients": llmnr_client_counts.most_common(3),
                "top_servers": llmnr_server_counts.most_common(3),
            })

    vt_results: dict[str, dict[str, object]] = {}
    if vt_lookup:
        api_key = os.environ.get("VT_API_KEY")
        if not api_key:
            errors.append("VT_API_KEY is not set; skipping VirusTotal lookups.")
        else:
            domain_counts: dict[str, int] = {}
            for name, count in qname_counts.items():
                domain = name.strip(".").lower()
                if not domain:
                    continue
                domain_counts[domain] = domain_counts.get(domain, 0) + count
            for name, count in base_domain_counts.items():
                domain = name.strip(".").lower()
                if not domain:
                    continue
                domain_counts[domain] = domain_counts.get(domain, 0) + count
            ranked_domains = [
                domain for domain, _count in sorted(domain_counts.items(), key=lambda item: item[1], reverse=True)
            ]
            vt_results, vt_errors = _vt_lookup_domains(ranked_domains, api_key)
            errors.extend(vt_errors)
            if vt_results:
                vt_findings = list(vt_results.values())
                vt_findings.sort(
                    key=lambda item: (
                        int(item.get("malicious", 0) or 0) > 0,
                        int(item.get("suspicious", 0) or 0) > 0,
                        int(item.get("malicious", 0) or 0),
                        int(item.get("suspicious", 0) or 0),
                        int(item.get("harmless", 0) or 0),
                    ),
                    reverse=True,
                )
                severity = "warning" if any(
                    int(item.get("malicious", 0) or 0) > 0 or int(item.get("suspicious", 0) or 0) > 0
                    for item in vt_findings
                ) else "info"
                detections.append({
                    "type": "dns_vt_hits",
                    "severity": severity,
                    "summary": "VirusTotal DNS reputation",
                    "vt_findings": vt_findings,
                })

    return DnsSummary(
        path=path,
        total_packets=total_packets,
        total_bytes=total_bytes,
        query_packets=query_packets,
        response_packets=response_packets,
        udp_packets=udp_packets,
        tcp_packets=tcp_packets,
        mdns_packets=mdns_packets,
        mdns_query_packets=mdns_query_packets,
        mdns_response_packets=mdns_response_packets,
        mdns_error_responses=mdns_error_responses,
        mdns_qname_counts=mdns_qname_counts,
        mdns_service_counts=mdns_service_counts,
        mdns_client_counts=mdns_client_counts,
        mdns_server_counts=mdns_server_counts,
        unique_mdns_clients=len(mdns_client_counts),
        unique_mdns_servers=len(mdns_server_counts),
        packet_length_stats=packet_length_stats,
        multicast_streams=[
            {
                "group": group,
                "protocol": proto,
                "port": port,
                "count": data.get("count", 0),
                "bytes": data.get("bytes", 0),
                "sources": data.get("sources", Counter()).most_common(5),
                "first_seen": data.get("first_seen"),
                "last_seen": data.get("last_seen"),
            }
            for (group, proto, port), data in multicast_streams.items()
        ],
        type_counts=type_counts,
        rcode_counts=rcode_counts,
        qname_counts=qname_counts,
        client_counts=client_counts,
        server_counts=server_counts,
        qtype_counts=qtype_counts,
        mdns_qtype_counts=mdns_qtype_counts,
        base_domain_counts=base_domain_counts,
        ot_qname_counts=ot_qname_counts,
        ot_keyword_counts=ot_keyword_counts,
        public_resolver_counts=public_resolver_counts,
        local_unicast_qname_counts=local_unicast_qname_counts,
        answers_by_qname=answers_by_qname,
        base_domain_answers=base_domain_answers,
        zone_transfer_requests=zone_transfer_requests,
        txt_query_names=txt_query_names,
        tld_counts=tld_counts,
        opcode_counts=opcode_counts,
        flag_counts=flag_counts,
        edns0_opt_count=edns0_opt_count,
        llmnr_packets=llmnr_packets,
        llmnr_query_packets=llmnr_query_packets,
        llmnr_response_packets=llmnr_response_packets,
        llmnr_client_counts=llmnr_client_counts,
        llmnr_server_counts=llmnr_server_counts,
        query_size_stats=query_size_stats,
        response_size_stats=response_size_stats,
        vt_results=vt_results,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        unique_qnames=len(qname_counts),
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
        detections=detections,
        errors=errors,
    )
