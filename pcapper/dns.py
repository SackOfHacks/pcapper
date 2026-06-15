from __future__ import annotations

from .utils import shannon_entropy as _shannon_entropy
import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.request
from collections import Counter, OrderedDict, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .pcap_cache import PcapMeta, get_reader
from .progress import build_statusbar
from .utils import counter_inc, decode_payload, extract_packet_endpoints, memoize_analysis, packet_length, safe_float, set_add_cap, setdict_add

try:
    from scapy.layers.dns import DNS, DNSQR, DNSRR  # type: ignore
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
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

# TLDs disproportionately abused for malware/phishing relative to legitimate use
# (Interisle Phishing Landscape 2025 + Spamhaus domain-reputation). Deliberately
# EXCLUDES the large general-purpose TLDs (.com/.net/.org/.info/.cn/.ru) which
# dominate phishing by raw volume but are overwhelmingly legitimate — flagging
# those would be all false positive. This is the Freenom free-TLD set plus the
# cheap new-gTLDs with the highest per-capita abuse scores. Used as a low-weight
# corroborating signal gated on query VOLUME, never a standalone high alert.
_HIGH_RISK_TLDS = {
    "tk", "ml", "ga", "cf", "gq",  # Freenom free TLDs (historically #1 abused)
    "top", "xyz", "shop", "online", "xin", "click", "link", "work", "gdn",
    "icu", "rest", "cyou", "sbs", "buzz", "monster", "quest", "kim", "country",
    "science", "review", "stream", "download", "loan", "men", "date", "racing",
    "win", "bid", "party", "trade", "webcam", "support", "fit", "cam", "lol",
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

# Match OT keywords only at letter boundaries so short tokens (ied, abb, s7,
# dcs, mms, rtu, opc) don't match as substrings of unrelated words ("ied" in
# "iedge", "applied"; "abb" in "rabbit"). Digits are allowed adjacent so real
# OT hostnames keep matching (plc1, hmi2, rtu05, s7-1200). Longest keyword
# first so multi-token names (s7comm, factorytalk) win over their prefixes.
OT_KEYWORD_RE = re.compile(
    r"(?<![a-z])("
    + "|".join(re.escape(token) for token in sorted(OT_KEYWORDS, key=len, reverse=True))
    + r")(?![a-z])",
    re.IGNORECASE,
)


# IANA DNS OpCodes (https://www.iana.org/assignments/dns-parameters). Opcodes 3
# and 7-15 are reserved/unassigned; observing them on port 53 almost always means
# malformed packets, a non-DNS protocol mis-parsed as DNS, or tunneling/evasion
# rather than a real DNS operation.
_DNS_OPCODE_NAMES: dict[int, str] = {
    0: "QUERY",
    1: "IQUERY",
    2: "STATUS",
    4: "NOTIFY",
    5: "UPDATE",
    6: "DSO",
}


def _opcode_name(opcode: object) -> str:
    try:
        op = int(opcode)
    except Exception:
        return "RESERVED/UNASSIGNED"
    return _DNS_OPCODE_NAMES.get(op, "RESERVED/UNASSIGNED")


# Subset of IANA RR TYPEs used to label query/answer record types in detection
# detail strings so they read for an analyst (e.g. "HTTPS (65)" not "65").
_DNS_QTYPE_NAMES: dict[int, str] = {
    1: "A", 2: "NS", 3: "MD", 4: "MF", 5: "CNAME", 6: "SOA", 7: "MB", 8: "MG",
    9: "MR", 10: "NULL", 11: "WKS", 12: "PTR", 13: "HINFO", 14: "MINFO",
    15: "MX", 16: "TXT", 17: "RP", 18: "AFSDB", 24: "SIG", 25: "KEY", 28: "AAAA",
    29: "LOC", 33: "SRV", 35: "NAPTR", 36: "KX", 37: "CERT", 39: "DNAME",
    41: "OPT", 42: "APL", 43: "DS", 44: "SSHFP", 45: "IPSECKEY", 46: "RRSIG",
    47: "NSEC", 48: "DNSKEY", 49: "DHCID", 50: "NSEC3", 51: "NSEC3PARAM",
    52: "TLSA", 53: "SMIMEA", 55: "HIP", 59: "CDS", 60: "CDNSKEY",
    61: "OPENPGPKEY", 62: "CSYNC", 63: "ZONEMD", 64: "SVCB", 65: "HTTPS",
    99: "SPF", 108: "EUI48", 109: "EUI64", 249: "TKEY", 250: "TSIG",
    251: "IXFR", 252: "AXFR", 253: "MAILB", 254: "MAILA", 255: "ANY",
    256: "URI", 257: "CAA", 32768: "TA", 32769: "DLV",
}


def _qtype_name(qtype: object) -> str:
    try:
        t = int(qtype)
    except Exception:
        return "UNKNOWN"
    if t == 0 or 65280 <= t <= 65535:
        return "RESERVED"
    return _DNS_QTYPE_NAMES.get(t, "UNASSIGNED")


def _qtype_label(qtype: object) -> str:
    try:
        t = int(qtype)
    except Exception:
        return str(qtype)
    return f"{_qtype_name(t)} ({t})"


# QTYPEs that are routine in modern enterprise/OT DNS and must NOT be treated as
# "unusual" (SVCB/HTTPS are issued by every current browser; DNSSEC + CAA + TLSA
# are normal infrastructure). Anything outside this set is genuinely uncommon and
# worth surfacing for triage.
_BENIGN_QTYPES = {
    1, 2, 5, 6, 12, 13, 15, 16, 17, 28, 33, 35, 39, 41, 43, 44, 46, 47, 48,
    49, 50, 51, 52, 53, 59, 60, 61, 62, 63, 64, 65, 99, 256, 257, 255,
}


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
    deterministic_checks: dict[str, list[str]] = field(default_factory=dict)
    resolver_drift: list[dict[str, object]] = field(default_factory=list)
    client_abuse_profiles: list[dict[str, object]] = field(default_factory=list)
    ttl_outliers: list[dict[str, object]] = field(default_factory=list)
    cname_anomalies: list[dict[str, object]] = field(default_factory=list)
    transaction_violations: list[dict[str, object]] = field(default_factory=list)
    amplification_candidates: list[dict[str, object]] = field(default_factory=list)
    timeline: list[dict[str, object]] = field(default_factory=list)
    periodicity_profiles: list[dict[str, object]] = field(default_factory=list)
    benign_context: list[str] = field(default_factory=list)


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


def _vt_lookup_domain(
    domain: str, api_key: str
) -> tuple[Optional[dict[str, object]], Optional[str]]:
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


def _vt_lookup_domains(
    domains: list[str],
    api_key: str,
    progress_cb: Callable[[int, int, str], None] | None = None,
) -> tuple[dict[str, dict[str, object]], list[str]]:
    results: dict[str, dict[str, object]] = {}
    errors: list[str] = []
    if not domains:
        return results, errors

    max_lookups = MAX_VT_LOOKUPS
    if max_lookups <= 0:
        max_lookups = len(domains)

    ordered_domains: list[str] = []
    seen_domains: set[str] = set()
    for domain in domains:
        domain_text = str(domain or "").strip().lower()
        if not domain_text or domain_text in seen_domains:
            continue
        seen_domains.add(domain_text)
        ordered_domains.append(domain_text)

    if len(ordered_domains) > max_lookups:
        errors.append(
            f"VT lookups capped at {max_lookups} domains (set PCAPPER_VT_MAX_LOOKUPS to raise)."
        )
        ordered_domains = ordered_domains[:max_lookups]

    total = len(ordered_domains)
    if total == 0:
        return results, errors

    for idx, domain in enumerate(ordered_domains, start=1):
        cached = _VT_CACHE.get(domain)
        if cached is not None:
            _VT_CACHE.move_to_end(domain)
            results[domain] = cached
        else:
            vt_result, err = _vt_lookup_domain(domain, api_key)
            if vt_result:
                results[domain] = vt_result
                _VT_CACHE[domain] = vt_result
                if len(_VT_CACHE) > MAX_VT_CACHE:
                    _VT_CACHE.popitem(last=False)
            if err:
                errors.append(err)
        if progress_cb is not None:
            try:
                progress_cb(idx, total, domain)
            except Exception:
                pass
        if idx > 1:
            time.sleep(0.05)
    return results, errors


@memoize_analysis
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
    multicast_streams: dict[tuple[str, str, int], dict[str, object]] = defaultdict(
        lambda: {
            "count": 0,
            "bytes": 0,
            "sources": Counter(),
            "first_seen": None,
            "last_seen": None,
        }
    )
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
    # Per-entity client attribution so domain-/qname-scoped detections can name
    # the clients that actually queried the flagged name rather than the
    # capture-wide top DNS talkers. Keyed by the lower-cased query name/base
    # (DNS names are case-insensitive); look up with .lower() against the
    # response-side rrname keys used by answers_by_qname/base_domain_answers.
    base_domain_clients: dict[str, Counter[str]] = defaultdict(Counter)
    qname_clients: dict[str, Counter[str]] = defaultdict(Counter)
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
    qname_query_times: dict[str, list[float]] = defaultdict(list)
    client_qname_times: dict[tuple[str, str], list[float]] = defaultdict(list)
    client_long_queries: Counter[str] = Counter()
    client_txt_queries: Counter[str] = Counter()
    client_nxdomain: Counter[str] = Counter()
    base_domain_priv_pub: dict[str, set[str]] = defaultdict(set)
    client_resolvers: dict[str, Counter[str]] = defaultdict(Counter)
    pending_queries: dict[tuple[str, str, int], dict[str, object]] = {}
    orphan_responses: list[dict[str, object]] = []
    qname_ttl_values: dict[str, list[int]] = defaultdict(list)
    cname_targets: dict[str, set[str]] = defaultdict(set)
    one_off_high_entropy: list[tuple[str, int, int]] = []
    flow_query_bytes: Counter[tuple[str, str]] = Counter()
    flow_response_bytes: Counter[tuple[str, str]] = Counter()
    opcode_counts: Counter[int] = Counter()
    # Per-opcode client/server attribution so opcode findings (zone-management /
    # anomalous) can name the hosts actually using the opcode rather than the
    # capture-wide top DNS talkers. "client" is always the non-server end.
    opcode_clients: dict[int, Counter[str]] = defaultdict(Counter)
    opcode_servers: dict[int, Counter[str]] = defaultdict(Counter)
    flag_counts: Counter[str] = Counter()
    edns0_opt_count = 0
    llmnr_packets = 0
    llmnr_query_packets = 0
    llmnr_response_packets = 0
    llmnr_client_counts: Counter[str] = Counter()
    llmnr_server_counts: Counter[str] = Counter()
    query_sizes: list[int] = []
    response_sizes: list[int] = []

    deterministic_checks: dict[str, list[str]] = {
        "dns_tunneling_indicators": [],
        "dga_like_behavior": [],
        "fast_flux_or_rebinding": [],
        "zone_transfer_attempt": [],
        "resolver_policy_violation": [],
        "dnssec_or_integrity_anomaly": [],
        "amplification_abuse_signal": [],
        "opcode_or_any_abuse": [],
        "dns_beaconing_periodicity": [],
        "likely_benign_cdn_rotation": [],
    }
    timeline: list[dict[str, object]] = []
    benign_context: list[str] = []

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
            pkt_len = packet_length(pkt)
            total_bytes += pkt_len
            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                for low, high, label in packet_len_buckets:
                    if low <= pkt_len <= high:
                        bucket_counts[label] += 1
                        bucket_sizes[label].append(pkt_len)
                        bucket_times[label].append(ts)
                        break

            # Dissect UDP once per packet; reused below for mDNS/LLMNR port
            # checks and multicast stream accounting.
            udp_layer = pkt.getlayer(UDP) if UDP is not None else None  # type: ignore[arg-type]
            if udp_layer is not None:
                udp_packets += 1
            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp_packets += 1

            dns_layer = pkt[DNS]  # type: ignore[index]
            # mDNS/LLMNR use large packets by design (known-answer suppression,
            # service records), so keep them out of the *unicast* query/response
            # size stats — otherwise they trip the "large DNS query/response"
            # heuristics on benign multicast discovery. (Packet counts are
            # unaffected; this only scopes the size distributions.)
            _is_mcast_dns = False
            if udp_layer is not None:
                _sp = int(getattr(udp_layer, "sport", 0) or 0)
                _dp = int(getattr(udp_layer, "dport", 0) or 0)
                if _sp in (5353, 5355) or _dp in (5353, 5355):
                    _is_mcast_dns = True
            if getattr(dns_layer, "qr", 0) == 0:
                query_packets += 1
                if not _is_mcast_dns:
                    query_sizes.append(pkt_len)
            else:
                response_packets += 1
                if not _is_mcast_dns:
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

            src_ip, dst_ip = extract_packet_endpoints(pkt)

            is_mdns = False
            is_llmnr = False
            if udp_layer is not None:
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
                    counter_inc(client_resolvers[src_ip], dst_ip)
                    flow_query_bytes[(src_ip, dst_ip)] += pkt_len
                    op_client, op_server = src_ip, dst_ip
                else:
                    counter_inc(client_counts, dst_ip)
                    counter_inc(server_counts, src_ip)
                    flow_response_bytes[(dst_ip, src_ip)] += pkt_len
                    if rcode is not None and int(rcode) == 3:
                        counter_inc(client_nxdomain, dst_ip)
                    op_client, op_server = dst_ip, src_ip
                if opcode is not None and int(opcode) != 0:
                    counter_inc(opcode_clients[int(opcode)], op_client)
                    counter_inc(opcode_servers[int(opcode)], op_server)

                if src_ip and dst_ip:
                    dns_id = int(getattr(dns_layer, "id", 0) or 0)
                    if getattr(dns_layer, "qr", 0) == 0:
                        pending_queries[(src_ip, dst_ip, dns_id)] = {
                            "ts": ts,
                            "src": src_ip,
                            "dst": dst_ip,
                            "id": dns_id,
                        }
                    else:
                        match_key = (dst_ip, src_ip, dns_id)
                        if match_key in pending_queries:
                            pending_queries.pop(match_key, None)
                        elif dns_id != 0:
                            orphan_responses.append(
                                {
                                    "ts": ts,
                                    "src": src_ip,
                                    "dst": dst_ip,
                                    "id": dns_id,
                                }
                            )

                if udp_layer is not None:
                    if dst_ip.startswith("224.") or dst_ip.startswith("ff02::"):
                        udp_multicast_packets += 1
                        dport = int(getattr(udp_layer, "dport", 0) or 0)
                        key = (dst_ip, "UDP", dport)
                        # NB: do not name this `stream` — that shadows the
                        # progress-bar stream from get_reader() and breaks the
                        # status update on every subsequent packet.
                        mstream = multicast_streams[key]
                        mstream["count"] = int(mstream["count"]) + 1
                        mstream["bytes"] = int(mstream["bytes"]) + pkt_len
                        counter_inc(mstream["sources"], src_ip)  # type: ignore[index]
                        if ts is not None:
                            if (
                                mstream["first_seen"] is None
                                or ts < mstream["first_seen"]
                            ):  # type: ignore[operator]
                                mstream["first_seen"] = ts
                            if mstream["last_seen"] is None or ts > mstream["last_seen"]:  # type: ignore[operator]
                                mstream["last_seen"] = ts

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
                        raw_name
                        if isinstance(raw_name, (bytes, bytearray))
                        else str(raw_name).encode("utf-8", errors="ignore"),
                        encoding="utf-8",
                    )
                    # DNS names are case-insensitive (RFC 4343). Fold to a
                    # canonical lower-case form so the same domain isn't split
                    # across the "Most Queried Domains" view by 0x20 case
                    # randomization (e.g. ASPMX.L.GOOGLE.com vs aspmx.l.google.com),
                    # which fragments query volume and hinders triage.
                    name = name.strip(".").lower()
                    if name:
                        counter_inc(qname_counts, name)
                        counter_inc(base_domain_counts, _base_domain(name))
                        # Attribute only genuine queriers: this block also runs
                        # for the question echoed in a response, where src_ip is
                        # the resolver, not a client (qr==1).
                        if src_ip and getattr(dns_layer, "qr", 0) == 0:
                            counter_inc(base_domain_clients[_base_domain(name)], src_ip)
                            counter_inc(qname_clients[name], src_ip)
                        tld = _tld(name)
                        counter_inc(tld_counts, tld)
                        if tld in INTERNAL_TLDS and not is_mdns:
                            counter_inc(local_unicast_qname_counts, name)
                        lower_name = name.lower()
                        ot_hits = OT_KEYWORD_RE.findall(lower_name)
                        if ot_hits:
                            counter_inc(ot_qname_counts, name)
                            for keyword in ot_hits:
                                counter_inc(ot_keyword_counts, keyword.lower())
                        if name in qname_entropy or len(qname_entropy) < MAX_DNS_UNIQUE:
                            entropy_val = int(_shannon_entropy(name) * 100)
                            qname_entropy[name] = entropy_val
                            if src_ip:
                                client_entropy_scores[src_ip].append(
                                    entropy_val / 100.0
                                )
                        if name in qname_lengths or len(qname_lengths) < MAX_DNS_UNIQUE:
                            qname_lengths[name] = len(name)
                        if is_mdns:
                            counter_inc(mdns_qname_counts, name)
                        if src_ip and getattr(dns_layer, "qr", 0) == 0:
                            setdict_add(
                                client_unique_qnames,
                                src_ip,
                                name,
                                max_values=MAX_DNS_UNIQUE,
                            )
                            if len(name) >= 50:
                                counter_inc(client_long_queries, src_ip)
                            if ts is not None:
                                if (
                                    name in qname_query_times
                                    or len(qname_query_times) < MAX_DNS_UNIQUE
                                ):
                                    q_times = qname_query_times[name]
                                    if len(q_times) < 512:
                                        q_times.append(ts)
                                pair_key = (src_ip, name)
                                if (
                                    pair_key in client_qname_times
                                    or len(client_qname_times) < MAX_DNS_UNIQUE
                                ):
                                    cq_times = client_qname_times[pair_key]
                                    if len(cq_times) < 256:
                                        cq_times.append(ts)
                    qtype = getattr(qd, "qtype", None)
                    if qtype is not None:
                        counter_inc(qtype_counts, int(qtype))
                        counter_inc(type_counts, str(qtype))
                        if is_mdns:
                            counter_inc(mdns_qtype_counts, int(qtype))
                        if int(qtype) in {251, 252} and name:
                            set_add_cap(
                                zone_transfer_requests, name, max_size=MAX_DNS_UNIQUE
                            )
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
                                rrname_bytes = (
                                    rrname
                                    if isinstance(rrname, (bytes, bytearray))
                                    else str(rrname).encode("utf-8", errors="ignore")
                                )
                                rrname_str = decode_payload(
                                    rrname_bytes, encoding="utf-8"
                                ).strip(".")
                                setdict_add(
                                    answers_by_qname,
                                    rrname_str,
                                    str(rdata),
                                    max_values=MAX_DNS_UNIQUE,
                                )
                                rr_ttl = int(getattr(rr, "ttl", 0) or 0)
                                if rr_ttl > 0:
                                    qname_ttl_values[rrname_str].append(rr_ttl)
                                if rrtype in {1, 28}:  # A or AAAA
                                    setdict_add(
                                        base_domain_answers,
                                        _base_domain(rrname_str),
                                        str(rdata),
                                        max_values=MAX_DNS_UNIQUE,
                                    )
                                    try:
                                        ip_val = ipaddress.ip_address(str(rdata))
                                        if ip_val.is_private:
                                            base_domain_priv_pub[
                                                _base_domain(rrname_str)
                                            ].add("private")
                                        elif ip_val.is_global:
                                            base_domain_priv_pub[
                                                _base_domain(rrname_str)
                                            ].add("public")
                                    except Exception:
                                        pass
                                if is_mdns:
                                    if rrtype == 33:
                                        counter_inc(mdns_service_counts, rrname_str)
                                if rrtype == 5 and rrname_str:
                                    try:
                                        target = str(rdata).strip(".")
                                    except Exception:
                                        target = str(rdata)
                                    if target:
                                        set_add_cap(
                                            cname_targets[rrname_str],
                                            target,
                                            max_size=MAX_DNS_UNIQUE,
                                        )
                                # PTR answers advertise service instances (mDNS/
                                # DNS-SD). This was previously nested inside the
                                # rrtype==5 (CNAME) branch and so never ran, since
                                # a record cannot be both CNAME and PTR.
                                if rrtype == 12:
                                    try:
                                        service_name = str(rdata).strip(".")
                                    except Exception:
                                        service_name = str(rdata)
                                    if service_name and (
                                        "_tcp" in service_name
                                        or "_udp" in service_name
                                    ):
                                        counter_inc(
                                            mdns_service_counts, service_name
                                        )
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
        rate = (
            (count / duration_seconds)
            if duration_seconds and duration_seconds > 0
            else 0.0
        )

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

        packet_length_stats.append(
            {
                "bucket": label,
                "count": count,
                "avg": avg_size,
                "min": min_size,
                "max": max_size,
                "rate": rate,
                "pct": pct,
                "burst_rate": burst_rate,
                "burst_start": burst_start,
            }
        )

    query_size_stats = _size_stats(query_sizes)
    response_size_stats = _size_stats(response_sizes)
    public_resolver_counts: Counter[str] = Counter(
        {ip: count for ip, count in server_counts.items() if ip in PUBLIC_DNS_RESOLVERS}
    )

    detections: list[dict[str, str | list[tuple[str, int]] | int]] = []
    if total_packets == 0:
        detections.append(
            {
                "type": "no_dns",
                "severity": "info",
                "summary": "No DNS traffic detected",
                "details": "DNS not observed in capture.",
            }
        )
    else:
        # A flood is a *sustained* high rate, not a few packets captured in a
        # sub-second window. Guard against tiny/short captures where dividing by
        # a near-zero duration produces a meaningless pkt/s (e.g. a 2-packet AXFR
        # capture reporting thousands of pkt/s).
        if (
            duration_seconds
            and duration_seconds >= 1.0
            and total_packets >= 1000
        ):
            pps = total_packets / duration_seconds
            if pps > 2000:
                detections.append(
                    {
                        "type": "dns_flood",
                        "severity": "warning",
                        "summary": f"High DNS rate observed ({pps:.1f} pkt/s)",
                        "details": "Excessive DNS traffic may indicate abuse or misconfiguration.",
                        "top_clients": client_counts.most_common(3),
                        "top_servers": server_counts.most_common(3),
                    }
                )

        nxdomain = rcode_counts.get("3", 0)
        if nxdomain > 100 and total_packets > 0 and (nxdomain / total_packets) > 0.3:
            detections.append(
                {
                    "type": "dns_nxdomain",
                    "severity": "warning",
                    "summary": f"High NXDOMAIN rate ({nxdomain} responses)",
                    "details": "Potential DGA, misconfiguration, or scanning.",
                    # Evidence is the clients that actually received NXDOMAINs,
                    # not capture-wide top talkers — a DGA host is frequently
                    # low-volume and would be hidden behind a busy benign client.
                    "top_clients": client_nxdomain.most_common(3),
                    "top_servers": server_counts.most_common(3),
                }
            )
            deterministic_checks["dga_like_behavior"].append(
                f"NXDOMAIN ratio high: {nxdomain}/{total_packets}"
            )

        servfail = rcode_counts.get("2", 0)
        if servfail > 50 and total_packets > 0 and (servfail / total_packets) > 0.2:
            detections.append(
                {
                    "type": "dns_servfail",
                    "severity": "warning",
                    "summary": f"High SERVFAIL rate ({servfail} responses)",
                    "details": "Resolver errors or upstream issues observed.",
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                }
            )

        refused = rcode_counts.get("5", 0)
        if refused > 50 and total_packets > 0 and (refused / total_packets) > 0.2:
            detections.append(
                {
                    "type": "dns_refused",
                    "severity": "warning",
                    "summary": f"High REFUSED rate ({refused} responses)",
                    "details": "Possible scanning or access control enforcement.",
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                }
            )

        suspicious_qnames = [
            name
            for name, count in qname_counts.items()
            if qname_lengths.get(name, 0) > 50
            or (qname_entropy.get(name, 0) / 100) > 4.0
        ]
        if len(suspicious_qnames) > 30:
            detections.append(
                {
                    "type": "dns_tunnel_indicator",
                    "severity": "warning",
                    "summary": "Potential DNS tunneling behavior",
                    "details": "Many long/high-entropy query names detected.",
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                }
            )
            deterministic_checks["dns_tunneling_indicators"].append(
                f"High-entropy/long qnames count={len(suspicious_qnames)}"
            )

        client_suspects: list[str] = []
        suspect_client_ips: list[str] = []
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
                suspect_client_ips.append(client)
        if client_suspects:
            detections.append(
                {
                    "type": "dns_client_dga",
                    "severity": "warning",
                    "summary": "Clients with DGA/tunnel-like DNS patterns",
                    "details": "; ".join(client_suspects[:6]),
                    # Evidence must be the flagged suspects, not capture-wide
                    # talkers — the heavy benign client is not the DGA host.
                    "top_clients": [
                        (ip, client_counts.get(ip, 0)) for ip in suspect_client_ips[:3]
                    ],
                    "top_servers": server_counts.most_common(3),
                }
            )
            deterministic_checks["dga_like_behavior"].extend(client_suspects[:8])

        for base, count in sorted(
            ((b, c) for b, c in base_domain_counts.items() if c > 1000),
            key=lambda item: item[1],
            reverse=True,
        )[:8]:
            if count > 1000:
                base_clients = base_domain_clients.get(base) or base_domain_clients.get(
                    base.lower()
                )
                detections.append(
                    {
                        "type": "dns_domain_concentration",
                        "severity": "info",
                        "summary": f"High query volume for {base} ({count} queries)",
                        "details": "Check for beaconing or resolver issues.",
                        # Clients that actually queried this domain, not the
                        # capture-wide top talkers (fall back only if unknown).
                        "top_clients": (
                            base_clients.most_common(3)
                            if base_clients
                            else client_counts.most_common(3)
                        ),
                        "top_servers": server_counts.most_common(3),
                    }
                )

        for qname, answers in sorted(
            ((q, a) for q, a in answers_by_qname.items() if len(a) >= 6),
            key=lambda item: len(item[1]),
            reverse=True,
        )[:8]:
            if len(answers) >= 6:
                name_clients = qname_clients.get(qname) or qname_clients.get(
                    qname.lower()
                )
                detections.append(
                    {
                        "type": "dns_poisoning_indicator",
                        "severity": "warning",
                        "summary": f"Multiple answers observed for {qname}",
                        "details": f"Observed {len(answers)} distinct answers; verify expected CDN/rotation.",
                        # Clients that queried this exact name (may be empty when
                        # the name is only a CNAME target — fall back to capture-
                        # wide so the resolver evidence still has a client view).
                        "top_clients": (
                            name_clients.most_common(3)
                            if name_clients
                            else client_counts.most_common(3)
                        ),
                        "top_servers": server_counts.most_common(3),
                    }
                )

        for base, answers in sorted(
            ((b, a) for b, a in base_domain_answers.items() if len(a) >= 10),
            key=lambda item: len(item[1]),
            reverse=True,
        )[:8]:
            if len(answers) >= 10:
                base_clients = base_domain_clients.get(base) or base_domain_clients.get(
                    base.lower()
                )
                detections.append(
                    {
                        "type": "dns_fast_flux",
                        "severity": "warning",
                        "summary": f"Fast-flux indicator for {base}",
                        "details": f"Observed {len(answers)} unique A/AAAA answers.",
                        # Clients that queried this domain, not capture-wide
                        # talkers (fall back only if unknown).
                        "top_clients": (
                            base_clients.most_common(3)
                            if base_clients
                            else client_counts.most_common(3)
                        ),
                        "top_servers": server_counts.most_common(3),
                    }
                )

        rebinding_domains = [
            base
            for base, flags in base_domain_priv_pub.items()
            if "private" in flags and "public" in flags
        ]
        if rebinding_domains:
            sample = ", ".join(sorted(rebinding_domains)[:5])
            detections.append(
                {
                    "type": "dns_rebinding",
                    "severity": "warning",
                    "summary": "Potential DNS rebinding behavior",
                    "details": f"Domains with both private and public answers: {sample}",
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                }
            )
            deterministic_checks["fast_flux_or_rebinding"].append(
                f"Rebinding domains: {sample}"
            )

        if zone_transfer_requests:
            sample = ", ".join(sorted(list(zone_transfer_requests))[:5])
            detections.append(
                {
                    "type": "dns_zone_transfer",
                    "severity": "warning",
                    "summary": "Zone transfer attempt detected",
                    "details": f"AXFR/IXFR requested for: {sample}",
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                }
            )
            deterministic_checks["zone_transfer_attempt"].append(sample)

        txt_queries = qtype_counts.get(16, 0)
        if (
            txt_queries > 100
            and total_packets > 0
            and (txt_queries / total_packets) > 0.2
        ):
            txt_sample = ", ".join(sorted(list(txt_query_names))[:5])
            txt_details = (
                "TXT-heavy traffic can indicate data exfiltration or policy misuse."
            )
            if txt_sample:
                txt_details += f" Sample TXT names: {txt_sample}"
            detections.append(
                {
                    "type": "dns_txt_exfil",
                    "severity": "warning",
                    "summary": f"High TXT query volume ({txt_queries} queries)",
                    "details": txt_details,
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                }
            )
            deterministic_checks["dns_tunneling_indicators"].append(
                f"TXT-heavy ratio: {txt_queries}/{total_packets}"
            )

        ptr_queries = qtype_counts.get(12, 0)
        if (
            ptr_queries > 50
            and total_packets > 0
            and (ptr_queries / total_packets) > 0.2
        ):
            ptr_names = [
                name
                for name in qname_counts.keys()
                if name.endswith("in-addr.arpa") or name.endswith("ip6.arpa")
            ]
            ptr_sample = ", ".join(sorted(ptr_names)[:5])
            details = "High PTR/reverse lookup volume may indicate scanning or asset discovery."
            if ptr_sample:
                details += f" Sample PTR names: {ptr_sample}"
            detections.append(
                {
                    "type": "dns_ptr_sweep",
                    "severity": "warning",
                    "summary": f"High PTR query volume ({ptr_queries} queries)",
                    "details": details,
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                }
            )

        # Endpoints almost never look up MX records; a host issuing many MX
        # queries is enumerating mail servers — classic spam-bot / mass-mailer /
        # malspam behaviour (e.g. Hancitor) or mail-infrastructure recon.
        mx_queries = int(qtype_counts.get(15, 0) or 0)
        if mx_queries >= 30:
            mx_clients = client_counts.most_common(3)
            top_client = mx_clients[0][0] if mx_clients else "-"
            detections.append(
                {
                    "type": "dns_mx_enumeration",
                    "severity": "warning",
                    "summary": f"High MX query volume ({mx_queries} queries)",
                    "details": (
                        f"{mx_queries} MX lookups observed (top client {top_client}). "
                        "Endpoints rarely query MX; this indicates mail-server "
                        "enumeration — spam-bot/mass-mailer (e.g. malspam) or recon. "
                        "Correlate with --smtp/--email for outbound mail."
                    ),
                    "top_clients": mx_clients,
                    "top_servers": server_counts.most_common(3),
                }
            )

        # mDNS legitimately uses QTYPE 255 (ANY) for resolution; only unicast
        # ANY is a recon/amplification signal, so subtract the mDNS share.
        any_queries = int(qtype_counts.get(255, 0) or 0) - int(
            mdns_qtype_counts.get(255, 0) or 0
        )
        if any_queries > 20:
            detections.append(
                {
                    "type": "dns_any_abuse",
                    "severity": "warning",
                    "summary": f"ANY query usage observed ({any_queries})",
                    "details": "ANY queries can indicate reconnaissance or amplification abuse.",
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                }
            )
            deterministic_checks["opcode_or_any_abuse"].append(
                f"ANY query volume observed count={int(any_queries)}"
            )

        # NULL (qtype 10) records have no legitimate client use and are the
        # canonical carrier for iodine-style DNS tunneling — flag any volume.
        null_queries = int(qtype_counts.get(10, 0) or 0)
        if null_queries >= 5:
            detections.append(
                {
                    "type": "dns_null_records",
                    "severity": "warning",
                    "summary": f"NULL-record queries observed ({null_queries})",
                    "details": (
                        f"{null_queries} NULL (qtype 10) queries. NULL records have no "
                        "legitimate client use and are the default carrier for iodine "
                        "DNS tunneling; correlate with high-entropy/long qnames and "
                        "single-domain query concentration."
                    ),
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                }
            )
            deterministic_checks["dns_tunneling_indicators"].append(
                f"NULL-record (qtype 10) queries: {null_queries}"
            )

        unusual_qtypes = [
            (qtype, count)
            for qtype, count in qtype_counts.items()
            if int(qtype) not in _BENIGN_QTYPES and int(qtype) != 10
        ]
        if unusual_qtypes:
            unusual_total = sum(count for _, count in unusual_qtypes)
            if unusual_total >= 20:
                top_unusual = ", ".join(
                    f"{_qtype_label(qtype)} x{count}"
                    for qtype, count in sorted(
                        unusual_qtypes, key=lambda x: x[1], reverse=True
                    )[:6]
                )
                detections.append(
                    {
                        "type": "dns_unusual_qtypes",
                        "severity": "info",
                        "summary": "Unusual DNS query record types observed",
                        "details": (
                            f"Uncommon/obsolete record types ({unusual_total} queries): "
                            f"{top_unusual}. Rare types can indicate recon, tunneling, "
                            "or non-DNS traffic parsed as DNS."
                        ),
                        "top_clients": client_counts.most_common(3),
                        "top_servers": server_counts.most_common(3),
                    }
                )

        # OpCode analysis. Classify into two buckets rather than lumping every
        # non-zero opcode together: legitimate zone-management ops (NOTIFY/UPDATE/
        # DSO) vs genuinely anomalous ones. IQUERY is obsolete (RFC 3425), STATUS
        # is rarely used by real clients, and opcodes 3 / 7-15 are reserved or
        # unassigned -- on port 53 those usually mean malformed packets, a non-DNS
        # protocol parsed as DNS, or deliberate tunneling/evasion.
        if opcode_counts:
            anomalous_ops = {
                int(op): int(c)
                for op, c in opcode_counts.items()
                if int(op) in (1, 2, 3) or int(op) >= 7
            }
            mgmt_ops = {
                int(op): int(c)
                for op, c in opcode_counts.items()
                if int(op) in (4, 5, 6)
            }
            if anomalous_ops:
                detail = ", ".join(
                    f"{_opcode_name(op)} (opcode {op}) x{c}"
                    for op, c in sorted(anomalous_ops.items())
                )
                reserved_present = any(op == 3 or op >= 7 for op in anomalous_ops)
                explanation = (
                    "IQUERY is obsolete (RFC 3425) and STATUS is rarely used by "
                    "legitimate clients."
                )
                if reserved_present:
                    explanation = (
                        "Reserved/unassigned opcodes on port 53 typically indicate "
                        "malformed packets, non-DNS traffic parsed as DNS, or "
                        "tunneling/evasion. " + explanation
                    )
                anomalous_clients: Counter[str] = Counter()
                anomalous_servers: Counter[str] = Counter()
                for op in anomalous_ops:
                    anomalous_clients.update(opcode_clients.get(op, {}))
                    anomalous_servers.update(opcode_servers.get(op, {}))
                detections.append(
                    {
                        "type": "dns_anomalous_opcode",
                        "severity": "warning",
                        "summary": "Anomalous/obsolete DNS opcodes observed",
                        "details": f"{detail}. {explanation}",
                        # Hosts that actually used the anomalous opcode(s), not
                        # the capture-wide top DNS talkers.
                        "top_clients": (
                            anomalous_clients.most_common(3)
                            if anomalous_clients
                            else client_counts.most_common(3)
                        ),
                        "top_servers": (
                            anomalous_servers.most_common(3)
                            if anomalous_servers
                            else server_counts.most_common(3)
                        ),
                    }
                )
                deterministic_checks["opcode_or_any_abuse"].append(
                    "Anomalous/obsolete opcodes: " + detail
                )
            if mgmt_ops:
                detail = ", ".join(
                    f"{_opcode_name(op)} (opcode {op}) x{c}"
                    for op, c in sorted(mgmt_ops.items())
                )
                mgmt_clients: Counter[str] = Counter()
                mgmt_servers: Counter[str] = Counter()
                for op in mgmt_ops:
                    mgmt_clients.update(opcode_clients.get(op, {}))
                    mgmt_servers.update(opcode_servers.get(op, {}))
                detections.append(
                    {
                        "type": "dns_dynamic_updates",
                        "severity": "warning",
                        "summary": "DNS zone-management opcodes observed",
                        "details": (
                            f"{detail}. NOTIFY/UPDATE/DSO are legitimate zone-management "
                            "operations (often DHCP-driven dynamic DNS); confirm the "
                            "clients are authorized DNS infrastructure and not "
                            "unexpected hosts registering or mutating records."
                        ),
                        # Hosts that actually issued the zone-management opcode(s),
                        # not the capture-wide top DNS talkers.
                        "top_clients": (
                            mgmt_clients.most_common(3)
                            if mgmt_clients
                            else client_counts.most_common(3)
                        ),
                        "top_servers": (
                            mgmt_servers.most_common(3)
                            if mgmt_servers
                            else server_counts.most_common(3)
                        ),
                    }
                )
                deterministic_checks["opcode_or_any_abuse"].append(
                    "Zone-management opcodes: " + detail
                )

        if tcp_packets and total_packets > 0:
            tcp_ratio = tcp_packets / max(total_packets, 1)
            if tcp_ratio >= 0.2 and total_packets >= 200:
                detections.append(
                    {
                        "type": "dns_tcp_heavy",
                        "severity": "info",
                        "summary": "Elevated DNS-over-TCP usage",
                        "details": f"TCP DNS accounts for {tcp_ratio * 100:.1f}% of packets.",
                        "top_clients": client_counts.most_common(3),
                        "top_servers": server_counts.most_common(3),
                    }
                )

        if query_size_stats:
            query_p95 = int(query_size_stats.get("p95", 0) or 0)
            if query_p95 > 300:
                detections.append(
                    {
                        "type": "dns_large_queries",
                        "severity": "warning",
                        "summary": "Large DNS query payloads observed",
                        "details": f"Query p95 size {query_p95} bytes; max {query_size_stats.get('max')} bytes.",
                        "top_clients": client_counts.most_common(3),
                        "top_servers": server_counts.most_common(3),
                    }
                )

        if response_size_stats:
            stats = response_size_stats
            if int(stats.get("p95", 0) or 0) > 1232:
                detections.append(
                    {
                        "type": "dns_large_responses",
                        "severity": "warning",
                        "summary": "Large DNS responses observed",
                        "details": f"Response p95 size {stats.get('p95')} bytes; max {stats.get('max')} bytes.",
                        "top_clients": client_counts.most_common(3),
                        "top_servers": server_counts.most_common(3),
                    }
                )

        tc_count = int(flag_counts.get("TC", 0) or 0)
        if tc_count > 10 and total_packets > 0 and (tc_count / total_packets) > 0.02:
            detections.append(
                {
                    "type": "dns_truncation",
                    "severity": "info",
                    "summary": "Truncated DNS responses observed",
                    "details": f"TC flag set in {tc_count} packets; may indicate large responses or fragmentation.",
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                }
            )

        if public_resolver_counts:
            resolver_details = ", ".join(
                f"{ip}({count})[{PUBLIC_DNS_RESOLVERS.get(ip, '-')}]"
                for ip, count in public_resolver_counts.most_common(5)
            )
            # Attribute the finding to the clients that actually queried a
            # public resolver, not the capture-wide top DNS talkers. Counting
            # only public-resolver queries keeps the evidence consistent with
            # the per-resolver packet counts in the details string.
            public_resolver_clients: Counter[str] = Counter()
            for client, resolver_counter in client_resolvers.items():
                hits = sum(
                    cnt
                    for resolver, cnt in resolver_counter.items()
                    if resolver in PUBLIC_DNS_RESOLVERS
                )
                if hits:
                    public_resolver_clients[client] = hits
            detections.append(
                {
                    "type": "dns_public_resolvers",
                    "severity": "warning",
                    "summary": "Public DNS resolvers observed",
                    "details": f"Public resolvers: {resolver_details}. In OT/ICS networks, direct public DNS usage is often a policy violation.",
                    "top_clients": public_resolver_clients.most_common(3),
                }
            )
            deterministic_checks["resolver_policy_violation"].append(resolver_details)

        if local_unicast_qname_counts:
            sample = ", ".join(sorted(list(local_unicast_qname_counts))[:5])
            detections.append(
                {
                    "type": "dns_local_unicast",
                    "severity": "info",
                    "summary": "Unicast queries for local TLDs observed",
                    "details": f"Local-only TLDs (e.g., .local/.lan) queried via unicast DNS: {sample}",
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                }
            )

        # High-risk-TLD query volume: a host resolving many distinct domains
        # under the disproportionately-abused TLDs is a malware/phishing-staging
        # or DGA-adjacent pattern. Gated on DISTINCT-domain count to avoid the
        # false positive a single benign .xyz/.shop lookup would cause.
        high_risk_domains = {
            name
            for name in qname_counts
            if _tld(name) in _HIGH_RISK_TLDS
        }
        if len(high_risk_domains) >= 5:
            tld_breakdown = Counter(_tld(n) for n in high_risk_domains)
            sample = ", ".join(sorted(high_risk_domains)[:6])
            detections.append(
                {
                    "type": "dns_high_risk_tld",
                    "severity": "warning",
                    "summary": "High volume of queries to abuse-prone TLDs",
                    "details": (
                        f"{len(high_risk_domains)} distinct domains queried under "
                        f"high-abuse TLDs ({', '.join(f'.{t}({c})' for t, c in tld_breakdown.most_common(6))}); "
                        f"e.g. {sample}. Disproportionately used for malware/phishing "
                        "(Interisle/Spamhaus) — correlate with --http/--tls destinations."
                    ),
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                }
            )

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
            detections.append(
                {
                    "type": "dns_ot_naming",
                    "severity": "info",
                    "summary": "OT/ICS asset naming detected in DNS",
                    "details": details,
                    "top_clients": client_counts.most_common(3),
                    "top_servers": server_counts.most_common(3),
                }
            )

        if mdns_packets > 0:
            detections.append(
                {
                    "type": "mdns_present",
                    "severity": "info",
                    "summary": f"mDNS traffic observed ({mdns_packets} packets)",
                    "details": "mDNS/Bonjour discovery seen; in OT/ICS networks this can expand broadcast attack surface.",
                    "top_clients": mdns_client_counts.most_common(3),
                    "top_servers": mdns_server_counts.most_common(3),
                }
            )

            if mdns_packets > 1000:
                detections.append(
                    {
                        "type": "mdns_chatty",
                        "severity": "warning",
                        "summary": "High mDNS volume",
                        "details": f"Observed {mdns_packets} mDNS packets; potential chatter or misconfiguration.",
                        "top_clients": mdns_client_counts.most_common(3),
                    }
                )

            for name, count in mdns_qname_counts.items():
                if name.endswith(".local") and count > 200:
                    detections.append(
                        {
                            "type": "mdns_burst",
                            "severity": "warning",
                            "summary": f"High mDNS query volume for {name}",
                            "details": "Investigate for discovery storms or spoofing.",
                            "top_clients": mdns_client_counts.most_common(3),
                        }
                    )
                    break

            if mdns_unicast_packets > 0:
                detections.append(
                    {
                        "type": "mdns_unicast",
                        "severity": "warning",
                        "summary": "Unicast mDNS traffic detected",
                        "details": f"Observed {mdns_unicast_packets} mDNS packets sent via unicast; review for abuse or misconfiguration.",
                        "top_clients": mdns_client_counts.most_common(3),
                        "top_servers": mdns_server_counts.most_common(3),
                    }
                )

            if udp_multicast_packets > 0:
                detections.append(
                    {
                        "type": "udp_multicast_streams",
                        "severity": "warning",
                        "summary": "UDP multicast streams detected",
                        "details": f"Observed {udp_multicast_packets} UDP multicast DNS packets; review for discovery abuse.",
                        "top_clients": client_counts.most_common(3),
                        "top_servers": server_counts.most_common(3),
                    }
                )

            allowed_types = {1, 28, 12, 16, 33}
            unusual_mdns = [
                (t, c) for t, c in mdns_qtype_counts.items() if t not in allowed_types
            ]
            if unusual_mdns:
                top_unusual = ", ".join(
                    f"{t}({c})"
                    for t, c in sorted(unusual_mdns, key=lambda x: x[1], reverse=True)[
                        :5
                    ]
                )
                detections.append(
                    {
                        "type": "mdns_unusual_qtypes",
                        "severity": "warning",
                        "summary": "Unusual mDNS query record types detected",
                        "details": f"Observed uncommon mDNS qtypes: {top_unusual}",
                        "top_clients": mdns_client_counts.most_common(3),
                    }
                )

            mdns_txt_queries = mdns_qtype_counts.get(16, 0)
            if mdns_txt_queries > 0:
                detections.append(
                    {
                        "type": "mdns_txt_records",
                        "severity": "warning",
                        "summary": "mDNS TXT Record Analysis",
                        "details": f"Observed {mdns_txt_queries} mDNS TXT queries; review for metadata leakage or abuse.",
                        "top_clients": mdns_client_counts.most_common(3),
                        "top_servers": mdns_server_counts.most_common(3),
                    }
                )

        if llmnr_packets > 0:
            detections.append(
                {
                    "type": "llmnr_present",
                    "severity": "warning",
                    "summary": f"LLMNR traffic observed ({llmnr_packets} packets)",
                    "details": "LLMNR can be abused for spoofing/poisoning; in OT/ICS environments it is a common lateral movement risk.",
                    "top_clients": llmnr_client_counts.most_common(3),
                    "top_servers": llmnr_server_counts.most_common(3),
                }
            )

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
                domain
                for domain, _count in sorted(
                    domain_counts.items(), key=lambda item: item[1], reverse=True
                )
            ]
            with build_statusbar(
                path, enabled=show_status, desc="VirusTotal lookups"
            ) as vt_status:
                vt_status.update(0)

                def _vt_progress(done: int, total: int, _domain: str) -> None:
                    pct = 100 if total <= 0 else int((done / total) * 100)
                    vt_status.update(pct)

                vt_results, vt_errors = _vt_lookup_domains(
                    ranked_domains, api_key, progress_cb=_vt_progress
                )
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
                severity = (
                    "warning"
                    if any(
                        int(item.get("malicious", 0) or 0) > 0
                        or int(item.get("suspicious", 0) or 0) > 0
                        for item in vt_findings
                    )
                    else "info"
                )
                detections.append(
                    {
                        "type": "dns_vt_hits",
                        "severity": severity,
                        "summary": "VirusTotal DNS reputation",
                        "vt_findings": vt_findings,
                    }
                )

    for domain, answers in base_domain_answers.items():
        if len(answers) >= 15:
            deterministic_checks["fast_flux_or_rebinding"].append(
                f"{domain} has {len(answers)} unique answers"
            )

    ttl_outliers: list[dict[str, object]] = []
    for qname, ttls in qname_ttl_values.items():
        if len(ttls) < 5:
            continue
        unique_ttl = len(set(ttls))
        min_ttl = min(ttls)
        max_ttl = max(ttls)
        if unique_ttl >= 4 or min_ttl <= 30:
            ttl_outliers.append(
                {
                    "qname": qname,
                    "samples": len(ttls),
                    "unique_ttl": unique_ttl,
                    "min_ttl": min_ttl,
                    "max_ttl": max_ttl,
                }
            )
    ttl_outliers.sort(
        key=lambda item: (int(item.get("unique_ttl", 0)), int(item.get("samples", 0))),
        reverse=True,
    )
    for item in ttl_outliers[:20]:
        deterministic_checks["fast_flux_or_rebinding"].append(
            f"TTL outlier {item.get('qname')} unique={item.get('unique_ttl')} min={item.get('min_ttl')} max={item.get('max_ttl')}"
        )

    cname_anomalies: list[dict[str, object]] = []
    for qname, targets in cname_targets.items():
        if len(targets) >= 4:
            cname_anomalies.append(
                {
                    "qname": qname,
                    "target_count": len(targets),
                    "targets": sorted(targets)[:8],
                }
            )
            deterministic_checks["dnssec_or_integrity_anomaly"].append(
                f"CNAME target churn {qname} targets={len(targets)}"
            )
    cname_anomalies.sort(
        key=lambda item: int(item.get("target_count", 0)), reverse=True
    )

    transaction_violations: list[dict[str, object]] = orphan_responses[:120]
    for item in transaction_violations[:20]:
        deterministic_checks["dnssec_or_integrity_anomaly"].append(
            f"Orphan response id={item.get('id')} {item.get('src')}->{item.get('dst')}"
        )

    amplification_candidates: list[dict[str, object]] = []
    for flow, qbytes in flow_query_bytes.items():
        rbytes = int(flow_response_bytes.get(flow, 0) or 0)
        if qbytes <= 0 or rbytes <= 0:
            continue
        ratio = rbytes / max(qbytes, 1)
        if ratio >= 8.0 and rbytes >= 20_000:
            amplification_candidates.append(
                {
                    "client": flow[0],
                    "resolver": flow[1],
                    "query_bytes": qbytes,
                    "response_bytes": rbytes,
                    "ratio": round(ratio, 2),
                }
            )
            deterministic_checks["amplification_abuse_signal"].append(
                f"{flow[0]}->{flow[1]} amplification ratio={ratio:.2f}"
            )
    amplification_candidates.sort(
        key=lambda item: float(item.get("ratio", 0.0) or 0.0), reverse=True
    )

    resolver_drift: list[dict[str, object]] = []
    for client, resolver_counter in client_resolvers.items():
        if sum(resolver_counter.values()) < 20:
            continue
        resolvers = list(resolver_counter.keys())
        if len(resolvers) < 2:
            continue
        has_public = any(ip in PUBLIC_DNS_RESOLVERS for ip in resolvers)
        has_private = False
        for ip in resolvers:
            try:
                if ipaddress.ip_address(ip).is_private:
                    has_private = True
                    break
            except Exception:
                continue
        if len(resolvers) >= 3 or (has_public and has_private):
            resolver_drift.append(
                {
                    "client": client,
                    "resolver_count": len(resolvers),
                    "public": has_public,
                    "private": has_private,
                    "top_resolvers": resolver_counter.most_common(5),
                }
            )
            deterministic_checks["resolver_policy_violation"].append(
                f"{client} resolver drift count={len(resolvers)} public={has_public} private={has_private}"
            )
    resolver_drift.sort(
        key=lambda item: int(item.get("resolver_count", 0)), reverse=True
    )

    client_abuse_profiles: list[dict[str, object]] = []
    for client, total in client_counts.items():
        if total < 15:
            continue
        unique = len(client_unique_qnames.get(client, set()))
        ratio = unique / max(total, 1)
        entropies = client_entropy_scores.get(client, [])
        avg_entropy = (sum(entropies) / len(entropies)) if entropies else 0.0
        profile = {
            "client": client,
            "queries": int(total),
            "unique_qnames": unique,
            "unique_ratio": round(ratio, 2),
            "avg_entropy": round(avg_entropy, 2),
            "nxdomain": int(client_nxdomain.get(client, 0) or 0),
            "txt_queries": int(client_txt_queries.get(client, 0) or 0),
            "long_queries": int(client_long_queries.get(client, 0) or 0),
        }
        client_abuse_profiles.append(profile)
    client_abuse_profiles.sort(
        key=lambda item: (
            float(item.get("unique_ratio", 0.0)),
            float(item.get("avg_entropy", 0.0)),
        ),
        reverse=True,
    )

    for name, count in qname_counts.items():
        if (
            count == 1
            and qname_lengths.get(name, 0) >= 36
            and (qname_entropy.get(name, 0) / 100.0) >= 4.1
        ):
            one_off_high_entropy.append(
                (name, qname_lengths.get(name, 0), qname_entropy.get(name, 0))
            )
    if one_off_high_entropy:
        sample = ", ".join(name for name, _len_v, _ent in one_off_high_entropy[:5])
        deterministic_checks["dga_like_behavior"].append(
            f"one-off high-entropy qnames: {sample}"
        )

    if (
        any(len(answers) <= 4 for answers in base_domain_answers.values())
        and base_domain_answers
    ):
        benign_context.append(
            "Some answer rotation appears low-volume and may reflect normal CDN behavior"
        )
        deterministic_checks["likely_benign_cdn_rotation"].append(
            "Low-cardinality answer rotation observed"
        )

    periodicity_profiles: list[dict[str, object]] = []

    def _periodicity_score(series: list[float]) -> dict[str, object] | None:
        values = sorted(float(v) for v in series if isinstance(v, (int, float)))
        if len(values) < 6:
            return None
        deltas = [b - a for a, b in zip(values, values[1:]) if (b - a) > 0.0]
        if len(deltas) < 5:
            return None
        mean = sum(deltas) / len(deltas)
        if mean <= 0.0:
            return None
        variance = sum((val - mean) ** 2 for val in deltas) / len(deltas)
        stddev = variance**0.5
        cv = stddev / mean if mean > 0.0 else 1.0
        min_gap = min(deltas)
        max_gap = max(deltas)
        sorted_deltas = sorted(deltas)
        p95_idx = int(0.95 * (len(sorted_deltas) - 1)) if len(sorted_deltas) > 1 else 0
        p95_gap = sorted_deltas[p95_idx]

        score = 0
        if 5.0 <= mean <= 600.0:
            score += 1
        if cv <= 0.20:
            score += 2
        if cv <= 0.10:
            score += 1
        if max_gap <= max(mean * 1.8, max(min_gap, 0.001) * 2.5):
            score += 1
        if len(values) >= 12:
            score += 1
        if p95_gap <= (mean * 1.7):
            score += 1

        if score >= 6:
            confidence = "high"
        elif score >= 4:
            confidence = "medium"
        elif score >= 3:
            confidence = "low"
        else:
            return None

        return {
            "events": len(values),
            "interval_samples": len(deltas),
            "mean_interval": round(mean, 2),
            "stddev_interval": round(stddev, 2),
            "cv": round(cv, 3),
            "min_interval": round(min_gap, 2),
            "max_interval": round(max_gap, 2),
            "p95_interval": round(p95_gap, 2),
            "score": score,
            "confidence": confidence,
            "first_seen": values[0],
            "last_seen": values[-1],
        }

    for qname, series in qname_query_times.items():
        if qname_counts.get(qname, 0) < 6:
            continue
        scored = _periodicity_score(series)
        if not scored:
            continue
        periodicity_profiles.append(
            {
                "scope": "qname",
                "entity": qname,
                **scored,
            }
        )

    for (client, qname), series in client_qname_times.items():
        if len(series) < 6:
            continue
        scored = _periodicity_score(series)
        if not scored:
            continue
        periodicity_profiles.append(
            {
                "scope": "client_qname",
                "entity": f"{client} -> {qname}",
                "client": client,
                "qname": qname,
                **scored,
            }
        )

    periodicity_profiles.sort(
        key=lambda item: (
            int(item.get("score", 0) or 0),
            int(item.get("events", 0) or 0),
            -float(item.get("cv", 1.0) or 1.0),
        ),
        reverse=True,
    )
    periodicity_profiles = periodicity_profiles[:40]

    high_periodic = [
        item
        for item in periodicity_profiles
        if str(item.get("confidence", "")).lower() == "high"
    ]
    medium_periodic = [
        item
        for item in periodicity_profiles
        if str(item.get("confidence", "")).lower() == "medium"
    ]
    def _beacon_evidence(
        profiles: list[dict[str, object]],
    ) -> tuple[Counter[str], Counter[str]]:
        # Attribute the finding to the beaconing clients and the resolvers they
        # used for the periodic lookups, not the capture-wide top DNS talkers
        # (which are usually unrelated busy hosts).
        clients: Counter[str] = Counter()
        servers: Counter[str] = Counter()
        for item in profiles:
            client = item.get("client")
            if not client:
                continue
            events = int(item.get("events", 0) or 0) or 1
            clients[str(client)] += events
            servers.update(client_resolvers.get(str(client), {}))
        return clients, servers

    if high_periodic:
        evidence = [
            f"{item.get('entity')} interval={item.get('mean_interval')}s cv={item.get('cv')} events={item.get('events')}"
            for item in high_periodic[:8]
        ]
        deterministic_checks["dns_beaconing_periodicity"].extend(evidence)
        beacon_clients, beacon_servers = _beacon_evidence(high_periodic)
        detections.append(
            {
                "type": "dns_beacon_periodicity",
                "severity": "warning",
                "summary": "High-confidence periodic DNS check-in behavior",
                "details": "; ".join(evidence[:4]),
                "top_clients": (
                    beacon_clients.most_common(3)
                    if beacon_clients
                    else client_counts.most_common(3)
                ),
                "top_servers": (
                    beacon_servers.most_common(3)
                    if beacon_servers
                    else server_counts.most_common(3)
                ),
            }
        )
    elif medium_periodic:
        evidence = [
            f"{item.get('entity')} interval={item.get('mean_interval')}s cv={item.get('cv')} events={item.get('events')}"
            for item in medium_periodic[:8]
        ]
        deterministic_checks["dns_beaconing_periodicity"].extend(evidence)
        beacon_clients, beacon_servers = _beacon_evidence(medium_periodic)
        detections.append(
            {
                "type": "dns_beacon_periodicity",
                "severity": "info",
                "summary": "Possible periodic DNS check-in behavior",
                "details": "; ".join(evidence[:4]),
                "top_clients": (
                    beacon_clients.most_common(3)
                    if beacon_clients
                    else client_counts.most_common(3)
                ),
                "top_servers": (
                    beacon_servers.most_common(3)
                    if beacon_servers
                    else server_counts.most_common(3)
                ),
            }
        )
    else:
        benign_context.append(
            "No high-confidence DNS periodic beaconing pattern was detected"
        )

    for det in detections[:120]:
        timeline.append(
            {
                "ts": first_seen,
                "event": str(det.get("type", "detection")),
                "summary": str(det.get("summary", "")),
                "details": str(det.get("details", "")),
            }
        )

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
        deterministic_checks=deterministic_checks,
        resolver_drift=resolver_drift,
        client_abuse_profiles=client_abuse_profiles,
        ttl_outliers=ttl_outliers,
        cname_anomalies=cname_anomalies,
        transaction_violations=transaction_violations,
        amplification_candidates=amplification_candidates,
        timeline=timeline,
        periodicity_profiles=periodicity_profiles,
        benign_context=benign_context,
    )
