from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import re

try:
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.packet import Raw, Packet
except Exception:  # pragma: no cover
    IP = TCP = UDP = Raw = None  # type: ignore

from .pcap_cache import get_reader
from .utils import detect_file_type, safe_float


SUSPICIOUS_PATTERNS = [
    (re.compile(r"password\s*[:=]", re.IGNORECASE), "Credential exposure"),
    (re.compile(r"passwd\s*[:=]", re.IGNORECASE), "Credential exposure"),
    (re.compile(r"api[_-]?key\s*[:=]", re.IGNORECASE), "API key exposure"),
    (re.compile(r"secret\s*[:=]", re.IGNORECASE), "Secret exposure"),
    (re.compile(r"authorization:\s*bearer\s+", re.IGNORECASE), "Bearer token"),
    (re.compile(r"token\s*[:=]", re.IGNORECASE), "Token exposure"),
    (re.compile(r"BEGIN (RSA|EC|DSA) PRIVATE KEY", re.IGNORECASE), "Private key material"),
    (re.compile(r"ssh-rsa|ssh-ed25519", re.IGNORECASE), "SSH key material"),
    (re.compile(r"/bin/(sh|bash)|cmd\.exe|powershell", re.IGNORECASE), "Command execution"),
    (re.compile(r"curl\s+http|wget\s+http", re.IGNORECASE), "Download/exfil tooling"),
    (re.compile(r"^GET\s+|^POST\s+|^PUT\s+", re.IGNORECASE), "HTTP request"),
]

URL_PATTERN = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
DOMAIN_PATTERN = re.compile(r"\b([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\b")


@dataclass(frozen=True)
class StringArtifact:
    value: str
    count: int


@dataclass(frozen=True)
class StringsSummary:
    path: Path
    total_packets: int
    strings_found: int
    unique_strings: int
    top_strings: List[StringArtifact]
    suspicious_strings: List[StringArtifact]
    suspicious_details: List[Dict[str, object]]
    urls: List[StringArtifact]
    emails: List[StringArtifact]
    domains: List[StringArtifact]
    client_strings: Dict[str, List[StringArtifact]]
    server_strings: Dict[str, List[StringArtifact]]
    anomalies: List[str]
    errors: List[str]


def _get_ip_pair(pkt: Packet) -> Tuple[str, str]:
    if IP is not None and IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 is not None and IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    return "0.0.0.0", "0.0.0.0"


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


def _match_suspicious(value: str) -> Optional[str]:
    for pattern, reason in SUSPICIOUS_PATTERNS:
        if pattern.search(value):
            return reason
    return None


def analyze_strings(path: Path, show_status: bool = True, max_unique: int = 5000) -> StringsSummary:
    if TCP is None:
        return StringsSummary(
            path,
            0,
            0,
            0,
            [],
            [],
            [],
            [],
            [],
            {},
            {},
            ["Scapy not available"],
            [],
        )

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path, show_status=show_status
        )
    except Exception as e:
        return StringsSummary(
            path,
            0,
            0,
            0,
            [],
            [],
            [],
            [],
            [],
            {},
            {},
            [f"Error opening pcap: {e}"],
            [],
        )

    size_bytes = size_bytes

    total_packets = 0
    string_counter: Counter[str] = Counter()
    suspicious_counter: Counter[str] = Counter()
    suspicious_reasons: Dict[str, Set[str]] = defaultdict(set)
    suspicious_srcs: Dict[str, Counter[str]] = defaultdict(Counter)
    suspicious_dsts: Dict[str, Counter[str]] = defaultdict(Counter)
    url_counter: Counter[str] = Counter()
    email_counter: Counter[str] = Counter()
    domain_counter: Counter[str] = Counter()
    client_map: Dict[str, Counter[str]] = defaultdict(Counter)
    server_map: Dict[str, Counter[str]] = defaultdict(Counter)
    errors: List[str] = []

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
            payload = b""
            if Raw in pkt:
                payload = bytes(pkt[Raw])
            elif TCP in pkt or UDP in pkt:
                try:
                    payload = bytes(pkt[TCP].payload) if TCP in pkt else bytes(pkt[UDP].payload)
                except Exception:
                    payload = b""

            if not payload:
                continue

            src, dst = _get_ip_pair(pkt)

            for value in _extract_ascii_strings(payload) + _extract_utf16le_strings(payload):
                if not value:
                    continue
                if len(string_counter) < max_unique or value in string_counter:
                    string_counter[value] += 1
                    client_map[src][value] += 1
                    server_map[dst][value] += 1

                reason = _match_suspicious(value)
                if reason:
                    suspicious_counter[value] += 1
                    suspicious_reasons[value].add(reason)
                    suspicious_srcs[value][src] += 1
                    suspicious_dsts[value][dst] += 1

                for url in URL_PATTERN.findall(value):
                    url_counter[url] += 1
                for email in EMAIL_PATTERN.findall(value):
                    email_counter[email] += 1
                for domain in DOMAIN_PATTERN.findall(value):
                    domain_counter[domain] += 1

    except Exception as e:
        errors.append(str(e))
    finally:
        status.finish()
        reader.close()

    anomalies: List[str] = []
    if suspicious_counter:
        anomalies.append("Suspicious string indicators detected.")
    if any(key.lower().startswith("bearer ") for key in string_counter.keys()):
        anomalies.append("Bearer tokens observed in cleartext.")

    def _top_artifacts(counter: Counter[str], limit: int = 15) -> List[StringArtifact]:
        return [StringArtifact(value=k, count=v) for k, v in counter.most_common(limit)]

    client_strings = {
        ip: _top_artifacts(counter, 8)
        for ip, counter in sorted(client_map.items(), key=lambda item: sum(item[1].values()), reverse=True)[:5]
    }
    server_strings = {
        ip: _top_artifacts(counter, 8)
        for ip, counter in sorted(server_map.items(), key=lambda item: sum(item[1].values()), reverse=True)[:5]
    }

    suspicious_details: List[Dict[str, object]] = []
    for value, count in suspicious_counter.most_common(20):
        reasons = sorted(suspicious_reasons.get(value, set()))
        top_src = suspicious_srcs.get(value, Counter()).most_common(3)
        top_dst = suspicious_dsts.get(value, Counter()).most_common(3)
        suspicious_details.append({
            "value": value,
            "count": count,
            "reasons": reasons,
            "top_sources": top_src,
            "top_destinations": top_dst,
        })

    for item in suspicious_details:
        reasons = ", ".join(item.get("reasons", [])) or "Unknown reason"
        top_src = ", ".join(f"{ip}({count})" for ip, count in item.get("top_sources", [])) or "-"
        top_dst = ", ".join(f"{ip}({count})" for ip, count in item.get("top_destinations", [])) or "-"
        anomalies.append(
            f"Suspicious string: {item.get('value', '-')}; reason: {reasons}; src: {top_src}; dst: {top_dst}"
        )

    return StringsSummary(
        path=path,
        total_packets=total_packets,
        strings_found=sum(string_counter.values()),
        unique_strings=len(string_counter),
        top_strings=_top_artifacts(string_counter, 20),
        suspicious_strings=_top_artifacts(suspicious_counter, 20),
        suspicious_details=suspicious_details,
        urls=_top_artifacts(url_counter, 15),
        emails=_top_artifacts(email_counter, 15),
        domains=_top_artifacts(domain_counter, 15),
        client_strings=client_strings,
        server_strings=server_strings,
        anomalies=anomalies,
        errors=errors,
    )
