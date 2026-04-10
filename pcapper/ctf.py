from __future__ import annotations

import base64
import binascii
import ipaddress
import re
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .pcap_cache import get_reader
from .utils import safe_float

try:
    from scapy.layers.dns import DNS, DNSQR, DNSRR  # type: ignore
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore
    DNS = None  # type: ignore
    DNSQR = None  # type: ignore
    DNSRR = None  # type: ignore
    Raw = None  # type: ignore


FLAG_PATTERNS = [
    re.compile(r"(flag\{[^}]{4,}\})", re.IGNORECASE),
    re.compile(r"(ctf\{[^}]{4,}\})", re.IGNORECASE),
    re.compile(r"(htb\{[^}]{4,}\})", re.IGNORECASE),
    re.compile(r"(picoCTF\{[^}]{4,}\})", re.IGNORECASE),
]

FILE_HINT_PATTERNS = [
    re.compile(r"(flag\\.txt)$", re.IGNORECASE),
    re.compile(r"(root\\.txt)$", re.IGNORECASE),
    re.compile(r"(user\\.txt)$", re.IGNORECASE),
    re.compile(r"(proof\\.txt)$", re.IGNORECASE),
    re.compile(r"(flag\\b)", re.IGNORECASE),
    re.compile(r"(ctf\\b)", re.IGNORECASE),
]

SECRETISH_PATTERNS = [
    re.compile(r"\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
]

HTTP_METHOD_RE = re.compile(
    r"^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|TRACE|CONNECT)\s+([^\s]+)", re.IGNORECASE
)
GENERIC_TOKEN_RE = re.compile(r"[A-Za-z0-9%+/=_:.-]{10,}")
HTTP_BASIC_AUTH_RE = re.compile(
    r"(?im)^authorization:\s*basic\s+([A-Za-z0-9+/=]{8,})\s*$"
)
HTTP_CRED_PARAM_RE = re.compile(
    r"(?i)\b(pass(?:word|wd|phrase)?|psk|wpa(?:2)?passphrase|key)\s*=\s*([^&\s;]{1,160})"
)
PLAUSIBLE_CRED_PAIR_RE = re.compile(r"^[A-Za-z0-9_.@\-]{1,64}:[^\s:]{1,96}$")


def _pattern_name(pattern: re.Pattern[str]) -> str:
    text = pattern.pattern.lower()
    if "flag\\{" in text:
        return "flag{}"
    if "ctf\\{" in text:
        return "ctf{}"
    if "htb\\{" in text:
        return "htb{}"
    if "picoctf\\{" in text:
        return "picoctf{}"
    return "ctf-pattern"


@dataclass(frozen=True)
class CtfHit:
    src_ip: str
    dst_ip: str
    protocol: str
    context: str


@dataclass(frozen=True)
class CtfSummary:
    path: Path
    total_packets: int
    hits: list[CtfHit]
    decoded_hits: list[str]
    token_counts: Counter[str]
    file_hints: list[str]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]
    confidence_counts: Counter[str] = field(default_factory=Counter)
    candidate_findings: list[dict[str, object]] = field(default_factory=list)
    deterministic_checks: dict[str, list[str]] = field(default_factory=dict)
    timeline: list[dict[str, object]] = field(default_factory=list)
    hunting_pivots: list[dict[str, object]] = field(default_factory=list)
    false_positive_context: list[str] = field(default_factory=list)


def _extract_payload(pkt) -> bytes:
    if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
        try:
            return bytes(pkt[Raw].load)  # type: ignore[index]
        except Exception:
            return b""
    if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
        try:
            return bytes(pkt[TCP].payload)  # type: ignore[index]
        except Exception:
            return b""
    if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
        try:
            return bytes(pkt[UDP].payload)  # type: ignore[index]
        except Exception:
            return b""
    return b""


def _decode_candidates(text: str) -> list[str]:
    results: list[str] = []
    text = text.strip()
    if not text:
        return results

    try:
        decoded = urllib.parse.unquote_to_bytes(text)
        if decoded and decoded != text.encode("utf-8", errors="ignore"):
            results.append(decoded.decode("utf-8", errors="ignore"))
    except Exception:
        pass

    try:
        if len(text) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", text):
            raw = binascii.unhexlify(text)
            results.append(raw.decode("utf-8", errors="ignore"))
    except Exception:
        pass

    try:
        if len(text) >= 12 and re.fullmatch(r"[A-Za-z0-9+/=]+", text):
            raw = base64.b64decode(text + "===")
            results.append(raw.decode("utf-8", errors="ignore"))
    except Exception:
        pass

    return results


def _iter_decode_candidates(token: str, max_depth: int = 3) -> list[tuple[str, str]]:
    queue: list[tuple[str, str, int]] = [(token, "raw", 0)]
    seen: set[str] = {token}
    out: list[tuple[str, str]] = []

    while queue:
        value, chain, depth = queue.pop(0)
        out.append((value, chain))
        if depth >= max_depth:
            continue

        # URL decode
        try:
            url_dec = urllib.parse.unquote(value)
            if url_dec and url_dec != value and url_dec not in seen:
                seen.add(url_dec)
                queue.append((url_dec, f"{chain}->url", depth + 1))
        except Exception:
            pass

        # Hex decode
        try:
            if len(value) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", value):
                hex_dec = binascii.unhexlify(value).decode("utf-8", errors="ignore")
                if hex_dec and hex_dec not in seen:
                    seen.add(hex_dec)
                    queue.append((hex_dec, f"{chain}->hex", depth + 1))
        except Exception:
            pass

        # Base64 decode (std/urlsafe)
        if len(value) >= 8 and re.fullmatch(r"[A-Za-z0-9_+/=-]+", value):
            for decoder_name, decoder in (
                ("b64", base64.b64decode),
                ("b64url", base64.urlsafe_b64decode),
            ):
                try:
                    padded = value + ("=" * (-len(value) % 4))
                    dec = decoder(padded).decode("utf-8", errors="ignore")
                    if dec and dec not in seen:
                        seen.add(dec)
                        queue.append((dec, f"{chain}->{decoder_name}", depth + 1))
                except Exception:
                    pass

    # Bound returned candidates to avoid pathological payloads.
    return out[:24]


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except Exception:
        return False


def _is_secretish_token(value: str) -> bool:
    if any(pattern.search(value) for pattern in SECRETISH_PATTERNS):
        return True
    if len(value) >= 32 and value.lower().startswith(
        ("ghp_", "glpat-", "xoxb-", "xoxp-", "sk_")
    ):
        return True
    return False


def _candidate_score(
    value: str, chain: str, source: str, external: bool, reassembled: bool
) -> tuple[int, str]:
    score = 0
    lower = value.lower()

    matched = any(pattern.search(value) for pattern in FLAG_PATTERNS)
    if matched:
        score += 4
    if chain != "raw":
        score += 1
    if source == "dns":
        score += 1
    if source == "http":
        score += 1
    if external:
        score += 1
    if reassembled:
        score += 1
    if PLAUSIBLE_CRED_PAIR_RE.fullmatch(value):
        score += 3
    if any(
        marker in lower
        for marker in (
            "passphrase=",
            "password=",
            "passwd=",
            "pwd=",
            "psk=",
            "wpa2passphrase=",
        )
    ):
        score += 2
    if _is_secretish_token(value) and not matched:
        score -= 2
    if any(prefix in lower for prefix in ("flag{", "ctf{", "htb{", "picoctf{")):
        score += 2

    if score >= 6:
        return score, "high"
    if score >= 3:
        return score, "medium"
    return score, "low"


def _proto_label(pkt) -> str:
    if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
        try:
            dport = int(pkt[TCP].dport)  # type: ignore[index]
            return f"TCP/{dport}"
        except Exception:
            return "TCP"
    if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
        try:
            dport = int(pkt[UDP].dport)  # type: ignore[index]
            return f"UDP/{dport}"
        except Exception:
            return "UDP"
    return "OTHER"


def analyze_ctf(path: Path, show_status: bool = True) -> CtfSummary:
    reader, status, stream, size_bytes, _file_type = get_reader(
        path, show_status=show_status
    )
    total_packets = 0
    hits: list[CtfHit] = []
    decoded_hits: list[str] = []
    token_counts: Counter[str] = Counter()
    file_hints: list[str] = []
    errors: list[str] = []
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    confidence_counts: Counter[str] = Counter()
    candidate_findings: list[dict[str, object]] = []
    timeline: list[dict[str, object]] = []
    false_positive_context: list[str] = []
    source_counts: Counter[str] = Counter()
    destination_counts: Counter[str] = Counter()
    protocol_counts: Counter[str] = Counter()
    token_to_sources: dict[str, set[str]] = {}
    token_to_dests: dict[str, set[str]] = {}
    flow_text_tail: dict[tuple[str, str, str], str] = {}
    seen_finding_keys: set[tuple[str, int, str, str]] = set()

    deterministic_checks: dict[str, list[str]] = {
        "flag_wrapper_pattern_present": [],
        "decoded_wrapper_pattern_present": [],
        "multi_source_corroboration": [],
        "stream_reassembled_match": [],
        "external_replay_exfil_behavior": [],
        "challenge_file_hint_correlation": [],
        "likely_secret_not_flag": [],
        "credential_pattern_present": [],
        "passphrase_parameter_present": [],
    }

    def _record_candidate(
        *,
        value: str,
        decode_chain: str,
        source: str,
        context: str,
        packet_number: int,
        ts: Optional[float],
        src_ip: str,
        dst_ip: str,
        protocol: str,
        reassembled: bool = False,
    ) -> None:
        if not value.strip():
            return
        external = _is_public_ip(dst_ip)
        score, confidence = _candidate_score(
            value, decode_chain, source, external, reassembled
        )
        key = (value[:96], packet_number, src_ip, dst_ip)
        if key in seen_finding_keys:
            return
        seen_finding_keys.add(key)

        confidence_counts[confidence] += 1
        source_counts[src_ip] += 1
        destination_counts[dst_ip] += 1
        protocol_counts[protocol] += 1

        normalized = value.strip().lower()
        token_to_sources.setdefault(normalized, set()).add(src_ip)
        token_to_dests.setdefault(normalized, set()).add(dst_ip)

        finding = {
            "candidate": value,
            "normalized": normalized[:120],
            "score": score,
            "confidence": confidence,
            "decode_chain": decode_chain,
            "source": source,
            "reassembled": reassembled,
            "packet": packet_number,
            "ts": ts,
            "src": src_ip,
            "dst": dst_ip,
            "protocol": protocol,
            "context": context[:180],
        }
        candidate_findings.append(finding)
        timeline.append(
            {
                "ts": ts,
                "event": "candidate",
                "candidate": value[:80],
                "confidence": confidence,
                "src": src_ip,
                "dst": dst_ip,
                "protocol": protocol,
                "packet": packet_number,
            }
        )

        if _is_secretish_token(value) and not any(
            pattern.search(value) for pattern in FLAG_PATTERNS
        ):
            deterministic_checks["likely_secret_not_flag"].append(
                f"pkt={packet_number} {src_ip}->{dst_ip} token looked secret-like (not CTF wrapper)"
            )
            false_positive_context.append(
                f"Likely secret-like token (downranked): pkt={packet_number} {src_ip}->{dst_ip} {value[:40]}"
            )

        for pattern in FLAG_PATTERNS:
            m = pattern.search(value)
            if not m:
                continue
            matched_value = m.group(1)
            token_counts[matched_value] += 1
            hits.append(
                CtfHit(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    context=matched_value,
                )
            )
            deterministic_checks["flag_wrapper_pattern_present"].append(
                f"pkt={packet_number} {_pattern_name(pattern)} {src_ip}->{dst_ip}"
            )
            if decode_chain != "raw":
                decoded_hits.append(value)
                deterministic_checks["decoded_wrapper_pattern_present"].append(
                    f"pkt={packet_number} {_pattern_name(pattern)} via {decode_chain}"
                )

    try:
        for pkt_index, pkt in enumerate(reader, start=1):
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
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                src_ip = str(pkt[IP].src)  # type: ignore[index]
                dst_ip = str(pkt[IP].dst)  # type: ignore[index]
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                src_ip = str(pkt[IPv6].src)  # type: ignore[index]
                dst_ip = str(pkt[IPv6].dst)  # type: ignore[index]
            if not src_ip or not dst_ip:
                continue

            protocol = _proto_label(pkt)

            payload = _extract_payload(pkt)
            if not payload:
                continue
            text = payload.decode("latin-1", errors="ignore")

            # Raw payload wrapper checks.
            for pattern in FLAG_PATTERNS:
                for match in pattern.findall(text):
                    _record_candidate(
                        value=match,
                        decode_chain="raw",
                        source="payload",
                        context="raw payload wrapper match",
                        packet_number=pkt_index,
                        ts=ts,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol=protocol,
                    )

            # HTTP-aware extraction for URI/body candidates.
            lines = text.splitlines()
            if lines:
                method_match = HTTP_METHOD_RE.match(lines[0].strip())
                if method_match:
                    uri = method_match.group(2)
                    for token in GENERIC_TOKEN_RE.findall(uri):
                        for value, chain in _iter_decode_candidates(token):
                            if any(pattern.search(value) for pattern in FLAG_PATTERNS):
                                _record_candidate(
                                    value=value,
                                    decode_chain=chain,
                                    source="http",
                                    context=f"http-uri token={token[:40]}",
                                    packet_number=pkt_index,
                                    ts=ts,
                                    src_ip=src_ip,
                                    dst_ip=dst_ip,
                                    protocol=protocol,
                                )
                    # HTTP Basic credentials (e.g., Authorization: Basic YWRtaW46YWRtaW4=).
                    for match in HTTP_BASIC_AUTH_RE.finditer(text):
                        token = str(match.group(1) or "").strip()
                        if not token:
                            continue
                        decoded = ""
                        try:
                            padded = token + ("=" * (-len(token) % 4))
                            decoded = (
                                base64.b64decode(padded, validate=False)
                                .decode("utf-8", errors="ignore")
                                .strip()
                            )
                        except Exception:
                            decoded = ""
                        if decoded and PLAUSIBLE_CRED_PAIR_RE.fullmatch(decoded):
                            deterministic_checks["credential_pattern_present"].append(
                                f"pkt={pkt_index} http-basic {src_ip}->{dst_ip} credential-pair observed"
                            )
                            _record_candidate(
                                value=decoded,
                                decode_chain="http-basic",
                                source="http",
                                context="http authorization basic decoded credential",
                                packet_number=pkt_index,
                                ts=ts,
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                protocol=protocol,
                            )

                    # Passphrase/password style key=value parameters in URI/body.
                    for match in HTTP_CRED_PARAM_RE.finditer(text):
                        key = str(match.group(1) or "").strip()
                        value = str(match.group(2) or "").strip()
                        if not key or not value:
                            continue
                        candidate = f"{key}={value}"
                        deterministic_checks["passphrase_parameter_present"].append(
                            f"pkt={pkt_index} {src_ip}->{dst_ip} parameter {key}=<redacted>"
                        )
                        _record_candidate(
                            value=candidate,
                            decode_chain="http-param",
                            source="http",
                            context=f"http credential parameter {key}",
                            packet_number=pkt_index,
                            ts=ts,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            protocol=protocol,
                        )

            # Generic token decode pipeline.
            token_budget = 80
            seen_tokens: set[str] = set()
            for token in GENERIC_TOKEN_RE.findall(text):
                if token in seen_tokens:
                    continue
                seen_tokens.add(token)
                if len(seen_tokens) > token_budget:
                    break
                for value, chain in _iter_decode_candidates(token):
                    if any(pattern.search(value) for pattern in FLAG_PATTERNS):
                        _record_candidate(
                            value=value,
                            decode_chain=chain,
                            source="payload",
                            context=f"decoded token={token[:40]}",
                            packet_number=pkt_index,
                            ts=ts,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            protocol=protocol,
                        )

            # Simple stream-boundary reconstruction to catch split wrappers.
            flow_key = (src_ip, dst_ip, protocol)
            prior = flow_text_tail.get(flow_key, "")
            combined = (prior + text)[-8192:]
            for pattern in FLAG_PATTERNS:
                for match in pattern.findall(combined):
                    if match not in text and match in combined:
                        deterministic_checks["stream_reassembled_match"].append(
                            f"pkt={pkt_index} flow={src_ip}->{dst_ip} protocol={protocol}"
                        )
                        _record_candidate(
                            value=match,
                            decode_chain="raw",
                            source="reassembly",
                            context="flow tail reassembly",
                            packet_number=pkt_index,
                            ts=ts,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            protocol=protocol,
                            reassembled=True,
                        )
            flow_text_tail[flow_key] = combined[-256:]

            if DNS is not None and pkt.haslayer(DNS):  # type: ignore[truthy-bool]
                try:
                    dns_layer = pkt[DNS]  # type: ignore[index]
                    qd = getattr(dns_layer, "qd", None)
                    if qd is not None and hasattr(qd, "qname"):
                        qname = str(getattr(qd, "qname", b"")).strip("b'").strip("'")
                        if qname:
                            for value, chain in _iter_decode_candidates(qname):
                                if any(
                                    pattern.search(value) for pattern in FLAG_PATTERNS
                                ):
                                    _record_candidate(
                                        value=value,
                                        decode_chain=chain,
                                        source="dns",
                                        context=f"dns-qname={qname[:80]}",
                                        packet_number=pkt_index,
                                        ts=ts,
                                        src_ip=src_ip,
                                        dst_ip=dst_ip,
                                        protocol=protocol,
                                    )
                except Exception:
                    pass

    finally:
        status.finish()
        reader.close()

    try:
        from .files import analyze_files

        file_summary = analyze_files(path, show_status=False)
        for art in file_summary.artifacts:
            name = (art.filename or "").lower()
            if not name:
                continue
            if any(pattern.search(name) for pattern in FILE_HINT_PATTERNS):
                line = f"{art.filename} {art.src_ip}->{art.dst_ip} {art.protocol}"
                file_hints.append(line)
                deterministic_checks["challenge_file_hint_correlation"].append(line)
    except Exception:
        pass

    # Multi-source corroboration and replay/exfil style behavior for candidates.
    for token, srcs in token_to_sources.items():
        if len(srcs) >= 2:
            deterministic_checks["multi_source_corroboration"].append(
                f"candidate={token[:48]} seen from {len(srcs)} sources"
            )

    for token, dsts in token_to_dests.items():
        public_dsts = [dst for dst in dsts if _is_public_ip(dst)]
        if len(dsts) >= 2 or len(public_dsts) >= 1:
            deterministic_checks["external_replay_exfil_behavior"].append(
                f"candidate={token[:48]} dsts={len(dsts)} public={len(public_dsts)}"
            )

    candidate_findings.sort(
        key=lambda item: (
            int(item.get("score", 0) or 0),
            str(item.get("confidence", "")) == "high",
            int(item.get("packet", 0) or 0),
        ),
        reverse=True,
    )

    hunting_pivots: list[dict[str, object]] = []
    for item in candidate_findings[:40]:
        hunting_pivots.append(
            {
                "packet": item.get("packet", "-"),
                "src": item.get("src", "-"),
                "dst": item.get("dst", "-"),
                "protocol": item.get("protocol", "-"),
                "candidate": str(item.get("candidate", "-"))[:64],
                "decode_chain": item.get("decode_chain", "raw"),
            }
        )

    timeline.sort(key=lambda item: float(item.get("ts", 0.0) or 0.0))

    duration = (
        (last_seen - first_seen)
        if first_seen is not None and last_seen is not None
        else None
    )
    return CtfSummary(
        path=path,
        total_packets=total_packets,
        hits=hits,
        decoded_hits=decoded_hits[:50],
        token_counts=token_counts,
        file_hints=file_hints,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
        confidence_counts=confidence_counts,
        candidate_findings=candidate_findings[:200],
        deterministic_checks={
            key: value[:40] for key, value in deterministic_checks.items()
        },
        timeline=timeline[:200],
        hunting_pivots=hunting_pivots[:80],
        false_positive_context=false_positive_context[:30],
    )
