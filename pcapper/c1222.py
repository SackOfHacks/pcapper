"""ANSI C12.22 (smart-meter communications, TCP/UDP 1153).

C12.22 wraps C12.19 table services (EPSEM) in an ACSE association PDU:
``0x60`` + BER length, then context-tagged elements - called/calling AP titles
(0xA2/0xA6, OIDs), calling authentication value (0xAC), user information
(0xBE -> EXTERNAL -> octet-aligned EPSEM). EPSEM: control byte (bits 2-3
security mode: 0 clear, 1 clear + authenticated, 2 ciphered; bit 4 ED-class
present) [ED class (4)], then service length (BER) + service code + data.

Service codes (C12.18/C12.19/C12.22), confirmed against the CISA ICSNPP
per-service test traces: 0x20 Identify, 0x50 Logon (user ID + user name in
clear), 0x51 Security (password in clear), 0x27 Registration, 0x25 Resolve,
0x26 Trace, 0x70 Wait, 0x30-0x3F reads, 0x40-0x4F writes. Responses reuse
the code byte as a status (0x00 OK).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .industrial_helpers import (
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
    append_public_exposure_anomaly,
)
from .utils import memoize_analysis

C1222_PORT = 1153

SERVICES = {
    0x20: "Identify", 0x21: "Terminate", 0x22: "Disconnect", 0x24: "Deregistration",
    0x25: "Resolve", 0x26: "Trace", 0x27: "Registration", 0x30: "Full Read",
    0x3E: "Default Read", 0x3F: "Partial Read (offset)", 0x40: "Full Write",
    0x4F: "Partial Write (offset)", 0x50: "Logon", 0x51: "Security", 0x52: "Logoff",
    0x60: "Negotiate", 0x70: "Wait",
}
for _code in range(0x31, 0x3A):
    SERVICES[_code] = "Partial Read (index)"
for _code in range(0x41, 0x4A):
    SERVICES[_code] = "Partial Write (index)"
RESPONSES = {
    0x00: "OK", 0x01: "Error", 0x02: "Service Not Supported", 0x03: "Insufficient Security Clearance",
    0x04: "Operation Not Possible", 0x05: "Inappropriate Action Requested", 0x06: "Device Busy",
    0x07: "Data Not Ready", 0x08: "Data Locked", 0x09: "Renegotiate Request",
    0x0A: "Invalid Service Sequence State", 0x0B: "Security Mechanism Error",
    0x0C: "Unknown Application Title", 0x0D: "Network Timeout", 0x0E: "Network Not Reachable",
    0x0F: "Request Too Large", 0x10: "Response Too Large", 0x11: "Segmentation Not Possible",
    0x12: "Segmentation Error",
}
WRITE_CODES = {0x40, 0x4F} | set(range(0x41, 0x4A))


def _ber_len(data: bytes, pos: int) -> tuple[int, int]:
    first = data[pos]
    if first < 0x80:
        return first, pos + 1
    count = first & 0x7F
    return int.from_bytes(data[pos + 1:pos + 1 + count], "big"), pos + 1 + count


def _oid(data: bytes) -> str:
    parts: list[int] = []
    value = 0
    for byte in data:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    if not parts:
        return ""
    first = parts[0]
    head = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    return ".".join(str(p) for p in head + parts[1:])


@dataclass
class C1222Message:
    called: str = ""
    calling: str = ""
    authenticated: bool = False
    security_mode: int = 0
    services: list[tuple[int, bytes]] = field(default_factory=list)


def parse_c1222(payload: bytes) -> C1222Message | None:
    if len(payload) < 4 or payload[0] != 0x60:
        return None
    try:
        length, pos = _ber_len(payload, 1)
        if pos + length != len(payload):
            return None
        message = C1222Message()
        end = pos + length
        while pos < end:
            tag = payload[pos]
            size, inner = _ber_len(payload, pos + 1)
            value = payload[inner:inner + size]
            if tag in (0xA2, 0xA6) and len(value) >= 2:
                text = _oid(value[2:2 + value[1]])
                if tag == 0xA2:
                    message.called = text
                else:
                    message.calling = text
            elif tag == 0xAC:
                message.authenticated = True
            elif tag == 0xBE and len(value) > 4:
                _external_len, ext = _ber_len(value, 1)
                _octets_len, epsem_pos = _ber_len(value, ext + 1)
                epsem = value[epsem_pos:]
                control = epsem[0]
                message.security_mode = (control >> 2) & 0x03
                cursor = 1 + (4 if control & 0x10 else 0)
                if message.security_mode != 2:
                    while cursor < len(epsem):
                        service_len, cursor = _ber_len(epsem, cursor)
                        if service_len == 0 or cursor + service_len > len(epsem):
                            break
                        message.services.append((epsem[cursor], bytes(epsem[cursor + 1:cursor + service_len])))
                        cursor += service_len
            pos = inner + size
        return message
    except IndexError:
        return None


def _signature(payload: bytes) -> bool:
    message = parse_c1222(payload)
    return message is not None and bool(message.services or message.security_mode == 2)


def _commands(payload: bytes) -> list[str]:
    message = parse_c1222(payload)
    if message is None:
        return []
    if message.security_mode == 2:
        return ["Ciphered EPSEM"]
    return [SERVICES.get(code) or f"Response: {RESPONSES.get(code, hex(code))}" for code, _data in message.services]


def _printable(data: bytes) -> str:
    return "".join(chr(b) for b in data if 32 <= b < 127).strip()


class _C1222State:
    def __init__(self) -> None:
        self.credentials: list[str] = []
        self.writes: Counter[str] = Counter()
        self.registrations: Counter[str] = Counter()
        self.ciphered = 0
        self.cleartext = 0
        self.errors: Counter[str] = Counter()
        self.first: dict[str, tuple[str, str, float]] = {}

    def feed(self, payload: bytes, src: str, dst: str, ts: float, _commands: object) -> list[IndustrialAnomaly]:
        message = parse_c1222(payload)
        if message is None:
            return []
        if message.security_mode == 2:
            self.ciphered += 1
            return []
        if message.services:
            self.cleartext += 1
        for code, data in message.services:
            if code == 0x50 and len(data) >= 2:
                self.credentials.append(
                    f"{src} -> {dst}: logon user ID {int.from_bytes(data[:2], 'big')} user {_printable(data[2:12])!r}"
                )
                self.first.setdefault("cred", (src, dst, ts))
            elif code == 0x51:
                self.credentials.append(f"{src} -> {dst}: security password {_printable(data[:20])!r}")
                self.first.setdefault("cred", (src, dst, ts))
            elif code in WRITE_CODES and len(data) >= 2:
                self.writes[f"{src} -> {dst} table {int.from_bytes(data[:2], 'big')}"] += 1
                self.first.setdefault("write", (src, dst, ts))
            elif code in (0x27, 0x24):
                self.registrations[f"{SERVICES[code]} from {message.calling or src}"] += 1
            elif code in RESPONSES and code not in (0x00,) and code < 0x20:
                self.errors[RESPONSES[code]] += 1
        return []

    def findings(self) -> list[IndustrialAnomaly]:
        found: list[IndustrialAnomaly] = []
        if self.credentials:
            src, dst, ts = self.first["cred"]
            found.append(IndustrialAnomaly(
                "HIGH", "C12.22 cleartext logon/security credentials",
                f"{len(self.credentials)} Logon/Security service(s) sent without EPSEM encryption.",
                src, dst, ts, attack="T0859 Valid Accounts", evidence=self.credentials[:8],
            ))
        if self.writes:
            src, dst, ts = self.first["write"]
            found.append(IndustrialAnomaly(
                "HIGH", "C12.22 meter table writes",
                ", ".join(f"{k} x{v}" for k, v in self.writes.most_common(5)) + " (meter configuration, "
                "tariff or billing data changed).",
                src, dst, ts, attack="T0836 Modify Parameter",
            ))
        if self.cleartext and not self.ciphered:
            found.append(IndustrialAnomaly(
                "MEDIUM", "C12.22 without EPSEM encryption",
                f"{self.cleartext} C12.22 message(s) carried cleartext EPSEM (security mode 0/1).",
                "*", "*", 0.0, attack="T0830 Adversary-in-the-Middle",
            ))
        if self.registrations:
            found.append(IndustrialAnomaly(
                "LOW", "C12.22 node (de)registration",
                ", ".join(f"{k} x{v}" for k, v in self.registrations.most_common(4)), "*", "*", 0.0,
            ))
        return found


@memoize_analysis
def analyze_c1222(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    state = _C1222State()
    analysis = analyze_port_protocol(
        port_key="c1222",
        path=path,
        protocol_name="ANSI C12.22",
        tcp_ports={C1222_PORT},
        udp_ports={C1222_PORT},
        signature_matcher=_signature,
        command_parser=_commands,
        artifact_parser=lambda _payload: [],
        anomaly_detector=state.feed,
        enable_enrichment=True,
        show_status=show_status,
    )
    analysis.anomalies.extend(state.findings())
    append_public_exposure_anomaly(analysis, "C12.22")
    return analysis
