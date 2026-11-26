"""Beckhoff ADS/AMS (TwinCAT PLCs and IPCs).

* AMS/TCP on TCP 48898: 2 reserved zero bytes, length (4, LE), then the
  32-byte AMS header - target NetId (6) | target port (2) | source NetId (6)
  | source port (2) | command (2) | state flags (2: 0x0004 request, 0x0005
  response) | data length (4) | error code (4) | invoke ID (4) - and the ADS
  data.
* UDP 48899: TwinCAT discovery and *AddRoute*: magic ``03 66 14 71``, invoke
  (4), service (4: 1 discover, 6 add route; |0x80000000 = response), AMS
  NetId + port, tag count, then tag/length/value. An AddRoute request carries
  the target's Windows user name and password in clear; with a route in
  place anyone can drive the PLC over ADS (no further authentication).
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from .industrial_helpers import (
    IndustrialAnalysis,
    IndustrialAnomaly,
    IndustrialArtifact,
    analyze_port_protocol,
    append_public_exposure_anomaly,
)
from .utils import memoize_analysis

PROTOCOL_NAME = "Beckhoff ADS/AMS"
ADS_TCP_PORT = 48898
ADS_UDP_PORT = 48899

COMMANDS = {
    0: "Invalid", 1: "ReadDeviceInfo", 2: "Read", 3: "Write", 4: "ReadState",
    5: "WriteControl", 6: "AddDeviceNotification", 7: "DeleteDeviceNotification",
    8: "DeviceNotification", 9: "ReadWrite",
}
ADS_STATES = {
    0: "INVALID", 1: "IDLE", 2: "RESET", 3: "INIT", 4: "START", 5: "RUN", 6: "STOP",
    7: "SAVECFG", 8: "LOADCFG", 9: "POWERFAILURE", 10: "POWERGOOD", 11: "ERROR",
    12: "SHUTDOWN", 13: "SUSPEND", 14: "RESUME", 15: "CONFIG", 16: "RECONFIG",
}
INDEX_GROUPS = {
    0x4020: "PLC memory (%M)", 0x4021: "PLC memory bits", 0x4025: "PLC data (%M)",
    0xF003: "symbol handle by name", 0xF005: "value by symbol handle",
    0xF006: "release symbol handle", 0xF007: "symbol info by name",
    0xF008: "symbol version", 0xF009: "symbol info by name (ext)",
    0xF00B: "symbol upload", 0xF00C: "symbol upload info", 0xF00F: "data type upload",
    0xF020: "process image inputs", 0xF030: "process image outputs",
    0xF080: "sum read", 0xF081: "sum write", 0xF082: "sum read/write",
}
UDP_SERVICES = {1: "Discovery", 6: "AddRoute"}
UDP_TAGS = {2: "password", 3: "OS info", 4: "TwinCAT version", 5: "host/address", 7: "AMS NetId",
            12: "route name", 13: "user name", 14: "fingerprint"}


def _ams_frames(payload: bytes) -> list[tuple[int, int, int, bytes, str, str]]:
    """(command, flags, error, data, source NetId:port, target NetId:port) per frame."""
    frames = []
    pos = 0
    while pos + 38 <= len(payload):
        if payload[pos:pos + 2] != b"\x00\x00":
            return []
        size = int.from_bytes(payload[pos + 2:pos + 6], "little")
        header = payload[pos + 6:pos + 38]
        command = int.from_bytes(header[16:18], "little")
        data_len = int.from_bytes(header[20:24], "little")
        if command > 9 or size < 32 or data_len + 32 != size or pos + 6 + size > len(payload):
            return []
        target = ".".join(str(b) for b in header[0:6]) + f":{int.from_bytes(header[6:8], 'little')}"
        source = ".".join(str(b) for b in header[8:14]) + f":{int.from_bytes(header[14:16], 'little')}"
        frames.append((
            command,
            int.from_bytes(header[18:20], "little"),
            int.from_bytes(header[24:28], "little"),
            bytes(payload[pos + 38:pos + 6 + size]),
            source,
            target,
        ))
        pos += 6 + size
    return frames if pos == len(payload) else []


def parse_udp(payload: bytes) -> tuple[str, bool, dict[str, str]] | None:
    """(service, is_response, tags) for a TwinCAT UDP 48899 message."""
    if len(payload) < 24 or payload[:4] != b"\x03\x66\x14\x71":
        return None
    service = int.from_bytes(payload[8:12], "little")
    response = bool(service & 0x80000000)
    name = UDP_SERVICES.get(service & 0x7FFFFFFF, f"service {service & 0x7FFFFFFF}")
    count = int.from_bytes(payload[20:24], "little")
    tags: dict[str, str] = {}
    pos = 24
    for _ in range(min(count, 32)):
        if pos + 4 > len(payload):
            break
        tag = int.from_bytes(payload[pos:pos + 2], "little")
        size = int.from_bytes(payload[pos + 2:pos + 4], "little")
        value = payload[pos + 4:pos + 4 + size]
        pos += 4 + size
        label = UDP_TAGS.get(tag, f"tag {tag}")
        if tag == 7 and len(value) == 6:
            tags[label] = ".".join(str(b) for b in value)
        elif tag in (2, 5, 12, 13):
            tags[label] = value.split(b"\x00", 1)[0].decode("latin-1", errors="replace")
        else:
            tags[label] = value.hex()
    return name, response, tags


def _logon(tags: dict[str, str]) -> tuple[str, str | None, str | None, str] | None:
    """(kind, user, password, detail) of an AddRoute request's Windows logon."""
    if "user name" not in tags and "password" not in tags:
        return None
    detail = f"user {tags.get('user name', '?')!r} password {tags.get('password', '?')!r}"
    return "ADS AddRoute Credential", tags.get("user name"), tags.get("password"), detail


def credentials(payload: bytes) -> list[tuple[str, str | None, str | None, str]]:
    """The logon this analysis reports, for --creds: (kind, user, password,
    detail) of a TwinCAT AddRoute request. The parse is the protocol's
    signature, so it matches on any port the analysis would."""
    udp = parse_udp(payload)
    if udp is None or udp[0] != "AddRoute" or udp[1]:
        return []
    logon = _logon(udp[2])
    return [logon] if logon else []


def _signature(payload: bytes) -> bool:
    return bool(_ams_frames(payload)) or parse_udp(payload) is not None


def _commands(payload: bytes) -> list[str]:
    udp = parse_udp(payload)
    if udp is not None:
        return [f"UDP {udp[0]}" + (" response" if udp[1] else "")]
    names = []
    for command, flags, _error, data, _src, _dst in _ams_frames(payload):
        name = COMMANDS.get(command, f"Command {command}")
        if flags & 0x0001:
            names.append(f"{name} response")
            continue
        if command in (2, 3, 9) and len(data) >= 4:
            group = int.from_bytes(data[0:4], "little")
            name += f" [{INDEX_GROUPS.get(group, f'group 0x{group:x}')}]"
        elif command == 5 and len(data) >= 2:
            name += f" -> {ADS_STATES.get(int.from_bytes(data[0:2], 'little'), '?')}"
        names.append(name)
    return names


class _AdsState:
    def __init__(self) -> None:
        self.routes: list[str] = []
        self.credentials: list[str] = []
        self.hosts: Counter[str] = Counter()
        self.writes: Counter[str] = Counter()
        self.writers: Counter[str] = Counter()
        self.control: Counter[str] = Counter()
        self.symbols: Counter[str] = Counter()
        self.errors: Counter[int] = Counter()
        self.first: dict[str, tuple[str, str, float]] = {}

    def feed(self, payload: bytes, src: str, dst: str, ts: float, _commands: object) -> list[IndustrialAnomaly]:
        udp = parse_udp(payload)
        if udp is not None:
            service, response, tags = udp
            host = tags.get("host/address") or tags.get("route name")
            if response and host:
                self.hosts[f"{src}: {host}"] += 1
            if service == "AddRoute" and not response:
                self.first.setdefault("route", (src, dst, ts))
                self.routes.append(f"{src} -> {dst}: route {tags.get('route name', '?')} for {tags.get('AMS NetId', '?')}")
                logon = _logon(tags)
                if logon:
                    self.credentials.append(f"{src} -> {dst}: {logon[3]}")
            return []
        for command, flags, error, data, _source, _target in _ams_frames(payload):
            if flags & 0x0001:
                if error:
                    self.errors[error] += 1
                continue
            if command == 3 or (command == 9 and len(data) >= 4 and int.from_bytes(data[0:4], "little") in (0xF081, 0xF082)):
                group = int.from_bytes(data[0:4], "little") if len(data) >= 4 else -1
                self.writes[INDEX_GROUPS.get(group, f"group 0x{group:x}")] += 1
                self.writers[src] += 1
                self.first.setdefault("write", (src, dst, ts))
            if command == 5 and len(data) >= 2:
                self.control[ADS_STATES.get(int.from_bytes(data[0:2], "little"), "?")] += 1
                self.first.setdefault("control", (src, dst, ts))
            if command == 9 and len(data) >= 16 and int.from_bytes(data[0:4], "little") == 0xF003:
                name = data[16:].split(b"\x00", 1)[0].decode("latin-1", errors="replace")
                if name:
                    self.symbols[name] += 1
        return []

    def findings(self) -> list[IndustrialAnomaly]:
        found: list[IndustrialAnomaly] = []
        if self.credentials:
            src, dst, ts = self.first["route"]
            found.append(IndustrialAnomaly(
                "HIGH", "ADS AddRoute with cleartext Windows credentials",
                f"{len(self.credentials)} TwinCAT AddRoute request(s) carry the target's user name and "
                "password in clear; a route gives unauthenticated ADS control of the PLC.",
                src, dst, ts, attack="T0859 Valid Accounts; T0886 Remote Services",
                evidence=self.credentials[:6] + self.routes[:4],
            ))
        elif self.routes:
            src, dst, ts = self.first["route"]
            found.append(IndustrialAnomaly(
                "MEDIUM", "ADS AddRoute", f"{len(self.routes)} route registration(s).",
                src, dst, ts, attack="T0886 Remote Services", evidence=self.routes[:6],
            ))
        if self.control:
            src, dst, ts = self.first["control"]
            stop = any(state in self.control for state in ("STOP", "RESET", "RECONFIG", "CONFIG", "SHUTDOWN"))
            found.append(IndustrialAnomaly(
                "HIGH" if stop else "MEDIUM", "ADS WriteControl (PLC state change)",
                "Requested ADS state(s): " + ", ".join(f"{s} x{c}" for s, c in self.control.most_common()) + ".",
                src, dst, ts, attack="T0858 Change Operating Mode",
            ))
        if self.writes:
            src, dst, ts = self.first["write"]
            found.append(IndustrialAnomaly(
                "HIGH", "ADS memory/variable writes",
                ", ".join(f"{g} x{c}" for g, c in self.writes.most_common(5))
                + f" from {', '.join(ip for ip, _n in self.writers.most_common(3))}.",
                src, dst, ts, attack="T0836 Modify Parameter; T0855 Unauthorized Command Message",
                evidence=[f"symbol {name}" for name, _c in self.symbols.most_common(8)],
            ))
        if self.errors:
            found.append(IndustrialAnomaly(
                "LOW", "ADS error responses",
                ", ".join(f"0x{code:x} x{count}" for code, count in self.errors.most_common(6)),
                "*", "*", 0.0,
            ))
        return found


@memoize_analysis
def analyze_ads(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    state = _AdsState()
    analysis = analyze_port_protocol(
        port_key="ads",
        path=path,
        protocol_name=PROTOCOL_NAME,
        tcp_ports={ADS_TCP_PORT},
        udp_ports={ADS_UDP_PORT},
        signature_matcher=_signature,
        command_parser=_commands,
        artifact_parser=lambda _payload: [],
        anomaly_detector=state.feed,
        enable_enrichment=True,
        show_status=show_status,
    )
    analysis.anomalies.extend(state.findings())
    for host, _count in state.hosts.most_common(10):
        analysis.artifacts.append(IndustrialArtifact("ads_host", host, "*", "*", 0.0))
    for name, _count in state.symbols.most_common(20):
        analysis.artifacts.append(IndustrialArtifact("ads_symbol", name, "*", "*", 0.0))
    append_public_exposure_anomaly(analysis, "ADS/AMS")
    return analysis
