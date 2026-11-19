"""LonTalk (LonWorks, ISO/IEC 14908-1) carried over CN/IP (EIA-852 / ISO 14908-4).

CN/IP (UDP 1628 data, 1629 configuration) puts a 20-byte header in front of
each LonTalk packet: packet length (2, BE) | version (1) | packet type (1)
| extended header size (1) | protocol flags (1) | vendor code (2) | session
ID (4) | sequence number (4) | timestamp (4).

The LonTalk packet: priority/alt-path/delta-backlog byte, then the NPDU
header (version 2 bits | PDU format 2 | address format 2 | domain length 2),
source subnet/node, destination (by address format), domain ID (0/1/3/6
bytes), then for TPDU/SPDU a transaction byte, then the APDU whose first
byte is the message code: 0x80+ network-variable messages, 0x60-0x7F network
management, 0x50-0x5F diagnostics, 0x00-0x3F application messages.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .industrial_helpers import (
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
    append_public_exposure_anomaly,
)
from .utils import memoize_analysis

CNIP_PORTS = {1628, 1629}
CNIP_PACKET_TYPES = {
    0x01: "Data", 0x03: "Device registration request", 0x04: "Device configuration request",
    0x05: "Channel membership request", 0x06: "Send list request", 0x07: "Channel routing request",
    0x08: "Channel membership", 0x09: "Send list", 0x0A: "Channel routing",
    0x0B: "Device registration", 0x0C: "Device configuration", 0x0D: "Acknowledge",
    0x0E: "Segment", 0x0F: "Status/health request", 0x10: "Status/health response",
    0x60: "Echelon proprietary", 0x7F: "Vendor specific",
}
NM_CODES = {
    0x60: "Query ID", 0x61: "Respond to Query", 0x62: "Update Domain", 0x63: "Leave Domain",
    0x64: "Update Key", 0x65: "Update Address", 0x66: "Query Address", 0x67: "Query NV Config",
    0x68: "Update Group Address", 0x69: "Query Domain", 0x6A: "Update NV Config",
    0x6B: "Set Node Mode", 0x6C: "Read Memory", 0x6D: "Write Memory",
    0x6E: "Checksum Recalculate", 0x6F: "Wink/Install", 0x70: "Memory Refresh",
    0x71: "Query SNVT", 0x72: "NV Fetch", 0x73: "Device Escape",
    0x51: "Query Status", 0x52: "Proxy", 0x53: "Clear Status", 0x54: "Query Transceiver Status",
}
NM_WRITES = {"Update Domain", "Leave Domain", "Update Key", "Update Address", "Update Group Address",
             "Update NV Config", "Set Node Mode", "Write Memory", "Checksum Recalculate", "Memory Refresh"}
_DOMAIN_LENGTHS = (0, 1, 3, 6)
_PDU_FORMATS = ("TPDU", "SPDU", "AuthPDU", "APDU")


@dataclass(frozen=True)
class LonPacket:
    packet_type: str
    session: int
    sequence: int
    source: str | None = None
    destination: str | None = None
    pdu: str | None = None
    message: str | None = None
    nv_selector: int | None = None


def parse_cnip(payload: bytes) -> LonPacket | None:
    if len(payload) < 20 or int.from_bytes(payload[0:2], "big") != len(payload) or payload[2] not in (1, 2):
        return None
    ptype = payload[3]
    packet_type = CNIP_PACKET_TYPES.get(ptype, f"type 0x{ptype:02x}")
    session = int.from_bytes(payload[8:12], "big")
    sequence = int.from_bytes(payload[12:16], "big")
    if ptype != 0x01:
        return LonPacket(packet_type, session, sequence)
    lon = payload[20 + payload[4] * 4 if payload[4] else 20:]
    try:
        npdu = lon[1]
        pdu_format = (npdu >> 4) & 0x03
        addr_format = (npdu >> 2) & 0x03
        domain_len = _DOMAIN_LENGTHS[npdu & 0x03]
        src_subnet, src_node = lon[2], lon[3]
        pos = 4
        if addr_format == 0:
            dest = f"subnet {lon[pos]} (broadcast)"
            pos += 1
        elif addr_format == 1:
            dest = f"group {lon[pos]}"
            pos += 1
        elif addr_format == 2:
            if src_node & 0x80:
                dest = f"{lon[pos]}/{lon[pos + 1] & 0x7F}"
                pos += 2
            else:
                dest = f"{lon[pos]}/{lon[pos + 1] & 0x7F} (group {lon[pos + 2]} ack)"
                pos += 4
        else:
            dest = f"Neuron ID {lon[pos + 1:pos + 7].hex()}"
            pos += 7
        pos += domain_len
        if pdu_format in (0, 1, 2):
            pos += 1  # transaction byte (TPDU/SPDU/AuthPDU type + transaction no.)
            if pdu_format == 0 and (lon[pos - 1] >> 4) & 0x07 not in (0, 1, 5):
                return LonPacket(packet_type, session, sequence, f"{src_subnet}/{src_node & 0x7F}", dest,
                                 _PDU_FORMATS[pdu_format])
        code = lon[pos] if pos < len(lon) else None
    except IndexError:
        return LonPacket(packet_type, session, sequence)
    message = None
    selector = None
    if code is not None:
        if code & 0x80:
            selector = ((code & 0x3F) << 8) | (lon[pos + 1] if pos + 1 < len(lon) else 0)
            message = "NV Update" if not code & 0x40 else "NV Poll"
        else:
            message = NM_CODES.get(code, f"App message 0x{code:02x}" if code < 0x40 else f"Message 0x{code:02x}")
    return LonPacket(
        packet_type, session, sequence, f"{src_subnet}/{src_node & 0x7F}", dest,
        _PDU_FORMATS[pdu_format], message, selector,
    )


def _signature(payload: bytes) -> bool:
    return parse_cnip(payload) is not None


def _commands(payload: bytes) -> list[str]:
    packet = parse_cnip(payload)
    if packet is None:
        return []
    return [packet.message or f"CN/IP {packet.packet_type}"]


class _LonState:
    def __init__(self) -> None:
        self.nm: Counter[str] = Counter()
        self.nm_src: Counter[str] = Counter()
        self.nv_updates: Counter[str] = Counter()
        self.nodes: set[str] = set()
        self.last_seq: dict[tuple[str, int], int] = {}
        self.seq_anomalies = 0
        self.first: tuple[str, str, float] | None = None

    def feed(self, payload: bytes, src: str, dst: str, ts: float, _commands: object) -> list[IndustrialAnomaly]:
        packet = parse_cnip(payload)
        if packet is None:
            return []
        if packet.source:
            self.nodes.add(packet.source)
        key = (src, packet.session)
        previous = self.last_seq.get(key)
        if previous is not None and packet.sequence and packet.sequence <= previous:
            self.seq_anomalies += 1
        self.last_seq[key] = packet.sequence
        if packet.message in NM_WRITES:
            self.nm[packet.message] += 1
            self.nm_src[f"{src} (node {packet.source})"] += 1
            if self.first is None:
                self.first = (src, dst, ts)
        elif packet.message == "NV Update" and packet.destination:
            self.nv_updates[f"{packet.source} -> {packet.destination} sel 0x{packet.nv_selector:04x}"] += 1
        return []

    def findings(self) -> list[IndustrialAnomaly]:
        found: list[IndustrialAnomaly] = []
        if self.nm:
            src, dst, ts = self.first or ("*", "*", 0.0)
            reset = any(name in self.nm for name in ("Set Node Mode", "Leave Domain", "Update Key"))
            found.append(IndustrialAnomaly(
                "HIGH" if reset else "MEDIUM", "LonWorks network management writes",
                ", ".join(f"{n} x{c}" for n, c in self.nm.most_common()) + " (device addressing, "
                "domains, keys, NV bindings or memory changed; Set Node Mode takes nodes offline/resets).",
                src, dst, ts, attack="T0836 Modify Parameter; T0816 Device Restart/Shutdown" if reset else "T0836 Modify Parameter",
                evidence=[f"{s}: {c}" for s, c in self.nm_src.most_common(5)],
            ))
        if self.seq_anomalies >= 3:
            found.append(IndustrialAnomaly(
                "LOW", "CN/IP sequence numbers not increasing",
                f"{self.seq_anomalies} CN/IP data packet(s) repeated or reversed a session sequence "
                "number (replay, duplication or a restarted sender).",
                "*", "*", 0.0, attack="T0856 Spoof Reporting Message",
            ))
        return found


@memoize_analysis
def analyze_lontalk(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    state = _LonState()
    analysis = analyze_port_protocol(
        port_key="lontalk",
        path=path,
        protocol_name="LonTalk (CN/IP)",
        tcp_ports=set(),
        udp_ports=CNIP_PORTS,
        command_parser=_commands,
        artifact_parser=lambda _payload: [],
        anomaly_detector=state.feed,
        enable_enrichment=True,
        show_status=show_status,
    )
    analysis.anomalies.extend(state.findings())
    append_public_exposure_anomaly(analysis, "LonTalk/CN-IP")
    return analysis
