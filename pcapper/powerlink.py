"""Ethernet POWERLINK (EPL, IEC 61158/61784 CPF 13).

EPL v2 runs on EtherType 0x88AB (and over UDP 3819 for routed ASnd). Frame:
message type (1: 0x01 SoC, 0x03 PReq, 0x04 PRes, 0x05 SoA, 0x06 ASnd)
| destination node (1) | source node (1) | ... Node 240 is the Managing Node
(MN); 255 is broadcast. ASnd carries a service ID (1 IdentResponse,
2 StatusResponse, 3 NMTRequest, 4 NMTCommand, 5 SDO); NMT commands start,
stop and reset controlled nodes. EPL v1 (EtherType 0x3E3F) is counted.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

from .industrial_helpers import (
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_protocols_together,
    ethertype_protocol_spec,
    port_protocol_spec,
)
from .utils import memoize_analysis

EPL_ETHERTYPE = 0x88AB
EPL_V1_ETHERTYPE = 0x3E3F
EPL_UDP_PORT = 3819
MN_NODE = 240

MESSAGE_TYPES = {0x01: "SoC", 0x03: "PReq", 0x04: "PRes", 0x05: "SoA", 0x06: "ASnd", 0x07: "AMNI", 0x0D: "AInv"}
ASND_SERVICES = {1: "IdentResponse", 2: "StatusResponse", 3: "NMTRequest", 4: "NMTCommand", 5: "SDO"}
NMT_COMMANDS = {
    0x21: "NMTStartNode", 0x22: "NMTStopNode", 0x23: "NMTEnterPreOperational2",
    0x24: "NMTEnableReadyToOperate", 0x28: "NMTResetNode", 0x29: "NMTResetCommunication",
    0x2A: "NMTResetConfiguration", 0x2B: "NMTSwReset", 0x41: "NMTStartNodeEx",
    0x42: "NMTStopNodeEx", 0x43: "NMTEnterPreOperational2Ex", 0x44: "NMTEnableReadyToOperateEx",
    0x48: "NMTResetNodeEx", 0x49: "NMTResetCommunicationEx", 0x4A: "NMTResetConfigurationEx",
    0x4B: "NMTSwResetEx", 0x62: "NMTNetHostNameSet", 0x63: "NMTFlushArpEntry",
}
DISRUPTIVE = {"NMTStopNode", "NMTResetNode", "NMTResetCommunication", "NMTResetConfiguration",
              "NMTSwReset", "NMTStopNodeEx", "NMTResetNodeEx", "NMTResetCommunicationEx",
              "NMTResetConfigurationEx", "NMTSwResetEx", "NMTEnterPreOperational2"}
SDO_COMMANDS = {0x01: "WriteByIndex", 0x02: "ReadByIndex", 0x03: "WriteAllByIndex",
                0x04: "ReadAllByIndex", 0x05: "WriteByName", 0x06: "ReadByName",
                0x20: "FileWrite", 0x21: "FileRead", 0x31: "WriteMultipleParamByIndex",
                0x32: "ReadMultipleParamByIndex"}


def describe(payload: bytes) -> tuple[str, int, int, str | None]:
    """(message, destination node, source node, detail) for an EPL v2 frame."""
    if len(payload) < 3:
        return "short", -1, -1, None
    mtype = payload[0] & 0x7F
    name = MESSAGE_TYPES.get(mtype, f"type 0x{mtype:02x}")
    detail = None
    if mtype == 0x06 and len(payload) >= 4:
        service = ASND_SERVICES.get(payload[3], f"service {payload[3]}")
        detail = service
        if payload[3] == 4 and len(payload) >= 5:
            detail = NMT_COMMANDS.get(payload[4], f"NMT 0x{payload[4]:02x}")
        elif payload[3] == 5 and len(payload) >= 12:
            flags, command = payload[10], payload[11]
            if not flags & 0x80:  # request, not response
                detail = f"SDO {SDO_COMMANDS.get(command, f'command 0x{command:02x}')}"
    return name, payload[1], payload[2], detail


def _commands(payload: bytes) -> list[str]:
    name, _dst, _src, detail = describe(payload)
    return [detail or name]


class _EplState:
    def __init__(self) -> None:
        self.mn_sources: set[str] = set()
        self.nmt: Counter[str] = Counter()
        self.nmt_src: dict[str, Counter[str]] = defaultdict(Counter)
        self.sdo_writes: Counter[str] = Counter()
        self.nodes: set[int] = set()

    def feed(self, payload: bytes, src: str, dst: str, ts: float, _commands: object) -> list[IndustrialAnomaly]:
        name, dst_node, src_node, detail = describe(payload)
        if src_node >= 0:
            self.nodes.add(src_node)
        if src_node == MN_NODE and name in ("SoC", "PReq", "SoA"):
            self.mn_sources.add(src)
        if detail in NMT_COMMANDS.values():
            self.nmt[detail] += 1
            self.nmt_src[detail][f"{src} (node {src_node}) -> node {dst_node}"] += 1
        if detail and detail.startswith("SDO Write"):
            self.sdo_writes[f"{src} -> node {dst_node}"] += 1
        return []

    def absorb(self, later: "_EplState") -> None:
        """Fold in a state fed with the frames after this one's: the same
        counts, and the same first-seen order, as one state fed with both."""
        self.mn_sources |= later.mn_sources
        self.nmt.update(later.nmt)
        for detail, pairs in later.nmt_src.items():
            self.nmt_src[detail].update(pairs)
        self.sdo_writes.update(later.sdo_writes)
        self.nodes |= later.nodes

    def findings(self) -> list[IndustrialAnomaly]:
        found: list[IndustrialAnomaly] = []
        if len(self.mn_sources) > 1:
            found.append(IndustrialAnomaly(
                "HIGH", "Multiple POWERLINK Managing Nodes",
                f"Cycle frames (SoC/PReq/SoA) from node 240 sent by {len(self.mn_sources)} different "
                "stations: a rogue or second MN is driving the cycle.",
                ", ".join(sorted(self.mn_sources)[:4]), "*", 0.0,
                attack="T0856 Spoof Reporting Message; T0830 Adversary-in-the-Middle",
                evidence=sorted(self.mn_sources)[:6],
            ))
        disruptive = {name: count for name, count in self.nmt.items() if name in DISRUPTIVE}
        if disruptive:
            found.append(IndustrialAnomaly(
                "HIGH", "POWERLINK NMT stop/reset commands",
                ", ".join(f"{n} x{c}" for n, c in sorted(disruptive.items())) + ".",
                "*", "*", 0.0, attack="T0816 Device Restart/Shutdown",
                evidence=[f"{n}: {pair}" for n in disruptive for pair, _c in self.nmt_src[n].most_common(2)],
            ))
        if self.sdo_writes:
            found.append(IndustrialAnomaly(
                "MEDIUM", "POWERLINK SDO writes (object dictionary changed)",
                ", ".join(f"{pair} x{c}" for pair, c in self.sdo_writes.most_common(4)) + ".",
                "*", "*", 0.0, attack="T0836 Modify Parameter",
            ))
        return found


def _merge(target: IndustrialAnalysis, other: IndustrialAnalysis) -> None:
    target.protocol_packets += other.protocol_packets
    target.protocol_bytes += other.protocol_bytes
    target.requests += other.requests
    target.responses += other.responses
    for attr in ("src_ips", "dst_ips", "client_ips", "server_ips", "sessions", "ports", "commands"):
        getattr(target, attr).update(getattr(other, attr))
    for name, endpoints in other.service_endpoints.items():
        target.service_endpoints.setdefault(name, type(endpoints)()).update(endpoints)
    target.command_events.extend(other.command_events)
    target.anomalies.extend(other.anomalies)
    target.errors.extend(other.errors)


@memoize_analysis
def analyze_powerlink(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    # EPL v2 on its EtherType, routed EPL on UDP 3819 and EPL v1, in one read.
    # Each feeds its own state; the UDP one is folded in after the L2 one,
    # as when the UDP frames were read in a second pass.
    state = _EplState()
    routed_state = _EplState()
    analysis, routed, v1 = analyze_protocols_together(
        path,
        [
            ethertype_protocol_spec(
                path,
                "POWERLINK",
                EPL_ETHERTYPE,
                command_parser=_commands,
                artifact_parser=lambda _payload: [],
                anomaly_detector=state.feed,
                enable_enrichment=True,
            ),
            port_protocol_spec(
                path,
                "POWERLINK (UDP)",
                port_key="powerlink",
                tcp_ports=set(),
                udp_ports={EPL_UDP_PORT},
                command_parser=_commands,
                artifact_parser=lambda _payload: [],
                anomaly_detector=routed_state.feed,
                enable_enrichment=True,
            ),
            ethertype_protocol_spec(
                path,
                "POWERLINK v1",
                EPL_V1_ETHERTYPE,
                command_parser=lambda _payload: ["EPL v1 frame"],
                artifact_parser=lambda _payload: [],
            ),
        ],
        show_status=show_status,
    )
    _merge(analysis, routed)
    _merge(analysis, v1)
    state.absorb(routed_state)
    analysis.anomalies.extend(state.findings())
    return analysis
