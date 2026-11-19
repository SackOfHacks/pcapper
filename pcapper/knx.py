"""KNXnet/IP (building automation, UDP/TCP 3671) and the cEMI frames it carries.

KNXnet/IP wraps KNX bus telegrams (cEMI) for tunnelling to an IP interface or
routing between lines. On the wire:

    KNXnet/IP header: 0x06 | version 0x10 | service type (2) | total length (2)
    tunnelling:       connection header (len 4, channel, sequence, status)
    cEMI:             message code | add-info length (+ info) | ctrl1 | ctrl2
                      | source (individual addr) | destination | NPDU length
                      | TPCI/APCI (2) | data

Group telegrams (``GroupValueWrite`` to a group address) switch lights,
blinds, HVAC and access control; device management (``MemoryWrite``,
``PropertyValueWrite``, ``Restart``, ``M_Reset``, ``IndividualAddressWrite``)
reprograms the devices themselves. Analysed by payload structure on any
port: the KNX IDS dataset also tunnels on UDP 20100.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from .industrial_helpers import (
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
    append_public_exposure_anomaly,
)
from .utils import memoize_analysis

KNX_PORT = 3671

SERVICE_TYPES = {
    0x0201: "SEARCH_REQUEST", 0x0202: "SEARCH_RESPONSE",
    0x0203: "DESCRIPTION_REQUEST", 0x0204: "DESCRIPTION_RESPONSE",
    0x0205: "CONNECT_REQUEST", 0x0206: "CONNECT_RESPONSE",
    0x0207: "CONNECTIONSTATE_REQUEST", 0x0208: "CONNECTIONSTATE_RESPONSE",
    0x0209: "DISCONNECT_REQUEST", 0x020A: "DISCONNECT_RESPONSE",
    0x020B: "SEARCH_REQUEST_EXT", 0x020C: "SEARCH_RESPONSE_EXT",
    0x0310: "DEVICE_CONFIGURATION_REQUEST", 0x0311: "DEVICE_CONFIGURATION_ACK",
    0x0420: "TUNNELLING_REQUEST", 0x0421: "TUNNELLING_ACK",
    0x0422: "TUNNELLING_FEATURE_GET", 0x0423: "TUNNELLING_FEATURE_RESPONSE",
    0x0424: "TUNNELLING_FEATURE_SET", 0x0425: "TUNNELLING_FEATURE_INFO",
    0x0530: "ROUTING_INDICATION", 0x0531: "ROUTING_LOST_MESSAGE",
    0x0532: "ROUTING_BUSY", 0x0533: "ROUTING_SYSTEM_BROADCAST",
    0x0740: "REMOTE_DIAGNOSTIC_REQUEST", 0x0741: "REMOTE_DIAGNOSTIC_RESPONSE",
    0x0742: "REMOTE_BASIC_CONFIGURATION_REQUEST", 0x0743: "REMOTE_RESET_REQUEST",
    0x0950: "SECURE_WRAPPER", 0x0951: "SESSION_REQUEST", 0x0952: "SESSION_RESPONSE",
    0x0953: "SESSION_AUTHENTICATE", 0x0954: "SESSION_STATUS", 0x0955: "TIMER_NOTIFY",
}

CEMI_CODES = {
    0x11: "L_Data.req", 0x2E: "L_Data.con", 0x29: "L_Data.ind",
    0x10: "L_Raw.req", 0x2D: "L_Raw.ind", 0x2F: "L_Raw.con", 0x2B: "L_Busmon.ind",
    0x13: "L_Poll_Data.req", 0x25: "L_Poll_Data.con",
    0xFC: "M_PropRead.req", 0xFB: "M_PropRead.con", 0xF6: "M_PropWrite.req",
    0xF5: "M_PropWrite.con", 0xF7: "M_PropInfo.ind", 0xF8: "M_FuncPropCommand.req",
    0xF9: "M_FuncPropStateRead.req", 0xFA: "M_FuncPropCommand.con",
    0xF1: "M_Reset.req", 0xF0: "M_Reset.ind",
}

# 4-bit APCI families; 0x3C0 (escape) is resolved with the full 10 bits.
APCI_NAMES = {
    0x000: "GroupValueRead", 0x040: "GroupValueResponse", 0x080: "GroupValueWrite",
    0x0C0: "IndividualAddressWrite", 0x100: "IndividualAddressRead",
    0x140: "IndividualAddressResponse", 0x180: "ADC_Read", 0x1C0: "ADC_Response",
    0x200: "MemoryRead", 0x240: "MemoryResponse", 0x280: "MemoryWrite",
    0x2C0: "UserMessage", 0x300: "DeviceDescriptorRead",
    0x340: "DeviceDescriptorResponse", 0x380: "Restart",
}
APCI_ESCAPE = {
    0x3C8: "SystemNetworkParameterRead", 0x3C9: "SystemNetworkParameterResponse",
    0x3CA: "SystemNetworkParameterWrite", 0x3D1: "AuthorizeRequest",
    0x3D2: "AuthorizeResponse", 0x3D3: "KeyWrite", 0x3D4: "KeyResponse",
    0x3D5: "PropertyValueRead", 0x3D6: "PropertyValueResponse",
    0x3D7: "PropertyValueWrite", 0x3D8: "PropertyDescriptionRead",
    0x3D9: "PropertyDescriptionResponse", 0x3DA: "NetworkParameterRead",
    0x3DB: "NetworkParameterResponse", 0x3DC: "IndividualAddressSerialNumberRead",
    0x3DD: "IndividualAddressSerialNumberResponse",
    0x3DE: "IndividualAddressSerialNumberWrite", 0x3E0: "DomainAddressWrite",
    0x3E1: "DomainAddressRead", 0x3E2: "DomainAddressResponse",
    0x3E3: "DomainAddressSelectiveRead", 0x3E4: "NetworkParameterWrite",
    0x3E5: "LinkRead", 0x3E6: "LinkResponse", 0x3E7: "LinkWrite",
}
TPCI_CONTROL = {0x80: "T_Connect", 0x81: "T_Disconnect", 0xC2: "T_ACK", 0xC3: "T_NAK"}

DEVICE_WRITE = {
    "MemoryWrite", "PropertyValueWrite", "IndividualAddressWrite", "KeyWrite",
    "IndividualAddressSerialNumberWrite", "DomainAddressWrite", "LinkWrite",
    "SystemNetworkParameterWrite", "NetworkParameterWrite", "M_PropWrite.req",
}
DEVICE_RESET = {"Restart", "M_Reset.req", "REMOTE_RESET_REQUEST"}
DISCOVERY = {
    "SEARCH_REQUEST", "SEARCH_REQUEST_EXT", "DESCRIPTION_REQUEST",
    "DeviceDescriptorRead", "IndividualAddressRead", "T_Connect",
    "IndividualAddressSerialNumberRead", "M_PropRead.req", "PropertyValueRead",
}


def individual_address(value: int) -> str:
    return f"{value >> 12}.{(value >> 8) & 0x0F}.{value & 0xFF}"


def group_address(value: int) -> str:
    return f"{(value >> 11) & 0x1F}/{(value >> 8) & 0x07}/{value & 0xFF}"


@dataclass(frozen=True)
class KnxTelegram:
    service: str
    cemi: str | None = None
    apci: str | None = None
    source: str | None = None
    destination: str | None = None
    group: bool = False
    value: str | None = None
    malformed: bool = False


def _cemi(data: bytes) -> tuple[str | None, str | None, str | None, str | None, bool, str | None, bool]:
    """(cemi, apci, source, destination, is_group, value, malformed)."""
    if not data:
        return None, None, None, None, False, None, True
    code = CEMI_CODES.get(data[0], f"cEMI 0x{data[0]:02x}")
    if data[0] in (0xF1, 0xF0, 0xFC, 0xFB, 0xF6, 0xF5, 0xF7):
        return code, None, None, None, False, None, False
    if data[0] not in (0x11, 0x2E, 0x29, 0x13, 0x25):
        return code, None, None, None, False, None, False
    if len(data) < 2:
        return code, None, None, None, False, None, True
    pos = 2 + data[1]
    if len(data) < pos + 7:
        return code, None, None, None, False, None, True
    ctrl2 = data[pos + 1]
    src = int.from_bytes(data[pos + 2:pos + 4], "big")
    dst = int.from_bytes(data[pos + 4:pos + 6], "big")
    npdu_len = data[pos + 6]
    group = bool(ctrl2 & 0x80)
    source = individual_address(src)
    destination = group_address(dst) if group else individual_address(dst)
    tpdu = data[pos + 7:]
    malformed = len(tpdu) != npdu_len + 1
    if not tpdu:
        return code, None, source, destination, group, None, True
    tpci = tpdu[0]
    if npdu_len == 0 or len(tpdu) < 2:
        return code, TPCI_CONTROL.get(tpci & 0xC3, f"TPCI 0x{tpci:02x}"), source, destination, group, None, malformed
    apci_value = ((tpci & 0x03) << 8) | tpdu[1]
    family = apci_value & 0x3C0
    if family == 0x3C0:
        apci = APCI_ESCAPE.get(apci_value, f"APCI 0x{apci_value:03x}")
    else:
        apci = APCI_NAMES.get(family, f"APCI 0x{family:03x}")
    value = None
    if apci in ("GroupValueWrite", "GroupValueResponse"):
        value = str(tpdu[1] & 0x3F) if npdu_len == 1 else tpdu[2:].hex()
    return code, apci, source, destination, group, value, malformed


def parse_knx(payload: bytes) -> KnxTelegram | None:
    """One KNXnet/IP frame, or None when the header does not frame the payload."""
    if len(payload) < 6 or payload[0] != 0x06 or payload[1] not in (0x10, 0x20):
        return None
    service_type = int.from_bytes(payload[2:4], "big")
    if int.from_bytes(payload[4:6], "big") != len(payload) or not 0x0200 <= service_type <= 0x09FF:
        return None
    service = SERVICE_TYPES.get(service_type, f"SERVICE 0x{service_type:04x}")
    body = payload[6:]
    if service_type in (0x0420, 0x0310) and body:
        cemi = body[body[0]:] if body[0] >= 4 else b""
    elif service_type == 0x0530:
        cemi = body
    else:
        return KnxTelegram(service=service)
    code, apci, source, destination, group, value, malformed = _cemi(cemi)
    return KnxTelegram(service, code, apci, source, destination, group, value, malformed)


def _knx_signature(payload: bytes) -> bool:
    return parse_knx(payload) is not None


def _commands(payload: bytes) -> list[str]:
    telegram = parse_knx(payload)
    if telegram is None:
        return []
    names = [telegram.service]
    if telegram.cemi and telegram.cemi.startswith("M_"):
        names.append(telegram.cemi)
    if telegram.apci:
        names.append(telegram.apci)
    return names


class _KnxState:
    """Aggregates the per-packet detector feeds; turned into findings at the end."""

    def __init__(self) -> None:
        self.group_writes: Counter[str] = Counter()  # by IP source
        self.write_times: dict[str, list[float]] = defaultdict(list)
        self.write_targets: dict[str, Counter[str]] = defaultdict(Counter)
        self.write_values: dict[str, set[str]] = defaultdict(set)
        self.discovery: dict[str, Counter[str]] = defaultdict(Counter)
        self.discovery_targets: dict[str, set[str]] = defaultdict(set)
        self.device_writes: dict[str, Counter[str]] = defaultdict(Counter)
        self.resets: dict[str, Counter[str]] = defaultdict(Counter)
        self.malformed: Counter[str] = Counter()
        self.prop_reads: Counter[str] = Counter()
        self.secure = 0
        self.telegrams = 0
        self.group_reads: Counter[str] = Counter()
        self.read_targets: dict[str, set[str]] = defaultdict(set)
        self.relayed_writes: Counter[str] = Counter()

    def feed(self, payload: bytes, src: str, dst: str, ts: float, _commands: object) -> list[IndustrialAnomaly]:
        telegram = parse_knx(payload)
        if telegram is None:
            return []
        self.telegrams += 1
        if telegram.service.startswith(("SECURE_", "SESSION_")):
            self.secure += 1
        if telegram.malformed:
            self.malformed[src] += 1
        names = {telegram.service, telegram.cemi or "", telegram.apci or ""}
        # Only telegrams a host *sends* onto the bus count against it: an
        # L_Data.req through a tunnel, or a routing indication from a router.
        # L_Data.ind is the KNX/IP interface relaying what the bus carried.
        sent = telegram.cemi in ("L_Data.req", None) or telegram.service == "ROUTING_INDICATION"
        if telegram.apci == "GroupValueRead" and sent and telegram.destination:
            self.group_reads[src] += 1
            if len(self.read_targets[src]) < 100_000:
                self.read_targets[src].add(telegram.destination)
        if telegram.apci == "GroupValueWrite" and not sent:
            self.relayed_writes[src] += 1
        elif telegram.apci == "GroupValueWrite":
            self.group_writes[src] += 1
            if len(self.write_times[src]) < 200_000:
                self.write_times[src].append(ts)
            if telegram.destination:
                self.write_targets[src][telegram.destination] += 1
            if telegram.value is not None and len(self.write_values[src]) < 5000:
                self.write_values[src].add(telegram.value)
        for name in (names & DISCOVERY) if sent or telegram.cemi.startswith("M_") else ():
            self.discovery[src][name] += 1
            target = telegram.destination or dst
            if len(self.discovery_targets[src]) < 100_000:
                self.discovery_targets[src].add(target)
        if "M_PropRead.req" in names:
            self.prop_reads[src] += 1
        for name in names & DEVICE_WRITE:
            self.device_writes[src][name] += 1
        for name in names & DEVICE_RESET:
            self.resets[src][name] += 1
        return []

    def findings(self) -> list[IndustrialAnomaly]:
        found: list[IndustrialAnomaly] = []
        for src, count in self.group_writes.most_common(10):
            times = sorted(self.write_times.get(src, []))
            span = (times[-1] - times[0]) if len(times) > 1 else 0.0
            rate = count / span if span > 0 else float(count)
            targets = self.write_targets[src]
            values = self.write_values[src]
            evidence = [
                f"{count} GroupValueWrite over {span:.1f}s ({rate:.1f}/s)",
                "groups: " + ", ".join(f"{g}({n})" for g, n in targets.most_common(6)),
                f"{len(values)} distinct value(s)",
            ]
            fuzz = len(values) >= 64 or len(targets) >= 64
            if fuzz or (count >= 1000 and rate >= 10):
                found.append(IndustrialAnomaly(
                    "HIGH",
                    "KNX GroupValueWrite fuzzing (many groups/values)" if fuzz else "KNX GroupValueWrite flood",
                    f"{src} sent {count} group writes at {rate:.0f}/s to {len(targets)} group(s): "
                    "bus saturation and actuator flapping (lights, blinds, HVAC, access).",
                    src, "*", times[0] if times else 0.0,
                    attack="T0814 Denial of Service" + ("; T0806 Brute Force I/O" if fuzz else ""),
                    evidence=evidence,
                ))
            else:
                found.append(IndustrialAnomaly(
                    "MEDIUM",
                    "KNX group writes (actuator commands)",
                    f"{src} sent {count} GroupValueWrite telegram(s) to {len(targets)} group(s); "
                    "confirm the sender is a commissioned KNX/IP interface or visualisation.",
                    src, "*", times[0] if times else 0.0,
                    attack="T0855 Unauthorized Command Message",
                    evidence=evidence,
                ))
        for src, count in self.group_reads.most_common(5):
            targets = self.read_targets[src]
            if len(targets) < 64 and count < 1000:
                continue
            found.append(IndustrialAnomaly(
                "MEDIUM", "KNX GroupValueRead sweep/fuzzing",
                f"{src} sent {count} GroupValueRead request(s) across {len(targets)} group address(es): "
                "group-address enumeration or read flooding.",
                src, "*", 0.0, attack="T0861 Point & Tag Identification",
                evidence=sorted(targets)[:8],
            ))
        for src, names in self.resets.items():
            found.append(IndustrialAnomaly(
                "HIGH", "KNX device reset",
                f"{src}: " + ", ".join(f"{n} x{c}" for n, c in names.most_common()) + ".",
                src, "*", 0.0, attack="T0816 Device Restart/Shutdown",
                evidence=[f"{n}: {c}" for n, c in names.most_common()],
            ))
        for src, names in self.device_writes.items():
            found.append(IndustrialAnomaly(
                "HIGH", "KNX device configuration written",
                f"{src}: " + ", ".join(f"{n} x{c}" for n, c in names.most_common()) + " (device memory/properties/addressing changed).",
                src, "*", 0.0, attack="T0836 Modify Parameter",
                evidence=[f"{n}: {c}" for n, c in names.most_common()],
            ))
        for src, names in self.discovery.items():
            targets = self.discovery_targets[src]
            total = sum(names.values())
            if len(targets) < 10 and total < 100:
                continue
            fuzz = self.prop_reads.get(src, 0) >= 500
            found.append(IndustrialAnomaly(
                "MEDIUM",
                "KNX property read fuzzing" if fuzz else "KNX bus/network scanning",
                f"{src} sent {total} discovery request(s) to {len(targets)} distinct device/IP target(s): "
                + ", ".join(f"{n} x{c}" for n, c in names.most_common(4)) + ".",
                src, "*", 0.0, attack="T0846 Remote System Discovery",
                evidence=sorted(targets)[:8],
            ))
        for src, count in self.malformed.most_common(5):
            if count >= 10:
                found.append(IndustrialAnomaly(
                    "MEDIUM", "Malformed KNX telegrams (possible fuzzing)",
                    f"{src}: {count} cEMI frame(s) whose NPDU length does not match the data.",
                    src, "*", 0.0, attack="T0806 Brute Force I/O",
                ))
        return found


@memoize_analysis
def analyze_knx(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    state = _KnxState()
    analysis = analyze_port_protocol(
        port_key="knx",
        path=path,
        protocol_name="KNXnet/IP",
        tcp_ports={KNX_PORT},
        udp_ports={KNX_PORT},
        signature_matcher=_knx_signature,
        command_parser=_commands,
        artifact_parser=lambda _payload: [],
        anomaly_detector=state.feed,
        enable_enrichment=True,
        show_status=show_status,
    )
    analysis.anomalies.extend(state.findings())
    if state.secure:
        analysis.artifacts.append(
            _artifact("KNX Secure", f"{state.secure} KNX IP Secure frame(s) (session/secure wrapper)")
        )
    append_public_exposure_anomaly(analysis, "KNXnet/IP")
    return analysis


def _artifact(kind: str, detail: str):
    from .industrial_helpers import IndustrialArtifact

    return IndustrialArtifact(kind=kind, detail=detail, src="*", dst="*", ts=0.0)
