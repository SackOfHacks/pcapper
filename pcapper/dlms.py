"""DLMS/COSEM (IEC 62056, smart metering) over the TCP/UDP wrapper, port 4059.

IEC 62056-47 wrapper: version (2, = 1) | source wPort (2) | destination wPort
(2) | length (2) | APDU. APDU tags (IEC 62056-53): 0x60 AARQ, 0x61 AARE,
0x62 RLRQ, 0x63 RLRE, 0xC0 Get-Request, 0xC1 Set-Request, 0xC2
Event-Notification, 0xC3 Action-Request, 0xC4 Get-Response, 0xC5
Set-Response, 0xC7 Action-Response, 0xD8 Exception-Response; 0xC8-0xCF the
global-ciphered variants, 0xDB/0xDC general-glo/ded-ciphering.

Normal Get/Set/Action requests name the target as class ID (2) + logical
name (OBIS code, 6 bytes) + attribute/method ID. An AARQ using low-level
security (LLS) carries the meter password in clear in the calling
authentication value (0xAC -> 0x80).
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from .industrial_helpers import (
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
    append_public_exposure_anomaly,
)
from .utils import memoize_analysis

DLMS_PORT = 4059

APDUS = {
    0x60: "AARQ", 0x61: "AARE", 0x62: "RLRQ", 0x63: "RLRE",
    0xC0: "Get-Request", 0xC1: "Set-Request", 0xC2: "Event-Notification",
    0xC3: "Action-Request", 0xC4: "Get-Response", 0xC5: "Set-Response",
    0xC7: "Action-Response", 0xD8: "Exception-Response",
    0xC8: "glo-Get-Request", 0xC9: "glo-Set-Request", 0xCA: "glo-Event-Notification",
    0xCB: "glo-Action-Request", 0xCC: "glo-Get-Response", 0xCD: "glo-Set-Response",
    0xCF: "glo-Action-Response", 0xDB: "general-glo-ciphering", 0xDC: "general-ded-ciphering",
    0xDD: "general-ciphering", 0x0E: "Confirmed-Service-Error",
}
CIPHERED = {0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCF, 0xDB, 0xDC, 0xDD}
# Well-known COSEM objects worth naming in a report.
OBIS_NAMES = {
    "0.0.1.0.0.255": "Clock", "0.0.96.3.10.255": "Disconnect control",
    "0.0.43.1.0.255": "Invocation counter", "0.0.40.0.0.255": "Current association",
    "0.0.15.0.0.255": "Single action schedule", "0.0.44.0.0.255": "Image transfer (firmware)",
    "0.0.10.0.0.255": "Script table", "1.0.1.8.0.255": "Active energy import",
    "1.0.2.8.0.255": "Active energy export", "0.0.42.0.0.255": "COSEM logical device name",
}
DISCONNECT_OBIS = "0.0.96.3.10.255"
FIRMWARE_OBIS = "0.0.44.0.0.255"


def parse_dlms(payload: bytes) -> tuple[str, str | None, int | None, bytes] | None:
    """(APDU name, OBIS code, class id, APDU) for one wrapper frame."""
    if len(payload) < 9 or payload[0:2] != b"\x00\x01":
        return None
    if payload[2] != 0 or payload[4] != 0:
        return None  # wPorts are small (1 = management, 16 = public client ...)
    if int.from_bytes(payload[6:8], "big") + 8 != len(payload):
        return None
    apdu = payload[8:]
    tag = apdu[0]
    if tag not in APDUS:
        return None
    obis = None
    class_id = None
    # Get/Set/Action-Request-Normal: tag, request type 0x01, invoke-id,
    # class id (2), instance id / OBIS (6), attribute or method id (1).
    if tag in (0xC0, 0xC1, 0xC3) and len(apdu) >= 12 and apdu[1] == 0x01:
        class_id = int.from_bytes(apdu[3:5], "big")
        obis = ".".join(str(b) for b in apdu[5:11])
    return APDUS[tag], obis, class_id, bytes(apdu)


def _lls_password(apdu: bytes) -> str | None:
    """Calling authentication value of an AARQ (LLS sends the password)."""
    if not apdu or apdu[0] != 0x60:
        return None
    pos = 2
    while pos + 2 <= len(apdu):
        tag, size = apdu[pos], apdu[pos + 1]
        value = apdu[pos + 2:pos + 2 + size]
        if tag == 0xAC and len(value) >= 2 and value[0] == 0x80:
            return value[2:2 + value[1]].decode("latin-1", errors="replace")
        pos += 2 + size
    return None


def _signature(payload: bytes) -> bool:
    return parse_dlms(payload) is not None


def _commands(payload: bytes) -> list[str]:
    parsed = parse_dlms(payload)
    if parsed is None:
        return []
    name, obis, _class_id, _apdu = parsed
    if obis:
        return [f"{name} {OBIS_NAMES.get(obis, obis)}"]
    return [name]


class _DlmsState:
    def __init__(self) -> None:
        self.passwords: list[str] = []
        self.sets: Counter[str] = Counter()
        self.actions: Counter[str] = Counter()
        self.ciphered = 0
        self.plain = 0
        self.first: dict[str, tuple[str, str, float]] = {}

    def feed(self, payload: bytes, src: str, dst: str, ts: float, _commands: object) -> list[IndustrialAnomaly]:
        parsed = parse_dlms(payload)
        if parsed is None:
            return []
        name, obis, _class_id, apdu = parsed
        if apdu[0] in CIPHERED:
            self.ciphered += 1
        elif apdu[0] in (0xC0, 0xC1, 0xC3, 0xC4, 0xC5, 0xC7):
            self.plain += 1
        password = _lls_password(apdu)
        if password is not None:
            self.passwords.append(f"{src} -> {dst}: LLS password {password!r}")
            self.first.setdefault("cred", (src, dst, ts))
        label = OBIS_NAMES.get(obis or "", obis or "?")
        if name == "Set-Request":
            self.sets[label] += 1
            self.first.setdefault("set", (src, dst, ts))
        if name == "Action-Request":
            self.actions[label] += 1
            self.first.setdefault("action", (src, dst, ts))
        return []

    def findings(self) -> list[IndustrialAnomaly]:
        found: list[IndustrialAnomaly] = []
        if self.passwords:
            src, dst, ts = self.first["cred"]
            found.append(IndustrialAnomaly(
                "HIGH", "DLMS low-level-security password in clear",
                f"{len(self.passwords)} AARQ(s) authenticate with an LLS password.",
                src, dst, ts, attack="T0859 Valid Accounts", evidence=self.passwords[:6],
            ))
        disconnect = self.actions.get(OBIS_NAMES[DISCONNECT_OBIS], 0)
        firmware = self.actions.get(OBIS_NAMES[FIRMWARE_OBIS], 0) + self.sets.get(OBIS_NAMES[FIRMWARE_OBIS], 0)
        if disconnect:
            src, dst, ts = self.first["action"]
            found.append(IndustrialAnomaly(
                "HIGH", "DLMS remote disconnect/reconnect",
                f"{disconnect} Action-Request(s) on the disconnect control object (supply switched).",
                src, dst, ts, attack="T0831 Manipulation of Control; T0826 Loss of Availability",
            ))
        if firmware:
            src, dst, ts = self.first.get("action") or self.first["set"]
            found.append(IndustrialAnomaly(
                "HIGH", "DLMS firmware image transfer",
                f"{firmware} request(s) on the image transfer object.",
                src, dst, ts, attack="T0839 Module Firmware",
            ))
        if self.sets:
            src, dst, ts = self.first["set"]
            found.append(IndustrialAnomaly(
                "MEDIUM", "DLMS attribute writes (Set-Request)",
                ", ".join(f"{k} x{v}" for k, v in self.sets.most_common(6)) + ".",
                src, dst, ts, attack="T0836 Modify Parameter",
            ))
        if self.plain and not self.ciphered:
            found.append(IndustrialAnomaly(
                "LOW", "DLMS without ciphering",
                f"{self.plain} unciphered Get/Set/Action APDU(s).", "*", "*", 0.0,
            ))
        return found


@memoize_analysis
def analyze_dlms(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    state = _DlmsState()
    analysis = analyze_port_protocol(
        port_key="dlms",
        path=path,
        protocol_name="DLMS/COSEM",
        tcp_ports={DLMS_PORT},
        udp_ports={DLMS_PORT},
        signature_matcher=_signature,
        command_parser=_commands,
        artifact_parser=lambda _payload: [],
        anomaly_detector=state.feed,
        enable_enrichment=True,
        show_status=show_status,
    )
    analysis.anomalies.extend(state.findings())
    append_public_exposure_anomaly(analysis, "DLMS/COSEM")
    return analysis
