"""Emerson ROC Plus (ROC800/FloBoss flow computers and RTUs, TCP and UDP 4000).

Frame (CISA ICSNPP roc-plus grammar): destination unit (1) | destination group
(1) | source unit (1) | source group (1) | opcode (1) | data length (1) | data
| CRC-16 (2). The CRC is CRC-16/MODBUS (poly 0xA001 reflected, init 0xFFFF),
little-endian: verified on every frame of the ICSNPP test traces, which makes
it the structural test that recognises ROC Plus on any port.

There is no direction flag; requests and responses are told apart by opcode
and data length, as the ICSNPP parser does. Opcode 17 (login) carries the
operator ID and password in clear.
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

PROTOCOL_NAME = "ROC Plus"
ROC_PORT = 4000

OPCODES = {
    6: "System Config", 7: "Read Realtime Clock", 8: "Set Realtime Clock",
    10: "Read Configurable Opcode Point Data", 11: "Write Configurable Opcode Point Data",
    17: "Login Request", 24: "Store And Forward", 50: "Request IO Point Position",
    100: "Access User Defined Information", 105: "Request Today's/Yesterday's Min/Max Values",
    108: "Request History Tag And Periodic Index", 118: "Request Alarm Data",
    119: "Request Event Data", 135: "Request Single History Point Data",
    136: "Request Multiple History Point Data", 137: "Request History Index",
    138: "Request Daily And Periodic History", 139: "History Information Data",
    166: "Set Single Point Parameters", 167: "Request Single Point Parameters",
    180: "Request Parameters", 181: "Write Parameters", 203: "General File Transfer",
    205: "Peer To Peer Network Messages", 206: "Read Transaction History Data",
    224: "SRBX Signal", 225: "Acknowledge SRBX", 255: "Error Indicator",
}
ERROR_CODES = {
    1: "Invalid Opcode Request", 2: "Invalid Parameter Number", 3: "Invalid Logical Number",
    4: "Invalid Point Type", 5: "Received Too Many Data Bytes", 6: "Received Too Few Data Bytes",
    13: "Outside Valid Address Range", 14: "Invalid History Request", 15: "Invalid FST Request",
    19: "Write to Read-Only Parameter", 20: "Security Error", 21: "Invalid Security Logon",
    25: "Invalid Parameter Range", 33: "Invalid Time", 50: "General Error",
    51: "Invalid State for Write", 63: "Request Access Level Too High", 77: "Invalid Logoff String",
}
WRITES = {8, 11, 166, 181}
# (opcode -> data length that marks a request); the rest decided below.
_REQUEST_LENGTH = {6: 0, 7: 0, 10: 3, 50: 1, 100: 3, 105: 2, 118: 3, 119: 3, 135: 6, 136: 7, 137: 3, 138: 4, 167: 4, 225: 2}


def _crc_table() -> tuple[int, ...]:
    table = []
    for value in range(256):
        crc = value
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
        table.append(crc)
    return tuple(table)


_CRC_TABLE = _crc_table()


def crc16_modbus(data: bytes) -> int:
    """CRC-16/MODBUS, table-driven: it runs on every TCP/UDP payload as the
    ROC Plus signature check, where the bitwise loop cost ~39 us a payload."""
    crc = 0xFFFF
    table = _CRC_TABLE
    for byte in data:
        crc = (crc >> 8) ^ table[(crc ^ byte) & 0xFF]
    return crc


@dataclass(frozen=True)
class RocFrame:
    dst: str
    src: str
    opcode: int
    data: bytes
    is_request: bool | None

    @property
    def name(self) -> str:
        return OPCODES.get(self.opcode, f"Opcode {self.opcode}")


def _direction(opcode: int, length: int) -> bool | None:
    if opcode in _REQUEST_LENGTH:
        return length == _REQUEST_LENGTH[opcode]
    if opcode in (8, 11, 166, 224):
        return length > 0
    if opcode == 17:
        return length not in (0, 24)
    if opcode == 24:
        return length > 0
    if opcode == 255:
        return False
    return None


def parse_roc_frames(payload: bytes) -> list[RocFrame]:
    """Every CRC-valid ROC Plus frame in ``payload`` (TCP may carry several)."""
    frames: list[RocFrame] = []
    pos = 0
    while pos + 8 <= len(payload):
        length = payload[pos + 5]
        end = pos + 6 + length + 2
        if end > len(payload):
            return frames if pos else []
        body = payload[pos:end - 2]
        if crc16_modbus(body) != int.from_bytes(payload[end - 2:end], "little"):
            return frames if pos else []
        frames.append(
            RocFrame(
                dst=f"{payload[pos]}/{payload[pos + 1]}",
                src=f"{payload[pos + 2]}/{payload[pos + 3]}",
                opcode=payload[pos + 4],
                data=bytes(payload[pos + 6:pos + 6 + length]),
                is_request=_direction(payload[pos + 4], length),
            )
        )
        pos = end
    return frames if pos == len(payload) else []


def _signature(payload: bytes) -> bool:
    return bool(parse_roc_frames(payload))


def _commands(payload: bytes) -> list[str]:
    names = []
    for frame in parse_roc_frames(payload):
        suffix = "" if frame.is_request is None else (" (request)" if frame.is_request else " (response)")
        names.append(frame.name + suffix)
        if frame.opcode == 255 and frame.data:
            names.append(f"Error: {ERROR_CODES.get(frame.data[-1], frame.data[-1])}")
    return names


def _login(frame: RocFrame) -> tuple[str, str] | None:
    data = frame.data
    if frame.opcode != 17 or not frame.is_request:
        return None
    if len(data) in (6, 11):  # standard login / logout: operator ID (3), password (2)
        operator = data[:3].decode("ascii", errors="replace").strip("\x00 ")
        return operator, str(int.from_bytes(data[3:5], "little"))
    if len(data) in (71, 76):  # enhanced: operator ID (30), password (40)
        operator = data[:30].split(b"\x00", 1)[0].decode("ascii", errors="replace").strip()
        password = data[30:70].split(b"\x00", 1)[0].decode("ascii", errors="replace").strip()
        return operator, password
    return None


def _login_credential(frame: RocFrame) -> tuple[str, str | None, str | None, str] | None:
    """(kind, operator, password, detail) of an opcode 17 login request."""
    login = _login(frame)
    if login is None:
        return None
    return "ROC Plus Login Credential", login[0], login[1], f"operator {login[0]!r} password {login[1]!r}"


def _has_login_opcode(payload: bytes) -> bool:
    """Whether a walk of the frame lengths in ``payload`` (no CRC) meets
    opcode 17. parse_roc_frames returns a prefix of these same frames, so
    without one there is no login and no CRC to compute."""
    pos = 0
    while pos + 8 <= len(payload):
        if payload[pos + 4] == 17:
            return True
        pos += payload[pos + 5] + 8
    return False


def credentials(payload: bytes) -> list[tuple[str, str | None, str | None, str]]:
    """The logins this analysis reports, for --creds. The parse (CRC-valid
    frames) is the protocol's signature, so it matches on any port the
    analysis would. --creds calls this for every payload, so a payload
    without a login frame is turned away before the CRC."""
    if not _has_login_opcode(payload):
        return []
    return [credential for frame in parse_roc_frames(payload) if (credential := _login_credential(frame))]


class _RocState:
    def __init__(self) -> None:
        self.writes: Counter[str] = Counter()
        self.writers: Counter[str] = Counter()
        self.logins: list[str] = []
        self.errors: Counter[str] = Counter()
        self.file_transfers = 0
        self.first: dict[str, tuple[str, str, float]] = {}

    def feed(self, payload: bytes, src: str, dst: str, ts: float, _commands: object) -> list[IndustrialAnomaly]:
        for frame in parse_roc_frames(payload):
            if frame.opcode in WRITES and frame.is_request:
                self.writes[frame.name] += 1
                self.writers[src] += 1
                self.first.setdefault("write", (src, dst, ts))
            if frame.opcode == 203:
                self.file_transfers += 1
                self.first.setdefault("file", (src, dst, ts))
            login = _login_credential(frame)
            if login and len(self.logins) < 20:
                self.logins.append(f"{src} -> {dst}: {login[3]}")
            if frame.opcode == 255 and frame.data:
                code = frame.data[-1]
                self.errors[ERROR_CODES.get(code, f"error {code}")] += 1
        return []

    def findings(self) -> list[IndustrialAnomaly]:
        found: list[IndustrialAnomaly] = []
        if self.logins:
            found.append(IndustrialAnomaly(
                "HIGH", "ROC Plus cleartext login credentials",
                f"{len(self.logins)} opcode 17 login(s) with operator ID and password in clear.",
                "*", "*", 0.0, attack="T0859 Valid Accounts",
                evidence=self.logins[:8],
            ))
        if self.writes:
            src, dst, ts = self.first["write"]
            found.append(IndustrialAnomaly(
                "HIGH", "ROC Plus parameter/configuration writes",
                ", ".join(f"{n} x{c}" for n, c in self.writes.most_common()) + ".",
                src, dst, ts, attack="T0836 Modify Parameter",
                evidence=[f"writer {ip}: {n}" for ip, n in self.writers.most_common(5)],
            ))
        if self.file_transfers:
            src, dst, ts = self.first["file"]
            found.append(IndustrialAnomaly(
                "MEDIUM", "ROC Plus file transfer",
                f"{self.file_transfers} General File Transfer (203) frame(s): user programs, "
                "configuration or history moved to/from the device.",
                src, dst, ts, attack="T0845 Program Upload; T0843 Program Download",
            ))
        if self.errors.get("Invalid Security Logon") or self.errors.get("Security Error"):
            found.append(IndustrialAnomaly(
                "MEDIUM", "ROC Plus failed logins",
                ", ".join(f"{n} x{c}" for n, c in self.errors.most_common(4)),
                "*", "*", 0.0, attack="T0859 Valid Accounts",
            ))
        return found


@memoize_analysis
def analyze_rocplus(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    state = _RocState()
    analysis = analyze_port_protocol(
        port_key="rocplus",
        path=path,
        protocol_name=PROTOCOL_NAME,
        tcp_ports={ROC_PORT},
        udp_ports={ROC_PORT},
        signature_matcher=_signature,
        command_parser=_commands,
        artifact_parser=lambda _payload: [],
        anomaly_detector=state.feed,
        enable_enrichment=True,
        show_status=show_status,
    )
    analysis.anomalies.extend(state.findings())
    append_public_exposure_anomaly(analysis, "ROC Plus")
    return analysis
