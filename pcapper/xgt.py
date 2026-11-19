"""LS ELECTRIC (LSIS) XGT FEnet: the dedicated Ethernet protocol of XGT/XGK PLCs.

TCP 2004 / UDP 2005. Every frame starts with a 20-byte application header:

    company ID (10, "LSIS-XGT" or "LGIS-GLOFA") | PLC info (2) | CPU info (1)
    | source (1: 0x33 client->PLC, 0x11 PLC->client) | invoke ID (2)
    | length (2, LE, bytes after the header) | FEnet position (1) | BCC (1)

followed by the instruction: command (2, LE: 0x54/0x55 read, 0x58/0x59
write, 0xB0/0xB1 status), data type (2), reserved (2), then for requests a
block count and per block a variable name (``%MB200``, ``%DW10`` ...) and,
for writes, the data; responses carry an error status, then the data.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .industrial_helpers import (
    IndustrialAnalysis,
    IndustrialAnomaly,
    IndustrialArtifact,
    analyze_port_protocol,
    append_public_exposure_anomaly,
)
from .utils import memoize_analysis

XGT_TCP_PORT = 2004
XGT_UDP_PORT = 2005

COMMANDS = {
    0x54: "Read request", 0x55: "Read response",
    0x58: "Write request", 0x59: "Write response",
    0xB0: "Status request", 0xB1: "Status response",
}
DATA_TYPES = {0x00: "bit", 0x01: "byte", 0x02: "word", 0x03: "dword", 0x04: "lword", 0x14: "block"}


@dataclass(frozen=True)
class XgtFrame:
    from_plc: bool
    invoke_id: int
    command: int
    data_type: int
    variables: tuple[str, ...]
    values: tuple[bytes, ...]
    error: int | None

    @property
    def name(self) -> str:
        return COMMANDS.get(self.command, f"Command 0x{self.command:04x}")


def parse_xgt(payload: bytes) -> XgtFrame | None:
    if len(payload) < 26:
        return None
    if not (payload[:8] == b"LSIS-XGT" or payload[:10] == b"LGIS-GLOFA"):
        return None
    length = int.from_bytes(payload[16:18], "little")
    if 20 + length != len(payload):
        return None
    body = payload[20:]
    from_plc = payload[13] == 0x11
    command = int.from_bytes(body[0:2], "little")
    data_type = int.from_bytes(body[2:4], "little")
    invoke = int.from_bytes(payload[14:16], "little")
    variables: list[str] = []
    values: list[bytes] = []
    error: int | None = None
    try:
        if command in (0x54, 0x58):
            blocks = int.from_bytes(body[6:8], "little")
            pos = 8
            for _ in range(min(blocks, 64)):
                size = int.from_bytes(body[pos:pos + 2], "little")
                variables.append(body[pos + 2:pos + 2 + size].decode("ascii", errors="replace"))
                pos += 2 + size
            if command == 0x58:
                for _ in range(len(variables)):
                    size = int.from_bytes(body[pos:pos + 2], "little")
                    values.append(bytes(body[pos + 2:pos + 2 + size]))
                    pos += 2 + size
        elif command in (0x55, 0x59, 0xB1):
            error = int.from_bytes(body[6:8], "little")
            if command == 0x55 and error == 0:
                blocks = int.from_bytes(body[8:10], "little")
                pos = 10
                for _ in range(min(blocks, 64)):
                    size = int.from_bytes(body[pos:pos + 2], "little")
                    values.append(bytes(body[pos + 2:pos + 2 + size]))
                    pos += 2 + size
    except (IndexError, ValueError):
        pass
    return XgtFrame(from_plc, invoke, command, data_type, tuple(variables), tuple(values), error)


def _signature(payload: bytes) -> bool:
    return parse_xgt(payload) is not None


def _commands(payload: bytes) -> list[str]:
    frame = parse_xgt(payload)
    if frame is None:
        return []
    names = [frame.name]
    if frame.error:
        names.append(f"Error response (status 0x{frame.error:04x})")
    return names


def _artifacts(payload: bytes) -> list[tuple[str, str]]:
    frame = parse_xgt(payload)
    if frame is None:
        return []
    if frame.command == 0x58:
        return [
            ("xgt_write", f"{name} = {value.hex()}")
            for name, value in zip(frame.variables, frame.values)
        ]
    return [("xgt_variable", name) for name in frame.variables]


class _XgtState:
    def __init__(self) -> None:
        self.writes: list[tuple[float, str, str, str, bytes]] = []
        self.writers: Counter[str] = Counter()
        self.reads: Counter[str] = Counter()
        self.errors: Counter[str] = Counter()
        self.variables_written: Counter[str] = Counter()

    def feed(self, payload: bytes, src: str, dst: str, ts: float, _commands: object) -> list[IndustrialAnomaly]:
        frame = parse_xgt(payload)
        if frame is None:
            return []
        if frame.command == 0x58:
            self.writers[src] += 1
            for name, value in zip(frame.variables, frame.values):
                self.variables_written[name] += 1
                if len(self.writes) < 5000:
                    self.writes.append((ts, src, dst, name, value))
        elif frame.command == 0x54:
            for name in frame.variables:
                self.reads[name] += 1
        if frame.error:
            self.errors[f"{frame.name} 0x{frame.error:04x}"] += 1
        return []

    def written_text(self) -> str:
        """Written bytes in order, when they read as text (CTF flags hide here)."""
        data = b"".join(value for *_rest, value in self.writes)
        chars = [chr(b) for b in data if b]
        text = "".join(chars)
        return text if len(text) >= 4 and all(32 <= ord(c) < 127 for c in text) else ""

    def findings(self) -> list[IndustrialAnomaly]:
        found: list[IndustrialAnomaly] = []
        if self.writes:
            evidence = [
                f"{src} -> {dst} {name} = {value.hex()}" for _ts, src, dst, name, value in self.writes[:10]
            ]
            text = self.written_text()
            if text:
                if "{" in text or "}" in text:
                    evidence.insert(0, f"written bytes reversed: {text[::-1]!r}")
                evidence.insert(0, f"written bytes as text: {text!r}")
            found.append(IndustrialAnomaly(
                "HIGH", "XGT memory writes",
                f"{len(self.writes)} variable write(s) from {len(self.writers)} client(s) to "
                + ", ".join(f"{n} x{c}" for n, c in self.variables_written.most_common(5))
                + "; confirm the writer is the engineering/HMI host.",
                self.writes[0][1], self.writes[0][2], self.writes[0][0],
                attack="T0836 Modify Parameter; T0855 Unauthorized Command Message",
                evidence=evidence,
            ))
        if len(self.reads) >= 50:
            found.append(IndustrialAnomaly(
                "MEDIUM", "XGT memory sweep",
                f"{len(self.reads)} distinct variables read (enumeration of PLC memory).",
                "*", "*", 0.0, attack="T0861 Point & Tag Identification",
                evidence=sorted(self.reads)[:8],
            ))
        if self.errors:
            found.append(IndustrialAnomaly(
                "LOW", "XGT error responses",
                ", ".join(f"{n} x{c}" for n, c in self.errors.most_common(5)),
                "*", "*", 0.0,
            ))
        return found


@memoize_analysis
def analyze_xgt(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    state = _XgtState()
    analysis = analyze_port_protocol(
        port_key="xgt",
        path=path,
        protocol_name="LS XGT FEnet",
        tcp_ports={XGT_TCP_PORT},
        udp_ports={XGT_UDP_PORT},
        signature_matcher=_signature,
        command_parser=_commands,
        artifact_parser=_artifacts,
        anomaly_detector=state.feed,
        enable_enrichment=True,
        show_status=show_status,
    )
    analysis.anomalies.extend(state.findings())
    text = state.written_text()
    if text:
        analysis.artifacts.append(IndustrialArtifact("xgt_written_text", text, "*", "*", 0.0))
    append_public_exposure_anomaly(analysis, "XGT FEnet")
    return analysis
