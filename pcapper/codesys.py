from __future__ import annotations

import re
from collections import OrderedDict
from pathlib import Path

from .industrial_helpers import (
    append_public_exposure_anomaly,
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
)
from .opcode_models import format_opcode, load_opcode_model
from .utils import memoize_analysis

try:
    from scapy.layers.inet import TCP  # type: ignore
except Exception:  # pragma: no cover
    TCP = None  # type: ignore

# Legacy CoDeSys runtime/gateway and V3 runtime/gateway/discovery ports.
CODESYS_TCP_PORTS = {2455, 1217, 11740, 11741, 11742, 11743}
CODESYS_UDP_PORTS = {1740, 1741, 1742, 1743}
CODESYS_MODEL_PATH = Path(__file__).with_name("codesys_opcodes.json")
CODESYS_TCP_MAGIC = b"\x00\x01\x17\xe8"
_MAX_TCP_STREAMS = 256
_MAX_TCP_FRAME_SIZE = 256 * 1024

CODESYS_KEYWORDS = {
    "login": "Login",
    "logout": "Logout",
    "download": "Download",
    "upload": "Upload",
    "start": "Start",
    "stop": "Stop",
    "reset": "Reset",
    "project": "Project",
    "application": "Application",
    "debug": "Debug",
    "codesys": "Banner",
}

CODESYS_DATAGRAM_SERVICES = {
    1: "AddressNotification Request",
    2: "AddressNotification Response",
    3: "NameService Server",
    4: "NameService Client",
    64: "Channel Manager",
}

CODESYS_NS_SUBCOMMANDS = {
    0xC201: "Resolve Address",
    0xC202: "Resolve Name",
    0xC280: "Device Info",
}

CODESYS_SERVICE_COMMANDS = {
    (1, 2): "Device Login",
    (1, 3): "Device Logout",
    (1, 4): "Device Reset",
    (1, 6): "Device Set Operating Mode",
    (1, 8): "Device Interactive Login",
    (1, 9): "Device Rename Node",
    (2, 1): "Application Login",
    (2, 2): "Application Logout",
    (2, 3): "Application Create",
    (2, 4): "Application Delete",
    (2, 5): "Application Download",
    (2, 6): "Application Online Change",
    (2, 7): "Application Device Download",
    (2, 16): "Application Start",
    (2, 17): "Application Stop",
    (2, 18): "Application Reset",
    (2, 52): "Application Encrypted Download",
    (8, 3): "File Open for Write",
    (8, 4): "File Write",
    (8, 14): "File Delete",
    (8, 15): "File Rename",
    (17, 1): "PLC Shell Execute",
}

CODESYS_OPCODE_PATTERN = re.compile(
    r"(?:opcode|op|cmd)\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)", re.IGNORECASE
)


class _CodesysTCPReassembler:
    def __init__(self) -> None:
        self._streams: OrderedDict[
            tuple[str, str, int, int], tuple[int, bytes]
        ] = OrderedDict()
        self.errors: list[str] = []

    def __call__(self, packet: object, match: object) -> bytes:
        payload = bytes(getattr(match, "payload", b"") or b"")
        if not payload or TCP is None:
            return payload
        tcp = packet.getlayer(TCP)  # type: ignore[attr-defined]
        if tcp is None:
            return payload
        src = str(getattr(match, "src", "?"))
        dst = str(getattr(match, "dst", "?"))
        sport = int(getattr(match, "sport", 0))
        dport = int(getattr(match, "dport", 0))
        key = (src, dst, sport, dport)
        previous = self._streams.pop(key, None)
        flags = int(getattr(tcp, "flags", 0))
        if flags & 0x02 and previous is not None:
            self._report_incomplete()
            previous = None

        if previous is None and not (
            payload.startswith(CODESYS_TCP_MAGIC)
            or CODESYS_TCP_MAGIC.startswith(payload)
        ):
            return payload

        sequence = int(getattr(tcp, "seq", 0))
        original_length = len(payload)
        if previous is not None:
            expected, buffered = previous
            delta = (sequence - expected + (1 << 31)) % (1 << 32) - (1 << 31)
            if delta < 0:
                overlap = -delta
                if overlap >= len(payload):
                    self._streams[key] = previous
                    return b""
                payload = payload[overlap:]
            elif delta > 0:
                self._report_gap()
                buffered = b""
            payload = buffered + payload

        frames, remainder = self._complete_frames(payload)
        if remainder and not flags & 0x05:
            if len(self._streams) >= _MAX_TCP_STREAMS:
                self._streams.popitem(last=False)
                self._report_limit()
            self._streams[key] = (
                (
                    sequence
                    + original_length
                    + int(bool(flags & 0x02))
                )
                & 0xFFFFFFFF,
                remainder,
            )
        elif remainder:
            self._report_incomplete()
        return b"".join(frames)

    def _complete_frames(self, data: bytes) -> tuple[list[bytes], bytes]:
        frames: list[bytes] = []
        while data:
            start = data.find(CODESYS_TCP_MAGIC)
            if start < 0:
                suffix_len = next(
                    (
                        size
                        for size in range(
                            min(len(data), len(CODESYS_TCP_MAGIC) - 1), 0, -1
                        )
                        if CODESYS_TCP_MAGIC.startswith(data[-size:])
                    ),
                    0,
                )
                if len(data) > suffix_len:
                    self._report_framing()
                return frames, data[-suffix_len:] if suffix_len else b""
            if start:
                self._report_framing()
                data = data[start:]
            if len(data) < 8:
                return frames, data
            frame_length = int.from_bytes(data[4:8], "little")
            if frame_length < 8 or frame_length > _MAX_TCP_FRAME_SIZE:
                self._report_framing()
                data = data[1:]
                continue
            if len(data) < frame_length:
                return frames, data
            frames.append(data[:frame_length])
            data = data[frame_length:]
        return frames, b""

    def _report_framing(self) -> None:
        message = "Malformed CoDeSys V3 TCP framing; invalid bytes or length discarded."
        if message not in self.errors:
            self.errors.append(message)

    def _report_gap(self) -> None:
        message = "CoDeSys V3 TCP sequence gap discarded an incomplete frame."
        if message not in self.errors:
            self.errors.append(message)

    def _report_incomplete(self) -> None:
        message = "CoDeSys V3 TCP stream ended with an incomplete frame."
        if message not in self.errors:
            self.errors.append(message)

    def _report_limit(self) -> None:
        message = "CoDeSys V3 TCP stream limit reached; oldest partial stream discarded."
        if message not in self.errors:
            self.errors.append(message)

    def finish(self) -> None:
        if self._streams:
            self._report_incomplete()
            self._streams.clear()


def _load_model() -> object | None:
    return load_opcode_model(CODESYS_MODEL_PATH)


def _parse_v3_datagram(payload: bytes) -> dict[str, object] | None:
    if not payload or payload[0] != 0xC5:
        return None
    issues: list[str] = []
    result: dict[str, object] = {"issues": issues}
    if len(payload) < 6:
        issues.append("Truncated CoDeSys V3 datagram header.")
        return result

    header_len = (payload[1] & 0x07) * 2
    address_lengths = payload[5]
    sender_len = (address_lengths >> 4) * 2
    receiver_len = (address_lengths & 0x0F) * 2
    address_end = header_len + sender_len + receiver_len
    aligned_end = (address_end + 3) & ~3
    if header_len < 6 or aligned_end > len(payload):
        issues.append("CoDeSys V3 datagram address lengths exceed payload.")
        return result

    service_id = payload[3]
    result["service_id"] = service_id
    result["service_name"] = CODESYS_DATAGRAM_SERVICES.get(
        service_id, f"Datagram Service 0x{service_id:02x}"
    )
    result["data_offset"] = aligned_end
    if service_id in {3, 4}:
        if aligned_end + 8 > len(payload):
            issues.append("Truncated CoDeSys V3 name-service header.")
            return result
        subcommand = int.from_bytes(payload[aligned_end : aligned_end + 2], "little")
        result["subcommand"] = subcommand
        result["subcommand_name"] = CODESYS_NS_SUBCOMMANDS.get(
            subcommand, f"Name Service 0x{subcommand:04x}"
        )
        result["message_id"] = int.from_bytes(
            payload[aligned_end + 4 : aligned_end + 8], "little"
        )
    return result


def _iter_v3_tcp_datagrams(payload: bytes) -> list[bytes]:
    datagrams: list[bytes] = []
    offset = 0
    while offset + 8 <= len(payload) and payload[offset : offset + 4] == CODESYS_TCP_MAGIC:
        frame_length = int.from_bytes(payload[offset + 4 : offset + 8], "little")
        if frame_length < 8 or offset + frame_length > len(payload):
            break
        datagrams.append(payload[offset + 8 : offset + frame_length])
        offset += frame_length
    return datagrams


def _parse_v3_tcp_service(payload: bytes) -> dict[str, object] | None:
    datagram = _parse_v3_datagram(payload)
    if datagram is None or datagram.get("service_id") != 64:
        return None
    data_offset = datagram.get("data_offset")
    if not isinstance(data_offset, int) or data_offset + 20 > len(payload):
        return None
    if payload[data_offset] != 0x01 or not payload[data_offset + 1] & 0x01:
        return None

    channel_offset = data_offset
    service_offset = channel_offset + 20
    remaining_size = int.from_bytes(
        payload[channel_offset + 12 : channel_offset + 16], "little"
    )
    if remaining_size > len(payload) - service_offset:
        return None
    service = payload[service_offset:]
    if len(service) < 20:
        return None
    header_size = int.from_bytes(service[2:4], "little")
    if header_size not in {12, 16}:
        return None
    command_flags = int.from_bytes(service[4:6], "little")
    group = command_flags & 0x7F
    subcommand = int.from_bytes(service[6:8], "little")
    content_size = int.from_bytes(service[12:16], "little")
    content_offset = header_size + 4
    if content_offset + content_size > len(service):
        return None
    command = CODESYS_SERVICE_COMMANDS.get(
        (group, subcommand), f"Service 0x{group:02x}/0x{subcommand:04x}"
    )
    return {
        "group": group,
        "subcommand": subcommand,
        "response": bool(command_flags & 0x80),
        "command": command,
        "content_size": content_size,
    }


def _parse_v3_commands(payload: bytes) -> list[str]:
    datagram = _parse_v3_datagram(payload)
    if datagram is None:
        return []
    commands = [f"CODESYS {datagram.get('service_name', 'Datagram')}"]
    if datagram.get("subcommand_name"):
        commands.append(f"CODESYS {datagram['subcommand_name']}")
    service = _parse_v3_tcp_service(payload)
    if service and not service["response"]:
        commands.append(f"CODESYS {service['command']}")
    if datagram.get("issues"):
        commands.append("CODESYS Malformed Datagram")
    return commands


def _parse_commands(payload: bytes) -> list[str]:
    if not payload:
        return []
    tcp_datagrams = _iter_v3_tcp_datagrams(payload)
    if tcp_datagrams:
        return [
            command
            for datagram in tcp_datagrams
            for command in _parse_v3_commands(datagram)
        ]
    datagram = _parse_v3_datagram(payload)
    if datagram is not None:
        return _parse_v3_commands(payload)
    text = payload[:400].decode("utf-8", errors="ignore").lower()
    commands: list[str] = []
    for key, label in CODESYS_KEYWORDS.items():
        if key in text:
            commands.append(f"CODESYS {label}")
    model = _load_model()
    for match in CODESYS_OPCODE_PATTERN.findall(text):
        commands.append(f"CODESYS Opcode {match}")
        if model is not None:
            try:
                opcode = (
                    int(match, 16)
                    if str(match).lower().startswith("0x")
                    else int(match)
                )
                label = getattr(model, "opcodes", {}).get(opcode)
                if label:
                    commands.append(f"CODESYS {label}")
            except Exception:
                pass
    if model is not None:
        for opcode, label, _offset in model.extract_opcodes(payload):
            commands.append(f"CODESYS Opcode {format_opcode(opcode, label)}")
    return commands


def _parse_artifacts(payload: bytes) -> list[tuple[str, str]]:
    artifacts: list[tuple[str, str]] = []
    if not payload:
        return artifacts
    tcp_datagrams = _iter_v3_tcp_datagrams(payload)
    if tcp_datagrams:
        for datagram_payload in tcp_datagrams:
            artifacts.extend(_parse_artifacts(datagram_payload))
            service = _parse_v3_tcp_service(datagram_payload)
            if service:
                artifacts.append(
                    ("codesys_service", f"{service['group']}:{service['subcommand']}")
                )
                artifacts.append(("codesys_service_command", str(service["command"])))
        return artifacts
    datagram = _parse_v3_datagram(payload)
    if datagram is not None:
        if datagram.get("service_name"):
            artifacts.append(("codesys_datagram_service", str(datagram["service_name"])))
        if datagram.get("subcommand_name"):
            artifacts.append(("codesys_name_service", str(datagram["subcommand_name"])))
        if isinstance(datagram.get("message_id"), int):
            artifacts.append(
                ("codesys_message_id", f"0x{int(datagram['message_id']):08x}")
            )
        issues = datagram.get("issues")
        if isinstance(issues, list):
            for issue in issues:
                artifacts.append(("codesys_parser_issue", str(issue)))
        return artifacts
    text = payload[:400].decode("utf-8", errors="ignore")
    for match in CODESYS_OPCODE_PATTERN.findall(text):
        artifacts.append(("codesys_opcode", match))
    model = _load_model()
    if model is not None:
        for opcode, label, _offset in model.extract_opcodes(payload):
            artifacts.append(("codesys_opcode", format_opcode(opcode, label)))
    return artifacts


def _detect_anomalies(
    payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]
) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    datagram = _parse_v3_datagram(payload)
    if datagram is not None and datagram.get("issues"):
        anomalies.append(
            IndustrialAnomaly(
                severity="LOW",
                title="Malformed CODESYS Datagram",
                description=str(datagram["issues"][0]),
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(
        cmd
        in {
            "CODESYS Download",
            "CODESYS Upload",
            "CODESYS Application Download",
            "CODESYS Application Online Change",
            "CODESYS Application Device Download",
            "CODESYS Application Encrypted Download",
            "CODESYS File Open for Write",
            "CODESYS File Write",
        }
        for cmd in commands
    ):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="CODESYS Program Transfer",
                description="Download/upload activity observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(
        cmd in {"CODESYS Stop", "CODESYS Reset"}
        or cmd.endswith(("Application Stop", "Application Reset", "Device Reset"))
        for cmd in commands
    ):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="CODESYS Control Operation",
                description="Stop/reset command observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    return anomalies


@memoize_analysis
def analyze_codesys(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    reassembler = _CodesysTCPReassembler()
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="CODESYS",
        tcp_ports=CODESYS_TCP_PORTS,
        udp_ports=CODESYS_UDP_PORTS,
        command_parser=_parse_commands,
        artifact_parser=_parse_artifacts,
        anomaly_detector=_detect_anomalies,
        enable_enrichment=True,
        show_status=show_status,
        payload_reassembler=reassembler,
    )
    reassembler.finish()
    analysis.errors.extend(reassembler.errors)
    append_public_exposure_anomaly(analysis, "CODESYS")
    return analysis
