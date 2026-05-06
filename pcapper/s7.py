from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .equipment import equipment_artifacts
from .industrial_helpers import (
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
    default_artifacts,
)

S7_PORT = 102

ROSCTR = {
    1: "Job",
    2: "Ack",
    3: "AckData",
    7: "UserData",
}

S7_FUNCTIONS = {
    0x00: "CpuServices",
    0x04: "ReadVar",
    0x05: "WriteVar",
    0x1A: "RequestDownload",
    0x1B: "DownloadBlock",
    0x1C: "DownloadEnded",
    0x1D: "StartUpload",
    0x1E: "UploadBlock",
    0x1F: "EndUpload",
    0x28: "PIService",
    0x29: "PLCStop",
    0x2B: "PLCHotStart",
    0x2C: "PLCColdStart",
    0x2F: "BlockList",
    0x31: "GetBlockInfo",
    0x32: "GetDiagData",
    0xF0: "SetupCommunication",
}

S7_USERDATA_GROUPS = {
    0x01: "Cpu",
    0x02: "Block",
    0x03: "Alarm",
    0x04: "UserData",
    0x05: "Security",
    0x07: "Time",
    0x0B: "Program",
    0x0C: "CyclicData",
}

S7_USERDATA_FUNCTIONS = {
    (0x01, 0x01): "CpuRead",
    (0x01, 0x02): "CpuWrite",
    (0x01, 0x03): "CpuService03",
    (0x01, 0x04): "CpuService04",
    (0x01, 0x05): "CpuPassword",
    (0x01, 0x07): "CpuStatus",
    (0x02, 0x01): "BlockList",
    (0x02, 0x02): "BlockInfo",
    (0x03, 0x01): "AlarmQuery",
    (0x07, 0x01): "ReadClock",
    (0x07, 0x02): "SetClock",
    (0x05, 0x01): "SecurityInfo",
    (0x0B, 0x01): "ProgramInfo",
}

AREA_NAMES = {
    0x81: "I",
    0x82: "Q",
    0x83: "M",
    0x84: "DB",
    0x85: "DI",
    0x86: "L",
    0x87: "V",
}

TRANSPORT_NAMES = {
    0x03: "BIT",
    0x04: "BYTE",
    0x05: "WORD",
    0x06: "DWORD",
    0x07: "INT",
    0x08: "DINT",
    0x09: "REAL",
}

COTP_PDU_TYPES = {
    0xE0: "CR",
    0xD0: "CC",
    0xF0: "DT",
    0x80: "DR",
    0xC0: "DC",
}

COTP_DR_REASONS = {
    0x00: "Normal",
    0x80: "Normal",
    0x81: "Remote transport entity congestion",
    0x82: "Connection negotiation failed",
    0x83: "Transport connection not attached",
    0x84: "Address unknown",
    0x85: "Protocol error",
}

TSAP_ROLE_HINTS = {
    0x01: "PG",
    0x02: "OP",
    0x03: "S7-Basic",
    0x10: "HMI",
}

_WRITE_FUNCTIONS = {
    "WriteVar",
    "UserData:Cpu:CpuWrite",
    "UserData:Cpu:CpuService02",
    "UserData:Cpu:VarTabWrite",
}

_PROGRAM_FUNCTIONS = {
    "RequestDownload",
    "DownloadBlock",
    "DownloadEnded",
    "StartUpload",
    "UploadBlock",
    "EndUpload",
    "UserData:Program:ProgramInfo",
}

_CPU_STATE_FUNCTIONS = {
    "PLCStop",
    "PLCHotStart",
    "PLCColdStart",
}

_ENUM_FUNCTIONS = {
    "ReadVar",
    "BlockList",
    "GetBlockInfo",
    "GetDiagData",
    "UserData:Cpu:CpuRead",
    "UserData:Cpu:CpuService03",
    "UserData:Cpu:CpuService04",
    "UserData:Cpu:CpuStatus",
    "UserData:Cpu:VarTabRead",
    "UserData:Cpu:VarTabAccess",
    "UserData:Alarm:AlarmQuery",
}

_ERROR_CLASS_TEXT = {
    0x00: "No Error",
    0x81: "Application Relationship",
    0x82: "Object Definition",
    0x83: "No Resources",
    0x84: "Service Processing",
    0x85: "Supplies",
    0x87: "Access",
}


@dataclass
class _S7PacketEvent:
    commands: list[str] = field(default_factory=list)
    cotp_type: str | None = None
    cotp_reason: str | None = None
    cotp_src_ref: int | None = None
    cotp_dst_ref: int | None = None
    cotp_tpdu_size: int | None = None
    rosctr: int | None = None
    pdu_ref: int | None = None
    func_name: str | None = None
    error_class: int = 0
    error_code: int = 0
    src_tsap: str | None = None
    dst_tsap: str | None = None
    targets: list[str] = field(default_factory=list)


@dataclass
class _PendingTransaction:
    func_name: str
    src: str
    dst: str
    ts: float
    targets: tuple[str, ...]


@dataclass(frozen=True)
class _CotpFrame:
    pdu_name: str
    payload: bytes
    src_tsap: str | None = None
    dst_tsap: str | None = None
    src_ref: int | None = None
    dst_ref: int | None = None
    tpdu_size: int | None = None
    reason: str | None = None


@dataclass
class _S7State:
    pending: dict[tuple[str, str, int], _PendingTransaction] = field(
        default_factory=dict
    )
    tpkt_frames: int = 0
    cotp_frames: int = 0
    valid_s7_frames: int = 0
    invalid_tpkt_frames: int = 0
    cotp_tsap_profiles: int = 0
    semantic_commands: int = 0

    def parse_commands(self, payload: bytes) -> list[str]:
        events = self._extract_events(payload, update_counters=True)
        commands: list[str] = []
        for event in events:
            commands.extend(event.commands)
        return _dedupe(commands)

    def parse_artifacts(self, payload: bytes) -> list[tuple[str, str]]:
        artifacts = default_artifacts(payload)
        artifacts.extend(equipment_artifacts(payload))
        seen: set[tuple[str, str]] = {(kind, detail) for kind, detail in artifacts}

        for event in self._extract_events(payload, update_counters=False):
            if event.src_tsap or event.dst_tsap:
                detail = (
                    "COTP Session Profile "
                    f"pdu={event.cotp_type or '?'} "
                    f"src_tsap={event.src_tsap or '?'} "
                    f"dst_tsap={event.dst_tsap or '?'}"
                )
                if event.cotp_tpdu_size:
                    detail += f" tpdu={event.cotp_tpdu_size}"
                marker = ("device", detail)
                if marker not in seen:
                    seen.add(marker)
                    artifacts.append(marker)
        return artifacts

    def detect_anomalies(
        self, payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]
    ) -> list[IndustrialAnomaly]:
        anomalies: list[IndustrialAnomaly] = []
        seen: set[tuple[str, str, str]] = set()

        def add(severity: str, title: str, description: str) -> None:
            key = (severity, title, description)
            if key in seen:
                return
            seen.add(key)
            anomalies.append(
                IndustrialAnomaly(
                    severity=severity,
                    title=title,
                    description=description,
                    src=src_ip,
                    dst=dst_ip,
                    ts=ts,
                )
            )

        self._prune_pending(ts)
        events = self._extract_events(payload, update_counters=False)
        saw_structured = any(event.rosctr is not None for event in events)

        for event in events:
            func_name_raw = event.func_name or ""
            func_name = _canonical_command_name(func_name_raw)
            target_text = ""
            if event.targets:
                preview = ", ".join(event.targets[:3])
                if len(event.targets) > 3:
                    preview = f"{preview} (+{len(event.targets) - 3} more)"
                target_text = f" Targets: {preview}."

            if event.rosctr == 0x01 and event.pdu_ref is not None and func_name:
                self.pending[(src_ip, dst_ip, event.pdu_ref)] = _PendingTransaction(
                    func_name=func_name,
                    src=src_ip,
                    dst=dst_ip,
                    ts=ts,
                    targets=tuple(event.targets),
                )
                if func_name in _CPU_STATE_FUNCTIONS:
                    add(
                        "HIGH",
                        "S7 CPU State Change Requested",
                        f"{func_name} job issued to PLC.{target_text}",
                    )
                elif func_name in _PROGRAM_FUNCTIONS:
                    add(
                        "HIGH",
                        "S7 Program Transfer Requested",
                        f"{func_name} job observed.{target_text}",
                    )
                elif func_name in _WRITE_FUNCTIONS:
                    add(
                        "MEDIUM",
                        "S7 Write Operation Requested",
                        f"{func_name} job observed.{target_text}",
                    )
                elif func_name in _ENUM_FUNCTIONS:
                    add(
                        "LOW",
                        "S7 Enumeration/Diagnostics",
                        f"{func_name} request observed.{target_text}",
                    )

            if event.rosctr in {0x02, 0x03} and event.pdu_ref is not None:
                pending = self.pending.pop((dst_ip, src_ip, event.pdu_ref), None)
                if pending is not None:
                    status_ok = (event.error_class == 0 and event.error_code == 0)
                    err_text = ""
                    if not status_ok:
                        err_text = (
                            " Response error: "
                            f"{_format_s7_error(event.error_class, event.error_code)}."
                        )
                    if pending.func_name in _CPU_STATE_FUNCTIONS:
                        add(
                            "CRITICAL" if status_ok else "HIGH",
                            "S7 CPU State Change Confirmed"
                            if status_ok
                            else "S7 CPU State Change Failed",
                            f"{pending.func_name} transaction {'succeeded' if status_ok else 'failed'}."
                            f"{err_text}",
                        )
                    elif pending.func_name in _PROGRAM_FUNCTIONS:
                        add(
                            "HIGH" if status_ok else "MEDIUM",
                            "S7 Program Transfer Confirmed"
                            if status_ok
                            else "S7 Program Transfer Failed",
                            f"{pending.func_name} transaction {'succeeded' if status_ok else 'failed'}."
                            f"{err_text}",
                        )
                    elif pending.func_name in _WRITE_FUNCTIONS:
                        add(
                            "HIGH" if status_ok else "MEDIUM",
                            "S7 Write Operation Confirmed"
                            if status_ok
                            else "S7 Write Operation Failed",
                            f"{pending.func_name} transaction {'succeeded' if status_ok else 'failed'}."
                            f"{err_text}",
                        )
                    elif not status_ok:
                        add(
                            "LOW",
                            "S7 Operation Error Response",
                            f"{pending.func_name} received error response: {_format_s7_error(event.error_class, event.error_code)}.",
                        )
                elif event.error_class or event.error_code:
                    add(
                        "LOW",
                        "S7 Error Response",
                        f"S7 ack/data includes error {_format_s7_error(event.error_class, event.error_code)}.",
                    )

            if func_name.startswith("UserData:Security") or "CpuPassword" in func_name:
                add(
                    "MEDIUM",
                    "S7 Security Query",
                    "UserData security function observed.",
                )

            if func_name == "SetClock" or func_name.endswith(":SetClock"):
                add(
                    "MEDIUM",
                    "S7 Clock Modification",
                    "S7 clock set operation observed.",
                )

            if event.rosctr == 0x07 and func_name:
                if func_name in _PROGRAM_FUNCTIONS:
                    add(
                        "HIGH",
                        "S7 Program Transfer Requested",
                        f"{func_name} UserData operation observed.{target_text}",
                    )
                elif func_name in _WRITE_FUNCTIONS:
                    add(
                        "MEDIUM",
                        "S7 Write Operation Requested",
                        f"{func_name} UserData operation observed.{target_text}",
                    )
                elif func_name in _ENUM_FUNCTIONS:
                    add(
                        "LOW",
                        "S7 Enumeration/Diagnostics",
                        f"{func_name} UserData operation observed.{target_text}",
                    )

            if event.cotp_type == "DR":
                reason = event.cotp_reason or "Unspecified"
                add(
                    "LOW",
                    "COTP Disconnect Request",
                    f"COTP disconnect observed (reason: {reason}).",
                )
            elif event.cotp_type == "DC":
                add(
                    "LOW",
                    "COTP Disconnect Confirm",
                    "COTP disconnect confirm observed.",
                )
            elif event.cotp_type in {"CR", "CC"} and (
                not event.src_tsap or not event.dst_tsap
            ):
                add(
                    "LOW",
                    "COTP Session Setup Without TSAP",
                    f"COTP {event.cotp_type} observed without full TSAP profile.",
                )

        # Fallback heuristics from command labels only when payload parsing was partial.
        if not saw_structured:
            if any(cmd == "WriteVar" for cmd in commands):
                add(
                    "MEDIUM",
                    "S7 Write Operation Requested",
                    "WriteVar operation observed.",
                )
            if any(
                cmd
                in {"DownloadBlock", "RequestDownload", "StartUpload", "UploadBlock"}
                for cmd in commands
            ):
                add(
                    "HIGH",
                    "S7 Program Transfer Requested",
                    "Program download/upload activity observed.",
                )

        return anomalies

    def is_low_confidence(self, analysis: IndustrialAnalysis) -> bool:
        if analysis.protocol_packets == 0:
            return False
        semantic_total = sum(
            count
            for command, count in analysis.commands.items()
            if _is_semantic_command(command)
        )
        cotp_total = sum(
            count
            for command, count in analysis.commands.items()
            if str(command).startswith("COTP:")
        )
        cotp_session_total = sum(
            count
            for command, count in analysis.commands.items()
            if str(command).startswith("COTP:CR")
            or str(command).startswith("COTP:CC")
            or str(command).startswith("COTP:DR")
            or str(command).startswith("COTP:DC")
        )

        if self.valid_s7_frames == 0 and semantic_total == 0:
            # Keep COTP-only captures when we have explicit connection/session semantics.
            if cotp_session_total > 0 or self.cotp_tsap_profiles > 0 or cotp_total >= 3:
                return False
            return True

        if (
            self.valid_s7_frames <= 1
            and semantic_total <= 1
            and analysis.protocol_packets <= 3
            and cotp_session_total == 0
        ):
            return True

        return False

    def _prune_pending(self, ts: float, max_age_seconds: float = 900.0) -> None:
        if ts <= 0:
            return
        stale_keys = [
            key for key, value in self.pending.items() if (ts - value.ts) > max_age_seconds
        ]
        for key in stale_keys:
            self.pending.pop(key, None)

    def _extract_events(self, payload: bytes, update_counters: bool) -> list[_S7PacketEvent]:
        if not payload:
            return []

        events: list[_S7PacketEvent] = []
        frames, invalid_count, truncated = _extract_tpkt_frames(payload)
        if update_counters:
            self.invalid_tpkt_frames += invalid_count
            if truncated:
                self.invalid_tpkt_frames += 1

        for frame in frames:
            if update_counters:
                self.tpkt_frames += 1
            event = _S7PacketEvent(commands=["TPKT"])

            cotp = _parse_cotp_frame(frame)
            if cotp is None:
                if update_counters:
                    self.invalid_tpkt_frames += 1
                continue

            cotp_type = cotp.pdu_name
            cotp_payload = cotp.payload
            src_tsap = cotp.src_tsap
            dst_tsap = cotp.dst_tsap
            if update_counters:
                self.cotp_frames += 1

            event.commands.append(f"COTP:{cotp_type}")
            event.cotp_type = cotp_type
            event.cotp_reason = cotp.reason
            event.cotp_src_ref = cotp.src_ref
            event.cotp_dst_ref = cotp.dst_ref
            event.cotp_tpdu_size = cotp.tpdu_size

            if cotp.dst_ref is not None or cotp.src_ref is not None:
                dst_ref_text = (
                    f"0x{cotp.dst_ref:04x}" if cotp.dst_ref is not None else "?"
                )
                src_ref_text = (
                    f"0x{cotp.src_ref:04x}" if cotp.src_ref is not None else "?"
                )
                event.commands.append(
                    f"COTP:{cotp_type}:DstRef={dst_ref_text}:SrcRef={src_ref_text}"
                )

            if cotp.tpdu_size is not None:
                event.commands.append(f"COTP:{cotp_type}:TPDUSize={cotp.tpdu_size}")

            if cotp.reason:
                event.commands.append(f"COTP:{cotp_type}:Reason={cotp.reason}")

            event.src_tsap = src_tsap
            event.dst_tsap = dst_tsap
            if src_tsap or dst_tsap:
                if update_counters:
                    self.cotp_tsap_profiles += 1
                event.commands.append(
                    f"COTP:{cotp_type}:SrcTSAP={src_tsap or '?'}:DstTSAP={dst_tsap or '?'}"
                )

            if cotp_payload and cotp_payload[0:1] == b"\x32":
                self._parse_s7_payload(
                    cotp_payload,
                    event,
                    update_counters=update_counters,
                )

            events.append(event)

        return events

    def _parse_s7_payload(
        self,
        payload: bytes,
        event: _S7PacketEvent,
        *,
        update_counters: bool,
    ) -> None:
        if len(payload) < 10 or payload[0] != 0x32:
            return

        rosctr = payload[1]
        pdu_ref = int.from_bytes(payload[4:6], "big")
        param_len = int.from_bytes(payload[6:8], "big")

        header_len = 10
        if rosctr in {0x02, 0x03}:
            if len(payload) < 12:
                return
            header_len = 12
            event.error_class = payload[10]
            event.error_code = payload[11]

        if header_len > len(payload):
            return

        param_end = min(len(payload), header_len + max(param_len, 0))
        param = payload[header_len:param_end]

        event.rosctr = rosctr
        event.pdu_ref = pdu_ref
        event.commands.append(ROSCTR.get(rosctr, f"ROSCTR {rosctr}"))
        if update_counters:
            self.valid_s7_frames += 1

        if rosctr == 0x07:
            user_cmd = _parse_userdata_command(param)
            if user_cmd:
                event.func_name = user_cmd
                event.commands.append(user_cmd)
                if update_counters:
                    self.semantic_commands += 1
        else:
            func_name = None
            if param:
                func_code = param[0]
                func_name = S7_FUNCTIONS.get(func_code, f"Function 0x{func_code:02x}")
                event.commands.append(func_name)
                event.func_name = func_name
                if update_counters and _is_semantic_command(func_name):
                    self.semantic_commands += 1

                if func_name in {"ReadVar", "WriteVar"}:
                    item_cmds, targets = _parse_var_items(func_name, param)
                    event.commands.extend(item_cmds)
                    event.targets.extend(targets)
                    if update_counters and item_cmds:
                        self.semantic_commands += len(item_cmds)

        if rosctr in {0x02, 0x03} and (event.error_class or event.error_code):
            event.commands.append(
                f"S7Error:{_format_s7_error(event.error_class, event.error_code)}"
            )


def _extract_tpkt_frames(payload: bytes) -> tuple[list[bytes], int, bool]:
    frames: list[bytes] = []
    invalid_count = 0
    truncated = False
    idx = 0
    marker = b"\x03\x00"

    while idx + 4 <= len(payload):
        if payload[idx : idx + 2] != marker:
            next_idx = payload.find(marker, idx + 1)
            if next_idx < 0:
                break
            idx = next_idx
            continue

        total_len = int.from_bytes(payload[idx + 2 : idx + 4], "big")
        if total_len < 7:
            invalid_count += 1
            idx += 2
            continue

        end = idx + total_len
        if end > len(payload):
            truncated = True
            break

        frames.append(payload[idx:end])
        idx = end

    return frames, invalid_count, truncated


def _parse_cotp_frame(frame: bytes) -> _CotpFrame | None:
    if len(frame) < 7:
        return None

    cotp_len = frame[4]
    if cotp_len < 1:
        return None

    cotp_end = 5 + cotp_len
    if cotp_end > len(frame):
        return None

    pdu_type = frame[5]
    pdu_name = COTP_PDU_TYPES.get(pdu_type, f"0x{pdu_type:02x}")
    src_tsap = None
    dst_tsap = None
    src_ref = None
    dst_ref = None
    tpdu_size = None
    reason = None

    if pdu_type in {0xE0, 0xD0, 0x80, 0xC0} and cotp_end >= 10:
        dst_ref = int.from_bytes(frame[6:8], "big")
        src_ref = int.from_bytes(frame[8:10], "big")
        if pdu_type == 0x80 and cotp_end >= 11:
            raw_reason = frame[10]
            reason = COTP_DR_REASONS.get(raw_reason, f"0x{raw_reason:02x}")

    if pdu_type in {0xE0, 0xD0}:  # CR/CC
        pos = 11
        while pos + 2 <= cotp_end:
            code = frame[pos]
            length = frame[pos + 1]
            pos += 2
            if pos + length > cotp_end:
                break
            value = frame[pos : pos + length]
            pos += length
            if code == 0xC1:
                src_tsap = _decode_tsap(value)
            elif code == 0xC2:
                dst_tsap = _decode_tsap(value)
            elif code == 0xC0 and value:
                tpdu_size = _decode_tpdu_size(value[0])

    data = frame[cotp_end:] if pdu_type == 0xF0 and cotp_end < len(frame) else b""
    return _CotpFrame(
        pdu_name=pdu_name,
        payload=data,
        src_tsap=src_tsap,
        dst_tsap=dst_tsap,
        src_ref=src_ref,
        dst_ref=dst_ref,
        tpdu_size=tpdu_size,
        reason=reason,
    )


def _decode_tpdu_size(value: int) -> int:
    if value <= 0x1F:
        return 1 << value
    return value


def _decode_tsap(value: bytes) -> str:
    if not value:
        return "?"
    if len(value) == 2:
        hi, lo = value
        role = TSAP_ROLE_HINTS.get(hi)
        rack = (lo >> 5) & 0x07
        slot = lo & 0x1F
        role_text = f"{role}," if role else ""
        return f"0x{hi:02x}{lo:02x}({role_text}rack={rack},slot={slot})"
    return "0x" + value.hex()


def _parse_userdata_command(param: bytes) -> str | None:
    if len(param) < 4:
        return None

    vartab_cmd = _parse_userdata_vartab_command(param)
    if vartab_cmd:
        return vartab_cmd

    marker_idx = param.find(b"\x12\x04")
    if marker_idx < 0 or marker_idx + 4 > len(param):
        return None

    group_raw = param[marker_idx + 2]
    subfunc_raw = param[marker_idx + 3]

    group = group_raw
    if group_raw > 0x0F and (group_raw & 0x0F) in S7_USERDATA_GROUPS:
        group = group_raw & 0x0F

    # Some captures encode subfunction variants in the high nibble (e.g. 0x44,0x43,0x47).
    subfunc = subfunc_raw & 0x0F if subfunc_raw > 0x0F else subfunc_raw

    group_name = S7_USERDATA_GROUPS.get(group, f"Group 0x{group:02x}")
    func_name = S7_USERDATA_FUNCTIONS.get((group, subfunc))
    if func_name:
        if subfunc != subfunc_raw or group != group_raw:
            return (
                f"UserData:{group_name}:{func_name}"
                f"(g=0x{group_raw:02x},s=0x{subfunc_raw:02x})"
            )
        return f"UserData:{group_name}:{func_name}"
    if subfunc != subfunc_raw or group != group_raw:
        return (
            f"UserData:{group_name}:0x{subfunc:02x}"
            f"(g=0x{group_raw:02x},s=0x{subfunc_raw:02x})"
        )
    return f"UserData:{group_name}:0x{subfunc:02x}"


def _parse_userdata_vartab_command(param: bytes) -> str | None:
    # Seen in several STEP7 VAT captures: 00 01 12 08 12 .. .. ..
    if len(param) < 8:
        return None
    if not (param[0] == 0x00 and param[2] == 0x12 and param[3] == 0x08 and param[4] == 0x12):
        return None

    selector = param[5]
    item = param[6]
    mode = param[7]

    if selector & 0x80:
        op = "VarTabWrite"
    elif selector & 0x40:
        op = "VarTabRead"
    else:
        op = "VarTabAccess"

    return (
        f"UserData:Cpu:{op}"
        f"(sel=0x{selector:02x},item=0x{item:02x},mode=0x{mode:02x})"
    )


def _parse_var_items(func_name: str, param: bytes) -> tuple[list[str], list[str]]:
    if len(param) < 2:
        return [], []

    commands: list[str] = []
    targets: list[str] = []
    item_count = param[1]
    offset = 2

    for _ in range(item_count):
        if offset + 2 > len(param):
            break
        if param[offset] != 0x12:
            break
        spec_len = param[offset + 1]
        item_size = 2 + spec_len
        if spec_len < 10 or offset + item_size > len(param):
            break

        transport = param[offset + 3]
        length = int.from_bytes(param[offset + 4 : offset + 6], "big")
        db_num = int.from_bytes(param[offset + 6 : offset + 8], "big")
        area = param[offset + 8]
        addr = int.from_bytes(param[offset + 9 : offset + 12], "big")

        addr_text = _format_var_address(area, db_num, addr, transport)
        transport_name = TRANSPORT_NAMES.get(transport, f"T0x{transport:02x}")
        op = f"{func_name} {addr_text} len={length} {transport_name}"
        commands.append(op)
        targets.append(addr_text)

        offset += item_size

    return commands, targets


def _format_var_address(area: int, db_num: int, addr: int, transport: int) -> str:
    byte_offset = addr // 8
    bit_offset = addr % 8
    area_name = AREA_NAMES.get(area, f"AREA0x{area:02x}")

    if area_name == "DB":
        if transport == 0x03:
            return f"DB{db_num}.DBX{byte_offset}.{bit_offset}"
        if transport == 0x04:
            return f"DB{db_num}.DBB{byte_offset}"
        if transport in {0x05, 0x07}:
            return f"DB{db_num}.DBW{byte_offset}"
        if transport in {0x06, 0x08, 0x09}:
            return f"DB{db_num}.DBD{byte_offset}"
        return f"DB{db_num}.DBX{byte_offset}.{bit_offset}"

    if transport == 0x03:
        return f"{area_name}{byte_offset}.{bit_offset}"
    if transport == 0x04:
        return f"{area_name}B{byte_offset}"
    if transport in {0x05, 0x07}:
        return f"{area_name}W{byte_offset}"
    if transport in {0x06, 0x08, 0x09}:
        return f"{area_name}D{byte_offset}"
    return f"{area_name}{byte_offset}.{bit_offset}"


def _format_s7_error(error_class: int, error_code: int) -> str:
    class_text = _ERROR_CLASS_TEXT.get(error_class, f"class=0x{error_class:02x}")
    if error_class in _ERROR_CLASS_TEXT:
        return f"{class_text} (code=0x{error_code:02x})"
    return f"class=0x{error_class:02x} code=0x{error_code:02x}"


def _is_semantic_command(command: str) -> bool:
    lowered = command.lower()
    if lowered in {"tpkt", "job", "ack", "ackdata", "userdata"}:
        return False
    if lowered.startswith("cotp:"):
        return False
    return any(
        token in lowered
        for token in (
            "readvar",
            "writevar",
            "download",
            "upload",
            "plc",
            "diag",
            "block",
            "security",
            "clock",
            "cpu",
        )
    )


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _canonical_command_name(command: str) -> str:
    marker = "("
    if marker in command:
        return command.split(marker, 1)[0].rstrip()
    return command


def _clear_low_confidence(analysis: IndustrialAnalysis) -> IndustrialAnalysis:
    analysis.protocol_packets = 0
    analysis.protocol_bytes = 0
    analysis.requests = 0
    analysis.responses = 0
    analysis.src_ips.clear()
    analysis.dst_ips.clear()
    analysis.client_ips.clear()
    analysis.server_ips.clear()
    analysis.sessions.clear()
    analysis.ports.clear()
    analysis.commands.clear()
    analysis.service_endpoints.clear()
    analysis.packet_size_buckets = []
    analysis.payload_size_buckets = []
    analysis.command_events = []
    analysis.artifacts = []
    analysis.anomalies = []
    return analysis


def _rollup_anomalies(anomalies: list[IndustrialAnomaly]) -> list[IndustrialAnomaly]:
    if not anomalies:
        return []

    grouped: dict[
        tuple[str, str, str, str],
        dict[str, object],
    ] = {}
    passthrough: list[IndustrialAnomaly] = []

    for anomaly in anomalies:
        ts = float(getattr(anomaly, "ts", 0.0) or 0.0)
        if ts <= 0:
            passthrough.append(anomaly)
            continue
        key = (anomaly.severity, anomaly.title, anomaly.description, anomaly.src)
        slot = grouped.setdefault(
            key,
            {
                "count": 0,
                "first": ts,
                "last": ts,
                "targets": set(),
            },
        )
        slot["count"] = int(slot["count"]) + 1
        slot["first"] = min(float(slot["first"]), ts)
        slot["last"] = max(float(slot["last"]), ts)
        cast_targets = slot["targets"]
        if isinstance(cast_targets, set):
            cast_targets.add(anomaly.dst)

    rolled: list[IndustrialAnomaly] = []
    for (severity, title, description, src), slot in grouped.items():
        count = int(slot["count"])
        first = float(slot["first"])
        last = float(slot["last"])
        targets = slot["targets"] if isinstance(slot["targets"], set) else set()
        dst = "*" if len(targets) != 1 else next(iter(targets))
        desc = description
        if count > 1:
            desc = (
                f"{description} "
                f"Observed {count} times from {_fmt_ts(first)} to {_fmt_ts(last)} "
                f"across {len(targets)} target(s)."
            )
        rolled.append(
            IndustrialAnomaly(
                severity=severity,
                title=title,
                description=desc,
                src=src,
                dst=dst,
                ts=first,
            )
        )

    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    rolled.sort(
        key=lambda item: (
            severity_rank.get(str(item.severity).upper(), 99),
            float(getattr(item, "ts", 0.0) or 0.0),
            str(item.title),
        )
    )

    return rolled + passthrough


def _fmt_ts(ts: float) -> str:
    if ts <= 0:
        return "n/a"
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    except Exception:
        return "n/a"


def _parse_commands(payload: bytes) -> list[str]:
    # Backward-compatible parser entry used by OT fast-mode command extraction.
    return _S7State().parse_commands(payload)


def analyze_s7(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    state = _S7State()
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="S7",
        tcp_ports={S7_PORT},
        command_parser=state.parse_commands,
        artifact_parser=state.parse_artifacts,
        anomaly_detector=state.detect_anomalies,
        enable_enrichment=True,
        show_status=show_status,
    )

    if state.is_low_confidence(analysis):
        return _clear_low_confidence(analysis)

    analysis.anomalies = _rollup_anomalies(analysis.anomalies)

    public_endpoints = []
    for ip_value in set(analysis.src_ips) | set(analysis.dst_ips):
        try:
            if ipaddress.ip_address(ip_value).is_global:
                public_endpoints.append(ip_value)
        except Exception:
            continue
    if public_endpoints and len(analysis.anomalies) < 200:
        analysis.anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="S7 Exposure to Public IP",
                description=f"S7 traffic observed with public endpoint(s): {', '.join(sorted(public_endpoints)[:5])}.",
                src="*",
                dst="*",
                ts=0.0,
            )
        )

    analysis.anomalies = _rollup_anomalies(analysis.anomalies)
    return analysis
