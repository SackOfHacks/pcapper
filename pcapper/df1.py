from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from .industrial_helpers import IndustrialAnalysis, IndustrialAnomaly, analyze_port_protocol

DF1_DLE_STX = b"\x10\x02"
DF1_DLE_ETX = b"\x10\x03"
DF1_DLE_ACK = b"\x10\x06"
DF1_DLE_NAK = b"\x10\x15"

DF1_COMMANDS = {
    0x0A: "Unprotected Logical Read",
    0x0B: "Unprotected Logical Write",
    0x0C: "Typed Logical Read",
    0x0D: "Typed Logical Write",
    0x0E: "Protected Typed Logical Read",
    0x0F: "Protected Typed Logical Write",
}

DF1_WRITE_COMMANDS = {0x0B, 0x0D, 0x0F}
_LIKELY_ENCRYPTED_PORTS = {
    443,
    465,
    853,
    993,
    995,
    8443,
}
_SESSION_PORT_RE = re.compile(r"^.+:(\d+)\s*->\s*.+:(\d+)$")


def _is_df1_control_payload(payload: bytes) -> bool:
    return payload in {DF1_DLE_ACK, DF1_DLE_NAK}


def _match_signature(payload: bytes) -> bool:
    if _is_df1_control_payload(payload):
        return True
    for frame in _extract_df1_frames(payload):
        if _parse_df1_frame(frame) is not None:
            return True
    return False


def _extract_df1_frames(payload: bytes) -> list[bytes]:
    frames: list[bytes] = []
    idx = 0
    while idx + 1 < len(payload):
        if payload[idx : idx + 2] == DF1_DLE_STX:
            idx += 2
            data = bytearray()
            while idx + 1 < len(payload):
                if payload[idx] == 0x10:
                    if payload[idx + 1] == 0x10:
                        data.append(0x10)
                        idx += 2
                        continue
                    if payload[idx : idx + 2] == DF1_DLE_ETX:
                        idx += 2
                        break
                data.append(payload[idx])
                idx += 1
            if data:
                frames.append(bytes(data))
            continue
        idx += 1
    return frames


def _parse_df1_frame(frame: bytes) -> tuple[str, bool] | None:
    if len(frame) < 4:
        return None
    cmd = frame[2]
    name = DF1_COMMANDS.get(cmd)
    if not name:
        return None
    write = cmd in DF1_WRITE_COMMANDS
    return f"DF1 {name}", write


def _parse_commands(payload: bytes) -> list[str]:
    commands: list[str] = []
    if payload == DF1_DLE_ACK:
        commands.append("DF1 ACK")
    if payload == DF1_DLE_NAK:
        commands.append("DF1 NAK")
    for frame in _extract_df1_frames(payload):
        parsed = _parse_df1_frame(frame)
        if parsed is None:
            continue
        cmd, _write = parsed
        commands.append(cmd)
    if commands:
        return commands
    return []


def _session_has_likely_encrypted_port(session_key: str) -> bool:
    match = _SESSION_PORT_RE.match(session_key.strip())
    if not match:
        return False
    sport = int(match.group(1))
    dport = int(match.group(2))
    return sport in _LIKELY_ENCRYPTED_PORTS or dport in _LIKELY_ENCRYPTED_PORTS


def _is_low_confidence_detection(analysis: IndustrialAnalysis) -> bool:
    if analysis.protocol_packets == 0:
        return True

    sessions = list(analysis.sessions.keys())
    if not sessions:
        return True

    all_sessions_tied_to_encrypted = all(
        _session_has_likely_encrypted_port(session) for session in sessions
    )
    if all_sessions_tied_to_encrypted and analysis.protocol_packets <= 5:
        return True

    command_total = sum(analysis.commands.values())
    if analysis.protocol_packets <= 2 and command_total <= 2:
        return True

    return False


def _detect_anomalies(
    payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]
) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    if any("Logical Write" in cmd for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="DF1 Write Operation",
                description="DF1 logical write command observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    for frame in _extract_df1_frames(payload):
        parsed = _parse_df1_frame(frame)
        if parsed is None:
            continue
        cmd, is_write = parsed
        if not is_write:
            continue
        data_len = max(len(frame) - 6, 0)
        if data_len >= 256:
            anomalies.append(
                IndustrialAnomaly(
                    severity="HIGH",
                    title="Possible DF1 Download/Upload",
                    description="Large DF1 write payload observed (possible program/data download).",
                    src=src_ip,
                    dst=dst_ip,
                    ts=ts,
                )
            )
            break
    return anomalies


def analyze_df1(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="DF1",
        signature_matcher=_match_signature,
        command_parser=_parse_commands,
        anomaly_detector=_detect_anomalies,
        enable_enrichment=True,
        show_status=show_status,
    )
    if _is_low_confidence_detection(analysis):
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
                title="DF1 Exposure to Public IP",
                description=f"DF1 traffic observed with public endpoint(s): {', '.join(sorted(public_endpoints)[:5])}.",
                src="*",
                dst="*",
                ts=0.0,
            )
        )
    return analysis
