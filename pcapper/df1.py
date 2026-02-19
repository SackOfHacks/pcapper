from __future__ import annotations

from pathlib import Path
import ipaddress

from .industrial_helpers import IndustrialAnalysis, IndustrialAnomaly, analyze_port_protocol

DF1_SIGNATURES = (b"\x10\x02", b"\x10\x03", b"\x10\x06")

DF1_COMMANDS = {
    0x0A: "Unprotected Logical Read",
    0x0B: "Unprotected Logical Write",
    0x0C: "Typed Logical Read",
    0x0D: "Typed Logical Write",
    0x0E: "Protected Typed Logical Read",
    0x0F: "Protected Typed Logical Write",
}

DF1_WRITE_COMMANDS = {0x0B, 0x0D, 0x0F}


def _match_signature(payload: bytes) -> bool:
    return any(sig in payload for sig in DF1_SIGNATURES)


def _extract_df1_frames(payload: bytes) -> list[bytes]:
    frames: list[bytes] = []
    idx = 0
    while idx + 1 < len(payload):
        if payload[idx] == 0x10 and payload[idx + 1] == 0x02:
            idx += 2
            data = bytearray()
            while idx + 1 < len(payload):
                if payload[idx] == 0x10:
                    if payload[idx + 1] == 0x10:
                        data.append(0x10)
                        idx += 2
                        continue
                    if payload[idx + 1] == 0x03:
                        idx += 2
                        break
                data.append(payload[idx])
                idx += 1
            if data:
                frames.append(bytes(data))
            continue
        idx += 1
    return frames


def _parse_df1_frame(frame: bytes) -> tuple[str, bool]:
    if len(frame) < 4:
        return "DF1 Frame", False
    cmd = frame[2]
    name = DF1_COMMANDS.get(cmd, f"Command 0x{cmd:02x}")
    write = cmd in DF1_WRITE_COMMANDS
    return f"DF1 {name}", write


def _parse_commands(payload: bytes) -> list[str]:
    commands: list[str] = []
    if b"\x10\x06" in payload:
        commands.append("DF1 ACK")
    if b"\x10\x15" in payload:
        commands.append("DF1 NAK")
    for frame in _extract_df1_frames(payload):
        cmd, _write = _parse_df1_frame(frame)
        commands.append(cmd)
    if commands:
        return commands
    if _match_signature(payload):
        return ["DF1 Frame"]
    return []


def _detect_anomalies(payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]) -> list[IndustrialAnomaly]:
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
        cmd, is_write = _parse_df1_frame(frame)
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
