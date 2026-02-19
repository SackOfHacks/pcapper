from __future__ import annotations

from pathlib import Path
import ipaddress

from .industrial_helpers import IndustrialAnalysis, IndustrialAnomaly, analyze_port_protocol

MELSEC_TCP_PORT = 5007
MELSEC_UDP_PORT = 5006

MC_COMMANDS = {
    0x0401: "Batch Read",
    0x0403: "Random Read",
    0x0601: "Read PLC Type",
    0x0602: "Read PLC Status",
    0x0801: "Remote Run",
    0x1001: "Remote Stop",
    0x1003: "Remote Pause",
    0x1005: "Remote Latch",
    0x1006: "Remote Unlatch",
    0x1401: "Batch Write",
    0x1402: "Random Write",
    0x1403: "Multiple Device Write",
    0x1404: "Batch Write (Random)",
    0x1801: "Remote Reset",
}

MC_WRITE_COMMANDS = {0x1401, 0x1402, 0x1403, 0x1404}


def _format_cmd(cmd: int, subcmd: int | None = None) -> str:
    name = MC_COMMANDS.get(cmd)
    if name:
        label = f"{name} (0x{cmd:04x})"
    else:
        label = f"0x{cmd:04x}"
    if subcmd is not None:
        return f"{label} sub=0x{subcmd:04x}"
    return label


def _parse_commands(payload: bytes) -> list[str]:
    if not payload:
        return []
    if payload.startswith(b"5000") or payload.startswith(b"5001"):
        if len(payload) >= 30:
            try:
                cmd_hex = payload[22:26].decode("ascii", errors="ignore")
                sub_hex = payload[26:30].decode("ascii", errors="ignore") if len(payload) >= 30 else ""
                if all(ch in "0123456789ABCDEFabcdef" for ch in cmd_hex):
                    cmd = int(cmd_hex, 16)
                    subcmd = int(sub_hex, 16) if sub_hex and all(ch in "0123456789ABCDEFabcdef" for ch in sub_hex) else None
                    return [f"MC ASCII {_format_cmd(cmd, subcmd)}"]
            except Exception:
                pass
        return ["MC ASCII"]
    if len(payload) >= 2 and payload[0] == 0x50 and payload[1] == 0x00:
        if len(payload) >= 13:
            cmd = int.from_bytes(payload[11:13], "little")
            subcmd = int.from_bytes(payload[13:15], "little") if len(payload) >= 15 else None
            return [f"MC Binary {_format_cmd(cmd, subcmd)}"]
        return ["MC Binary"]
    return []

def _detect_anomalies(payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    write_detected = False
    for cmd in commands:
        if "0x" in cmd:
            try:
                cmd_hex = cmd.split("0x", 1)[1][:4]
                cmd_val = int(cmd_hex, 16)
                if cmd_val in MC_WRITE_COMMANDS:
                    write_detected = True
            except Exception:
                continue
    if write_detected:
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="MELSEC Write Operation",
                description="MC protocol write command observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any("0x14" in cmd and "Write" not in cmd for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="MEDIUM",
                title="MELSEC Command (Potential Write)",
                description="MC protocol command in 0x14xx range observed (conservative heuristic, potential write).",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    return anomalies


def analyze_melsec(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="MELSEC-Q",
        tcp_ports={MELSEC_TCP_PORT},
        udp_ports={MELSEC_UDP_PORT},
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
                title="MELSEC Exposure to Public IP",
                description=f"MELSEC traffic observed with public endpoint(s): {', '.join(sorted(public_endpoints)[:5])}.",
                src="*",
                dst="*",
                ts=0.0,
            )
        )
    return analysis
