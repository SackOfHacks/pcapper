from __future__ import annotations

import ipaddress
from pathlib import Path

from .industrial_helpers import (
    append_public_exposure_anomaly,
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
)

MELSEC_TCP_PORT = 5007
MELSEC_UDP_PORT = 5006
# Mitsubishi MELSOFT direct connection (GX Works / iQ-R engineering traffic)
# uses TCP 5562 / UDP 5560 — distinct from SLMP/MC (5006/5007). Without these,
# MELSOFT engineering-station traffic (a high-value OT target) was invisible to
# the analyzer. The SLMP command parser only partially decodes MELSOFT framing,
# but the traffic is at least surfaced and port-classified.
MELSOFT_TCP_PORT = 5562
MELSOFT_UDP_PORT = 5560

# SLMP / MELSEC-MC command codes (Mitsubishi SLMP Reference SH(NA)-080956ENG).
# Remote control codes are 0x1001 RUN / 0x1002 STOP / 0x1003 PAUSE /
# 0x1005 Latch Clear / 0x1006 RESET — previously RUN/STOP were swapped and
# RESET was mis-keyed, which inverted the most operationally significant
# OT control distinction (a PLC STOP vs RUN).
MC_COMMANDS = {
    0x0401: "Batch Read",
    0x0403: "Random Read",
    0x0601: "Read PLC Type",
    0x0602: "Read PLC Status",
    0x1001: "Remote Run",
    0x1002: "Remote Stop",
    0x1003: "Remote Pause",
    0x1005: "Remote Latch Clear",
    0x1006: "Remote Reset",
    0x1401: "Batch Write",
    0x1402: "Random Write",
    0x1403: "Multiple Device Write",
    0x1404: "Batch Write (Random)",
}

MC_WRITE_COMMANDS = {0x1401, 0x1402, 0x1403, 0x1404}

# Remote CPU control operations. Stop/Pause/Reset are operationally disruptive
# (PLC halt/reset = ATT&CK for ICS T0816 Device Restart/Shutdown); Run/Latch
# Clear are control changes worth surfacing but restorative.
MC_CONTROL_DISRUPTIVE = {0x1002: "Remote Stop", 0x1003: "Remote Pause", 0x1006: "Remote Reset"}
MC_CONTROL_OTHER = {0x1001: "Remote Run", 0x1005: "Remote Latch Clear"}


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
                sub_hex = (
                    payload[26:30].decode("ascii", errors="ignore")
                    if len(payload) >= 30
                    else ""
                )
                if all(ch in "0123456789ABCDEFabcdef" for ch in cmd_hex):
                    cmd = int(cmd_hex, 16)
                    subcmd = (
                        int(sub_hex, 16)
                        if sub_hex
                        and all(ch in "0123456789ABCDEFabcdef" for ch in sub_hex)
                        else None
                    )
                    return [f"MC ASCII {_format_cmd(cmd, subcmd)}"]
            except Exception:
                pass
        return ["MC ASCII"]
    if len(payload) >= 2 and payload[0] == 0x50 and payload[1] == 0x00:
        if len(payload) >= 13:
            cmd = int.from_bytes(payload[11:13], "little")
            subcmd = (
                int.from_bytes(payload[13:15], "little") if len(payload) >= 15 else None
            )
            return [f"MC Binary {_format_cmd(cmd, subcmd)}"]
        return ["MC Binary"]
    return []


def _detect_anomalies(
    payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]
) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    write_detected = False
    disruptive_control: list[str] = []
    other_control: list[str] = []
    for cmd in commands:
        if "0x" in cmd:
            try:
                cmd_hex = cmd.split("0x", 1)[1][:4]
                cmd_val = int(cmd_hex, 16)
            except Exception:
                continue
            if cmd_val in MC_WRITE_COMMANDS:
                write_detected = True
            if cmd_val in MC_CONTROL_DISRUPTIVE:
                disruptive_control.append(MC_CONTROL_DISRUPTIVE[cmd_val])
            elif cmd_val in MC_CONTROL_OTHER:
                other_control.append(MC_CONTROL_OTHER[cmd_val])
    if disruptive_control:
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="MELSEC CPU Control Command",
                description=(
                    "MC protocol CPU control command observed ("
                    + ", ".join(sorted(set(disruptive_control)))
                    + "); halts/disrupts PLC execution (ATT&CK T0816)."
                ),
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if other_control:
        anomalies.append(
            IndustrialAnomaly(
                severity="MEDIUM",
                title="MELSEC CPU Control Command",
                description=(
                    "MC protocol CPU control command observed ("
                    + ", ".join(sorted(set(other_control)))
                    + ")."
                ),
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
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
        tcp_ports={MELSEC_TCP_PORT, MELSOFT_TCP_PORT},
        udp_ports={MELSEC_UDP_PORT, MELSOFT_UDP_PORT},
        command_parser=_parse_commands,
        anomaly_detector=_detect_anomalies,
        enable_enrichment=True,
        show_status=show_status,
    )
    append_public_exposure_anomaly(analysis, "MELSEC")

    # MELSOFT (GX Works) engineering-protocol traffic on TCP 5562 / UDP 5560 is
    # the engineering station programming/configuring the PLC — the channel for
    # program download and parameter change (ATT&CK ICS T0843 / T0836). The
    # proprietary MELSOFT framing isn't fully decoded to the individual command,
    # but the presence of engineering-station communication to a controller is
    # itself a high-value event that warrants confirming it is authorized.
    ports_seen = set(getattr(analysis, "ports", {}) or {})
    if (
        {MELSOFT_TCP_PORT, MELSOFT_UDP_PORT} & ports_seen
        and len(analysis.anomalies) < 200
    ):
        eng_pairs = [
            sess
            for sess in (getattr(analysis, "sessions", {}) or {})
            if f":{MELSOFT_TCP_PORT}" in sess or f":{MELSOFT_UDP_PORT}" in sess
        ]
        sample = "; ".join(eng_pairs[:3]) if eng_pairs else ""
        analysis.anomalies.append(
            IndustrialAnomaly(
                severity="MEDIUM",
                title="MELSOFT Engineering-Station Access",
                description=(
                    "MELSOFT (GX Works) engineering-protocol traffic to a "
                    "Mitsubishi PLC — programming/configuration capability "
                    "(program download / parameter change, ATT&CK T0843/T0836). "
                    "Confirm it originates from an authorized engineering station."
                    + (f" Sessions: {sample}." if sample else "")
                ),
                src="*",
                dst="*",
                ts=0.0,
            )
        )
    return analysis
