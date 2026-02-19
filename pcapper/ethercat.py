from __future__ import annotations

from pathlib import Path

from .industrial_helpers import IndustrialAnalysis, IndustrialAnomaly, analyze_ethertype_protocol

ETHERCAT_ETHERTYPE = 0x88A4

ETHERCAT_CMDS = {
    0x01: "APRD",
    0x02: "APWR",
    0x03: "APRW",
    0x04: "FPRD",
    0x05: "FPWR",
    0x06: "FPRW",
    0x07: "BRD",
    0x08: "BWR",
    0x09: "BRW",
    0x0A: "LRD",
    0x0B: "LWR",
    0x0C: "LRW",
    0x0D: "ARMW",
    0x0E: "FRMW",
}

WRITE_COMMANDS = {
    "APWR",
    "APRW",
    "FPWR",
    "FPRW",
    "BWR",
    "BRW",
    "LWR",
    "LRW",
    "ARMW",
    "FRMW",
}

MAILBOX_TYPES = {
    0x01: "CoE",
    0x02: "FoE",
    0x03: "SoE",
    0x04: "EoE",
    0x05: "AoE",
}

FOE_OPCODES = {
    0x01: "RRQ",
    0x02: "WRQ",
    0x03: "DATA",
    0x04: "ACK",
    0x05: "ERR",
}

SOE_OPCODES = {
    0x01: "Read",
    0x02: "Write",
    0x03: "Info",
}


def _parse_datagrams(payload: bytes) -> list[tuple[str, bytes]]:
    datagrams: list[tuple[str, bytes]] = []
    if not payload:
        return datagrams
    start_offsets = [0]
    if len(payload) > 2:
        start_offsets.append(2)
    for start in start_offsets:
        if start >= len(payload):
            continue
        cmd = payload[start]
        if cmd not in ETHERCAT_CMDS:
            continue
        idx = start
        while idx + 10 <= len(payload):
            cmd = payload[idx]
            cmd_name = ETHERCAT_CMDS.get(cmd, f"CMD 0x{cmd:02x}")
            length = int.from_bytes(payload[idx + 6:idx + 8], "little") & 0x07FF
            data_start = idx + 10
            data_end = data_start + length
            if data_end + 2 > len(payload):
                break
            data = payload[data_start:data_end]
            datagrams.append((cmd_name, data))
            idx = data_end + 2
        if datagrams:
            break
    return datagrams


def _parse_mailbox(data: bytes) -> list[str]:
    commands: list[str] = []
    if len(data) < 7:
        return commands
    mailbox_type = None
    candidate = data[6]
    if candidate in MAILBOX_TYPES:
        mailbox_type = candidate
        commands.append(f"Mailbox {MAILBOX_TYPES[candidate]}")
        if len(data) > 7:
            commands.append(f"{MAILBOX_TYPES[candidate]} Len {len(data) - 7}")
    elif data[0] in MAILBOX_TYPES:
        mailbox_type = data[0]
        commands.append(f"Mailbox {MAILBOX_TYPES[mailbox_type]}")

    if mailbox_type == 0x02 and len(data) >= 8:
        opcode = data[7]
        commands.append(f"FoE {FOE_OPCODES.get(opcode, f'0x{opcode:02x}')}")
    if mailbox_type == 0x03 and len(data) >= 8:
        opcode = data[7]
        commands.append(f"SoE {SOE_OPCODES.get(opcode, f'0x{opcode:02x}')}")
    return commands

def _parse_commands(payload: bytes) -> list[str]:
    if not payload:
        return []
    commands: list[str] = []
    for cmd_name, data in _parse_datagrams(payload):
        commands.append(cmd_name)
        commands.extend(_parse_mailbox(data))
    if not commands:
        cmd = payload[0]
        commands.append(ETHERCAT_CMDS.get(cmd, f"CMD 0x{cmd:02x}"))
    return commands

def _detect_anomalies(payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    if any(cmd in WRITE_COMMANDS for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="MEDIUM",
                title="EtherCAT Write Operation",
                description="EtherCAT write/control command observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(cmd.startswith("Mailbox FoE") for cmd in commands):
        severity = "HIGH"
        detail = "FoE mailbox activity observed."
        if any("FoE WRQ" in cmd or "FoE DATA" in cmd for cmd in commands):
            detail = "FoE file transfer/write activity observed (possible firmware update)."
        anomalies.append(
            IndustrialAnomaly(
                severity=severity,
                title="EtherCAT FoE Activity",
                description=detail,
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(cmd.startswith("Mailbox CoE") for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="LOW",
                title="EtherCAT CoE Mailbox",
                description="CoE mailbox traffic observed (configuration or SDO exchange).",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(cmd.startswith("Mailbox SoE") for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="LOW",
                title="EtherCAT SoE Mailbox",
                description="SoE mailbox traffic observed (drive/parameter exchange).",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    return anomalies


def analyze_ethercat(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_ethertype_protocol(
        path=path,
        protocol_name="EtherCAT",
        ethertype=ETHERCAT_ETHERTYPE,
        command_parser=_parse_commands,
        anomaly_detector=_detect_anomalies,
        enable_enrichment=True,
        show_status=show_status,
    )
