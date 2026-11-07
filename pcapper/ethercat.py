from __future__ import annotations

from pathlib import Path

from .industrial_helpers import (
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_ethertype_protocol,
)
from .utils import memoize_analysis

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

# LWR/LRW are the *cyclic* logical process-data exchange — in a running EtherCAT
# network the master issues them every bus cycle (~1 ms), so flagging each as a
# write anomaly floods the list with thousands of baseline operations (198 hit
# the cap on a normal capture, burying the real findings like FoE firmware
# transfer). Only acyclic/configuration writes are treated as notable.
ACYCLIC_WRITE_COMMANDS = WRITE_COMMANDS - {"LWR", "LRW"}

MAILBOX_TYPES = {
    0x01: "AoE",
    0x02: "EoE",
    0x03: "CoE",
    0x04: "FoE",
    0x05: "SoE",
    0x0F: "VoE",
}

FOE_OPCODES = {
    0x01: "RRQ",
    0x02: "WRQ",
    0x03: "DATA",
    0x04: "ACK",
    0x05: "ERR",
}

SOE_OPCODES = {
    0x01: "Read Request",
    0x02: "Read Response",
    0x03: "Write Request",
    0x04: "Write Response",
    0x05: "Notification",
    0x06: "Emergency",
}


def _parse_datagrams(payload: bytes) -> list[tuple[str, bytes]]:
    datagrams: list[tuple[str, bytes]] = []
    if len(payload) < 2:
        return datagrams
    frame_header = int.from_bytes(payload[:2], "little")
    frame_length = frame_header & 0x07FF
    frame_type = (frame_header >> 12) & 0x0F
    frame_end = 2 + frame_length
    if frame_type != 1 or frame_end > len(payload):
        return datagrams

    idx = 2
    while idx + 10 <= frame_end:
        cmd = payload[idx]
        cmd_name = ETHERCAT_CMDS.get(cmd)
        if cmd_name is None:
            break
        length_flags = int.from_bytes(payload[idx + 6 : idx + 8], "little")
        length = length_flags & 0x07FF
        data_start = idx + 10
        data_end = data_start + length
        if data_end + 2 > frame_end:
            break
        datagrams.append((cmd_name, payload[data_start:data_end]))
        idx = data_end + 2
        if not length_flags & 0x8000:
            break
    return datagrams


def _parse_mailbox(data: bytes) -> list[str]:
    commands: list[str] = []
    if len(data) < 7:
        return commands
    mailbox_length = int.from_bytes(data[:2], "little")
    if mailbox_length > len(data) - 6:
        return commands
    mailbox_type = data[5] & 0x0F
    mailbox_name = MAILBOX_TYPES.get(mailbox_type)
    if mailbox_name is None:
        return commands
    mailbox_data = data[6 : 6 + mailbox_length]
    commands.append(f"Mailbox {mailbox_name}")
    if mailbox_data:
        commands.append(f"{mailbox_name} Len {len(mailbox_data)}")

    if mailbox_type == 0x04 and mailbox_data:
        opcode = mailbox_data[0]
        commands.append(f"FoE {FOE_OPCODES.get(opcode, f'0x{opcode:02x}')}")
    if mailbox_type == 0x05 and mailbox_data:
        opcode = mailbox_data[0] & 0x0F
        commands.append(f"SoE {SOE_OPCODES.get(opcode, f'0x{opcode:02x}')}")
    return commands


def _parse_commands(payload: bytes) -> list[str]:
    if not payload:
        return []
    commands: list[str] = []
    for cmd_name, data in _parse_datagrams(payload):
        commands.append(cmd_name)
        commands.extend(_parse_mailbox(data))
    return commands


def _detect_anomalies(
    payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]
) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    # Raw EtherCAT writes (LWR/LRW cyclic process data AND FPWR/APWR mailbox
    # writes) are the protocol's normal high-frequency transport — a running bus
    # issues tens of thousands per capture, so a per-packet "Write Operation"
    # anomaly just floods the cap and buries the real findings. The
    # security-relevant *application-layer* actions are surfaced by the mailbox
    # detections below (FoE firmware transfer, EoE tunneling, etc.); raw writes
    # are not flagged. (ACYCLIC_WRITE_COMMANDS / WRITE_COMMANDS remain available
    # for the write-volume statistics.)
    if any(cmd.startswith("Mailbox FoE") for cmd in commands):
        foe_write = any("FoE WRQ" in cmd or "FoE DATA" in cmd for cmd in commands)
        severity = "HIGH" if foe_write else "MEDIUM"
        detail = "FoE mailbox activity observed."
        if foe_write:
            detail = (
                "FoE file transfer/write activity observed (possible firmware update)."
            )
        foe_cmds = [cmd for cmd in commands if cmd.startswith("Mailbox FoE")]
        anomalies.append(
            IndustrialAnomaly(
                severity=severity,
                title="EtherCAT FoE Activity",
                description=detail,
                src=src_ip,
                dst=dst_ip,
                ts=ts,
                # File-over-EtherCAT write = firmware/file load to a slave device.
                attack="T0857 System Firmware",
                evidence=[", ".join(foe_cmds[:6]), f"{src_ip} -> {dst_ip}"]
                if foe_cmds
                else [f"{src_ip} -> {dst_ip}"],
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
    if any(cmd.startswith("Mailbox EoE") for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="MEDIUM",
                title="EtherCAT EoE Tunnel",
                description="Ethernet-over-EtherCAT tunneling activity observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    return anomalies


@memoize_analysis
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
