from __future__ import annotations

from .utils import read_ber_length as _read_ber_length
import ipaddress
from pathlib import Path

from .industrial_helpers import (
    append_public_exposure_anomaly,
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
)

MMS_PORT = 102

MMS_PDU_TAGS = {
    0xA0: "Confirmed-Request",
    0xA1: "Confirmed-Response",
    0xA2: "Confirmed-Error",
    0xA3: "Unconfirmed",
    0xA4: "Reject",
    0xA5: "Cancel-Request",
    0xA6: "Cancel-Response",
    0xA7: "Cancel-Error",
    0xA8: "Initiate-Request",
    0xA9: "Initiate-Response",
    0xAA: "Initiate-Error",
    0xAB: "Conclude-Request",
    0xAC: "Conclude-Response",
    0xAD: "Conclude-Error",
}

MMS_SERVICE_TAGS = {
    0xA4: "Read",
    0xA5: "Write",
    0xA6: "GetVariableAccessAttributes",
    0xA7: "DefineNamedVariable",
    0xA8: "DefineScatteredAccess",
    0xA9: "GetScatteredAccessAttributes",
    0xAA: "DeleteVariableAccess",
    0xAB: "DefineNamedVariableList",
    0xAC: "GetNamedVariableListAttributes",
    0xAD: "DeleteNamedVariableList",
    0xAE: "DefineNamedType",
    0xAF: "GetNamedTypeAttributes",
    0xB0: "DeleteNamedType",
    0xB1: "ReadJournal",
    0xB2: "InitializeJournal",
    0xB3: "ReportJournalStatus",
    0xB4: "GetCapabilityList",
    0xB5: "FileOpen",
    0xB6: "FileRead",
    0xB7: "FileClose",
    0xB8: "FileRename",
    0xB9: "FileDelete",
}


def _locate_mms_payload(payload: bytes) -> bytes:
    if len(payload) < 4:
        return payload
    if payload[0] == 0x03 and payload[1] == 0x00 and len(payload) >= 7:
        tpkt_len = int.from_bytes(payload[2:4], "big")
        tpkt_end = min(len(payload), tpkt_len)
        idx = 4
        if idx < tpkt_end:
            cotp_len = payload[idx]
            idx += 1 + cotp_len
        return payload[idx:tpkt_end] if idx < tpkt_end else payload
    return payload


def _parse_mms_commands(payload: bytes) -> list[str]:
    commands: list[str] = []
    if len(payload) >= 4 and payload[0] == 0x03 and payload[1] == 0x00:
        commands.append("TPKT")
    data = _locate_mms_payload(payload)
    for idx, byte in enumerate(data[:64]):
        if byte in MMS_PDU_TAGS:
            commands.append(f"MMS {MMS_PDU_TAGS[byte]}")
            break
    service = _parse_mms_service(data)
    if service:
        commands.append(f"MMS Service {service}")
    return commands


def _read_ber_tlv(data: bytes, idx: int) -> tuple[int | None, bytes, int]:
    if idx >= len(data):
        return None, b"", idx
    tag = data[idx]
    idx += 1
    length, idx = _read_ber_length(data, idx)
    if length is None or idx + length > len(data):
        return None, b"", idx
    value = data[idx : idx + length]
    return tag, value, idx + length


def _parse_mms_service(data: bytes) -> str | None:
    tag, value, _ = _read_ber_tlv(data, 0)
    if tag != 0xA0 or not value:
        return None
    idx = 0
    while idx < len(value):
        inner_tag, inner_value, next_idx = _read_ber_tlv(value, idx)
        if inner_tag is None or next_idx <= idx:
            break
        if inner_tag in MMS_SERVICE_TAGS:
            return MMS_SERVICE_TAGS[inner_tag]
        idx = next_idx
    return None


def _parse_commands(payload: bytes) -> list[str]:
    return _parse_mms_commands(payload)


# High-signal MMS services. On an IEC 61850 substation network a MMS Write
# (variable write to an IED) is an unauthorized-command indicator (ATT&CK ICS
# T0855), and Delete/File operations indicate config/firmware tampering or
# anti-forensic activity (T0809/T0872).
MMS_WRITE_SERVICES = {"Write"}
MMS_DELETE_SERVICES = {
    "FileDelete",
    "DeleteNamedVariableList",
    "DeleteVariableAccess",
    "DeleteNamedType",
}
MMS_FILE_SERVICES = {"FileOpen", "FileRead", "FileRename"}


def _detect_mms_anomalies(
    payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]
) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    services = {
        cmd.split("MMS Service ", 1)[1]
        for cmd in commands
        if cmd.startswith("MMS Service ")
    }
    writes = services & MMS_WRITE_SERVICES
    if writes:
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="MMS Write Operation",
                description="MMS Write service observed (variable write to IED; ATT&CK T0855).",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
                attack="T0855 Unauthorized Command Message",
                evidence=[
                    "MMS service(s): " + ", ".join(sorted(writes)),
                    f"{src_ip} -> {dst_ip}",
                ],
            )
        )
    deletes = services & MMS_DELETE_SERVICES
    if deletes:
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="MMS Delete/File Removal",
                description=(
                    "MMS delete service observed ("
                    + ", ".join(sorted(deletes))
                    + "); possible config tampering or anti-forensics (T0872)."
                ),
                src=src_ip,
                dst=dst_ip,
                ts=ts,
                attack="T0809 Data Destruction",
                evidence=[
                    "MMS service(s): " + ", ".join(sorted(deletes)),
                    f"{src_ip} -> {dst_ip}",
                ],
            )
        )
    files = services & MMS_FILE_SERVICES
    if files:
        anomalies.append(
            IndustrialAnomaly(
                severity="MEDIUM",
                title="MMS File Operation",
                description=(
                    "MMS file service observed ("
                    + ", ".join(sorted(files))
                    + "); config/firmware file access."
                ),
                src=src_ip,
                dst=dst_ip,
                ts=ts,
                attack="T0857 System Firmware",
                evidence=[
                    "MMS service(s): " + ", ".join(sorted(files)),
                    f"{src_ip} -> {dst_ip}",
                ],
            )
        )
    return anomalies


def analyze_mms(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="IEC 61850 MMS",
        tcp_ports={MMS_PORT},
        command_parser=_parse_commands,
        anomaly_detector=_detect_mms_anomalies,
        enable_enrichment=True,
        show_status=show_status,
    )
    append_public_exposure_anomaly(analysis, "MMS")
    return analysis
