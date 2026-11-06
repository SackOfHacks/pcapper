from __future__ import annotations

from collections.abc import Iterator

from .utils import read_ber_length as _read_ber_length
from pathlib import Path

from .industrial_helpers import (
    append_public_exposure_anomaly,
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
    TPKTTCPReassembler,
)
from .utils import memoize_analysis

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

_MMS_SERVICE_NAMES = (
    "Status",
    "GetNameList",
    "Identify",
    "Rename",
    "Read",
    "Write",
    "GetVariableAccessAttributes",
    "DefineNamedVariable",
    "DefineScatteredAccess",
    "GetScatteredAccessAttributes",
    "DeleteVariableAccess",
    "DefineNamedVariableList",
    "GetNamedVariableListAttributes",
    "DeleteNamedVariableList",
    "DefineNamedType",
    "GetNamedTypeAttributes",
    "DeleteNamedType",
    "Input",
    "Output",
    "TakeControl",
    "RelinquishControl",
    "DefineSemaphore",
    "DeleteSemaphore",
    "ReportSemaphoreStatus",
    "ReportPoolSemaphoreStatus",
    "ReportSemaphoreEntryStatus",
    "InitiateDownloadSequence",
    "DownloadSegment",
    "TerminateDownloadSequence",
    "InitiateUploadSequence",
    "UploadSegment",
    "TerminateUploadSequence",
    "RequestDomainDownload",
    "RequestDomainUpload",
    "LoadDomainContent",
    "StoreDomainContent",
    "DeleteDomain",
    "GetDomainAttributes",
    "CreateProgramInvocation",
    "DeleteProgramInvocation",
    "Start",
    "Stop",
    "Resume",
    "Reset",
    "Kill",
    "GetProgramInvocationAttributes",
    "ObtainFile",
    "DefineEventCondition",
    "DeleteEventCondition",
    "GetEventConditionAttributes",
    "ReportEventConditionStatus",
    "AlterEventConditionMonitoring",
    "TriggerEvent",
    "DefineEventAction",
    "DeleteEventAction",
    "GetEventActionAttributes",
    "ReportEventActionStatus",
    "DefineEventEnrollment",
    "DeleteEventEnrollment",
    "AlterEventEnrollment",
    "ReportEventEnrollmentStatus",
    "GetEventEnrollmentAttributes",
    "AcknowledgeEventNotification",
    "GetAlarmSummary",
    "GetAlarmEnrollmentSummary",
    "ReadJournal",
    "WriteJournal",
    "InitializeJournal",
    "ReportJournalStatus",
    "CreateJournal",
    "DeleteJournal",
    "GetCapabilityList",
    "FileOpen",
    "FileRead",
    "FileClose",
    "FileRename",
    "FileDelete",
    "FileDirectory",
)

MMS_SERVICE_TAGS = {
    tag: name
    for index, name in enumerate(_MMS_SERVICE_NAMES)
    for tag in (
        (0x80 + index, 0xA0 + index)
        if index < 31
        else (0x9F00 | index, 0xBF00 | index)
    )
}


def _locate_mms_payload(payload: bytes) -> bytes:
    if payload.startswith(b"\x03\x00"):
        if len(payload) < 7:
            return b""
        tpkt_len = int.from_bytes(payload[2:4], "big")
        cotp_end = 5 + payload[4]
        if tpkt_len < 7 or tpkt_len > len(payload) or cotp_end > tpkt_len:
            return b""
        return payload[cotp_end:tpkt_len]
    return payload


def _iter_tpkt_frames(payload: bytes) -> Iterator[bytes]:
    if not payload.startswith(b"\x03\x00"):
        yield payload
        return
    idx = 0
    while idx + 4 <= len(payload):
        start = payload.find(b"\x03\x00", idx)
        if start < 0:
            return
        if start + 4 > len(payload):
            return
        frame_len = int.from_bytes(payload[start + 2 : start + 4], "big")
        if frame_len < 7:
            idx = start + 2
            continue
        end = start + frame_len
        if end > len(payload):
            return
        yield payload[start:end]
        idx = end


def _parse_mms_commands(payload: bytes) -> list[str]:
    commands: list[str] = []
    for frame in _iter_tpkt_frames(payload):
        is_tpkt = frame.startswith(b"\x03\x00")
        if is_tpkt:
            commands.append("TPKT")
        data = _locate_mms_payload(frame) if is_tpkt else frame
        pdu, service = _find_mms_pdu(data)
        if pdu:
            commands.append(f"MMS {pdu}")
        if service:
            commands.append(f"MMS Service {service}")
    return commands


def _read_ber_tlv(data: bytes, idx: int) -> tuple[int | None, bytes, int]:
    if idx >= len(data):
        return None, b"", idx
    tag_start = idx
    tag = data[idx]
    idx += 1
    if tag & 0x1F == 0x1F:
        tag_number = 0
        terminated = False
        for _ in range(5):
            if idx >= len(data):
                return None, b"", idx
            octet = data[idx]
            idx += 1
            if tag_number == 0 and octet == 0x80:
                return None, b"", idx
            tag_number = (tag_number << 7) | (octet & 0x7F)
            if not octet & 0x80:
                terminated = True
                break
        if not terminated or tag_number < 31:
            return None, b"", idx
        tag = int.from_bytes(data[tag_start:idx], "big")
    length, idx = _read_ber_length(data, idx)
    if length is None or idx + length > len(data):
        return None, b"", idx
    value = data[idx : idx + length]
    return tag, value, idx + length


def _parse_mms_service(data: bytes) -> str | None:
    _, service = _find_mms_pdu(data)
    return service


def _find_mms_pdu(data: bytes) -> tuple[str | None, str | None]:
    for offset, candidate in enumerate(data):
        if candidate not in MMS_PDU_TAGS:
            continue
        tag, value, end = _read_ber_tlv(data, offset)
        if tag != candidate or end <= offset or end > len(data):
            continue
        if tag in {0xA0, 0xA1}:
            service = _confirmed_service(value)
            if service is None:
                continue
            return MMS_PDU_TAGS[tag], service if tag == 0xA0 else None
        if tag in {0xA8, 0xA9} and _is_initiate_pdu(value):
            return MMS_PDU_TAGS[tag], None
    return None, None


def _confirmed_service(value: bytes) -> str | None:
    idx = 0
    invoke_tag, invoke_id, idx = _read_ber_tlv(value, idx)
    if invoke_tag != 0x02 or not 1 <= len(invoke_id) <= 4:
        return None
    while idx < len(value):
        inner_tag, inner_value, next_idx = _read_ber_tlv(value, idx)
        if inner_tag is None or next_idx <= idx:
            return None
        if inner_tag in MMS_SERVICE_TAGS:
            return MMS_SERVICE_TAGS[inner_tag]
        idx = next_idx
    return None


def _is_initiate_pdu(value: bytes) -> bool:
    tag, inner_value, next_idx = _read_ber_tlv(value, 0)
    return tag == 0x80 and bool(inner_value) and next_idx > 0


def _parse_commands(payload: bytes) -> list[str]:
    return _parse_mms_commands(payload)


# High-signal MMS services. On an IEC 61850 substation network a MMS Write
# (variable write to an IED) is an unauthorized-command indicator (ATT&CK ICS
# T0855), and Delete/File operations indicate config/firmware tampering or
# anti-forensic activity (T0809/T0872).
MMS_WRITE_SERVICES = {"Write"}
MMS_DELETE_SERVICES = {
    "DeleteNamedVariableList",
    "DeleteVariableAccess",
    "DeleteNamedType",
    "DeleteSemaphore",
    "DeleteProgramInvocation",
    "DeleteDomain",
    "DeleteEventCondition",
    "DeleteEventAction",
    "DeleteEventEnrollment",
    "DeleteJournal",
    "FileDelete",
}
MMS_FILE_SERVICES = {"ObtainFile", "FileOpen", "FileRead", "FileRename"}
MMS_CONTROL_SERVICES = {"Output", "TakeControl", "Start", "Stop", "Resume", "Reset", "Kill"}
MMS_TRANSFER_SERVICES = {
    "InitiateDownloadSequence",
    "DownloadSegment",
    "TerminateDownloadSequence",
    "InitiateUploadSequence",
    "UploadSegment",
    "TerminateUploadSequence",
    "RequestDomainDownload",
    "RequestDomainUpload",
    "LoadDomainContent",
    "StoreDomainContent",
    "CreateProgramInvocation",
}


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
    controls = services & MMS_CONTROL_SERVICES
    if controls:
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="MMS Control Operation",
                description=(
                    "MMS control service observed ("
                    + ", ".join(sorted(controls))
                    + "); validate the operator, target, and change authorization."
                ),
                src=src_ip,
                dst=dst_ip,
                ts=ts,
                attack="T0855 Unauthorized Command Message",
                evidence=[
                    "MMS service(s): " + ", ".join(sorted(controls)),
                    f"{src_ip} -> {dst_ip}",
                ],
            )
        )
    transfers = services & MMS_TRANSFER_SERVICES
    if transfers:
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="MMS Program/Domain Transfer",
                description=(
                    "MMS program or domain transfer service observed ("
                    + ", ".join(sorted(transfers))
                    + "); verify this activity is authorized."
                ),
                src=src_ip,
                dst=dst_ip,
                ts=ts,
                attack="T0843 Program Download",
                evidence=[
                    "MMS service(s): " + ", ".join(sorted(transfers)),
                    f"{src_ip} -> {dst_ip}",
                ],
            )
        )
    return anomalies


@memoize_analysis
def analyze_mms(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    reassembler = TPKTTCPReassembler("MMS")
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="IEC 61850 MMS",
        tcp_ports={MMS_PORT},
        command_parser=_parse_commands,
        anomaly_detector=_detect_mms_anomalies,
        enable_enrichment=True,
        show_status=show_status,
        payload_reassembler=reassembler,
    )
    reassembler.finish()
    analysis.errors.extend(reassembler.errors)
    append_public_exposure_anomaly(analysis, "MMS")
    return analysis
