from __future__ import annotations

from pathlib import Path
import ipaddress

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


def _parse_commands(payload: bytes) -> list[str]:
    if not payload:
        return []
    cmds: list[str] = []
    if len(payload) >= 4 and payload[0] == 0x03 and payload[1] == 0x00:
        cmds.append("TPKT")
    try:
        idx = payload.index(0x32)
        if idx + 1 < len(payload):
            rosctr = payload[idx + 1]
            cmds.append(ROSCTR.get(rosctr, f"ROSCTR {rosctr}"))
        if idx + 10 <= len(payload):
            param_len = int.from_bytes(payload[idx + 6:idx + 8], "big")
            param_start = idx + 10
            if param_len > 0 and param_start < len(payload):
                func_code = payload[param_start]
                func_name = S7_FUNCTIONS.get(func_code)
                if func_name:
                    cmds.append(func_name)
                else:
                    cmds.append(f"Function 0x{func_code:02x}")

                if func_code in {0x04, 0x05} and param_len >= 2:
                    item_count = payload[param_start + 1]
                    item_offset = param_start + 2
                    for _ in range(item_count):
                        if item_offset + 12 > len(payload):
                            break
                        if payload[item_offset] != 0x12:
                            break
                        spec_len = payload[item_offset + 1]
                        if spec_len < 0x0A:
                            break
                        transport = payload[item_offset + 3]
                        length = int.from_bytes(payload[item_offset + 4:item_offset + 6], "big")
                        db_num = int.from_bytes(payload[item_offset + 6:item_offset + 8], "big")
                        area = payload[item_offset + 8]
                        addr = int.from_bytes(payload[item_offset + 9:item_offset + 12], "big")
                        byte_offset = addr // 8
                        bit_offset = addr % 8
                        area_name = AREA_NAMES.get(area, f"AREA0x{area:02x}")
                        transport_name = TRANSPORT_NAMES.get(transport, f"T0x{transport:02x}")
                        if area_name == "DB":
                            addr_text = f"DB{db_num}.DBX{byte_offset}.{bit_offset}"
                        else:
                            addr_text = f"{area_name}{byte_offset}.{bit_offset}"
                        cmds.append(f"{func_name} {addr_text} len={length} {transport_name}")
                        item_offset += 12

                if rosctr == 0x07 and param_len >= 8:
                    if param_start + 6 <= len(payload):
                        param_bytes = payload[param_start:param_start + param_len]
                        if len(param_bytes) >= 6 and param_bytes[2:4] == b"\x12\x04":
                            group = param_bytes[4]
                            subfunc = param_bytes[5]
                            group_name = S7_USERDATA_GROUPS.get(group, f"Group 0x{group:02x}")
                            func_name = S7_USERDATA_FUNCTIONS.get((group, subfunc))
                            if func_name:
                                cmds.append(f"UserData:{group_name}:{func_name}")
                            else:
                                cmds.append(f"UserData:{group_name}:0x{subfunc:02x}")
    except ValueError:
        pass
    return cmds


def _detect_anomalies(payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    text = payload[:200].decode("utf-8", errors="ignore").lower()
    if "stop" in text or "start" in text:
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="S7 Start/Stop Observed",
                description="Potential PLC start/stop command observed in payload.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(cmd == "WriteVar" for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="S7 Write Operation",
                description="WriteVar operation observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(cmd in {"DownloadBlock", "RequestDownload", "StartUpload", "UploadBlock"} for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="S7 Program Transfer",
                description="Program download/upload activity observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(cmd in {"PLCStop", "PLCColdStart", "PLCHotStart"} for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="S7 CPU State Change",
                description="PLC stop/start operation observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(cmd.startswith("UserData:Security") for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="MEDIUM",
                title="S7 Security Query",
                description="UserData security function observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(cmd in {"ReadVar", "BlockList", "GetBlockInfo", "GetDiagData"} for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="LOW",
                title="S7 Enumeration/Diagnostics",
                description="PLC enumeration or diagnostic query observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    return anomalies


def _parse_artifacts(payload: bytes) -> list[tuple[str, str]]:
    artifacts = default_artifacts(payload)
    artifacts.extend(equipment_artifacts(payload))
    return artifacts


def analyze_s7(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="S7",
        tcp_ports={S7_PORT},
        command_parser=_parse_commands,
        artifact_parser=_parse_artifacts,
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
                title="S7 Exposure to Public IP",
                description=f"S7 traffic observed with public endpoint(s): {', '.join(sorted(public_endpoints)[:5])}.",
                src="*",
                dst="*",
                ts=0.0,
            )
        )
    return analysis
