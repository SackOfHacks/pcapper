from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Optional
import ipaddress
import struct

from .equipment import equipment_artifacts
from .industrial_helpers import (
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_ethertype_protocol,
    analyze_port_protocol,
    default_artifacts,
)

PROFINET_PORTS = {34962, 34963, 34964}
PROFINET_ETHERTYPE = 0x8892

DCP_SERVICE_IDS = {
    0x03: "Identify",
    0x04: "Set",
    0x05: "Get",
    0x06: "Hello",
    0x07: "Get-Enum",
    0x08: "Reset",
}

DCP_SERVICE_TYPES = {
    0x00: "Request",
    0x01: "Response",
}

DCP_OPTIONS = {
    0x01: "IP",
    0x02: "Device",
    0x03: "DHCP",
    0x04: "Control",
    0x05: "DeviceInitiative",
}

DCP_SUBOPTIONS = {
    (0x01, 0x01): "MAC Address",
    (0x01, 0x02): "IP Parameters",
    (0x01, 0x03): "IP Suite",
    (0x02, 0x01): "Device Vendor",
    (0x02, 0x02): "Device Name",
    (0x02, 0x03): "Device ID",
    (0x02, 0x04): "Device Role",
    (0x02, 0x05): "Device Options",
    (0x02, 0x06): "Alias Name",
    (0x03, 0x01): "DHCP",
    (0x04, 0x02): "Reset",
    (0x04, 0x03): "Control",
}

PNIO_BLOCK_TYPES = {
    0x0100: "AR",
    0x0101: "IOCR",
    0x0102: "IOCR",
    0x0104: "AlarmCR",
    0x0105: "ExpectedSubmodule",
    0x0106: "PrmServer",
}

AR_TYPE_NAMES = {
    0x0001: "IO-Controller",
    0x0002: "IO-Supervisor",
    0x0003: "IO-Device",
}

IOCR_TYPE_NAMES = {
    0x0001: "Input",
    0x0002: "Output",
    0x0003: "Multicast",
}

ALARM_TYPE_NAMES = {
    0x0001: "Diagnosis",
    0x0002: "Process",
    0x0003: "Pull",
    0x0004: "Plug",
    0x0005: "Status",
    0x0006: "Update",
    0x0007: "Manufacturer",
}


def _decode_dcp_blocks(payload: bytes, offset: int) -> list[tuple[int, int, bytes]]:
    blocks: list[tuple[int, int, bytes]] = []
    ptr = offset
    while ptr + 4 <= len(payload):
        option = payload[ptr]
        suboption = payload[ptr + 1]
        block_len = int.from_bytes(payload[ptr + 2:ptr + 4], "big")
        ptr += 4
        if block_len <= 0 or ptr + block_len > len(payload):
            break
        block = payload[ptr:ptr + block_len]
        ptr += block_len
        blocks.append((option, suboption, block))
    return blocks


def _format_mac(data: bytes) -> Optional[str]:
    if len(data) < 6:
        return None
    return ":".join(f"{b:02x}" for b in data[:6])


def _parse_dcp_block(
    option: int,
    suboption: int,
    service_name: str,
    data: bytes,
    block_info: Optional[int],
) -> tuple[list[str], list[tuple[str, str]], list[IndustrialAnomaly]]:
    commands: list[str] = []
    artifacts: list[tuple[str, str]] = []
    anomalies: list[IndustrialAnomaly] = []

    option_name = DCP_OPTIONS.get(option, f"Option 0x{option:02x}")
    sub_name = DCP_SUBOPTIONS.get((option, suboption), f"Sub 0x{suboption:02x}")
    commands.append(f"DCP {option_name}/{sub_name}")

    if (option, suboption) == (0x02, 0x02) and data:
        name = data.decode("utf-8", errors="ignore").strip("\x00").strip()
        if name:
            artifacts.append(("dcp_device_name", name))
            if service_name == "Set":
                anomalies.append(
                    IndustrialAnomaly(
                        severity="HIGH",
                        title="PROFINET DCP Device Name Set",
                        description=f"Device name set to {name}.",
                        src="*",
                        dst="*",
                        ts=0.0,
                    )
                )

    if (option, suboption) in {(0x01, 0x02), (0x01, 0x03)} and len(data) >= 12:
        ip = ".".join(str(b) for b in data[0:4])
        mask = ".".join(str(b) for b in data[4:8])
        gw = ".".join(str(b) for b in data[8:12])
        artifacts.append(("dcp_ip", f"{ip} mask {mask} gw {gw}"))
        if service_name == "Set":
            anomalies.append(
                IndustrialAnomaly(
                    severity="HIGH",
                    title="PROFINET DCP IP Set",
                    description=f"IP parameters set to {ip} / {mask} gw {gw}.",
                    src="*",
                    dst="*",
                    ts=0.0,
                )
            )

    if (option, suboption) == (0x01, 0x01):
        mac = _format_mac(data)
        if mac:
            artifacts.append(("dcp_mac", mac))

    if (option, suboption) == (0x02, 0x01) and data:
        vendor = data.decode("utf-8", errors="ignore").strip("\x00").strip()
        if vendor:
            artifacts.append(("dcp_vendor", vendor))
        elif len(data) >= 2:
            vendor_id = int.from_bytes(data[:2], "big")
            artifacts.append(("dcp_vendor_id", str(vendor_id)))

    if (option, suboption) == (0x02, 0x03) and len(data) >= 4:
        vendor_id = int.from_bytes(data[0:2], "big")
        device_id = int.from_bytes(data[2:4], "big")
        artifacts.append(("dcp_device_id", f"vendor={vendor_id} device={device_id}"))

    if (option, suboption) == (0x02, 0x04) and len(data) >= 2:
        role = int.from_bytes(data[0:2], "big")
        artifacts.append(("dcp_device_role", f"0x{role:04x}"))

    if (option, suboption) == (0x02, 0x05) and data:
        opts = ",".join(f"0x{b:02x}" for b in data[:8])
        artifacts.append(("dcp_device_options", opts))

    if (option, suboption) == (0x02, 0x06) and data:
        alias = data.decode("utf-8", errors="ignore").strip("\x00").strip()
        if alias:
            artifacts.append(("dcp_alias_name", alias))

    if (option, suboption) == (0x03, 0x01) and len(data) >= 2:
        dhcp = int.from_bytes(data[0:2], "big")
        artifacts.append(("dcp_dhcp", f"0x{dhcp:04x}"))

    if (option, suboption) == (0x04, 0x02):
        reset_type = int.from_bytes(data[0:2], "big") if len(data) >= 2 else 0
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="PROFINET DCP Reset",
                description=f"DCP reset operation observed (type 0x{reset_type:04x}).",
                src="*",
                dst="*",
                ts=0.0,
            )
        )

    if block_info is not None:
        artifacts.append(("dcp_block", f"{option_name}/{sub_name} info=0x{block_info:04x}"))

    return commands, artifacts, anomalies


def _parse_dcp(payload: bytes) -> tuple[list[str], list[tuple[str, str]], list[IndustrialAnomaly]]:
    commands: list[str] = []
    artifacts: list[tuple[str, str]] = []
    anomalies: list[IndustrialAnomaly] = []
    if len(payload) < 12:
        return commands, artifacts, anomalies

    frame_id = int.from_bytes(payload[0:2], "big")
    service_id = payload[2]
    service_type = payload[3]
    service_name = DCP_SERVICE_IDS.get(service_id, f"Service 0x{service_id:02x}")
    service_type_name = DCP_SERVICE_TYPES.get(service_type, f"Type 0x{service_type:02x}")
    commands.append(f"DCP {service_name} {service_type_name}")
    if service_name in {"Identify", "Get"}:
        anomalies.append(
            IndustrialAnomaly(
                severity="LOW",
                title="PROFINET DCP Enumeration",
                description=f"DCP {service_name} {service_type_name} observed.",
                src="*",
                dst="*",
                ts=0.0,
            )
        )
    if service_name in {"Set", "Reset"}:
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="PROFINET DCP Set/Reset",
                description=f"DCP {service_name} {service_type_name} observed.",
                src="*",
                dst="*",
                ts=0.0,
            )
        )

    data_len = int.from_bytes(payload[10:12], "big")
    block_start = 12
    if data_len and block_start + data_len <= len(payload):
        blocks = _decode_dcp_blocks(payload, block_start)
    else:
        blocks = _decode_dcp_blocks(payload, block_start)

    for option, suboption, block in blocks:
        block_info = None
        data = block
        if len(block) >= 2:
            block_info = int.from_bytes(block[0:2], "big")
            data = block[2:]
        block_cmds, block_artifacts, block_anoms = _parse_dcp_block(
            option, suboption, service_name, data, block_info
        )
        commands.extend(block_cmds)
        artifacts.extend(block_artifacts)
        anomalies.extend(block_anoms)
    return commands, artifacts, anomalies


def _parse_pnio_blocks(payload: bytes) -> tuple[list[str], list[tuple[str, str]]]:
    commands: list[str] = []
    artifacts: list[tuple[str, str]] = []
    if len(payload) < 6:
        return commands, artifacts
    ptr = 0
    while ptr + 4 <= len(payload):
        block_type = int.from_bytes(payload[ptr:ptr + 2], "big")
        block_len = int.from_bytes(payload[ptr + 2:ptr + 4], "big")
        ptr += 4
        if block_len <= 0 or ptr + block_len > len(payload):
            break
        block = payload[ptr:ptr + block_len]
        ptr += block_len

        name = PNIO_BLOCK_TYPES.get(block_type)
        if name is None:
            continue
        commands.append(f"PNIO {name} Block")

        version_hi = None
        version_lo = None
        block_payload = block
        if len(block) >= 2:
            version_hi = block[0]
            version_lo = block[1]
            block_payload = block[2:]
            artifacts.append(("pnio_block", f"{name} v{version_hi}.{version_lo} len={block_len}"))
        else:
            artifacts.append(("pnio_block", f"{name} len={block_len}"))

        if block_type == 0x0100 and len(block_payload) >= 2:
            ar_type = int.from_bytes(block_payload[0:2], "big")
            ar_name = AR_TYPE_NAMES.get(ar_type)
            if len(block_payload) >= 18:
                ar_uuid = block_payload[2:18].hex()
                detail = f"type=0x{ar_type:04x}"
                if ar_name:
                    detail = f"{detail}({ar_name})"
                detail = f"{detail} uuid={ar_uuid}"
                artifacts.append(("pnio_ar", detail))
            else:
                detail = f"type=0x{ar_type:04x}"
                if ar_name:
                    detail = f"{detail}({ar_name})"
                artifacts.append(("pnio_ar", detail))

        if block_type in {0x0101, 0x0102} and len(block_payload) >= 8:
            iocr_type = int.from_bytes(block_payload[0:2], "big")
            iocr_name = IOCR_TYPE_NAMES.get(iocr_type)
            iocr_ref = int.from_bytes(block_payload[2:4], "big")
            frame_id = int.from_bytes(block_payload[6:8], "big")
            detail = f"type=0x{iocr_type:04x}"
            if iocr_name:
                detail = f"{detail}({iocr_name})"
            detail = f"{detail} ref={iocr_ref} frame_id=0x{frame_id:04x}"
            if len(block_payload) >= 12:
                send_clock = int.from_bytes(block_payload[8:10], "big")
                reduction = int.from_bytes(block_payload[10:12], "big")
                detail = f"{detail} clock={send_clock} reduction={reduction}"
            artifacts.append(("pnio_iocr", detail))

        if block_type == 0x0104 and len(block_payload) >= 2:
            alarm_cr_type = int.from_bytes(block_payload[0:2], "big")
            artifacts.append(("pnio_alarmcr", f"type=0x{alarm_cr_type:04x}"))

        if block_type == 0x0105 and len(block_payload) >= 4:
            slot = int.from_bytes(block_payload[0:2], "big")
            subslot = int.from_bytes(block_payload[2:4], "big")
            artifacts.append(("pnio_submodule", f"slot={slot} subslot={subslot}"))

    return commands, artifacts


def _parse_alarm(payload: bytes) -> tuple[list[str], list[tuple[str, str]]]:
    commands: list[str] = []
    artifacts: list[tuple[str, str]] = []
    if len(payload) < 4:
        return commands, artifacts
    alarm_type = int.from_bytes(payload[2:4], "big")
    alarm_name = ALARM_TYPE_NAMES.get(alarm_type)
    if alarm_name:
        commands.append(f"Alarm {alarm_name}")
    else:
        commands.append(f"Alarm 0x{alarm_type:04x}")
    artifacts.append(("alarm_type", f"0x{alarm_type:04x}"))

    if len(payload) >= 6:
        alarm_spec = int.from_bytes(payload[4:6], "big")
        artifacts.append(("alarm_specifier", f"0x{alarm_spec:04x}"))
    if len(payload) >= 10:
        api = int.from_bytes(payload[6:10], "big")
        artifacts.append(("alarm_api", f"0x{api:08x}"))
    if len(payload) >= 12:
        slot = int.from_bytes(payload[10:12], "big")
        artifacts.append(("alarm_slot", str(slot)))
    if len(payload) >= 14:
        subslot = int.from_bytes(payload[12:14], "big")
        artifacts.append(("alarm_subslot", str(subslot)))
    return commands, artifacts


def _parse_commands(payload: bytes) -> list[str]:
    if len(payload) < 2:
        return []
    commands: list[str] = []
    frame_id = int.from_bytes(payload[:2], "big")
    commands.append(f"FrameID 0x{frame_id:04x}")

    if 0xFE00 <= frame_id <= 0xFEFF:
        dcp_commands, _artifacts, _anoms = _parse_dcp(payload)
        commands.extend(dcp_commands)
    elif 0xFC00 <= frame_id <= 0xFDFF:
        commands.append("Alarm Frame")
        alarm_cmds, _ = _parse_alarm(payload)
        commands.extend(alarm_cmds)

    pnio_cmds, _ = _parse_pnio_blocks(payload)
    commands.extend(pnio_cmds)
    return commands


def _parse_artifacts(payload: bytes) -> list[tuple[str, str]]:
    artifacts = default_artifacts(payload)
    artifacts.extend(equipment_artifacts(payload))
    if len(payload) >= 2:
        frame_id = int.from_bytes(payload[:2], "big")
        artifacts.append(("frame_id", f"0x{frame_id:04x}"))
        if 0xFE00 <= frame_id <= 0xFEFF:
            _, dcp_artifacts, _ = _parse_dcp(payload)
            artifacts.extend(dcp_artifacts)
        elif 0xFC00 <= frame_id <= 0xFDFF:
            _, alarm_artifacts = _parse_alarm(payload)
            artifacts.extend(alarm_artifacts)
        pnio_cmds, pnio_artifacts = _parse_pnio_blocks(payload)
        if pnio_cmds:
            artifacts.extend(pnio_artifacts)
    return artifacts


def _detect_anomalies(payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    if len(payload) >= 2:
        frame_id = int.from_bytes(payload[:2], "big")
        if 0xFC00 <= frame_id <= 0xFDFF:
            alarm_cmds, _ = _parse_alarm(payload)
            alarm_detail = alarm_cmds[0] if alarm_cmds else f"Alarm frame (FrameID 0x{frame_id:04x})"
            anomalies.append(
                IndustrialAnomaly(
                    severity="MEDIUM",
                    title="PROFINET Alarm",
                    description=f"{alarm_detail} observed (FrameID 0x{frame_id:04x}).",
                    src=src_ip,
                    dst=dst_ip,
                    ts=ts,
                )
            )
        if 0xFE00 <= frame_id <= 0xFEFF:
            dcp_cmds, _artifacts, dcp_anoms = _parse_dcp(payload)
            for anom in dcp_anoms:
                anomalies.append(
                    IndustrialAnomaly(
                        severity=anom.severity,
                        title=anom.title,
                        description=anom.description,
                        src=src_ip,
                        dst=dst_ip,
                        ts=ts,
                    )
                )
    if len(payload) >= 3 and payload[0] == 0x16 and payload[1] == 0x03:
        anomalies.append(
            IndustrialAnomaly(
                severity="LOW",
                title="Possible PROFINET Security (TLS)",
                description="TLS-style handshake bytes observed on PROFINET traffic.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    return anomalies




def _merge(left: IndustrialAnalysis, right: IndustrialAnalysis) -> IndustrialAnalysis:
    left.total_packets += right.total_packets
    left.protocol_packets += right.protocol_packets
    left.total_bytes += right.total_bytes
    left.protocol_bytes += right.protocol_bytes
    left.requests += right.requests
    left.responses += right.responses
    left.src_ips.update(right.src_ips)
    left.dst_ips.update(right.dst_ips)
    left.client_ips.update(right.client_ips)
    left.server_ips.update(right.server_ips)
    left.sessions.update(right.sessions)
    left.ports.update(right.ports)
    left.commands.update(right.commands)
    for service, endpoints in right.service_endpoints.items():
        left.service_endpoints.setdefault(service, Counter()).update(endpoints)
    left.artifacts.extend(right.artifacts)
    left.anomalies.extend(right.anomalies)
    left.errors.extend(right.errors)
    left.duration = max(left.duration, right.duration)
    left.packet_size_buckets = _merge_size_buckets(
        left.packet_size_buckets, right.packet_size_buckets
    )
    left.payload_size_buckets = _merge_size_buckets(
        left.payload_size_buckets, right.payload_size_buckets
    )
    return left


def _merge_size_buckets(left: list, right: list) -> list:
    if not left:
        return list(right)
    if not right:
        return list(left)
    merged = []
    for l_bucket, r_bucket in zip(left, right):
        count = l_bucket.count + r_bucket.count
        if count:
            avg = ((l_bucket.avg * l_bucket.count) + (r_bucket.avg * r_bucket.count)) / count
            min_val = min(val for val in (l_bucket.min, r_bucket.min) if val is not None)
            max_val = max(val for val in (l_bucket.max, r_bucket.max) if val is not None)
        else:
            avg = 0.0
            min_val = 0
            max_val = 0
        merged.append(
            l_bucket.__class__(
                label=l_bucket.label,
                count=count,
                avg=avg,
                min=min_val,
                max=max_val,
                pct=0.0,
            )
        )
    total = sum(bucket.count for bucket in merged)
    if not total:
        return merged
    updated = []
    for bucket in merged:
        updated.append(
            bucket.__class__(
                label=bucket.label,
                count=bucket.count,
                avg=bucket.avg,
                min=bucket.min,
                max=bucket.max,
                pct=(bucket.count / total) * 100,
            )
        )
    return updated


def analyze_profinet(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    port_analysis = analyze_port_protocol(
        path=path,
        protocol_name="Profinet",
        tcp_ports=PROFINET_PORTS,
        udp_ports=PROFINET_PORTS,
        command_parser=_parse_commands,
        artifact_parser=_parse_artifacts,
        anomaly_detector=_detect_anomalies,
        enable_enrichment=True,
        show_status=show_status,
    )
    eth_analysis = analyze_ethertype_protocol(
        path=path,
        protocol_name="Profinet RT",
        ethertype=PROFINET_ETHERTYPE,
        command_parser=_parse_commands,
        artifact_parser=_parse_artifacts,
        anomaly_detector=_detect_anomalies,
        enable_enrichment=True,
        show_status=show_status,
    )
    merged = _merge(port_analysis, eth_analysis)
    public_endpoints = []
    for ip_value in set(merged.src_ips) | set(merged.dst_ips):
        try:
            if ipaddress.ip_address(ip_value).is_global:
                public_endpoints.append(ip_value)
        except Exception:
            continue
    if public_endpoints and len(merged.anomalies) < 200:
        merged.anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="Profinet Exposure to Public IP",
                description=f"Profinet traffic observed with public endpoint(s): {', '.join(sorted(public_endpoints)[:5])}.",
                src="*",
                dst="*",
                ts=0.0,
            )
        )
    return merged
