from __future__ import annotations

from pathlib import Path
import ipaddress

from .industrial_helpers import IndustrialAnalysis, IndustrialAnomaly, analyze_port_protocol

BACNET_PORT = 47808

BVLC_FUNCTIONS = {
    0x00: "BVLC-Result",
    0x01: "Write-Broadcast-Distribution-Table",
    0x02: "Read-Broadcast-Distribution-Table",
    0x03: "Read-Broadcast-Distribution-Table-Ack",
    0x04: "Forwarded-NPDU",
    0x05: "Register-Foreign-Device",
    0x06: "Read-Foreign-Device-Table",
    0x07: "Delete-Foreign-Device-Table",
    0x08: "Distribute-Broadcast-To-Network",
    0x09: "Original-Unicast-NPDU",
    0x0A: "Original-Broadcast-NPDU",
}

APDU_TYPES = {
    0x00: "Confirmed-Request",
    0x01: "Unconfirmed-Request",
    0x02: "Simple-ACK",
    0x03: "Complex-ACK",
    0x04: "Segment-ACK",
    0x05: "Error",
    0x06: "Reject",
    0x07: "Abort",
}

CONFIRMED_SERVICE_CHOICES = {
    0x0F: "WriteProperty",
    0x11: "DeviceCommunicationControl",
    0x20: "ReinitializeDevice",
}

UNCONFIRMED_SERVICE_CHOICES = {
    0x00: "I-Am",
    0x08: "Who-Is",
}


def _parse_bacnet_apdu(payload: bytes) -> list[str]:
    commands: list[str] = []
    if len(payload) < 6:
        return commands
    if payload[0] != 0x81:
        return commands

    bvlc_func = payload[1]
    if bvlc_func not in {0x09, 0x0A, 0x04}:
        return commands

    idx = 4
    if idx + 2 > len(payload):
        return commands
    if payload[idx] != 0x01:
        return commands
    npdu_control = payload[idx + 1]
    idx += 2

    if npdu_control & 0x20:
        if idx + 3 > len(payload):
            return commands
        dlen = payload[idx + 2]
        idx += 3 + dlen
    if npdu_control & 0x08:
        if idx + 3 > len(payload):
            return commands
        slen = payload[idx + 2]
        idx += 3 + slen
    if npdu_control & 0x80:
        return commands

    if idx >= len(payload):
        return commands
    apdu = payload[idx:]
    if not apdu:
        return commands

    pdu_type = (apdu[0] >> 4) & 0x0F
    pdu_name = APDU_TYPES.get(pdu_type, f"APDU {pdu_type}")
    commands.append(f"APDU {pdu_name}")

    if pdu_type == 0x00:
        segmented = bool(apdu[0] & 0x08)
        offset = 3
        if segmented:
            offset += 2
        if offset < len(apdu):
            service_choice = apdu[offset]
            service_name = CONFIRMED_SERVICE_CHOICES.get(service_choice)
            if service_name:
                commands.append(service_name)
            else:
                commands.append(f"Confirmed Service 0x{service_choice:02x}")
    elif pdu_type == 0x01:
        if len(apdu) >= 2:
            service_choice = apdu[1]
            service_name = UNCONFIRMED_SERVICE_CHOICES.get(service_choice)
            if service_name:
                commands.append(service_name)
            else:
                commands.append(f"Unconfirmed Service 0x{service_choice:02x}")

    return commands


def _parse_commands(payload: bytes) -> list[str]:
    if len(payload) < 2:
        return []
    bvlc_type = payload[0]
    bvlc_func = payload[1]
    cmds = []
    if bvlc_type == 0x81:
        cmds.append("BVLC")
        cmds.append(BVLC_FUNCTIONS.get(bvlc_func, f"BVLC Func {bvlc_func}"))
        cmds.extend(_parse_bacnet_apdu(payload))
    return cmds


def _detect_anomalies(payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    if any("Write-Broadcast-Distribution-Table" in cmd for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="BACnet Broadcast Table Write",
                description="Broadcast Distribution Table write observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any("Register-Foreign-Device" in cmd for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="MEDIUM",
                title="BACnet Foreign Device Registration",
                description="Foreign device registration observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any("Read-Foreign-Device-Table" in cmd for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="LOW",
                title="BACnet Foreign Device Enumeration",
                description="Foreign device table read observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any("Delete-Foreign-Device-Table" in cmd for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="BACnet Foreign Device Table Modification",
                description="Foreign device table deletion observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any("Distribute-Broadcast-To-Network" in cmd for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="LOW",
                title="BACnet Broadcast Distribution",
                description="Broadcast distribution to network observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(cmd == "WriteProperty" for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="BACnet WriteProperty",
                description="WriteProperty service request observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(cmd == "DeviceCommunicationControl" for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="BACnet Device Communication Control",
                description="DeviceCommunicationControl service request observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(cmd == "ReinitializeDevice" for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="BACnet Reinitialize Device",
                description="ReinitializeDevice service request observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    return anomalies


def analyze_bacnet(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="BACnet",
        tcp_ports={BACNET_PORT},
        udp_ports={BACNET_PORT},
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
                title="BACnet Exposure to Public IP",
                description=f"BACnet traffic observed with public endpoint(s): {', '.join(sorted(public_endpoints)[:5])}.",
                src="*",
                dst="*",
                ts=0.0,
            )
        )
    return analysis
