from __future__ import annotations

from pathlib import Path
import ipaddress

from .industrial_helpers import IndustrialAnalysis, IndustrialAnomaly, analyze_port_protocol

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
    return commands


def _parse_commands(payload: bytes) -> list[str]:
    return _parse_mms_commands(payload)


def analyze_mms(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="IEC 61850 MMS",
        tcp_ports={MMS_PORT},
        command_parser=_parse_commands,
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
                title="MMS Exposure to Public IP",
                description=f"MMS traffic observed with public endpoint(s): {', '.join(sorted(public_endpoints)[:5])}.",
                src="*",
                dst="*",
                ts=0.0,
            )
        )
    return analysis
