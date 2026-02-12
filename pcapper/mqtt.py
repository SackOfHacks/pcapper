from __future__ import annotations

from pathlib import Path

from .industrial_helpers import IndustrialAnalysis, IndustrialAnomaly, analyze_port_protocol

MQTT_PORTS = {1883, 8883}

MQTT_TYPES = {
    1: "CONNECT",
    2: "CONNACK",
    3: "PUBLISH",
    4: "PUBACK",
    5: "PUBREC",
    6: "PUBREL",
    7: "PUBCOMP",
    8: "SUBSCRIBE",
    9: "SUBACK",
    10: "UNSUBSCRIBE",
    11: "UNSUBACK",
    12: "PINGREQ",
    13: "PINGRESP",
    14: "DISCONNECT",
    15: "AUTH",
}


def _parse_commands(payload: bytes) -> list[str]:
    if not payload:
        return []
    msg_type = payload[0] >> 4
    return [MQTT_TYPES.get(msg_type, f"TYPE {msg_type}")]


def _detect_anomalies(payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    if any(cmd == "CONNECT" for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="LOW",
                title="MQTT Connect",
                description="MQTT CONNECT observed (check for auth configuration).",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(cmd == "PUBLISH" for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="LOW",
                title="MQTT Publish",
                description="MQTT PUBLISH message observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    return anomalies


def analyze_mqtt(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    return analyze_port_protocol(
        path=path,
        protocol_name="MQTT",
        tcp_ports=MQTT_PORTS,
        command_parser=_parse_commands,
        anomaly_detector=_detect_anomalies,
        show_status=show_status,
    )
