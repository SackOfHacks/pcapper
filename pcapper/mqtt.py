from __future__ import annotations

from pathlib import Path
import ipaddress

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

MQTT_CONTROL_KEYWORDS = ("cmd", "command", "write", "set", "control", "actuate", "stop", "start")


def _decode_remaining_length(payload: bytes, idx: int) -> tuple[int | None, int]:
    multiplier = 1
    value = 0
    while True:
        if idx >= len(payload):
            return None, idx
        digit = payload[idx]
        idx += 1
        value += (digit & 0x7F) * multiplier
        if (digit & 0x80) == 0:
            break
        multiplier *= 128
        if multiplier > 128 * 128 * 128:
            return None, idx
    return value, idx


def _parse_mqtt_packets(payload: bytes) -> list[dict[str, object]]:
    packets: list[dict[str, object]] = []
    idx = 0
    while idx < len(payload):
        if idx + 2 > len(payload):
            break
        header = payload[idx]
        msg_type = header >> 4
        flags = header & 0x0F
        remaining_len, next_idx = _decode_remaining_length(payload, idx + 1)
        if remaining_len is None:
            break
        header_len = next_idx - idx
        msg_start = next_idx
        msg_end = msg_start + remaining_len
        if msg_end > len(payload):
            break
        data = payload[msg_start:msg_end]

        entry: dict[str, object] = {"type": msg_type, "flags": flags, "topics": [], "payload": b""}
        if msg_type == 1 and len(data) >= 10:
            proto_len = int.from_bytes(data[0:2], "big")
            if len(data) >= 2 + proto_len + 4:
                client_id_len_offset = 2 + proto_len + 4
                if client_id_len_offset + 2 <= len(data):
                    client_len = int.from_bytes(data[client_id_len_offset:client_id_len_offset + 2], "big")
                    client_start = client_id_len_offset + 2
                    client_id = data[client_start:client_start + client_len].decode("utf-8", errors="ignore")
                    if client_id:
                        entry["client_id"] = client_id
        elif msg_type == 3 and len(data) >= 2:
            tlen = int.from_bytes(data[0:2], "big")
            topic = data[2:2 + tlen].decode("utf-8", errors="ignore") if 2 + tlen <= len(data) else ""
            if topic:
                entry["topics"] = [topic]
            qos = (flags >> 1) & 0x03
            pos = 2 + tlen
            if qos:
                pos += 2
            entry["payload"] = data[pos:]
        elif msg_type in {8, 10} and len(data) >= 4:
            pos = 2
            topics = []
            while pos + 2 <= len(data):
                tlen = int.from_bytes(data[pos:pos + 2], "big")
                pos += 2
                if pos + tlen > len(data):
                    break
                topic = data[pos:pos + tlen].decode("utf-8", errors="ignore")
                pos += tlen
                if msg_type == 8 and pos < len(data):
                    pos += 1
                if topic:
                    topics.append(topic)
            entry["topics"] = topics

        packets.append(entry)
        idx = msg_end
    return packets


def _parse_commands(payload: bytes) -> list[str]:
    if not payload:
        return []
    commands: list[str] = []
    for entry in _parse_mqtt_packets(payload):
        msg_type = int(entry.get("type", -1))
        base = MQTT_TYPES.get(msg_type, f"TYPE {msg_type}")
        if msg_type == 3:
            flags = int(entry.get("flags", 0))
            dup = (flags & 0x08) != 0
            qos = (flags >> 1) & 0x03
            retain = (flags & 0x01) != 0
            suffix = f" qos{qos}"
            if retain:
                suffix += " retain"
            if dup:
                suffix += " dup"
            topics = entry.get("topics") or []
            topic = topics[0] if topics else ""
            if topic:
                commands.append(f"{base} {topic}{suffix}")
            else:
                commands.append(f"{base}{suffix}")
        elif msg_type in {8, 10}:
            topics = entry.get("topics") or []
            if topics:
                for topic in topics:
                    commands.append(f"{base} {topic}")
            else:
                commands.append(base)
        else:
            commands.append(base)
    return commands


def _parse_artifacts(payload: bytes) -> list[tuple[str, str]]:
    artifacts: list[tuple[str, str]] = []
    for entry in _parse_mqtt_packets(payload):
        topics = entry.get("topics") or []
        for topic in topics:
            artifacts.append(("mqtt_topic", topic))
        payload_bytes = entry.get("payload")
        if isinstance(payload_bytes, (bytes, bytearray)) and payload_bytes:
            snippet = payload_bytes[:120].decode("utf-8", errors="ignore").strip()
            if snippet:
                artifacts.append(("mqtt_payload", snippet))
        client_id = entry.get("client_id")
        if isinstance(client_id, str) and client_id:
            artifacts.append(("mqtt_client_id", client_id))
    return artifacts


def _detect_anomalies(payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    parsed = _parse_mqtt_packets(payload)
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
    if any(cmd.startswith("PUBLISH") for cmd in commands):
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
    if any(cmd.startswith("PUBLISH") and "retain" in cmd for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="MEDIUM",
                title="MQTT Retained Publish",
                description="Retained PUBLISH observed (persistent control payload).",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    for entry in parsed:
        topics = entry.get("topics") or []
        for topic in topics:
            if any(marker in topic.lower() for marker in MQTT_CONTROL_KEYWORDS):
                anomalies.append(
                    IndustrialAnomaly(
                        severity="MEDIUM",
                        title="MQTT Control Topic",
                        description=f"Publish/subscribe on control-like topic '{topic}'.",
                        src=src_ip,
                        dst=dst_ip,
                        ts=ts,
                    )
                )
                break
    if any(cmd.startswith("SUBSCRIBE") or cmd.startswith("UNSUBSCRIBE") for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="MEDIUM",
                title="MQTT Subscription Change",
                description="SUBSCRIBE/UNSUBSCRIBE observed (topic access changes).",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(cmd == "AUTH" for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="LOW",
                title="MQTT Auth Exchange",
                description="MQTT AUTH exchange observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    return anomalies


def analyze_mqtt(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="MQTT",
        tcp_ports=MQTT_PORTS,
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
                title="MQTT Exposure to Public IP",
                description=f"MQTT traffic observed with public endpoint(s): {', '.join(sorted(public_endpoints)[:5])}.",
                src="*",
                dst="*",
                ts=0.0,
            )
        )
    return analysis
