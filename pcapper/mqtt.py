from __future__ import annotations

from pathlib import Path

from .industrial_helpers import (
    append_public_exposure_anomaly,
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
)
from .utils import memoize_analysis

MQTT_PORTS = {1883, 8883}
PROTOCOL_NAME = "MQTT"

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

MQTT_CONTROL_KEYWORDS = (
    "cmd",
    "command",
    "write",
    "set",
    "control",
    "actuate",
    "stop",
    "start",
)
_FIXED_FLAGS = {
    1: 0,
    2: 0,
    4: 0,
    5: 0,
    6: 2,
    7: 0,
    8: 2,
    9: 0,
    10: 2,
    11: 0,
    12: 0,
    13: 0,
    14: 0,
    15: 0,
}
_MIN_REMAINING_LENGTH = {
    1: 12,
    2: 2,
    4: 2,
    5: 2,
    6: 2,
    7: 2,
    8: 5,
    9: 3,
    10: 5,
    11: 2,
}


def _decode_remaining_length(payload: bytes, idx: int) -> tuple[int | None, int]:
    start = idx
    multiplier = 1
    value = 0
    while True:
        if idx >= len(payload):
            return None, idx
        digit = payload[idx]
        idx += 1
        value += (digit & 0x7F) * multiplier
        if (digit & 0x80) == 0:
            if idx - start > 1 and value < 128 ** (idx - start - 1):
                return None, idx
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
        if not 1 <= msg_type <= 15:
            break
        if msg_type == 3:
            if (flags >> 1) & 0x03 == 3:
                break
        elif flags != _FIXED_FLAGS[msg_type]:
            break
        remaining_len, next_idx = _decode_remaining_length(payload, idx + 1)
        if remaining_len is None:
            break
        if remaining_len < _MIN_REMAINING_LENGTH.get(msg_type, 0):
            break
        msg_start = next_idx
        msg_end = msg_start + remaining_len
        if msg_end > len(payload):
            break
        data = payload[msg_start:msg_end]

        entry: dict[str, object] = {
            "type": msg_type,
            "flags": flags,
            "topics": [],
            "payload": b"",
        }
        if msg_type == 1 and len(data) >= 10:
            connect = _connect_fields(data)
            if connect is not None:
                for key in ("client_id", "username", "password"):
                    if connect.get(key):
                        entry[key] = connect[key]
            else:
                proto_len = int.from_bytes(data[0:2], "big")
                if len(data) >= 2 + proto_len + 4:
                    client_id_len_offset = 2 + proto_len + 4
                    if client_id_len_offset + 2 <= len(data):
                        client_len = int.from_bytes(
                            data[client_id_len_offset : client_id_len_offset + 2], "big"
                        )
                        client_start = client_id_len_offset + 2
                        client_id = data[client_start : client_start + client_len].decode(
                            "utf-8", errors="ignore"
                        )
                        if client_id:
                            entry["client_id"] = client_id
        elif msg_type == 3 and len(data) >= 2:
            tlen = int.from_bytes(data[0:2], "big")
            if 2 + tlen > len(data):
                break
            topic = data[2 : 2 + tlen].decode("utf-8", errors="ignore")
            if topic:
                entry["topics"] = [topic]
            qos = (flags >> 1) & 0x03
            pos = 2 + tlen
            if qos:
                if pos + 2 > len(data):
                    break
                pos += 2
            entry["payload"] = data[pos:]
        elif msg_type in {8, 10} and len(data) >= 4:
            pos = 2
            topics = []
            while pos + 2 <= len(data):
                tlen = int.from_bytes(data[pos : pos + 2], "big")
                pos += 2
                if pos + tlen > len(data):
                    break
                topic = data[pos : pos + tlen].decode("utf-8", errors="ignore")
                pos += tlen
                if msg_type == 8 and pos < len(data):
                    pos += 1
                if topic:
                    topics.append(topic)
            entry["topics"] = topics

        packets.append(entry)
        idx = msg_end
    return packets


def _mqtt_string(data: bytes, pos: int) -> tuple[bytes, int] | None:
    if pos + 2 > len(data):
        return None
    size = int.from_bytes(data[pos : pos + 2], "big")
    end = pos + 2 + size
    if end > len(data):
        return None
    return data[pos + 2 : end], end


def _connect_fields(data: bytes) -> dict[str, object] | None:
    """Client id, username and password of a CONNECT body (variable header +
    payload), MQTT 3.1 ("MQIsdp"), 3.1.1 and 5. A CONNECT carries the
    credentials in the clear unless the session runs over TLS (8883)."""
    name = _mqtt_string(data, 0)
    if name is None or name[0] not in (b"MQTT", b"MQIsdp"):
        return None
    pos = name[1]
    if pos + 4 > len(data):
        return None
    level, flags = data[pos], data[pos + 1]
    pos += 4  # level, connect flags, keep-alive
    if level == 5:  # properties: a variable-length integer, then the bytes
        size, after = _decode_remaining_length(data, pos)
        if size is None:
            return None
        pos = after + size
    fields: dict[str, object] = {}
    client = _mqtt_string(data, pos)
    if client is None:
        return None
    fields["client_id"] = client[0].decode("utf-8", errors="replace")
    pos = client[1]
    if flags & 0x04:  # will: [v5 properties], topic, message
        if level == 5:
            size, after = _decode_remaining_length(data, pos)
            if size is None:
                return fields
            pos = after + size
        for _ in range(2):
            item = _mqtt_string(data, pos)
            if item is None:
                return fields
            pos = item[1]
    if flags & 0x80:
        user = _mqtt_string(data, pos)
        if user is None:
            return fields
        fields["username"] = user[0].decode("utf-8", errors="replace")
        pos = user[1]
    if flags & 0x40:
        secret = _mqtt_string(data, pos)
        if secret is not None:
            fields["password"] = secret[0].decode("utf-8", errors="replace")
    return fields


def credentials(payload: bytes) -> list[tuple[str, str | None, str | None, str]]:
    """``--creds`` tuples for the CONNECT messages in one TCP payload."""
    found: list[tuple[str, str | None, str | None, str]] = []
    if not payload or payload[0] != 0x10:
        return found
    for entry in _parse_mqtt_packets(payload):
        user = entry.get("username")
        secret = entry.get("password")
        if entry.get("type") != 1 or not (user or secret):
            continue
        client = entry.get("client_id") or "-"
        found.append(
            (
                "MQTT CONNECT Credentials",
                str(user) if user else None,
                str(secret) if secret else None,
                f"CONNECT client id {client!r}" + (" username/password" if secret else " username"),
            )
        )
    return found


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
        username = entry.get("username")
        if isinstance(username, str) and username:
            artifacts.append(("mqtt_username", username))
    return artifacts


def _detect_anomalies(
    payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]
) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    parsed = _parse_mqtt_packets(payload)
    # Plain CONNECT and PUBLISH are normal MQTT operations — a broker capture
    # has thousands of publishes, so a LOW anomaly per message floods the list
    # and buries the notable findings (retained publishes, subscription changes,
    # public-IP exposure — kept below). The CONNECT/PUBLISH volume is already in
    # the command counters and command_events; not flagged per-message.
    if any(
        entry.get("type") == 3 and int(entry.get("flags", 0)) & 0x01
        for entry in parsed
    ):
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
            topic_parts = topic.lower().strip("/").split("/")
            if any(part in MQTT_CONTROL_KEYWORDS for part in topic_parts):
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
    if any(
        cmd.startswith("SUBSCRIBE") or cmd.startswith("UNSUBSCRIBE") for cmd in commands
    ):
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
    for entry in parsed:
        if entry.get("type") == 1 and entry.get("password"):
            anomalies.append(
                IndustrialAnomaly(
                    severity="HIGH",
                    title="MQTT Credentials in Cleartext",
                    description=(
                        f"CONNECT from client {entry.get('client_id') or '-'} carries "
                        f"username {entry.get('username') or '-'!r} and a password "
                        "outside TLS."
                    ),
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


@memoize_analysis
def analyze_mqtt(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        port_key="mqtt",
        path=path,
        protocol_name="MQTT",
        tcp_ports=MQTT_PORTS,
        command_parser=_parse_commands,
        artifact_parser=_parse_artifacts,
        anomaly_detector=_detect_anomalies,
        enable_enrichment=True,
        show_status=show_status,
    )
    append_public_exposure_anomaly(analysis, "MQTT")
    return analysis
