from __future__ import annotations

from pathlib import Path
import ipaddress

from .industrial_helpers import IndustrialAnalysis, IndustrialAnomaly, analyze_port_protocol

OPC_UA_PORT = 4840

OPC_TYPES = {
    b"HEL": "Hello",
    b"ACK": "Acknowledge",
    b"OPN": "OpenSecureChannel",
    b"CLO": "CloseSecureChannel",
    b"MSG": "Message",
    b"ERR": "Error",
}

OPC_UA_SERVICE_NAMES = {
    # Common services (numeric NodeId i=xxxx)
    428: "FindServersRequest",
    431: "FindServersResponse",
    432: "GetEndpointsRequest",
    435: "GetEndpointsResponse",
    459: "CreateSessionRequest",
    462: "CreateSessionResponse",
    467: "ActivateSessionRequest",
    470: "ActivateSessionResponse",
    473: "CloseSessionRequest",
    476: "CloseSessionResponse",
    527: "BrowseRequest",
    530: "BrowseResponse",
    631: "ReadRequest",
    634: "ReadResponse",
    673: "WriteRequest",
    676: "WriteResponse",
    704: "CallRequest",
    707: "CallResponse",
    751: "CreateSubscriptionRequest",
    754: "CreateSubscriptionResponse",
    787: "CreateMonitoredItemsRequest",
    790: "CreateMonitoredItemsResponse",
    793: "ModifyMonitoredItemsRequest",
    796: "ModifyMonitoredItemsResponse",
    799: "SetMonitoringModeRequest",
    802: "SetMonitoringModeResponse",
    805: "SetTriggeringRequest",
    808: "SetTriggeringResponse",
    811: "DeleteMonitoredItemsRequest",
    814: "DeleteMonitoredItemsResponse",
    817: "CreateSubscriptionRequest",
    820: "CreateSubscriptionResponse",
    823: "ModifySubscriptionRequest",
    826: "ModifySubscriptionResponse",
    829: "SetPublishingModeRequest",
    832: "SetPublishingModeResponse",
    835: "PublishRequest",
    838: "PublishResponse",
    841: "RepublishRequest",
    844: "RepublishResponse",
    847: "TransferSubscriptionsRequest",
    850: "TransferSubscriptionsResponse",
    853: "DeleteSubscriptionsRequest",
    856: "DeleteSubscriptionsResponse",
    620: "BrowseNextRequest",
    623: "BrowseNextResponse",
    627: "TranslateBrowsePathsToNodeIdsRequest",
    630: "TranslateBrowsePathsToNodeIdsResponse",
    637: "ReadRequest",
    640: "ReadResponse",
    673: "WriteRequest",
    676: "WriteResponse",
    704: "CallRequest",
    707: "CallResponse",
    736: "HistoryReadRequest",
    739: "HistoryReadResponse",
    742: "HistoryUpdateRequest",
    745: "HistoryUpdateResponse",
    746: "RegisterNodesRequest",
    749: "RegisterNodesResponse",
    750: "UnregisterNodesRequest",
    753: "UnregisterNodesResponse",
}


def _parse_nodeid(payload: bytes, idx: int) -> tuple[tuple[int, int] | None, int]:
    if idx >= len(payload):
        return None, idx
    encoding = payload[idx]
    idx += 1
    if encoding == 0x00 and idx < len(payload):
        node_id = payload[idx]
        idx += 1
        return (0, node_id), idx
    if encoding == 0x01 and idx + 2 < len(payload):
        node_id = int.from_bytes(payload[idx:idx + 2], "little")
        ns = payload[idx + 2]
        idx += 3
        return (ns, node_id), idx
    if encoding == 0x02 and idx + 5 < len(payload):
        ns = int.from_bytes(payload[idx:idx + 2], "little")
        node_id = int.from_bytes(payload[idx + 2:idx + 6], "little")
        idx += 6
        return (ns, node_id), idx
    return None, idx


def _read_int32(payload: bytes, idx: int) -> tuple[int | None, int]:
    if idx + 4 > len(payload):
        return None, idx
    value = int.from_bytes(payload[idx:idx + 4], "little", signed=True)
    return value, idx + 4


def _read_uint32(payload: bytes, idx: int) -> tuple[int | None, int]:
    if idx + 4 > len(payload):
        return None, idx
    value = int.from_bytes(payload[idx:idx + 4], "little")
    return value, idx + 4


def _read_uint8(payload: bytes, idx: int) -> tuple[int | None, int]:
    if idx >= len(payload):
        return None, idx
    return payload[idx], idx + 1


def _read_uint16(payload: bytes, idx: int) -> tuple[int | None, int]:
    if idx + 2 > len(payload):
        return None, idx
    return int.from_bytes(payload[idx:idx + 2], "little"), idx + 2


def _read_double(payload: bytes, idx: int) -> tuple[float | None, int]:
    if idx + 8 > len(payload):
        return None, idx
    try:
        import struct
        value = struct.unpack("<d", payload[idx:idx + 8])[0]
    except Exception:
        value = None
    return value, idx + 8


def _read_string(payload: bytes, idx: int) -> tuple[str | None, int]:
    length, idx = _read_int32(payload, idx)
    if length is None:
        return None, idx
    if length == -1:
        return None, idx
    if length < 0 or idx + length > len(payload):
        return None, idx
    value = payload[idx:idx + length].decode("utf-8", errors="ignore")
    return value, idx + length


def _read_bytestring(payload: bytes, idx: int) -> tuple[bytes | None, int]:
    length, idx = _read_int32(payload, idx)
    if length is None:
        return None, idx
    if length == -1:
        return None, idx
    if length < 0 or idx + length > len(payload):
        return None, idx
    return payload[idx:idx + length], idx + length


def _skip_localized_text(payload: bytes, idx: int) -> int:
    mask, idx = _read_uint8(payload, idx)
    if mask is None:
        return idx
    if mask & 0x01:
        _, idx = _read_string(payload, idx)
    if mask & 0x02:
        _, idx = _read_string(payload, idx)
    return idx


def _skip_qualified_name(payload: bytes, idx: int) -> int:
    _, idx = _read_uint16(payload, idx)
    _, idx = _read_string(payload, idx)
    return idx


def _skip_diagnostic_info(payload: bytes, idx: int, depth: int = 0) -> int:
    if depth > 4:
        return idx
    mask, idx = _read_uint8(payload, idx)
    if mask is None:
        return idx
    if mask & 0x01:
        _, idx = _read_int32(payload, idx)
    if mask & 0x02:
        _, idx = _read_int32(payload, idx)
    if mask & 0x04:
        _, idx = _read_int32(payload, idx)
    if mask & 0x08:
        _, idx = _read_int32(payload, idx)
    if mask & 0x10:
        _, idx = _read_string(payload, idx)
    if mask & 0x20:
        _, idx = _read_uint32(payload, idx)
    if mask & 0x40:
        idx = _skip_diagnostic_info(payload, idx, depth + 1)
    return idx


def _skip_extension_object(payload: bytes, idx: int) -> int:
    node, idx = _parse_nodeid(payload, idx)
    if node is None:
        return idx
    if idx >= len(payload):
        return idx
    encoding = payload[idx]
    idx += 1
    if encoding == 0:
        return idx
    length, idx = _read_int32(payload, idx)
    if length is None or length < 0:
        return idx
    return min(len(payload), idx + length)


def _skip_request_header(payload: bytes, idx: int) -> int:
    node, idx = _parse_nodeid(payload, idx)
    _ = node
    if idx + 8 > len(payload):
        return idx
    idx += 8
    _, idx = _read_uint32(payload, idx)
    _, idx = _read_uint32(payload, idx)
    _, idx = _read_string(payload, idx)
    _, idx = _read_uint32(payload, idx)
    idx = _skip_extension_object(payload, idx)
    return idx


def _skip_response_header(payload: bytes, idx: int) -> tuple[int, int | None]:
    if idx + 8 > len(payload):
        return idx, None
    idx += 8  # timestamp
    _, idx = _read_uint32(payload, idx)
    service_result, idx = _read_uint32(payload, idx)
    idx = _skip_diagnostic_info(payload, idx)
    string_count, idx = _read_int32(payload, idx)
    if string_count is not None and string_count > 0:
        for _ in range(min(string_count, 32)):
            _, idx = _read_string(payload, idx)
    idx = _skip_extension_object(payload, idx)
    return idx, service_result


def _skip_variant(payload: bytes, idx: int) -> int:
    encoding, idx = _read_uint8(payload, idx)
    if encoding is None:
        return idx
    is_array = bool(encoding & 0x80)
    data_type = encoding & 0x3F
    if is_array:
        length, idx = _read_int32(payload, idx)
        if length is None or length < 0:
            return idx
        length = min(length, 64)
    else:
        length = 1

    def _skip_scalar(dtype: int, idx: int) -> int:
        if dtype in {1, 2, 3}:  # Boolean/SByte/Byte
            return min(len(payload), idx + 1)
        if dtype in {4, 5}:  # Int16/UInt16
            return min(len(payload), idx + 2)
        if dtype in {6, 7, 8, 9}:  # Int32/UInt32/Int64/UInt64
            return min(len(payload), idx + (4 if dtype in {6, 7} else 8))
        if dtype == 10:  # Float
            return min(len(payload), idx + 4)
        if dtype == 11:  # Double
            return min(len(payload), idx + 8)
        if dtype == 12:  # String
            _, idx = _read_string(payload, idx)
            return idx
        if dtype == 15:  # ByteString
            _, idx = _read_bytestring(payload, idx)
            return idx
        if dtype == 17:  # NodeId
            _, idx = _parse_nodeid(payload, idx)
            return idx
        if dtype == 20:  # QualifiedName
            return _skip_qualified_name(payload, idx)
        if dtype == 21:  # LocalizedText
            return _skip_localized_text(payload, idx)
        if dtype == 22:  # ExtensionObject
            return _skip_extension_object(payload, idx)
        return idx

    for _ in range(length):
        idx = _skip_scalar(data_type, idx)
        if idx >= len(payload):
            break
    return idx


def _decode_service_payload(payload: bytes, idx: int, service_name: str) -> list[tuple[str, str]]:
    artifacts: list[tuple[str, str]] = []
    if service_name.endswith("Request"):
        idx = _skip_request_header(payload, idx)
        if service_name == "ReadRequest":
            _, idx = _read_double(payload, idx)
            _, idx = _read_uint32(payload, idx)
            count, idx = _read_int32(payload, idx)
            if count is not None and count >= 0:
                artifacts.append(("opcua_read_count", str(count)))
            node, _ = _parse_nodeid(payload, idx)
            if node:
                artifacts.append(("opcua_read_node", f"ns={node[0]};i={node[1]}"))
        elif service_name == "WriteRequest":
            count, idx = _read_int32(payload, idx)
            if count is not None and count >= 0:
                artifacts.append(("opcua_write_count", str(count)))
            node, _ = _parse_nodeid(payload, idx)
            if node:
                artifacts.append(("opcua_write_node", f"ns={node[0]};i={node[1]}"))
        elif service_name == "CallRequest":
            count, idx = _read_int32(payload, idx)
            if count is not None and count >= 0:
                artifacts.append(("opcua_call_count", str(count)))
            node, idx = _parse_nodeid(payload, idx)
            if node:
                artifacts.append(("opcua_call_object", f"ns={node[0]};i={node[1]}"))
            node, _ = _parse_nodeid(payload, idx)
            if node:
                artifacts.append(("opcua_call_method", f"ns={node[0]};i={node[1]}"))
        elif service_name == "BrowseRequest":
            _, idx = _read_uint32(payload, idx)
            count, idx = _read_int32(payload, idx)
            if count is not None and count >= 0:
                artifacts.append(("opcua_browse_count", str(count)))
            node, _ = _parse_nodeid(payload, idx)
            if node:
                artifacts.append(("opcua_browse_node", f"ns={node[0]};i={node[1]}"))
        elif service_name == "CreateSessionRequest":
            app_uri, idx = _read_string(payload, idx)
            product_uri, idx = _read_string(payload, idx)
            idx = _skip_localized_text(payload, idx)
            _, idx = _read_uint32(payload, idx)
            _, idx = _read_string(payload, idx)
            _, idx = _read_string(payload, idx)
            url_count, idx = _read_int32(payload, idx)
            if url_count and url_count > 0:
                for _ in range(min(url_count, 4)):
                    _, idx = _read_string(payload, idx)
            server_uri, idx = _read_string(payload, idx)
            endpoint_url, idx = _read_string(payload, idx)
            session_name, idx = _read_string(payload, idx)
            if app_uri:
                artifacts.append(("opcua_app_uri", app_uri))
            if product_uri:
                artifacts.append(("opcua_product_uri", product_uri))
            if server_uri:
                artifacts.append(("opcua_server_uri", server_uri))
            if endpoint_url:
                artifacts.append(("opcua_endpoint", endpoint_url))
            if session_name:
                artifacts.append(("opcua_session_name", session_name))
    elif service_name.endswith("Response"):
        idx, service_result = _skip_response_header(payload, idx)
        if service_result is not None:
            artifacts.append(("opcua_service_result", f"0x{service_result:08x}"))
        if service_name == "ReadResponse":
            count, idx = _read_int32(payload, idx)
            if count is not None and count >= 0:
                artifacts.append(("opcua_read_results", str(count)))
            # Attempt to capture first status code if present
            if count and count > 0:
                _, status = _skip_data_value(payload, idx)
                if status is not None:
                    artifacts.append(("opcua_read_status", f"0x{status:08x}"))
        elif service_name == "WriteResponse":
            count, idx = _read_int32(payload, idx)
            if count is not None and count >= 0:
                artifacts.append(("opcua_write_results", str(count)))
            statuses: list[str] = []
            for _ in range(min(count or 0, 3)):
                status, idx = _read_uint32(payload, idx)
                if status is None:
                    break
                statuses.append(f"0x{status:08x}")
            if statuses:
                artifacts.append(("opcua_write_status", ", ".join(statuses)))
        elif service_name == "CallResponse":
            count, idx = _read_int32(payload, idx)
            if count is not None and count >= 0:
                artifacts.append(("opcua_call_results", str(count)))
            status, idx = _read_uint32(payload, idx)
            if status is not None:
                artifacts.append(("opcua_call_status", f"0x{status:08x}"))
        elif service_name == "BrowseResponse":
            count, idx = _read_int32(payload, idx)
            if count is not None and count >= 0:
                artifacts.append(("opcua_browse_results", str(count)))
            status, idx = _read_uint32(payload, idx)
            if status is not None:
                artifacts.append(("opcua_browse_status", f"0x{status:08x}"))
        elif service_name == "GetEndpointsResponse":
            count, idx = _read_int32(payload, idx)
            if count is not None and count >= 0:
                artifacts.append(("opcua_endpoints", str(count)))
        elif service_name == "FindServersResponse":
            count, idx = _read_int32(payload, idx)
            if count is not None and count >= 0:
                artifacts.append(("opcua_servers", str(count)))
        elif service_name == "CreateSessionResponse":
            node, idx = _parse_nodeid(payload, idx)
            if node:
                artifacts.append(("opcua_session_id", f"ns={node[0]};i={node[1]}"))
            node, idx = _parse_nodeid(payload, idx)
            if node:
                artifacts.append(("opcua_auth_token", f"ns={node[0]};i={node[1]}"))
            timeout, idx = _read_double(payload, idx)
            if timeout is not None:
                artifacts.append(("opcua_session_timeout", f"{timeout:.1f}"))
    return artifacts


def _skip_data_value(payload: bytes, idx: int) -> tuple[int, int | None]:
    mask, idx = _read_uint8(payload, idx)
    if mask is None:
        return idx, None
    status = None
    if mask & 0x01:
        idx = _skip_variant(payload, idx)
    if mask & 0x02:
        status, idx = _read_uint32(payload, idx)
    if mask & 0x04:
        idx += 8
    if mask & 0x08:
        idx += 2
    if mask & 0x10:
        idx += 8
    if mask & 0x20:
        idx += 2
    return idx, status


def _parse_hello(payload: bytes) -> Optional[str]:
    if len(payload) < 8 + 24:
        return None
    idx = 8 + 20
    if idx + 4 > len(payload):
        return None
    url_len = int.from_bytes(payload[idx:idx + 4], "little")
    idx += 4
    if idx + url_len > len(payload):
        return None
    url = payload[idx:idx + url_len].decode("utf-8", errors="ignore")
    return url.strip() if url else None


def _parse_opcua(payload: bytes) -> tuple[list[str], list[tuple[str, str]]]:
    commands: list[str] = []
    artifacts: list[tuple[str, str]] = []
    if len(payload) < 8:
        return commands, artifacts
    msg_type = payload[:3]
    name = OPC_TYPES.get(msg_type)
    if name:
        commands.append(name)
    chunk_type = payload[3:4].decode("ascii", errors="ignore")
    if chunk_type:
        commands.append(f"Chunk {chunk_type}")
    if msg_type in {b"HEL"}:
        url = _parse_hello(payload)
        if url:
            artifacts.append(("opcua_endpoint", url))
    if msg_type == b"MSG" and len(payload) >= 24:
        channel_id = int.from_bytes(payload[8:12], "little")
        token_id = int.from_bytes(payload[12:16], "little")
        seq = int.from_bytes(payload[16:20], "little")
        req_id = int.from_bytes(payload[20:24], "little")
        artifacts.append(("opcua_channel", str(channel_id)))
        artifacts.append(("opcua_token", str(token_id)))
        artifacts.append(("opcua_seq", str(seq)))
        artifacts.append(("opcua_request_id", str(req_id)))
        node, idx = _parse_nodeid(payload, 24)
        if node:
            ns, node_id = node
            service_name = OPC_UA_SERVICE_NAMES.get(node_id)
            label = f"ns={ns};i={node_id}"
            if service_name:
                commands.append(service_name)
                artifacts.append(("opcua_service", f"{service_name} ({label})"))
                for kind, detail in _decode_service_payload(payload, idx, service_name):
                    artifacts.append((kind, detail))
            else:
                commands.append(f"Service {label}")
                artifacts.append(("opcua_service", label))
    return commands, artifacts


def _parse_commands(payload: bytes) -> list[str]:
    cmds, _artifacts = _parse_opcua(payload)
    return cmds


def _parse_artifacts(payload: bytes) -> list[tuple[str, str]]:
    _cmds, artifacts = _parse_opcua(payload)
    return artifacts

def _detect_anomalies(payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    if any(cmd == "OpenSecureChannel" for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="LOW",
                title="OPC UA Secure Channel Open",
                description="OpenSecureChannel observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(cmd == "CloseSecureChannel" for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="LOW",
                title="OPC UA Secure Channel Close",
                description="CloseSecureChannel observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(cmd == "Error" for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="MEDIUM",
                title="OPC UA Error",
                description="OPC UA Error frame observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(cmd in {"WriteRequest", "CallRequest"} for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="OPC UA Write/Call Service",
                description="Write or Call service request observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(cmd in {"CreateSessionRequest", "ActivateSessionRequest"} for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="LOW",
                title="OPC UA Session Establishment",
                description="Session creation/activation observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    return anomalies


def analyze_opc(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="OPC UA",
        tcp_ports={OPC_UA_PORT},
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
                title="OPC UA Exposure to Public IP",
                description=f"OPC UA traffic observed with public endpoint(s): {', '.join(sorted(public_endpoints)[:5])}.",
                src="*",
                dst="*",
                ts=0.0,
            )
        )
    return analysis
