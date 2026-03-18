from __future__ import annotations

from collections import Counter, defaultdict
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

BVLC_RESULT_CODES = {
    0x0000: "Successful-Completion",
    0x0010: "Write-BDT-NAK",
    0x0020: "Read-BDT-NAK",
    0x0030: "Register-FD-NAK",
    0x0040: "Read-FDT-NAK",
    0x0050: "Delete-FDT-NAK",
    0x0060: "Distribute-Broadcast-NAK",
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
    0x00: "AcknowledgeAlarm",
    0x01: "ConfirmedCOVNotification",
    0x02: "ConfirmedEventNotification",
    0x03: "GetAlarmSummary",
    0x04: "GetEnrollmentSummary",
    0x05: "SubscribeCOV",
    0x06: "AtomicReadFile",
    0x07: "AtomicWriteFile",
    0x08: "AddListElement",
    0x09: "RemoveListElement",
    0x0A: "CreateObject",
    0x0B: "DeleteObject",
    0x0C: "ReadProperty",
    0x0D: "ReadPropertyConditional",
    0x0E: "ReadPropertyMultiple",
    0x0F: "WriteProperty",
    0x10: "WritePropertyMultiple",
    0x11: "DeviceCommunicationControl",
    0x12: "ConfirmedPrivateTransfer",
    0x13: "ConfirmedTextMessage",
    0x14: "ReinitializeDevice",
    0x15: "VT-Open",
    0x16: "VT-Close",
    0x17: "VT-Data",
    0x18: "Authenticate",
    0x19: "RequestKey",
    0x1A: "ReadRange",
    0x1B: "LifeSafetyOperation",
    0x1C: "SubscribeCOVProperty",
    0x1D: "GetEventInformation",
    0x1E: "SubscribeCOVPropertyMultiple",
}

UNCONFIRMED_SERVICE_CHOICES = {
    0x00: "I-Am",
    0x01: "I-Have",
    0x02: "UnconfirmedCOVNotification",
    0x03: "UnconfirmedEventNotification",
    0x04: "UnconfirmedPrivateTransfer",
    0x05: "UnconfirmedTextMessage",
    0x06: "TimeSynchronization",
    0x07: "Who-Has",
    0x08: "Who-Is",
    0x09: "UTC-TimeSynchronization",
    0x0A: "WriteGroup",
}

NPDU_NETWORK_MESSAGES = {
    0x00: "Who-Is-Router-To-Network",
    0x01: "I-Am-Router-To-Network",
    0x02: "I-Could-Be-Router-To-Network",
    0x03: "Reject-Message-To-Network",
    0x04: "Router-Busy-To-Network",
    0x05: "Router-Available-To-Network",
    0x06: "Initialize-Routing-Table",
    0x07: "Initialize-Routing-Table-Ack",
    0x08: "Establish-Connection-To-Network",
    0x09: "Disconnect-Connection-To-Network",
    0x0A: "Challenge-Request",
    0x0B: "Security-Payload",
    0x0C: "Security-Response",
    0x0D: "Request-Key-Update",
    0x0E: "Update-Key-Set",
    0x0F: "Update-Distribution-Key",
    0x10: "Request-Master-Key",
    0x11: "Set-Master-Key",
    0x12: "What-Is-Network-Number",
    0x13: "Network-Number-Is",
}

REJECT_REASONS = {
    0x00: "Other",
    0x01: "BufferOverflow",
    0x02: "InconsistentParameters",
    0x03: "InvalidParameterDataType",
    0x04: "InvalidTag",
    0x05: "MissingRequiredParameter",
    0x06: "ParameterOutOfRange",
    0x07: "TooManyArguments",
    0x08: "UndefinedEnumeration",
    0x09: "UnrecognizedService",
}

ABORT_REASONS = {
    0x00: "Other",
    0x01: "BufferOverflow",
    0x02: "InvalidAPDUInThisState",
    0x03: "PreemptedByHigherPriorityTask",
    0x04: "SegmentationNotSupported",
    0x05: "SecurityError",
    0x06: "InsufficientSecurity",
    0x07: "WindowSizeOutOfRange",
    0x08: "ApplicationExceededReplyTime",
    0x09: "OutOfResources",
    0x0A: "TSMTimeout",
    0x0B: "APDUTooLong",
}

BACNET_OBJECT_TYPES = {
    0: "analog-input",
    1: "analog-output",
    2: "analog-value",
    3: "binary-input",
    4: "binary-output",
    5: "binary-value",
    8: "device",
    13: "multi-state-input",
    14: "multi-state-output",
    19: "multi-state-value",
    20: "notification-class",
    28: "loop",
    31: "program",
    56: "network-port",
}

BACNET_PROPERTY_IDS = {
    28: "Description",
    44: "Feedback_Value",
    75: "Object_Identifier",
    76: "Object_List",
    77: "Object_Name",
    79: "Object_Type",
    85: "Present_Value",
    87: "Priority_Array",
    88: "Priority_For_Writing",
    104: "Relinquish_Default",
    111: "Status_Flags",
    112: "System_Status",
    117: "Units",
    121: "Vendor_Name",
    122: "Vendor_Identifier",
}

CONTROL_SERVICES = {
    "WriteProperty",
    "WritePropertyMultiple",
    "CreateObject",
    "DeleteObject",
    "DeviceCommunicationControl",
    "ReinitializeDevice",
    "AtomicWriteFile",
    "LifeSafetyOperation",
    "WriteGroup",
}

DISCOVERY_SERVICES = {
    "Who-Is",
    "Who-Has",
    "I-Am",
    "I-Have",
    "ReadProperty",
    "ReadPropertyMultiple",
    "Read-Broadcast-Distribution-Table",
    "Read-Foreign-Device-Table",
    "Who-Is-Router-To-Network",
}

HIGH_RISK_NETWORK_MESSAGES = {
    "Initialize-Routing-Table",
    "Establish-Connection-To-Network",
    "Disconnect-Connection-To-Network",
    "Set-Master-Key",
    "Update-Key-Set",
    "Update-Distribution-Key",
}


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except Exception:
        return False


def _parse_context_tag(data: bytes, idx: int) -> tuple[dict[str, object] | None, int]:
    if idx >= len(data):
        return None, idx

    first = data[idx]
    idx += 1
    tag_number = (first >> 4) & 0x0F
    tag_class = (first >> 3) & 0x01
    lvt = first & 0x07

    if tag_number == 0x0F:
        if idx >= len(data):
            return None, len(data)
        tag_number = data[idx]
        idx += 1

    if tag_class == 1 and lvt in {6, 7}:
        return {
            "tag_number": tag_number,
            "tag_class": tag_class,
            "opening": lvt == 6,
            "closing": lvt == 7,
            "value": b"",
        }, idx

    if lvt <= 4:
        length = lvt
    elif lvt == 5:
        if idx >= len(data):
            return None, len(data)
        ext = data[idx]
        idx += 1
        if ext == 254:
            if idx + 2 > len(data):
                return None, len(data)
            length = int.from_bytes(data[idx:idx + 2], "big")
            idx += 2
        elif ext == 255:
            if idx + 4 > len(data):
                return None, len(data)
            length = int.from_bytes(data[idx:idx + 4], "big")
            idx += 4
        else:
            length = ext
    else:
        # For application tags, 6/7 are normal lengths.
        length = lvt

    if idx + length > len(data):
        return None, len(data)
    value = data[idx:idx + length]
    idx += length
    return {
        "tag_number": tag_number,
        "tag_class": tag_class,
        "opening": False,
        "closing": False,
        "value": value,
    }, idx


def _context_primitive_value(data: bytes, tag_number: int, max_tags: int = 24) -> bytes | None:
    idx = 0
    seen = 0
    while idx < len(data) and seen < max_tags:
        parsed, next_idx = _parse_context_tag(data, idx)
        if parsed is None or next_idx <= idx:
            break
        idx = next_idx
        seen += 1
        if int(parsed.get("tag_class", -1)) != 1:
            continue
        if bool(parsed.get("opening")) or bool(parsed.get("closing")):
            continue
        if int(parsed.get("tag_number", -1)) != tag_number:
            continue
        value = parsed.get("value")
        if isinstance(value, bytes):
            return value
    return None


def _context_unsigned(data: bytes, tag_number: int) -> int | None:
    raw = _context_primitive_value(data, tag_number)
    if raw is None or not raw or len(raw) > 8:
        return None
    return int.from_bytes(raw, "big")


def _decode_object_identifier(raw: bytes) -> tuple[int | None, str | None, int | None]:
    if len(raw) != 4:
        return None, None, None
    oid = int.from_bytes(raw, "big")
    obj_type_code = (oid >> 22) & 0x03FF
    instance = oid & 0x3FFFFF
    obj_name = BACNET_OBJECT_TYPES.get(obj_type_code, f"object-{obj_type_code}")
    return obj_type_code, obj_name, instance


def _format_target(info: dict[str, object]) -> str:
    obj_name = str(info.get("object_type_name") or "")
    obj_instance = info.get("object_instance")
    prop_name = str(info.get("property_name") or "")
    prop_id = info.get("property_id")

    parts: list[str] = []
    if obj_name and isinstance(obj_instance, int):
        parts.append(f"object={obj_name}:{obj_instance}")
    if prop_name and isinstance(prop_id, int):
        parts.append(f"property={prop_name}({prop_id})")
    elif isinstance(prop_id, int):
        parts.append(f"property={prop_id}")
    return " ".join(parts)


def _parse_bacnet_payload(payload: bytes) -> dict[str, object]:
    info: dict[str, object] = {
        "valid": False,
        "issues": [],
        "bvlc_type": None,
        "bvlc_function": None,
        "bvlc_name": "",
        "bvlc_length": 0,
        "bvlc_result_code": None,
        "bvlc_result_name": "",
        "foreign_ttl": None,
        "forwarded_from": None,
        "forwarded_ip": None,
        "forwarded_port": None,
        "delete_fdt_target": None,
        "bdt_entries": [],
        "npdu_control": None,
        "npdu_expect_reply": False,
        "npdu_network_message": False,
        "npdu_message_type": None,
        "npdu_message_name": "",
        "dnet": None,
        "snet": None,
        "apdu_type": None,
        "apdu_name": "",
        "invoke_id": None,
        "service_choice": None,
        "service_name": "",
        "reject_reason": None,
        "abort_reason": None,
        "object_type_code": None,
        "object_type_name": None,
        "object_instance": None,
        "property_id": None,
        "property_name": None,
        "who_is_low_limit": None,
        "who_is_high_limit": None,
    }
    issues: list[str] = info["issues"]  # type: ignore[assignment]

    if len(payload) < 4:
        issues.append("BACnet payload shorter than BVLC header.")
        return info
    if payload[0] != 0x81:
        issues.append(f"Unexpected BVLC type 0x{payload[0]:02x}.")
        return info

    info["valid"] = True
    bvlc_func = payload[1]
    bvlc_len = int.from_bytes(payload[2:4], "big")
    info["bvlc_type"] = payload[0]
    info["bvlc_function"] = bvlc_func
    info["bvlc_name"] = BVLC_FUNCTIONS.get(bvlc_func, f"BVLC Func 0x{bvlc_func:02x}")
    info["bvlc_length"] = bvlc_len

    if bvlc_len < 4:
        issues.append(f"Invalid BVLC length {bvlc_len}.")
    if bvlc_len != len(payload):
        issues.append(f"BVLC length {bvlc_len} does not match UDP payload length {len(payload)}.")
    body_end = min(len(payload), bvlc_len) if bvlc_len >= 4 else len(payload)
    body = payload[4:body_end]

    if bvlc_func == 0x00 and len(body) >= 2:
        result_code = int.from_bytes(body[:2], "big")
        info["bvlc_result_code"] = result_code
        info["bvlc_result_name"] = BVLC_RESULT_CODES.get(result_code, f"Result-0x{result_code:04x}")
    elif bvlc_func == 0x05 and len(body) >= 2:
        info["foreign_ttl"] = int.from_bytes(body[:2], "big")
    elif bvlc_func == 0x07 and len(body) >= 6:
        target_ip = ".".join(str(part) for part in body[:4])
        target_port = int.from_bytes(body[4:6], "big")
        info["delete_fdt_target"] = f"{target_ip}:{target_port}"
    elif bvlc_func in {0x01, 0x03} and body:
        entries: list[str] = []
        for idx in range(0, len(body), 10):
            if idx + 10 > len(body):
                break
            ip_raw = body[idx:idx + 4]
            port = int.from_bytes(body[idx + 4:idx + 6], "big")
            mask_raw = body[idx + 6:idx + 10]
            ip_text = ".".join(str(part) for part in ip_raw)
            mask_text = ".".join(str(part) for part in mask_raw)
            entries.append(f"{ip_text}:{port} mask={mask_text}")
        if len(body) % 10 != 0:
            issues.append("BDT payload has trailing bytes not aligned to 10-byte entries.")
        info["bdt_entries"] = entries

    npdu_start = 4
    if bvlc_func == 0x04:
        if len(payload) < 10:
            issues.append("Forwarded-NPDU is missing 6-byte origin address.")
            return info
        origin_ip = ".".join(str(part) for part in payload[4:8])
        origin_port = int.from_bytes(payload[8:10], "big")
        info["forwarded_from"] = f"{origin_ip}:{origin_port}"
        info["forwarded_ip"] = origin_ip
        info["forwarded_port"] = origin_port
        npdu_start = 10

    if bvlc_func not in {0x04, 0x08, 0x09, 0x0A}:
        return info

    if npdu_start + 2 > len(payload):
        issues.append("Truncated NPDU header.")
        return info
    npdu_version = payload[npdu_start]
    if npdu_version != 0x01:
        issues.append(f"Unexpected NPDU version 0x{npdu_version:02x}.")
        return info

    idx = npdu_start + 1
    npdu_control = payload[idx]
    idx += 1
    info["npdu_control"] = npdu_control
    info["npdu_expect_reply"] = bool(npdu_control & 0x04)
    info["npdu_network_message"] = bool(npdu_control & 0x80)

    if npdu_control & 0x20:
        if idx + 3 > len(payload):
            issues.append("Truncated NPDU destination specifier.")
            return info
        dnet = int.from_bytes(payload[idx:idx + 2], "big")
        dlen = payload[idx + 2]
        idx += 3
        info["dnet"] = dnet
        if idx + dlen > len(payload):
            issues.append("Truncated NPDU destination address.")
            return info
        idx += dlen
        if idx >= len(payload):
            issues.append("Truncated NPDU hop-count.")
            return info
        idx += 1

    if npdu_control & 0x08:
        if idx + 3 > len(payload):
            issues.append("Truncated NPDU source specifier.")
            return info
        snet = int.from_bytes(payload[idx:idx + 2], "big")
        slen = payload[idx + 2]
        idx += 3
        info["snet"] = snet
        if idx + slen > len(payload):
            issues.append("Truncated NPDU source address.")
            return info
        idx += slen

    if npdu_control & 0x80:
        if idx >= len(payload):
            issues.append("Truncated NPDU network message type.")
            return info
        msg_type = payload[idx]
        info["npdu_message_type"] = msg_type
        info["npdu_message_name"] = NPDU_NETWORK_MESSAGES.get(msg_type, f"NPDU-Message-0x{msg_type:02x}")
        return info

    if idx >= len(payload):
        return info

    apdu = payload[idx:]
    pdu_type = (apdu[0] >> 4) & 0x0F
    info["apdu_type"] = pdu_type
    info["apdu_name"] = APDU_TYPES.get(pdu_type, f"APDU {pdu_type}")

    service_choice = None
    service_data = b""
    if pdu_type == 0x00:
        segmented = bool(apdu[0] & 0x08)
        if len(apdu) >= 3:
            info["invoke_id"] = apdu[2]
        offset = 5 if segmented else 3
        if offset < len(apdu):
            service_choice = apdu[offset]
            info["service_name"] = CONFIRMED_SERVICE_CHOICES.get(service_choice, f"Confirmed Service 0x{service_choice:02x}")
            service_data = apdu[offset + 1:]
    elif pdu_type == 0x01:
        if len(apdu) >= 2:
            service_choice = apdu[1]
            info["service_name"] = UNCONFIRMED_SERVICE_CHOICES.get(service_choice, f"Unconfirmed Service 0x{service_choice:02x}")
            service_data = apdu[2:]
    elif pdu_type == 0x02:
        if len(apdu) >= 2:
            info["invoke_id"] = apdu[1]
        if len(apdu) >= 3:
            service_choice = apdu[2]
            info["service_name"] = CONFIRMED_SERVICE_CHOICES.get(service_choice, f"Confirmed Service 0x{service_choice:02x}")
            service_data = apdu[3:]
    elif pdu_type == 0x03:
        segmented = bool(apdu[0] & 0x08)
        if len(apdu) >= 2:
            info["invoke_id"] = apdu[1]
        offset = 5 if segmented else 3
        if offset < len(apdu):
            service_choice = apdu[offset]
            info["service_name"] = CONFIRMED_SERVICE_CHOICES.get(service_choice, f"Confirmed Service 0x{service_choice:02x}")
            service_data = apdu[offset + 1:]
    elif pdu_type == 0x05:
        if len(apdu) >= 2:
            info["invoke_id"] = apdu[1]
        if len(apdu) >= 3:
            service_choice = apdu[2]
            info["service_name"] = CONFIRMED_SERVICE_CHOICES.get(service_choice, f"Confirmed Service 0x{service_choice:02x}")
            service_data = apdu[3:]
    elif pdu_type == 0x06:
        if len(apdu) >= 2:
            info["invoke_id"] = apdu[1]
        if len(apdu) >= 3:
            reason = apdu[2]
            info["reject_reason"] = REJECT_REASONS.get(reason, f"Reason-0x{reason:02x}")
    elif pdu_type == 0x07:
        if len(apdu) >= 2:
            info["invoke_id"] = apdu[1]
        if len(apdu) >= 3:
            reason = apdu[2]
            info["abort_reason"] = ABORT_REASONS.get(reason, f"Reason-0x{reason:02x}")

    info["service_choice"] = service_choice

    if isinstance(service_choice, int) and service_data:
        if service_choice in {0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x1A}:
            object_raw = _context_primitive_value(service_data, 0)
            if isinstance(object_raw, bytes):
                type_code, type_name, instance = _decode_object_identifier(object_raw)
                info["object_type_code"] = type_code
                info["object_type_name"] = type_name
                info["object_instance"] = instance
            property_id = _context_unsigned(service_data, 1)
            if isinstance(property_id, int):
                info["property_id"] = property_id
                info["property_name"] = BACNET_PROPERTY_IDS.get(property_id, f"Property-{property_id}")
        elif service_choice == 0x08:
            info["who_is_low_limit"] = _context_unsigned(service_data, 0)
            info["who_is_high_limit"] = _context_unsigned(service_data, 1)

    return info


def _parse_commands(payload: bytes) -> list[str]:
    info = _parse_bacnet_payload(payload)
    if not info.get("valid"):
        return []

    commands: list[str] = ["BVLC"]
    bvlc_name = str(info.get("bvlc_name") or "")
    if bvlc_name:
        commands.append(bvlc_name)
    npdu_msg = str(info.get("npdu_message_name") or "")
    if npdu_msg:
        commands.append(npdu_msg)
    apdu_name = str(info.get("apdu_name") or "")
    if apdu_name:
        commands.append(f"APDU {apdu_name}")
    service_name = str(info.get("service_name") or "")
    if service_name:
        commands.append(service_name)
    reject_reason = str(info.get("reject_reason") or "")
    if reject_reason:
        commands.append(f"Reject {reject_reason}")
    abort_reason = str(info.get("abort_reason") or "")
    if abort_reason:
        commands.append(f"Abort {abort_reason}")
    if info.get("issues"):
        commands.append("Malformed BACnet Frame")
    return list(dict.fromkeys(commands))


def _parse_artifacts(payload: bytes) -> list[tuple[str, str]]:
    info = _parse_bacnet_payload(payload)
    if not info.get("valid"):
        return []

    artifacts: list[tuple[str, str]] = []
    bvlc_name = str(info.get("bvlc_name") or "")
    if bvlc_name:
        artifacts.append(("bacnet_bvlc", f"{bvlc_name} len={info.get('bvlc_length', 0)}"))

    result_name = str(info.get("bvlc_result_name") or "")
    result_code = info.get("bvlc_result_code")
    if result_name and isinstance(result_code, int):
        artifacts.append(("bacnet_bvlc_result", f"{result_name} (0x{result_code:04x})"))

    ttl = info.get("foreign_ttl")
    if isinstance(ttl, int):
        artifacts.append(("bacnet_foreign_device_ttl", f"{ttl}s"))

    delete_fdt_target = str(info.get("delete_fdt_target") or "")
    if delete_fdt_target:
        artifacts.append(("bacnet_fdt_target", delete_fdt_target))

    for entry in (info.get("bdt_entries") or [])[:4]:
        artifacts.append(("bacnet_bdt_entry", str(entry)))

    forwarded_from = str(info.get("forwarded_from") or "")
    if forwarded_from:
        artifacts.append(("bacnet_forwarded_origin", forwarded_from))

    npdu_msg = str(info.get("npdu_message_name") or "")
    if npdu_msg:
        artifacts.append(("bacnet_network_message", npdu_msg))

    service_name = str(info.get("service_name") or "")
    if service_name:
        if service_name in CONTROL_SERVICES:
            kind = "bacnet_control_service"
        elif service_name in DISCOVERY_SERVICES:
            kind = "bacnet_discovery"
        else:
            kind = "bacnet_service"
        artifacts.append((kind, service_name))

        target = _format_target(info)
        if target:
            artifacts.append(("bacnet_target", f"{service_name} {target}"))

    who_is_low = info.get("who_is_low_limit")
    who_is_high = info.get("who_is_high_limit")
    if isinstance(who_is_low, int) and isinstance(who_is_high, int):
        artifacts.append(("bacnet_discovery_scope", f"Who-Is range {who_is_low}-{who_is_high}"))

    for issue in (info.get("issues") or [])[:3]:
        artifacts.append(("bacnet_parser_issue", str(issue)))
    return artifacts


def _detect_anomalies(payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    info = _parse_bacnet_payload(payload)
    command_set = set(commands)

    target_suffix = _format_target(info)
    if target_suffix:
        target_suffix = f" Target: {target_suffix}."

    if "Write-Broadcast-Distribution-Table" in command_set:
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="BACnet Broadcast Table Write",
                description="Broadcast Distribution Table write observed; this can alter BBMD routing and aid lateral movement.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if "Register-Foreign-Device" in command_set:
        ttl = info.get("foreign_ttl")
        ttl_text = f" TTL={ttl}s." if isinstance(ttl, int) else ""
        severity = "HIGH" if isinstance(ttl, int) and ttl >= 21600 else "MEDIUM"
        anomalies.append(
            IndustrialAnomaly(
                severity=severity,
                title="BACnet Foreign Device Registration",
                description=f"Foreign device registration observed.{ttl_text}",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if "Read-Foreign-Device-Table" in command_set:
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
    if "Delete-Foreign-Device-Table" in command_set:
        target = str(info.get("delete_fdt_target") or "")
        target_text = f" Target={target}." if target else ""
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="BACnet Foreign Device Table Modification",
                description=f"Foreign device table deletion observed.{target_text}",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if "Distribute-Broadcast-To-Network" in command_set:
        anomalies.append(
            IndustrialAnomaly(
                severity="MEDIUM",
                title="BACnet Broadcast Distribution",
                description="Broadcast distribution to network observed; can be abused for traffic fan-out.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if "WriteProperty" in command_set:
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="BACnet WriteProperty",
                description=f"WriteProperty service request observed.{target_suffix}",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if "WritePropertyMultiple" in command_set:
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="BACnet WritePropertyMultiple",
                description=f"WritePropertyMultiple service request observed.{target_suffix}",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if "DeviceCommunicationControl" in command_set:
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="BACnet Device Communication Control",
                description="DeviceCommunicationControl service request observed; can disable communications.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if "ReinitializeDevice" in command_set:
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
    if "CreateObject" in command_set or "DeleteObject" in command_set:
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="BACnet Object Lifecycle Change",
                description="CreateObject/DeleteObject service request observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if "AtomicWriteFile" in command_set:
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="BACnet File Write Operation",
                description="AtomicWriteFile request observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if "LifeSafetyOperation" in command_set:
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="BACnet Life Safety Operation",
                description="LifeSafetyOperation request observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if "ConfirmedPrivateTransfer" in command_set or "UnconfirmedPrivateTransfer" in command_set:
        anomalies.append(
            IndustrialAnomaly(
                severity="MEDIUM",
                title="BACnet Private Transfer",
                description="Vendor-specific private transfer observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )

    npdu_msg = str(info.get("npdu_message_name") or "")
    if npdu_msg in HIGH_RISK_NETWORK_MESSAGES:
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="BACnet Routing/Security Control Message",
                description=f"NPDU network message observed: {npdu_msg}.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    elif npdu_msg == "Who-Is-Router-To-Network":
        anomalies.append(
            IndustrialAnomaly(
                severity="LOW",
                title="BACnet Router Discovery",
                description="Who-Is-Router-To-Network message observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )

    forwarded_ip = str(info.get("forwarded_ip") or "")
    forwarded_from = str(info.get("forwarded_from") or "")
    if forwarded_from:
        if forwarded_ip and _is_public_ip(forwarded_ip):
            anomalies.append(
                IndustrialAnomaly(
                    severity="HIGH",
                    title="BACnet Forwarded NPDU from Public Origin",
                    description=f"Forwarded-NPDU origin is public ({forwarded_from}).",
                    src=src_ip,
                    dst=dst_ip,
                    ts=ts,
                )
            )
        else:
            anomalies.append(
                IndustrialAnomaly(
                    severity="LOW",
                    title="BACnet Forwarded NPDU",
                    description=f"Forwarded-NPDU observed with origin {forwarded_from}.",
                    src=src_ip,
                    dst=dst_ip,
                    ts=ts,
                )
            )

    who_is_low = info.get("who_is_low_limit")
    who_is_high = info.get("who_is_high_limit")
    if "Who-Is" in command_set and isinstance(who_is_low, int) and isinstance(who_is_high, int):
        if who_is_low == 0 and who_is_high >= 4_194_303:
            anomalies.append(
                IndustrialAnomaly(
                    severity="MEDIUM",
                    title="BACnet Global Who-Is Discovery",
                    description=f"Who-Is query spans full device range ({who_is_low}-{who_is_high}).",
                    src=src_ip,
                    dst=dst_ip,
                    ts=ts,
                )
            )

    issues = [str(item) for item in (info.get("issues") or [])]
    if issues:
        anomalies.append(
            IndustrialAnomaly(
                severity="LOW",
                title="BACnet Malformed Frame",
                description=issues[0],
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    return anomalies


def _split_endpoint_pair(value: str) -> tuple[str, str] | None:
    if " -> " not in value:
        return None
    src, dst = value.split(" -> ", 1)
    src = src.strip()
    dst = dst.strip()
    if not src or not dst:
        return None
    return src, dst


def _append_behavioral_anomalies(analysis: IndustrialAnalysis) -> None:
    max_anomalies = 200
    if len(analysis.anomalies) >= max_anomalies:
        return

    endpoint_map = getattr(analysis, "service_endpoints", {}) or {}
    commands = getattr(analysis, "commands", Counter()) or Counter()

    who_is_src_to_dst: dict[str, set[str]] = defaultdict(set)
    for endpoint in endpoint_map.get("Who-Is", Counter()):
        pair = _split_endpoint_pair(str(endpoint))
        if pair:
            who_is_src_to_dst[pair[0]].add(pair[1])

    for src, dsts in who_is_src_to_dst.items():
        if len(dsts) >= 15 and len(analysis.anomalies) < max_anomalies:
            analysis.anomalies.append(
                IndustrialAnomaly(
                    severity="MEDIUM",
                    title="BACnet Discovery Sweep",
                    description=f"Source issued Who-Is queries to {len(dsts)} distinct endpoints.",
                    src=src,
                    dst="*",
                    ts=0.0,
                )
            )

    read_src_to_dst: dict[str, set[str]] = defaultdict(set)
    for command_name in ("ReadProperty", "ReadPropertyMultiple", "Read-Broadcast-Distribution-Table", "Read-Foreign-Device-Table"):
        for endpoint, count in endpoint_map.get(command_name, Counter()).items():
            pair = _split_endpoint_pair(str(endpoint))
            if pair and count:
                read_src_to_dst[pair[0]].add(pair[1])
    for src, dsts in read_src_to_dst.items():
        if len(dsts) >= 12 and len(analysis.anomalies) < max_anomalies:
            analysis.anomalies.append(
                IndustrialAnomaly(
                    severity="MEDIUM",
                    title="BACnet Property/Topology Enumeration",
                    description=f"Source queried {len(dsts)} BACnet endpoints for discovery/read operations.",
                    src=src,
                    dst="*",
                    ts=0.0,
                )
            )

    control_counts: Counter[str] = Counter()
    control_dsts: dict[str, set[str]] = defaultdict(set)
    for command_name in CONTROL_SERVICES:
        for endpoint, count in endpoint_map.get(command_name, Counter()).items():
            pair = _split_endpoint_pair(str(endpoint))
            if not pair or not count:
                continue
            src, dst = pair
            control_counts[src] += int(count)
            control_dsts[src].add(dst)
    for src, total in control_counts.items():
        if total >= 20 and len(control_dsts[src]) >= 4 and len(analysis.anomalies) < max_anomalies:
            analysis.anomalies.append(
                IndustrialAnomaly(
                    severity="HIGH",
                    title="BACnet Multi-Target Control Burst",
                    description=f"Source issued {total} control/write operations across {len(control_dsts[src])} endpoints.",
                    src=src,
                    dst="*",
                    ts=0.0,
                )
            )
        if src in who_is_src_to_dst and total >= 5 and len(control_dsts[src]) >= 2 and len(analysis.anomalies) < max_anomalies:
            analysis.anomalies.append(
                IndustrialAnomaly(
                    severity="HIGH",
                    title="BACnet Discovery Followed by Control",
                    description=f"Source performed discovery and then sent {total} control/write operations.",
                    src=src,
                    dst="*",
                    ts=0.0,
                )
            )

    bvlc_admin_ops = int(commands.get("Write-Broadcast-Distribution-Table", 0)) + int(commands.get("Delete-Foreign-Device-Table", 0))
    if bvlc_admin_ops >= 3 and len(analysis.anomalies) < max_anomalies:
        analysis.anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="BACnet Repeated BBMD/FDT Administration",
                description=f"Observed {bvlc_admin_ops} BBMD/FDT administrative change operations.",
                src="*",
                dst="*",
                ts=0.0,
            )
        )

    apdu_total = sum(int(count) for cmd, count in commands.items() if str(cmd).startswith("APDU "))
    error_total = int(commands.get("APDU Error", 0)) + int(commands.get("APDU Reject", 0)) + int(commands.get("APDU Abort", 0))
    if apdu_total >= 20 and error_total >= 6 and error_total / max(apdu_total, 1) >= 0.25 and len(analysis.anomalies) < max_anomalies:
        analysis.anomalies.append(
            IndustrialAnomaly(
                severity="MEDIUM",
                title="BACnet High APDU Failure Rate",
                description=f"APDU error/reject/abort ratio is {error_total}/{apdu_total}.",
                src="*",
                dst="*",
                ts=0.0,
            )
        )


def analyze_bacnet(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="BACnet",
        tcp_ports={BACNET_PORT},
        udp_ports={BACNET_PORT},
        command_parser=_parse_commands,
        artifact_parser=_parse_artifacts,
        anomaly_detector=_detect_anomalies,
        enable_enrichment=True,
        show_status=show_status,
    )
    _append_behavioral_anomalies(analysis)

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
