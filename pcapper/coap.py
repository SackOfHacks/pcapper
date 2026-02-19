from __future__ import annotations

from pathlib import Path
import ipaddress

from .industrial_helpers import IndustrialAnalysis, IndustrialAnomaly, analyze_port_protocol

COAP_PORTS = {5683, 5684}

METHODS = {
    1: "GET",
    2: "POST",
    3: "PUT",
    4: "DELETE",
}

TYPES = {
    0: "CON",
    1: "NON",
    2: "ACK",
    3: "RST",
}

COAP_OPTIONS = {
    6: "Observe",
    7: "Uri-Port",
    11: "Uri-Path",
    12: "Content-Format",
    14: "Max-Age",
    15: "Uri-Query",
    17: "Accept",
    23: "Block2",
    27: "Block1",
    28: "Size2",
    60: "Size1",
}


def _decode_option_value(opt_number: int, opt_value: bytes) -> str:
    if not opt_value:
        return ""
    if opt_number in {7, 11, 15}:
        return opt_value.decode("utf-8", errors="ignore")
    if opt_number in {6, 12, 14, 17, 23, 27, 28, 60}:
        return str(int.from_bytes(opt_value, "big"))
    return opt_value.hex()


def _parse_coap_options(payload: bytes) -> tuple[list[str], list[tuple[str, str]], dict[str, object]]:
    commands: list[str] = []
    artifacts: list[tuple[str, str]] = []
    info: dict[str, object] = {"uri": "", "observe": None}
    if len(payload) < 4:
        return commands, artifacts, info
    ver = payload[0] >> 6
    tkl = payload[0] & 0x0F
    if ver != 1:
        return commands, artifacts, info
    idx = 4 + tkl
    if idx > len(payload):
        return commands, artifacts, info

    current_opt = 0
    uri_paths: list[str] = []
    uri_queries: list[str] = []
    observe_val = None

    while idx < len(payload):
        if payload[idx] == 0xFF:
            break
        byte = payload[idx]
        idx += 1
        delta = (byte >> 4) & 0x0F
        length = byte & 0x0F
        if delta == 15 or length == 15:
            break
        if delta == 13:
            if idx >= len(payload):
                break
            delta = 13 + payload[idx]
            idx += 1
        elif delta == 14:
            if idx + 1 >= len(payload):
                break
            delta = 269 + int.from_bytes(payload[idx:idx + 2], "big")
            idx += 2
        if length == 13:
            if idx >= len(payload):
                break
            length = 13 + payload[idx]
            idx += 1
        elif length == 14:
            if idx + 1 >= len(payload):
                break
            length = 269 + int.from_bytes(payload[idx:idx + 2], "big")
            idx += 2
        if idx + length > len(payload):
            break
        current_opt += delta
        value = payload[idx:idx + length]
        idx += length
        decoded = _decode_option_value(current_opt, value)
        opt_name = COAP_OPTIONS.get(current_opt, f"Option {current_opt}")

        if current_opt == 11 and decoded:
            uri_paths.append(decoded)
        if current_opt == 15 and decoded:
            uri_queries.append(decoded)
        if current_opt == 6 and decoded:
            try:
                observe_val = int(decoded)
            except ValueError:
                observe_val = None

        commands.append(f"{opt_name}={decoded}")
        if current_opt in {11, 15} and decoded:
            artifacts.append(("coap_option", f"{opt_name}={decoded}"))

    uri = "/" + "/".join(uri_paths) if uri_paths else ""
    if uri_queries:
        uri = f"{uri}?{'&'.join(uri_queries)}" if uri else f"?{'&'.join(uri_queries)}"
    if uri:
        artifacts.append(("coap_uri", uri))
        commands.append(f"URI {uri}")
    if observe_val is not None:
        info["observe"] = observe_val
        artifacts.append(("coap_observe", str(observe_val)))
        if observe_val == 0:
            commands.append("Observe Register")
        elif observe_val == 1:
            commands.append("Observe Cancel")
        else:
            commands.append("Observe Notification")

    info["uri"] = uri
    return commands, artifacts, info


def _parse_commands(payload: bytes) -> list[str]:
    if len(payload) < 2:
        return []
    ver = payload[0] >> 6
    msg_type = (payload[0] >> 4) & 0x03
    code = payload[1]
    if ver != 1:
        return []
    prefix = TYPES.get(msg_type, "UNK")
    if code in METHODS:
        commands = [f"{prefix} REQ {METHODS[code]}"]
        opt_cmds, _artifacts, _info = _parse_coap_options(payload)
        commands.extend(opt_cmds)
        return commands
    if code >= 64:
        commands = [f"{prefix} RESP {code//32}.{code%32:02d}"]
        opt_cmds, _artifacts, _info = _parse_coap_options(payload)
        commands.extend(opt_cmds)
        return commands
    return []


def _parse_artifacts(payload: bytes) -> list[tuple[str, str]]:
    if len(payload) < 4:
        return []
    opt_cmds, artifacts, _info = _parse_coap_options(payload)
    _ = opt_cmds
    return artifacts

def _detect_anomalies(payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    if any(cmd.endswith("REQ PUT") or cmd.endswith("REQ POST") or cmd.endswith("REQ DELETE") for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="MEDIUM",
                title="CoAP Write/Control Operation",
                description="CoAP modification request observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(cmd.startswith("RST") for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="LOW",
                title="CoAP Reset",
                description="CoAP reset (RST) message observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(cmd == "Observe Register" for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="LOW",
                title="CoAP Observe Registration",
                description="Observe registration request observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    if any(cmd == "Observe Cancel" for cmd in commands):
        anomalies.append(
            IndustrialAnomaly(
                severity="LOW",
                title="CoAP Observe Cancel",
                description="Observe cancellation request observed.",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
            )
        )
    return anomalies


def analyze_coap(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="CoAP",
        udp_ports=COAP_PORTS,
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
                title="CoAP Exposure to Public IP",
                description=f"CoAP traffic observed with public endpoint(s): {', '.join(sorted(public_endpoints)[:5])}.",
                src="*",
                dst="*",
                ts=0.0,
            )
        )
    return analysis
