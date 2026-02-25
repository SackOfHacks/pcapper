from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from collections import Counter, defaultdict
import json
import struct

from .bacnet import analyze_bacnet, BACNET_PORT, _parse_commands as _parse_bacnet_commands
from .cip import (
    analyze_cip,
    CIP_TCP_PORT,
    CIP_UDP_PORT,
    CIP_SECURITY_PORT,
    _parse_enip,
    _parse_cip_message,
)
from .coap import analyze_coap, COAP_PORTS, _parse_commands as _parse_coap_commands
from .df1 import analyze_df1
from .dnp3 import (
    analyze_dnp3,
    DNP3_PORT,
    FUNC_CODES as DNP3_FUNC_CODES,
    CONTROL_FUNCTIONS,
    FREEZE_FUNCTIONS,
    RESTART_FUNCTIONS,
    APP_CONTROL_FUNCTIONS,
    FILE_FUNCTIONS,
    TIME_FUNCTIONS,
)
from .ethercat import analyze_ethercat, WRITE_COMMANDS as ETHERCAT_WRITE_COMMANDS
from .fins import analyze_fins, FINS_PORT, _parse_commands as _parse_fins_commands
from .iec104 import analyze_iec104, IEC104_PORT, ASDU_TYPES, _parse_commands as _parse_iec104_commands
from .industrial_helpers import _extract_transport
from .melsec import analyze_melsec, MELSEC_TCP_PORT, MELSEC_UDP_PORT, _parse_commands as _parse_melsec_commands
from .mms import analyze_mms, MMS_PORT, _parse_mms_commands as _parse_mms_commands
from .modbus import analyze_modbus, MODBUS_TCP_PORT, FUNC_NAMES as MODBUS_FUNC_NAMES
from .modicon import analyze_modicon
from .mqtt import analyze_mqtt, MQTT_PORTS, _parse_commands as _parse_mqtt_commands
from .niagara import analyze_niagara
from .odesys import analyze_odesys
from .opc import analyze_opc
from .pcap_cache import load_filtered_packets, get_cached_packets, has_cached_packets
from .pccc import analyze_pccc
from .pcworx import analyze_pcworx
from .prconos import analyze_prconos
from .profinet import analyze_profinet, PROFINET_PORTS, _parse_commands as _parse_profinet_commands
from .s7 import analyze_s7, S7_PORT, _parse_commands as _parse_s7_commands
from .srtp import analyze_srtp
from .utils import safe_float
from .yokogawa import analyze_yokogawa


@dataclass(frozen=True)
class OtCommandSummary:
    path: Path
    command_counts: Counter[str]
    sources: Counter[str]
    destinations: Counter[str]
    command_sessions: Counter[str]
    command_session_times: dict[str, tuple[float | None, float | None]]
    control_targets: dict[str, Counter[str]]
    control_rate_per_min: float | None
    control_burst_max: int
    control_burst_window: int
    fast_mode: bool
    fast_notes: list[str]
    detections: list[dict[str, object]]
    errors: list[str]


@dataclass(frozen=True)
class OtControlConfig:
    write_markers: tuple[str, ...] = ()
    protocol_markers: dict[str, tuple[str, ...]] = field(default_factory=dict)
    dnp3_control_names: set[str] = field(default_factory=set)


WRITE_MARKERS = (
    "write",
    "operate",
    "select",
    "control",
    "set",
    "download",
    "upload",
    "stop",
    "start",
    "close",
    "open",
    "command",
    "run",
    "reinit",
    "delete",
    "define",
)
COAP_WRITE_MARKERS = ("put", "post")
ETHERCAT_WRITE_MARKERS = tuple(marker.lower() for marker in ETHERCAT_WRITE_COMMANDS)
DNP3_CONTROL_CODES = CONTROL_FUNCTIONS | FREEZE_FUNCTIONS | RESTART_FUNCTIONS | APP_CONTROL_FUNCTIONS | FILE_FUNCTIONS | TIME_FUNCTIONS
DNP3_CONTROL_NAMES = {DNP3_FUNC_CODES.get(code) for code in DNP3_CONTROL_CODES if code in DNP3_FUNC_CODES}

def _normalize_markers(values: object) -> list[str]:
    if not values:
        return []
    if isinstance(values, (str, bytes)):
        return [str(values).strip().lower()] if str(values).strip() else []
    items: list[str] = []
    if isinstance(values, (list, tuple, set)):
        for item in values:
            text = str(item).strip()
            if text:
                items.append(text.lower())
    return items


def load_ot_control_config(path: Path) -> OtControlConfig:
    raw_text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    data: dict[str, object]
    if suffix in {".yml", ".yaml"}:
        try:
            import yaml  # type: ignore
        except Exception as exc:
            raise ValueError("YAML config requires PyYAML to be installed.") from exc
        data = yaml.safe_load(raw_text) or {}
    else:
        data = json.loads(raw_text) if raw_text.strip() else {}

    if not isinstance(data, dict):
        raise ValueError("OT control config must be a JSON/YAML object.")

    write_markers = tuple(dict.fromkeys(_normalize_markers(data.get("write_markers"))))

    protocol_markers: dict[str, tuple[str, ...]] = {}
    raw_protocols = data.get("protocol_markers") or {}
    if isinstance(raw_protocols, dict):
        for proto, markers in raw_protocols.items():
            proto_key = str(proto).strip().upper()
            if not proto_key:
                continue
            marker_list = _normalize_markers(markers)
            if marker_list:
                protocol_markers[proto_key] = tuple(dict.fromkeys(marker_list))

    dnp3_control_names: set[str] = set()
    dnp3_cfg = data.get("dnp3") or {}
    if isinstance(dnp3_cfg, dict):
        for code in dnp3_cfg.get("functions", []) or []:
            try:
                code_int = int(code)
            except Exception:
                continue
            name = DNP3_FUNC_CODES.get(code_int, f"Func {code_int}")
            dnp3_control_names.add(name.lower())
        for name in dnp3_cfg.get("names", []) or []:
            text = str(name).strip()
            if text:
                dnp3_control_names.add(text.lower())

    iec_cfg = data.get("iec104") or {}
    if isinstance(iec_cfg, dict):
        names: list[str] = []
        for code in iec_cfg.get("asdu_types", []) or []:
            try:
                code_int = int(code)
            except Exception:
                continue
            names.append(ASDU_TYPES.get(code_int, f"ASDU {code_int}"))
        names.extend(str(item).strip() for item in (iec_cfg.get("names") or []) if str(item).strip())
        if names:
            proto_key = "IEC-104"
            existing = list(protocol_markers.get(proto_key, ()))
            existing.extend(item.lower() for item in names if item)
            protocol_markers[proto_key] = tuple(dict.fromkeys(existing))

    mms_cfg = data.get("mms") or {}
    if isinstance(mms_cfg, dict):
        names = _normalize_markers(mms_cfg.get("services"))
        names.extend(_normalize_markers(mms_cfg.get("names")))
        if names:
            proto_key = "MMS"
            existing = list(protocol_markers.get(proto_key, ()))
            existing.extend(names)
            protocol_markers[proto_key] = tuple(dict.fromkeys(existing))

    return OtControlConfig(
        write_markers=write_markers,
        protocol_markers=protocol_markers,
        dnp3_control_names=dnp3_control_names,
    )


def _merge_markers(base: tuple[str, ...], extra: tuple[str, ...]) -> tuple[str, ...]:
    merged = list(base)
    merged.extend(extra)
    return tuple(dict.fromkeys(merged))


def _track_session(
    session_counts: Counter[str],
    session_times: dict[str, tuple[float | None, float | None]],
    proto: str,
    src: str,
    dst: str,
    ts: float | None,
    control_timestamps: list[float] | None = None,
) -> None:
    key = f"{proto} {src} -> {dst}"
    session_counts[key] += 1
    if ts is None:
        return
    first, last = session_times.get(key, (ts, ts))
    if first is None or ts < first:
        first = ts
    if last is None or ts > last:
        last = ts
    session_times[key] = (first, last)
    if control_timestamps is not None:
        control_timestamps.append(ts)


def _is_write_command(
    text: str,
    extra_markers: tuple[str, ...] = (),
    base_markers: tuple[str, ...] = WRITE_MARKERS,
) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in base_markers) or any(marker in lowered for marker in extra_markers)


def _add_control_target(targets: dict[str, Counter[str]], proto: str, dst: str, detail: str) -> None:
    clean_detail = detail.strip() if detail else ""
    if not clean_detail:
        clean_detail = "control"
    targets.setdefault(proto, Counter())[f"{dst} :: {clean_detail}"] += 1


def _compute_control_intensity(timestamps: list[float], window_seconds: float = 60.0) -> tuple[float | None, int]:
    if not timestamps:
        return None, 0
    times = sorted(timestamps)
    duration = times[-1] - times[0]
    if duration > 0:
        rate = len(times) / (duration / 60.0)
    else:
        rate = float(len(times))

    max_burst = 0
    start = 0
    for end, ts in enumerate(times):
        while ts - times[start] > window_seconds:
            start += 1
        max_burst = max(max_burst, end - start + 1)
    return rate, max_burst


def _count_from_counter(
    counter: Counter[str],
    label: str,
    out: Counter[str],
    extra_markers: tuple[str, ...] = (),
    base_markers: tuple[str, ...] = WRITE_MARKERS,
) -> None:
    for key, count in counter.items():
        if _is_write_command(str(key), extra_markers, base_markers):
            out[f"{label}:{key}"] += count


def _count_from_artifacts(
    artifacts: list[object],
    label: str,
    out: Counter[str],
    sources: Counter[str],
    destinations: Counter[str],
    base_markers: tuple[str, ...] = WRITE_MARKERS,
) -> None:
    for item in artifacts or []:
        detail = str(getattr(item, "detail", "")).lower()
        if not detail:
            continue
        if _is_write_command(detail, base_markers=base_markers):
            out[f"{label}:payload"] += 1
            sources[str(getattr(item, "src", "-"))] += 1
            destinations[str(getattr(item, "dst", "-"))] += 1


def _count_from_events(
    events: list[object],
    sources: Counter[str],
    destinations: Counter[str],
    session_counts: Counter[str],
    session_times: dict[str, tuple[float | None, float | None]],
    label: str,
    extra_markers: tuple[str, ...] = (),
    base_markers: tuple[str, ...] = WRITE_MARKERS,
    control_timestamps: list[float] | None = None,
    control_targets: dict[str, Counter[str]] | None = None,
    target_formatter: Callable[[str], str] | None = None,
) -> None:
    for item in events or []:
        command = str(getattr(item, "command", ""))
        if not command:
            continue
        if _is_write_command(command, extra_markers, base_markers):
            src = str(getattr(item, "src", "-"))
            dst = str(getattr(item, "dst", "-"))
            sources[src] += 1
            destinations[dst] += 1
            _track_session(session_counts, session_times, label, src, dst, getattr(item, "ts", None), control_timestamps)
            if control_targets is not None:
                detail = target_formatter(command) if target_formatter else command
                _add_control_target(control_targets, label, dst, detail)


def _count_from_service_endpoints(
    endpoints: dict[str, Counter[str]],
    sources: Counter[str],
    destinations: Counter[str],
    session_counts: Counter[str],
    session_times: dict[str, tuple[float | None, float | None]],
    label: str,
    base_markers: tuple[str, ...] = WRITE_MARKERS,
) -> None:
    for service, counter in endpoints.items():
        if not _is_write_command(service, base_markers=base_markers):
            continue
        for endpoint, count in counter.items():
            src, _, dst = str(endpoint).partition(" -> ")
            if src:
                sources[src] += count
            if dst:
                destinations[dst] += count
            if src and dst:
                key = f"{label} {src} -> {dst}"
                session_counts[key] += count


def _count_from_industrial(
    summary: object,
    label: str,
    command_counts: Counter[str],
    sources: Counter[str],
    destinations: Counter[str],
    session_counts: Counter[str],
    session_times: dict[str, tuple[float | None, float | None]],
    extra_markers: tuple[str, ...] = (),
    base_markers: tuple[str, ...] = WRITE_MARKERS,
    control_timestamps: list[float] | None = None,
    control_targets: dict[str, Counter[str]] | None = None,
    target_formatter: Callable[[str], str] | None = None,
) -> None:
    _count_from_counter(getattr(summary, "commands", Counter()), label, command_counts, extra_markers, base_markers)
    _count_from_events(
        getattr(summary, "command_events", []) or [],
        sources,
        destinations,
        session_counts,
        session_times,
        label,
        extra_markers,
        base_markers,
        control_timestamps,
        control_targets,
        target_formatter,
    )


FAST_PORTS = sorted({
    MODBUS_TCP_PORT,
    DNP3_PORT,
    IEC104_PORT,
    BACNET_PORT,
    FINS_PORT,
    MELSEC_TCP_PORT,
    MELSEC_UDP_PORT,
    MMS_PORT,
    S7_PORT,
    CIP_TCP_PORT,
    CIP_UDP_PORT,
    CIP_SECURITY_PORT,
    *COAP_PORTS,
    *MQTT_PORTS,
    *PROFINET_PORTS,
})
FAST_PORT_SET = set(FAST_PORTS)


def _fast_modbus_command(payload: bytes) -> str | None:
    if len(payload) < 8:
        return None
    try:
        _trans_id, proto_id, _length, _unit_id = struct.unpack(">HHHB", payload[:7])
    except Exception:
        return None
    if proto_id != 0:
        return None
    func = payload[7]
    return MODBUS_FUNC_NAMES.get(func, f"Func {func}")


def _fast_dnp3_command(payload: bytes, control_names: set[str]) -> tuple[str | None, bool]:
    idx = payload.find(b"\x05\x64")
    if idx < 0:
        return None, False
    func_offset = idx + 12
    if func_offset >= len(payload):
        return None, False
    func_code = payload[func_offset]
    name = DNP3_FUNC_CODES.get(func_code, f"Func {func_code}")
    return name, name.lower() in control_names


def _fast_cip_commands(payload: bytes) -> list[str]:
    commands: list[str] = []
    try:
        encap_command, encap_name, _status, cip_payload, _is_connected = _parse_enip(payload)
    except Exception:
        return commands
    if encap_name:
        commands.append(encap_name)
    if cip_payload:
        try:
            _service, service_name, _is_request, _status, _status_text, _class_id, _instance_id, _attribute_id, _path, _payload = _parse_cip_message(cip_payload)
        except Exception:
            service_name = None
        if service_name:
            commands.append(service_name)
    return commands


def _build_fast_bpf() -> str:
    port_expr = " or ".join(f"port {port}" for port in FAST_PORTS)
    return f"(tcp or udp) and ({port_expr})"


def _analyze_ot_commands_fast(
    path: Path,
    show_status: bool = True,
    config: OtControlConfig | None = None,
) -> OtCommandSummary:
    base_markers = _merge_markers(WRITE_MARKERS, config.write_markers) if config else WRITE_MARKERS
    protocol_markers = config.protocol_markers if config else {}
    dnp3_control_names = {str(name).lower() for name in DNP3_CONTROL_NAMES if name}
    if config and config.dnp3_control_names:
        dnp3_control_names.update({str(name).lower() for name in config.dnp3_control_names if name})

    command_counts: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    destinations: Counter[str] = Counter()
    command_sessions: Counter[str] = Counter()
    command_session_times: dict[str, tuple[float | None, float | None]] = {}
    control_targets: dict[str, Counter[str]] = defaultdict(Counter)
    control_timestamps: list[float] = []
    fast_notes: list[str] = [
        "Fast mode scans TCP/UDP control ports only; L2 protocols (GOOSE/SV/EtherCAT) and non-standard ports may be missed."
    ]
    errors: list[str] = []

    try:
        bpf_status: dict[str, object] = {}
        if has_cached_packets(path):
            packets, _meta = get_cached_packets(path, show_status=show_status)
        else:
            packets, _meta = load_filtered_packets(
                path,
                show_status=show_status,
                bpf=_build_fast_bpf(),
                bpf_status=bpf_status,
            )
        if bpf_status.get("error"):
            fast_notes.append(f"BPF filter unavailable: {bpf_status['error']}. Falling back to full scan.")
    except Exception as exc:
        return OtCommandSummary(
            path=path,
            command_counts=command_counts,
            sources=sources,
            destinations=destinations,
            command_sessions=command_sessions,
            command_session_times=command_session_times,
            control_targets=control_targets,
            control_rate_per_min=None,
            control_burst_max=0,
            control_burst_window=60,
            fast_mode=True,
            fast_notes=fast_notes,
            detections=[],
            errors=[f"Fast scan error: {exc}"],
        )

    signature_scan = bool(bpf_status.get("error"))
    if signature_scan:
        fast_notes.append("Signature scan enabled for DNP3/ENIP on non-standard ports.")

    for pkt in packets:
        has_transport, src_ip, dst_ip, sport, dport, payload = _extract_transport(pkt)
        if not has_transport or not payload:
            continue
        port = dport if dport in FAST_PORT_SET else sport if sport in FAST_PORT_SET else None
        ts = safe_float(getattr(pkt, "time", None))

        proto = None
        commands: list[str] = []
        command_gate: Callable[[str], bool] | None = None
        proto_extra: tuple[str, ...] = ()

        if port == MODBUS_TCP_PORT:
            cmd = _fast_modbus_command(payload)
            if cmd:
                proto = "Modbus"
                commands = [cmd]
        elif port == DNP3_PORT:
            cmd, is_control = _fast_dnp3_command(payload, dnp3_control_names)
            if cmd:
                proto = "DNP3"
                commands = [cmd]
                command_gate = (
                    lambda name, flag=is_control, extra=protocol_markers.get("DNP3", ()), base=base_markers:
                    flag or _is_write_command(name, extra, base)
                )
        elif port == IEC104_PORT:
            proto = "IEC-104"
            commands = _parse_iec104_commands(payload)
        elif port == BACNET_PORT:
            proto = "BACnet"
            commands = _parse_bacnet_commands(payload)
        elif port == FINS_PORT:
            proto = "FINS"
            commands = _parse_fins_commands(payload)
        elif port in {MELSEC_TCP_PORT, MELSEC_UDP_PORT}:
            proto = "MELSEC"
            commands = _parse_melsec_commands(payload)
        elif port == MMS_PORT:
            mms_cmds = _parse_mms_commands(payload)
            if mms_cmds:
                proto = "MMS"
                commands = mms_cmds
            else:
                s7_cmds = _parse_s7_commands(payload)
                if s7_cmds:
                    proto = "S7"
                    commands = s7_cmds
        elif port in COAP_PORTS:
            proto = "CoAP"
            commands = _parse_coap_commands(payload)
        elif port in MQTT_PORTS:
            proto = "MQTT"
            commands = _parse_mqtt_commands(payload)
        elif port in PROFINET_PORTS:
            proto = "Profinet"
            commands = _parse_profinet_commands(payload)
        elif port in {CIP_TCP_PORT, CIP_UDP_PORT, CIP_SECURITY_PORT}:
            proto = "CIP"
            commands = _fast_cip_commands(payload)
        elif port is None and signature_scan:
            cmd, is_control = _fast_dnp3_command(payload, dnp3_control_names)
            if cmd:
                proto = "DNP3"
                commands = [cmd]
                command_gate = (
                    lambda name, flag=is_control, extra=protocol_markers.get("DNP3", ()), base=base_markers:
                    flag or _is_write_command(name, extra, base)
                )
            else:
                commands = _fast_cip_commands(payload)
                if commands:
                    proto = "CIP"

        if not proto or not commands:
            continue

        if proto == "CoAP":
            proto_extra = _merge_markers(protocol_markers.get(proto.upper(), ()), COAP_WRITE_MARKERS)
        else:
            proto_extra = protocol_markers.get(proto.upper(), ())

        for cmd in commands:
            is_control = command_gate(cmd) if command_gate else _is_write_command(cmd, proto_extra, base_markers)
            if not is_control:
                continue
            command_counts[f"{proto}:{cmd}"] += 1
            sources[src_ip] += 1
            destinations[dst_ip] += 1
            _track_session(command_sessions, command_session_times, proto, src_ip, dst_ip, ts, control_timestamps)
            _add_control_target(control_targets, proto, dst_ip, cmd)

    detections: list[dict[str, object]] = []
    if command_counts:
        detections.append({
            "severity": "warning",
            "summary": "OT control/write command activity observed (fast scan)",
            "details": "; ".join(f"{cmd} ({count})" for cmd, count in command_counts.most_common(8)),
        })

    rate, burst = _compute_control_intensity(control_timestamps)

    return OtCommandSummary(
        path=path,
        command_counts=command_counts,
        sources=sources,
        destinations=destinations,
        command_sessions=command_sessions,
        command_session_times=command_session_times,
        control_targets=control_targets,
        control_rate_per_min=rate,
        control_burst_max=burst,
        control_burst_window=60,
        fast_mode=True,
        fast_notes=fast_notes,
        detections=detections,
        errors=errors,
    )


def analyze_ot_commands(
    path: Path,
    show_status: bool = True,
    fast: bool = False,
    config: OtControlConfig | None = None,
) -> OtCommandSummary:
    if fast:
        return _analyze_ot_commands_fast(path, show_status=show_status, config=config)

    base_markers = _merge_markers(WRITE_MARKERS, config.write_markers) if config else WRITE_MARKERS
    protocol_markers = config.protocol_markers if config else {}
    dnp3_control_names = {str(name).lower() for name in DNP3_CONTROL_NAMES if name}
    if config and config.dnp3_control_names:
        dnp3_control_names.update({str(name).lower() for name in config.dnp3_control_names if name})

    command_counts: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    destinations: Counter[str] = Counter()
    command_sessions: Counter[str] = Counter()
    command_session_times: dict[str, tuple[float | None, float | None]] = {}
    control_targets: dict[str, Counter[str]] = defaultdict(Counter)
    control_timestamps: list[float] = []
    errors: list[str] = []

    def _protocol_extra(label: str, extra: tuple[str, ...] = ()) -> tuple[str, ...]:
        return _merge_markers(protocol_markers.get(label.upper(), ()), extra)

    def _iec104_target(command: str) -> str:
        if command.startswith("IOA "):
            return command
        if command.startswith("C_") or "Control ASDU" in command:
            return command
        return command

    modbus = analyze_modbus(path, show_status=show_status)
    modbus_extra = _protocol_extra("Modbus")
    _count_from_counter(modbus.func_counts, "Modbus", command_counts, modbus_extra, base_markers)
    errors.extend(modbus.errors or [])
    for msg in getattr(modbus, "messages", []) or []:
        if _is_write_command(str(getattr(msg, "func_name", "")), modbus_extra, base_markers):
            src = str(getattr(msg, "src_ip", "-"))
            dst = str(getattr(msg, "dst_ip", "-"))
            sources[src] += 1
            destinations[dst] += 1
            detail = str(getattr(msg, "detail", "") or getattr(msg, "func_name", ""))
            _track_session(command_sessions, command_session_times, "Modbus", src, dst, getattr(msg, "ts", None), control_timestamps)
            _add_control_target(control_targets, "Modbus", dst, detail)

    dnp3 = analyze_dnp3(path, show_status=show_status)
    dnp3_extra = _protocol_extra("DNP3")
    for key, count in dnp3.func_counts.items():
        key_text = str(key)
        if key_text.lower() in dnp3_control_names or _is_write_command(key_text, dnp3_extra, base_markers):
            command_counts[f"DNP3:{key}"] += count
    errors.extend(dnp3.errors or [])
    for msg in getattr(dnp3, "messages", []) or []:
        func_name = str(getattr(msg, "func_name", ""))
        if func_name.lower() in dnp3_control_names or _is_write_command(func_name, dnp3_extra, base_markers):
            src = str(getattr(msg, "src_ip", "-"))
            dst = str(getattr(msg, "dst_ip", "-"))
            sources[src] += 1
            destinations[dst] += 1
            detail = str(getattr(msg, "object_summary", "") or getattr(msg, "func_name", ""))
            _track_session(command_sessions, command_session_times, "DNP3", src, dst, getattr(msg, "ts", None), control_timestamps)
            _add_control_target(control_targets, "DNP3", dst, detail)

    cip = analyze_cip(path, show_status=show_status)
    cip_extra = _protocol_extra("CIP")
    enip_extra = _protocol_extra("ENIP")
    _count_from_counter(getattr(cip, "cip_services", Counter()), "CIP", command_counts, cip_extra, base_markers)
    _count_from_counter(getattr(cip, "enip_commands", Counter()), "ENIP", command_counts, enip_extra, base_markers)
    errors.extend(getattr(cip, "errors", []) or [])
    _count_from_service_endpoints(
        getattr(cip, "service_endpoints", {}) or {},
        sources,
        destinations,
        command_sessions,
        command_session_times,
        "CIP",
        base_markers,
    )
    for art in getattr(cip, "artifacts", []) or []:
        if getattr(art, "kind", "") == "tag_write":
            dst = str(getattr(art, "dst", "-"))
            detail = str(getattr(art, "detail", "") or "tag_write")
            _add_control_target(control_targets, "CIP", dst, detail)

    iec = analyze_iec104(path, show_status=show_status)
    iec_extra = _protocol_extra("IEC-104")
    _count_from_industrial(
        iec,
        "IEC-104",
        command_counts,
        sources,
        destinations,
        command_sessions,
        command_session_times,
        iec_extra,
        base_markers,
        control_timestamps,
        control_targets,
        _iec104_target,
    )
    errors.extend(getattr(iec, "errors", []) or [])

    s7 = analyze_s7(path, show_status=show_status)
    s7_extra = _protocol_extra("S7")
    _count_from_industrial(
        s7,
        "S7",
        command_counts,
        sources,
        destinations,
        command_sessions,
        command_session_times,
        s7_extra,
        base_markers,
        control_timestamps,
        control_targets,
    )
    errors.extend(getattr(s7, "errors", []) or [])

    opc = analyze_opc(path, show_status=show_status)
    opc_extra = _protocol_extra("OPC UA")
    _count_from_industrial(
        opc,
        "OPC UA",
        command_counts,
        sources,
        destinations,
        command_sessions,
        command_session_times,
        opc_extra,
        base_markers,
        control_timestamps,
        control_targets,
    )
    errors.extend(getattr(opc, "errors", []) or [])

    odesys = analyze_odesys(path, show_status=show_status)
    odesys_extra = _protocol_extra("ODESYS")
    _count_from_industrial(
        odesys,
        "ODESYS",
        command_counts,
        sources,
        destinations,
        command_sessions,
        command_session_times,
        odesys_extra,
        base_markers,
        control_timestamps,
        control_targets,
    )
    errors.extend(getattr(odesys, "errors", []) or [])

    pccc = analyze_pccc(path, show_status=show_status)
    pccc_extra = _protocol_extra("PCCC")
    _count_from_industrial(
        pccc,
        "PCCC",
        command_counts,
        sources,
        destinations,
        command_sessions,
        command_session_times,
        pccc_extra,
        base_markers,
        control_timestamps,
        control_targets,
    )
    errors.extend(getattr(pccc, "errors", []) or [])

    niagara = analyze_niagara(path, show_status=show_status)
    niagara_extra = _protocol_extra("Niagara")
    _count_from_industrial(
        niagara,
        "Niagara",
        command_counts,
        sources,
        destinations,
        command_sessions,
        command_session_times,
        niagara_extra,
        base_markers,
        control_timestamps,
        control_targets,
    )
    errors.extend(getattr(niagara, "errors", []) or [])

    mqtt = analyze_mqtt(path, show_status=show_status)
    mqtt_extra = _protocol_extra("MQTT")
    _count_from_industrial(
        mqtt,
        "MQTT",
        command_counts,
        sources,
        destinations,
        command_sessions,
        command_session_times,
        mqtt_extra,
        base_markers,
        control_timestamps,
        control_targets,
    )
    errors.extend(getattr(mqtt, "errors", []) or [])

    bacnet = analyze_bacnet(path, show_status=show_status)
    bacnet_extra = _protocol_extra("BACnet")
    _count_from_industrial(
        bacnet,
        "BACnet",
        command_counts,
        sources,
        destinations,
        command_sessions,
        command_session_times,
        bacnet_extra,
        base_markers,
        control_timestamps,
        control_targets,
    )
    errors.extend(getattr(bacnet, "errors", []) or [])

    coap = analyze_coap(path, show_status=show_status)
    coap_extra = _merge_markers(_protocol_extra("CoAP"), COAP_WRITE_MARKERS)
    _count_from_industrial(
        coap,
        "CoAP",
        command_counts,
        sources,
        destinations,
        command_sessions,
        command_session_times,
        coap_extra,
        base_markers,
        control_timestamps,
        control_targets,
    )
    errors.extend(getattr(coap, "errors", []) or [])

    df1 = analyze_df1(path, show_status=show_status)
    df1_extra = _protocol_extra("DF1")
    _count_from_industrial(
        df1,
        "DF1",
        command_counts,
        sources,
        destinations,
        command_sessions,
        command_session_times,
        df1_extra,
        base_markers,
        control_timestamps,
        control_targets,
    )
    errors.extend(getattr(df1, "errors", []) or [])

    ethercat = analyze_ethercat(path, show_status=show_status)
    ethercat_extra = _merge_markers(_protocol_extra("EtherCAT"), ETHERCAT_WRITE_MARKERS)
    _count_from_industrial(
        ethercat,
        "EtherCAT",
        command_counts,
        sources,
        destinations,
        command_sessions,
        command_session_times,
        ethercat_extra,
        base_markers,
        control_timestamps,
        control_targets,
    )
    errors.extend(getattr(ethercat, "errors", []) or [])

    fins = analyze_fins(path, show_status=show_status)
    fins_extra = _protocol_extra("FINS")
    _count_from_industrial(
        fins,
        "FINS",
        command_counts,
        sources,
        destinations,
        command_sessions,
        command_session_times,
        fins_extra,
        base_markers,
        control_timestamps,
        control_targets,
    )
    errors.extend(getattr(fins, "errors", []) or [])

    melsec = analyze_melsec(path, show_status=show_status)
    melsec_extra = _protocol_extra("MELSEC")
    _count_from_industrial(
        melsec,
        "MELSEC",
        command_counts,
        sources,
        destinations,
        command_sessions,
        command_session_times,
        melsec_extra,
        base_markers,
        control_timestamps,
        control_targets,
    )
    errors.extend(getattr(melsec, "errors", []) or [])

    mms = analyze_mms(path, show_status=show_status)
    mms_extra = _protocol_extra("MMS")
    _count_from_industrial(
        mms,
        "MMS",
        command_counts,
        sources,
        destinations,
        command_sessions,
        command_session_times,
        mms_extra,
        base_markers,
        control_timestamps,
        control_targets,
    )
    errors.extend(getattr(mms, "errors", []) or [])

    modicon = analyze_modicon(path, show_status=show_status)
    modicon_extra = _protocol_extra("Modicon")
    _count_from_industrial(
        modicon,
        "Modicon",
        command_counts,
        sources,
        destinations,
        command_sessions,
        command_session_times,
        modicon_extra,
        base_markers,
        control_timestamps,
        control_targets,
    )
    errors.extend(getattr(modicon, "errors", []) or [])

    profinet = analyze_profinet(path, show_status=show_status)
    profinet_extra = _protocol_extra("Profinet")
    _count_from_industrial(
        profinet,
        "Profinet",
        command_counts,
        sources,
        destinations,
        command_sessions,
        command_session_times,
        profinet_extra,
        base_markers,
        control_timestamps,
        control_targets,
    )
    errors.extend(getattr(profinet, "errors", []) or [])

    srtp = analyze_srtp(path, show_status=show_status)
    srtp_extra = _protocol_extra("SRTP")
    _count_from_industrial(
        srtp,
        "SRTP",
        command_counts,
        sources,
        destinations,
        command_sessions,
        command_session_times,
        srtp_extra,
        base_markers,
        control_timestamps,
        control_targets,
    )
    errors.extend(getattr(srtp, "errors", []) or [])

    yokogawa = analyze_yokogawa(path, show_status=show_status)
    yokogawa_extra = _protocol_extra("Yokogawa")
    _count_from_industrial(
        yokogawa,
        "Yokogawa",
        command_counts,
        sources,
        destinations,
        command_sessions,
        command_session_times,
        yokogawa_extra,
        base_markers,
        control_timestamps,
        control_targets,
    )
    errors.extend(getattr(yokogawa, "errors", []) or [])

    pcworx = analyze_pcworx(path, show_status=show_status)
    pcworx_markers = _merge_markers(base_markers, _protocol_extra("PCWorx"))
    _count_from_artifacts(
        getattr(pcworx, "artifacts", []) or [],
        "PCWorx",
        command_counts,
        sources,
        destinations,
        pcworx_markers,
    )
    errors.extend(getattr(pcworx, "errors", []) or [])

    prconos = analyze_prconos(path, show_status=show_status)
    prconos_markers = _merge_markers(base_markers, _protocol_extra("ProConOS"))
    _count_from_artifacts(
        getattr(prconos, "artifacts", []) or [],
        "ProConOS",
        command_counts,
        sources,
        destinations,
        prconos_markers,
    )
    errors.extend(getattr(prconos, "errors", []) or [])

    detections: list[dict[str, object]] = []
    if command_counts:
        detections.append({
            "severity": "warning",
            "summary": "OT control/write command activity observed",
            "details": "; ".join(f"{cmd} ({count})" for cmd, count in command_counts.most_common(8)),
        })

    rate, burst = _compute_control_intensity(control_timestamps)

    return OtCommandSummary(
        path=path,
        command_counts=command_counts,
        sources=sources,
        destinations=destinations,
        command_sessions=command_sessions,
        command_session_times=command_session_times,
        control_targets=control_targets,
        control_rate_per_min=rate,
        control_burst_max=burst,
        control_burst_window=60,
        fast_mode=False,
        fast_notes=[],
        detections=detections,
        errors=errors,
    )
