"""Baselines: record what a network normally does, then report what deviates.

``--baseline`` writes a snapshot of a capture (or, with -summarize, of several
merged): hosts and services, OT/ICS/IoT communication pairs with their volume
and polling cadence, the commands each pair exchanges (reads and writes),
layer-2 industrial streams and the IP -> MAC bindings. ``--baseline-diff``
compares a capture against a saved snapshot, or against a second capture, and
turns every deviation into a finding with a severity.

Every rule that turns a difference into a finding is a fixed rule in this
module (``compare_baseline``) with its thresholds named below, so a verdict is
inspectable and regression-tested rather than a judgment made at render time.

Schema 2 (this module) extends schema 1 (what ``--baseline-save`` wrote before):
a schema-1 file still loads and compares; the sections it lacks are reported
as not in the baseline, never as drift.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from collections import defaultdict
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from .baseline_profile import TrafficProfile, classify_port, interval_stats
from .hosts import HostSummary, merge_hosts_summaries
from .ipmac import mac_manufacturer
from .ot_commands import OtCommandSummary
from .services import ServiceSummary, merge_services_summaries
from .utils import is_unicast_host_ip, safe_read_text

SCHEMA_VERSION = 2
BASELINE_SUFFIX = ".baseline.json"

# --- Deviation thresholds (the rules compare_baseline applies) --------------
# Rates are only compared when both captures span at least this long; a
# 10-second capture says nothing about a per-minute rate.
MIN_RATE_WINDOW_SECONDS = 30.0
# A conversation's rate must change by this factor (either way) ...
RATE_CHANGE_FACTOR = 3.0
# ... on at least this many packets in the baseline.
MIN_RATE_PACKETS = 20
# Cadence: median request interval changes by this factor (either way) and by
# at least this many seconds; both sides need this many interval samples.
CADENCE_CHANGE_FACTOR = 1.5
CADENCE_MIN_DELTA_SECONDS = 0.05
MIN_CADENCE_SAMPLES = 10
# Jitter (median absolute deviation / median): regular below, irregular above.
REGULAR_JITTER = 0.10
IRREGULAR_JITTER = 0.30
# A missing conversation matters when the current capture lasted this many
# baseline intervals (it would have polled); otherwise it is informational.
MISSING_INTERVALS = 3
# A MAC that fronts this many IPs is a router/gateway: an IP "moving" behind
# a different gateway MAC is routing, not a host being replaced.
GATEWAY_MAC_IPS = 3
# Register values: a register needs this many samples on both sides; a value
# beyond the baseline range by more than this share of its span (at least 1)
# is out of range. Registers kept in a baseline, busiest first.
MIN_REGISTER_SAMPLES = 5
REGISTER_RANGE_MARGIN = 0.10
MAX_BASELINE_REGISTERS = 20_000
# Remote-access, file-transfer and admin protocols: on an OT host they are
# the classic lateral-movement or misuse cue.
REMOTE_ADMIN_PORTS = {21, 22, 23, 69, 135, 139, 445, 3389, 5800, 5900, 5985, 5986}
# A rate this many times the baseline on an OT conversation reads as flooding.
FLOOD_FACTOR = 10.0

# ATT&CK for ICS techniques a deviation is evidence of (only where the
# deviation itself is that behaviour, not merely compatible with it).
ATTACK_ROGUE_MASTER = "T0848 Rogue Master"
ATTACK_UNAUTH_COMMAND = "T0855 Unauthorized Command Message"
ATTACK_MODIFY_PARAMETER = "T0836 Modify Parameter"
ATTACK_AITM = "T0830 Adversary-in-the-Middle"
ATTACK_REMOTE_SERVICES = "T0886 Remote Services"
ATTACK_MANIPULATION = "T0831 Manipulation of Control; T0832 Manipulation of View"
ATTACK_SPOOF_REPORTING = "T0856 Spoof Reporting Message"
ATTACK_DOS = "T0814 Denial of Service"
ATTACK_BRUTE_IO = "T0806 Brute Force I/O"

# pcapper flags that dissect a protocol a deviation names: the next step.
PROTOCOL_FLAGS = {
    "Modbus": "--modbus", "DNP3": "--dnp3", "IEC-104": "--iec104", "S7": "--s7", "ENIP": "--enip", "CIP": "--cip",
    "BACnet": "--bacnet", "MMS": "--mms", "OPC UA": "--opc", "OPC-UA": "--opc", "PROFINET": "--profinet",
    "PROFINET RT": "--profinet", "MQTT": "--mqtt", "MQTT-TLS": "--mqtt", "CoAP": "--coap", "FINS": "--fins",
    "MELSEC": "--melsec", "CODESYS": "--codesys", "IEC 61850 GOOSE": "--goose", "IEC 61850 SV": "--sv",
    "RDP": "--rdp", "SMB": "--smb", "SSH": "--ssh", "Telnet": "--telnet", "FTP": "--ftp", "VNC": "--vnc",
}


@dataclass(frozen=True)
class BaselineSnapshot:
    created_at: str
    pcapper_version: str
    sources: list[str]
    hosts: list[dict[str, object]] = field(default_factory=list)
    services: list[dict[str, object]] = field(default_factory=list)
    ot_commands: dict[str, int] = field(default_factory=dict)
    control_targets: dict[str, dict[str, int]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    # --- schema 2 ---
    schema_version: int = SCHEMA_VERSION
    capture: dict[str, object] = field(default_factory=dict)
    flows: list[dict[str, object]] = field(default_factory=list)
    l2_flows: list[dict[str, object]] = field(default_factory=list)
    ip_macs: dict[str, list[dict[str, object]]] = field(default_factory=dict)
    pair_commands: list[dict[str, object]] = field(default_factory=list)
    ot_command_mode: str = ""
    registers: list[dict[str, object]] = field(default_factory=list)

    @property
    def has_profile(self) -> bool:
        """Whether this snapshot carries the communication profile (schema 2)."""
        return self.schema_version >= 2

    @property
    def duration_seconds(self) -> float:
        try:
            return float(self.capture.get("duration_seconds") or 0.0)
        except (TypeError, ValueError):
            return 0.0

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "created_at": self.created_at,
            "pcapper_version": self.pcapper_version,
            "sources": list(self.sources),
            "capture": self.capture,
            "hosts": self.hosts,
            "services": self.services,
            "flows": self.flows,
            "l2_flows": self.l2_flows,
            "ip_macs": self.ip_macs,
            "pair_commands": self.pair_commands,
            "ot_command_mode": self.ot_command_mode,
            "registers": self.registers,
            "ot_commands": self.ot_commands,
            "control_targets": self.control_targets,
            "notes": self.notes,
        }


@dataclass(frozen=True)
class BaselineDelta:
    baseline_version: str
    current_version: str
    new_hosts: list[str]
    missing_hosts: list[str]
    host_changes: list[dict[str, object]]
    new_services: list[dict[str, object]]
    missing_services: list[dict[str, object]]
    service_changes: list[dict[str, object]]
    new_ot_commands: list[str]
    missing_ot_commands: list[str]
    ot_command_changes: list[dict[str, object]]
    new_control_targets: list[str]
    missing_control_targets: list[str]
    notes: list[str]
    # --- schema 2 ---
    baseline_sources: list[str] = field(default_factory=list)
    current_sources: list[str] = field(default_factory=list)
    baseline_capture: dict[str, object] = field(default_factory=dict)
    current_capture: dict[str, object] = field(default_factory=dict)
    new_flows: list[dict[str, object]] = field(default_factory=list)
    missing_flows: list[dict[str, object]] = field(default_factory=list)
    flow_changes: list[dict[str, object]] = field(default_factory=list)
    new_l2_flows: list[dict[str, object]] = field(default_factory=list)
    missing_l2_flows: list[dict[str, object]] = field(default_factory=list)
    new_pair_commands: list[dict[str, object]] = field(default_factory=list)
    missing_pair_commands: list[dict[str, object]] = field(default_factory=list)
    pair_command_changes: list[dict[str, object]] = field(default_factory=list)
    mac_changes: list[dict[str, object]] = field(default_factory=list)
    register_changes: list[dict[str, object]] = field(default_factory=list)
    deviations: list[dict[str, object]] = field(default_factory=list)
    # Deviations correlated into what happened, per actor: see correlate_incidents.
    incidents: list[dict[str, object]] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.deviations) or any(
            [
                self.new_hosts,
                self.missing_hosts,
                self.host_changes,
                self.new_services,
                self.missing_services,
                self.service_changes,
                self.new_ot_commands,
                self.missing_ot_commands,
                self.ot_command_changes,
                self.new_control_targets,
                self.missing_control_targets,
            ]
        )


# --- Building ---------------------------------------------------------------


def _merge_ot_commands(
    summaries: Iterable[OtCommandSummary],
) -> OtCommandSummary | None:
    summary_list = [item for item in summaries if item is not None]
    if not summary_list:
        return None

    command_counts: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    destinations: Counter[str] = Counter()
    command_sessions: Counter[str] = Counter()
    command_session_times: dict[str, tuple[float | None, float | None]] = {}
    control_targets: dict[str, Counter[str]] = {}
    pair_commands: Counter[tuple[str, str, str, str, bool]] = Counter()
    pair_command_times: dict[tuple, tuple[float, float]] = {}
    detections: list[dict[str, object]] = []
    errors: list[str] = []
    fast_mode = False
    fast_notes: list[str] = []

    for summary in summary_list:
        command_counts.update(getattr(summary, "command_counts", Counter()))
        sources.update(getattr(summary, "sources", Counter()))
        destinations.update(getattr(summary, "destinations", Counter()))
        command_sessions.update(getattr(summary, "command_sessions", Counter()))
        pair_commands.update(getattr(summary, "pair_commands", Counter()) or Counter())
        for key, (first, last) in (getattr(summary, "pair_command_times", None) or {}).items():
            if first is None or last is None:
                continue
            seen = pair_command_times.get(key)
            pair_command_times[key] = (first, last) if seen is None else (min(seen[0], first), max(seen[1], last))
        for key, value in (getattr(summary, "command_session_times", {}) or {}).items():
            first, last = value
            prev_first, prev_last = command_session_times.get(key, (first, last))
            if prev_first is None or (first is not None and first < prev_first):
                prev_first = first
            if prev_last is None or (last is not None and last > prev_last):
                prev_last = last
            command_session_times[key] = (prev_first, prev_last)
        for proto, targets in (getattr(summary, "control_targets", {}) or {}).items():
            counter = control_targets.setdefault(proto, Counter())
            counter.update(targets)
        detections.extend(getattr(summary, "detections", []) or [])
        errors.extend(getattr(summary, "errors", []) or [])
        fast_mode = fast_mode or bool(getattr(summary, "fast_mode", False))
        fast_notes.extend(getattr(summary, "fast_notes", []) or [])

    return OtCommandSummary(
        path=Path("ALL_PCAPS"),
        command_counts=command_counts,
        sources=sources,
        destinations=destinations,
        command_sessions=command_sessions,
        command_session_times=command_session_times,
        control_targets=control_targets,
        control_rate_per_min=None,
        control_burst_max=0,
        control_burst_window=0,
        fast_mode=fast_mode,
        fast_notes=list(dict.fromkeys(fast_notes)),
        detections=detections,
        errors=sorted({err for err in errors if err}),
        pair_commands=pair_commands,
        pair_command_times=pair_command_times,
    )


def _round(value: Optional[float], digits: int = 6) -> Optional[float]:
    return None if value is None else round(float(value), digits)


def _profile_sections(
    profiles: list[TrafficProfile],
) -> tuple[dict[str, object], list[dict[str, object]], list[dict[str, object]], dict[str, list[dict[str, object]]], list[str]]:
    """(capture, flows, l2_flows, ip_macs, notes) merged across captures.

    Request intervals are pooled per conversation, never bridged across
    captures: the gap between two captures is not a polling interval.
    Duration is the sum of the captures' own spans, so rates stay per minute
    of traffic actually observed.
    """
    notes: list[str] = []
    packets = sum(p.total_packets for p in profiles)
    firsts = [p.first_seen for p in profiles if p.first_seen is not None]
    lasts = [p.last_seen for p in profiles if p.last_seen is not None]
    capture = {
        "packets": packets,
        "first_seen": min(firsts) if firsts else None,
        "last_seen": max(lasts) if lasts else None,
        "duration_seconds": round(sum(p.duration_seconds for p in profiles), 6),
        "captures": len(profiles),
    }

    merged: dict[tuple, dict[str, object]] = {}
    intervals: dict[tuple, list[float]] = {}
    for prof in profiles:
        for key, stats in prof.flows.items():
            entry = merged.get(key)
            if entry is None:
                entry = merged[key] = {"packets": 0, "bytes": 0, "requests": 0, "first_seen": None, "last_seen": None}
                intervals[key] = []
            entry["packets"] += stats.packets
            entry["bytes"] += stats.bytes
            entry["requests"] += stats.requests
            if stats.first_seen is not None and (entry["first_seen"] is None or stats.first_seen < entry["first_seen"]):
                entry["first_seen"] = stats.first_seen
            if stats.last_seen is not None and (entry["last_seen"] is None or stats.last_seen > entry["last_seen"]):
                entry["last_seen"] = stats.last_seen
            intervals[key].extend(stats.intervals)
        for err in prof.errors:
            notes.append(f"{prof.path.name}: {err}")

    flows: list[dict[str, object]] = []
    for key in sorted(merged, key=lambda k: (k[0], k[1], k[2], k[3])):
        client, server, transport, port = key
        entry = merged[key]
        protocol, category = classify_port(port) if transport in ("TCP", "UDP") else (transport, "other")
        median, jitter = interval_stats(intervals[key])
        flows.append({
            "client": client,
            "server": server,
            "transport": transport,
            "port": port,
            "protocol": protocol or f"{transport.lower()}/{port}",
            "category": category,
            "packets": entry["packets"],
            "bytes": entry["bytes"],
            "requests": entry["requests"],
            "first_seen": entry["first_seen"],
            "last_seen": entry["last_seen"],
            "interval_median": _round(median),
            "interval_jitter": _round(jitter, 4),
            "interval_samples": len(intervals[key]),
        })

    l2_merged: dict[tuple, dict[str, object]] = {}
    l2_intervals: dict[tuple, list[float]] = {}
    for prof in profiles:
        for key, stats in prof.l2_flows.items():
            entry = l2_merged.get(key)
            if entry is None:
                entry = l2_merged[key] = {"packets": 0, "bytes": 0, "first_seen": None, "last_seen": None}
                l2_intervals[key] = []
            entry["packets"] += stats.packets
            entry["bytes"] += stats.bytes
            if stats.first_seen is not None and (entry["first_seen"] is None or stats.first_seen < entry["first_seen"]):
                entry["first_seen"] = stats.first_seen
            if stats.last_seen is not None and (entry["last_seen"] is None or stats.last_seen > entry["last_seen"]):
                entry["last_seen"] = stats.last_seen
            l2_intervals[key].extend(stats.intervals)
    l2_flows: list[dict[str, object]] = []
    for key in sorted(l2_merged):
        src_mac, dst_mac, protocol = key
        entry = l2_merged[key]
        median, jitter = interval_stats(l2_intervals[key])
        l2_flows.append({
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "protocol": protocol,
            "packets": entry["packets"],
            "bytes": entry["bytes"],
            "first_seen": entry["first_seen"],
            "last_seen": entry["last_seen"],
            "interval_median": _round(median),
            "interval_jitter": _round(jitter, 4),
            "interval_samples": len(l2_intervals[key]),
        })

    mac_counts: dict[str, Counter[str]] = {}
    mac_times: dict[tuple[str, str], tuple[float, float]] = {}
    for prof in profiles:
        for ip, macs in prof.ip_macs.items():
            mac_counts.setdefault(ip, Counter()).update(macs)
        for key, (first, last) in (getattr(prof, "ip_mac_times", None) or {}).items():
            seen = mac_times.get(key)
            mac_times[key] = (first, last) if seen is None else (min(seen[0], first), max(seen[1], last))
    ip_macs = {
        ip: [{"mac": mac, "vendor": _vendor(mac), "frames": int(count),
              "first_seen": mac_times.get((ip, mac), (None, None))[0],
              "last_seen": mac_times.get((ip, mac), (None, None))[1]}
             for mac, count in sorted(counter.items())]
        for ip, counter in sorted(mac_counts.items())
        if is_unicast_host_ip(ip)
    }
    return capture, flows, l2_flows, ip_macs, notes


def _register_section(modbus_summaries: list, notes: list[str]) -> list[dict[str, object]]:
    """Modbus register value ranges merged across captures, busiest kept,
    with the time each extreme value was first seen."""
    merged: dict[tuple, list] = {}
    for summary in modbus_summaries:
        for key, entry_in in (getattr(summary, "register_ranges", None) or {}).items():
            low, high, count = entry_in[0], entry_in[1], entry_in[2]
            low_ts = entry_in[3] if len(entry_in) > 3 else 0.0
            high_ts = entry_in[4] if len(entry_in) > 4 else 0.0
            entry = merged.get(key)
            if entry is None:
                merged[key] = [low, high, count, low_ts, high_ts]
                continue
            if low < entry[0] or (low == entry[0] and low_ts and (not entry[3] or low_ts < entry[3])):
                entry[0], entry[3] = low, low_ts
            if high > entry[1] or (high == entry[1] and high_ts and (not entry[4] or high_ts < entry[4])):
                entry[1], entry[4] = high, high_ts
            entry[2] += count
    ranked = sorted(merged.items(), key=lambda kv: (-kv[1][2], kv[0]))
    if len(ranked) > MAX_BASELINE_REGISTERS:
        notes.append(f"Register values: the {MAX_BASELINE_REGISTERS:,} busiest of {len(ranked):,} registers kept.")
        ranked = ranked[:MAX_BASELINE_REGISTERS]
    return [
        {"protocol": "Modbus", "server": server, "unit": unit, "type": reg_type, "address": address,
         "min": low, "max": high, "samples": count, "min_first_seen": low_ts or None, "max_first_seen": high_ts or None}
        for (server, unit, reg_type, address), (low, high, count, low_ts, high_ts) in sorted(ranked, key=lambda kv: kv[0])
    ]


def _vendor(mac: str) -> str:
    name = str(mac_manufacturer(mac) or "").strip()
    return "" if name in ("-", "Unknown", "unknown") else name


def build_baseline(
    pcapper_version: str,
    sources: list[str],
    host_summaries: Iterable[HostSummary],
    service_summaries: Iterable[ServiceSummary],
    ot_summaries: Iterable[OtCommandSummary],
    profiles: Iterable[TrafficProfile] = (),
    modbus_summaries: Iterable[object] = (),
) -> BaselineSnapshot:
    created_at = datetime.now(timezone.utc).isoformat()
    notes: list[str] = []
    host_summaries = [item for item in host_summaries if item is not None]
    service_summaries = [item for item in service_summaries if item is not None]
    ot_summaries = [item for item in ot_summaries if item is not None]
    profile_list = [item for item in profiles if item is not None]

    host_summary = merge_hosts_summaries(host_summaries) if host_summaries else None
    service_summary = merge_services_summaries(service_summaries) if service_summaries else None
    ot_summary = _merge_ot_commands(ot_summaries) if ot_summaries else None

    hosts: list[dict[str, object]] = []
    services: list[dict[str, object]] = []
    ot_commands: dict[str, int] = {}
    control_targets: dict[str, dict[str, int]] = {}
    pair_commands: list[dict[str, object]] = []

    if host_summary and host_summary.hosts:
        for host in host_summary.hosts:
            if not is_unicast_host_ip(str(getattr(host, "ip", "") or "")):
                continue  # multicast / broadcast: not a host to baseline
            ports = []
            for port in getattr(host, "open_ports", []) or []:
                ports.append(
                    {
                        "port": int(getattr(port, "port", 0) or 0),
                        "protocol": str(getattr(port, "protocol", "") or ""),
                        "service": str(getattr(port, "service", "") or ""),
                        "software": str(getattr(port, "software", "") or ""),
                    }
                )
            hosts.append(
                {
                    "ip": str(getattr(host, "ip", "") or ""),
                    "macs": list(getattr(host, "mac_addresses", []) or []),
                    "hostnames": list(getattr(host, "hostnames", []) or []),
                    "os": str(getattr(host, "operating_system", "") or ""),
                    "open_ports": ports,
                }
            )
    else:
        notes.append("Host inventory unavailable: the host analysis did not run or failed for this baseline.")

    if service_summary and service_summary.assets:
        for asset in service_summary.assets:
            services.append(
                {
                    "ip": str(getattr(asset, "ip", "") or ""),
                    "port": int(getattr(asset, "port", 0) or 0),
                    "protocol": str(getattr(asset, "protocol", "") or ""),
                    "service": str(getattr(asset, "service_name", "") or ""),
                    "software": str(getattr(asset, "software", "") or ""),
                    "clients": sorted(getattr(asset, "clients", []) or []),
                }
            )
    elif not service_summaries:
        notes.append("Service inventory unavailable: the service analysis did not run or failed for this baseline.")

    if ot_summary:
        ot_commands = {str(k): int(v) for k, v in (ot_summary.command_counts or {}).items()}
        control_targets = {
            str(proto): {str(target): int(count) for target, count in targets.items()}
            for proto, targets in (ot_summary.control_targets or {}).items()
        }
        times = getattr(ot_summary, "pair_command_times", None) or {}
        for key, count in sorted(
            (ot_summary.pair_commands or {}).items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2], kv[0][3], kv[0][4])
        ):
            proto, src, dst, command, is_write = key
            first, last = times.get(key, (None, None))
            pair_commands.append(
                {"protocol": proto, "src": src, "dst": dst, "command": command, "write": bool(is_write), "count": int(count),
                 "first_seen": first, "last_seen": last}
            )
    else:
        notes.append("OT command inventory unavailable: the OT command analysis did not run or failed for this baseline.")

    capture: dict[str, object] = {}
    flows: list[dict[str, object]] = []
    l2_flows: list[dict[str, object]] = []
    ip_macs: dict[str, list[dict[str, object]]] = {}
    if profile_list:
        capture, flows, l2_flows, ip_macs, profile_notes = _profile_sections(profile_list)
        notes.extend(profile_notes)
    else:
        notes.append("Communication profile unavailable: the traffic profile did not run for this baseline.")

    registers = _register_section([m for m in modbus_summaries if m is not None], notes)

    return BaselineSnapshot(
        created_at=created_at,
        pcapper_version=pcapper_version,
        sources=sources,
        hosts=hosts,
        services=services,
        ot_commands=ot_commands,
        control_targets=control_targets,
        notes=notes,
        schema_version=SCHEMA_VERSION,
        capture=capture,
        flows=flows,
        l2_flows=l2_flows,
        ip_macs=ip_macs,
        pair_commands=pair_commands,
        ot_command_mode=("fast" if ot_summary.fast_mode else "full") if ot_summary else "",
        registers=registers,
    )


@dataclass
class CaptureParts:
    """What one capture contributes to a baseline."""

    path: Path
    hosts: Optional[HostSummary] = None
    services: Optional[ServiceSummary] = None
    ot_commands: Optional[OtCommandSummary] = None
    profile: Optional[TrafficProfile] = None
    modbus: Optional[object] = None
    errors: list[str] = field(default_factory=list)


def collect_capture_parts(
    path: Path,
    *,
    fast: bool = False,
    config: object = None,
    packets: list[object] | None = None,
    meta: object = None,
    show_status: bool = False,
) -> CaptureParts:
    """Run the analyses a baseline is built from. Each is memoized, so a step
    the run already printed (--services, --ot-commands ...) is not re-read; one
    that fails is named and the others still contribute."""
    from .baseline_profile import analyze_baseline_profile
    from .hosts import analyze_hosts
    from .modbus import analyze_modbus
    from .ot_commands import analyze_ot_commands
    from .services import analyze_services

    parts = CaptureParts(path=path)
    view = {"packets": packets, "meta": meta, "show_status": show_status}
    for attr, label, func, extra in (
        ("hosts", "host inventory", analyze_hosts, {}),
        ("services", "service inventory", analyze_services, {}),
        ("ot_commands", "OT commands", analyze_ot_commands, {"fast": fast, "config": config}),
        ("profile", "communication profile", analyze_baseline_profile, {}),
        # The full OT command scan has run it already (memoized); fast mode has not.
        ("modbus", "Modbus register values", analyze_modbus, {}),
    ):
        try:
            setattr(parts, attr, func(path, **view, **extra))
        except Exception as exc:  # noqa: BLE001 - the rest of the baseline stands
            parts.errors.append(f"{label} failed on {path.name}: {exc}")
    return parts


def build_baseline_from_parts(pcapper_version: str, parts: list[CaptureParts]) -> BaselineSnapshot:
    snapshot = build_baseline(
        pcapper_version,
        [str(p.path) for p in parts],
        [p.hosts for p in parts],
        [p.services for p in parts],
        [p.ot_commands for p in parts],
        [p.profile for p in parts],
        [p.modbus for p in parts],
    )
    errors = [err for p in parts for err in p.errors]
    if errors:
        snapshot.notes.extend(errors)
    return snapshot


def baseline_file_name(paths: list[Path]) -> str:
    """``X.pcap`` -> ``X.baseline.json``; several captures -> their common name
    prefix (``Site-A-1.pcap``, ``Site-A-2.pcap`` -> ``Site-A.baseline.json``)."""
    stems = [_capture_stem(Path(p)) for p in paths]
    if len(stems) == 1:
        return stems[0] + BASELINE_SUFFIX
    prefix = os.path.commonprefix(stems).rstrip(" ._-")
    # A prefix cut mid-number ("capture-1" / "capture-12" -> "capture-1") names
    # one of the captures; drop the dangling digits.
    prefix = re.sub(r"[ ._-]*\d+$", "", prefix) if prefix and any(s != prefix for s in stems) else prefix
    return (prefix or f"merged-{len(stems)}-captures") + BASELINE_SUFFIX


def _capture_stem(path: Path) -> str:
    name = path.name
    for suffix in (".gz", ".pcapng", ".pcap", ".cap"):
        if name.lower().endswith(suffix):
            name = name[: -len(suffix)]
    return name or path.stem


def is_baseline_file(path: Path) -> bool:
    """A saved snapshot (JSON) rather than a capture to profile."""
    if path.suffix.lower() == ".json":
        return True
    try:
        with open(path, "rb") as handle:
            head = handle.read(64).lstrip()
    except OSError:
        return False
    return head.startswith(b"{")


def write_baseline(snapshot: BaselineSnapshot, path: Path) -> None:
    from .utils import safe_write_text

    safe_write_text(path, json.dumps(snapshot.to_dict(), indent=2), encoding="utf-8", context="baseline save")


# --- Comparing --------------------------------------------------------------


def _port_key(port: dict[str, object]) -> tuple[int, str, str, str]:
    return (
        int(port.get("port", 0) or 0),
        str(port.get("protocol", "") or ""),
        str(port.get("service", "") or ""),
        str(port.get("software", "") or ""),
    )


def _service_key(service: dict[str, object]) -> tuple[str, int, str]:
    return (
        str(service.get("ip", "") or ""),
        int(service.get("port", 0) or 0),
        str(service.get("protocol", "") or ""),
    )


def _flow_key(flow: dict[str, object]) -> tuple[str, str, str, int]:
    return (str(flow.get("client", "")), str(flow.get("server", "")), str(flow.get("transport", "")), int(flow.get("port", 0) or 0))


def _l2_key(flow: dict[str, object]) -> tuple[str, str, str]:
    return (str(flow.get("src_mac", "")), str(flow.get("dst_mac", "")), str(flow.get("protocol", "")))


def _command_key(item: dict[str, object]) -> tuple[str, str, str, str]:
    return (str(item.get("protocol", "")), str(item.get("src", "")), str(item.get("dst", "")), str(item.get("command", "")))


def describe_flow(flow: dict[str, object]) -> str:
    """``Modbus 502/tcp`` -- the protocol and where it was seen."""
    transport = str(flow.get("transport", "") or "")
    port = int(flow.get("port", 0) or 0)
    protocol = str(flow.get("protocol", "") or transport)
    if transport in ("TCP", "UDP") and port:
        where = f"{port}/{transport.lower()}"
        return where if protocol == f"{transport.lower()}/{port}" else f"{protocol} {where}"
    return protocol


def _per_minute(count: object, seconds: float) -> float:
    return float(count or 0) * 60.0 / seconds if seconds > 0 else 0.0


def _seconds(value: float) -> str:
    if value >= 1:
        return f"{value:.2f}s"
    return f"{value * 1000:.0f} ms"


def _known(value: object) -> str:
    text = str(value or "").strip()
    return "" if text.lower() in ("unknown", "-", "n/a", "none") else text


def _compare_hosts(current: BaselineSnapshot, baseline: BaselineSnapshot):
    base_hosts = {str(item.get("ip", "")): item for item in baseline.hosts}
    curr_hosts = {str(item.get("ip", "")): item for item in current.hosts}

    new_hosts = sorted([ip for ip in curr_hosts if ip and ip not in base_hosts])
    missing_hosts = sorted([ip for ip in base_hosts if ip and ip not in curr_hosts])
    host_changes: list[dict[str, object]] = []

    for ip, curr in curr_hosts.items():
        base = base_hosts.get(ip)
        if not base:
            continue
        changes: dict[str, object] = {"ip": ip}
        curr_hostnames = set(curr.get("hostnames", []) or [])
        base_hostnames = set(base.get("hostnames", []) or [])
        added_hostnames = sorted(curr_hostnames - base_hostnames)
        removed_hostnames = sorted(base_hostnames - curr_hostnames)
        if added_hostnames:
            changes["new_hostnames"] = added_hostnames
        if removed_hostnames:
            changes["missing_hostnames"] = removed_hostnames

        curr_macs = set(curr.get("macs", []) or [])
        base_macs = set(base.get("macs", []) or [])
        added_macs = sorted(curr_macs - base_macs)
        removed_macs = sorted(base_macs - curr_macs)
        if added_macs:
            changes["new_macs"] = added_macs
        if removed_macs:
            changes["missing_macs"] = removed_macs

        # A port is its number and protocol: a changed service name or
        # banner on the same port is a change to it, not one port closing
        # and another opening.
        curr_ports = {key[:2]: key for key in sorted(_port_key(p) for p in (curr.get("open_ports", []) or []))}
        base_ports = {key[:2]: key for key in sorted(_port_key(p) for p in (base.get("open_ports", []) or []))}
        added_ports = [curr_ports[k] for k in sorted(curr_ports.keys() - base_ports.keys())]
        removed_ports = [base_ports[k] for k in sorted(base_ports.keys() - curr_ports.keys())]
        relabelled = [
            {"port": k[0], "protocol": k[1], "from": list(base_ports[k][2:]), "to": list(curr_ports[k][2:])}
            for k in sorted(curr_ports.keys() & base_ports.keys())
            if curr_ports[k] != base_ports[k]
        ]
        if added_ports:
            changes["new_ports"] = added_ports
        if removed_ports:
            changes["missing_ports"] = removed_ports
        if relabelled:
            changes["port_changes"] = relabelled

        # "Unknown" is the absence of an OS guess, not a value to compare.
        base_os = _known(base.get("os"))
        curr_os = _known(curr.get("os"))
        if base_os and curr_os and base_os != curr_os:
            changes["os_change"] = {"from": base_os, "to": curr_os}

        if len(changes) > 1:
            host_changes.append(changes)
    return new_hosts, missing_hosts, host_changes


def _compare_services(current: BaselineSnapshot, baseline: BaselineSnapshot):
    base_services = {_service_key(item): item for item in baseline.services}
    curr_services = {_service_key(item): item for item in current.services}
    # Sorted: these came straight from set-difference iteration, so the
    # rendered delta changed order from run to run.
    new_services = [curr_services[key] for key in sorted(curr_services.keys() - base_services.keys())]
    missing_services = [base_services[key] for key in sorted(base_services.keys() - curr_services.keys())]
    service_changes: list[dict[str, object]] = []
    for key in sorted(curr_services.keys() & base_services.keys()):
        base = base_services[key]
        curr = curr_services[key]
        if str(base.get("service", "") or "") != str(curr.get("service", "") or "") or str(
            base.get("software", "") or ""
        ) != str(curr.get("software", "") or ""):
            service_changes.append(
                {
                    "ip": key[0],
                    "port": key[1],
                    "protocol": key[2],
                    "from_service": str(base.get("service", "") or ""),
                    "to_service": str(curr.get("service", "") or ""),
                    "from_software": str(base.get("software", "") or ""),
                    "to_software": str(curr.get("software", "") or ""),
                }
            )
    return new_services, missing_services, service_changes


def _compare_ot_command_totals(current: BaselineSnapshot, baseline: BaselineSnapshot):
    base_commands = Counter({str(k): int(v) for k, v in baseline.ot_commands.items()})
    curr_commands = Counter({str(k): int(v) for k, v in current.ot_commands.items()})
    new_ot_commands = sorted([cmd for cmd in curr_commands if cmd not in base_commands])
    missing_ot_commands = sorted([cmd for cmd in base_commands if cmd not in curr_commands])
    ot_command_changes: list[dict[str, object]] = []
    for cmd in sorted(curr_commands.keys() & base_commands.keys()):
        base_val = base_commands.get(cmd, 0)
        curr_val = curr_commands.get(cmd, 0)
        diff = curr_val - base_val
        if base_val == 0:
            continue
        if abs(diff) >= 5 and abs(diff) / max(base_val, 1) >= 0.5:
            ot_command_changes.append({"command": cmd, "baseline": base_val, "current": curr_val, "delta": diff})

    base_targets = {f"{proto}:{target}" for proto, targets in baseline.control_targets.items() for target in targets}
    curr_targets = {f"{proto}:{target}" for proto, targets in current.control_targets.items() for target in targets}
    return (
        new_ot_commands,
        missing_ot_commands,
        ot_command_changes,
        sorted(curr_targets - base_targets),
        sorted(base_targets - curr_targets),
    )


def _ot_hosts(*snapshots: BaselineSnapshot) -> set[str]:
    """Hosts on either end of an OT or IoT conversation in any snapshot."""
    hosts: set[str] = set()
    for snap in snapshots:
        for flow in snap.flows:
            if flow.get("category") in ("OT", "IoT"):
                hosts.add(str(flow.get("client", "")))
                hosts.add(str(flow.get("server", "")))
        for item in snap.pair_commands:
            hosts.add(str(item.get("src", "")))
            hosts.add(str(item.get("dst", "")))
    hosts.discard("")
    return hosts


def _dev(severity: str, summary: str, details: str, src: object = None, dst: object = None, kind: str = "", *,
         ts: object = None, until: object = None, attack: str = "", protocol: str = "", actors: object = None,
         background: bool = False) -> dict[str, object]:
    item: dict[str, object] = {"severity": severity, "summary": summary, "details": details, "kind": kind}
    if src:
        item["src"] = src
    if dst:
        item["dst"] = dst
    if ts:
        item["ts"] = ts
    if until:
        item["last_seen"] = until
    if attack:
        item["attack"] = attack
    if protocol:
        item["protocol"] = protocol
    if actors:
        item["actors"] = list(actors)
    if background:
        item["background"] = True
    return item


def _background_ip(value: object) -> bool:
    """Broadcast, multicast, link-local or unspecified: discovery and
    autoconfiguration chatter that comes and goes, not a host's behaviour."""
    text = str(value or "")
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False
    return addr.is_link_local or addr.is_unspecified or not is_unicast_host_ip(text)


def _ot_clients(snapshot: BaselineSnapshot) -> set[str]:
    """Hosts that acted as an OT/IoT client (master) in a snapshot."""
    clients = {str(f.get("client", "")) for f in snapshot.flows if f.get("category") in ("OT", "IoT")}
    clients |= {str(i.get("src", "")) for i in snapshot.pair_commands}
    clients.discard("")
    return clients


def _host_first_seen(snapshot: BaselineSnapshot) -> dict[str, float]:
    first: dict[str, float] = {}
    for flow in snapshot.flows:
        ts = flow.get("first_seen")
        if not ts:
            continue
        for ip in (flow.get("client"), flow.get("server")):
            if ip and (str(ip) not in first or float(ts) < first[str(ip)]):
                first[str(ip)] = float(ts)
    return first


def _compare_flows(current: BaselineSnapshot, baseline: BaselineSnapshot, deviations: list[dict[str, object]]):
    base = {_flow_key(f): f for f in baseline.flows}
    curr = {_flow_key(f): f for f in current.flows}
    ot_hosts = _ot_hosts(baseline, current)
    base_pairs = {(k[0], k[1]) for k in base} | {(k[1], k[0]) for k in base}
    base_masters = _ot_clients(baseline)

    new_flows = [curr[k] for k in sorted(curr.keys() - base.keys())]
    missing_flows = [base[k] for k in sorted(base.keys() - curr.keys())]
    flow_changes: list[dict[str, object]] = []

    for flow in new_flows:
        client, server = flow.get("client"), flow.get("server")
        category = str(flow.get("category", "other"))
        port = int(flow.get("port", 0) or 0)
        interval = flow.get("interval_median")
        what = f"{describe_flow(flow)}, {int(flow.get('packets', 0)):,} packets" + (
            f", every {_seconds(float(interval))}" if interval else "")
        known_pair = (client, server) in base_pairs
        seen = flow.get("first_seen")
        until = flow.get("last_seen")
        protocol = str(flow.get("protocol", "") or "")
        if _background_ip(client) or _background_ip(server):
            deviations.append(_dev("info", "Background chatter: new conversation", what, client, server, "flow",
                                   ts=seen, protocol=protocol, background=True))
        elif category == "OT":
            rogue = ATTACK_ROGUE_MASTER if client not in base_masters else ""
            if known_pair:
                deviations.append(_dev("high", "New OT protocol between known hosts", what, client, server, "flow",
                                       ts=seen, until=until, attack=rogue, protocol=protocol))
            else:
                deviations.append(_dev("high", "New OT communication pair", what, client, server, "flow",
                                       ts=seen, until=until, attack=rogue, protocol=protocol))
        elif category == "IoT":
            deviations.append(_dev("medium", "New IoT communication pair", what, client, server, "flow", ts=seen, until=until,
                                   protocol=protocol))
        elif client in ot_hosts or server in ot_hosts:
            on = server if server in ot_hosts else client
            if port in REMOTE_ADMIN_PORTS and flow.get("transport") in ("TCP", "UDP"):
                deviations.append(_dev("high", "Remote-access/file-transfer protocol on OT host", f"{what} (OT host {on})",
                                       client, server, "flow", ts=seen, until=until, attack=ATTACK_REMOTE_SERVICES,
                                       protocol=protocol))
            elif flow.get("transport") not in ("TCP", "UDP"):
                deviations.append(_dev("low", "New ICMP/IP-level traffic on OT host", f"{what} (OT host {on})", client, server, "flow",
                                       ts=seen, protocol=protocol))
            else:
                deviations.append(_dev("medium", "IT protocol on OT host", f"{what} (OT host {on})", client, server, "flow",
                                       ts=seen, protocol=protocol))
        else:
            deviations.append(_dev("low", "New conversation", what, client, server, "flow", ts=seen, protocol=protocol))

    current_seconds = current.duration_seconds
    for flow in missing_flows:
        category = str(flow.get("category", "other"))
        if _background_ip(flow.get("client")) or _background_ip(flow.get("server")):
            deviations.append(_dev("info", "Background chatter: conversation absent", describe_flow(flow), flow.get("client"),
                                   flow.get("server"), "flow", background=True))
            continue
        if category not in ("OT", "IoT"):
            deviations.append(_dev("info", "Conversation absent", describe_flow(flow), flow.get("client"), flow.get("server"), "flow"))
            continue
        interval = flow.get("interval_median")
        would_poll = (
            int(flow.get("packets", 0) or 0) >= 10
            and (not interval or current_seconds >= MISSING_INTERVALS * float(interval))
        )
        detail = describe_flow(flow)
        if interval:
            detail += f", polled every {_seconds(float(interval))} in the baseline"
        if would_poll:
            deviations.append(_dev("medium", f"{category} communication absent", detail, flow.get("client"), flow.get("server"), "flow",
                                   protocol=str(flow.get("protocol", "") or "")))
        else:
            deviations.append(_dev("info", f"{category} communication absent (capture too short to tell)", detail,
                                   flow.get("client"), flow.get("server"), "flow"))

    base_seconds = baseline.duration_seconds
    rates_comparable = base_seconds >= MIN_RATE_WINDOW_SECONDS and current_seconds >= MIN_RATE_WINDOW_SECONDS
    for key in sorted(curr.keys() & base.keys()):
        b, c = base[key], curr[key]
        change: dict[str, object] = {"flow": c}
        category = str(c.get("category", "other"))
        ot_like = category in ("OT", "IoT")
        if _background_ip(key[0]) or _background_ip(key[1]):
            continue  # discovery chatter's rate and cadence are not behaviour
        protocol = str(c.get("protocol", "") or "")
        if rates_comparable and int(b.get("packets", 0) or 0) >= MIN_RATE_PACKETS:
            b_rate = _per_minute(b.get("packets"), base_seconds)
            c_rate = _per_minute(c.get("packets"), current_seconds)
            if b_rate > 0 and (c_rate >= b_rate * RATE_CHANGE_FACTOR or c_rate <= b_rate / RATE_CHANGE_FACTOR):
                change["rate"] = {"baseline": round(b_rate, 2), "current": round(c_rate, 2)}
                flood = ot_like and c_rate >= b_rate * FLOOD_FACTOR
                deviations.append(_dev("high" if flood else ("medium" if ot_like else "low"),
                                       "OT traffic flood" if flood else "Traffic rate changed",
                                       f"{describe_flow(c)}: {b_rate:,.1f} -> {c_rate:,.1f} packets/min",
                                       key[0], key[1], "rate", attack=ATTACK_DOS if flood else "", protocol=protocol))
        b_med, c_med = b.get("interval_median"), c.get("interval_median")
        if (
            b_med and c_med
            and int(b.get("interval_samples", 0) or 0) >= MIN_CADENCE_SAMPLES
            and int(c.get("interval_samples", 0) or 0) >= MIN_CADENCE_SAMPLES
        ):
            b_med, c_med = float(b_med), float(c_med)
            ratio = c_med / b_med if b_med > 0 else 0.0
            if (ratio >= CADENCE_CHANGE_FACTOR or (ratio and ratio <= 1 / CADENCE_CHANGE_FACTOR)) and abs(c_med - b_med) >= CADENCE_MIN_DELTA_SECONDS:
                change["cadence"] = {"baseline": b_med, "current": c_med}
                faster = "faster" if c_med < b_med else "slower"
                deviations.append(_dev("medium" if ot_like else "low", f"Polling cadence changed ({faster})",
                                       f"{describe_flow(c)}: every {_seconds(b_med)} -> every {_seconds(c_med)}",
                                       key[0], key[1], "cadence", protocol=protocol))
            b_jit, c_jit = b.get("interval_jitter"), c.get("interval_jitter")
            if b_jit is not None and c_jit is not None and float(b_jit) <= REGULAR_JITTER and float(c_jit) >= IRREGULAR_JITTER:
                change["jitter"] = {"baseline": float(b_jit), "current": float(c_jit)}
                deviations.append(_dev("medium" if ot_like else "low", "Regular polling became irregular",
                                       f"{describe_flow(c)}: jitter {float(b_jit):.2f} -> {float(c_jit):.2f}",
                                       key[0], key[1], "cadence", protocol=protocol))
        if len(change) > 1:
            flow_changes.append(change)
    return new_flows, missing_flows, flow_changes


def _compare_l2(current: BaselineSnapshot, baseline: BaselineSnapshot, deviations: list[dict[str, object]]):
    base = {_l2_key(f): f for f in baseline.l2_flows}
    curr = {_l2_key(f): f for f in current.l2_flows}
    new_l2 = [curr[k] for k in sorted(curr.keys() - base.keys())]
    missing_l2 = [base[k] for k in sorted(base.keys() - curr.keys())]
    for flow in new_l2:
        protocol = str(flow.get("protocol", ""))
        sev = "low" if protocol in ("LLDP", "PTP") else "high"
        spoof = ATTACK_SPOOF_REPORTING if protocol in ("IEC 61850 GOOSE", "IEC 61850 SV") else ""
        deviations.append(_dev(sev, "New layer-2 industrial stream", f"{protocol}, {int(flow.get('packets', 0)):,} frames",
                               flow.get("src_mac"), flow.get("dst_mac"), "l2", ts=flow.get("first_seen"), attack=spoof,
                               protocol=protocol))
    for flow in missing_l2:
        protocol = str(flow.get("protocol", ""))
        sev = "info" if protocol in ("LLDP", "PTP") else "medium"
        deviations.append(_dev(sev, "Layer-2 industrial stream absent", protocol, flow.get("src_mac"), flow.get("dst_mac"), "l2"))
    return new_l2, missing_l2


def _compare_macs(current: BaselineSnapshot, baseline: BaselineSnapshot, deviations: list[dict[str, object]]):
    def macs_of(snap: BaselineSnapshot) -> dict[str, dict[str, str]]:
        return {ip: {str(e.get("mac", "")): str(e.get("vendor", "") or "") for e in entries if e.get("mac")}
                for ip, entries in snap.ip_macs.items()}

    base, curr = macs_of(baseline), macs_of(current)
    first_seen = {(ip, str(e.get("mac", ""))): e.get("first_seen") for ip, entries in current.ip_macs.items() for e in entries}
    last_seen = {(ip, str(e.get("mac", ""))): e.get("last_seen") for ip, entries in current.ip_macs.items() for e in entries}
    fronting: Counter[str] = Counter()
    for snap in (base, curr):
        for macs in snap.values():
            fronting.update(set(macs))
    changes: list[dict[str, object]] = []
    for ip in sorted(base.keys() & curr.keys()):
        new = {m: v for m, v in curr[ip].items() if m not in base[ip]}
        if not new:
            continue
        # A gateway MAC fronts every remote IP; a different gateway is routing.
        if all(fronting[m] >= GATEWAY_MAC_IPS for m in list(new) + list(base[ip])):
            continue
        still = [m for m in curr[ip] if m in base[ip]]
        change = {"ip": ip, "baseline": base[ip], "current": curr[ip]}
        changes.append(change)

        def _label(mac: str, vendor: str) -> str:
            # The other addresses this MAC sends from: an ARP spoofer's own IP.
            others = sorted(o for o, macs in curr.items() if mac in macs and o != ip)
            extra = [vendor] if vendor else []
            if others:
                extra.append("also " + ", ".join(others[:3]) + (f" +{len(others) - 3}" if len(others) > 3 else ""))
            return f"{mac} ({'; '.join(extra)})" if extra else mac

        new_text = ", ".join(_label(m, v) for m, v in new.items())
        old_text = ", ".join(f"{m} ({v})" if v else m for m, v in base[ip].items())
        spoofers = sorted({o for m in new for o, macs in curr.items() if m in macs and o != ip})
        seen = min((float(first_seen[(ip, m)]) for m in new if first_seen.get((ip, m))), default=None)
        until = max((float(last_seen[(ip, m)]) for m in new if last_seen.get((ip, m))), default=None)
        change["actors"] = spoofers
        if still:
            deviations.append(_dev("high", "IP address seen from an additional MAC",
                                   f"{new_text} alongside baseline {old_text}: possible ARP spoofing or duplicate IP",
                                   ip, None, "identity", ts=seen, until=until, attack=ATTACK_AITM, actors=spoofers))
        else:
            deviations.append(_dev("high", "IP address moved to a different MAC",
                                   f"was {old_text}, now {new_text}: device replaced or impersonated",
                                   ip, None, "identity", ts=seen, until=until, attack=ATTACK_AITM, actors=spoofers))
    return changes


def _compare_pair_commands(current: BaselineSnapshot, baseline: BaselineSnapshot, deviations: list[dict[str, object]]):
    base = {_command_key(i): i for i in baseline.pair_commands}
    curr = {_command_key(i): i for i in current.pair_commands}
    base_writers = {(k[0], k[1], k[2]) for k, i in base.items() if i.get("write")}
    # Writes first, then the busiest: what an analyst reads first.
    def _rank(items: dict, key: tuple) -> tuple:
        return (not items[key].get("write"), -int(items[key].get("count", 0) or 0), key)

    new_items = [curr[k] for k in sorted(curr.keys() - base.keys(), key=lambda k: _rank(curr, k))]
    missing_items = [base[k] for k in sorted(base.keys() - curr.keys(), key=lambda k: _rank(base, k))]
    changes: list[dict[str, object]] = []

    for item in new_items:
        proto, src, dst, command = _command_key(item)
        count = int(item.get("count", 0) or 0)
        seen = item.get("first_seen")
        until = item.get("last_seen")
        if item.get("write"):
            attack = ATTACK_UNAUTH_COMMAND + (f"; {ATTACK_MODIFY_PARAMETER}" if "write" in command.lower() else "")
            if (proto, src, dst) not in base_writers:
                deviations.append(_dev("high", "New writer to OT device",
                                       f"{proto} {command} (x{count}); this pair never wrote in the baseline",
                                       src, dst, "command", ts=seen, until=until, attack=attack, protocol=proto))
            else:
                deviations.append(_dev("high", "New OT write/control command", f"{proto} {command} (x{count})", src, dst, "command",
                                       ts=seen, until=until, attack=attack, protocol=proto))
        else:
            deviations.append(_dev("low", "New OT read/diagnostic command", f"{proto} {command} (x{count})", src, dst, "command",
                                   ts=seen, protocol=proto))
    for item in missing_items:
        proto, src, dst, command = _command_key(item)
        deviations.append(_dev("info", "OT command absent", f"{proto} {command}", src, dst, "command"))

    base_seconds, current_seconds = baseline.duration_seconds, current.duration_seconds
    if base_seconds >= MIN_RATE_WINDOW_SECONDS and current_seconds >= MIN_RATE_WINDOW_SECONDS:
        for key in sorted(curr.keys() & base.keys()):
            b, c = base[key], curr[key]
            if not c.get("write") or int(b.get("count", 0) or 0) < 5:
                continue
            b_rate = _per_minute(b.get("count"), base_seconds)
            c_rate = _per_minute(c.get("count"), current_seconds)
            if b_rate > 0 and (c_rate >= b_rate * RATE_CHANGE_FACTOR or c_rate <= b_rate / RATE_CHANGE_FACTOR):
                changes.append({"item": c, "baseline_per_min": round(b_rate, 2), "current_per_min": round(c_rate, 2)})
                burst = c_rate >= b_rate * FLOOD_FACTOR
                deviations.append(_dev("high" if burst else "medium", "OT write/control rate changed",
                                       f"{key[0]} {key[3]}: {b_rate:,.1f} -> {c_rate:,.1f} per min", key[1], key[2], "command",
                                       attack=ATTACK_BRUTE_IO if burst else "", protocol=key[0]))
    return new_items, missing_items, changes


def _register_key(item: dict[str, object]) -> tuple:
    return (str(item.get("server", "")), int(item.get("unit", 0) or 0), str(item.get("type", "")),
            int(item.get("address", 0) or 0))


def _register_name(key: tuple) -> str:
    return f"unit {key[1]} {key[2]}[{key[3]}]"


def _span(low: int, high: int) -> str:
    return str(low) if low == high else f"{low}..{high}"


def _compare_registers(current: BaselineSnapshot, baseline: BaselineSnapshot, deviations: list[dict[str, object]]):
    """Values a register never held in the baseline: a constant that moved,
    or a reading beyond the baseline range (a process upset, or a value
    rewritten in transit). Registers new to a known server are noted."""
    if not baseline.registers:
        return []  # no Modbus values recorded: nothing to hold the capture to
    base = {_register_key(r): r for r in baseline.registers}
    curr = {_register_key(r): r for r in current.registers}
    changes: list[dict[str, object]] = []
    for key in sorted(curr.keys() & base.keys()):
        b, c = base[key], curr[key]
        if int(b.get("samples", 0) or 0) < MIN_REGISTER_SAMPLES or int(c.get("samples", 0) or 0) < MIN_REGISTER_SAMPLES:
            continue
        bmin, bmax = int(b.get("min", 0)), int(b.get("max", 0))
        cmin, cmax = int(c.get("min", 0)), int(c.get("max", 0))
        if bmin == bmax:
            if cmin == cmax == bmin:
                continue
            summary, severity = "Constant register changed value", "high"
            detail = f"{_register_name(key)}: always {bmin} in the baseline, now {_span(cmin, cmax)}"
        else:
            margin = max(1.0, (bmax - bmin) * REGISTER_RANGE_MARGIN)
            if cmin >= bmin - margin and cmax <= bmax + margin:
                continue
            summary, severity = "Register value outside baseline range", "medium"
            detail = f"{_register_name(key)}: baseline {_span(bmin, bmax)}, now {_span(cmin, cmax)}"
        changes.append({"register": c, "baseline": [bmin, bmax], "current": [cmin, cmax]})
        # When the value first left the baseline: the first time the
        # offending extreme was seen.
        stamps = []
        if cmin < bmin and c.get("min_first_seen"):
            stamps.append(float(c["min_first_seen"]))
        if cmax > bmax and c.get("max_first_seen"):
            stamps.append(float(c["max_first_seen"]))
        deviations.append(_dev(severity, summary, detail, None, key[0], "register", ts=min(stamps) if stamps else None,
                               attack=ATTACK_MANIPULATION, protocol="Modbus"))
    known_servers = {k[0] for k in base}
    for key in sorted(curr.keys() - base.keys()):
        if key[0] in known_servers:
            deviations.append(_dev("low", "Register not seen in the baseline", _register_name(key), None, key[0], "register"))
    return changes


def _inventory_deviations(delta_parts: dict[str, list], ot_hosts: set[str], deviations: list[dict[str, object]],
                          first_seen: dict[str, float] | None = None) -> None:
    first_seen = first_seen or {}
    for ip in delta_parts["new_hosts"]:
        if _background_ip(ip):
            deviations.append(_dev("info", "Background chatter: new host", "", ip, None, "host", ts=first_seen.get(ip), background=True))
        else:
            deviations.append(_dev("medium", "New host", "", ip, None, "host", ts=first_seen.get(ip)))
    for ip in delta_parts["missing_hosts"]:
        if _background_ip(ip):
            deviations.append(_dev("info", "Background chatter: host absent", "", ip, None, "host", background=True))
        else:
            deviations.append(_dev("info", "Host absent", "", ip, None, "host"))
    for change in delta_parts["host_changes"]:
        ip = str(change.get("ip", ""))
        os_change = change.get("os_change")
        if isinstance(os_change, dict):
            deviations.append(_dev("medium", "Host OS changed", f"{os_change.get('from')} -> {os_change.get('to')}", ip, None, "host"))
    for svc in delta_parts["new_services"]:
        ip = str(svc.get("ip", ""))
        sev = "high" if ip in ot_hosts else "medium"
        name = svc.get("service") or "service"
        deviations.append(_dev(sev, "New service", f"{ip}:{svc.get('port')}/{str(svc.get('protocol', '')).lower()} {name}", None, ip, "service",
                               ts=first_seen.get(ip)))
    for svc in delta_parts["service_changes"]:
        ip = str(svc.get("ip", ""))
        was = " ".join(v for v in (svc.get("from_service"), svc.get("from_software")) if v) or "-"
        now = " ".join(v for v in (svc.get("to_service"), svc.get("to_software")) if v) or "-"
        deviations.append(_dev("medium", "Service software changed", f"{ip}:{svc.get('port')} {was} -> {now}", None, ip, "service"))


def compare_baseline(current: BaselineSnapshot, baseline: BaselineSnapshot) -> BaselineDelta:
    new_hosts, missing_hosts, host_changes = _compare_hosts(current, baseline)
    new_services, missing_services, service_changes = _compare_services(current, baseline)
    (new_ot_commands, missing_ot_commands, ot_command_changes,
     new_control_targets, missing_control_targets) = _compare_ot_command_totals(current, baseline)

    notes = list(dict.fromkeys(baseline.notes + current.notes))
    deviations: list[dict[str, object]] = []
    new_flows: list[dict[str, object]] = []
    missing_flows: list[dict[str, object]] = []
    flow_changes: list[dict[str, object]] = []
    new_l2: list[dict[str, object]] = []
    missing_l2: list[dict[str, object]] = []
    mac_changes: list[dict[str, object]] = []
    new_cmds: list[dict[str, object]] = []
    missing_cmds: list[dict[str, object]] = []
    cmd_changes: list[dict[str, object]] = []
    register_changes: list[dict[str, object]] = []

    profiled = baseline.has_profile and current.has_profile
    if profiled:
        new_flows, missing_flows, flow_changes = _compare_flows(current, baseline, deviations)
        new_l2, missing_l2 = _compare_l2(current, baseline, deviations)
        mac_changes = _compare_macs(current, baseline, deviations)
        new_cmds, missing_cmds, cmd_changes = _compare_pair_commands(current, baseline, deviations)
        register_changes = _compare_registers(current, baseline, deviations)
        if baseline.ot_command_mode and current.ot_command_mode and baseline.ot_command_mode != current.ot_command_mode:
            notes.append(
                f"OT commands were scanned in {baseline.ot_command_mode} mode for the baseline and {current.ot_command_mode} "
                "mode now; fast mode sees fewer protocols, so command differences may be the mode, not the network."
            )
        for snap, label in ((baseline, "baseline"), (current, "current")):
            if 0 < snap.duration_seconds < MIN_RATE_WINDOW_SECONDS:
                notes.append(
                    f"The {label} capture spans {snap.duration_seconds:.0f} s; rates and command volumes are compared "
                    f"only when both span at least {MIN_RATE_WINDOW_SECONDS:.0f} s."
                )
    else:
        notes.append(
            "The baseline predates the communication profile (schema 1): conversations, polling cadence, per-pair "
            "commands and MAC bindings are not compared. Re-create it with --baseline to compare them."
        )

    _inventory_deviations(
        {"new_hosts": new_hosts, "missing_hosts": missing_hosts, "host_changes": host_changes,
         "new_services": new_services, "service_changes": service_changes},
        _ot_hosts(baseline, current),
        deviations,
        _host_first_seen(current),
    )
    if not profiled:
        for cmd in new_ot_commands:
            deviations.append(_dev("high", "New OT write/control command", cmd, None, None, "command"))
        for target in new_control_targets:
            deviations.append(_dev("high", "New OT control target", target, None, None, "command"))

    return BaselineDelta(
        baseline_version=baseline.pcapper_version,
        current_version=current.pcapper_version,
        new_hosts=new_hosts,
        missing_hosts=missing_hosts,
        host_changes=host_changes,
        new_services=new_services,
        missing_services=missing_services,
        service_changes=service_changes,
        new_ot_commands=new_ot_commands,
        missing_ot_commands=missing_ot_commands,
        ot_command_changes=ot_command_changes,
        new_control_targets=new_control_targets,
        missing_control_targets=missing_control_targets,
        notes=notes,
        baseline_sources=list(baseline.sources),
        current_sources=list(current.sources),
        baseline_capture=dict(baseline.capture),
        current_capture=dict(current.capture),
        new_flows=new_flows,
        missing_flows=missing_flows,
        flow_changes=flow_changes,
        new_l2_flows=new_l2,
        missing_l2_flows=missing_l2,
        new_pair_commands=new_cmds,
        missing_pair_commands=missing_cmds,
        pair_command_changes=cmd_changes,
        mac_changes=mac_changes,
        register_changes=register_changes,
        deviations=deviations,
        incidents=correlate_incidents(deviations, set(new_hosts), _ot_clients(baseline)),
    )


# --- Correlation ------------------------------------------------------------


_CONTROL = {"New OT communication pair", "New OT protocol between known hosts", "New writer to OT device",
            "New OT write/control command", "OT write/control rate changed", "OT traffic flood"}
_WRITES = {"New writer to OT device", "New OT write/control command", "OT write/control rate changed"}


def _incident(title: str, actor: object, targets: list, members: list[int], deviations: list[dict[str, object]]) -> dict[str, object]:
    items = [deviations[i] for i in sorted(members)]
    worst = max(items, key=lambda d: _SEV.get(str(d.get("severity")), 0))
    stamps = [float(d["ts"]) for d in items if d.get("ts")]
    ends = stamps + [float(d["last_seen"]) for d in items if d.get("last_seen")]
    attacks: list[str] = []
    for d in items:
        for technique in str(d.get("attack", "") or "").split("; "):
            if technique and technique not in attacks:
                attacks.append(technique)
    attacks.sort(key=lambda t: (_ATTACK_ORDER.index(t[:5]) if t[:5] in _ATTACK_ORDER else len(_ATTACK_ORDER), t))
    protocols = sorted({str(d.get("protocol")) for d in items if d.get("protocol")})
    return {
        "severity": worst.get("severity"),
        "title": title,
        "actor": actor,
        "targets": [t for t in targets if t],
        "first_seen": min(stamps) if stamps else None,
        "last_seen": max(ends) if ends else None,
        "attack": "; ".join(attacks),
        "members": sorted(members),
        "protocols": protocols,
        "pivots": _pivots(actor, [t for t in targets if t], items, protocols),
    }


_SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# How an incident lists its techniques: who acted, what they sent, how they
# got there, what it did to the process.
_ATTACK_ORDER = ["T0848", "T0855", "T0836", "T0830", "T0856", "T0886", "T0806", "T0814", "T0831", "T0832"]


def _pivots(actor: object, targets: list, items: list[dict[str, object]], protocols: list[str]) -> list[list[str]]:
    """pcapper flags for the next look at an incident: the protocols it
    involves, the actor's dossier and timeline, ARP for identity changes."""
    pivots: list[list[str]] = []
    flags = sorted({PROTOCOL_FLAGS[p] for p in protocols if p in PROTOCOL_FLAGS})
    kinds = {d.get("kind") for d in items}
    if "register" in kinds and "--modbus" in flags:
        flags.append("--control-loop")
    if "identity" in kinds:
        flags.insert(0, "--arp")
    if flags:
        pivots.append(flags)
    for host in [actor, *targets][:2]:
        if host and is_unicast_host_ip(str(host)):
            pivots.append(["--hostdetails", "-ip", str(host)])
    if actor and is_unicast_host_ip(str(actor)):
        pivots.append(["--timeline", "-ip", str(actor)])
    return pivots


def correlate_incidents(deviations: list[dict[str, object]], new_hosts: set[str], base_masters: set[str]) -> list[dict[str, object]]:
    """Group deviations into what happened, by the host that did it.

    Fixed rules, in this order (a deviation joins one incident at most):
    control activity per source -- a rogue master when the source never
    acted as an OT client in the baseline -- with the process values that
    changed on its targets; identity changes, attributed to the IP that sent
    from the intruding MAC; remote access to an OT host; process values that
    changed with no new writer to explain them; OT conversations gone silent.
    """
    claimed: set[int] = set()
    incidents: list[dict[str, object]] = []

    def free(i: int) -> bool:
        return i not in claimed and not deviations[i].get("background")

    # 1. Control activity per source.
    by_src: dict[str, list[int]] = defaultdict(list)
    for i, d in enumerate(deviations):
        if d.get("summary") in _CONTROL and d.get("src") and free(i):
            by_src[str(d["src"])].append(i)
    for actor, idx in sorted(by_src.items()):
        members = set(idx)
        targets = sorted({str(deviations[i].get("dst")) for i in idx if deviations[i].get("dst")})
        writes = any(deviations[i].get("summary") in _WRITES for i in idx)
        for j, d in enumerate(deviations):
            if j in members or not free(j):
                continue
            if d.get("kind") in ("host", "flow", "rate", "cadence") and d.get("src") == actor:
                members.add(j)
            elif writes and d.get("kind") == "register" and d.get("dst") in targets:
                members.add(j)
        if actor in new_hosts or actor not in base_masters:
            title = f"Rogue OT master {actor}" + (" writing to " + ", ".join(targets[:3]) if writes and targets else "")
        elif writes:
            title = f"New control activity from {actor} to " + ", ".join(targets[:3])
        else:
            title = f"New OT access from {actor} to " + ", ".join(targets[:3])
        claimed |= members
        incidents.append(_incident(title, actor, targets, sorted(members), deviations))

    # 2. Identity: an IP sending from another device's MAC.
    for i, d in enumerate(deviations):
        if d.get("kind") != "identity" or not free(i):
            continue
        victim = str(d.get("src", ""))
        actors = [str(a) for a in d.get("actors") or []]
        members = {i}
        for j, other in enumerate(deviations):
            if free(j) and j != i and other.get("kind") in ("host", "flow") and other.get("src") in actors:
                members.add(j)
        title = (f"Adversary-in-the-middle: {actors[0]} impersonating {victim}" if actors
                 else f"{victim} answered from an unknown MAC")
        claimed |= members
        incidents.append(_incident(title, actors[0] if actors else None, [victim], sorted(members), deviations))

    # 3. Remote access to OT hosts, per source.
    remote: dict[str, list[int]] = defaultdict(list)
    for i, d in enumerate(deviations):
        if d.get("summary") == "Remote-access/file-transfer protocol on OT host" and free(i):
            remote[str(d.get("src", ""))].append(i)
    for actor, idx in sorted(remote.items()):
        members = set(idx) | {j for j, d in enumerate(deviations) if free(j) and d.get("kind") == "host" and d.get("src") == actor}
        targets = sorted({str(deviations[i].get("dst")) for i in idx})
        claimed |= members
        incidents.append(_incident(f"Remote access to OT asset {', '.join(targets[:3])} from {actor}", actor, targets,
                                   sorted(members), deviations))

    # 4. Process values that moved with no new writer behind them.
    by_server: dict[str, list[int]] = defaultdict(list)
    for i, d in enumerate(deviations):
        if d.get("kind") == "register" and d.get("severity") in ("high", "medium") and free(i):
            by_server[str(d.get("dst", ""))].append(i)
    for server, idx in sorted(by_server.items()):
        claimed |= set(idx)
        incidents.append(_incident(f"Process values changed on {server} (no new writer seen)", None, [server], idx, deviations))

    # 5. OT conversations gone silent, per server.
    silent: dict[str, list[int]] = defaultdict(list)
    for i, d in enumerate(deviations):
        if str(d.get("summary", "")).endswith("communication absent") and d.get("severity") == "medium" and free(i):
            silent[str(d.get("dst", ""))].append(i)
    for server, idx in sorted(silent.items()):
        claimed |= set(idx)
        incidents.append(_incident(f"OT communication lost with {server}", None, [server], idx, deviations))

    # Worst first; among equals, the best corroborated (most high-severity
    # deviations behind it), then the earliest.
    def _rank(inc: dict[str, object]) -> tuple:
        highs = sum(1 for i in inc["members"] if deviations[i].get("severity") in ("high", "critical"))  # type: ignore[union-attr]
        return (-_SEV.get(str(inc["severity"]), 0), -highs, inc["first_seen"] or float("inf"), inc["title"])

    incidents.sort(key=_rank)
    return incidents


# --- Loading ----------------------------------------------------------------


def load_baseline(path: Path) -> BaselineSnapshot:
    """Load a saved snapshot; every failure surfaces as ValueError with the path.

    A baseline is analyst-authored JSON, so a hand edit that leaves a count as
    a string or drops a table must produce a message naming the file, not a
    traceback out of ``int()`` three calls deep.
    """
    raw = safe_read_text(path, error_list=None, context="baseline read")
    if not raw:
        raise ValueError(f"Baseline file is empty or unreadable: {path}")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Baseline file is not valid JSON: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"Baseline file root is not an object: {path}")
    try:
        return _baseline_from_dict(data)
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError(f"Baseline file has an unexpected shape: {path}: {exc}") from exc


def _dict_list(value: object, name: str) -> list[dict[str, object]]:
    items = list(value or [])
    for item in items:
        if not isinstance(item, dict):
            raise ValueError(f"{name} entries must be objects")
    return items


def _baseline_from_dict(data: dict) -> BaselineSnapshot:
    schema = int(data.get("schema_version") or 1)
    ip_macs_raw = data.get("ip_macs") or {}
    if not isinstance(ip_macs_raw, dict):
        raise ValueError("ip_macs must be an object")
    return BaselineSnapshot(
        created_at=str(data.get("created_at") or ""),
        pcapper_version=str(data.get("pcapper_version") or ""),
        sources=[str(item) for item in (data.get("sources") or [])],
        hosts=_dict_list(data.get("hosts"), "hosts"),
        services=_dict_list(data.get("services"), "services"),
        ot_commands={str(k): int(v) for k, v in (data.get("ot_commands") or {}).items()},
        control_targets={
            str(proto): {str(target): int(count) for target, count in (targets or {}).items()}
            for proto, targets in (data.get("control_targets") or {}).items()
        },
        notes=list(data.get("notes") or []),
        schema_version=schema,
        capture=dict(data.get("capture") or {}),
        flows=_dict_list(data.get("flows"), "flows"),
        l2_flows=_dict_list(data.get("l2_flows"), "l2_flows"),
        ip_macs={str(ip): _dict_list(entries, "ip_macs") for ip, entries in ip_macs_raw.items()},
        pair_commands=_dict_list(data.get("pair_commands"), "pair_commands"),
        ot_command_mode=str(data.get("ot_command_mode") or ""),
        registers=_dict_list(data.get("registers"), "registers"),
    )
