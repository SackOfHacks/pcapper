from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from collections import Counter

from .hosts import HostSummary, merge_hosts_summaries
from .services import ServiceSummary, merge_services_summaries
from .ot_commands import OtCommandSummary
from .utils import safe_read_text


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

    def to_dict(self) -> dict[str, object]:
        return {
            "created_at": self.created_at,
            "pcapper_version": self.pcapper_version,
            "sources": list(self.sources),
            "hosts": self.hosts,
            "services": self.services,
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

    @property
    def has_changes(self) -> bool:
        return any(
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


def _merge_ot_commands(summaries: Iterable[OtCommandSummary]) -> OtCommandSummary | None:
    summary_list = [item for item in summaries if item is not None]
    if not summary_list:
        return None

    command_counts: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    destinations: Counter[str] = Counter()
    command_sessions: Counter[str] = Counter()
    command_session_times: dict[str, tuple[float | None, float | None]] = {}
    control_targets: dict[str, Counter[str]] = {}
    detections: list[dict[str, object]] = []
    errors: list[str] = []
    fast_mode = False
    fast_notes: list[str] = []

    for summary in summary_list:
        command_counts.update(getattr(summary, "command_counts", Counter()))
        sources.update(getattr(summary, "sources", Counter()))
        destinations.update(getattr(summary, "destinations", Counter()))
        command_sessions.update(getattr(summary, "command_sessions", Counter()))
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
    )


def build_baseline(
    pcapper_version: str,
    sources: list[str],
    host_summaries: Iterable[HostSummary],
    service_summaries: Iterable[ServiceSummary],
    ot_summaries: Iterable[OtCommandSummary],
) -> BaselineSnapshot:
    created_at = datetime.now(timezone.utc).isoformat()
    notes: list[str] = []

    host_summary = merge_hosts_summaries(list(host_summaries)) if host_summaries else None
    service_summary = merge_services_summaries(list(service_summaries)) if service_summaries else None
    ot_summary = _merge_ot_commands(list(ot_summaries)) if ot_summaries else None

    hosts: list[dict[str, object]] = []
    services: list[dict[str, object]] = []
    ot_commands: dict[str, int] = {}
    control_targets: dict[str, dict[str, int]] = {}

    if host_summary and host_summary.hosts:
        for host in host_summary.hosts:
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
        notes.append("Host inventory unavailable (enable --hosts).")

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
    else:
        notes.append("Service inventory unavailable (enable --services).")

    if ot_summary:
        ot_commands = {str(k): int(v) for k, v in (ot_summary.command_counts or {}).items()}
        control_targets = {
            str(proto): {str(target): int(count) for target, count in targets.items()}
            for proto, targets in (ot_summary.control_targets or {}).items()
        }
    else:
        notes.append("OT command inventory unavailable (enable --ot-commands).")

    return BaselineSnapshot(
        created_at=created_at,
        pcapper_version=pcapper_version,
        sources=sources,
        hosts=hosts,
        services=services,
        ot_commands=ot_commands,
        control_targets=control_targets,
        notes=notes,
    )


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


def compare_baseline(current: BaselineSnapshot, baseline: BaselineSnapshot) -> BaselineDelta:
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

        curr_ports = {_port_key(p) for p in (curr.get("open_ports", []) or [])}
        base_ports = {_port_key(p) for p in (base.get("open_ports", []) or [])}
        added_ports = sorted(curr_ports - base_ports)
        removed_ports = sorted(base_ports - curr_ports)
        if added_ports:
            changes["new_ports"] = added_ports
        if removed_ports:
            changes["missing_ports"] = removed_ports

        base_os = str(base.get("os", "") or "")
        curr_os = str(curr.get("os", "") or "")
        if base_os and curr_os and base_os != curr_os:
            changes["os_change"] = {"from": base_os, "to": curr_os}

        if len(changes) > 1:
            host_changes.append(changes)

    base_services = { _service_key(item): item for item in baseline.services }
    curr_services = { _service_key(item): item for item in current.services }

    new_services = [curr_services[key] for key in curr_services.keys() - base_services.keys()]
    missing_services = [base_services[key] for key in base_services.keys() - curr_services.keys()]
    service_changes: list[dict[str, object]] = []
    for key in curr_services.keys() & base_services.keys():
        base = base_services[key]
        curr = curr_services[key]
        if (
            str(base.get("service", "") or "") != str(curr.get("service", "") or "")
            or str(base.get("software", "") or "") != str(curr.get("software", "") or "")
        ):
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

    base_commands = Counter({str(k): int(v) for k, v in baseline.ot_commands.items()})
    curr_commands = Counter({str(k): int(v) for k, v in current.ot_commands.items()})
    new_ot_commands = sorted([cmd for cmd in curr_commands if cmd not in base_commands])
    missing_ot_commands = sorted([cmd for cmd in base_commands if cmd not in curr_commands])
    ot_command_changes: list[dict[str, object]] = []
    for cmd in curr_commands.keys() & base_commands.keys():
        base_val = base_commands.get(cmd, 0)
        curr_val = curr_commands.get(cmd, 0)
        diff = curr_val - base_val
        if base_val == 0:
            continue
        if abs(diff) >= 5 and abs(diff) / max(base_val, 1) >= 0.5:
            ot_command_changes.append(
                {"command": cmd, "baseline": base_val, "current": curr_val, "delta": diff}
            )

    base_targets = set()
    for proto, targets in baseline.control_targets.items():
        for target in targets.keys():
            base_targets.add(f"{proto}:{target}")
    curr_targets = set()
    for proto, targets in current.control_targets.items():
        for target in targets.keys():
            curr_targets.add(f"{proto}:{target}")

    new_control_targets = sorted(curr_targets - base_targets)
    missing_control_targets = sorted(base_targets - curr_targets)

    notes = list(dict.fromkeys(baseline.notes + current.notes))
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
    )


def load_baseline(path: Path) -> BaselineSnapshot:
    raw = safe_read_text(path, error_list=None, context="baseline read")
    if not raw:
        raise ValueError(f"Baseline file is empty: {path}")
    import json
    data = json.loads(raw)
    return BaselineSnapshot(
        created_at=str(data.get("created_at") or ""),
        pcapper_version=str(data.get("pcapper_version") or ""),
        sources=[str(item) for item in (data.get("sources") or [])],
        hosts=list(data.get("hosts") or []),
        services=list(data.get("services") or []),
        ot_commands={str(k): int(v) for k, v in (data.get("ot_commands") or {}).items()},
        control_targets={
            str(proto): {str(target): int(count) for target, count in (targets or {}).items()}
            for proto, targets in (data.get("control_targets") or {}).items()
        },
        notes=list(data.get("notes") or []),
    )
