from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
import json
import csv
import sqlite3

from .utils import to_serializable, safe_write_text, redact_data


@dataclass
class ExportBundle:
    path: Path
    summaries: dict[str, Any]


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def export_json(bundle: ExportBundle, output_path: Path, *, redact: bool = True) -> None:
    _ensure_parent(output_path)
    payload = {
        "path": str(bundle.path),
        "summaries": {name: to_serializable(summary) for name, summary in bundle.summaries.items()},
    }
    if redact:
        payload = redact_data(payload)
    safe_write_text(output_path, json.dumps(payload, indent=2), encoding="utf-8", context="export_json")


def _iter_detections(summary: Any) -> Iterable[dict[str, Any]]:
    detections = getattr(summary, "detections", None)
    if isinstance(detections, list):
        for item in detections:
            if isinstance(item, dict):
                yield item

    anomalies = getattr(summary, "anomalies", None)
    if isinstance(anomalies, list):
        for item in anomalies:
            if hasattr(item, "__dict__"):
                payload = to_serializable(item)
                if isinstance(payload, dict):
                    yield payload


def _iter_artifacts(summary: Any) -> Iterable[dict[str, Any]]:
    artifacts = getattr(summary, "artifacts", None)
    if isinstance(artifacts, list):
        for item in artifacts:
            if hasattr(item, "__dict__"):
                payload = to_serializable(item)
                if isinstance(payload, dict):
                    yield payload
            elif isinstance(item, str):
                yield {"detail": item}


def _iter_hosts(summary: Any) -> Iterable[Any]:
    hosts = getattr(summary, "hosts", None)
    if isinstance(hosts, list):
        for host in hosts:
            yield host


def _csv_safe(value: Any) -> Any:
    if isinstance(value, str):
        stripped = value.lstrip()
        if stripped and stripped[0] in ("=", "+", "-", "@"):
            return "'" + value
    return value


def export_csv(bundle: ExportBundle, output_path: Path, *, redact: bool = True) -> None:
    _ensure_parent(output_path)
    rows: list[dict[str, Any]] = []
    host_rows: list[dict[str, Any]] = []
    for name, summary in bundle.summaries.items():
        for item in _iter_detections(summary):
            row = {"category": "detection", "module": name}
            row.update(to_serializable(item))
            if redact:
                row = redact_data(row)
            rows.append({key: _csv_safe(value) for key, value in row.items()})
        for item in _iter_artifacts(summary):
            row = {"category": "artifact", "module": name}
            row.update(to_serializable(item))
            if redact:
                row = redact_data(row)
            rows.append({key: _csv_safe(value) for key, value in row.items()})
        for host in _iter_hosts(summary):
            open_ports = []
            for port in getattr(host, "open_ports", []) or []:
                open_ports.append({
                    "port": int(getattr(port, "port", 0) or 0),
                    "protocol": str(getattr(port, "protocol", "") or ""),
                    "service": str(getattr(port, "service", "") or ""),
                    "software": str(getattr(port, "software", "") or ""),
                })
            row = {
                "category": "host",
                "module": name,
                "pcap_path": str(bundle.path),
                "ip": str(getattr(host, "ip", "") or ""),
                "macs": ", ".join(getattr(host, "mac_addresses", []) or []),
                "hostnames": ", ".join(getattr(host, "hostnames", []) or []),
                "operating_system": str(getattr(host, "operating_system", "") or ""),
                "os_evidence": " | ".join(getattr(host, "os_evidence", []) or []),
                "packets_sent": int(getattr(host, "packets_sent", 0) or 0),
                "packets_recv": int(getattr(host, "packets_recv", 0) or 0),
                "bytes_sent": int(getattr(host, "bytes_sent", 0) or 0),
                "bytes_recv": int(getattr(host, "bytes_recv", 0) or 0),
                "first_seen": getattr(host, "first_seen", None),
                "last_seen": getattr(host, "last_seen", None),
                "open_ports": json.dumps(open_ports),
            }
            if redact:
                row = redact_data(row)
            host_rows.append({key: _csv_safe(value) for key, value in row.items()})

    if not rows:
        safe_write_text(output_path, "", encoding="utf-8", context="export_csv")
    else:
        fieldnames = sorted({key for row in rows for key in row.keys()})
        with output_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)

    if host_rows:
        host_path = output_path.with_name(f"{output_path.stem}_hosts{output_path.suffix or '.csv'}")
        _ensure_parent(host_path)
        host_fields = sorted({key for row in host_rows for key in row.keys()})
        with host_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=host_fields)
            writer.writeheader()
            for row in host_rows:
                writer.writerow(row)


def export_sqlite(bundle: ExportBundle, output_path: Path, *, redact: bool = True) -> None:
    _ensure_parent(output_path)
    if output_path.exists():
        if output_path.is_dir():
            raise ValueError(f"SQLite export path is a directory: {output_path}")
        output_path.unlink()
    conn = sqlite3.connect(str(output_path))
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE detections (module TEXT, data TEXT)"
    )
    cur.execute(
        "CREATE TABLE artifacts (module TEXT, data TEXT)"
    )
    cur.execute(
        "CREATE TABLE hosts (pcap_path TEXT, module TEXT, ip TEXT, macs TEXT, hostnames TEXT, "
        "operating_system TEXT, os_evidence TEXT, packets_sent INTEGER, packets_recv INTEGER, "
        "bytes_sent INTEGER, bytes_recv INTEGER, first_seen REAL, last_seen REAL, open_ports TEXT)"
    )

    for name, summary in bundle.summaries.items():
        for item in _iter_detections(summary):
            payload = to_serializable(item)
            if redact:
                payload = redact_data(payload)
            cur.execute("INSERT INTO detections (module, data) VALUES (?, ?)", (name, json.dumps(payload)))
        for item in _iter_artifacts(summary):
            payload = to_serializable(item)
            if redact:
                payload = redact_data(payload)
            cur.execute("INSERT INTO artifacts (module, data) VALUES (?, ?)", (name, json.dumps(payload)))
        for host in _iter_hosts(summary):
            open_ports = []
            for port in getattr(host, "open_ports", []) or []:
                open_ports.append({
                    "port": int(getattr(port, "port", 0) or 0),
                    "protocol": str(getattr(port, "protocol", "") or ""),
                    "service": str(getattr(port, "service", "") or ""),
                    "software": str(getattr(port, "software", "") or ""),
                })
            row = {
                "pcap_path": str(bundle.path),
                "module": name,
                "ip": str(getattr(host, "ip", "") or ""),
                "macs": list(getattr(host, "mac_addresses", []) or []),
                "hostnames": list(getattr(host, "hostnames", []) or []),
                "operating_system": str(getattr(host, "operating_system", "") or ""),
                "os_evidence": list(getattr(host, "os_evidence", []) or []),
                "packets_sent": int(getattr(host, "packets_sent", 0) or 0),
                "packets_recv": int(getattr(host, "packets_recv", 0) or 0),
                "bytes_sent": int(getattr(host, "bytes_sent", 0) or 0),
                "bytes_recv": int(getattr(host, "bytes_recv", 0) or 0),
                "first_seen": getattr(host, "first_seen", None),
                "last_seen": getattr(host, "last_seen", None),
                "open_ports": open_ports,
            }
            payload = redact_data(row) if redact else row
            cur.execute(
                "INSERT INTO hosts (pcap_path, module, ip, macs, hostnames, operating_system, os_evidence, "
                "packets_sent, packets_recv, bytes_sent, bytes_recv, first_seen, last_seen, open_ports) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    payload.get("pcap_path"),
                    payload.get("module"),
                    payload.get("ip"),
                    json.dumps(payload.get("macs", [])),
                    json.dumps(payload.get("hostnames", [])),
                    payload.get("operating_system"),
                    json.dumps(payload.get("os_evidence", [])),
                    payload.get("packets_sent"),
                    payload.get("packets_recv"),
                    payload.get("bytes_sent"),
                    payload.get("bytes_recv"),
                    payload.get("first_seen"),
                    payload.get("last_seen"),
                    json.dumps(payload.get("open_ports", [])),
                ),
            )

    conn.commit()
    conn.close()
