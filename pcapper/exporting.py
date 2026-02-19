from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
import json
import csv
import sqlite3

from .utils import to_serializable, safe_write_text


@dataclass
class ExportBundle:
    path: Path
    summaries: dict[str, Any]


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def export_json(bundle: ExportBundle, output_path: Path) -> None:
    _ensure_parent(output_path)
    payload = {
        "path": str(bundle.path),
        "summaries": {name: to_serializable(summary) for name, summary in bundle.summaries.items()},
    }
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


def export_csv(bundle: ExportBundle, output_path: Path) -> None:
    _ensure_parent(output_path)
    rows: list[dict[str, Any]] = []
    for name, summary in bundle.summaries.items():
        for item in _iter_detections(summary):
            row = {"category": "detection", "module": name}
            row.update(to_serializable(item))
            rows.append(row)
        for item in _iter_artifacts(summary):
            row = {"category": "artifact", "module": name}
            row.update(to_serializable(item))
            rows.append(row)

    if not rows:
        safe_write_text(output_path, "", encoding="utf-8", context="export_csv")
        return

    fieldnames = sorted({key for row in rows for key in row.keys()})
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def export_sqlite(bundle: ExportBundle, output_path: Path) -> None:
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

    for name, summary in bundle.summaries.items():
        for item in _iter_detections(summary):
            cur.execute("INSERT INTO detections (module, data) VALUES (?, ?)", (name, json.dumps(to_serializable(item))))
        for item in _iter_artifacts(summary):
            cur.execute("INSERT INTO artifacts (module, data) VALUES (?, ?)", (name, json.dumps(to_serializable(item))))

    conn.commit()
    conn.close()
