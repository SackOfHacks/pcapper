from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
import hashlib
import os


@dataclass(frozen=True)
class CaseMetadata:
    case_id: str
    analyst: str
    notes: str
    version: str
    start_time: str
    end_time: str
    duration_seconds: float
    argv: list[str]
    config_path: str
    inputs: list[dict[str, object]]

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "analyst": self.analyst,
            "notes": self.notes,
            "version": self.version,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "argv": self.argv,
            "config_path": self.config_path,
            "inputs": self.inputs,
        }


def _hash_file(path: Path, algo: str = "sha256") -> str:
    hasher = hashlib.new(algo)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def build_case_metadata(
    *,
    case_id: str,
    analyst: str,
    notes: str,
    version: str,
    argv: list[str],
    config_path: str,
    inputs: Iterable[Path],
    start_time: datetime,
    end_time: datetime,
) -> CaseMetadata:
    inputs_meta: list[dict[str, object]] = []
    for item in inputs:
        try:
            stat = item.stat()
            inputs_meta.append(
                {
                    "path": str(item),
                    "size_bytes": int(stat.st_size),
                    "modified_time": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                    "sha256": _hash_file(item),
                }
            )
        except Exception:
            inputs_meta.append({"path": str(item), "error": "hash_failed"})

    duration = (end_time - start_time).total_seconds()
    return CaseMetadata(
        case_id=case_id,
        analyst=analyst,
        notes=notes,
        version=version,
        start_time=start_time.isoformat(),
        end_time=end_time.isoformat(),
        duration_seconds=duration,
        argv=argv,
        config_path=config_path,
        inputs=inputs_meta,
    )
