from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - fallback for 3.9/3.10
    import tomli as tomllib  # type: ignore[import-not-found]


@dataclass(frozen=True)
class ConfigLoadResult:
    path: Path | None
    data: dict[str, Any]


DEFAULT_CONFIG_PATHS = [
    Path("pcapper.toml"),
    Path.home() / ".pcapper.toml",
    Path.home() / ".config" / "pcapper" / "config.toml",
]


def find_config(explicit: str | Path | None) -> Path | None:
    if explicit:
        return Path(explicit).expanduser()
    for candidate in DEFAULT_CONFIG_PATHS:
        if candidate.exists():
            return candidate
    return None


def load_config(path: Path | None) -> ConfigLoadResult:
    if not path or not path.exists():
        return ConfigLoadResult(path=None, data={})
    try:
        raw = path.read_bytes()
        data = tomllib.loads(raw.decode("utf-8", errors="ignore"))
        if not isinstance(data, dict):
            return ConfigLoadResult(path=path, data={})
        return ConfigLoadResult(path=path, data=data)
    except Exception:
        return ConfigLoadResult(path=path, data={})
