"""TOML configuration: where it is looked for, and how a load failure is reported.

The lookup deliberately does **not** include the current working directory.
pcapper is routinely run from inside an evidence directory, and a config file
planted there would be applied to the analyst's run without any command-line
sign that it existed. Config keys can enable outbound VirusTotal / ip-api
lookups (sending the investigation's IOCs to a third party) and redirect
every output path, so a config is only taken from the user's own home
locations, from ``PCAPPER_CONFIG``, or from an explicit ``--config PATH``.
"""

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
    # Set when a config file was found but could not be used. Callers must
    # surface it: a silently ignored config means thresholds and output paths
    # quietly fall back to defaults while the analyst believes otherwise.
    error: str | None = None


DEFAULT_CONFIG_PATHS = [
    Path.home() / ".pcapper.toml",
    Path.home() / ".config" / "pcapper" / "config.toml",
]

# Config keys that turn on network egress. Applying one of these from a file
# must never be silent, so the CLI prints a notice naming the key and the file.
EGRESS_KEYS = frozenset({"vt", "ip_geo"})


def find_config(explicit: str | Path | None) -> Path | None:
    """Resolve the config path: explicit argument, else the home locations."""
    if explicit:
        return Path(explicit).expanduser()
    for candidate in DEFAULT_CONFIG_PATHS:
        if candidate.is_file():
            return candidate
    return None


def load_config(path: Path | None) -> ConfigLoadResult:
    if not path:
        return ConfigLoadResult(path=None, data={})
    if not path.is_file():
        return ConfigLoadResult(path=path, data={}, error=f"config file not found: {path}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return ConfigLoadResult(path=path, data={}, error=f"config unreadable: {exc}")
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        return ConfigLoadResult(path=path, data={}, error=f"config is not UTF-8: {exc}")
    except tomllib.TOMLDecodeError as exc:
        return ConfigLoadResult(path=path, data={}, error=f"config parse error: {exc}")
    if not isinstance(data, dict):
        return ConfigLoadResult(path=path, data={}, error="config root is not a table")
    return ConfigLoadResult(path=path, data=data)
