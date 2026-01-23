from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class StatusBar:
    label: str
    enabled: bool = True
    _last_percent: int = -1

    def __enter__(self) -> "StatusBar":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.finish()

    def update(self, percent: int) -> None:
        if not self.enabled:
            return
        percent = max(0, min(100, percent))
        if percent == self._last_percent:
            return
        self._last_percent = percent
        sys.stdout.write(f"\r{self.label} {percent:3d}%")
        sys.stdout.flush()

    def finish(self) -> None:
        if not self.enabled:
            return
        if self._last_percent < 100:
            self.update(100)
        sys.stdout.write("\n")
        sys.stdout.flush()


def should_show_statusbar() -> bool:
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def build_statusbar(path: Path, enabled: bool = True, desc: str | None = None) -> StatusBar:
    base_label = desc if desc else "Processing"
    label = f"{base_label} {path.name}".strip()
    return StatusBar(label=label, enabled=enabled and should_show_statusbar())
