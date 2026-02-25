from __future__ import annotations

import sys
import threading
import time
import itertools
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, TypeVar


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


@dataclass
class BusyStatusBar:
    label: str
    enabled: bool = True
    interval: float = 0.2
    _stop_event: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None
    _start_time: float = 0.0

    def __enter__(self) -> "BusyStatusBar":
        if not self.enabled:
            return self
        self._start_time = time.monotonic()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.finish()

    def _spin(self) -> None:
        spinner = itertools.cycle("|/-\\")
        while not self._stop_event.is_set():
            elapsed = time.monotonic() - self._start_time
            sys.stdout.write(f"\r{self.label} {next(spinner)} {elapsed:5.1f}s")
            sys.stdout.flush()
            self._stop_event.wait(self.interval)
        elapsed = time.monotonic() - self._start_time
        sys.stdout.write(f"\r{self.label} done {elapsed:5.1f}s\n")
        sys.stdout.flush()

    def finish(self) -> None:
        if not self.enabled:
            return
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join()


def build_busy_statusbar(path: Path, enabled: bool = True, desc: str | None = None) -> BusyStatusBar:
    base_label = desc if desc else "Processing"
    label = f"{base_label} {path.name}".strip()
    return BusyStatusBar(label=label, enabled=enabled and should_show_statusbar())


_T = TypeVar("_T")


def run_with_busy_status(
    path: Path,
    enabled: bool,
    desc: str | None,
    func: Callable[..., _T],
    *args,
    **kwargs,
) -> _T:
    status = build_busy_statusbar(path, enabled=enabled, desc=desc)
    with status:
        return func(*args, **kwargs)
