from __future__ import annotations

import itertools
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, TypeVar


# --- verbose-progress ----------------------------------------------------------
# When True, ``run_with_busy_status`` emits per-module start/end/timing lines
# to stderr in addition to (or instead of, on non-TTY) the interactive
# spinner. Provides the "was anything happening for the last 3 minutes?"
# signal that a spinner on a background/non-TTY invocation can't give.
#
# Wired in by the CLI once at startup — see cli.py where set_verbose_output
# is also called; we piggy-back on the same --verbose flag.
_VERBOSE_PROGRESS: bool = False


def set_verbose_progress(enabled: bool) -> None:
    """Enable/disable stderr progress lines from ``run_with_busy_status``.
    Called once by the CLI at startup when ``--verbose`` is set."""
    global _VERBOSE_PROGRESS
    _VERBOSE_PROGRESS = bool(enabled)


def _emit_progress(text: str) -> None:
    """Write a single progress line to stderr, flushed. No-op when
    verbose progress is off."""
    if not _VERBOSE_PROGRESS:
        return
    try:
        sys.stderr.write(text)
        if not text.endswith("\n"):
            sys.stderr.write("\n")
        sys.stderr.flush()
    except Exception:  # noqa: BLE001 — progress emit must never break the run
        pass


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
        # Progress is a diagnostic, not part of the report: it goes to stderr
        # so `pcapper ... > report.txt` on a TTY does not interleave "\r..."
        # progress with the rendered output.
        sys.stderr.write(f"\r{self.label} {percent:3d}%")
        sys.stderr.flush()

    def finish(self) -> None:
        if not self.enabled:
            return
        if self._last_percent < 100:
            self.update(100)
        sys.stderr.write("\n")
        sys.stderr.flush()


def should_show_statusbar() -> bool:
    try:
        return sys.stderr.isatty()
    except Exception:
        return False


def build_statusbar(
    path: Path, enabled: bool = True, desc: str | None = None
) -> StatusBar:
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
            sys.stderr.write(f"\r{self.label} {next(spinner)} {elapsed:5.1f}s")
            sys.stderr.flush()
            self._stop_event.wait(self.interval)
        elapsed = time.monotonic() - self._start_time
        clear_width = len(f"{self.label} done {elapsed:5.1f}s")
        sys.stderr.write("\r" + (" " * clear_width) + "\r")
        sys.stderr.flush()

    def finish(self) -> None:
        if not self.enabled:
            return
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join()


def build_busy_statusbar(
    path: Path, enabled: bool = True, desc: str | None = None
) -> BusyStatusBar:
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
    label = f"{desc} {path.name}".strip() if desc else path.name
    _emit_progress(f"[pcapper] {label}: starting...")
    started = time.monotonic()
    status = build_busy_statusbar(path, enabled=enabled, desc=desc)
    try:
        with status:
            result = func(*args, **kwargs)
    except BaseException as exc:  # noqa: BLE001 — emit + reraise
        elapsed = time.monotonic() - started
        _emit_progress(
            f"[pcapper] {label}: FAILED after {elapsed:.1f}s "
            f"({type(exc).__name__}: {exc})"
        )
        raise
    elapsed = time.monotonic() - started
    _emit_progress(f"[pcapper] {label}: done in {elapsed:.1f}s")
    return result
