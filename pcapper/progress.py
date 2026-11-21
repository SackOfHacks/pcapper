"""What the terminal shows while captures are analysed.

The CLI runs inside one of two displays (``display_session``):

* default -- one progress bar per capture on stderr, and nothing else. Read
  passes and finished analyses move the bar instead of drawing their own
  lines, and library chatter (scapy's per-record dissection warnings,
  Python warnings such as cryptography deprecations) is not shown;
* ``-v`` -- the detail: every read pass's percentage, each analysis's
  spinner and start/finish timing, library warnings and pcapper's notices.

Either way, anything else written to the terminal -- a report line, a
warning, an error -- first takes the status line off the screen, so the two
never share a line; the status line comes back below it.

Outside the CLI (an analyzer called from Python) neither applies: read
passes and spinners draw their own lines as they always have.
"""

from __future__ import annotations

import itertools
import logging
import os
import sys
import threading
import time
import warnings
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator, TypeVar

from .coloring import ANSI_CYAN, ANSI_DIM, ANSI_RESET

# --- verbose-progress ----------------------------------------------------------
# With -v, ``run_with_busy_status`` also writes per-analysis start/finish
# timing lines to stderr: the "was anything happening for the last 3
# minutes?" signal that a spinner cannot give on a non-TTY invocation.
_VERBOSE_PROGRESS: bool = False


def set_verbose_progress(enabled: bool) -> None:
    """Enable/disable the -v detail display (set once by the CLI)."""
    global _VERBOSE_PROGRESS
    _VERBOSE_PROGRESS = bool(enabled)


def detail_enabled() -> bool:
    """-v: show read-pass percentages, analysis timing, warnings and notices."""
    return _VERBOSE_PROGRESS


# Every status write holds this lock. --jobs forks worker processes while the
# bar or a spinner may be drawing from a thread; a fork in the middle of a
# stderr write would hand the child stderr's buffer lock in the locked state,
# so the lock is held across every fork. Re-entrant: a write to a clearing
# stream clears the status line under the same lock.
_SPINNER_WRITE = threading.RLock()
if hasattr(os, "register_at_fork"):
    os.register_at_fork(
        before=_SPINNER_WRITE.acquire,
        after_in_parent=_SPINNER_WRITE.release,
        after_in_child=_SPINNER_WRITE.release,
    )

# --- the status line ----------------------------------------------------------
# Drawn with "\r" on the terminal's stderr and overwritten with spaces before
# anything else is written to the terminal.
_STATUS_STREAM = None  # the real stderr, during a display session
_LINE_WIDTH = 0  # visible width of the status line on screen (0: none)
_AT_LINE_START = True  # the last report/stderr write ended its line
_LAST_WRITE = 0.0  # when it happened (monotonic)
_BAR_MODE = False  # the default display: one bar per capture
_COLOR = False
_IN_CHILD = False  # a forked worker: draws and clears nothing


def _status_stream():
    return _STATUS_STREAM if _STATUS_STREAM is not None else sys.stderr


def _draw_locked(text: str, width: int) -> None:
    """Show ``text`` (``width`` visible columns) as the status line."""
    global _LINE_WIDTH
    if _IN_CHILD:
        return
    pad = max(0, _LINE_WIDTH - width)  # cover a longer line drawn before
    try:
        stream = _status_stream()
        stream.write("\r" + text + " " * pad)
        stream.flush()
    except Exception:  # noqa: BLE001 — a status write must never break the run
        return
    _LINE_WIDTH = width + pad


def _clear_locked() -> None:
    global _LINE_WIDTH
    if _LINE_WIDTH and not _IN_CHILD:
        try:
            stream = _status_stream()
            stream.write("\r" + " " * _LINE_WIDTH + "\r")
            stream.flush()
        except Exception:  # noqa: BLE001
            pass
    _LINE_WIDTH = 0


def _commit_locked() -> None:
    """End the status line with a newline: it stays on screen as a log line."""
    global _LINE_WIDTH
    if _LINE_WIDTH and not _IN_CHILD:
        try:
            stream = _status_stream()
            stream.write("\n")
            stream.flush()
        except Exception:  # noqa: BLE001
            pass
    _LINE_WIDTH = 0


def clear_status_line() -> None:
    """Take the status line off the screen; its next update draws it again."""
    with _SPINNER_WRITE:
        _clear_locked()


class _ClearingStream:
    """A terminal stream that takes the status line off the screen before
    anything is written to it, and notes whether its writes end a line (the
    bar is only drawn back at the start of a line)."""

    def __init__(self, stream) -> None:
        self._stream = stream

    def write(self, text):
        global _AT_LINE_START, _LAST_WRITE
        if not text:
            return self._stream.write(text)
        with _SPINNER_WRITE:
            _clear_locked()
            result = self._stream.write(text)
            _AT_LINE_START = text.endswith("\n")
            _LAST_WRITE = time.monotonic()
        return result

    def writelines(self, lines) -> None:
        for line in lines:
            self.write(line)

    def __getattr__(self, name):
        return getattr(self._stream, name)


class _ClearStatusFilter(logging.Filter):
    """scapy's log handler kept the stderr it was created with, so it is not
    a clearing stream: clear the status line before it writes."""

    def filter(self, record: logging.LogRecord) -> bool:
        clear_status_line()
        return True


# --- the capture bar (default display) ----------------------------------------
# A capture's bar is divided into units: the read that loads its packets (or
# the shared pass over a capture too large to keep), then one unit per
# requested analysis step, each weighted by the analyses it is expected to
# compute (the shared pass's dry run counts them). Inside a unit the bar
# moves with every analysis finished and with a read pass's percentage; when
# the count is unknown, each finished analysis takes a share of what is
# left. The bar never moves back.
_PASS_SHARE = 0.9
_SUBTASK_SHARE = 0.08
_UNIT_CEILING = 0.97  # a unit shows full only once it is over
_TICK = 0.1  # seconds between redraws (the clock)
_REDRAW_QUIET = 0.15  # report output must pause this long before the bar returns


@dataclass
class _Capture:
    name: str
    index: int
    total: int
    weights: list = field(default_factory=lambda: [1.0])
    expected: list = field(default_factory=list)  # planned analysis cost per unit (0: unknown)
    started: float = field(default_factory=time.monotonic)
    unit: int = 0
    inner: float = 0.0  # progress inside the current unit, 0..1
    done: float = 0.0  # cost of the analyses finished in the current unit
    pass_base: float | None = None  # inner when the current read pass began
    shown: float = 0.0

    def planned(self) -> float:
        return float(self.expected[self.unit]) if self.unit < len(self.expected) else 0.0

    def fraction(self) -> float:
        total = sum(self.weights) or 1.0
        before = sum(self.weights[: self.unit])
        span = self.weights[self.unit] if self.unit < len(self.weights) else 0.0
        inner = self.inner
        if self.planned():
            inner = max(inner, min(_UNIT_CEILING, self.done / self.planned()))
        value = (before + span * min(1.0, inner)) / total
        self.shown = max(self.shown, min(1.0, value))
        return self.shown


_CAPTURE: _Capture | None = None
_WEIGHER: Callable[[str], float] | None = None  # cost of an analysis by its module
_TICKER: threading.Thread | None = None
_TICKER_STOP = threading.Event()
_LAST_BAR = ""


def _forked_child() -> None:
    # A worker forked mid-run (--jobs, --split) shares the terminal but not
    # the bar: it must neither draw nor clear the parent's status line.
    global _IN_CHILD, _LINE_WIDTH, _CAPTURE, _TICKER
    _IN_CHILD = True
    _LINE_WIDTH = 0
    _CAPTURE = None
    _TICKER = None


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_forked_child)


def bar_active() -> bool:
    """The default display is drawing capture bars (worth planning them)."""
    return _BAR_MODE and not _IN_CHILD


def set_analysis_weigher(weigher: Callable[[str], float] | None) -> None:
    """How much a finished analysis moves the bar, by its module (the CLI
    prices OT protocol analyses below payload-scanning IT ones)."""
    global _WEIGHER
    _WEIGHER = weigher


def capture_begin(
    path: Path | str,
    *,
    index: int = 1,
    total: int = 1,
    weights: list[float] | None = None,
    expected: list[float] | None = None,
) -> None:
    """Start the bar for one capture (ends the previous one)."""
    global _CAPTURE, _LAST_BAR
    if not bar_active():
        return
    with _SPINNER_WRITE:
        _clear_locked()
        _LAST_BAR = ""
        _CAPTURE = _Capture(
            name=Path(path).name, index=index, total=total,
            weights=list(weights or [1.0]), expected=list(expected or []),
        )
    redraw_bar()  # at once, not on the next tick


def capture_plan(*, weights: list[float], expected: list[float] | None = None) -> None:
    """Re-divide the current capture's bar: ``weights[0]`` is the read,
    then one entry per step; ``expected`` the planned analysis cost of each."""
    with _SPINNER_WRITE:
        if _CAPTURE is not None:
            _CAPTURE.weights = list(weights) or [1.0]
            _CAPTURE.expected = list(expected or [])


def capture_next_unit() -> None:
    """The next requested analysis step starts: the unit before it is done."""
    with _SPINNER_WRITE:
        capture = _CAPTURE
        if capture is None:
            return
        if capture.unit + 1 < len(capture.weights):
            capture.unit += 1
            capture.inner = 0.0
            capture.done = 0.0
        capture.pass_base = None


def capture_end() -> None:
    """The capture is done: take its bar off the screen."""
    global _CAPTURE
    with _SPINNER_WRITE:
        if _CAPTURE is None:
            return
        _CAPTURE = None
        _clear_locked()


def subtask_done(count: int = 1, *, module: str = "") -> None:
    """Analyses finished (a memoised analyzer, a --jobs worker's share): the
    bar moves on by their cost."""
    if _CAPTURE is None:  # the common case outside the default display
        return
    weigher = _WEIGHER
    cost = float(weigher(module)) if weigher is not None and module else 1.0
    with _SPINNER_WRITE:
        capture = _CAPTURE
        if capture is None:
            return
        count = max(0, int(count))
        capture.done += cost * count
        if not capture.planned():  # unknown: each takes a share of what is left
            for _ in range(count):
                capture.inner += (1.0 - capture.inner) * _SUBTASK_SHARE


def _capture_pass(percent: int) -> None:
    with _SPINNER_WRITE:
        capture = _CAPTURE
        if capture is None:
            return
        if capture.pass_base is None:
            capture.pass_base = capture.inner
        reached = capture.pass_base + (1.0 - capture.pass_base) * _PASS_SHARE * percent / 100.0
        capture.inner = max(capture.inner, reached)


def _capture_pass_done() -> None:
    with _SPINNER_WRITE:
        if _CAPTURE is not None:
            _CAPTURE.pass_base = None


def _columns() -> int:
    try:
        return max(40, os.get_terminal_size(_status_stream().fileno()).columns)
    except (AttributeError, OSError, ValueError):
        return 80


def _clock(seconds: float) -> str:
    seconds = int(max(0.0, seconds))
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}:{minutes:02d}:{secs:02d}" if hours else f"{minutes}:{secs:02d}"


def _ellipsize(name: str, width: int) -> str:
    if len(name) <= width:
        return name
    keep = max(1, width - 1)
    head = (keep + 1) // 2
    return name[:head] + "…" + name[len(name) - (keep - head):]


def _bar_glyphs() -> tuple[str, str]:
    encoding = getattr(_status_stream(), "encoding", None) or "ascii"
    try:
        "━─…".encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return "#", "-"
    return ("━", "━") if _COLOR else ("━", "─")


def _render_bar(capture: _Capture) -> tuple[str, int]:
    """The bar line and its visible width:
    ``  [2/3] name.pcap  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━────  85%  0:24``."""
    fraction = capture.fraction()
    percent = f"{int(fraction * 100):3d}%"
    clock = _clock(time.monotonic() - capture.started)
    prefix = f"[{capture.index}/{capture.total}] " if capture.total > 1 else ""
    columns = _columns()
    fixed = 2 + len(prefix) + 2 + 2 + len(percent) + 2 + len(clock)
    bar_width = max(10, min(40, columns - 1 - fixed - len(capture.name)))
    name = _ellipsize(capture.name, max(8, columns - 1 - fixed - bar_width))
    if "…" in name and _bar_glyphs()[0] == "#":
        name = name.replace("…", "~")
    full, empty = _bar_glyphs()
    filled = min(bar_width, int(fraction * bar_width))
    done_part, todo_part = full * filled, empty * (bar_width - filled)
    if _COLOR:
        bar = f"{ANSI_CYAN}{done_part}{ANSI_RESET}{ANSI_DIM}{todo_part}{ANSI_RESET}"
        tail = f"{ANSI_DIM}{clock}{ANSI_RESET}"
    else:
        bar, tail = done_part + todo_part, clock
    text = f"  {prefix}{name}  {bar}  {percent}  {tail}"
    width = 2 + len(prefix) + len(name) + 2 + bar_width + 2 + len(percent) + 2 + len(clock)
    return text, width


def redraw_bar() -> None:
    """Draw the current capture's bar, unless report output is mid-line or
    still flowing (the ticker calls this; so can a test)."""
    global _LAST_BAR
    with _SPINNER_WRITE:
        capture = _CAPTURE
        if capture is None or _IN_CHILD:
            return
        if not _AT_LINE_START or time.monotonic() - _LAST_WRITE < _REDRAW_QUIET:
            return
        text, width = _render_bar(capture)
        if text == _LAST_BAR and _LINE_WIDTH:
            return
        _draw_locked(text, width)
        _LAST_BAR = text


def _tick() -> None:
    while not _TICKER_STOP.wait(_TICK):
        redraw_bar()


def _isatty(stream) -> bool:
    try:
        return bool(stream.isatty())
    except Exception:  # noqa: BLE001
        return False


@contextmanager
def display_session(*, verbose: bool, status: bool = True, color: bool = True) -> Iterator[None]:
    """The terminal display for one CLI run: a progress bar per capture, or
    with ``verbose`` the detail (see the module docstring)."""
    global _BAR_MODE, _COLOR, _STATUS_STREAM, _TICKER, _AT_LINE_START, _LAST_WRITE
    set_verbose_progress(verbose)
    scapy_logger = logging.getLogger("scapy")
    saved_level = scapy_logger.level
    real_out, real_err = sys.stdout, sys.stderr
    on_terminal = _isatty(real_err)
    log_filter = _ClearStatusFilter()
    with warnings.catch_warnings():
        if not verbose:
            # Library chatter is detail: scapy's per-record warnings ("Unknown
            # cipher suite ... from ClientMasterKey") and Python warnings show
            # with -v only. An explicit -W / PYTHONWARNINGS still wins.
            scapy_logger.setLevel(logging.ERROR)
            if not sys.warnoptions:
                warnings.simplefilter("ignore")
        _BAR_MODE = bool(status and on_terminal and not verbose)
        _COLOR = bool(color and on_terminal and not os.environ.get("NO_COLOR"))
        if on_terminal:
            _STATUS_STREAM = real_err
            _AT_LINE_START, _LAST_WRITE = True, 0.0
            sys.stderr = _ClearingStream(real_err)
            if _isatty(real_out):
                sys.stdout = _ClearingStream(real_out)
            for handler in scapy_logger.handlers:
                handler.addFilter(log_filter)
        if _BAR_MODE:
            _TICKER_STOP.clear()
            _TICKER = threading.Thread(target=_tick, name="pcapper-progress", daemon=True)
            _TICKER.start()
        try:
            yield
        finally:
            if _TICKER is not None:
                _TICKER_STOP.set()
                _TICKER.join(timeout=1.0)
                _TICKER = None
            capture_end()
            clear_status_line()
            for handler in scapy_logger.handlers:
                handler.removeFilter(log_filter)
            scapy_logger.setLevel(saved_level)
            if isinstance(sys.stdout, _ClearingStream):
                sys.stdout = real_out
            if isinstance(sys.stderr, _ClearingStream):
                sys.stderr = real_err
            _STATUS_STREAM = None
            _BAR_MODE = False
            _COLOR = False


# --- per-pass and per-analysis status ------------------------------------------


def _emit_progress(text: str) -> None:
    """Write one -v timing line to stderr (no-op without -v)."""
    if not _VERBOSE_PROGRESS:
        return
    with _SPINNER_WRITE:
        _clear_locked()
        try:
            stream = _status_stream()
            stream.write(text if text.endswith("\n") else text + "\n")
            stream.flush()
        except Exception:  # noqa: BLE001 — progress emit must never break the run
            pass


@dataclass
class StatusBar:
    """One read pass: its percentage feeds the capture bar (default display)
    or is drawn as its own line (-v, and outside the CLI)."""

    label: str
    enabled: bool = True
    _last_percent: int = -1

    def __enter__(self) -> "StatusBar":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.finish()

    def update(self, percent: int) -> None:
        if not self.enabled or _IN_CHILD:
            return
        percent = max(0, min(100, int(percent)))
        if percent == self._last_percent:
            return
        self._last_percent = percent
        if _BAR_MODE:
            _capture_pass(percent)
            return
        # Progress is a diagnostic, not part of the report: it goes to stderr
        # so `pcapper ... > report.txt` on a TTY does not interleave "\r..."
        # progress with the rendered output.
        text = f"{self.label} {percent:3d}%"
        with _SPINNER_WRITE:
            _draw_locked(text, len(text))

    def finish(self) -> None:
        if not self.enabled or _IN_CHILD:
            return
        if _BAR_MODE:
            _capture_pass_done()
            return
        # The finished pass stays on screen as a log line, even when a
        # warning took the live line off the screen just before.
        self._last_percent = 100
        text = f"{self.label} 100%"
        with _SPINNER_WRITE:
            _draw_locked(text, len(text))
            _commit_locked()


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
    """A spinner with the elapsed time for work that cannot report a
    percentage (-v and outside the CLI; the default display's bar has its
    own clock)."""

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
            text = f"{self.label} {next(spinner)} {elapsed:5.1f}s"
            with _SPINNER_WRITE:
                _draw_locked(text, len(text))
            self._stop_event.wait(self.interval)
        with _SPINNER_WRITE:
            _clear_locked()

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
    return BusyStatusBar(label=label, enabled=enabled and should_show_statusbar() and not _BAR_MODE)


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
