"""An external program that reads a copy of the run's read of a capture.

Suricata and tshark read a capture by file name. Started on a FIFO instead,
and fed (through :class:`pcap_cache.TeeSink`) every byte of the read the run
makes of the capture anyway -- or of one made for them when nothing else
reads it -- they read no file of their own: the same bytes in the same order
as the file, one read for pcapper and them together.
"""

from __future__ import annotations

import atexit
import errno
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable, Optional

from . import pcap_cache
from .capture_parts import capture_parts


# FIFOs (POSIX). Without them a program that reads a capture from its
# standard input (tshark's ``-r -``; not Suricata) is fed through that.
HAVE_FIFOS = hasattr(os, "mkfifo")


def can_feed(path: Path, *, stdin_ok: bool = False) -> bool:
    """The one file ``path`` names (a capture, or a part of a split one) can
    be fed: on a system with FIFOs, or (``stdin_ok``) to a program reading
    its standard input. A gzip-compressed one is fed inflated."""
    return (HAVE_FIFOS or stdin_ok) and pcap_cache.can_tee(path, single=True)


def start_part_feeds(path: Path, start_one: Callable[[Path], object]) -> None:
    """``start_one(file)`` for each file of the capture ``path``: at once for
    a capture in one file; for a split capture at once for its first two
    parts and for each next one when the run's read opens the part before it
    -- a program per part, never more than about three alive at a time,
    whatever the number of parts."""
    parts = capture_parts(path)
    if len(parts) == 1:
        start_one(path)
        return
    started: set[int] = set()

    def _ensure(index: int) -> None:
        if 0 <= index < len(parts) and index not in started:
            started.add(index)
            start_one(parts[index])

    _ensure(0)
    _ensure(1)
    pcap_cache.on_part_open(path, lambda index: _ensure(index + 1))


class FifoFeed:
    """``command(source, workdir)`` -- an argv reading the capture from
    ``source`` (a FIFO's path, or ``-``: its standard input, ``stdin_ok`` and
    no FIFOs) -- run on a copy of the capture. Its stdout and stderr go to
    files (a full pipe would stall it and, through the copy, the run). A
    reader that takes nothing for ``timeout`` seconds is taken to be stuck:
    the copy is abandoned and :meth:`result` says so (None), for the caller
    to read the file instead."""

    def __init__(
        self,
        path: Path,
        command: Callable[[str, Path], list[str]],
        *,
        timeout: float,
        name: str,
        stdin_ok: bool = False,
    ) -> None:
        self.path = path
        self.timeout = timeout
        self.owner = os.getpid()  # a forked process never stops its parent's feeds
        self.via_stdin = not HAVE_FIFOS
        if self.via_stdin and not stdin_ok:
            raise OSError("no FIFOs here, and the program reads no capture from its standard input")
        self.workdir = Path(tempfile.mkdtemp(prefix=f"pcapper-{name}-"))
        self.fifo = self.workdir / "capture.fifo"
        if not self.via_stdin:
            os.mkfifo(self.fifo, 0o600)
        self.argv = command("-" if self.via_stdin else str(self.fifo), self.workdir)
        stdout = open(self.workdir / "stdout.log", "w", encoding="utf-8")  # noqa: SIM115
        stderr = open(self.workdir / "stderr.log", "w", encoding="utf-8")  # noqa: SIM115
        try:
            self.started = time.monotonic()
            self.process = subprocess.Popen(
                self.argv,
                stdout=stdout,
                stderr=stderr,
                stdin=subprocess.PIPE if self.via_stdin else subprocess.DEVNULL,
            )
        except BaseException:
            shutil.rmtree(self.workdir, ignore_errors=True)
            raise
        finally:
            stdout.close()
            stderr.close()
        if self.via_stdin:
            # Its standard input: written by the copy's thread, closed by it.
            fd = os.dup(self.process.stdin.fileno())  # type: ignore[union-attr]
            self.process.stdin.close()  # type: ignore[union-attr]
            self.process.stdin = None
            self.sink = pcap_cache.TeeSink(
                fd, name=f"{name}-copy", stall_timeout=timeout, on_stall=self._stalled
            )
        else:
            self.sink = pcap_cache.TeeSink(
                None, opener=self._open_fifo, name=f"{name}-copy", stall_timeout=timeout, on_stall=self._stalled
            )
        pcap_cache.tee_capture(path, [self.sink], plain=True)

    def _stalled(self) -> None:
        """The program took nothing for ``timeout`` seconds: stopped, so a
        write blocked on it fails (and the caller reads the file)."""
        if self.process.poll() is None:
            self.process.kill()

    def _open_fifo(self) -> Optional[int]:
        """The FIFO's write end, once the program has opened it for reading."""
        import fcntl

        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            try:
                fd = os.open(self.fifo, os.O_WRONLY | os.O_NONBLOCK)
            except OSError as exc:
                if exc.errno != errno.ENXIO or self.process.poll() is not None:
                    return None
                time.sleep(0.05)
                continue
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
            try:
                fcntl.fcntl(fd, getattr(fcntl, "F_SETPIPE_SZ", 1031), 1 << 20)
            except OSError:
                pass
            return fd
        return None

    def result(self) -> Optional[tuple[int, str, str, float]]:
        """``(exit code, stdout, stderr, seconds)`` once the program is done
        with the whole capture; None when its copy fell short. Raises
        ``subprocess.TimeoutExpired`` when it is not done ``timeout`` seconds
        after getting it all (the time it spent waiting on the run's read
        does not count: a slow pass is not a stuck program)."""
        pcap_cache.feed_tees(self.path)  # nothing read the capture: copied from a read of its own
        self.sink.wait()
        if not self.sink.complete:
            self.close()
            return None
        try:
            code = self.process.wait(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            self.close()
            raise
        out = (self.workdir / "stdout.log").read_text(encoding="utf-8", errors="replace")
        err = (self.workdir / "stderr.log").read_text(encoding="utf-8", errors="replace")
        return int(code), out, err, time.monotonic() - self.started

    def close(self) -> None:
        """Stop the program if it still runs and remove its files."""
        self.sink.abandon()
        self.sink.finish()
        if self.process.poll() is None:
            self.process.kill()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        shutil.rmtree(self.workdir, ignore_errors=True)


class FeedRegistry:
    """Feeds started for a capture, by what they were started for, until the
    step that uses each takes it (or the capture is done). Feeds no step took
    -- a run that failed or was interrupted -- are stopped at exit."""

    def __init__(self) -> None:
        self._feeds: dict[tuple, FifoFeed] = {}
        _REGISTRIES.append(self)

    def add(self, key: tuple, feed: FifoFeed) -> None:
        self._feeds[key] = feed

    def __contains__(self, key: tuple) -> bool:
        return key in self._feeds

    def take(self, key: tuple) -> Optional[FifoFeed]:
        return self._feeds.pop(key, None)

    def discard(self, capture_key: Optional[str] = None) -> None:
        for key in list(self._feeds):
            if capture_key is None or key[0] == capture_key:
                self._feeds.pop(key).close()


_REGISTRIES: list[FeedRegistry] = []


@atexit.register
def _discard_all() -> None:
    pid = os.getpid()
    for registry in _REGISTRIES:
        for key, feed in list(registry._feeds.items()):
            if feed.owner == pid:
                registry._feeds.pop(key)
                feed.close()
