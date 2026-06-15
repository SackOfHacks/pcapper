"""Pcapper package."""

from __future__ import annotations

import heapq
import logging
import numbers
import os
import sys
from collections import Counter
from typing import Any

__all__ = ["__version__"]
__version__ = "2.0.0"


# --- Early quiet-mode hook ---------------------------------------------------
# Scapy emits cryptography-version-mismatch errors and other module-loading
# warnings on stderr at IMPORT time (i.e., before any pcapper code runs).
# When the user passes --quiet/-q (or PCAPPER_QUIET=1), suppress that noise
# at the logging-and-stderr level before scapy gets imported transitively
# through cli.py. Default behavior is unchanged.
#
# The check is purely on sys.argv / env so it doesn't drag in argparse here.
def _early_quiet_requested() -> bool:
    if os.environ.get("PCAPPER_QUIET", "").lower() in ("1", "true", "yes"):
        return True
    return any(a in ("--quiet", "-q") for a in sys.argv[1:])


if _early_quiet_requested():
    # 1. Silence scapy's own logger ("scapy", "scapy.loading", "scapy.runtime").
    for _name in ("scapy", "scapy.loading", "scapy.runtime"):
        logging.getLogger(_name).setLevel(logging.CRITICAL + 1)
    # 2. Suppress scapy-emitted Python warnings (filterwarnings here so they
    #    don't print during the cli import chain).
    import warnings as _warnings
    _warnings.filterwarnings("ignore", module=r"scapy(\..*)?")
    _warnings.filterwarnings("ignore", message=r".*cryptography.*")
    # 3. Belt-and-braces: scapy.main._load() can print directly to sys.stderr.
    #    Replace stderr with a buffer for the duration of the import chain;
    #    the buffer is dropped (the messages are not actionable to the user
    #    who explicitly asked for quiet output). Restored automatically on
    #    interpreter exit; the cli explicitly restores at end of main() too.
    import io as _io
    _PCAPPER_REAL_STDERR = sys.stderr
    sys.stderr = _io.StringIO()


def _restore_stderr_if_suppressed() -> None:
    """Called by cli.main() once arg parsing is done so any post-import
    stderr writes go to the real stderr again."""
    real = globals().get("_PCAPPER_REAL_STDERR")
    if real is not None and sys.stderr is not real:
        sys.stderr = real


def _stable_key(value: Any) -> tuple[int, Any]:
    if isinstance(value, (int, float)):
        return (0, float(value))
    return (1, str(value))


def _count_value(value: Any) -> float:
    if isinstance(value, numbers.Number):
        return float(value)
    try:
        return float(value)
    except Exception:
        return 0.0


def _stable_most_common(self: Counter, n: int | None = None):  # type: ignore[override]
    items = list(self.items())

    def _sort_key(item: tuple[Any, Any]) -> tuple[float, tuple[int, Any]]:
        key, count = item
        return (_count_value(count), _stable_key(key))

    if n is None:
        items.sort(key=lambda item: (-_sort_key(item)[0], _sort_key(item)[1]))
        return items
    try:
        n = int(n)
    except Exception:
        items.sort(key=lambda item: (-_sort_key(item)[0], _sort_key(item)[1]))
        return items
    if n <= 0:
        return []
    if n >= len(items):
        items.sort(key=lambda item: (-_sort_key(item)[0], _sort_key(item)[1]))
        return items[:n]
    return heapq.nlargest(n, items, key=_sort_key)


if os.environ.get("PCAPPER_DETERMINISTIC", "1") != "0":
    Counter.most_common = _stable_most_common  # type: ignore[assignment]
