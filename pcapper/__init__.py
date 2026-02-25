"""Pcapper package."""

from __future__ import annotations

import os
from collections import Counter
import heapq
import numbers
from typing import Any

__all__ = ["__version__"]
__version__ = "1.4.3"


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
