from __future__ import annotations

from collections import Counter

import pcapper  # noqa: F401  # ensure Counter.most_common is patched


def test_stable_most_common_order() -> None:
    counter = Counter({"b": 1, "a": 1, "c": 2})
    assert counter.most_common() == [("c", 2), ("a", 1), ("b", 1)]
