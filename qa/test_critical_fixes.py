"""Validation tests for the 3 critical bug fixes."""
from __future__ import annotations

from collections import Counter

import pcapper  # noqa: F401  -- patches Counter.most_common


# ============================================================
# Fix #1: Counter.most_common(n) vs most_common() consistency
# ============================================================

def test_most_common_n_matches_full_slice():
    """most_common(n) must return the same items as most_common()[:n]."""
    counter = Counter({"z": 5, "a": 5, "m": 5, "b": 3, "c": 3, "x": 1})
    full = counter.most_common()
    for n in range(1, len(counter) + 2):
        assert counter.most_common(n) == full[:n], (
            f"most_common({n}) != most_common()[:{n}]"
        )


def test_tiebreak_is_ascending_key():
    """When counts are tied, keys sort ascending (alphabetical for strings,
    numeric for numbers)."""
    counter = Counter({"c": 1, "a": 1, "b": 1})
    result = counter.most_common()
    keys = [k for k, _ in result]
    assert keys == ["a", "b", "c"]


def test_tiebreak_ascending_with_n():
    """Same ascending tiebreak must hold for the most_common(n) path."""
    counter = Counter({"c": 1, "a": 1, "b": 1})
    # n=2 would have used heapq.nlargest in the old code
    result = counter.most_common(2)
    keys = [k for k, _ in result]
    assert keys == ["a", "b"]


def test_mixed_types_stable():
    """Numeric keys sort before string keys when tied."""
    counter = Counter({1: 5, "a": 5, 2: 5, "b": 5})
    result = counter.most_common()
    keys = [k for k, _ in result]
    # Numeric keys (bucket 0) come first sorted by value, then string keys (bucket 1)
    assert keys == [1, 2, "a", "b"]


def test_most_common_n_less_than_length():
    """Specifically exercises the n < len(items) path that was buggy."""
    counter = Counter({"d": 10, "b": 10, "a": 10, "c": 10})
    full = counter.most_common()
    # This was the exact path that used heapq.nlargest before the fix
    assert counter.most_common(2) == full[:2]
    assert counter.most_common(3) == full[:3]


def test_most_common_edge_cases():
    """Edge cases: n=0, n negative, n > length, empty counter."""
    counter = Counter({"a": 1, "b": 2})
    assert counter.most_common(0) == []
    assert counter.most_common(-1) == []
    empty = Counter()
    assert empty.most_common() == []
    assert empty.most_common(5) == []


# ============================================================
# Fix #2: NameError in load_filtered_packets (structural check)
# ============================================================

def test_load_filtered_packets_defines_reader_attrs():
    """Verify that load_filtered_packets assigns linktype/snaplen/interfaces
    from the reader before calling _finalize_meta in the fallback path."""
    import ast
    import inspect
    from pcapper import pcap_cache

    source = inspect.getsource(pcap_cache.load_filtered_packets)
    tree = ast.parse(source)

    func = tree.body[0]
    assert isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef))

    # Walk the AST to find all assignments in the function body
    assigned_names: set[str] = set()
    finalize_call_line: int | None = None

    for node in ast.walk(func):
        # Track all simple assignments (name = ...)
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigned_names.add(target.id)
        # Track _finalize_meta calls
        if isinstance(node, ast.Call):
            call_func = node.func
            if isinstance(call_func, ast.Name) and call_func.id == "_finalize_meta":
                finalize_call_line = node.lineno

    # The three variables must be assigned somewhere in the function
    for var in ("linktype", "snaplen", "interfaces"):
        assert var in assigned_names, (
            f"'{var}' is never assigned in load_filtered_packets — NameError risk"
        )

    assert finalize_call_line is not None, "_finalize_meta is never called"


def test_load_filtered_packets_fallback_has_getattr():
    """Verify the fallback (non-BPF) path reads linktype/snaplen/interfaces
    from the reader via getattr before _finalize_meta."""
    import inspect
    from pcapper import pcap_cache

    source = inspect.getsource(pcap_cache.load_filtered_packets)

    # After the BPF try/except block, there should be getattr reads
    # Find the fallback reader creation line
    fallback_idx = source.find("reader = PcapNgReader(str(path))")
    assert fallback_idx != -1, "Could not find fallback reader creation"

    # The getattr calls should come after the reader creation and before _finalize_meta
    after_fallback = source[fallback_idx:]
    finalize_idx = after_fallback.find("_finalize_meta")
    assert finalize_idx != -1

    between = after_fallback[:finalize_idx]
    for attr in ("linktype", "snaplen", "interfaces"):
        assert f'getattr(reader, "{attr}"' in between, (
            f'getattr for "{attr}" missing between reader creation and _finalize_meta'
        )


# ============================================================
# Fix #3: Guarded scapy import
# ============================================================

def test_scapy_import_is_guarded():
    """Verify PcapReader/PcapNgReader imports are wrapped in try/except."""
    import inspect
    from pcapper import pcap_cache

    source = inspect.getsource(pcap_cache)
    # The import should be inside a try block, not at module top-level bare
    # Check that "from scapy.utils import PcapReader" is NOT a bare top-level import
    lines = source.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if "from scapy.utils import PcapReader" in stripped:
            # Look backwards for a try: within 3 lines
            found_try = False
            for j in range(max(0, i - 3), i):
                if "try:" in lines[j]:
                    found_try = True
                    break
            assert found_try, (
                f"PcapReader import at line {i+1} is not guarded by try/except"
            )
            break


def test_pcapreader_fallback_values():
    """When scapy is missing, PcapReader/PcapNgReader should be None."""
    # We can't easily unimport scapy, but we can verify the fallback
    # assignment pattern exists in the source
    import inspect
    from pcapper import pcap_cache

    source = inspect.getsource(pcap_cache)
    assert "PcapReader = None" in source
    assert "PcapNgReader = None" in source


# ============================================================
# Bonus: load_packets no longer has duplicate getattr reads
# ============================================================

def test_load_packets_no_duplicate_getattr():
    """Verify load_packets doesn't have triple-duplicate getattr calls."""
    import inspect
    from pcapper import pcap_cache

    source = inspect.getsource(pcap_cache.load_packets)
    # Count occurrences of each getattr
    for attr in ("linktype", "snaplen", "interfaces"):
        pattern = f'getattr(reader, "{attr}"'
        count = source.count(pattern)
        assert count == 1, (
            f'getattr for "{attr}" appears {count} times in load_packets (expected 1)'
        )
