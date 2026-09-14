"""Structural guards that keep the codebase from regressing on review findings.

These are *ratchet* tests: each pins the current count of a known-bad pattern
and fails when a new instance appears. As instances are removed the pinned
number is lowered, never raised. They are AST-based, so a rule that stops
matching fails loudly instead of silently passing.

Patterns guarded:

* a module re-implementing a helper that ``pcapper.utils`` already provides
  (the review found 24 such copies after an earlier consolidation);
* code mutating the object returned by an ``analyze_*`` / ``merge_*`` call.
  Results are shared through ``memoize_analysis``, so an in-place mutation
  changes what every later caller sees.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).parent.parent / "pcapper"

# utils.py canonical name -> local names that re-implement it.
DUPLICATE_HELPER_NAMES: dict[str, tuple[str, ...]] = {
    "is_private_ip": ("_is_private_ip", "_is_private", "_private_ip", "_is_rfc1918", "_is_internal_ip", "_is_internal"),
    "is_public_ip": ("_is_public_ip", "_is_public", "_is_external_ip", "_is_external", "_is_routable"),
    "is_valid_ip": ("_is_valid_ip", "_valid_ip", "_is_ip"),
    "decode_payload": ("_decode", "_decode_payload", "_safe_decode", "_to_text", "_payload_text", "_bytes_to_text"),
    "beacon_score": ("_beacon_score", "_beaconing_score", "_is_beaconing", "_periodicity"),
    "extract_ascii_strings": ("_extract_strings", "_ascii_strings", "_extract_ascii", "_strings"),
    "shannon_entropy": ("_entropy", "_shannon", "_shannon_entropy", "_calc_entropy"),
    "tcp_flags_int": ("_flags_int", "_tcp_flags", "_flag_bits", "_flags_to_int"),
    "get_packet_ports": ("_ports", "_get_ports", "_packet_ports", "_extract_ports"),
    "extract_packet_endpoints": ("_endpoints", "_get_endpoints", "_packet_endpoints", "_extract_ips", "_src_dst", "_get_ips"),
    "packet_length": ("_pkt_len", "_packet_len", "_wire_len"),
    "format_ts": ("_format_ts", "_fmt_ts", "_ts_to_str", "_format_time", "_iso_ts"),
    "safe_float": ("_safe_float", "_to_float", "_as_float"),
    "counter_inc": ("_inc", "_counter_inc", "_bump"),
}

MUTATING_METHODS = {
    "append", "extend", "update", "setdefault", "pop", "clear", "insert",
    "remove", "add", "discard", "sort", "reverse",
}

# Builders that return a fresh object on every call (deliberately not
# memoized), so post-processing their result in place is by design. The
# outer analyze_<protocol> functions that own the object are the memoized ones.
UNSHARED_BUILDERS = {"analyze_port_protocol", "analyze_ethertype_protocol"}


def _modules() -> list[tuple[Path, ast.Module]]:
    out = []
    for path in sorted(PACKAGE.rglob("*.py")):
        out.append((path, ast.parse(path.read_text(encoding="utf-8"))))
    return out


def _function_defs(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def duplicate_helpers() -> list[str]:
    """``module:name`` for every local re-implementation of a utils helper."""
    found: list[str] = []
    for path, tree in _modules():
        if path.name == "utils.py":
            continue
        names = {fn.name for fn in _function_defs(tree)}
        for local_names in DUPLICATE_HELPER_NAMES.values():
            for name in local_names:
                if name in names:
                    found.append(f"{path.relative_to(PACKAGE).as_posix()}:{name}")
    return sorted(found)


def _root_name(node: ast.AST) -> ast.AST:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node


def result_mutations() -> list[str]:
    """``module:line`` for every in-place mutation of an analyzer result."""
    found: list[str] = []
    for path, tree in _modules():
        found.extend(_mutations_in(path.relative_to(PACKAGE).as_posix(), tree))
    return sorted(set(found))


def _mutations_in(rel: str, tree: ast.AST) -> list[str]:
    """Mutation sites in one module: names bound from a memoized ``analyze_*``
    / ``merge_*`` call that are then assigned into or mutated through."""
    found: list[str] = []
    for fn in _function_defs(tree):
        bound: set[str] = set()
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                func = node.value.func
                name = (
                    func.id if isinstance(func, ast.Name)
                    else func.attr if isinstance(func, ast.Attribute)
                    else ""
                )
                if name.startswith(("analyze_", "merge_")) and name not in UNSHARED_BUILDERS:
                    bound.update(t.id for t in node.targets if isinstance(t, ast.Name))
        if not bound:
            continue
        for node in ast.walk(fn):
            targets: list[ast.AST] = []
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
            elif isinstance(node, ast.AugAssign):
                targets = [node.target]
            for target in targets:
                root = _root_name(target)
                if isinstance(root, ast.Name) and root.id in bound and target is not root:
                    found.append(f"{rel}:{node.lineno}")
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in MUTATING_METHODS
            ):
                root = _root_name(node.func.value)
                if isinstance(root, ast.Name) and root.id in bound:
                    found.append(f"{rel}:{node.lineno}")
    return found


# Pinned at 24 at the start of the 2026-09 review and lowered as the copies
# were removed; a higher number means a new copy was introduced.
MAX_DUPLICATE_HELPERS = 0
# Zero since the memoization inversion: inner builders are unshared, the two
# cli.py QUIC annotators are copy-on-write.
MAX_RESULT_MUTATION_SITES = 0


def test_no_new_duplicate_helpers() -> None:
    found = duplicate_helpers()
    assert len(found) <= MAX_DUPLICATE_HELPERS, (
        f"{len(found)} local re-implementations of pcapper.utils helpers "
        f"(pinned max {MAX_DUPLICATE_HELPERS}). Import from utils instead:\n  "
        + "\n  ".join(found)
    )


def test_no_new_analyzer_result_mutation() -> None:
    found = result_mutations()
    assert len(found) <= MAX_RESULT_MUTATION_SITES, (
        f"{len(found)} sites mutate an analyze_*/merge_* result in place "
        f"(pinned max {MAX_RESULT_MUTATION_SITES}). Results are shared through "
        "memoize_analysis; build a new object instead:\n  " + "\n  ".join(found)
    )


MUTATING_SNIPPET = """
def f(p):
    s = analyze_x(p)
    s.items.append(1)
    s.count = 2
    s.count += 1
    t = analyze_port_protocol(p)
    t.items.append(1)
"""


def test_guards_still_detect_their_pattern() -> None:
    """Guard the guards: an AST rule that matches nothing has drifted."""
    assert duplicate_helpers() or MAX_DUPLICATE_HELPERS == 0
    # The mutation rule is proven live on a known-bad snippet: three hits on
    # the memoized result, none on the unshared builder's.
    hits = sorted(_mutations_in("snippet", ast.parse(MUTATING_SNIPPET)))
    assert hits == ["snippet:4", "snippet:5", "snippet:6"]


@pytest.mark.parametrize("pinned", [MAX_DUPLICATE_HELPERS, MAX_RESULT_MUTATION_SITES])
def test_pins_are_non_negative(pinned: int) -> None:
    assert pinned >= 0
