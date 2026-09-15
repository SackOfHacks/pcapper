"""`-summarize` rolls several captures into one report through the per-module
``merge_*`` functions. A field the merge forgets to carry is silently blank
in the rolled-up report while present in every single-capture report, which
is how the malware verdict, the DHCP lease table, the CIP size histograms
and the whole --hostdetails dossier went missing before this test existed.

For every merge function that has a same-module analyzer callable with just
a path, the analyzer is run on two fixtures, the results are merged, and any
dataclass field that is empty in the merge while populated in an input is a
failure. Merges whose analyzers need extra arguments are exercised with the
arguments listed in EXTRA_ARGS.
"""

from __future__ import annotations

import dataclasses
import importlib
import re
from pathlib import Path

import pytest

from pcapper import utils

PACKAGE = Path(__file__).parent.parent / "pcapper"
DATA = Path(__file__).parent / "data"
FIXTURES = [DATA / "mixed.pcap", DATA / "voip.pcap"]
EXTRA_ARGS = {
    "analyze_timeline": ("192.168.10.50",),
    "analyze_hostdetails": ("192.168.10.50",),
    "analyze_hostname": ("192.168.10.50",),
    "analyze_search": ("example",),
}
# Merges with no path-only analyzer in their module (the lookups take a query).
SKIP = {
    "merge_mac_lookup_summaries", "merge_ip_lookup_summaries", "merge_rules_summaries", "merge_mitre_summaries",
    "merge_size_buckets",  # a histogram helper, not a summary merge
}


def _is_default(value: object) -> bool:
    if value is None or value == 0 or value == "" or value == 0.0:
        return True
    if isinstance(value, dict):
        return all(_is_default(v) for v in value.values())
    try:
        return len(value) == 0  # type: ignore[arg-type]
    except TypeError:
        return False


def _merge_cases() -> list[tuple[str, str]]:
    cases = []
    for path in sorted(PACKAGE.glob("*.py")):
        for name in re.findall(r"^def (merge_\w+)\(", path.read_text(encoding="utf-8"), re.M):
            if name not in SKIP:
                cases.append((path.stem, name))
    return cases


def _analyzer_for(module, stem: str):
    fn = getattr(module, f"analyze_{stem}", None)
    if fn is not None:
        return fn
    for name in dir(module):
        if not name.startswith("analyze_"):
            continue
        cand = getattr(module, name)
        owner = getattr(getattr(cand, "__wrapped__", cand), "__module__", "")
        if owner == module.__name__:
            return cand
    return None


@pytest.mark.parametrize("stem, merge_name", _merge_cases(), ids=lambda v: v if str(v).startswith("merge") else None)
def test_merge_carries_every_populated_field(stem: str, merge_name: str) -> None:
    module = importlib.import_module(f"pcapper.{stem}")
    analyzer = _analyzer_for(module, stem)
    assert analyzer is not None, f"no analyzer found for {merge_name}"
    utils.clear_analysis_memo()
    inputs = [analyzer(f, *EXTRA_ARGS.get(analyzer.__name__, ()), show_status=False) for f in FIXTURES]
    merged = getattr(module, merge_name)(inputs)
    assert dataclasses.is_dataclass(merged)

    dropped = []
    for field in dataclasses.fields(merged):
        if field.name == "path":
            continue
        merged_value = getattr(merged, field.name, None)
        input_values = [getattr(item, field.name, None) for item in inputs]
        if _is_default(merged_value) and any(not _is_default(v) for v in input_values):
            dropped.append(field.name)
    assert not dropped, f"{merge_name} drops populated field(s): {dropped}"

    # The merged window spans every input.
    firsts = [getattr(i, "first_seen", None) for i in inputs if isinstance(getattr(i, "first_seen", None), (int, float))]
    lasts = [getattr(i, "last_seen", None) for i in inputs if isinstance(getattr(i, "last_seen", None), (int, float))]
    if firsts and isinstance(getattr(merged, "first_seen", None), (int, float)):
        assert merged.first_seen == pytest.approx(min(firsts))
    if lasts and isinstance(getattr(merged, "last_seen", None), (int, float)):
        assert merged.last_seen == pytest.approx(max(lasts))
