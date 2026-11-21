"""-summarize: frozen summaries merge into their own report."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from pcapper.cli import _rollup_fix_duration, _rollup_numeric_kind, _rollup_set, _tag_capture_records
from test_review_batches import T0, _tcp, _write


@dataclass(frozen=True)
class _Frozen:
    path: Path
    rows: list


def test_rollup_set_writes_frozen_copies() -> None:
    item = _Frozen(Path("a.pcap"), [{"packet": 3}])
    _rollup_set(item, "path", Path("ALL_PCAPS"))
    assert item.path.name == "ALL_PCAPS"
    _tag_capture_records(_Frozen(Path("b.pcap"), rows := [{"packet": 7}]))
    assert rows[0]["capture"] == "b.pcap"


@dataclass(frozen=True)
class _Timed:
    first_seen: float
    last_seen: float
    duration_seconds: float


def test_rollup_duration_is_the_span_not_the_sum() -> None:
    """Two 8 s captures of the same window merged to 16 s: CTF pairs
    first_seen/last_seen with duration_seconds, which the fix-up missed."""
    merged = _Timed(100.0, 108.0, 16.0)
    _rollup_fix_duration(merged)
    assert merged.duration_seconds == 8.0


def test_non_additive_fields_are_not_summed() -> None:
    assert _rollup_numeric_kind("total_packets") == "sum"
    assert _rollup_numeric_kind("linktype") == "max"
    assert _rollup_numeric_kind("unique_ips") == "max"
    assert _rollup_numeric_kind("control_rate_per_min") == "max"
    assert _rollup_numeric_kind("min_ttl") == "min"


def test_ctf_rollup_uses_the_ctf_report(tmp_path) -> None:
    paths = []
    for name in ("one.pcap", "two.pcap"):
        pkt = _tcp("10.0.0.9", "10.0.0.5", 80, 40000, b"HTTP/1.1 200 OK\r\n\r\nflag{r0llup_m3rg3d}")
        pkt.time = T0
        paths.append(str(_write(tmp_path, name, [pkt])))
    env = dict(os.environ, PCAPPER_CACHE_ENABLED="0")
    out = subprocess.run([sys.executable, "-m", "pcapper", *paths, "--ctf", "-summarize", "--no-color"],
                         capture_output=True, text=True, env=env, timeout=600).stdout
    text = re.sub(r"\x1b\[[0-9;]*m", "", out)
    assert "CTF · all captures" in text and "ROLLUP" not in text
    assert "flag{r0llup_m3rg3d}" in text and "one.pcap" in text
