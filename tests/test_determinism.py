"""Output ordering must not depend on the interpreter's hash seed.

The README promises deterministic ordering, and pcapper's output is used as
evidence: two analysts running the same command on the same capture must get
the same report, and a report must be reproducible months later. Python
randomises string hashing per process, so any ordering that falls through to
set or dict iteration varies run to run — silently, and only sometimes.

These run the CLI in a subprocess twice with different ``PYTHONHASHSEED``
values, because hash randomisation is fixed for the life of a process and
cannot be exercised in-process.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

# Each case spawns two interpreters, so the module costs ~30s. CI runs it;
# locally, skip with `pytest -m "not slow"`.
pytestmark = pytest.mark.slow

SEEDS = ("0", "987654")

# One per analyzer family that produces ranked host or event lists — the shape
# most likely to tie and fall back to iteration order.
COMMANDS = [
    ("modbus.pcap", ["--compromised"]),
    ("modbus.pcap", ["--threats"]),
    ("modbus.pcap", ["--modbus"]),
    ("modbus.pcap", ["--overview"]),
    ("dns.pcap", ["--dns"]),
    ("dns.pcap", ["--overview"]),
    ("dns.pcap", ["--hostnames"]),
    ("http.pcap", ["--http"]),
    ("http.pcap", ["--creds"]),
    ("http.pcap", ["--ip"]),
    ("carve_gap.pcap", ["--carve"]),
]


def _run(pcap: Path, flags: list[str], seed: str) -> str:
    env = dict(
        os.environ,
        NO_COLOR="1",
        PYTHONIOENCODING="utf-8",
        PYTHONHASHSEED=seed,
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pcapper",
            str(pcap),
            *flags,
            "--no-color",
            "--no-status",
            "--quiet",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        cwd=Path(__file__).parent.parent,
        timeout=300,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    return result.stdout


@pytest.mark.parametrize(
    "capture,flags", COMMANDS, ids=[f"{c}{'-'.join(f)}" for c, f in COMMANDS]
)
def test_output_does_not_depend_on_hash_seed(capture: str, flags: list[str], pcap) -> None:
    path = pcap(capture)
    first = _run(path, flags, SEEDS[0])
    second = _run(path, flags, SEEDS[1])
    assert first == second, (
        f"`pcapper {capture} {' '.join(flags)}` produced different output under "
        f"PYTHONHASHSEED={SEEDS[0]} and {SEEDS[1]}. Something is ordering by set "
        "or dict iteration, or sorting on a key that is not a total order — add "
        "a tiebreaker."
    )


def test_compromised_host_sort_is_a_total_order() -> None:
    """Regression for the specific case found: `compromised_hosts` was sorted on
    (severity, score) alone. Both are small and tie constantly, and the tie then
    fell through to insertion order, which is not stable across runs."""
    from pcapper.compromised import SEVERITY_WEIGHT

    class _Host:
        def __init__(self, ip: str, severity: str, score: int) -> None:
            self.ip, self.severity, self.score = ip, severity, score

    hosts = [
        _Host("192.168.10.50", "high", 10),
        _Host("192.168.10.10", "high", 10),
        _Host("10.0.0.1", "critical", 3),
        _Host("10.0.0.2", "high", 12),
    ]
    key = lambda h: (-SEVERITY_WEIGHT.get(h.severity, 0), -h.score, h.ip)  # noqa: E731
    for permutation in ([0, 1, 2, 3], [3, 2, 1, 0], [1, 3, 0, 2]):
        ordered = [hosts[i] for i in permutation]
        ordered.sort(key=key)
        assert [h.ip for h in ordered] == [
            "10.0.0.1",
            "10.0.0.2",
            "192.168.10.10",
            "192.168.10.50",
        ], "sort result depends on input order — the key is not a total order"
