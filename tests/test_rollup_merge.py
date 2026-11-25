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


def test_rollup_details_do_not_sum_ip_octets_or_percentages() -> None:
    from pcapper.utils import collapse_detection_details

    details = [
        "192.168.121.2 accounts for 100.0% of IP bytes.",
        "192.168.122.2 accounts for 100.0% of IP bytes.",
        "10.82.40.105 accounts for 100.0% of IP bytes.",
    ]
    merged = collapse_detection_details(details)
    assert "394" not in merged and "300" not in merged
    assert "192.168.121.2" in merged and "+1 additional detail variant" in merged
    # Same host and share in every capture: identical text, nothing to sum.
    same = collapse_detection_details(["10.0.0.1 accounts for 60.0% of IP bytes."] * 3)
    assert same == "10.0.0.1 accounts for 60.0% of IP bytes."


def test_rollup_details_never_add_up_free_text_numbers() -> None:
    """Unique peers of two captures are not 4 + 6 (a peer may be in both),
    and an account named 1001 in two captures is not account 2002: differing
    details are listed, not summed."""
    from pcapper.utils import collapse_detection_details

    merged = collapse_detection_details([
        "10.0.0.1 received traffic from 4 unique peers.",
        "10.0.0.1 received traffic from 6 unique peers.",
    ])
    assert merged == "10.0.0.1 received traffic from 4 unique peers. | 10.0.0.1 received traffic from 6 unique peers."
    accounts = collapse_detection_details(["1 credential(s) for 1 account(s): 1001", "13 credential(s) for 1 account(s): 1001"])
    assert "2002" not in accounts and "14 credential" not in accounts
    assert collapse_detection_details(["same text", "same text"]) == "same text"


def test_self_addressed_traffic_share_is_at_most_100_percent(tmp_path) -> None:
    from pcapper.ips import analyze_ips

    path = _write(tmp_path, "self.pcap", [_tcp("10.0.0.5", "10.0.0.5", 40000, 2404, b"x" * 20) for _ in range(5)])
    summary = analyze_ips(path, show_status=False)
    details = [d["details"] for d in summary.detections if d.get("summary") == "Traffic concentration on a single host"]
    assert details == ["10.0.0.5 accounts for 100.0% of IP bytes."]


def test_rollup_concentration_is_recomputed_on_merged_traffic(tmp_path) -> None:
    """Three single-host captures: each host is 100% of its own capture, but
    a third of the merged bytes, so the rollup must not claim concentration."""
    from pcapper.ips import analyze_ips, merge_ips_summaries

    summaries = []
    for host in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        pkts = [_tcp(host, host, 40000, 2404, b"x" * 20) for _ in range(5)]
        summaries.append(analyze_ips(_write(tmp_path, f"{host}.pcap", pkts), show_status=False))
    merged = merge_ips_summaries(summaries)
    assert [d for d in merged.detections if d.get("summary") == "Traffic concentration on a single host"] == []
    # Self-addressed bytes count once in a host's total.
    for endpoint in merged.endpoints:
        assert endpoint.bytes_sent == endpoint.bytes_recv == endpoint.bytes_self
        assert endpoint.bytes_total == endpoint.bytes_sent
