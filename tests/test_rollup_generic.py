"""-summarize: the generic rollup merger's rules (pcapper/rollup.py), and the
end-to-end properties a rollup must have:

* it does not depend on the order the captures are named in;
* merging a capture with one that holds nothing changes nothing -- a quiet
  capture's "No DNS traffic detected", benign claims, empty statistics and
  zero-count histogram rows must not leak into the merge.
"""

from __future__ import annotations

import contextlib
import dataclasses
import io
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from pcapper import cli, pcap_cache, port_heuristics, port_overrides, utils
from pcapper.rollup import (
    common_claims,
    drop_partial_absences,
    earliest_per_key,
    merge_bucket_lists,
    merge_generic_rollup_summaries,
    merge_sample_stats,
    is_negative_claim,
    merge_benign_claims,
    merge_records,
    merge_stats_by_key,
    merge_undirected,
    merge_window,
    recount_uniques,
    order_by_capture,
    verdict_rank,
)

DATA = Path(__file__).parent / "data"


# --- rules ----------------------------------------------------------------------


def test_sample_statistics_merge() -> None:
    quiet = {"min": 0.0, "max": 0.0, "avg": 0.0, "p50": 0.0, "p95": 0.0}
    busy = {"min": 54.0, "max": 1514.0, "avg": 300.0, "p50": 64.0, "p95": 1013.0}
    # A capture without samples is ignored: its zeros are not a minimum.
    assert merge_sample_stats([busy, quiet]) == busy
    other = {"min": 40.0, "max": 900.0, "avg": 100.0, "p50": 60.0, "p95": 500.0}
    merged = merge_sample_stats([busy, other], [3, 1])
    assert (merged["min"], merged["max"]) == (40.0, 1514.0)  # exact
    assert merged["p50"] == pytest.approx((64 * 3 + 60) / 4) and merged["approx"]  # an estimate, marked
    by_server = merge_stats_by_key([{"a": busy}, {"a": other, "b": busy}])
    assert by_server["b"] == busy and by_server["a"]["approx"]


def test_histogram_buckets_merge_per_label() -> None:
    from pcapper.sizes import SizeBucketStat

    def bucket(label: str, count: int, avg: float, rate: float = 0.0) -> SizeBucketStat:
        return SizeBucketStat(label=label, count=count, avg=avg, min=int(avg), max=int(avg), rate=rate, pct=0.0,
                              burst_rate=float(count), burst_start=None)

    merged = merge_bucket_lists([[bucket("0-99", 4, 60.0, 2.0), bucket("100-199", 0, 0.0)],
                                 [bucket("0-99", 6, 80.0, 3.0), bucket("100-199", 2, 150.0, 1.0)]])
    assert [b.label for b in merged] == ["0-99", "100-199"]  # one row per bucket, not one per capture
    first = merged[0]
    assert first.count == 10 and first.avg == pytest.approx(72.0) and first.pct == pytest.approx(10 / 12 * 100)
    assert first.rate == pytest.approx(10 / (4 / 2.0 + 6 / 3.0))  # total count over total observed time


def test_absence_and_benign_claims_need_every_capture() -> None:
    absent = {"severity": "info", "summary": "No DNS traffic detected", "absence": True}
    real = {"severity": "high", "summary": "DNS tunnel"}
    assert drop_partial_absences([[real], [absent]]) == [real]
    assert drop_partial_absences([[absent], [dict(absent)]]) == [absent]  # every capture: kept, once
    assert common_claims([["no SYN scan", "no exfil"], ["no exfil"]]) == ["no exfil"]


def test_first_seen_maps_keep_the_earliest() -> None:
    assert earliest_per_key([{"a": 5.0, "b": 1.0}, {"a": 2.0}]) == {"a": 2.0, "b": 1.0}


def test_verdicts_take_the_most_severe() -> None:
    assert verdict_rank("LIKELY - x") > verdict_rank("POSSIBLE - y") > verdict_rank("NO STRONG SIGNAL") > verdict_rank("")


@dataclasses.dataclass
class _Summary:
    path: Path
    detections: list = dataclasses.field(default_factory=list)
    benign_context: list = dataclasses.field(default_factory=list)
    session_times: dict = dataclasses.field(default_factory=dict)
    packet_size_stats: dict = dataclasses.field(default_factory=dict)
    analyst_verdict: str = ""
    analyst_confidence: str = ""
    packets: int = 0
    first_seen: float | None = None
    last_seen: float | None = None
    duration: float | None = None


def test_generic_merge_applies_every_rule() -> None:
    a = _Summary(Path("a.pcap"), detections=[{"summary": "No X traffic detected", "absence": True}],
                 benign_context=["no exfil", "no scan"], session_times={"s": (10.0, 20.0)},
                 packet_size_stats={"min": 0.0, "max": 0.0, "avg": 0.0, "p50": 0.0, "p95": 0.0},
                 analyst_verdict="NO STRONG SIGNAL - x", analyst_confidence="low", packets=0, first_seen=10.0, last_seen=20.0)
    b = _Summary(Path("b.pcap"), detections=[{"summary": "Real finding"}], benign_context=["no scan"],
                 session_times={"s": (5.0, 15.0)}, packet_size_stats={"min": 60.0, "max": 90.0, "avg": 70.0, "p50": 66.0, "p95": 88.0},
                 analyst_verdict="LIKELY - y", analyst_confidence="medium", packets=7, first_seen=5.0, last_seen=40.0)
    merged = merge_generic_rollup_summaries([a, b])
    assert merged.path.name == "ALL_PCAPS_2"
    assert [d["summary"] for d in merged.detections] == ["Real finding"]
    assert merged.benign_context == ["no scan"]
    assert merged.session_times == {"s": (5.0, 20.0)}
    assert merged.packet_size_stats == b.packet_size_stats
    assert (merged.analyst_verdict, merged.analyst_confidence) == ("LIKELY - y", "medium")
    assert (merged.packets, merged.first_seen, merged.last_seen, merged.duration) == (7, 5.0, 40.0, 35.0)


def test_captures_merge_in_chronological_order() -> None:
    late, early, unknown = _Summary(Path("late.pcap")), _Summary(Path("early.pcap")), _Summary(Path("zzz.pcap"))
    starts = {str(late.path): 200.0, str(early.path): 100.0}
    assert order_by_capture([unknown, late, early], starts) == [early, late, unknown]


# --- end to end ------------------------------------------------------------------


def _run(argv: list[str], monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setattr(sys, "argv", ["pcapper", *argv, "--quiet", "--no-status", "--no-auto-decode"])
    monkeypatch.setenv("PCAPPER_QUOTE", "q")
    utils.clear_analysis_memo()
    pcap_cache._PACKET_CACHE.clear()
    pcap_cache._HASH_CACHE.clear()
    pcap_cache._PCAPNG_META.clear()
    port_heuristics.clear_detections()
    port_overrides.clear()
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        cli.main()
    return re.sub(r"\x1b\[[0-9;]*m", "", buffer.getvalue())


def _empty_capture(tmp_path: Path) -> Path:
    from scapy.utils import PcapWriter  # type: ignore

    target = tmp_path / "empty.pcap"
    writer = PcapWriter(str(target), linktype=1)
    writer._write_header(None)
    writer.close()
    return target


ROLLUP_FLAGS = ["--dns", "--icmp", "--ips", "--sizes", "--tcp", "--udp", "--arp", "--beacon", "--modbus", "--threats",
                "--mitre", "--protocols", "--malware", "--exfil", "--health", "--ot-commands", "--overview", "--strings",
                "--services", "-v"]


def test_rollup_does_not_depend_on_capture_order(monkeypatch: pytest.MonkeyPatch) -> None:
    a, b = str(DATA / "mixed.pcap"), str(DATA / "voip.pcap")
    forward = _run(["-summarize", a, b, *ROLLUP_FLAGS], monkeypatch)
    backward = _run(["-summarize", b, a, *ROLLUP_FLAGS], monkeypatch)
    assert forward == backward


def _normalised(text: str, name: str) -> list[str]:
    out = []
    for line in text.splitlines():
        if line.startswith("PCAPPER v"):
            continue
        line = re.sub(r"all captures \(\d+\)|all captures", "<CAP>", line.replace(name, "<CAP>"))
        # A rollup names the capture a record came from (provenance), by design.
        line = line.replace("<CAP>: ", "")
        # A report names its capture; a rollup counts its captures.
        line = re.sub(r"^(\s*)(?:Path:\s+\S*<CAP>|Captures:\s+\d+)$", r"\1<CAPTURES>", line.rstrip())
        out.append(line.replace("in these captures", "in this capture").rstrip())
    return out


# Reports a rollup changes on purpose: health leaves out rates across a span
# that includes the gaps between captures.
IDENTITY_FLAGS = [f for f in ROLLUP_FLAGS if f != "--health"]


def test_a_quiet_capture_changes_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    capture = DATA / "mixed.pcap"
    empty = _empty_capture(tmp_path)
    alone = _normalised(_run([str(capture), *IDENTITY_FLAGS], monkeypatch), capture.name)
    merged = _normalised(_run(["-summarize", str(capture), str(empty), *IDENTITY_FLAGS], monkeypatch), capture.name)
    assert merged == alone


# Steps that list entities several captures share: conversations, hosts,
# services, leases, technique hits, findings.
SELF_FLAGS = ["--arp", "--dhcp", "--dns", "--icmp", "--ips", "--tcp", "--udp", "--protocols", "--netbios", "--ntlm",
              "--services", "--compromised", "--mitre", "--threats", "--strings", "--modbus", "--overview", "-v"]
# Addresses, MACs and timestamps say which row a line is; every other number
# (with its unit: 652 B doubles to 1.27 KB) is a count.
_ROW_TOKENS = re.compile(
    r"(?P<keep>\d{4}-\d\d-\d\dT[\d:.]+Z?"
    r"|(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?![\w.])"
    r"|(?<![\w:])[0-9a-f]{2}(?::[0-9a-f]{2}){5}(?![\w:])"
    r"|(?<![\w:])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?![\w:]))"
    r"|(?P<num>\d[\d,.]*\s?(?:[KMGT]i?B|B|ms|us|s|m|h|d|%|pps|bps|/min|/s|/h)?)",
    re.I,
)
_DISTINCT = re.compile(
    r"(\d[\d,]*)\s+(hosts?|conversations?|flows?|incidents?|indicators?|unique|clients?|servers?|"
    r"detections?|findings?|technique hits)\b"
)


def _row_shapes(lines: list[str]) -> dict[str, int]:
    shapes: dict[str, int] = {}
    for line in lines:
        text = line.strip()
        if len(text) <= 3 or set(text) <= set("─═-=│|·•. "):
            continue
        # "≈": a rollup's percentiles are estimates (see merge_sample_stats).
        shape = re.sub(r"\s+", " ", _ROW_TOKENS.sub(lambda m: m.group("keep") or "#", text.replace("≈", "")))
        shapes[shape] = shapes.get(shape, 0) + 1
    return shapes


def test_a_capture_merged_with_its_copy_lists_each_record_once(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A capture and a byte-identical copy are that traffic twice over: every
    row once with its counts doubled, every count of distinct things -- hosts,
    flows, unique strings, findings -- unchanged. Rows several captures share
    were listed once per capture, and their distinct counts added up."""
    capture = DATA / "mixed.pcap"
    copy = tmp_path / "mixed-copy.pcap"
    copy.write_bytes(capture.read_bytes())
    alone = _normalised(_run([str(capture), *SELF_FLAGS], monkeypatch), capture.name)
    both = _normalised(
        _run(["-summarize", str(capture), str(copy), *SELF_FLAGS], monkeypatch).replace(copy.name, capture.name),
        capture.name,
    )
    single, merged = _row_shapes(alone), _row_shapes(both)
    repeated = sorted(shape for shape, count in merged.items() if count > max(1, single.get(shape, 0)))
    assert not repeated, repeated[:5]

    def distinct(lines: list[str]) -> list[tuple[str, str]]:
        return [(m.group(2), m.group(1)) for line in lines for m in _DISTINCT.finditer(line)]

    assert distinct(both) == distinct(alone)


def _generic_steps() -> list[tuple[str, str]]:
    """(step, analyzer) for every step merged by the generic rules: its
    analyzer's module has no merge function of its own."""
    import importlib

    steps = []
    for step, names in sorted(cli._SIMPLE_STEP_ANALYZERS.items()):
        fn = getattr(cli, names[0], None) if names else None
        if fn is None:
            continue
        module = importlib.import_module(getattr(getattr(fn, "__wrapped__", fn), "__module__", ""))
        if not any(name.startswith("merge_") for name in vars(module)):
            steps.append((step, names[0]))
    return steps


@pytest.mark.parametrize("step, analyzer", _generic_steps(), ids=lambda v: v if not str(v).startswith("analyze") else None)
def test_generic_merge_carries_every_populated_field(step: str, analyzer: str) -> None:
    """The generic merge of two real captures keeps every field either holds
    (the dedicated merges have tests/test_merge_summaries.py)."""
    fn = getattr(cli, analyzer)
    utils.clear_analysis_memo()
    inputs = [fn(DATA / name, show_status=False) for name in ("mixed.pcap", "voip.pcap")]
    merged = merge_generic_rollup_summaries(inputs)
    assert merged is not None and merged.path.name == "ALL_PCAPS_2"

    def empty(value: object) -> bool:
        return value in (None, 0, "", 0.0) or (isinstance(value, (list, dict, set, tuple)) and not value)

    dropped = [f.name for f in dataclasses.fields(merged) if f.name != "path"
               and empty(getattr(merged, f.name, None)) and any(not empty(getattr(i, f.name, None)) for i in inputs)]
    assert not dropped, f"generic merge of {step} drops {dropped}"


# --- records: rows of a list field ------------------------------------------------


@dataclasses.dataclass(frozen=True)
class _Conv:
    src_ip: str
    dst_ip: str
    dst_port: int
    packets: int
    bytes: int
    first_seen: float | None
    last_seen: float | None


def _flows() -> list[_Conv]:
    return [
        _Conv("10.0.0.57", "10.0.0.3", 502, 10, 1000, 100.0, 110.0),
        _Conv("10.0.0.57", "10.0.0.3", 503, 4, 400, 101.0, 102.0),
    ]


def test_records_of_a_quiet_capture_change_nothing() -> None:
    rows = _flows()
    assert merge_records([rows, []]) == rows


def test_records_of_a_capture_and_its_copy_are_listed_once_with_counts_doubled() -> None:
    merged = merge_records([_flows(), _flows()])
    assert [(r.dst_port, r.packets, r.bytes, r.first_seen, r.last_seen) for r in merged] == [
        (502, 20, 2000, 100.0, 110.0),
        (503, 8, 800, 101.0, 102.0),
    ]


def test_records_merge_by_key_and_widen_the_window() -> None:
    later = [_Conv("10.0.0.57", "10.0.0.3", 502, 5, 500, 200.0, 250.0), _Conv("10.0.0.9", "10.0.0.3", 502, 1, 60, 205.0, 205.0)]
    merged = merge_records([_flows(), later])
    assert [(r.src_ip, r.dst_port, r.packets, r.first_seen, r.last_seen) for r in merged] == [
        ("10.0.0.57", 502, 15, 100.0, 250.0),
        ("10.0.0.57", 503, 4, 101.0, 102.0),
        ("10.0.0.9", 502, 1, 205.0, 205.0),
    ]


def test_records_of_one_capture_are_never_collapsed() -> None:
    """Rows merge across captures one to one; two equal rows of one capture
    stay two (and meet their own copies in a self-merge)."""
    events = [{"ts": 5.0, "src": "a", "command": "write"}, {"ts": 5.0, "src": "a", "command": "write"}]
    assert len(merge_records([events, []])) == 2
    assert len(merge_records([events, [dict(e) for e in events]])) == 2
    assert len(merge_records([events, [{"ts": 6.0, "src": "a", "command": "write"}]])) == 3


def test_records_located_by_packet_number_keep_their_capture() -> None:
    first = [{"packet": 12, "kind": "credential", "capture": "a.pcap"}]
    second = [{"packet": 12, "kind": "credential", "capture": "b.pcap"}]
    assert len(merge_records([first, second])) == 2
    events = merge_records([[{"ts": 1.0, "kind": "x", "capture": "a.pcap"}], [{"ts": 1.0, "kind": "x", "capture": "b.pcap"}]])
    assert events == [{"ts": 1.0, "kind": "x", "capture": "a.pcap, b.pcap"}]


def test_record_strings_are_listed_once() -> None:
    assert merge_records([["a", "b", "b"], ["b", "c"]]) == ["a", "b", "b", "c"]


def test_record_distinct_counts_are_recounted_not_added() -> None:
    """``client_count`` counts hosts: the same two clients in two captures are
    two clients, not four -- recounted from the row's preview of them."""
    service = {"service": "Modbus/TCP", "endpoint": "10.0.0.3", "port": 502, "count": 53,
               "clients": "10.0.0.57, 10.0.0.9", "client_count": 2}
    other = dict(service, count=7, clients="10.0.0.57, 10.0.0.77", client_count=2)
    merged = merge_records([[service], [other]])
    assert merged == [dict(service, count=60, clients="10.0.0.57, 10.0.0.77, 10.0.0.9", client_count=3)]
    # A preview cut at its analyzer's limit stays cut; the count stays a lower bound.
    wide = dict(service, clients="10.0.0.1, 10.0.0.2", client_count=9)
    merged = merge_records([[wide], [other]])
    assert merged[0]["clients"] == "10.0.0.1, 10.0.0.2" and merged[0]["client_count"] == 9


def test_record_durations_and_rates_follow_the_merged_traffic() -> None:
    """With a window the duration is its span and rates are recomputed; without
    one the durations add up (consecutive captures) and so does the time."""
    row = {"src": "a", "dst": "b", "bytes": 1000, "packets": 10, "duration_seconds": 10.0,
           "bytes_per_second": 100.0, "avg_packet_bytes": 100.0}
    merged = merge_records([[row], [dict(row, bytes=3000, packets=10, duration_seconds=10.0,
                                         bytes_per_second=300.0, avg_packet_bytes=300.0)]])[0]
    assert merged["duration_seconds"] == 20.0 and merged["bytes_per_second"] == 200.0
    assert merged["avg_packet_bytes"] == 200.0
    flow = {"src": "a", "dst": "b", "packets": 10, "bytes": 1000, "start_ts": 0.0, "end_ts": 10.0,
            "duration_seconds": 10.0, "packets_per_sec": 1.0, "bits_per_sec": 800}
    merged = merge_records([[flow], [dict(flow, start_ts=30.0, end_ts=40.0)]])[0]
    assert (merged["duration_seconds"], merged["packets_per_sec"], merged["bits_per_sec"]) == (40.0, 0.5, 400)


def test_records_of_one_conversation_merge_whichever_way_round() -> None:
    """A conversation keeps the direction of its first packet, so another
    capture can hold A<->B as B->A: still one conversation."""
    first = [{"src": "10.0.0.5", "dst": "10.0.0.9", "protocol": "TCP", "scope_pair": "internal->public",
              "packets": 4, "start_ts": 10.0, "end_ts": 20.0}]
    second = [{"src": "10.0.0.9", "dst": "10.0.0.5", "protocol": "TCP", "scope_pair": "public->internal",
               "packets": 6, "start_ts": 30.0, "end_ts": 40.0}]
    merged = merge_undirected([first, second])
    assert merged == [{"src": "10.0.0.5", "dst": "10.0.0.9", "protocol": "TCP", "scope_pair": "internal->public",
                       "packets": 10, "start_ts": 10.0, "end_ts": 40.0}]
    # Another protocol between the same hosts is another conversation.
    assert len(merge_undirected([first, [dict(second[0], protocol="UDP")]])) == 2


def test_a_merged_duration_spans_the_captures() -> None:
    """Durations of captures that overlap (or are one file twice) are not added
    up: the merge spans its captures' first and last packets."""

    @dataclasses.dataclass
    class _Summary:
        duration: float = 0.0
        first_seen: float | None = None
        last_seen: float | None = None

    merged = _Summary(duration=120.0)  # what adding the durations up gave
    merge_window(merged, [_Summary(60.0, 100.0, 160.0), _Summary(60.0, 130.0, 190.0)])
    assert (merged.first_seen, merged.last_seen, merged.duration) == (100.0, 190.0, 90.0)
    # Without times the summed duration stands (consecutive captures).
    untimed = _Summary(duration=120.0)
    merge_window(untimed, [_Summary(60.0), _Summary(60.0)])
    assert untimed.duration == 120.0


def _run_with_seed(argv: list[str], seed: str) -> str:
    env = dict(os.environ, PYTHONHASHSEED=seed, NO_COLOR="1", PCAPPER_NO_COLOR="1", PCAPPER_QUOTE="q",
               PYTHONIOENCODING="utf-8")
    proc = subprocess.run([sys.executable, "-m", "pcapper", *argv, "--quiet", "--no-status", "--no-auto-decode"],
                          env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)
    assert proc.returncode == 0, proc.stderr[-400:]
    return proc.stdout


def test_reports_do_not_depend_on_the_hash_seed() -> None:
    """The same captures print the same report on every run. Python orders a
    set of strings by a per-process hash seed, and sorts over a set without a
    full tie-break (IP hosts, SMB commands, DHCP client profiles) printed tied
    rows in a different order each run: a report must not depend on the run,
    nor a rollup's "order of captures does not matter" on luck."""
    flags = ["--ips", "--smb", "--dhcp", "--enip", "--ssh", "--tcp", "--udp", "--arp", "--dns", "--protocols", "-v"]
    single = [str(DATA / "mixed.pcap"), *flags]
    rollup = ["-summarize", str(DATA / "mixed.pcap"), str(DATA / "voip.pcap"), *flags]
    for argv in (single, rollup):
        assert _run_with_seed(argv, "1") == _run_with_seed(argv, "2")


def test_unique_counts_are_recounted_from_the_merged_counters() -> None:
    """``unique_<x>`` of a rollup is the size of its merged ``<x>_counts`` (the
    hosts several captures share counted once), not either capture's count."""

    @dataclasses.dataclass
    class _Summary:
        client_counts: dict
        unique_clients: int
        unique_widgets: int = 7  # no counter of widgets: left as it is

    merged = _Summary(client_counts={"10.0.0.1": 3, "10.0.0.2": 1, "10.0.0.3": 2}, unique_clients=2)
    recount_uniques(merged)
    assert (merged.unique_clients, merged.unique_widgets) == (3, 7)


def test_claims_of_absence_hold_only_when_every_capture_makes_them() -> None:
    """A quiet capture's "No SYN scan observed" must not stand beside another
    capture's scan; an explanation of what a capture did hold is kept."""
    assert is_negative_claim("No sustained SYN fan-out observed.")
    assert is_negative_claim("DNS not observed")
    assert not is_negative_claim("Answer rotation may reflect CDN behaviour.")
    busy = ["Answer rotation may reflect CDN behaviour.", "No SYN fan-out observed."]
    quiet = ["No SYN fan-out observed.", "No DNS traffic observed."]
    assert merge_benign_claims([busy, quiet]) == busy
    assert merge_benign_claims([busy, ["Something else entirely."]]) == [
        "Answer rotation may reflect CDN behaviour.", "Something else entirely."]


def test_top_n_ties_are_ranked_like_the_whole_list() -> None:
    """pcapper ranks Counter ties by key: a top-N cut ranks (and chooses) them
    as the whole ranking does. It ranked them in reverse when cut, so a
    capture's top strings and a rollup re-ranking them disagreed."""
    import collections

    import pcapper  # noqa: F401 - installs the deterministic most_common

    counter = collections.Counter({"zeta": 5, "alpha": 5, "mid": 7, "beta": 5, "omega": 1})
    whole = counter.most_common()
    assert whole == [("mid", 7), ("alpha", 5), ("beta", 5), ("zeta", 5), ("omega", 1)]
    for n in range(1, len(counter) + 1):
        assert counter.most_common(n) == whole[:n]


def test_a_service_rows_clients_are_recounted_from_its_client_list() -> None:
    """A service's client count across captures counts the clients they share
    once, from the row's client list -- exact where the five-client preview
    alone gave only a lower bound."""
    first = {"service": "DNS", "endpoint": "10.0.0.53", "port": 53, "proto": "UDP", "count": 100,
             "clients": "10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4, 10.0.0.5", "client_count": 8,
             "client_list": [f"10.0.0.{i}" for i in range(1, 9)]}
    second = dict(first, count=50, client_count=7, client_list=[f"10.0.0.{i}" for i in range(4, 11)],
                  clients="10.0.0.10, 10.0.0.4, 10.0.0.5, 10.0.0.6, 10.0.0.7")
    merged = merge_records([[first], [second]])
    assert len(merged) == 1
    assert (merged[0]["count"], merged[0]["client_count"], len(merged[0]["client_list"])) == (150, 10, 10)
    assert merged[0]["clients"] == "10.0.0.1, 10.0.0.10, 10.0.0.2, 10.0.0.3, 10.0.0.4"


def test_overview_tables_count_distinct_things_once() -> None:
    """The overview's tables count distinct things per row -- a protocol's flows
    and hosts, a service's assets, hosts and clients, a host's peers and
    conversations -- in columns without a noun beside them. A capture merged
    with its own copy keeps every one of them and doubles the packets: the
    merge added the columns up, so every protocol showed twice its hosts."""
    import copy

    from pcapper.overview import analyze_overview, merge_overview_summaries

    utils.clear_analysis_memo()
    alone = analyze_overview(DATA / "mixed.pcap", show_status=False)
    twice = merge_overview_summaries([copy.deepcopy(alone), copy.deepcopy(alone)])

    def table(rows: list, key: str, columns: tuple[str, ...]) -> dict:
        return {row[key]: tuple(row.get(c) for c in columns) for row in rows if isinstance(row, dict)}

    for rows_alone, rows_twice, key, columns in (
        (alone.protocol_activity, twice.protocol_activity, "protocol", ("flow_count", "host_count")),
        (alone.service_activity, twice.service_activity, "service", ("asset_count", "host_count", "client_count")),
        (alone.ip_activity, twice.ip_activity, "ip", ("peer_count", "public_peer_count", "internal_peer_count",
                                                      "conversation_count", "service_count", "used_service_count")),
    ):
        assert table(rows_twice, key, columns) == table(rows_alone, key, columns)
    assert twice.top_services == alone.top_services
    assert {r["protocol"]: r["packets"] * 2 for r in alone.protocol_activity} == {
        r["protocol"]: r["packets"] for r in twice.protocol_activity}
    assert twice.summary_details["flow_count"] == alone.summary_details["flow_count"]
