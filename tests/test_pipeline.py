"""The read-once pipeline: a run computes everything it needs from one read of
the capture -- held in memory, or streamed from disk in one shared pass --
hashes it on that read, and --jobs spreads the analyses over processes with
the same report."""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import io
import os
import shutil
import sys
from array import array
from pathlib import Path

import pytest

pytest.importorskip("scapy")

from scapy.all import IP, TCP, Ether, Raw, wrpcap  # noqa: E402

from pcapper import cli, pcap_cache, port_heuristics, port_overrides, sharedpass, timeline, utils  # noqa: E402
from pcapper.analyzer import analyze_pcap  # noqa: E402
from pcapper.rawcap import LiteStream  # noqa: E402

DATA = Path(__file__).parent / "data"


@pytest.fixture(autouse=True)
def _reset_pipeline_state():
    yield
    utils._FAN_OUT_HOOK = None
    sharedpass.set_jobs(1)
    pcap_cache._CAPTURE_WINDOWS.clear()
    pcap_cache._ESTIMATES.clear()
    pcap_cache._PACKET_CACHE.clear()
    pcap_cache._HASH_WANTED.clear()
    pcap_cache._HASH_CACHE.clear()
    pcap_cache._PCAPNG_META.clear()
    pcap_cache.discard_primed()
    utils.clear_analysis_memo()


def _mixed(tmp_path: Path) -> Path:
    path = tmp_path / "mixed.pcap"
    shutil.copy(DATA / "mixed.pcap", path)
    return path


def _run(path: Path, flags: list[str], monkeypatch: pytest.MonkeyPatch, **env: str) -> str:
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(sys, "argv", ["pcapper", str(path), *flags, "--quiet", "--no-status"])
    utils.clear_analysis_memo()
    pcap_cache._PACKET_CACHE.clear()
    pcap_cache._HASH_CACHE.clear()
    pcap_cache._PCAPNG_META.clear()
    # Each run detects decode-as ports itself (the detection is cached per
    # capture for the rest of a process).
    port_heuristics.clear_detections()
    port_overrides.clear()
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        cli.main()
    return buffer.getvalue()


# Steps whose analyses the run plans as a whole (cli._run_plan_roots).
_PLANNED_STEPS = [
    ["--http", "--dns"],
    ["--tls"],
    ["--files"],
    ["--ips"],
    ["--services"],
    ["--dns", "--dnsqueries"],
    ["--hostnames"],
    ["--webrequests"],
    ["--domain"],
    ["--creds"],
    ["--ctf"],
    ["--ot-commands"],
    ["--overview"],
    ["--threats"],
    ["--mitre"],
    ["--compromised"],
    ["--timeline", "-ip", "192.168.10.50"],
    ["--hostdetails", "-ip", "192.168.10.50"],
    ["--search", "update", "--voip", "--ip", "--mac", "--http"],
    ["--files", "-ip", "192.168.10.50"],
    ["--files", "--http", "-v"],
    ["--ioc", "--ioc-file", "{iocs}"],
    ["--mitre", "--ioc-file", "{iocs}"],
    ["--streams"],
    ["--carve", "--carve-out", "{carved}"],
    ["--streams", "--carve", "--carve-out", "{carved}", "--ioc", "--ioc-file", "{iocs}", "--http", "--dns"],
    ["--baseline-save", "{baseline}"],
    ["--http", "--correlate"],
    ["--control-loop"],
    ["--control-loop", "--modbus", "--dnp3"],
    ["--files", "-hash"],
    ["--files", "-hash", "update.exe", "--http"],
    ["--files", "-extract", "update.exe", "-view", "update.exe"],
]


@pytest.mark.parametrize("flags", _PLANNED_STEPS, ids=" ".join)
def test_disk_run_reads_the_capture_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flags: list[str]
) -> None:
    """From disk the capture is read once: one shared pass computes every
    analysis the steps then ask for -- the same calls, so the same memo keys
    -- or a single analysis streams it. A step computing anything after the
    plan means the plan and the step's call drifted apart (a kwarg added to
    one and not the other). (The decode-as port detection reads a bounded
    prefix of its own; it is off here so the count is exact.)"""
    path = _mixed(tmp_path)
    iocs = tmp_path / "iocs.txt"
    iocs.write_text("93.184.216.34\nupdates.example.net\n")
    flags = [f.format(iocs=iocs, carved=tmp_path / "carved", baseline=tmp_path / "baseline.json") for f in flags]
    flags += ["--no-auto-decode"]
    # Each run in a directory of its own: -extract writes files/ there.
    (tmp_path / "reference").mkdir()
    (tmp_path / "shared").mkdir()
    monkeypatch.chdir(tmp_path / "reference")
    reference = _run(path, flags, monkeypatch, PCAPPER_CACHE_ENABLED="0", PCAPPER_SHARED_PASS="0")

    rounds: list[int] = []
    real_broadcast = sharedpass.SharedPass._broadcast

    def _counting_broadcast(self, subs):  # type: ignore[no-untyped-def]
        rounds.append(len(subs))
        return real_broadcast(self, subs)

    state = {"depth": 0, "planned": False}
    after_plan: list[str] = []
    real_run_plan = sharedpass.run_plan
    real_store = utils._memo_store

    def _tracking_run_plan(*args, **kwargs):  # type: ignore[no-untyped-def]
        state["depth"] += 1
        ran = False
        try:
            ran = real_run_plan(*args, **kwargs)
            return ran
        finally:
            state["depth"] -= 1
            state["planned"] = state["planned"] or bool(ran)

    def _tracking_store(key, result, copy_results):  # type: ignore[no-untyped-def]
        if state["planned"] and state["depth"] == 0:
            after_plan.append(f"{key[0]}.{key[1]}")
        return real_store(key, result, copy_results)

    opened: list[int] = []
    real_init = LiteStream.__init__

    def _counting_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        opened.append(1)
        real_init(self, *args, **kwargs)

    real_open = pcap_cache._open_single_capture

    def _counting_open(*args, **kwargs):  # type: ignore[no-untyped-def]
        opened.append(1)  # a scapy reader
        return real_open(*args, **kwargs)

    hash_reads: list[int] = []
    real_hash = pcap_cache._hash_parts

    def _counting_hash(parts):  # type: ignore[no-untyped-def]
        hash_reads.append(1)
        return real_hash(parts)

    monkeypatch.setattr(sharedpass.SharedPass, "_broadcast", _counting_broadcast)
    monkeypatch.setattr(sharedpass, "run_plan", _tracking_run_plan)
    monkeypatch.setattr(utils, "_memo_store", _tracking_store)
    monkeypatch.setattr(LiteStream, "__init__", _counting_init)
    monkeypatch.setattr(pcap_cache, "_open_single_capture", _counting_open)
    monkeypatch.setattr(pcap_cache, "_hash_parts", _counting_hash)
    monkeypatch.chdir(tmp_path / "shared")
    shared = _run(path, flags, monkeypatch, PCAPPER_CACHE_ENABLED="0", PCAPPER_SHARED_PASS="1")

    assert shared.replace(str(tmp_path / "shared"), "<run>") == reference.replace(str(tmp_path / "reference"), "<run>")
    assert len(opened) == 1, f"{len(opened)} reads of the capture ({len(rounds)} shared {rounds})"
    assert len(rounds) <= 1
    assert hash_reads == [], "the hashes took a read of their own"
    assert after_plan == [], f"computed outside the plan: {after_plan}"


def test_single_step_with_nested_analyses_is_kept_in_memory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--domain alone starts DNS, TLS, HTTP and the file analysis too, and the
    domain analysis reads scapy packets: the capture is loaded once and every
    one reads it from memory, not from disk each."""
    path = _mixed(tmp_path)
    opened: list[int] = []
    real_init = LiteStream.__init__

    def _counting_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        opened.append(1)
        real_init(self, *args, **kwargs)

    loads: list[int] = []
    real_load = pcap_cache.load_packets

    def _counting_load(*args, **kwargs):  # type: ignore[no-untyped-def]
        loads.append(1)
        return real_load(*args, **kwargs)

    monkeypatch.setattr(LiteStream, "__init__", _counting_init)
    monkeypatch.setattr(pcap_cache, "load_packets", _counting_load)
    _run(path, ["--domain"], monkeypatch)
    assert loads == [1]
    assert opened == []


def test_lite_only_plan_streams_instead_of_loading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--http and --creds start only analyses that read lite records (HTTP,
    files, NFS, AIM, telnet). Streamed (PCAPPER_LITE_STREAM=1), one shared
    read from disk dissects just the packets they ask for instead of loading
    every packet with scapy; a small capture is loaded as before."""
    path = _mixed(tmp_path)
    opened: list[int] = []
    real_init = LiteStream.__init__

    def _counting_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        opened.append(1)
        real_init(self, *args, **kwargs)

    loads: list[int] = []
    real_load = pcap_cache.load_packets

    def _counting_load(*args, **kwargs):  # type: ignore[no-untyped-def]
        loads.append(1)
        return real_load(*args, **kwargs)

    monkeypatch.setattr(LiteStream, "__init__", _counting_init)
    monkeypatch.setattr(pcap_cache, "load_packets", _counting_load)
    for flags in (["--http"], ["--creds"]):
        opened.clear()
        loads.clear()
        _run(path, flags, monkeypatch, PCAPPER_LITE_STREAM="1")
        assert loads == [], flags
        assert len(opened) == 1, flags
        monkeypatch.delenv("PCAPPER_LITE_STREAM")
        opened.clear()
        _run(path, flags, monkeypatch)  # small: loaded, no look at its head
        assert loads == [1], flags
        assert opened == [], flags


def test_lite_only_plans_stream_scans_and_load_payloads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Above the size floor the head decides: a capture of payload-less
    segments (a scan) is streamed, one whose packets carry data is loaded."""
    from scapy.all import UDP

    scan = tmp_path / "scan.pcap"
    wrpcap(str(scan), [Ether() / IP(src="10.0.0.1", dst=f"10.0.{i // 250}.{i % 250 + 1}") / TCP(sport=40000, dport=i, flags="S") for i in range(1, 2000)])
    data = tmp_path / "data.pcap"
    wrpcap(str(data), [Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=6000) / Raw(b"x" * 400) for _ in range(400)])
    monkeypatch.setattr(cli, "_LITE_STREAM_MIN_BYTES", 1024)
    cli._LITE_STREAM_DECISIONS.clear()
    assert cli._streams_lite_plan(scan, True) is True
    assert cli._streams_lite_plan(data, True) is False
    monkeypatch.setattr(cli, "_LITE_STREAM_MIN_BYTES", 1 << 40)
    cli._LITE_STREAM_DECISIONS.clear()
    assert cli._streams_lite_plan(scan, True) is False  # below the floor: loaded without looking
    monkeypatch.setenv("PCAPPER_LITE_STREAM", "1")
    assert cli._streams_lite_plan(data, True) is True
    monkeypatch.setenv("PCAPPER_LITE_STREAM", "0")
    monkeypatch.setattr(cli, "_LITE_STREAM_MIN_BYTES", 1024)
    cli._LITE_STREAM_DECISIONS.clear()
    assert cli._streams_lite_plan(scan, True) is False
    cli._LITE_STREAM_DECISIONS.clear()


def test_in_memory_jobs_give_the_same_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if not sharedpass.parallel_available():
        pytest.skip("needs fork()")
    path = _mixed(tmp_path)
    # --compromised: ~100 analyses, a few of which read scapy packets, so the
    # capture is held in memory (--overview's all read lightweight records
    # and stream it instead).
    single = _run(path, ["--compromised", "--jobs", "1"], monkeypatch)
    returned: list[tuple[bool, int]] = []
    real_groups = sharedpass._run_groups

    def _counting_groups(*args, **kwargs):  # type: ignore[no-untyped-def]
        count = real_groups(*args, **kwargs)
        returned.append((kwargs.get("in_memory"), count))
        return count

    monkeypatch.setattr(sharedpass, "_run_groups", _counting_groups)
    parallel = _run(path, ["--compromised", "--jobs", "4"], monkeypatch)
    assert parallel == single
    assert returned and all(in_memory for in_memory, _count in returned)
    assert sum(count for _in_memory, count in returned) > 10  # the analyses really ran in workers


def test_jobs_for_a_capture_in_memory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if not sharedpass.parallel_available():
        pytest.skip("needs fork()")
    path = _mixed(tmp_path)
    pcap_cache.set_forced_packet_view(path, [object()] * 1_000_000, None)
    try:
        sharedpass.set_jobs(None)
        monkeypatch.setattr(pcap_cache, "_available_memory", lambda: 10**15)
        assert sharedpass.jobs_for(path, analyses=50) == sharedpass.auto_jobs()
        assert sharedpass.jobs_for(path, analyses=3) == min(3, sharedpass.auto_jobs())
        assert sharedpass.jobs_for(path, analyses=1) == 1  # nothing to spread
        # Each worker may copy the packets' memory: no more than half of
        # what is available holds.
        per_worker = 1_000_000 * pcap_cache.PACKET_MEMORY_BYTES
        monkeypatch.setattr(pcap_cache, "_available_memory", lambda: 3 * per_worker)
        assert sharedpass.jobs_for(path, analyses=50) == 1
        sharedpass.set_jobs(64)
        monkeypatch.setattr(pcap_cache, "_available_memory", lambda: 10**15)
        assert sharedpass.jobs_for(path, analyses=5) == 5  # never more workers than analyses
    finally:
        pcap_cache.clear_forced_packet_view(path)
    small = tmp_path / "small.pcap"
    shutil.copy(DATA / "dns.pcap", small)
    pcap_cache.set_forced_packet_view(small, [object()] * 6, None)
    try:
        sharedpass.set_jobs(None)
        assert sharedpass.jobs_for(small, analyses=96) == 1  # not worth a fork
    finally:
        pcap_cache.clear_forced_packet_view(small)


def _digests(data: bytes) -> tuple[str, str]:
    return hashlib.sha256(data).hexdigest(), hashlib.sha1(data).hexdigest()


def test_hashes_come_from_the_read_that_loads_the_capture(tmp_path: Path) -> None:
    path = _mixed(tmp_path)
    expected = _digests(path.read_bytes())
    key = pcap_cache._hashes_key(path)
    pcap_cache.want_hashes(path)
    assert list(LiteStream(path))  # a whole read from disk
    assert pcap_cache._HASH_CACHE.get(key) == expected
    pcap_cache._HASH_CACHE.clear()
    pcap_cache.load_packets(path, show_status=False)  # the scapy loader
    assert pcap_cache._HASH_CACHE.get(key) == expected
    assert pcap_cache.capture_hashes(path) == expected
    # A gzip-compressed capture: the compressed bytes, as capture_hashes does.
    packed = tmp_path / "mixed.pcap.gz"
    packed.write_bytes(gzip.compress(path.read_bytes()))
    pcap_cache.want_hashes(packed)
    assert list(LiteStream(packed))
    assert pcap_cache._HASH_CACHE.get(pcap_cache._hashes_key(packed)) == _digests(packed.read_bytes())


def test_a_read_that_stops_early_leaves_no_hash(tmp_path: Path) -> None:
    path = tmp_path / "big.pcap"
    packets = [Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000 + i % 50, dport=80) / Raw(b"x" * 200)
               for i in range(12_000)]
    for index, pkt in enumerate(packets):
        pkt.time = 1_700_000_000 + index
    wrpcap(str(path), packets)
    assert path.stat().st_size > 2 * (1 << 20)  # beyond one buffer
    pcap_cache.want_hashes(path)
    stream = LiteStream(path)
    records = iter(stream)
    next(records)
    stream.close()
    assert pcap_cache._hashes_key(path) not in pcap_cache._HASH_CACHE
    assert pcap_cache.capture_hashes(path) == _digests(path.read_bytes())


def test_a_dry_run_notes_the_hash_want_without_reading(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _mixed(tmp_path)
    reads: list[int] = []
    monkeypatch.setattr(pcap_cache, "_hash_parts", lambda parts: reads.append(1) or (None, None))
    sharedpass.dry_run_keys(path, [(analyze_pcap, (), {})])
    assert reads == []
    assert pcap_cache._path_key(path) in pcap_cache._HASH_WANTED


def test_overview_hashes_without_a_read_of_their_own(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _mixed(tmp_path)
    reads: list[int] = []
    real = pcap_cache._hash_parts

    def _counting(parts):  # type: ignore[no-untyped-def]
        reads.append(1)
        return real(parts)

    monkeypatch.setattr(pcap_cache, "_hash_parts", _counting)
    sha256 = _digests(path.read_bytes())[0]
    for env in ({}, {"PCAPPER_CACHE_ENABLED": "0"}):
        for flags in ([], ["--overview"]):  # the summary prints them; --overview keeps them
            reads.clear()
            out = _run(path, flags, monkeypatch, **env)
            assert reads == [], (env, flags)
            if not flags:
                assert sha256 in out


def test_timeline_artifact_times_past_the_kept_records(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Past _TIMELINE_TIMES_MAX records the timeline looks the file artifacts'
    times up in a scan of the record times: the same report."""
    path = _mixed(tmp_path)
    flags = ["--timeline", "-ip", "192.168.10.50"]
    kept = _run(path, flags, monkeypatch)
    monkeypatch.setattr(timeline, "_TIMELINE_TIMES_MAX", 2)
    scanned = _run(path, flags, monkeypatch)
    assert scanned == kept
    assert "update.exe" in kept


def test_artifact_times_lookup(tmp_path: Path) -> None:
    path = tmp_path / "five.pcap"
    packets = [Ether() / IP() / TCP() for _ in range(5)]
    for index, pkt in enumerate(packets):
        pkt.time = 1_700_000_000 + index + 0.25
    wrpcap(str(path), packets)
    times = array("d", [1_700_000_000.25, 1_700_000_001.25])  # the first two kept
    found = timeline._artifact_times(path, {0, 1, 2, 4, 9}, times, set(), 5, packets=None, meta=None)
    assert found == {1: 1_700_000_000.25, 2: 1_700_000_001.25, 4: 1_700_000_003.25}
    assert list(found) == [1, 2, 4]
    assert timeline._artifact_times(path, {1, 2}, times, {2}, 2, packets=None, meta=None) == {1: 1_700_000_000.25}


def test_estimate_skips_sampling_when_the_size_decides(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A capture too small to hold the packets any threshold asks about needs
    no sampled estimate: memory admission, --jobs and the large-capture note
    decide from its size."""
    path = _mixed(tmp_path)
    sampled: list[int] = []
    from pcapper import rawcap

    real = rawcap.estimate_packets

    def _counting(*args, **kwargs):  # type: ignore[no-untyped-def]
        sampled.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(rawcap, "estimate_packets", _counting)
    assert pcap_cache.packets_at_most(path) == (path.stat().st_size - 24) // 16
    assert pcap_cache.fits_in_memory(path)
    sharedpass.set_jobs(None)
    assert sharedpass.jobs_for(path) == 1
    _run(path, ["--http", "--dns"], monkeypatch)
    assert sampled == []


def test_split_window_sees_only_its_own_file_transfers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A --split window's nested file analysis (the one --timeline runs) read
    the whole capture: every window listed every file transfer."""
    if not sharedpass.parallel_available():
        pytest.skip("needs fork()")
    from scapy.all import ARP, rdpcap

    path = tmp_path / "two_halves.pcap"
    first = list(rdpcap(str(DATA / "mixed.pcap")))  # the HTTP download of update.exe
    last = float(max(p.time for p in first))
    filler = [Ether() / ARP(psrc="192.168.10.50", pdst="192.168.10.1") for _ in range(len(first))]
    for index, pkt in enumerate(filler):
        pkt.time = last + 60 + index
    wrpcap(str(path), first + filler)
    from pcapper import rawcap

    monkeypatch.setattr(cli, "_MIN_WINDOW_PACKETS", 10)
    monkeypatch.setattr(rawcap, "_SAMPLE_EVERY", 1)  # windows of a few dozen records
    out = _run(path, ["--split", "2", "--timeline", "-ip", "192.168.10.50"], monkeypatch)
    windows = out.split("TIMELINE ·")[1:]
    assert len(windows) == 2
    assert "update.exe" in windows[0]
    assert "update.exe" not in windows[1]


def _count_reads(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Every whole read of a capture: a lite stream or a scapy reader opened."""
    opened: list[int] = []
    real_init = LiteStream.__init__
    real_open = pcap_cache._open_single_capture

    def _counting_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        opened.append(1)
        real_init(self, *args, **kwargs)

    def _counting_open(*args, **kwargs):  # type: ignore[no-untyped-def]
        opened.append(1)
        return real_open(*args, **kwargs)

    monkeypatch.setattr(LiteStream, "__init__", _counting_init)
    monkeypatch.setattr(pcap_cache, "_open_single_capture", _counting_open)
    return opened


@pytest.mark.parametrize(
    "flags",
    [["--overview"], ["--threats"], ["--modbus"], ["--services"], ["--ot-commands"],
     ["--timeline", "-ip", "192.168.10.50"], ["--modbus", "--dnp3", "--http"]],
    ids=" ".join,
)
def test_decode_as_check_costs_no_read_of_its_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flags: list[str]
) -> None:
    """From disk the decode-as check reads the capture's first records before
    the analyses run; the read that follows replays them and goes on, so the
    capture is read once (PCAPPER_PRIME_MAX_BYTES=0 turns the replay off)."""
    path = tmp_path / "ot.pcap"
    shutil.copy(DATA / "modbus.pcap", path)
    reference = _run(path, flags, monkeypatch, PCAPPER_CACHE_ENABLED="0", PCAPPER_PRIME_MAX_BYTES="0")
    opened = _count_reads(monkeypatch)
    replayed = _run(path, flags, monkeypatch, PCAPPER_CACHE_ENABLED="0", PCAPPER_PRIME_MAX_BYTES=str(64 << 20))
    assert replayed == reference
    assert len(opened) == 1, f"{len(opened)} reads"
    assert not pcap_cache._PRIMED  # nothing left open


def test_kept_records_forget_answers_from_old_binding_tables(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A layer module that binds itself between the check and the pass (scapy's
    Modbus on 502 when --modbus runs) changes how records dissect: the kept
    ones forget what they worked out and give the same report."""
    path = tmp_path / "ot.pcap"
    shutil.copy(DATA / "modbus.pcap", path)
    flags = ["--modbus", "--overview"]
    reference = _run(path, flags, monkeypatch, PCAPPER_CACHE_ENABLED="0", PCAPPER_PRIME_MAX_BYTES="0")
    real_take = pcap_cache.take_primed
    rebound: list[bool] = []

    def _stale_take(target):  # type: ignore[no-untyped-def]
        stream = pcap_cache._PRIMED.get(pcap_cache._path_key(target))
        if stream is not None:
            for record in stream._records:
                record.headers()  # worked out under the tables then in force
            stream.signature = ("tables before a layer bound itself",)
        taken = real_take(target)
        rebound.append(taken is not None and all(record._hdr is None for record in taken._records))
        return taken

    monkeypatch.setattr(pcap_cache, "take_primed", _stale_take)
    replayed = _run(path, flags, monkeypatch, PCAPPER_CACHE_ENABLED="0", PCAPPER_PRIME_MAX_BYTES=str(64 << 20))
    assert replayed == reference
    assert rebound and rebound[0]


def test_read_head_replays_then_continues(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "numbered.pcap"
    packets = [Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000 + i, dport=80) / Raw(bytes([i % 256]) * 40)
               for i in range(600)]
    for index, pkt in enumerate(packets):
        pkt.time = 1_700_000_000 + index
    wrpcap(str(path), packets)
    expected = [record.original for record in LiteStream(path)]
    head = pcap_cache.read_head(path, 250)
    assert head is not None
    assert [record.original for record in head] == expected[:250]
    assert pcap_cache.primed(path)
    stream = pcap_cache.open_lite_stream(path)
    assert stream.size_bytes == LiteStream(path).size_bytes
    assert [record.original for record in stream] == expected  # the head, then the rest
    assert not pcap_cache.primed(path)
    # A head larger than the budget is not kept: the next read starts afresh.
    monkeypatch.setenv("PCAPPER_PRIME_MAX_BYTES", "1000")
    head = pcap_cache.read_head(path, 250)
    assert len(list(head)) == 250
    assert not pcap_cache.primed(path)



def _script_tool(path: Path, body: str) -> Path:
    """An executable stand-in for an external tool, written in Python. POSIX
    runs the script through its shebang; Windows cannot execute a shebang
    file (WinError 193), so there the tool is a .cmd launcher for it."""
    if os.name != "nt":
        path.write_text(f"#!{sys.executable}\n" + body)
        path.chmod(0o755)
        return path
    script = path.with_suffix(".py")
    script.write_text(body)
    launcher = path.with_suffix(".cmd")
    launcher.write_text(f'@"{sys.executable}" "{script}" %*\r\n')
    return launcher

def _fake_suricata(tmp_path: Path) -> Path:
    """A stand-in Suricata: reads the capture it is given (``-r``) to its end
    and raises one alert naming the bytes it got and their SHA-256; logs the
    path it read to $FAKE_SURICATA_LOG."""
    return _script_tool(tmp_path / "fake-suricata", (
        "import hashlib, json, os, sys\n"
        "args = sys.argv[1:]\n"
        "if '--build-info' in args or '-V' in args:\n"
        "    print('This is Suricata version 0.0.0-test'); sys.exit(0)\n"
        "source = args[args.index('-r') + 1]; out = args[args.index('-l') + 1]\n"
        "digest = hashlib.sha256(); total = 0\n"
        "with open(source, 'rb') as handle:\n"
        "    for chunk in iter(lambda: handle.read(65536), b''):\n"
        "        digest.update(chunk); total += len(chunk)\n"
        "with open(os.environ['FAKE_SURICATA_LOG'], 'a') as log:\n"
        "    log.write(source + '\\n')\n"
        "event = {'event_type': 'alert', 'src_ip': '10.0.0.1', 'dest_ip': '10.0.0.2', 'proto': 'TCP',\n"
        "         'alert': {'signature': f'copy of {total} bytes sha256 {digest.hexdigest()[:16]}',\n"
        "                   'signature_id': 1, 'severity': 1, 'category': 'test', 'action': 'allowed'}}\n"
        "with open(os.path.join(out, 'eve.json'), 'w') as handle:\n"
        "    handle.write(json.dumps(event) + '\\n')\n"
    ))


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
@pytest.mark.parametrize("flags", [["--suricata", "--http"], ["--suricata"]], ids=" ".join)
@pytest.mark.parametrize("disk", [False, True], ids=["memory", "disk"])
def test_suricata_reads_a_copy_of_the_run_s_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flags: list[str], disk: bool
) -> None:
    """Suricata is fed, through a FIFO, the bytes of the read the run makes
    anyway (or one made for it): it reads no file of its own, gets every byte,
    and the report is the one a scan of the file gives."""
    path = _mixed(tmp_path)
    data = path.read_bytes()
    log = tmp_path / "suricata-reads.log"
    env = {"PCAPPER_SURICATA_BIN": str(_fake_suricata(tmp_path)), "FAKE_SURICATA_LOG": str(log)}
    if disk:
        env["PCAPPER_CACHE_ENABLED"] = "0"
    import tempfile

    workdirs = set(Path(tempfile.gettempdir()).glob("pcapper-suricata-*"))
    scanned = _run(path, [*flags, "-v"], monkeypatch, **env, PCAPPER_SURICATA_FEED="0")
    reads = _count_reads(monkeypatch)
    hash_reads: list[int] = []
    real_hash = pcap_cache._hash_parts

    def _counting_hash(parts):  # type: ignore[no-untyped-def]
        hash_reads.append(1)
        return real_hash(parts)

    monkeypatch.setattr(pcap_cache, "_hash_parts", _counting_hash)
    fed = _run(path, [*flags, "-v"], monkeypatch, **env, PCAPPER_SURICATA_FEED="1")
    assert f"copy of {len(data)} bytes sha256 {hashlib.sha256(data).hexdigest()[:16]}" in fed
    assert fed == scanned
    read_from = log.read_text().split()
    assert read_from[0] == str(path) and read_from[1].endswith("capture.fifo")
    assert len(reads) <= 1 and hash_reads == []  # one read of the capture, here, for both
    assert set(Path(tempfile.gettempdir()).glob("pcapper-suricata-*")) == workdirs  # FIFO and output removed


def _mark_whole_reads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A file the pid of every process opening a whole read of a capture
    (pcap_cache.capture_file: a LiteStream's, or feed_tees's for copies) is
    written to -- forked workers included."""
    marks = tmp_path / "reads.log"
    real_capture_file = pcap_cache.capture_file

    def _marking_capture_file(*args, **kwargs):  # type: ignore[no-untyped-def]
        handle = real_capture_file(*args, **kwargs)
        if handle is not None:
            with open(marks, "a") as log:
                log.write(f"{os.getpid()}\n")
        return handle

    monkeypatch.setattr(pcap_cache, "capture_file", _marking_capture_file)
    return marks


@pytest.mark.parametrize("mode", ["head", "resume", "copy"])
def test_disk_jobs_workers_take_the_one_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    """From disk --jobs workers read no file: they replay the head the
    decode-as check kept (all of a small capture), or replay it and are copied
    the rest of the parent's read, or are copied all of it -- same report."""
    if not sharedpass.parallel_available():
        pytest.skip("needs fork()")
    path = tmp_path / "ot.pcap"
    shutil.copy(DATA / "modbus.pcap", path)
    with open(path, "ab") as handle:  # more records: the mixed capture's, after the global header
        handle.write((DATA / "mixed.pcap").read_bytes()[24:])
    flags = ["--threats", "--jobs", "3"]
    if mode == "copy":
        flags.append("--no-auto-decode")
    if mode == "resume":
        kwdefaults = dict(port_heuristics.detect_nonstandard_ports.__kwdefaults__ or {})
        kwdefaults["max_packets"] = 7  # a head shorter than the capture
        monkeypatch.setattr(port_heuristics.detect_nonstandard_ports, "__kwdefaults__", kwdefaults)
    reference = _run(path, [*flags[:1], "--jobs", "1", *flags[3:]], monkeypatch, PCAPPER_CACHE_ENABLED="0")
    marks = _mark_whole_reads(tmp_path, monkeypatch)
    parallel = _run(path, flags, monkeypatch, PCAPPER_CACHE_ENABLED="0")
    assert parallel == reference
    # One read, in this process: an analysis's (a LiteStream), or with none
    # left here the one that feeds the workers' copies (feed_tees).
    assert marks.read_text().split() == [str(os.getpid())]


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    import struct

    body += b"\x00" * (-len(body) % 4)
    length = 12 + len(body)
    return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)


def _pcapng_option(code: int, value: bytes) -> bytes:
    import struct

    return struct.pack("<HH", code, len(value)) + value + b"\x00" * (-len(value) % 4)


def _synthetic_pcapng() -> bytes:
    """A pcapng with section options, two interfaces (the second declared
    after packets), packets and an interface statistics block."""
    import struct

    end = _pcapng_option(0, b"")
    shb = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + _pcapng_option(2, b"probe-hw") + _pcapng_option(3, b"Linux 6") + _pcapng_option(4, b"dumpcap 4") + end
    idb0 = struct.pack("<HHI", 1, 0, 65535) + _pcapng_option(2, b"eth0") + _pcapng_option(6, b"\x00\x11\x22\x33\x44\x55") + _pcapng_option(8, struct.pack("<Q", 10**9)) + end
    idb1 = struct.pack("<HHI", 1, 0, 2048) + _pcapng_option(2, b"eth1") + _pcapng_option(11, b"\x00tcp port 502") + _pcapng_option(12, b"Linux") + end
    frame = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=502) / Raw(b"x" * 40))
    epb = struct.pack("<IIIII", 0, 0, 1000, len(frame), len(frame)) + frame
    isb = struct.pack("<III", 1, 0, 1000) + _pcapng_option(5, struct.pack("<Q", 7)) + end
    blocks = [_pcapng_block(0x0A0D0D0A, shb), _pcapng_block(1, idb0)]
    blocks += [_pcapng_block(6, epb)] * 30
    blocks += [_pcapng_block(1, idb1), _pcapng_block(6, epb[:0] + struct.pack("<IIIII", 1, 0, 2000, len(frame), len(frame)) + frame)]
    blocks += [_pcapng_block(5, isb)]
    return b"".join(blocks)


@pytest.mark.parametrize("chunk", [1, 3, 13, 1000, 1 << 20])
def test_pcapng_metadata_from_the_bytes_equals_a_walk_of_the_file(tmp_path: Path, chunk: int) -> None:
    """The run's read collects a pcapng's metadata with the very parser a
    walk of the file uses: same result however the bytes arrive, a whole
    file or a cut one."""
    data = _synthetic_pcapng()
    for name, content in (("whole.pcapng", data), ("cut.pcapng", data[: len(data) - 50])):
        path = tmp_path / name
        path.write_bytes(content)
        walked = pcap_cache._scan_pcapng_metadata(path)
        tap = pcap_cache._PcapngMetaTap()
        for start in range(0, len(content), chunk):
            tap.feed(content[start : start + chunk])
        assert tap.finish() == walked
    interfaces, section = pcap_cache._scan_pcapng_metadata(tmp_path / "whole.pcapng")
    assert section == {"hardware": "probe-hw", "os": "Linux 6", "application": "dumpcap 4"}
    assert [item["if_name"] for item in interfaces] == ["eth0", "eth1"]
    assert interfaces[0]["if_macaddr"] == "00:11:22:33:44:55" and interfaces[0]["if_speed"] == 10**9
    assert interfaces[1]["if_filter"] == "tcp port 502" and interfaces[1]["dropcount"] == 7


@pytest.mark.parametrize("flags", [[], ["--http"], ["--overview"], ["--http", "--dns"]], ids=lambda f: " ".join(f) or "summary")
@pytest.mark.parametrize("disk", [False, True], ids=["memory", "disk"])
def test_pcapng_metadata_costs_no_read_of_its_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flags: list[str], disk: bool
) -> None:
    """A pcapng's interface and section metadata (the summary's capture
    details) comes from the run's one read, not a walk of the whole file
    before or after it -- the same metadata the walk finds."""
    path = tmp_path / "capture.pcapng"
    path.write_bytes(_synthetic_pcapng())
    env = {"PCAPPER_CACHE_ENABLED": "0"} if disk else {}
    walked = pcap_cache._scan_pcapng_metadata(path)
    reads = _count_reads(monkeypatch)
    walks: list[int] = []
    real_walk = pcap_cache._scan_pcapng_metadata

    def _counting_walk(*args, **kwargs):  # type: ignore[no-untyped-def]
        walks.append(1)
        return real_walk(*args, **kwargs)

    monkeypatch.setattr(pcap_cache, "_scan_pcapng_metadata", _counting_walk)
    out = _run(path, flags, monkeypatch, **env)
    assert walks == [] and len(reads) <= 1
    if not flags:
        assert "eth1" in out or "probe-hw" in out or "Linux 6" in out
    key = pcap_cache._pcapng_meta_key(path)
    assert pcap_cache._PCAPNG_META.get(key, walked) == walked


def _fake_tshark(tmp_path: Path) -> Path:
    """A stand-in tshark: reads the capture it is given (``-r``) to its end,
    logs what it did, the path and the bytes it got to $FAKE_TSHARK_LOG; lists
    two TLS streams, or prints a follow block per ``-z`` tap (last first, as
    tshark does)."""
    return _script_tool(tmp_path / "fake-tshark", (
        "import hashlib, os, sys\n"
        "args = sys.argv[1:]\n"
        "source = args[args.index('-r') + 1]\n"
        "digest = hashlib.sha256(); total = 0\n"
        "with (open(sys.stdin.fileno(), 'rb', closefd=False) if source == '-' else open(source, 'rb')) as handle:\n"
        "    for chunk in iter(lambda: handle.read(65536), b''):\n"
        "        digest.update(chunk); total += len(chunk)\n"
        "taps = [args[i + 1] for i, arg in enumerate(args) if arg == '-z']\n"
        "with open(os.environ['FAKE_TSHARK_LOG'], 'a') as log:\n"
        "    log.write(f\"{'follow' if taps else 'list'} {source} {total} {digest.hexdigest()} {len(taps)}\\n\")\n"
        "if not taps:\n"
        "    print('0\\t10.0.0.1\\t40000\\t10.0.0.2\\t443\\t\\t')\n"
        "    print('3\\t10.0.0.3\\t40001\\t10.0.0.4\\t443\\t\\t')\n"
        "rule = '=' * 67\n"
        "for tap in reversed(taps):\n"
        "    proto, _fmt, stream = tap.split(',')[1:4]\n"
        "    print(f'\\n{rule}\\nFollow: {proto},ascii\\nFilter: tcp.stream eq {stream}\\nNode 0: a\\nNode 1: b\\npayload {stream}\\n{rule}')\n"
    ))


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
@pytest.mark.parametrize("flags", [["--http"], []], ids=lambda f: " ".join(f) or "decrypt only")
def test_decrypt_lists_streams_from_a_copy_of_the_run_s_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flags: list[str]
) -> None:
    """--decrypt: tshark lists the streams from a copy of the run's read
    (a FIFO) and follows them all in one run of its own, not one each; the
    report and the files are the ones listing the file gives."""
    import tempfile

    path = _mixed(tmp_path)
    data = path.read_bytes()
    keys = tmp_path / "keys.log"
    keys.write_text("")
    log = tmp_path / "tshark.log"
    out_dir = tmp_path / "decrypted"
    env = {"PCAPPER_TSHARK_BIN": str(_fake_tshark(tmp_path)), "FAKE_TSHARK_LOG": str(log)}
    args = [*flags, "--decrypt", "--tls-keylog", str(keys), "--decrypt-out", str(out_dir)]
    workdirs = set(Path(tempfile.gettempdir()).glob("pcapper-tshark-*"))

    listed = _run(path, args, monkeypatch, **env, PCAPPER_TSHARK_FEED="0")
    listed_files = {p.name: p.read_text() for p in out_dir.rglob("*.txt")}
    shutil.rmtree(out_dir)
    log.unlink()
    reads = _count_reads(monkeypatch)
    fed = _run(path, args, monkeypatch, **env, PCAPPER_TSHARK_FEED="1")
    fed_files = {p.name: p.read_text() for p in out_dir.rglob("*.txt")}

    assert fed == listed and fed_files == listed_files and len(fed_files) == 2
    runs = [line.split() for line in log.read_text().splitlines()]
    digest = hashlib.sha256(data).hexdigest()
    assert [run[0] for run in runs] == ["list", "follow"]
    assert runs[0][1].endswith("capture.fifo") and runs[0][2:4] == [str(len(data)), digest]
    assert runs[1][1] == str(path) and runs[1][4] == "2"  # both streams, one read
    assert len(reads) <= 1
    assert set(Path(tempfile.gettempdir()).glob("pcapper-tshark-*")) == workdirs


def test_suricata_report_does_not_depend_on_event_order(tmp_path: Path) -> None:
    """Suricata's threads write eve.json events in an order that changes from
    run to run: the same events in any order give the same report (the
    earliest examples, ties in every ranking by name)."""
    import json
    import random

    from pcapper.threats import _parse_suricata_eve_alerts

    events = []
    for second in range(40):
        host = f"10.0.0.{second % 7 + 1}"
        events.append({"timestamp": f"2024-01-01T00:00:{second:02d}.000000+0000", "event_type": "alert",
                       "src_ip": host, "dest_ip": f"192.168.1.{second % 3 + 1}", "proto": "TCP",
                       "alert": {"signature": f"SIG {'AB'[second % 2]}", "signature_id": 1 + second % 2,
                                 "severity": 2, "category": "test", "action": "allowed"}})
        events.append({"timestamp": f"2024-01-01T00:00:{second:02d}.500000+0000", "event_type": "dns",
                       "dns": {"rrname": f"name{second % 4}.example", "type": "query"}})
    events.append({"timestamp": "2024-01-01T00:01:00.000000+0000", "event_type": "flow"})
    events.append({"timestamp": "2024-01-01T00:01:01.000000+0000", "event_type": "tls", "tls": {"sni": "a.example"}})
    results = []
    for seed in (None, 1, 2, 3):
        shuffled = list(events)
        if seed is not None:
            random.Random(seed).shuffle(shuffled)
        eve = tmp_path / f"eve-{seed}.json"
        eve.write_text("".join(json.dumps(event) + "\n" for event in shuffled))
        results.append(_parse_suricata_eve_alerts(eve))
    assert all(result == results[0] for result in results[1:])
    detections, _errors, stats = results[0]
    sig_a = next(d for d in detections if d.get("summary") == "IDS alert: SIG A")
    assert sig_a["evidence"][0] == "src=10.0.0.1 dst=192.168.1.1 proto=TCP action=allowed"  # the earliest
    assert [name for name, _count in stats["dns_queries"]] == ["name0.example", "name1.example", "name2.example", "name3.example"]


def _split_capture(tmp_path: Path, parts: int = 3) -> tuple[Path, list[Path]]:
    """mixed.pcap's records in ``parts`` parts (each with the global header)
    in a directory of their own: one joined capture when the directory is
    the target."""
    import struct

    data = (DATA / "mixed.pcap").read_bytes()
    header, body = data[:24], data[24:]
    endian = "<" if header[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    records, pos = [], 0
    while pos + 16 <= len(body):
        caplen = struct.unpack(endian + "I", body[pos + 8 : pos + 12])[0]
        records.append(body[pos : pos + 16 + caplen])
        pos += 16 + caplen
    directory = tmp_path / "split"
    directory.mkdir()
    step = -(-len(records) // parts)
    files = []
    for index in range(parts):
        part = directory / f"cap.pcap.part{index:03d}.pcap"
        part.write_bytes(header + b"".join(records[index * step : (index + 1) * step]))
        files.append(part)
    return directory, files


@pytest.fixture
def _no_part_groups():
    from pcapper import capture_parts

    yield
    capture_parts.clear_capture_parts()


@pytest.mark.usefixtures("_no_part_groups")
@pytest.mark.parametrize("flags", [[], ["--overview"], ["--http", "--dns"]], ids=lambda f: " ".join(f) or "summary")
@pytest.mark.parametrize("disk", [False, True], ids=["memory", "disk"])
def test_split_capture_hashes_come_from_the_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flags: list[str], disk: bool
) -> None:
    """A split capture's SHA-256 (of its parts, in order) comes from the run's
    read of the parts, not a read of its own."""
    directory, parts = _split_capture(tmp_path)
    expected = hashlib.sha256(b"".join(part.read_bytes() for part in parts)).hexdigest()
    hash_reads: list[int] = []
    real_hash = pcap_cache._hash_parts

    def _counting_hash(files):  # type: ignore[no-untyped-def]
        hash_reads.append(1)
        return real_hash(files)

    monkeypatch.setattr(pcap_cache, "_hash_parts", _counting_hash)
    out = _run(directory, [*flags, "-v"], monkeypatch, **({"PCAPPER_CACHE_ENABLED": "0"} if disk else {}))
    assert hash_reads == []
    if not flags:  # the summary shows it (--overview only computes it)
        assert expected in out


@pytest.mark.usefixtures("_no_part_groups")
@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
@pytest.mark.parametrize("disk", [False, True], ids=["memory", "disk"])
def test_split_capture_suricata_reads_copies_of_the_parts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, disk: bool
) -> None:
    """Suricata scans a split capture part by part: each part's run is fed a
    copy of the run's read of that part, and the report is the one scans of
    the part files give."""
    directory, parts = _split_capture(tmp_path)
    log = tmp_path / "suricata-reads.log"
    env = {"PCAPPER_SURICATA_BIN": str(_fake_suricata(tmp_path)), "FAKE_SURICATA_LOG": str(log)}
    if disk:
        env["PCAPPER_CACHE_ENABLED"] = "0"
    scanned = _run(directory, ["--suricata", "--http", "-v"], monkeypatch, **env, PCAPPER_SURICATA_FEED="0")
    assert [Path(line).name for line in log.read_text().split()] == [part.name for part in parts]
    log.unlink()
    fed = _run(directory, ["--suricata", "--http", "-v"], monkeypatch, **env, PCAPPER_SURICATA_FEED="1")
    assert fed == scanned
    assert all(line.endswith("capture.fifo") for line in log.read_text().split()) and len(log.read_text().split()) == 3
    for part in parts:
        data = part.read_bytes()
        assert f"copy of {len(data)} bytes sha256 {hashlib.sha256(data).hexdigest()[:16]}" in fed


@pytest.mark.usefixtures("_no_part_groups")
@pytest.mark.parametrize("mode", ["resume", "copy"])
def test_split_capture_jobs_workers_take_the_one_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    """From disk, --jobs workers on a split capture read no part file: they
    are copied every part (framed) from the parent's read, or replay the head
    they inherit and are copied the rest -- same report."""
    if not sharedpass.parallel_available():
        pytest.skip("needs fork()")
    directory, _parts = _split_capture(tmp_path)
    flags = ["--threats", "--jobs", "3"]
    if mode == "copy":
        flags.append("--no-auto-decode")
    else:
        kwdefaults = dict(port_heuristics.detect_nonstandard_ports.__kwdefaults__ or {})
        kwdefaults["max_packets"] = 7  # a head that stops inside the first part
        monkeypatch.setattr(port_heuristics.detect_nonstandard_ports, "__kwdefaults__", kwdefaults)
    reference = _run(directory, [*flags[:1], "--jobs", "1", *flags[3:]], monkeypatch, PCAPPER_CACHE_ENABLED="0")
    marks = _mark_whole_reads(tmp_path, monkeypatch)
    parallel = _run(directory, flags, monkeypatch, PCAPPER_CACHE_ENABLED="0")
    assert parallel == reference
    assert set(marks.read_text().split()) == {str(os.getpid())}  # read in this process only


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
@pytest.mark.parametrize("feed", ["1", "0"])
def test_gzip_capture_is_scanned_inflated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, feed: str) -> None:
    """Suricata reads no gzip: a compressed capture is fed inflated from the
    run's read (or, with no feed, scanned from an inflated copy) -- it used to
    get the .gz, read nothing and report nothing."""
    path = tmp_path / "mixed.pcap.gz"
    plain = (DATA / "mixed.pcap").read_bytes()
    path.write_bytes(gzip.compress(plain))
    log = tmp_path / "suricata-reads.log"
    out = _run(path, ["--suricata", "--http", "-v"], monkeypatch, PCAPPER_SURICATA_BIN=str(_fake_suricata(tmp_path)),
               FAKE_SURICATA_LOG=str(log), PCAPPER_SURICATA_FEED=feed)
    assert f"copy of {len(plain)} bytes sha256 {hashlib.sha256(plain).hexdigest()[:16]}" in out
    read_from = log.read_text().split()
    assert read_from[0].endswith("capture.fifo" if feed == "1" else "capture.inflated")


@pytest.mark.parametrize("disk", [False, True], ids=["memory", "disk"])
def test_gzip_pcapng_metadata_costs_no_read_of_its_own(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, disk: bool) -> None:
    path = tmp_path / "capture.pcapng.gz"
    path.write_bytes(gzip.compress(_synthetic_pcapng()))
    walked = pcap_cache._scan_pcapng_metadata(path)
    walks: list[int] = []
    real_walk = pcap_cache._scan_pcapng_metadata

    def _counting_walk(*args, **kwargs):  # type: ignore[no-untyped-def]
        walks.append(1)
        return real_walk(*args, **kwargs)

    monkeypatch.setattr(pcap_cache, "_scan_pcapng_metadata", _counting_walk)
    out = _run(path, ["-v"], monkeypatch, **({"PCAPPER_CACHE_ENABLED": "0"} if disk else {}))
    assert walks == [] and "eth1" in out
    assert pcap_cache._PCAPNG_META[pcap_cache._pcapng_meta_key(path)] == walked



def _ot_capture(tmp_path: Path) -> Path:
    """Modbus records, then the mixed capture's: longer than a 7-record head."""
    path = tmp_path / "ot.pcap"
    shutil.copy(DATA / "modbus.pcap", path)
    with open(path, "ab") as handle:
        handle.write((DATA / "mixed.pcap").read_bytes()[24:])
    return path


def _short_head(monkeypatch: pytest.MonkeyPatch) -> None:
    kwdefaults = dict(port_heuristics.detect_nonstandard_ports.__kwdefaults__ or {})
    kwdefaults["max_packets"] = 7  # the decode-as check keeps a head shorter than the capture
    monkeypatch.setattr(port_heuristics.detect_nonstandard_ports, "__kwdefaults__", kwdefaults)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
@pytest.mark.parametrize("flags", [["--suricata", "--modbus"], ["--modbus", "--suricata"]], ids=" ".join)
def test_a_copy_waiting_reads_the_capture_ahead_of_the_steps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flags: list[str]
) -> None:
    """One analysis and a copy (Suricata): the run's read comes first, whatever
    the steps' order -- the Suricata step used to read the capture for its copy
    (dropping the decode-as head), and the Modbus step read it again."""
    path = _ot_capture(tmp_path)
    _short_head(monkeypatch)
    log = tmp_path / "suricata-reads.log"
    env = {"PCAPPER_SURICATA_BIN": str(_fake_suricata(tmp_path)), "FAKE_SURICATA_LOG": str(log),
           "PCAPPER_CACHE_ENABLED": "0"}
    scanned = _run(path, flags, monkeypatch, **env, PCAPPER_SURICATA_FEED="0")
    reads = _count_reads(monkeypatch)
    drained: list[int] = []
    real_copy = pcap_cache._CaptureRaw._copy_from_file

    def _counting_copy(self, upto):  # type: ignore[no-untyped-def]
        if self._sinks and upto > self._front:
            drained.append(upto - self._front)
        return real_copy(self, upto)

    monkeypatch.setattr(pcap_cache._CaptureRaw, "_copy_from_file", _counting_copy)
    fed = _run(path, flags, monkeypatch, **env, PCAPPER_SURICATA_FEED="1")
    assert fed == scanned
    assert len(reads) <= 1 and drained == []


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_jobs_workers_leave_the_parent_s_copies_alone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A forked --jobs worker inherits the parent's read (its primed head) with
    the copies on it: closing it there must not read the rest of the capture
    for copies only the parent feeds (asprox_24hr: 0.69 of the file again)."""
    if not sharedpass.parallel_available():
        pytest.skip("needs fork()")
    path = tmp_path / "big.pcap"  # past the reader's 1 MiB buffer: a head stops well before the end
    shutil.copy(DATA / "modbus.pcap", path)
    records = (DATA / "mixed.pcap").read_bytes()[24:]
    with open(path, "ab") as handle:
        for _ in range(-(-3_000_000 // len(records))):
            handle.write(records)
    _short_head(monkeypatch)
    marks = tmp_path / "puts.log"
    real_put = pcap_cache.TeeSink.put
    parent = os.getpid()

    def _marking_put(self, data):  # type: ignore[no-untyped-def]
        if os.getpid() != parent:
            with open(marks, "a") as handle:
                handle.write(f"{os.getpid()} {len(data)}\n")
        return real_put(self, data)

    monkeypatch.setattr(pcap_cache.TeeSink, "put", _marking_put)
    log = tmp_path / "suricata-reads.log"
    env = {"PCAPPER_SURICATA_BIN": str(_fake_suricata(tmp_path)), "FAKE_SURICATA_LOG": str(log),
           "PCAPPER_CACHE_ENABLED": "0", "PCAPPER_SURICATA_FEED": "1"}
    reference = _run(path, ["--suricata", "--modbus", "--dns", "--icmp", "--jobs", "1"], monkeypatch, **env)
    parallel = _run(path, ["--suricata", "--modbus", "--dns", "--icmp", "--jobs", "3"], monkeypatch, **env)
    assert parallel == reference
    assert not marks.exists(), marks.read_text()


@pytest.mark.parametrize("flags", [["--http"], []], ids=lambda f: " ".join(f) or "decrypt only")
def test_without_fifos_tshark_lists_from_its_standard_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flags: list[str]
) -> None:
    """No FIFOs (Windows): tshark reads ``-r -`` -- the copy goes down its
    standard input -- and the report is the same."""
    from pcapper import fifo_feed

    path = _mixed(tmp_path)
    data = path.read_bytes()
    keys = tmp_path / "keys.log"
    keys.write_text("")
    log = tmp_path / "tshark.log"
    out_dir = tmp_path / "decrypted"
    env = {"PCAPPER_TSHARK_BIN": str(_fake_tshark(tmp_path)), "FAKE_TSHARK_LOG": str(log)}
    args = [*flags, "--decrypt", "--tls-keylog", str(keys), "--decrypt-out", str(out_dir)]
    listed = _run(path, args, monkeypatch, **env, PCAPPER_TSHARK_FEED="0")
    listed_files = {p.name: p.read_text() for p in out_dir.rglob("*.txt")}
    shutil.rmtree(out_dir)
    log.unlink()
    monkeypatch.setattr(fifo_feed, "HAVE_FIFOS", False)
    reads = _count_reads(monkeypatch)
    fed = _run(path, args, monkeypatch, **env, PCAPPER_TSHARK_FEED="1")
    assert fed == listed and {p.name: p.read_text() for p in out_dir.rglob("*.txt")} == listed_files
    runs = [line.split() for line in log.read_text().splitlines()]
    assert runs[0][:4] == ["list", "-", str(len(data)), hashlib.sha256(data).hexdigest()]
    assert len(reads) <= 1


def test_without_fifos_suricata_reads_its_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Suricata reads no capture from its standard input: without FIFOs it
    reads the file, as before."""
    from pcapper import fifo_feed

    monkeypatch.setattr(fifo_feed, "HAVE_FIFOS", False)
    path = _mixed(tmp_path)
    log = tmp_path / "suricata-reads.log"
    _run(path, ["--suricata"], monkeypatch, PCAPPER_SURICATA_BIN=str(_fake_suricata(tmp_path)), FAKE_SURICATA_LOG=str(log))
    assert log.read_text().split() == [str(path)]


def test_tee_sink_watchdog_stops_a_reader_that_takes_nothing() -> None:
    """Where select() cannot watch a pipe (Windows) a watchdog sees a write
    blocked past the stall timeout, abandons the copy and stops the reader."""
    import time

    read_end, write_end = os.pipe()
    stopped: list[int] = []

    def _stop() -> None:
        stopped.append(1)
        os.close(read_end)  # the blocked write fails, as when the reader is killed

    sink = pcap_cache.TeeSink(write_end, name="test-copy", stall_timeout=0.5, on_stall=_stop, watchdog=True)
    started = time.monotonic()
    for _ in range(8):
        sink.put(b"x" * (1 << 20))  # far past what the pipe holds
    sink.finish()
    assert sink.wait(10)
    assert stopped == [1] and sink.failed and not sink.complete
    assert time.monotonic() - started < 8


_HAVE_TCPDUMP = shutil.which("tcpdump") is not None


@pytest.mark.skipif(not _HAVE_TCPDUMP, reason="needs tcpdump")
@pytest.mark.parametrize("disk", [False, True], ids=["memory", "disk"])
def test_bpf_filter_reads_the_capture_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, disk: bool) -> None:
    """--bpf: tcpdump filters a copy of this process's read (down its standard
    input), and the analyses -- nested ones too -- see the filtered packets:
    no read of the whole capture for a pcapng's details, none for the file
    analysis's NFS check, and the report is the one filtering the file gives."""
    path = tmp_path / "capture.pcapng"
    path.write_bytes(_synthetic_pcapng())
    env = {"PCAPPER_CACHE_ENABLED": "0"} if disk else {}
    walks: list[int] = []
    loads: list[int] = []
    real_walk = pcap_cache._scan_pcapng_metadata
    real_load = pcap_cache.load_packets

    def _counting_walk(*args, **kwargs):  # type: ignore[no-untyped-def]
        walks.append(1)
        return real_walk(*args, **kwargs)

    def _counting_load(*args, **kwargs):  # type: ignore[no-untyped-def]
        loads.append(1)
        return real_load(*args, **kwargs)

    monkeypatch.setattr(pcap_cache, "_scan_pcapng_metadata", _counting_walk)
    monkeypatch.setattr(pcap_cache, "load_packets", _counting_load)
    out = _run(path, ["--bpf", "tcp port 502", "--http", "--dns"], monkeypatch, **env)
    assert walks == [] and loads == []
    assert "HTTP · capture.pcapng" in out


@pytest.mark.skipif(not _HAVE_TCPDUMP, reason="needs tcpdump")
def test_bpf_filter_works_on_a_gzip_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """tcpdump reads no gzip: fed the inflated bytes, it filters a compressed
    capture as it does the uncompressed one."""
    plain = _mixed(tmp_path)
    packed = tmp_path / "mixed.pcap.gz"
    packed.write_bytes(gzip.compress(plain.read_bytes()))
    flags = ["--bpf", "udp", "--dns", "--http"]
    expected = _run(plain, flags, monkeypatch).replace(plain.name, "CAP")
    assert _run(packed, flags, monkeypatch).replace(packed.name, "CAP") == expected


@pytest.mark.usefixtures("_no_part_groups")
def test_split_windows_hash_from_the_index_walk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """--split: the walk that indexes the capture hashes it on the way (no
    read for the hashes), and each window's time span comes from the window's
    own read (no second read of it)."""
    if not sharedpass.parallel_available():
        pytest.skip("needs fork()")
    from pcapper import cli as cli_module

    path = tmp_path / "many.pcap"
    records = (DATA / "mixed.pcap").read_bytes()
    with open(path, "wb") as handle:
        handle.write(records)
        for _ in range(450):  # past two 1 MiB read buffers: records straddle their edges
            handle.write(records[24:])
    monkeypatch.setattr(cli_module, "_MIN_WINDOW_PACKETS", 50)
    hash_reads: list[int] = []
    real_hash = pcap_cache._hash_parts

    def _counting_hash(files):  # type: ignore[no-untyped-def]
        hash_reads.append(1)
        return real_hash(files)

    monkeypatch.setattr(pcap_cache, "_hash_parts", _counting_hash)
    marks = tmp_path / "streams.log"
    from pcapper import rawcap

    real_init = rawcap.LiteStream.__init__

    def _marking_init(self, path_arg, window=None):  # type: ignore[no-untyped-def]
        if window is not None:
            with open(marks, "a") as handle:  # forked window workers write here
                handle.write(f"{os.getpid()} {window.index}\n")
        real_init(self, path_arg, window)

    monkeypatch.setattr(rawcap.LiteStream, "__init__", _marking_init)
    out = _run(path, ["--split", "3", "-v"], monkeypatch)
    assert hash_reads == []
    assert hashlib.sha256(path.read_bytes()).hexdigest() in out
    windows = [line.split()[1] for line in marks.read_text().splitlines()]
    assert sorted(windows) == ["0", "1", "2"], windows  # one read of each window, not two


def test_suricata_reads_its_file_unless_asked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Suricata's results depend on the pace it is fed at, so by default it
    reads the file itself; PCAPPER_SURICATA_FEED=1 feeds it the run's read."""
    path = _mixed(tmp_path)
    log = tmp_path / "suricata-reads.log"
    monkeypatch.delenv("PCAPPER_SURICATA_FEED", raising=False)
    _run(path, ["--suricata"], monkeypatch, PCAPPER_SURICATA_BIN=str(_fake_suricata(tmp_path)), FAKE_SURICATA_LOG=str(log))
    assert log.read_text().split() == [str(path)]
