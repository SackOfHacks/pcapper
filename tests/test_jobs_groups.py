"""--jobs workers compute groups of analyses -- dependent ones included --
passing results to each other through the parent, and the per-packet fast
paths that keep the heaviest analyses short give the answers they replaced."""

from __future__ import annotations

import contextlib
import io
import shutil
import sys
from pathlib import Path

import pytest

pytest.importorskip("scapy")

from scapy.all import IP, LLC, SNAP, TCP, UDP, CookedLinuxV2, Ether, Raw  # noqa: E402

from pcapper import analyzer, cli, hostname, pcap_cache, port_heuristics, port_overrides, sharedpass, utils  # noqa: E402
from pcapper.rawcap import LiteStream  # noqa: E402

DATA = Path(__file__).parent / "data"


@pytest.fixture(autouse=True)
def _reset_state():
    yield
    utils._FAN_OUT_HOOK = None
    utils._STORE_HOOK = None
    sharedpass.set_jobs(1)
    pcap_cache._PACKET_CACHE.clear()
    pcap_cache._HASH_CACHE.clear()
    pcap_cache._PCAPNG_META.clear()
    pcap_cache.discard_primed()
    utils.clear_analysis_memo()


def _run(path: Path, flags: list[str], monkeypatch: pytest.MonkeyPatch, **env: str) -> str:
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(sys, "argv", ["pcapper", str(path), *flags, "--quiet", "--no-status"])
    utils.clear_analysis_memo()
    pcap_cache._PACKET_CACHE.clear()
    pcap_cache._HASH_CACHE.clear()
    pcap_cache._PCAPNG_META.clear()
    port_heuristics.clear_detections()
    port_overrides.clear()
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        cli.main()
    return buffer.getvalue()


@pytest.mark.parametrize("disk", [False, True])
def test_workers_take_dependent_analyses_too(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, disk: bool) -> None:
    """Every analysis but the ones reporting the capture's hashes (from disk)
    runs in a worker -- orchestrators and analyses needing others' results
    as well, which wait for them to be passed on -- and the report is the
    one a single process makes."""
    if not sharedpass.parallel_available():
        pytest.skip("needs fork()")
    path = tmp_path / "mixed.pcap"
    shutil.copy(DATA / "mixed.pcap", path)
    env = {"PCAPPER_CACHE_ENABLED": "0"} if disk else {}
    single = _run(path, ["--overview", "--jobs", "1"], monkeypatch, **env)
    seen: list[tuple[sharedpass.Plan, list[list[int]]]] = []
    real_balance = sharedpass._balanced_groups

    def _recording_balance(indices, workers, plan, **kwargs):  # type: ignore[no-untyped-def]
        groups = real_balance(indices, workers, plan, **kwargs)
        seen.append((plan, groups))
        return groups

    returned: list[int] = []
    real_groups = sharedpass._run_groups

    def _counting_groups(*args, **kwargs):  # type: ignore[no-untyped-def]
        count = real_groups(*args, **kwargs)
        returned.append(count)
        return count

    monkeypatch.setattr(sharedpass, "_balanced_groups", _recording_balance)
    monkeypatch.setattr(sharedpass, "_run_groups", _counting_groups)
    parallel = _run(path, ["--overview", "--jobs", "4"], monkeypatch, **env)
    assert parallel == single
    assert seen and sum(returned) > 10
    plan, groups = seen[0]
    in_workers = {i for group in groups for i in group}
    here = [i for i in range(len(plan)) if i not in in_workers]
    assert all(getattr(plan.calls[i][0], "reports_hashes", False) for i in here)
    assert any(plan.levels[i] > 0 for i in in_workers)  # orchestrators run in workers
    # Some analysis waits for a result another worker computes.
    owner = {i: w for w, group in enumerate(groups) for i in group}
    assert any(owner.get(kid, owner[i]) != owner[i] for i in in_workers for kid in plan.needs(i))


def test_frames_carry_results_and_say_when_none_came() -> None:
    stream = sharedpass._frame(("a", 1), {"x": [1, 2]}) + sharedpass._frame(("b",), lambda: None)
    frames = sharedpass._Frames()
    payloads: list[bytes] = []
    for offset in range(len(stream)):  # one byte at a time: frames complete in order
        payloads.extend(frames.feed(stream[offset:offset + 1]))
    assert [sharedpass._unframe(p) for p in payloads] == [(("a", 1), {"x": [1, 2]}), (("b",), sharedpass._MISSING)]
    assert sharedpass._frame(("c",), lambda: None, required=False) is None  # not sendable: nothing to send


def _fake_plan(specs: list[tuple[str, str]]) -> sharedpass.Plan:
    """A plan of analyses from modules (by their cost) reading lite records or packets."""
    plan = sharedpass.Plan()
    for index, (module, reads) in enumerate(specs):
        def analysis(path):  # type: ignore[no-untyped-def]
            return None

        analysis.__module__ = f"pcapper.{module}"
        analysis.__qualname__ = f"analysis{index}"
        plan.calls.append((analysis, (), {}))
        plan.keys.append((module, index))
        plan.reads.append(reads)
        plan.children.append(set())
        plan.levels.append(0)
    return plan


def test_lite_analyses_gather_where_nothing_is_dissected() -> None:
    # analyzer 20.5 (packets), then ips 13.8, routing 11.8, beacon 11.4 (lite).
    plan = _fake_plan([("analyzer", "packets"), ("ips", "lite"), ("routing", "lite"), ("beacon", "lite")])
    indices = list(range(len(plan)))
    # In memory nothing is dissected: the last lite analysis joins the
    # packet analysis' worker, the less loaded one.
    assert sharedpass._balanced_groups(indices, 2, plan) == [[0, 3], [1, 2]]
    # From disk that worker also dissects the capture: it goes with the
    # other lite ones, and one worker never dissects.
    assert sharedpass._balanced_groups(indices, 2, plan, from_disk=True) == [[0], [1, 2, 3]]
    for from_disk in (False, True):
        for workers in (1, 2, 3, 7):
            groups = sharedpass._balanced_groups(indices, workers, plan, from_disk=from_disk)
            assert sorted(i for group in groups for i in group) == indices  # each analysis once


def test_the_plan_knows_what_each_analysis_reads(tmp_path: Path) -> None:
    path = tmp_path / "mixed.pcap"
    shutil.copy(DATA / "mixed.pcap", path)
    from pcapper.compromised import analyze_compromised
    from pcapper.overview import analyze_overview
    from pcapper.threats import analyze_threats

    plan = sharedpass.discover(path, [(analyze_compromised, (), {})])
    assert len(plan.reads) == len(plan)
    reads = dict(zip((call[0].__module__.rsplit(".", 1)[-1] for call in plan.calls), plan.reads))
    assert reads["domain"] == "packets"
    # The host inventory's own pass (OS fingerprints) reads lightweight
    # records: it dissects only the TCP SYNs it samples.
    assert reads["hosts"] == "lite"
    assert reads["http"] == reads["creds"] == reads["dns"] == "lite"
    assert pcap_cache._READ_NOTE is None  # only while planning
    # Every analysis --threats and --overview start reads lightweight records:
    # neither run dissects every packet of a capture.
    for root in (analyze_threats, analyze_overview):
        reads = sharedpass.discover(path, [(root, (), {})]).reads
        assert reads and "packets" not in reads and "lite" in reads


def test_packets_built_from_disk_records_keep_their_layer_lookups(tmp_path: Path) -> None:
    path = tmp_path / "mixed.pcap"
    shutil.copy(DATA / "mixed.pcap", path)
    pcap_cache.install_layer_memo()
    stream = LiteStream(path)
    try:
        record = next(iter(stream))
        pkt = record.materialize()
    finally:
        stream.close()
    store = pkt.__dict__[pcap_cache._LAYER_MEMO_KEY]
    assert store[0] == id(pkt)
    layer = pkt.getlayer(IP)
    assert store[1][IP] is layer and pkt.getlayer(IP) is layer


def _dissected(packet):  # type: ignore[no-untyped-def]
    return packet.__class__(bytes(packet))


def test_cdp_check_skips_rebuilding_frames_that_cannot_hold_it() -> None:
    # TLV type 1 (device id), as a unicast 802.3 frame with the SNAP header:
    # the fast path must still read it.
    cdp = b"\x02\xb4\x00\x00" + b"\x00\x01\x00\x0b" + b"switch1"
    snap = _dissected(Ether(dst="00:11:22:33:44:55", src="00:0c:29:aa:bb:cc") / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
                      / SNAP(OUI=0x00000C, code=0x2000) / Raw(cdp))
    found = hostname._extract_cdp_hostnames(snap, b"", {})
    assert [entry[0] for entry in found] == ["switch1"]
    syn = _dissected(Ether(dst="00:11:22:33:44:55") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(flags="S"))
    rebuilt: list[int] = []
    payload_cls = type(syn.payload)
    real_bytes = payload_cls.__bytes__

    def _counting_bytes(self):  # type: ignore[no-untyped-def]
        rebuilt.append(1)
        return real_bytes(self)

    payload_cls.__bytes__ = _counting_bytes  # type: ignore[method-assign]
    try:
        assert hostname._extract_cdp_hostnames(syn, b"", {}) == []
    finally:
        payload_cls.__bytes__ = real_bytes  # type: ignore[method-assign]
    assert rebuilt == []  # its IP header cannot open the SNAP header


def test_mac_and_address_caches_keep_the_answers() -> None:
    ip_to_macs: dict[str, set[str]] = __import__("collections").defaultdict(set)
    mac_to_ips: dict[str, set[str]] = __import__("collections").defaultdict(set)
    for _ in range(2):  # cached the second time
        hostname._remember_ip_mac(ip_to_macs, "10.0.0.1", "AA:BB:CC:DD:EE:FF")
        hostname._remember_ip_mac(ip_to_macs, "0.0.0.0", "aa:bb:cc:dd:ee:01")  # unspecified: no
        hostname._remember_ip_mac(ip_to_macs, "not-an-ip", "aa:bb:cc:dd:ee:02")
        hostname._remember_mac_ip(mac_to_ips, "aa:bb:cc:dd:ee:ff", "224.0.0.1")  # multicast: no
        hostname._remember_mac_ip(mac_to_ips, "aa:bb:cc:dd:ee:ff", "2001:0db8::0001")
        hostname._remember_mac_ip(mac_to_ips, "garbage", "10.0.0.9")
    assert dict(ip_to_macs) == {"10.0.0.1": {"aa:bb:cc:dd:ee:ff"}}
    assert dict(mac_to_ips) == {"aa:bb:cc:dd:ee:ff": {"2001:db8::1"}}


def test_interface_key_without_scapy_s_field_search() -> None:
    plain = _dissected(Ether() / IP() / UDP())
    assert analyzer._get_iface_key(plain) is None
    plain.ifname = "eth9"  # set on the packet, not a field
    assert analyzer._get_iface_key(plain) == "eth9"
    # A layer with an interface field answers through scapy, as before.
    cooked = _dissected(CookedLinuxV2(ifindex=7) / IP() / UDP())
    assert analyzer._get_iface_key(cooked) == getattr(cooked, "ifindex") == 7
