"""--baseline / --baseline-diff: the profile a baseline records and the fixed
rules that turn a difference into a finding."""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from pcapper.baseline import (
    BaselineSnapshot,
    baseline_file_name,
    build_baseline_from_parts,
    collect_capture_parts,
    compare_baseline,
    load_baseline,
    write_baseline,
)
from pcapper.baseline_profile import analyze_baseline_profile, interval_stats

T0 = 1_700_000_000.0
HMI, PLC, ROGUE = "10.0.0.10", "10.0.0.20", "10.0.0.99"
HMI_MAC, PLC_MAC, ROGUE_MAC = "02:00:00:00:00:10", "02:00:00:00:00:20", "02:00:00:00:00:99"
_SEQ: dict[tuple[str, str], int] = {}


def _modbus(src: str, dst: str, src_mac: str, dst_mac: str, fc: int, ts: float, tid: int, *, response: bool = False,
            reg_value: int = 0):
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.layers.l2 import Ether  # type: ignore
    from scapy.packet import Raw  # type: ignore

    if fc == 3 and not response:
        pdu = struct.pack(">BHH", fc, 0, 10)
    elif fc == 3:
        pdu = struct.pack(">BBH", fc, 20, reg_value) + b"\x00" * 18
    else:  # 6: write single register (the response echoes the request)
        pdu = struct.pack(">BHH", fc, 1, 99)
    mbap = struct.pack(">HHHB", tid, 0, len(pdu) + 1, 1)
    sport, dport = (502, 40000) if response else (40000, 502)
    # Contiguous sequence numbers per direction: the Modbus analyzer
    # reassembles the stream and drops overlapping segments.
    payload = mbap + pdu
    seq = _SEQ.get((src, dst), 1000)
    _SEQ[(src, dst)] = seq + len(payload)
    pkt = (Ether(src=src_mac, dst=dst_mac) / IP(src=src, dst=dst)
           / TCP(sport=sport, dport=dport, flags="PA", seq=seq) / Raw(load=payload))
    pkt.time = ts
    return pkt


def _smb(ts: float):
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.layers.l2 import Ether  # type: ignore
    from scapy.packet import Raw  # type: ignore

    pkt = Ether(src=ROGUE_MAC, dst=PLC_MAC) / IP(src=ROGUE, dst=PLC) / TCP(sport=50000, dport=445, flags="PA") / Raw(load=b"\x00" * 40)
    pkt.time = ts
    return pkt


def _polls(period: float, seconds: float, *, plc_mac: str = PLC_MAC, start_tid: int = 1) -> list:
    packets, tid, ts = [], start_tid, T0
    while ts < T0 + seconds:
        packets.append(_modbus(HMI, PLC, HMI_MAC, plc_mac, 3, ts, tid))
        packets.append(_modbus(PLC, HMI, plc_mac, HMI_MAC, 3, ts + 0.005, tid, response=True))
        tid += 1
        ts += period
    return packets


def _write(path: Path, packets: list) -> Path:
    from scapy.all import wrpcap  # type: ignore

    wrpcap(str(path), sorted(packets, key=lambda p: float(p.time)))
    return path


def _snapshot(path: Path) -> BaselineSnapshot:
    return build_baseline_from_parts("test", [collect_capture_parts(path)])


@pytest.fixture(scope="module")
def captures(tmp_path_factory) -> dict[str, Path]:
    root = tmp_path_factory.mktemp("baseline")
    normal = _write(root / "normal.pcap", _polls(1.0, 120))
    # The same HMI polling 5x faster, the PLC answering from a new MAC, a
    # rogue host writing to it and opening SMB to it.
    attack = _polls(0.2, 120, plc_mac="02:00:00:00:00:21")
    attack += [_modbus(ROGUE, PLC, ROGUE_MAC, "02:00:00:00:00:21", 6, T0 + 30 + i, 9000 + i) for i in range(3)]
    attack += [_smb(T0 + 40 + i) for i in range(3)]
    return {"normal": normal, "attack": _write(root / "attack.pcap", attack)}


def test_profile_records_conversation_cadence_and_macs(captures) -> None:
    profile = analyze_baseline_profile(captures["normal"], show_status=False)
    stats = profile.flows[(HMI, PLC, "TCP", 502)]
    median, jitter = interval_stats(stats.intervals)
    assert stats.requests == 120 and median == pytest.approx(1.0, abs=1e-3) and jitter == pytest.approx(0.0, abs=1e-3)
    # The response leg is the same conversation (client -> server on 502).
    assert stats.packets == 240
    assert dict(profile.ip_macs[PLC]) == {PLC_MAC: 120}


def test_request_bursts_are_one_poll(tmp_path) -> None:
    """A write and its read-back 1 ms apart, every 2 s: the cadence is 2 s, not 1 ms."""
    packets, tid = [], 1
    for i in range(20):
        for offset in (0.0, 0.001):
            packets.append(_modbus(HMI, PLC, HMI_MAC, PLC_MAC, 3, T0 + 2 * i + offset, tid))
            tid += 1
    profile = analyze_baseline_profile(_write(tmp_path / "burst.pcap", packets), show_status=False)
    median, _ = interval_stats(profile.flows[(HMI, PLC, "TCP", 502)].intervals)
    assert median == pytest.approx(2.0, abs=1e-3)


def test_same_traffic_matches_the_baseline(captures) -> None:
    delta = compare_baseline(_snapshot(captures["normal"]), _snapshot(captures["normal"]))
    assert delta.deviations == [] and not delta.has_changes


def test_attack_capture_deviations(captures) -> None:
    delta = compare_baseline(_snapshot(captures["attack"]), _snapshot(captures["normal"]))
    found = {(d["severity"], d["summary"]) for d in delta.deviations}
    assert ("high", "New OT communication pair") in found  # rogue -> PLC Modbus
    assert ("high", "New writer to OT device") in found  # rogue writes, never did before
    writer = next(d for d in delta.deviations if d["summary"] == "New writer to OT device")
    assert "Write Single Register (x3)" in writer["details"]
    assert ("high", "Remote-access/file-transfer protocol on OT host") in found  # SMB to the PLC
    assert ("high", "IP address moved to a different MAC") in found  # PLC's MAC changed
    assert ("medium", "Polling cadence changed (faster)") in found
    assert ("medium", "Traffic rate changed") in found
    cadence = next(d for d in delta.deviations if d["summary"].startswith("Polling cadence"))
    assert "every 1.00s -> every 200 ms" in cadence["details"]
    # The HMI's own reads are not new: the pair and the command were baselined.
    assert not any(d["summary"].startswith("New OT read") and d.get("src") == HMI for d in delta.deviations)


def test_snapshot_round_trips_through_json(captures, tmp_path) -> None:
    snap = _snapshot(captures["normal"])
    path = tmp_path / "x.baseline.json"
    write_baseline(snap, path)
    assert load_baseline(path).to_dict() == json.loads(json.dumps(snap.to_dict()))


def test_schema1_baseline_compares_without_inventing_drift(captures, tmp_path) -> None:
    """A schema-1 --baseline-save file has no communication profile:
    the profile sections are a note, never 'everything is new'."""
    current = _snapshot(captures["normal"])
    old = {key: value for key, value in current.to_dict().items()
           if key in ("created_at", "pcapper_version", "sources", "hosts", "services", "ot_commands", "control_targets", "notes")}
    path = tmp_path / "old.json"
    path.write_text(json.dumps(old), encoding="utf-8")
    delta = compare_baseline(current, load_baseline(path))
    assert delta.deviations == []
    assert any("schema 1" in note for note in delta.notes)


def test_short_captures_do_not_compare_rates(tmp_path) -> None:
    base = _write(tmp_path / "b.pcap", _polls(1.0, 12))
    fast = _write(tmp_path / "f.pcap", _polls(0.1, 12))
    delta = compare_baseline(_snapshot(fast), _snapshot(base))
    assert not any(d["summary"] == "Traffic rate changed" for d in delta.deviations)
    assert any("compared only when both span" in note for note in delta.notes)
    # Cadence needs no window: 10+ intervals each side suffice.
    assert any(d["summary"].startswith("Polling cadence changed") for d in delta.deviations)


@pytest.mark.parametrize(
    ("names", "expected"),
    [
        (["site.pcap"], "site.baseline.json"),
        (["a/site.pcapng"], "site.baseline.json"),
        (["cap.pcap.gz"], "cap.baseline.json"),
        (["Industroyer2-StationAddress1.pcap", "Industroyer2-StationAddress3.pcap"], "Industroyer2-StationAddress.baseline.json"),
        (["capture-1.pcap", "capture-12.pcap"], "capture.baseline.json"),
        (["alpha.pcap", "beta.pcap"], "merged-2-captures.baseline.json"),
    ],
)
def test_baseline_file_name(names, expected) -> None:
    assert baseline_file_name([Path(n) for n in names]) == expected


def _cli(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ, PCAPPER_NO_COLOR="1", NO_COLOR="1")
    return subprocess.run([sys.executable, "-m", "pcapper", *args], cwd=cwd, env=env,
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)


def test_cli_baseline_then_diff(captures, tmp_path) -> None:
    for name in ("normal", "attack"):
        (tmp_path / f"{name}.pcap").write_bytes(captures[name].read_bytes())
    run = _cli("normal.pcap", "--baseline", cwd=tmp_path)
    assert run.returncode == 0, run.stderr
    assert (tmp_path / "normal.baseline.json").exists()
    assert "BASELINE" in run.stdout and "10.0.0.10 -> 10.0.0.20" in run.stdout

    diff = _cli("attack.pcap", "--baseline-diff", "normal.baseline.json", cwd=tmp_path)
    assert diff.returncode == 0, diff.stderr
    assert "BASELINE DRIFT" in diff.stdout and "New writer to OT device" in diff.stdout
    # A capture as the reference reaches the same verdict as its saved baseline.
    direct = _cli("attack.pcap", "--baseline-diff", "normal.pcap", cwd=tmp_path)
    assert "New writer to OT device" in direct.stdout
    # The capture summary is not printed: the baseline report is the output.
    assert "Top Protocols" not in run.stdout


def test_unknown_os_is_not_an_os_change() -> None:
    def snap(os_name: str) -> BaselineSnapshot:
        return BaselineSnapshot("t", "t", [], hosts=[{"ip": "10.0.0.1", "os": os_name}])

    assert compare_baseline(snap("Windows"), snap("Unknown")).host_changes == []
    assert compare_baseline(snap("Windows"), snap("Linux")).host_changes[0]["os_change"] == {"from": "Linux", "to": "Windows"}


def test_positional_and_keyword_calls_share_one_memo_entry(captures) -> None:
    """hosts.py calls analyze_hostname(path, None), ips.py calls it with
    target_ip=None: one computation, not two."""
    from pcapper.hostname import analyze_hostname

    first = analyze_hostname(captures["normal"], None, show_status=False)
    assert analyze_hostname(captures["normal"], target_ip=None, show_status=False, include_related=False) is first


def test_os_fingerprints_from_disk_match_dissected_packets() -> None:
    """The fingerprint pass skips non-SYN records from their bytes; the
    result must equal the same pass over scapy packets."""
    from pcapper.hosts import _collect_os_fingerprints
    from pcapper.pcap_cache import load_packets

    path = Path(__file__).parent / "data" / "mixed.pcap"
    disk = _collect_os_fingerprints(path, False)
    packets, meta = load_packets(path, show_status=False)
    dissected = _collect_os_fingerprints(path, False, packets=packets, meta=meta)
    assert disk[0] and ({k: dict(v) for k, v in disk[0].items()}, dict(disk[1])) == (
        {k: dict(v) for k, v in dissected[0].items()}, dict(dissected[1]))


def test_tampered_register_values_are_flagged(tmp_path) -> None:
    """Holding register 0 always read 0 in the baseline; responses rewritten
    in transit report 95. The values, not the traffic shape, deviate."""
    def polls(tampered_from: int | None) -> list:
        packets = []
        for i in range(60):
            value = 95 if tampered_from is not None and i >= tampered_from else 0
            packets.append(_modbus(HMI, PLC, HMI_MAC, PLC_MAC, 3, T0 + i, 5000 + i))
            packets.append(_modbus(PLC, HMI, PLC_MAC, HMI_MAC, 3, T0 + i + 0.005, 5000 + i, response=True, reg_value=value))
        return packets

    _SEQ.clear()
    clean = _snapshot(_write(tmp_path / "clean.pcap", polls(None)))
    _SEQ.clear()
    tampered = _snapshot(_write(tmp_path / "tampered.pcap", polls(30)))
    reg0 = next(r for r in clean.registers if r["address"] == 0)
    assert (reg0["server"], reg0["type"], reg0["min"], reg0["max"], reg0["samples"]) == (PLC, "holding_register", 0, 0, 60)
    delta = compare_baseline(tampered, clean)
    found = [d for d in delta.deviations if d["kind"] == "register"]
    assert [(d["severity"], d["summary"]) for d in found] == [("high", "Constant register changed value")]
    assert "holding_register[0]: always 0 in the baseline, now 0..95" in found[0]["details"]
    assert compare_baseline(clean, clean).deviations == []
