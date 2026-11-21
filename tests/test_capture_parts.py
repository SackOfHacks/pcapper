"""Split captures (X.pcap.part000.pcap ...) are analysed as one capture.

The ICS-PCAP-Challenges range splits every capture over 2 GB with
``tcpdump -C`` into ``<name>.partNNN.pcap`` files, each a complete pcap. These
tests split a fixture the same way and require the joined analysis to be the
analysis of the original file.
"""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

import pytest

from pcapper import cli
from pcapper.capture_parts import (
    capture_parts,
    clear_capture_parts,
    group_split_captures,
    part_info,
)
from pcapper.pcap_cache import capture_hashes, iter_packets


@pytest.fixture(autouse=True)
def _isolated_registry():
    # The registry is process-global; every test starts and ends empty so a
    # group formed here can never leak into another test's reads.
    clear_capture_parts()
    yield
    clear_capture_parts()


def _split_pcap(source: Path, dest_dir: Path, per_part: int) -> list[Path]:
    """Split a classic pcap into complete pcaps of ``per_part`` packets,
    named like ``tcpdump -C`` output renamed by the challenge range."""
    data = source.read_bytes()
    global_header = data[:24]
    endian = "<" if data[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    records: list[bytes] = []
    offset = 24
    while offset + 16 <= len(data):
        caplen = struct.unpack(endian + "I", data[offset + 8 : offset + 12])[0]
        records.append(data[offset : offset + 16 + caplen])
        offset += 16 + caplen
    parts: list[Path] = []
    for index in range(0, len(records), per_part):
        part = dest_dir / f"{source.name}.part{index // per_part:03d}.pcap"
        part.write_bytes(global_header + b"".join(records[index : index + per_part]))
        parts.append(part)
    return parts


def _run_cli(monkeypatch, *args: str, errors: list[str] | None = None) -> int:
    monkeypatch.setattr(sys, "argv", ["pcapper", *args])
    if errors is not None:
        monkeypatch.setattr(cli, "_print_error", errors.append)
    return cli.main()


class TestGrouping:
    def test_part_name_parsing(self) -> None:
        assert part_info(Path("a_day.pcap.part014.pcap")) == ("a_day.pcap", 14)
        assert part_info(Path("x.pcapng.part0001.pcapng")) == ("x.pcapng", 1)
        assert part_info(Path("plain.pcap")) is None
        assert part_info(Path("x.part1.pcap")) is None  # needs >= 3 digits

    def test_siblings_collapse_to_head_in_place(self, tmp_path: Path) -> None:
        parts = [tmp_path / f"cap.pcap.part{i:03d}.pcap" for i in range(3)]
        other = tmp_path / "other.pcap"
        paths, groups = group_split_captures([other, *parts])
        assert paths == [other, parts[0]]
        assert len(groups) == 1 and groups[0].parts == tuple(parts)
        assert groups[0].missing == ()
        assert capture_parts(parts[0]) == tuple(parts)

    def test_gap_is_reported(self, tmp_path: Path) -> None:
        parts = [tmp_path / f"cap.pcap.part{i:03d}.pcap" for i in (0, 1, 3)]
        _paths, groups = group_split_captures(parts)
        assert groups[0].missing == (2,)

    def test_lone_part_is_not_grouped(self, tmp_path: Path) -> None:
        part = tmp_path / "cap.pcap.part007.pcap"
        paths, groups = group_split_captures([part])
        assert paths == [part] and groups == []
        assert capture_parts(part) == (part,)


class TestJoinedReading:
    def test_joined_stream_equals_original(self, pcap, tmp_path: Path) -> None:
        source = pcap("mixed.pcap")
        parts = _split_pcap(source, tmp_path, per_part=10)
        assert len(parts) == 3
        paths, _groups = group_split_captures(parts)
        joined = [bytes(p) for p in iter_packets(paths[0], show_status=False)]
        original = [bytes(p) for p in iter_packets(source, show_status=False)]
        assert joined == original

    def test_hash_covers_every_part_in_order(self, pcap, tmp_path: Path) -> None:
        parts = _split_pcap(pcap("mixed.pcap"), tmp_path, per_part=10)
        paths, _groups = group_split_captures(parts)
        expected = hashlib.sha256(b"".join(p.read_bytes() for p in parts)).hexdigest()
        assert capture_hashes(paths[0])[0] == expected


class TestCli:
    def test_directory_of_parts_is_one_capture(
        self, pcap, tmp_path: Path, monkeypatch, capfd
    ) -> None:
        _split_pcap(pcap("mixed.pcap"), tmp_path, per_part=10)
        errors: list[str] = []
        assert _run_cli(monkeypatch, str(tmp_path), "--protocols", errors=errors) == 0
        out = capfd.readouterr().out
        assert any("Joined 3 split-capture parts" in e for e in errors)
        assert out.count("PROTOCOLS · ") == 1
        assert "mixed.pcap [3 parts joined]" in out
        assert "25 packets" in out

    def test_no_join_parts_keeps_them_separate(
        self, pcap, tmp_path: Path, monkeypatch, capfd
    ) -> None:
        _split_pcap(pcap("mixed.pcap"), tmp_path, per_part=10)
        assert (
            _run_cli(monkeypatch, str(tmp_path), "--protocols", "--no-join-parts")
            == 0
        )
        out = capfd.readouterr().out
        assert out.count("PROTOCOLS · ") == 3
