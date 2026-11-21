"""Captures are recognised by their header, never by their file name.

Backlog 1.5: the ELEGANT dataset (University of Coimbra) ships rotating
``cap_<n>_<timestamp>`` captures with no extension, and every one was refused
with "Target is not a supported pcap/pcapng file". These tests pin the
header-based rule, the directory scan that follows it, and the modified-pcap
variants that share the classic global header but not its record headers.
"""

from __future__ import annotations

import shutil
import struct
import sys
from pathlib import Path

import pytest

from pcapper import cli
from pcapper.discovery import find_pcaps, is_supported_pcap
from pcapper.pcap_cache import open_capture_reader
from pcapper.utils import capture_type_from_header, detect_file_type


def _run_cli(
    monkeypatch: pytest.MonkeyPatch, *args: str, errors: list[str] | None = None
) -> int:
    """Run the CLI; diagnostics go to ``errors`` (pcapper parks stderr at
    import when it sees a quiet flag, and pytest's ``-q`` looks like one)."""
    monkeypatch.setattr(sys, "argv", ["pcapper", *args])
    if errors is not None:
        monkeypatch.setattr(cli, "_print_error", errors.append)
    return cli.main()


def _to_modified_pcap(source: Path, dest: Path, extra: int) -> None:
    """Rewrite a little-endian classic pcap as modified pcap.

    ``extra`` is 8 for the common 24-byte record header (ifindex, protocol,
    packet type, pad) and 12 for SuSE 6.3's 28-byte variant.
    """
    data = source.read_bytes()
    assert data[:4] == b"\xd4\xc3\xb2\xa1", "fixture must be little-endian pcap"
    out = bytearray(b"\x34\xcd\xb2\xa1" + data[4:24])
    offset = 24
    while offset + 16 <= len(data):
        header = data[offset : offset + 16]
        caplen = struct.unpack("<I", header[8:12])[0]
        out += header + b"\x01\x00\x00\x00" + b"\x00\x08" + b"\x00" + b"\x00" * (extra - 7)
        out += data[offset + 16 : offset + 16 + caplen]
        offset += 16 + caplen
    dest.write_bytes(bytes(out))


class TestHeaderDetection:
    @pytest.mark.parametrize(
        "magic",
        [
            b"\xa1\xb2\xc3\xd4",
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\x3c\x4d",
            b"\x4d\x3c\xb2\xa1",
            b"\xa1\xb2\xcd\x34",
            b"\x34\xcd\xb2\xa1",
        ],
    )
    def test_every_classic_pcap_magic_is_pcap(self, magic: bytes) -> None:
        assert capture_type_from_header(magic) == "pcap"

    def test_pcapng_and_garbage(self) -> None:
        assert capture_type_from_header(b"\x0a\x0d\x0d\x0a") == "pcapng"
        assert capture_type_from_header(b"PK\x03\x04") == "unknown"
        assert capture_type_from_header(b"\x1f\x8b\x08\x00") == "unknown"
        assert capture_type_from_header(b"") == "unknown"

    def test_extensionless_capture_is_supported(self, pcap, tmp_path: Path) -> None:
        target = tmp_path / "cap_00001_20210318035345"
        shutil.copy(pcap("modbus.pcap"), target)
        assert detect_file_type(target) == "pcap"
        assert is_supported_pcap(target)

    def test_misnamed_non_capture_is_not_supported(self, tmp_path: Path) -> None:
        target = tmp_path / "looks_like.pcap"
        target.write_bytes(b"this is not a capture")
        assert not is_supported_pcap(target)


class TestDirectoryScan:
    def test_includes_extensionless_and_reports_misnamed(
        self, pcap, tmp_path: Path
    ) -> None:
        shutil.copy(pcap("modbus.pcap"), tmp_path / "cap_00001_20210318035345")
        shutil.copy(pcap("mixed.pcapng"), tmp_path / "ring_buffer_0002")
        (tmp_path / "README.md").write_text("dataset notes\n")
        (tmp_path / "broken.pcap").write_bytes(b"\x00" * 64)
        hidden = tmp_path / ".cache"
        hidden.mkdir()
        shutil.copy(pcap("modbus.pcap"), hidden / "copy.pcap")

        rejected: list[Path] = []
        found = find_pcaps(tmp_path, recursive=True, rejected=rejected)
        assert [p.name for p in found] == [
            "cap_00001_20210318035345",
            "ring_buffer_0002",
        ]
        assert [p.name for p in rejected] == ["broken.pcap"]


class TestCliTargets:
    def test_extensionless_target_runs(
        self, pcap, tmp_path: Path, monkeypatch, capfd
    ) -> None:
        target = tmp_path / "cap_00001_20210318035345"
        shutil.copy(pcap("modbus.pcap"), target)
        assert _run_cli(monkeypatch, str(target), "--modbus") == 0
        out = capfd.readouterr().out
        assert "MODBUS · cap_00001_20210318035345" in out

    def test_misnamed_target_is_refused_with_reason(
        self, tmp_path: Path, monkeypatch, capfd
    ) -> None:
        target = tmp_path / "evidence.pcap"
        target.write_bytes(b"\x1f\x8b\x08\x00 gzip, not a capture")
        errors: list[str] = []
        assert _run_cli(monkeypatch, str(target), "--modbus", errors=errors) == 2
        assert any("unrecognised file header" in e for e in errors)

    def test_directory_warns_about_misnamed_files(
        self, pcap, tmp_path: Path, monkeypatch, capfd
    ) -> None:
        shutil.copy(pcap("modbus.pcap"), tmp_path / "cap_00001")
        (tmp_path / "broken.pcap").write_bytes(b"\x00" * 64)
        errors: list[str] = []
        assert _run_cli(monkeypatch, str(tmp_path), "--modbus", errors=errors) == 0
        assert any("Skipped 1 file(s)" in e for e in errors)
        assert "MODBUS · cap_00001" in capfd.readouterr().out


class TestModifiedPcap:
    @pytest.mark.parametrize("extra", [8, 12])
    def test_reads_both_record_layouts(self, pcap, tmp_path: Path, extra: int) -> None:
        source = pcap("mixed.pcap")
        dest = tmp_path / f"modified_{extra}.pcap"
        _to_modified_pcap(source, dest, extra)

        expected = [bytes(p) for p in open_capture_reader(source)]
        reader = open_capture_reader(dest)
        assert type(reader).__name__ == "ModifiedPcapReader"
        assert reader._RECORD_HEADER == 16 + extra
        got = list(reader)
        assert [bytes(p) for p in got] == expected
        first = next(iter(open_capture_reader(source)))
        assert float(got[0].time) == float(first.time)
