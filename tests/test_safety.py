"""Tests for the guards on writing attacker-controlled data to disk.

pcapper reconstructs files an adversary put on the wire, so a filename off the
wire is hostile input by definition. These are the two places that decide where
those bytes land and how large they are allowed to get.
"""

from __future__ import annotations

import zlib
from pathlib import Path

import pytest

from pcapper.files import _safe_decompress, _safe_output_path, _unique_output_path


class TestSafeOutputPath:
    def test_ordinary_filename_lands_inside_the_base(self, tmp_path: Path) -> None:
        result = _safe_output_path(tmp_path, "report.pdf")
        assert result == tmp_path / "report.pdf"

    @pytest.mark.parametrize(
        "name",
        [
            "../escape.txt",
            "../../escape.txt",
            "sub/../../escape.txt",
            "..\\escape.txt",
        ],
    )
    def test_traversal_is_rejected(self, tmp_path: Path, name: str) -> None:
        base = tmp_path / "out"
        base.mkdir()
        assert _safe_output_path(base, name) is None

    def test_posix_absolute_path_is_rejected(self, tmp_path: Path) -> None:
        """``base / "/etc/passwd"`` silently discards the base, so an absolute
        name off the wire would otherwise write wherever it pleased."""
        base = tmp_path / "out"
        base.mkdir()
        assert _safe_output_path(base, "/etc/passwd") is None

    @pytest.mark.parametrize(
        "name",
        [
            "/etc/passwd",
            "/tmp/evil.sh",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\Windows\\System32\\calc.exe",
            "\\\\server\\share\\evil.dll",
            "../../../../etc/shadow",
            "....//....//escape.txt",
            "sub/../../escape.txt",
            "con",
            ".",
            "..",
        ],
    )
    def test_hostile_names_never_escape_the_base(
        self, tmp_path: Path, name: str
    ) -> None:
        """The invariant that matters: either the name is refused outright, or
        the path returned is inside the base directory. Nothing in between.

        A drive-absolute name that happens to point at an existing file takes
        the collision branch and is rebased under ``base`` rather than refused,
        which is why this asserts containment rather than ``is None``.
        """
        base = tmp_path / "out"
        base.mkdir()
        result = _safe_output_path(base, name)
        if result is None:
            return
        assert base.resolve() in result.resolve().parents

    def test_collision_gets_a_distinct_name(self, tmp_path: Path) -> None:
        first = _safe_output_path(tmp_path, "dup.bin")
        assert first is not None
        first.write_bytes(b"x")
        second = _safe_output_path(tmp_path, "dup.bin")
        assert second is not None
        assert second != first
        assert second.parent == tmp_path

    def test_unique_path_never_leaves_the_base(self, tmp_path: Path) -> None:
        for index in range(3):
            candidate = _unique_output_path(tmp_path, "same.bin")
            assert candidate.parent == tmp_path
            candidate.write_bytes(bytes([index]))


class TestSafeDecompress:
    def test_gzip_roundtrip(self) -> None:
        raw = b"hello world" * 10
        compressor = zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
        blob = compressor.compress(raw) + compressor.flush()
        assert _safe_decompress(blob, "gzip") == raw

    def test_deflate_roundtrip(self) -> None:
        raw = b"payload" * 10
        assert _safe_decompress(zlib.compress(raw), "deflate") == raw

    def test_unknown_encoding_passes_through(self) -> None:
        assert _safe_decompress(b"plain", "br") == b"plain"

    def test_empty_input(self) -> None:
        assert _safe_decompress(b"", "gzip") == b""

    def test_corrupt_input_is_returned_unchanged_not_raised(self) -> None:
        assert _safe_decompress(b"not really gzip", "gzip") == b"not really gzip"

    def test_decompression_bomb_is_bounded(self) -> None:
        """A few hundred bytes that expand to 100 MB must not be honoured."""
        bomb = zlib.compress(b"\x00" * (100 * 1024 * 1024))
        assert len(bomb) < 200_000
        out = _safe_decompress(bomb, "deflate", max_output=4096)
        assert len(out) <= 4096

    def test_zero_budget_yields_nothing(self) -> None:
        assert _safe_decompress(zlib.compress(b"data"), "deflate", max_output=0) == b""
