"""Tests for the guards on writing attacker-controlled data to disk.

pcapper reconstructs files an adversary put on the wire, so a filename off the
wire is hostile input by definition. These are the two places that decide where
those bytes land and how large they are allowed to get.
"""

from __future__ import annotations

import time
import zlib
from pathlib import Path

import pytest

from pcapper.files import (
    _local_filename,
    _safe_decompress,
    _safe_output_path,
    _unique_output_path,
)

UNC_NAME = r"\\attacker.example\share\evil.dll"


class TestLocalFilename:
    """The pure, no-I/O reduction applied before a wire filename touches disk."""

    @pytest.mark.parametrize(
        "given,expected",
        [
            ("report.pdf", "report.pdf"),
            ("sub/dir/report.pdf", "report.pdf"),
            (r"sub\dir\report.pdf", "report.pdf"),
            ("../escape.txt", "escape.txt"),
            (r"..\escape.txt", "escape.txt"),
            ("/etc/passwd", "passwd"),
            (r"C:\Windows\System32\calc.exe", "calc.exe"),
            ("C:evil.bin", "evil.bin"),
            (UNC_NAME, "evil.dll"),
            ("evil.exe. ", "evil.exe"),
            ("  spaced.bin  ", "spaced.bin"),
            ("nul\x00byte.bin", "nulbyte.bin"),
        ],
    )
    def test_reduces_to_a_bare_local_name(self, given: str, expected: str) -> None:
        assert _local_filename(given) == expected

    @pytest.mark.parametrize("given", ["", ".", "..", "   ", "/", "\\", "..."])
    def test_nothing_usable_is_rejected(self, given: str) -> None:
        assert _local_filename(given) is None

    @pytest.mark.parametrize("given", ["CON", "con.txt", "NUL", "com1", "LPT9.dat"])
    def test_windows_device_names_are_defused(self, given: str) -> None:
        """Windows resolves these as devices in any directory, so ``out/CON``
        opens the console instead of creating a file."""
        result = _local_filename(given)
        assert result is not None
        assert result.startswith("_")

    def test_an_ordinary_name_is_left_alone(self) -> None:
        assert _local_filename("invoice.2026.tar.gz") == "invoice.2026.tar.gz"


class TestSafeOutputPath:
    def test_ordinary_filename_lands_inside_the_base(self, tmp_path: Path) -> None:
        assert _safe_output_path(tmp_path, "report.pdf") == tmp_path / "report.pdf"

    @pytest.mark.parametrize(
        "name",
        [
            "/etc/passwd",
            "/tmp/evil.sh",
            r"C:\Windows\System32\drivers\etc\hosts",
            r"C:\Windows\System32\calc.exe",
            "C:evil.bin",
            UNC_NAME,
            "../escape.txt",
            r"..\escape.txt",
            "../../../../etc/shadow",
            "....//....//escape.txt",
            "sub/../../escape.txt",
            "con",
            ".",
            "..",
            "",
        ],
    )
    def test_hostile_names_never_escape_the_base(
        self, tmp_path: Path, name: str
    ) -> None:
        """The invariant, and the only one that holds on every platform: either
        the name is refused outright, or the path returned sits directly inside
        the base directory.

        Asserting which of those applies per name would be platform-specific.
        ``..\\escape.txt`` is traversal on Windows and an ordinary filename on
        POSIX; ``/etc/passwd`` exists on one and not the other.
        """
        base = tmp_path / "out"
        base.mkdir()
        result = _safe_output_path(base, name)
        if result is None:
            return
        assert result.parent.resolve() == base.resolve()

    def test_unc_name_does_no_network_io(self, tmp_path: Path) -> None:
        """Regression: the wire filename used to reach ``Path.exists()`` as a
        path. On Windows a UNC name then became a live SMB connection to a host
        named in the capture — a multi-second stall per artifact, and an
        outbound authentication attempt from the analyst's workstation to a
        server the adversary chose.
        """
        base = tmp_path / "out"
        base.mkdir()
        started = time.monotonic()
        result = _safe_output_path(base, UNC_NAME)
        elapsed = time.monotonic() - started
        assert result is not None
        assert result.name == "evil.dll"
        assert result.parent.resolve() == base.resolve()
        # Resolving a nonexistent SMB host takes tens of seconds; near-instant
        # is the evidence that no lookup was attempted.
        assert elapsed < 2.0, f"took {elapsed:.1f}s — the name reached the network"

    def test_collision_gets_a_distinct_name(self, tmp_path: Path) -> None:
        first = _safe_output_path(tmp_path, "dup.bin")
        assert first is not None
        first.write_bytes(b"x")
        second = _safe_output_path(tmp_path, "dup.bin")
        assert second is not None
        assert second != first
        assert second.parent == tmp_path

    def test_distinct_hostile_names_do_not_overwrite_each_other(
        self, tmp_path: Path
    ) -> None:
        """Two artifacts reducing to the same basename must not collide."""
        base = tmp_path / "out"
        base.mkdir()
        first = _safe_output_path(base, "../a.bin")
        assert first is not None
        first.write_bytes(b"1")
        second = _safe_output_path(base, "a.bin")
        assert second is not None
        assert second != first

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
        """A few KB that expand to 32 MB must not be honoured.

        32 MB rather than something larger only to keep the suite quick: the
        expansion ratio is already ~1000:1, which is all the bound has to
        survive. ``_safe_decompress`` caps by output size, not by ratio, so a
        bigger bomb tests nothing extra.
        """
        bomb = zlib.compress(b"\x00" * (32 * 1024 * 1024))
        assert len(bomb) < 100_000, "fixture is not actually a bomb"
        assert len(_safe_decompress(bomb, "deflate", max_output=4096)) <= 4096

    def test_zero_budget_yields_nothing(self) -> None:
        assert _safe_decompress(zlib.compress(b"data"), "deflate", max_output=0) == b""
