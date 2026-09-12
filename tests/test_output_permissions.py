"""Regression tests for owner-only output permissions.

pcapper deliberately does not redact what it recovers, so reports, exports,
carved artifacts and decrypted streams routinely contain cleartext credentials,
session tokens and malware samples. Under a default umask those landed at 0644
(directories 0755), readable by every other local account on a shared analysis
host — and world-readable evidence is also harder to defend on chain-of-custody
grounds.

POSIX mode bits are not meaningful on Windows, so these skip there rather than
asserting something the platform does not implement.
"""

from __future__ import annotations

import sqlite3
import stat
from pathlib import Path

import pytest

from pcapper.exporting import ExportBundle, export_csv, export_sqlite
from pcapper.utils import restrict_dir_permissions, restrict_permissions, safe_write_text

pytestmark = pytest.mark.usefixtures("posix_only")


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


class _FakeSummary:
    """The duck type the exporters consume: detections plus artifacts."""

    def __init__(self) -> None:
        self.detections = [
            {"severity": "warning", "summary": "cleartext credential", "user": "admin"}
        ]
        self.artifacts = ["admin:hunter2"]
        self.errors: list[str] = []


def _bundle() -> ExportBundle:
    return ExportBundle(path=Path("fixture.pcap"), summaries={"creds": _FakeSummary()})


class TestHelpers:
    def test_file_becomes_owner_only(self, tmp_path: Path) -> None:
        target = tmp_path / "secret.txt"
        target.write_text("password=hunter2")
        target.chmod(0o644)
        restrict_permissions(target)
        assert _mode(target) == 0o600

    def test_directory_becomes_owner_only(self, tmp_path: Path) -> None:
        target = tmp_path / "case"
        target.mkdir()
        target.chmod(0o755)
        restrict_permissions(target)
        assert _mode(target) == 0o700

    def test_created_directory_is_tightened(self, tmp_path: Path) -> None:
        target = tmp_path / "nested" / "out"
        restrict_dir_permissions(target)
        assert target.is_dir()
        assert _mode(target) == 0o700

    def test_existing_directory_keeps_the_mode_the_analyst_gave_it(
        self, tmp_path: Path
    ) -> None:
        """Pointing an output flag at a directory that already exists must not
        silently re-permission a shared team directory."""
        target = tmp_path / "shared"
        target.mkdir()
        target.chmod(0o755)
        restrict_dir_permissions(target)
        assert _mode(target) == 0o755

    def test_missing_path_does_not_raise(self, tmp_path: Path) -> None:
        # Best effort by design: tightening permissions must never abort a run.
        restrict_permissions(tmp_path / "does-not-exist")


class TestWritePaths:
    def test_safe_write_text_is_owner_only(self, tmp_path: Path) -> None:
        target = tmp_path / "report.txt"
        safe_write_text(target, "user=admin pass=hunter2")
        assert _mode(target) == 0o600

    def test_csv_export_is_owner_only(self, tmp_path: Path) -> None:
        target = tmp_path / "out.csv"
        export_csv(_bundle(), target)
        assert target.exists()
        assert _mode(target) == 0o600

    def test_sqlite_export_is_owner_only_before_rows_land(
        self, tmp_path: Path
    ) -> None:
        """Tightened straight after connect(), so the database is never briefly
        readable while it is being populated."""
        target = tmp_path / "out.sqlite"
        export_sqlite(_bundle(), target)
        assert _mode(target) == 0o600
        # And it is still a usable database.
        with sqlite3.connect(str(target)) as conn:
            names = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        assert "detections" in names


class TestCarveOutput:
    def test_carved_artifacts_and_their_directory_are_owner_only(
        self, pcap, tmp_path: Path
    ) -> None:
        from pcapper.carving import analyze_carving

        out = tmp_path / "carved"
        summary = analyze_carving(pcap("carve_wrap.pcap"), show_status=False, output_dir=out)
        assert _mode(out) == 0o700
        assert summary.extracted
        for artifact in summary.extracted:
            assert _mode(artifact) == 0o600
