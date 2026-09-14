"""The repository never carries evidence, key material or build output.

`.gitignore` is an allow-list; these tests pin what that list is allowed to
let through, so a widened rule or a `git add -f` shows up in CI rather than
in a public commit.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).parent.parent

ALLOWED_NAMES = {"LICENSE", ".gitignore", ".gitattributes"}
ALLOWED_SUFFIXES = {".py", ".md", ".toml", ".yml", ".yaml"}
# Where the remaining shipped file types may live.
FIXTURE_DIR = Path("tests/data")
GOLDEN_DIR = Path("tests/data/golden")
DATA_TABLE_DIR = Path("pcapper")
# A synthetic fixture is tiny; a real capture is not.
MAX_FIXTURE_BYTES = 256 * 1024


def _tracked_files() -> list[Path]:
    if shutil.which("git") is None or not (REPO / ".git").exists():
        pytest.skip("not a git checkout")
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO, capture_output=True, check=True
    ).stdout
    return [Path(p.decode("utf-8")) for p in out.split(b"\0") if p]


def _classify(path: Path) -> str | None:
    """None when the file is allowed, else why it is not."""
    if path.name in ALLOWED_NAMES or path.suffix in ALLOWED_SUFFIXES:
        return None
    if path.suffix == ".json":
        return None if path.parent == DATA_TABLE_DIR else "JSON outside the package data tables"
    if path.suffix == ".txt":
        if path == Path("requirements.txt") or path.parent == GOLDEN_DIR:
            return None
        return "text file outside tests/data/golden"
    if path.suffix in {".pcap", ".pcapng"}:
        if path.parent != FIXTURE_DIR:
            return "capture outside tests/data"
        if (REPO / path).stat().st_size > MAX_FIXTURE_BYTES:
            return f"capture larger than {MAX_FIXTURE_BYTES} bytes (not a synthetic fixture)"
        return None
    return f"unexpected file type {path.suffix or path.name!r}"


def test_every_tracked_file_is_an_allowed_kind() -> None:
    offenders = [f"{p.as_posix()}: {why}" for p in _tracked_files() if (why := _classify(p))]
    assert not offenders, "tracked files that should not be in the repository:\n  " + "\n  ".join(offenders)


def test_gitignore_is_an_allow_list() -> None:
    rules = [
        line.strip()
        for line in (REPO / ".gitignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    assert rules[:2] == ["*", "!*/"], "the ignore file must start by ignoring everything"
    assert "!tests/data/*.pcap" not in rules and "!tests/data/*" not in rules, (
        "fixtures are allowed one by one, never by wildcard"
    )


def test_tracked_fixtures_are_the_ones_the_ignore_file_names() -> None:
    """Every committed capture must be individually named in .gitignore, so a
    new fixture is a deliberate, reviewed allow entry."""
    rules = set(
        line.strip()
        for line in (REPO / ".gitignore").read_text(encoding="utf-8").splitlines()
    )
    captures = [p for p in _tracked_files() if p.suffix in {".pcap", ".pcapng"}]
    unnamed = [p.as_posix() for p in captures if f"!{p.as_posix()}" not in rules]
    assert not unnamed, "captures tracked but not allow-listed by name:\n  " + "\n  ".join(unnamed)
