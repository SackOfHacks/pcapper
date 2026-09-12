"""Shared fixtures and golden-file plumbing for the pcapper test suite.

Rendered reports are compared byte for byte, so anything that varies between
runs or between machines has to be pinned here rather than in each test: ANSI
colour, verbose mode, and the output-truncation limits all live in module-level
state inside ``pcapper.reporting``.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from pcapper import coloring, reporting

DATA_DIR = Path(__file__).parent / "data"
GOLDEN_DIR = DATA_DIR / "golden"


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--regenerate-golden",
        action="store_true",
        default=False,
        help="Rewrite the golden output files instead of comparing against them.",
    )


@pytest.fixture(autouse=True)
def deterministic_output(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin every global that would otherwise make rendered output vary.

    ``use_color`` falls back to ``sys.stdout.isatty()``, which differs between a
    terminal run and a CI run, so a golden file recorded in one place would fail
    in the other. Verbose mode is module-level state that leaks between tests.
    """
    monkeypatch.setenv("NO_COLOR", "1")
    coloring.set_color_override(False)
    reporting.set_verbose_output(False)
    yield
    coloring.set_color_override(None)
    reporting.set_verbose_output(False)


@pytest.fixture(scope="session")
def data_dir() -> Path:
    if not DATA_DIR.is_dir():
        pytest.fail(f"missing fixture directory {DATA_DIR}")
    return DATA_DIR


@pytest.fixture(scope="session")
def pcap(data_dir: Path):
    """Resolve a fixture capture by name, with a pointer to the builder."""

    def _pcap(name: str) -> Path:
        path = data_dir / name
        if not path.is_file():
            pytest.fail(
                f"missing capture fixture {path}. "
                "Regenerate with: python tests/make_fixtures.py"
            )
        return path

    return _pcap


@pytest.fixture
def golden(request: pytest.FixtureRequest):
    """Compare rendered text against a committed golden file.

    Run ``pytest --regenerate-golden`` after an intentional output change, then
    review the resulting diff — that diff is the point of these tests.
    """
    regenerate = request.config.getoption("--regenerate-golden")

    def _golden(name: str, actual: str) -> None:
        path = GOLDEN_DIR / f"{name}.txt"
        # Normalise line endings so a Windows checkout and a Linux CI run agree.
        actual = actual.replace("\r\n", "\n")
        if regenerate or not path.is_file():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(actual, encoding="utf-8", newline="\n")
            if not regenerate:
                pytest.fail(
                    f"golden file {path} did not exist and has been created; "
                    "review it and commit it"
                )
            return
        expected = path.read_text(encoding="utf-8").replace("\r\n", "\n")
        assert actual == expected, (
            f"rendered output differs from {path}. If the change is intended, "
            "re-run with --regenerate-golden and review the diff."
        )

    return _golden


@pytest.fixture
def posix_only() -> None:
    if os.name != "posix":
        pytest.skip("POSIX permission bits are not meaningful on this platform")
