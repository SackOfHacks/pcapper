"""The docs name only flags the CLI has (docs/reference.md listed --codesys as --odesys)."""

from __future__ import annotations

import re
from pathlib import Path

from pcapper.cli import build_parser


def test_documented_flags_exist() -> None:
    doc = (Path(__file__).resolve().parents[1] / "docs" / "reference.md").read_text(encoding="utf-8")
    documented = set(re.findall(r"^- `(--[a-z0-9-]+)`$", doc, re.M))
    assert len(documented) > 100  # the flag list is still there to check
    known = {opt for action in build_parser()._actions for opt in action.option_strings}
    assert sorted(documented - known) == []


def test_readme_flags_exist() -> None:
    """Every flag the README shows in an example or the flag table is one the
    CLI accepts -- a renamed or retired flag would otherwise linger there."""
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
    # The Development section shows git, pip and ruff command lines.
    readme = readme.split("\n## Development", 1)[0]
    shown = set(re.findall(r"(?<![\w/.-])(--[a-z][a-z0-9-]+|-(?:summarize|ip|vt|v|r))(?![\w-])", readme))
    assert len(shown) > 40  # the examples and the flag table are still there
    known = {opt for action in build_parser()._actions for opt in action.option_strings}
    assert sorted(shown - known) == []
