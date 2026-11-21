"""docs/reference.md names only flags the CLI has (it listed --codesys as --odesys)."""

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
