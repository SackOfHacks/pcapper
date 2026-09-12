"""Guards on the shape of the reporting package.

``reporting`` was a single 30,000-line module until it was split into one
module per analyzer. These tests exist so it cannot silently drift back, and so
the two things the split could plausibly have broken stay broken-if-broken
rather than subtly wrong:

* the public surface — every name the old module exported must still be
  importable from ``pcapper.reporting``;
* the mutable output-mode state — it lives in ``_common`` and is read through
  accessors, because a sibling module doing ``from ._common import
  _VERBOSE_OUTPUT`` would bind the value at import time and never see
  ``set_verbose_output()``.
"""

from __future__ import annotations

import ast
import importlib
import pkgutil
from pathlib import Path

import pytest

import pcapper.reporting as reporting

PACKAGE_DIR = Path(reporting.__file__).parent
MAX_MODULE_LINES = 2000

# The four flags that are rebound at runtime. Everything else at module level in
# _common is a constant.
MUTABLE_FLAGS = ("_VERBOSE_OUTPUT", "_QUIET_MODE", "_OUI_ANNOTATE", "_OT_FULL_OUTPUT")


def _module_paths() -> list[Path]:
    return sorted(p for p in PACKAGE_DIR.glob("*.py") if p.name != "__init__.py")


class TestPackageShape:
    def test_reporting_is_a_package(self) -> None:
        assert PACKAGE_DIR.is_dir()
        assert (PACKAGE_DIR / "__init__.py").is_file()
        assert not (PACKAGE_DIR.parent / "reporting.py").exists()

    def test_every_submodule_imports(self) -> None:
        failures = []
        for info in pkgutil.iter_modules([str(PACKAGE_DIR)]):
            try:
                importlib.import_module(f"pcapper.reporting.{info.name}")
            except Exception as exc:  # pragma: no cover - failure path
                failures.append(f"{info.name}: {type(exc).__name__}: {exc}")
        assert not failures, failures

    def test_no_module_grows_back_to_unreadable(self) -> None:
        """The original file's problem was that no reader could hold it in
        their head; both confirmed duplication bugs in the 2026-09 review lived
        in it. Keep the pieces reviewable."""
        oversized = {
            path.name: len(path.read_text(encoding="utf-8").splitlines())
            for path in _module_paths()
            if len(path.read_text(encoding="utf-8").splitlines()) > MAX_MODULE_LINES
        }
        assert not oversized, (
            f"modules over {MAX_MODULE_LINES} lines: {oversized}. Split the "
            "renderer rather than raising the limit."
        )


class TestPublicSurface:
    @pytest.mark.parametrize(
        "name",
        [
            "render_dns_summary",
            "render_http_summary",
            "render_smb_summary",
            "render_modbus_summary",
            "render_carve_summary",
            "render_threats_summary",
            "render_overview_summary",
            "set_verbose_output",
            "set_quiet_mode",
            "is_quiet_mode",
            "set_oui_annotation",
            "is_oui_annotation_enabled",
            "SECTION_BAR",
            "SUBSECTION_BAR",
        ],
    )
    def test_name_is_still_exported(self, name: str) -> None:
        assert hasattr(reporting, name)

    def test_every_name_cli_imports_resolves(self) -> None:
        """cli.py imports ~126 names from reporting in one statement. A missing
        re-export would be an ImportError at startup, not at use."""
        cli = Path(reporting.__file__).parent.parent / "cli.py"
        tree = ast.parse(cli.read_text(encoding="utf-8"))
        wanted: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "reporting":
                wanted.extend(alias.name for alias in node.names)
        assert wanted, "expected cli.py to import from .reporting"
        missing = [name for name in wanted if not hasattr(reporting, name)]
        assert not missing, missing

    def test_every_renderer_is_reexported(self) -> None:
        exported = set(dir(reporting))
        missing = []
        for info in pkgutil.iter_modules([str(PACKAGE_DIR)]):
            module = importlib.import_module(f"pcapper.reporting.{info.name}")
            for name in vars(module):
                if name.startswith("render_") and name not in exported:
                    missing.append(f"{info.name}.{name}")
        assert not missing, missing


class TestMutableStateIsNotCopied:
    def test_flags_live_only_in_common(self) -> None:
        """If a sibling module defined or imported one of these at module level
        it would hold a stale copy, and set_verbose_output() would silently stop
        working for that module's renderers."""
        offenders = []
        for path in _module_paths():
            if path.name == "_common.py":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in tree.body:
                names: list[str] = []
                if isinstance(node, ast.Assign):
                    names = [t.id for t in node.targets if isinstance(t, ast.Name)]
                elif isinstance(node, ast.ImportFrom):
                    names = [a.asname or a.name for a in node.names]
                for name in names:
                    if name in MUTABLE_FLAGS:
                        offenders.append(f"{path.name}: {name}")
        assert not offenders, offenders

    def test_set_verbose_output_reaches_every_module(self) -> None:
        """The behavioural version of the test above, through the real API."""
        from pcapper.reporting import _common

        try:
            reporting.set_verbose_output(True)
            assert _common._verbose_output() is True
            assert _common._limit_value(3) == _common._FULL_OUTPUT_LIMIT
            reporting.set_verbose_output(False)
            assert _common._verbose_output() is False
            assert _common._limit_value(3) == 3
        finally:
            reporting.set_verbose_output(False)

    def test_quiet_and_oui_toggles_round_trip(self) -> None:
        try:
            reporting.set_quiet_mode(True)
            assert reporting.is_quiet_mode() is True
            reporting.set_oui_annotation(True)
            assert reporting.is_oui_annotation_enabled() is True
        finally:
            reporting.set_quiet_mode(False)
            reporting.set_oui_annotation(False)
