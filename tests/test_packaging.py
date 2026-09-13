"""Guards on the version and on what actually ends up in the distribution.

Both defects these pin were invisible from the source tree and from CI:

* the version was declared twice — once in ``pcapper/__init__.py`` and once in
  ``pyproject.toml`` — and drifted, so ``pip install`` reported 2.2.0 while the
  banner still printed 2.1.0;
* ``[tool.setuptools] packages`` listed only ``pcapper``, so once ``reporting``
  became a subpackage the built wheel contained none of it and ``pcapper.cli``
  could not be imported at all. ``twine check`` passed the whole time, because
  it validates metadata rather than contents.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

try:  # 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.9/3.10
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:  # pragma: no cover
        tomllib = None  # type: ignore[assignment]

import pcapper

REPO_ROOT = Path(__file__).parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"
PACKAGE_ROOT = Path(pcapper.__file__).parent


def _pyproject() -> dict:
    if tomllib is None:  # pragma: no cover
        pytest.skip("no TOML parser available on this interpreter")
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


class TestVersionHasOneSource:
    def test_pyproject_does_not_hardcode_a_version(self) -> None:
        """A literal here is a second source of truth, and it drifted once."""
        project = _pyproject()["project"]
        assert "version" not in project, (
            "pyproject.toml declares its own version again. It must stay "
            'dynamic and read pcapper.__version__ instead.'
        )
        assert "version" in project.get("dynamic", [])

    def test_pyproject_reads_the_package_attribute(self) -> None:
        dynamic = _pyproject().get("tool", {}).get("setuptools", {}).get("dynamic", {})
        assert dynamic.get("version", {}).get("attr") == "pcapper.__version__"

    def test_version_is_a_plain_literal_setuptools_can_read_statically(self) -> None:
        """setuptools resolves ``attr:`` by parsing the module when it can. A
        computed value would force it to import pcapper at build time."""
        tree = ast.parse((PACKAGE_ROOT / "__init__.py").read_text(encoding="utf-8"))
        literals = [
            node.value.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(t, ast.Name) and t.id == "__version__"
                for t in node.targets
            )
            and isinstance(node.value, ast.Constant)
        ]
        assert literals == [pcapper.__version__]

    def test_version_looks_like_semver(self) -> None:
        assert re.fullmatch(r"\d+\.\d+\.\d+([-.].+)?", pcapper.__version__)

    def test_requirements_header_matches(self) -> None:
        """The header comment names a version; keep it honest rather than
        letting it rot into a third stale copy."""
        first = (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()[0]
        match = re.search(r"pcapper v(\d+\.\d+\.\d+)", first)
        assert match, f"expected a version in the requirements.txt header: {first!r}"
        assert match.group(1) == pcapper.__version__

    def test_cli_banner_uses_the_package_version(self) -> None:
        cli = (PACKAGE_ROOT / "cli.py").read_text(encoding="utf-8")
        assert "PCAPPER v{__version__}" in cli


class TestEverySubpackageIsDistributed:
    def test_declared_packages_cover_the_tree(self) -> None:
        """The wheel ships exactly what ``packages`` lists. When ``reporting``
        became a subpackage and this list was not updated, the built wheel had
        no renderers in it and ``import pcapper.cli`` raised
        ``ModuleNotFoundError`` — while CI stayed green, because ``twine check``
        inspects metadata, not contents."""
        declared = set(_pyproject()["tool"]["setuptools"]["packages"])
        found = {"pcapper"}
        for init in PACKAGE_ROOT.rglob("__init__.py"):
            relative = init.parent.relative_to(PACKAGE_ROOT)
            if relative == Path("."):
                continue
            if any(part.startswith((".", "__")) for part in relative.parts):
                continue
            found.add("pcapper." + ".".join(relative.parts))
        missing = found - declared
        assert not missing, (
            f"subpackages exist but are not declared in pyproject.toml: "
            f"{sorted(missing)}. They would be missing from the wheel."
        )

    def test_reporting_is_declared(self) -> None:
        declared = set(_pyproject()["tool"]["setuptools"]["packages"])
        assert "pcapper.reporting" in declared


class TestRequirementsMatchPyproject:
    """``requirements.txt`` and ``pyproject.toml`` must list the same runtime
    dependencies, with the same specifiers.

    The header of ``requirements.txt`` has always said "Keep in sync with
    pyproject.toml [project.dependencies]", and nothing enforced it. A
    Dependabot PR then proposed raising ``tomli>=2.0.1`` to ``>=2.4.1`` in
    ``requirements.txt`` alone, which would have left the two disagreeing on
    the first line it touched -- and silently, because installs resolve from
    ``pyproject.toml``, so the requirements floor has no effect on what a user
    actually gets. A manual-sync comment is not a control; this is.
    """

    @staticmethod
    def _normalise(spec: str) -> str:
        """Compare requirement strings without whitespace or quote noise.

        ``tomli>=2.0.1; python_version < "3.11"`` and the pyproject spelling of
        the same line differ only in spacing, so neither survives into the
        comparison.
        """
        return re.sub(r"\s+", "", spec).replace("'", '"')

    def _requirements(self) -> set[str]:
        out = set()
        text = (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8")
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                out.add(self._normalise(line))
        return out

    def test_the_two_manifests_agree(self) -> None:
        declared = {self._normalise(d) for d in _pyproject()["project"]["dependencies"]}
        listed = self._requirements()
        only_in_requirements = listed - declared
        only_in_pyproject = declared - listed
        assert not (only_in_requirements or only_in_pyproject), (
            "requirements.txt and pyproject.toml have drifted.\n"
            f"  only in requirements.txt: {sorted(only_in_requirements)}\n"
            f"  only in pyproject.toml:   {sorted(only_in_pyproject)}\n"
            "Both files must be updated together -- note that installs resolve "
            "from pyproject.toml, so a requirements-only change has no effect."
        )

    def test_requirements_is_not_empty(self) -> None:
        """Guard the guard: an empty parse would make the test above vacuous."""
        assert len(self._requirements()) >= 5
