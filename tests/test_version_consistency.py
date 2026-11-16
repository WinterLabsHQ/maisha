"""The version lives in one place (maishac/__init__.py); everything else must agree."""

import re
from pathlib import Path

import pytest

import maishac

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    tomllib = pytest.importorskip("tomli")

ROOT = Path(__file__).resolve().parents[1]
SEMVER = r"\d+\.\d+\.\d+"


def test_pyproject_version_is_dynamic_from_package():
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert "version" not in cfg["project"]
    assert "version" in cfg["project"]["dynamic"]
    assert cfg["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "maishac.__version__"}


def test_version_is_a_plain_literal_so_builds_need_no_dependencies():
    src = (ROOT / "maishac" / "__init__.py").read_text()
    assert re.search(rf'^__version__ = "{SEMVER}"$', src, re.M)
    assert not re.search(r"^(import|from)\s", src, re.M)


def test_citation_cff_matches_package_version():
    m = re.search(r'^version:\s*"?(' + SEMVER + r')"?\s*$',
                  (ROOT / "CITATION.cff").read_text(), re.M)
    assert m, "CITATION.cff has no version"
    assert m.group(1) == maishac.__version__


def test_no_stale_version_strings_in_readme_or_install():
    for name in ("README.md", "INSTALL.md"):
        text = (ROOT / name).read_text()
        for m in re.finditer(r"maishac " + SEMVER + r"|release-v" + SEMVER + r"|releases/tag/v" + SEMVER, text):
            assert maishac.__version__ in m.group(0), f"{name}: stale version {m.group(0)}"


def test_mcp_is_an_optional_extra_capped_below_2():
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert cfg["project"]["dependencies"] == []
    assert cfg["project"]["optional-dependencies"]["mcp"] == ["mcp>=1.2.0,<2"]
