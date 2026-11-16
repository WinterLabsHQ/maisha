"""Lint-level checks on the Dockerfile (no container runtime is needed)."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEXT = (ROOT / "Dockerfile").read_text()
LINES = [ln.strip() for ln in TEXT.splitlines() if ln.strip() and not ln.strip().startswith("#")]


def test_final_user_is_non_root():
    users = [ln.split(None, 1)[1].strip() for ln in LINES if ln.upper().startswith("USER ")]
    assert users, "Dockerfile must set USER"
    assert users[-1].split(":")[0] not in ("root", "0")


def test_user_is_created_before_use():
    assert re.search(r"useradd[^\n]*maisha", TEXT)
    assert TEXT.index("useradd") < TEXT.index("\nUSER maisha")


def test_installs_analyzers_and_compiler():
    apt = re.search(r"apt-get install[^\n]*(?:\\\n[^\n]*)*", TEXT).group(0)
    for pkg in ("gcc", "cppcheck", "clang-tidy"):
        assert re.search(rf"\b{pkg}\b", apt), pkg


def test_entrypoint_is_maishac_and_mcp_extra_installed():
    assert 'ENTRYPOINT ["maishac"]' in TEXT
    assert '"/src[mcp]"' in TEXT


def test_license_is_copied_for_license_files():
    copy = next(ln for ln in LINES if ln.startswith("COPY pyproject.toml"))
    assert "LICENSE" in copy and "README.md" in copy
