"""Lint-level checks on the GitHub Actions workflows and Dependabot config.

These parse the YAML (PyYAML, skipped when missing) and assert the release
safety properties: publish only after tests + build, tag/version check, pinned
third-party actions, least-privilege permissions, safe workflow_dispatch.
"""

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / ".github" / "workflows"
SHA = re.compile(r"^[0-9a-f]{40}$")
# Documented allowlist of third-party (non-local) action owners. Anything else
# must be added here deliberately, and still has to be pinned to a full SHA.
ALLOWED_OWNERS = {"actions", "docker", "pypa"}


def load(name):
    return yaml.safe_load((WF / name).read_text())


def all_workflows():
    return sorted(p.name for p in WF.glob("*.yml"))


def needs(job):
    n = job.get("needs", [])
    return {n} if isinstance(n, str) else set(n)


def transitive_needs(jobs, name):
    seen, todo = set(), [name]
    while todo:
        for dep in needs(jobs[todo.pop()]):
            if dep not in seen:
                seen.add(dep)
                todo.append(dep)
    return seen


def steps_text(job):
    return "\n".join(str(s) for s in job.get("steps", []))


@pytest.mark.parametrize("name", all_workflows())
def test_actions_pinned_to_full_sha_with_version_comment(name):
    text = (WF / name).read_text()
    uses = re.findall(r"^\s*(?:-\s*)?uses:\s*(\S+)(?:\s+#\s*(\S+))?", text, re.M)
    assert uses, name
    for ref, comment in uses:
        action, _, pin = ref.partition("@")
        owner = action.split("/")[0]
        assert owner in ALLOWED_OWNERS, f"{name}: {action} is not on the allowlist"
        assert SHA.match(pin), f"{name}: {action} is not pinned to a 40-hex SHA"
        assert comment and re.fullmatch(r"v\d+\.\d+\.\d+", comment), (
            f"{name}: {action} needs a trailing '# vX.Y.Z' comment, got {comment!r}")


@pytest.mark.parametrize("name", all_workflows())
def test_top_level_permissions_are_read_only(name):
    assert load(name)["permissions"] == {"contents": "read"}


def test_write_scopes_only_on_jobs_that_need_them():
    allowed = {"release.yml": {"publish": {"id-token"}},
               "docker-publish.yml": {"docker": {"packages"}}}
    for name in all_workflows():
        for jname, job in load(name)["jobs"].items():
            writes = {k for k, v in (job.get("permissions") or {}).items() if v == "write"}
            assert writes == allowed.get(name, {}).get(jname, set()), (name, jname, writes)


def test_release_publish_depends_on_tests_and_build():
    jobs = load("release.yml")["jobs"]
    deps = transitive_needs(jobs, "publish")
    assert {"test", "build"} <= deps
    assert "build" in needs(jobs["publish"])
    assert "test" in needs(jobs["build"])
    assert jobs["publish"]["environment"] == "pypi"


def test_release_build_checks_tag_against_version():
    build = load("release.yml")["jobs"]["build"]
    text = steps_text(build)
    assert "MAISHAC_TAG" in text and "github.ref_name" in text
    assert "tools/check_dist.py" in text
    assert "twine check" in text


def test_docker_publish_verifies_tag_and_tests_before_push():
    jobs = load("docker-publish.yml")["jobs"]
    assert "verify" in needs(jobs["docker"])
    verify = steps_text(jobs["verify"])
    assert "refs/tags/" in verify and "__version__" in verify
    assert "pytest" in verify


def test_docker_publish_dispatch_only_pushes_from_main_or_tags():
    wf = load("docker-publish.yml")
    assert "workflow_dispatch" in wf[True]  # PyYAML parses the `on` key as True
    guard = wf["jobs"]["docker"].get("if", "")
    assert "refs/heads/main" in guard
    assert "refs/tags/" in guard


def test_dependabot_covers_actions_and_pip_weekly_grouped():
    cfg = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())
    assert cfg["version"] == 2
    eco = {u["package-ecosystem"]: u for u in cfg["updates"]}
    assert {"github-actions", "pip"} <= set(eco)
    for u in eco.values():
        assert u["schedule"]["interval"] == "weekly"
        assert u["groups"]
