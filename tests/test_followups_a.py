"""Round 2 follow-ups A1-A4 (verify gate reason, migration re-pointing,
occurrence alignment across analyzers, schema 3/4 waiver provenance)."""

import sqlite3

import pytest

from maishac.engine import LoopEngine

MALLOC = 'void *f(void)\n{\n    return malloc(4);\n}\n'
CLEAN = '#include <stdint.h>\nint32_t ok(void)\n{\n    return 0;\n}\n'
NATIVE = {"analyzers": ["native"]}


@pytest.fixture(autouse=True)
def _no_agent_override(monkeypatch):
    monkeypatch.delenv("MAISHAC_ALLOW_AGENT_APPROVALS", raising=False)


def _proj(tmp_path, body=MALLOC):
    proj = tmp_path / "p"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "m.c").write_text(body)
    return proj


# ------------------------------------------------------------------ A1
def test_a1_mcp_forced_gate_on_analyzer_only_session_explains_itself(tmp_path):
    proj = _proj(tmp_path)
    sid = LoopEngine(proj).begin_session(
        ["src"], {**NATIVE, "verification_policy": "analyzer_only"})["session_id"]
    (proj / "src" / "m.c").write_text(CLEAN)
    out = LoopEngine(proj, source="mcp").verify(sid)
    assert out["state"] == "awaiting_verification"
    assert out["reason"].strip()
    assert "analyzer_only" in out["reason"] and "MCP" in out["reason"]
    assert "maishac approve" in out["reason"]
    assert "maishac approve" in out["next"]


def test_a1_cli_verify_of_analyzer_only_session_is_unchanged(tmp_path):
    proj = _proj(tmp_path)
    eng = LoopEngine(proj)
    sid = eng.begin_session(["src"], {**NATIVE, "verification_policy": "analyzer_only"}
                            )["session_id"]
    (proj / "src" / "m.c").write_text(CLEAN)
    out = eng.verify(sid)
    assert "forced" not in out["reason"]
