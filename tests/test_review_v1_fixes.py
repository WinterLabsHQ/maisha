"""Regression tests for the first review of the analysis-hardening branch:
ungated resolution paths, file_removed, migration provenance, session
compare-and-set, the live-session guard, occurrence alignment, Windows path
migration and unresolvable rule ids."""

import sqlite3

import pytest

from maishac import report as report_mod
from maishac.engine import LoopEngine
from maishac.memory import SCHEMA_VERSION, MemoryStore
from maishac.model import Finding, assign_occurrences, compute_fingerprint, occurrence_alignment

MALLOC = 'void *f(void)\n{\n    return malloc(4);\n}\n'
CLEAN = '#include <stdint.h>\nint32_t ok(void)\n{\n    return 0;\n}\n'
NATIVE = {"analyzers": ["native"]}


@pytest.fixture(autouse=True)
def _no_agent_override(monkeypatch):
    monkeypatch.delenv("MAISHAC_ALLOW_AGENT_APPROVALS", raising=False)


def _proj(tmp_path, body=MALLOC, name="m.c"):
    proj = tmp_path / "p"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / name).write_text(body)
    return proj


def _statuses(eng):
    return {r["fingerprint"]: r["status"] for r in eng.mem.db.execute("SELECT * FROM findings")}


# ---------------------------------------------- 1: agent cannot self-resolve
def test_mcp_scan_never_resolves_a_finding_straight_from_the_analyzer(tmp_path):
    proj = _proj(tmp_path)
    eng = LoopEngine(proj, source="mcp")
    eng.scan(["src"], ["native"])
    assert any(r["severity"] in ("blocker", "critical") for r in eng.mem.open_findings())
    (proj / "src" / "m.c").write_text(CLEAN)
    out = eng.scan(["src"], ["native"])
    assert out["diff"]["resolved"] == 0 and out["diff"]["pending"] >= 1
    assert set(_statuses(eng).values()) == {"pending_verification"}


def test_cli_scan_still_resolves_when_a_human_runs_it_ungated(tmp_path):
    proj = _proj(tmp_path)
    eng = LoopEngine(proj)
    eng.scan(["src"], ["native"])
    (proj / "src" / "m.c").write_text(CLEAN)
    assert eng.scan(["src"], ["native"])["diff"]["resolved"] >= 1


def test_mcp_scan_gate_can_be_lifted_only_by_the_operator_env(tmp_path, monkeypatch):
    proj = _proj(tmp_path)
    monkeypatch.setenv("MAISHAC_ALLOW_AGENT_APPROVALS", "1")
    eng = LoopEngine(proj, source="mcp")
    eng.scan(["src"], ["native"])
    (proj / "src" / "m.c").write_text(CLEAN)
    assert eng.scan(["src"], ["native"])["diff"]["resolved"] >= 1


def test_mcp_cannot_open_an_analyzer_only_session(tmp_path, monkeypatch):
    proj = _proj(tmp_path)
    eng = LoopEngine(proj, source="mcp")
    out = eng.begin_session(["src"], {**NATIVE, "verification_policy": "analyzer_only"})
    assert "error" in out and "analyzer_only" in out["error"]
    assert eng.mem.db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    # the human CLI may still choose it, and the operator can allow it for MCP
    assert "session_id" in LoopEngine(proj).begin_session(
        ["src"], {**NATIVE, "verification_policy": "analyzer_only"})
    monkeypatch.setenv("MAISHAC_ALLOW_AGENT_APPROVALS", "1")
    assert "session_id" in LoopEngine(_proj(tmp_path / "b"), source="mcp").begin_session(
        ["src"], {**NATIVE, "verification_policy": "analyzer_only"}, force=True)


def test_mcp_verify_with_a_cli_chosen_analyzer_only_policy_still_gates(tmp_path):
    proj = _proj(tmp_path)
    cli_eng = LoopEngine(proj)
    sid = cli_eng.begin_session(
        ["src"], {**NATIVE, "verification_policy": "analyzer_only"})["session_id"]
    (proj / "src" / "m.c").write_text(CLEAN)
    out = LoopEngine(proj, source="mcp").verify(sid)
    assert out["state"] == "awaiting_verification"
    assert set(_statuses(cli_eng).values()) == {"pending_verification"}


def test_analyzer_only_session_still_holds_high_severity_findings_for_a_person(tmp_path):
    two = MALLOC + "void g(void)\n{\n    int x = 1;\n}\n"
    proj = _proj(tmp_path, two)
    eng = LoopEngine(proj)
    sid = eng.begin_session(["src"], {**NATIVE, "verification_policy": "analyzer_only"}
                            )["session_id"]
    (proj / "src" / "m.c").write_text(CLEAN)
    out = eng.verify(sid)
    assert out["state"] == "awaiting_verification"
    rows = eng.mem.pending_findings()
    assert rows and all(r["severity"] in ("blocker", "critical") or r["semantic_risk"]
                        for r in rows)
    from maishac.memory import requires_human
    assert not any(r["verification_method"] == "analyzer" and requires_human(dict(r))
                   for r in eng.mem.db.execute("SELECT * FROM findings"))


# ------------------------------------------------- 2: file_removed + the gate
def _f(sev="critical", file="src/a.c"):
    return Finding(rule_id="MISRA-C:2012 Rule 21.3", standard="MISRA-C:2012", severity=sev,
                   file=file, line=3, message="m", line_content="p = malloc(1);",
                   analyzer="native")


def test_moved_file_does_not_resolve_a_blocker_without_sign_off(tmp_path):
    proj = _proj(tmp_path, MALLOC, "a.c")
    eng = LoopEngine(proj)                    # human CLI, ungated
    eng.scan(["src"], ["native"])
    fp = eng.mem.open_findings()[0]["fingerprint"]
    (proj / "build").mkdir()
    (proj / "src" / "a.c").rename(proj / "build" / "a.c")   # default-excluded dir
    (proj / "src" / "b.c").write_text(CLEAN)
    eng.scan(["src"], ["native"])
    assert eng.mem.get_finding(fp)["status"] == "pending_verification"
    assert eng.mem.get_finding(fp)["verification_method"] is None


def test_gated_scan_sends_a_removed_files_findings_to_pending(tmp_path):
    mem = MemoryStore(tmp_path)
    f = _f(sev="minor")
    mem.sync_scan([f], ["src/a.c"])
    d = mem.sync_scan([], ["src/b.c"], gate=True, removed_files={"src/a.c"})
    assert d["pending"] == [f.fingerprint] and d["stale"] == []
    assert mem.get_finding(f.fingerprint)["status"] == "pending_verification"


# ------------------------------------------------ 3: migration provenance
OLD_DDL = """
CREATE TABLE findings (fingerprint TEXT PRIMARY KEY, rule_id TEXT NOT NULL, standard TEXT,
  severity TEXT, file TEXT, line INTEGER, message TEXT, analyzer TEXT, line_content TEXT,
  context_symbol TEXT, fix_hint TEXT, status TEXT NOT NULL DEFAULT 'open',
  seen_count INTEGER NOT NULL DEFAULT 1, regress_count INTEGER NOT NULL DEFAULT 0,
  first_seen REAL NOT NULL, last_seen REAL NOT NULL, resolved_at REAL);
CREATE TABLE deviations (id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, scope TEXT NOT NULL DEFAULT '*',
  justification TEXT NOT NULL, approver TEXT, expires REAL, ts REAL NOT NULL);
CREATE TABLE suppressions (fingerprint TEXT PRIMARY KEY, reason TEXT NOT NULL, ts REAL NOT NULL);
CREATE TABLE recategorizations (rule_id TEXT PRIMARY KEY, to_category TEXT NOT NULL,
  rationale TEXT NOT NULL, approver TEXT, ts REAL NOT NULL);
CREATE TABLE fix_attempts (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, session_id TEXT,
  strategy TEXT, outcome TEXT, notes TEXT, ts REAL NOT NULL);
"""


def _old_db(root, files=()):
    (root / ".maishac").mkdir(parents=True)
    db = sqlite3.connect(root / ".maishac" / "memory.db")
    db.executescript(OLD_DDL)
    for fp, rule, file, content, symbol in files:
        db.execute("INSERT INTO findings (fingerprint, rule_id, file, line, line_content,"
                   " context_symbol, first_seen, last_seen, severity, analyzer)"
                   " VALUES (?,?,?,?,?,?,1,1,'critical','native')",
                   (fp, rule, file, 3, content, symbol))
    db.commit()
    return db


def test_pre_provenance_waivers_migrate_as_legacy_not_cli(tmp_path):
    root = tmp_path / "old"
    db = _old_db(root, [("fp1", "MISRA-C:2012 Rule 21.3", "src/a.c", "p = malloc(1);", "f")])
    db.execute("INSERT INTO deviations (id, rule_id, scope, justification, approver, ts)"
               " VALUES ('d1','MISRA-C:2012 Rule 21.3','*','agent made this one','mcp-agent',1)")
    db.execute("INSERT INTO suppressions VALUES ('fp1','agent reason',1)")
    db.execute("INSERT INTO recategorizations VALUES ('MISRA-C:2012 Rule 15.5','required','r','a',1)")
    db.commit()
    db.execute("ALTER TABLE findings ADD COLUMN approved_by TEXT")
    db.execute("UPDATE findings SET approved_by='mcp-agent'")
    db.commit()
    db.close()
    mem = MemoryStore(root)
    assert mem.deviations()[0]["source"] == "legacy"
    assert mem.suppressions()[0]["source"] == "legacy"
    assert mem.recategorizations()["MISRA-C:2012 Rule 15.5"]["source"] == "legacy"
    assert mem.get_finding("fp1")["approval_source"] == "legacy"
    # new rows written afterwards are attributed normally
    mem.add_deviation("MISRA-C:2012 Rule 15.5", "*", "a long enough justification", source="cli")
    assert {d["source"] for d in mem.deviations()} == {"legacy", "cli"}


def test_reports_flag_legacy_signoffs_as_unknown_origin(tmp_path):
    root = tmp_path / "old"
    db = _old_db(root)
    db.execute("INSERT INTO deviations (id, rule_id, scope, justification, approver, ts)"
               " VALUES ('d1','MISRA-C:2012 Rule 21.3','*','kept for now','lead',1)")
    db.commit()
    db.close()
    text = report_mod.markdown_report(MemoryStore(root))
    assert "ORIGIN UNKNOWN" in text and "predate provenance tracking" in text


# ------------------------------------------- 4: session compare-and-set
def test_verify_does_not_overwrite_a_session_aborted_meanwhile(tmp_path):
    proj = _proj(tmp_path)
    eng = LoopEngine(proj)
    sid = eng.begin_session(["src"], NATIVE)["session_id"]
    real_scan = eng.scan

    def scan_then_abort(*a, **kw):
        out = real_scan(*a, **kw)
        LoopEngine(proj).abort_session(sid, "operator stopped it")   # lands mid-verify
        return out

    eng.scan = scan_then_abort
    out = eng.verify(sid)
    assert "error" in out and out["state"] == "aborted"
    sess = eng.mem.get_session(sid)
    assert sess["status"] == "aborted" and sess["end_reason"] == "operator stopped it"
    assert sess["iteration"] == 0


def test_abort_loses_cleanly_to_a_session_that_changed_state(tmp_path):
    eng = LoopEngine(_proj(tmp_path))
    sid = eng.begin_session(["src"], NATIVE)["session_id"]
    sess = eng._require(sid)
    eng.mem.update_session(sid, status="converged")
    assert eng.mem.update_session(sid, status="aborted", expect_status=sess["status"]) is False
    assert eng.mem.get_session(sid)["status"] == "converged"


# ------------------------------------ 5: live-session guard covers waiting states
@pytest.mark.parametrize("state", ["awaiting_verification", "analysis_incomplete"])
def test_begin_session_is_blocked_by_a_waiting_session(tmp_path, state):
    eng = LoopEngine(_proj(tmp_path))
    sid = eng.begin_session(["src"], NATIVE)["session_id"]
    eng.mem.update_session(sid, status=state)
    out = eng.begin_session(["src"], NATIVE)
    assert out.get("active_session_id") == sid
    assert eng.mem.latest_active_session()["id"] == sid
    assert "session_id" in eng.begin_session(["src"], NATIVE, force=True)


def test_begin_session_is_allowed_after_a_terminal_state(tmp_path):
    eng = LoopEngine(_proj(tmp_path))
    sid = eng.begin_session(["src"], NATIVE)["session_id"]
    eng.abort_session(sid)
    assert "session_id" in eng.begin_session(["src"], NATIVE)


# --------------------------------------- 6: occurrence alignment across tools
def _occ(line, analyzer):
    return Finding(rule_id="MISRA-C:2012 Rule 21.3", standard="MISRA-C:2012",
                   severity="critical", file="a.c", line=line, message="m",
                   analyzer=analyzer, line_content="p = malloc(1);", context_symbol="f")


def _run(lines, analyzer, aligned):
    return assign_occurrences([_occ(n, analyzer) for n in lines], aligned)


def test_a_tool_reporting_only_the_second_line_gets_the_second_identity():
    native, cppcheck = [_occ(4, "native"), _occ(6, "native")], [_occ(6, "cppcheck")]
    aligned = occurrence_alignment([native, cppcheck])
    n = assign_occurrences(native, aligned)
    c = assign_occurrences(cppcheck, aligned)
    assert n[1].fingerprint == c[0].fingerprint != n[0].fingerprint
    # without alignment cppcheck's lone finding collided with the FIRST line
    lone = assign_occurrences([_occ(6, "cppcheck")])
    assert lone[0].fingerprint == n[0].fingerprint


def test_off_by_one_reports_of_one_violation_share_an_identity():
    a, b = [_occ(5, "native")], [_occ(6, "cppcheck")]
    aligned = occurrence_alignment([a, b])
    assert list(aligned.values()) == [{5: 0, 6: 0}]     # see test_followups_a for more
    assert (assign_occurrences(a, aligned)[0].fingerprint
            == assign_occurrences(b, aligned)[0].fingerprint)


# --------------------------------------------- 7: Windows path migration
def test_windows_backslash_rows_are_rewritten_with_their_fingerprints(tmp_path):
    root = tmp_path / "win"
    rule, content = "MISRA-C:2012 Rule 21.3", "p = malloc(1);"
    fp0 = compute_fingerprint(rule, "src\\a.c", content, "f")
    fp1 = compute_fingerprint(rule, "src\\a.c", content, "f", 1)
    db = _old_db(root, [(fp0, rule, "src\\a.c", content, "f"),
                        (fp1, rule, "src\\a.c", content, "f"),
                        ("ext-1", rule, "src\\b.c", "x", "g")])
    db.execute("INSERT INTO suppressions VALUES (?, 'ok reason here', 1)", (fp1,))
    db.execute("INSERT INTO fix_attempts VALUES ('a1', ?, 's', 'try', 'pending', '', 1)", (fp0,))
    db.commit()
    db.close()
    mem = MemoryStore(root)
    new0 = compute_fingerprint(rule, "src/a.c", content, "f")
    new1 = compute_fingerprint(rule, "src/a.c", content, "f", 1)
    rows = {r["fingerprint"]: r["file"] for r in mem.db.execute("SELECT * FROM findings")}
    assert rows == {new0: "src/a.c", new1: "src/a.c", "ext-1": "src/b.c"}
    assert mem.is_suppressed(new1) and not mem.is_suppressed(fp1)
    assert mem.attempts_for(new0)[0]["id"] == "a1"
    assert mem.db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    assert {e["action"] for e in mem.audit_entries()} == {"path_migration"}
    # a rescan now matches the rewritten rows instead of duplicating them
    f = Finding(rule_id=rule, standard="MISRA-C:2012", severity="critical", file="src\\a.c",
                line=3, message="m", line_content=content, context_symbol="f")
    d = mem.sync_scan([f], ["src/a.c"])
    assert d["new"] == [] and d["persisting"] == [new0]
    mem.close()
    assert len(MemoryStore(root).audit_entries()) == 3   # reopening migrates nothing more


def test_windows_row_colliding_with_a_live_row_is_dropped(tmp_path):
    root = tmp_path / "win"
    rule, content = "MISRA-C:2012 Rule 21.3", "p = malloc(1);"
    old = compute_fingerprint(rule, "src\\a.c", content, "f")
    new = compute_fingerprint(rule, "src/a.c", content, "f")
    db = _old_db(root, [(old, rule, "src\\a.c", content, "f"), (new, rule, "src/a.c", content, "f")])
    db.close()
    mem = MemoryStore(root)
    assert [r["fingerprint"] for r in mem.db.execute("SELECT * FROM findings")] == [new]
    assert mem.audit_entries()[0]["action"] == "path_migration_dropped_duplicate"


# ------------------------------------- 8: unresolvable ids in the memory layer
@pytest.mark.parametrize("rid", ["4.1", "no such rule"])  # both unknown to the registry
def test_memory_layer_refuses_a_deviation_for_an_unresolvable_rule(tmp_path, rid):
    mem = MemoryStore(tmp_path)
    with pytest.raises(ValueError):
        mem.add_deviation(rid, "*", "a long enough justification")
    assert mem.deviations() == []


def test_memory_layer_refuses_recategorizing_or_suppressing_an_ambiguous_id(tmp_path, monkeypatch):
    from maishac.rules import REGISTRY
    mem = MemoryStore(tmp_path)
    with pytest.raises(ValueError):
        mem.add_recategorization("4.1", "advisory", "rationale text")
    # an id that matches two guidelines could be Mandatory: do not guess
    both = [{"id": "MISRA-C:2012 Rule 4.1"}, {"id": "MISRA-C:2012 Dir 4.1"}]
    monkeypatch.setattr(REGISTRY, "candidates", lambda q: both)
    with pytest.raises(ValueError, match="ambiguous"):
        mem.suppress("fp-not-on-record", "a long enough reason", rule_id="4.1")
    monkeypatch.undo()
    # a foreign tool's rule id on an imported finding is still accepted
    mem.suppress("fp-x", "bring your own triage", rule_id="vendor-rule-9", source="import")
    assert mem.is_suppressed("fp-x")
