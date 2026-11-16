"""Gate integrity: who may approve, deviate, suppress and recategorize; the
protections for MISRA Mandatory guidelines; revocation; and the audit log."""

import json
import os
import sqlite3
import sys
import time

import pytest

from maishac.engine import LoopEngine
from maishac.memory import MandatoryRuleError, MemoryStore, SCHEMA_VERSION
from maishac.model import Finding

MAND = "MISRA-C:2012 Rule 17.6"      # Mandatory
REQ = "MISRA-C:2012 Rule 21.3"       # Required
ADV = "MISRA-C:2012 Rule 15.5"       # Advisory


def _f(rule=REQ, file="src/a.c", content="p = malloc(1);", sev="major"):
    return Finding(rule_id=rule, standard="MISRA-C:2012", severity=sev, file=file, line=3,
                   message="m", line_content=content, analyzer="native")


def _mem(tmp_path, *findings):
    mem = MemoryStore(tmp_path)
    if findings:
        mem.sync_scan(list(findings), sorted({f.file for f in findings}))
    return mem


# ------------------------------------------- item 10: mandatory protections
def test_suppress_refuses_a_mandatory_finding(tmp_path):
    f = _f(MAND, content="void g(int b[static 10]);")
    mem = _mem(tmp_path, f)
    with pytest.raises(MandatoryRuleError):
        mem.suppress(f.fingerprint, "we would rather not fix this")
    assert not mem.is_suppressed(f.fingerprint)
    assert mem.get_finding(f.fingerprint)["status"] == "open"


def test_suppress_uses_the_effective_category_after_grp(tmp_path):
    f = _f(ADV, content="x")
    eng = LoopEngine(tmp_path)
    eng.mem.sync_scan([f], ["src/a.c"])
    assert "error" not in eng.recategorize("MISRA 15.5", "mandatory", "agreed with acquirer")
    with pytest.raises(MandatoryRuleError):
        eng.mem.suppress(f.fingerprint, "no longer wanted here")
    assert "Mandatory" in eng.suppress(f.fingerprint, "a long enough reason")["error"]


def test_deviation_uses_the_effective_category_after_grp(tmp_path):
    eng = LoopEngine(tmp_path)
    assert "error" not in eng.recategorize("MISRA 15.5", "mandatory", "agreed with acquirer")
    with pytest.raises(MandatoryRuleError):
        eng.mem.add_deviation("MISRA-C:2012 Rule 15.5", "*", "justified for legacy code")
    assert "Mandatory" in eng.deviate("MISRA 15.5", "*", "justified for legacy code")["error"]
    assert eng.mem.deviations() == []


def test_grp_disapplied_rule_is_not_mandatory(tmp_path):
    eng = LoopEngine(tmp_path)
    eng.recategorize("MISRA 15.5", "disapplied", "agreed with acquirer")
    assert eng.mem.effective_category("MISRA-C:2012 Rule 15.5") == "disapplied"
    assert "deviation_id" in eng.deviate("MISRA 15.5", "*", "justified for legacy code")


def test_suppression_that_predates_the_guard_is_ignored_on_rescan(tmp_path):
    """An old database (or a GRP move to Mandatory) may hold a suppression/permit on
    a Mandatory rule; the next scan must keep the finding open."""
    f = _f(MAND, content="void g(int b[static 10]);")
    mem = _mem(tmp_path)
    mem.db.execute("INSERT INTO suppressions (fingerprint, reason, ts) VALUES (?,?,?)",
                   (f.fingerprint, "old reason", time.time()))
    mem.db.execute("INSERT INTO deviations (id, rule_id, scope, justification, ts)"
                   " VALUES ('d1',?,'*','old',?)", (MAND, time.time()))
    mem.db.commit()
    diff = mem.sync_scan([f], ["src/a.c"])
    assert mem.get_finding(f.fingerprint)["status"] == "open"
    assert diff["new"] == [f.fingerprint] and not diff["suppressed"] and not diff["deviated"]


def test_sarif_import_does_not_suppress_mandatory_findings(tmp_path):
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "qe", "rules": [
        {"id": "MISRA-C:2012 Rule 17.6"}]}}, "results": [{
            "ruleId": "MISRA-C:2012 Rule 17.6", "message": {"text": "m"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.c"},
                                                "region": {"startLine": 1}}}],
            "suppressions": [{"kind": "external", "justification": "triaged elsewhere"}]},
            {"ruleId": "MISRA-C:2012 Rule 21.3", "message": {"text": "m"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.c"},
                                                 "region": {"startLine": 2}}}],
             "suppressions": [{"kind": "external", "justification": "triaged elsewhere"}]}]}]}
    (tmp_path / "a.c").write_text("int x;\nint y;\n")
    p = tmp_path / "in.sarif"
    p.write_text(json.dumps(sarif))
    out = LoopEngine(tmp_path).import_sarif(p)
    assert out["suppressions_refused_mandatory"] == 1 and "Mandatory" in out["warning"]
    assert out["suppressions_carried"] == 1
    st = {r["rule_id"]: r["status"] for r in
          LoopEngine(tmp_path).mem.db.execute("SELECT rule_id, status FROM findings")}
    assert st["MISRA-C:2012 Rule 17.6"] == "open"
    assert st["MISRA-C:2012 Rule 21.3"] == "suppressed"


def test_engine_suppress_validates_like_mcp_always_did(tmp_path):
    f = _f()
    eng = LoopEngine(tmp_path)
    eng.mem.sync_scan([f], ["src/a.c"])
    assert "No finding" in eng.suppress("deadbeef", "a long enough reason")["error"]
    assert "too short" in eng.suppress(f.fingerprint, "short")["error"]
    assert "negative" in eng.suppress(f.fingerprint, "a long enough reason", expires_days=-1)["error"]
    assert "past" in eng.suppress(f.fingerprint, "a long enough reason", expires="2001-01-01")["error"]
    assert "YYYY-MM-DD" in eng.suppress(f.fingerprint, "a long enough reason", expires="soon")["error"]
    assert eng.suppress(f.fingerprint, "a long enough reason")["suppressed"] == f.fingerprint


def test_engine_deviate_validates(tmp_path):
    eng = LoopEngine(tmp_path)
    assert "Unknown rule" in eng.deviate("misra", "*", "x" * 30)["error"]
    assert "Unknown rule" in eng.deviate("21", "*", "x" * 30)["error"]
    assert "too short" in eng.deviate("MISRA 21.3", "*", "short")["error"]
    assert "negative" in eng.deviate("MISRA 21.3", "*", "x" * 30, expires_days=-3)["error"]
    assert "past" in eng.deviate("MISRA 21.3", "*", "x" * 30, expires="2001-01-01")["error"]
    assert eng.mem.deviations() == []


def test_expires_date_means_end_of_that_day(tmp_path):
    from datetime import date, timedelta
    eng = LoopEngine(tmp_path)
    tomorrow = (date.today() + timedelta(days=1)).isoformat()
    did = eng.deviate("MISRA 21.3", "*", "x" * 30, expires=tomorrow)["deviation_id"]
    exp = [d for d in eng.mem.deviations() if d["id"] == did][0]["expires"]
    lt = time.localtime(exp)
    assert (lt.tm_hour, lt.tm_min) == (23, 59)
    assert time.strftime("%Y-%m-%d", lt) == tomorrow
    # today's date is still valid: it expires at the end of today, not at midnight
    assert "deviation_id" in eng.deviate("MISRA 21.4", "*", "x" * 30,
                                         expires=date.today().isoformat())


def test_cli_suppress_validates_fingerprint_and_reason(tmp_path, capsys):
    from maishac.cli import main
    f = _f()
    LoopEngine(tmp_path).mem.sync_scan([f], ["src/a.c"])
    with pytest.raises(SystemExit) as e:
        main(["-p", str(tmp_path), "suppress", "deadbeef", "-r", "a long enough reason"])
    assert e.value.code == 1 and "No finding" in capsys.readouterr().err
    with pytest.raises(SystemExit) as e:
        main(["-p", str(tmp_path), "suppress", f.fingerprint, "-r", "short"])
    assert e.value.code == 1 and "too short" in capsys.readouterr().err
    main(["-p", str(tmp_path), "suppress", f.fingerprint, "-r", "a long enough reason"])
    assert LoopEngine(tmp_path).mem.is_suppressed(f.fingerprint)


def test_cli_deviate_partial_rule_fails_with_help(tmp_path, capsys):
    from maishac.cli import main
    for bad in ("misra", "21"):
        with pytest.raises(SystemExit) as e:
            main(["-p", str(tmp_path), "deviate", bad, "-j", "x" * 30])
        assert e.value.code == 1 and "Unknown rule" in capsys.readouterr().err


# ----------------------------------------------- item 12: revocation + audit
def test_unsuppress_reopens_and_is_audited(tmp_path):
    f = _f()
    eng = LoopEngine(tmp_path)
    eng.mem.sync_scan([f], ["src/a.c"])
    eng.suppress(f.fingerprint, "a long enough reason", approver="lead")
    assert eng.mem.get_finding(f.fingerprint)["status"] == "suppressed"
    assert eng.unsuppress(f.fingerprint, "lead", "was wrong")["ok"]
    assert eng.mem.get_finding(f.fingerprint)["status"] == "open"
    assert not eng.mem.is_suppressed(f.fingerprint)
    assert "No suppression" in eng.unsuppress(f.fingerprint)["error"]
    actions = [a["action"] for a in eng.mem.audit_entries()]
    assert actions.index("unsuppress") < actions.index("suppress")   # newest first


def test_revoke_deviation_reopens_findings_it_covered(tmp_path):
    f = _f()
    eng = LoopEngine(tmp_path)
    eng.mem.sync_scan([f], ["src/a.c"])
    did = eng.deviate("MISRA 21.3", "src/*", "x" * 30, "lead")["deviation_id"]
    assert eng.mem.get_finding(f.fingerprint)["status"] == "deviated"
    out = eng.revoke_deviation(did, "lead", "no longer valid")
    assert out["findings_reopened"] == 1
    assert eng.mem.get_finding(f.fingerprint)["status"] == "open"
    assert eng.mem.deviations() == [] and len(eng.mem.deviations(include_revoked=True)) == 1
    assert eng.mem.matching_deviation(REQ, "src/a.c") is None
    assert "already revoked" in eng.revoke_deviation(did)["error"]
    assert "No deviation" in eng.revoke_deviation("nope")["error"]


def test_revoking_one_of_two_overlapping_deviations_keeps_findings_deviated(tmp_path):
    f = _f()
    eng = LoopEngine(tmp_path)
    eng.mem.sync_scan([f], ["src/a.c"])
    d1 = eng.deviate("MISRA 21.3", "src/*", "x" * 30)["deviation_id"]
    eng.deviate("MISRA 21.3", "*", "y" * 30)
    assert eng.revoke_deviation(d1)["findings_reopened"] == 0
    assert eng.mem.get_finding(f.fingerprint)["status"] == "deviated"


def test_remove_recategorization(tmp_path):
    eng = LoopEngine(tmp_path)
    eng.recategorize("MISRA 15.5", "mandatory", "agreed with acquirer", "lead")
    assert eng.mem.is_mandatory(ADV)
    out = eng.remove_recategorization("MISRA 15.5", "lead", "reverted")
    assert out["removed"] == ADV and not eng.mem.is_mandatory(ADV)
    assert "No re-categorization" in eng.remove_recategorization("MISRA 15.5")["error"]


def test_replacing_a_suppression_keeps_the_earlier_reason_in_the_audit_log(tmp_path):
    f = _f()
    eng = LoopEngine(tmp_path)
    eng.mem.sync_scan([f], ["src/a.c"])
    eng.suppress(f.fingerprint, "first reason given here")
    eng.suppress(f.fingerprint, "second reason given here")
    latest = eng.mem.audit_entries(action="suppress")[0]
    assert latest["details"]["replaced"]["reason"] == "first reason given here"
    assert [s["reason"] for s in eng.mem.suppressions()] == ["second reason given here"]


def test_every_signoff_is_audited_with_actor_and_source(tmp_path):
    f = _f()
    eng = LoopEngine(tmp_path)
    eng.mem.sync_scan([f], ["src/a.c"])
    eng.suppress(f.fingerprint, "a long enough reason", approver="lead")
    eng.deviate("MISRA 21.4", "*", "x" * 30, "boss")
    eng.recategorize("MISRA 15.5", "required", "agreed with acquirer", "boss")
    rows = {a["action"]: a for a in eng.mem.audit_entries()}
    assert rows["suppress"]["actor"] == "lead" and rows["suppress"]["source"] == "cli"
    assert rows["add_deviation"]["actor"] == "boss"
    assert rows["recategorize"]["details"]["to_category"] == "required"


def test_pending_fix_approval_is_audited(tmp_path):
    f = _f(sev="critical")
    eng = LoopEngine(tmp_path)
    eng.mem.sync_scan([f], ["src/a.c"])
    eng.mem.sync_scan([], ["src/a.c"], gate=True)
    assert eng.approve(f.fingerprint, "lead")["ok"]
    row = eng.mem.get_finding(f.fingerprint)
    assert row["approved_by"] == "lead" and row["approval_source"] == "cli"
    assert eng.mem.audit_entries(action="approve_finding")[0]["actor"] == "lead"


def test_session_start_and_end_are_audited(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "m.c").write_text("#include <stdint.h>\nint32_t ok(void)\n{\n    return 0;\n}\n")
    eng = LoopEngine(tmp_path)
    sid = eng.begin_session(["src"], {"analyzers": ["native"]})["session_id"]
    assert eng.verify(sid)["state"] == "converged"
    actions = [a["action"] for a in eng.mem.audit_entries()]
    assert "session_start" in actions and "session_end" in actions


def test_audit_cli_lists_entries(tmp_path, capsys):
    from maishac.cli import main
    f = _f()
    LoopEngine(tmp_path).mem.sync_scan([f], ["src/a.c"])
    main(["-p", str(tmp_path), "suppress", f.fingerprint, "-r", "a long enough reason",
          "--approver", "lead"])
    capsys.readouterr()
    main(["-p", str(tmp_path), "audit"])
    out = capsys.readouterr().out
    assert "suppress" in out and "lead" in out
    main(["-p", str(tmp_path), "audit", "--json"])
    assert json.loads(capsys.readouterr().out)[0]["action"] == "suppress"


def test_audit_log_is_never_rewritten_by_the_engine(tmp_path):
    import inspect
    from maishac import memory
    src = inspect.getsource(memory)
    assert "UPDATE audit_log" not in src and "DELETE FROM audit_log" not in src


# ------------------------------------------------------- schema migration v3
V2_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
  fingerprint TEXT PRIMARY KEY,
  rule_id TEXT NOT NULL,
  standard TEXT,
  severity TEXT,
  file TEXT,
  line INTEGER,
  "column" INTEGER,              -- 1-based start column when the analyzer reports one (0/NULL = unknown)
  message TEXT,
  analyzer TEXT,
  line_content TEXT,
  context_symbol TEXT,
  fix_hint TEXT,
  code_flow TEXT,                -- JSON data-flow path from an imported qualified-engine SARIF (null for native findings)
  status TEXT NOT NULL DEFAULT 'open',        -- open|pending_verification|resolved|suppressed|deviated|regressed
  seen_count INTEGER NOT NULL DEFAULT 1,
  regress_count INTEGER NOT NULL DEFAULT 0,
  first_seen REAL NOT NULL,
  last_seen REAL NOT NULL,
  resolved_at REAL,
  semantic_risk INTEGER NOT NULL DEFAULT 0,
  analyzer_cleared_at REAL,      -- when the analyzer stopped flagging it (still unverified)
  verification_method TEXT,      -- analyzer|test|human — how it reached 'resolved'
  approved_by TEXT,
  approved_at REAL
);
CREATE TABLE IF NOT EXISTS fix_attempts (
  id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL,
  session_id TEXT,
  strategy TEXT,
  outcome TEXT,          -- pending|resolved|persisting|regressed|abandoned
  notes TEXT,
  ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS deviations (
  id TEXT PRIMARY KEY,
  rule_id TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT '*',   -- glob over file paths
  justification TEXT NOT NULL,
  approver TEXT,
  expires REAL,
  ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS suppressions (
  fingerprint TEXT PRIMARY KEY,
  reason TEXT NOT NULL,
  ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS recategorizations (
  rule_id TEXT PRIMARY KEY,
  to_category TEXT NOT NULL,          -- mandatory|required|advisory|disapplied (GRP target)
  rationale TEXT NOT NULL,
  approver TEXT,
  ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
  id TEXT PRIMARY KEY,
  topic TEXT,
  content TEXT NOT NULL,
  tags TEXT,
  ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL DEFAULT 'active',   -- active|converged|budget_exhausted|aborted|stalled|awaiting_verification|analysis_incomplete
  iteration INTEGER NOT NULL DEFAULT 0,
  config TEXT,
  history TEXT,          -- JSON list of iteration snapshots (open counts per iteration)
  started REAL NOT NULL,
  updated REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  kind TEXT NOT NULL,              -- scan|verify|import
  paths TEXT,                      -- JSON list of requested paths (import: the SARIF file)
  files_scanned INTEGER NOT NULL DEFAULT 0,
  analyzers_used TEXT,             -- JSON list: analyzers that ran and produced a usable result
  analyzers_failed TEXT,           -- JSON list of {analyzer,status,error,files_not_analyzed}
  toolchain TEXT,                  -- JSON snapshot: toolchain_status() plus analyzer versions
  degraded INTEGER NOT NULL DEFAULT 0,  -- 1 if a tool was missing/deselected or an analyzer failed
  maishac_version TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_attempts_fp ON fix_attempts(fingerprint);
"""


def test_v2_database_migrates_in_place_to_v3(tmp_path):
    root = tmp_path / "old"
    (root / ".maishac").mkdir(parents=True)
    db = sqlite3.connect(root / ".maishac" / "memory.db")
    db.executescript(V2_SCHEMA)
    db.execute("PRAGMA user_version=2")
    db.execute("INSERT INTO suppressions VALUES ('fp1','old reason',1.0)")
    db.execute("INSERT INTO deviations (id, rule_id, scope, justification, approver, expires, ts)"
               " VALUES ('d1','MISRA-C:2012 Rule 21.3','*','kept','lead',NULL,1.0)")
    db.execute("INSERT INTO recategorizations VALUES ('MISRA-C:2012 Rule 15.5','mandatory','r','a',1.0)")
    db.commit()
    assert not db.execute("SELECT 1 FROM sqlite_master WHERE name='audit_log'").fetchone()
    db.close()

    mem = MemoryStore(root)
    assert SCHEMA_VERSION >= 3
    assert mem.db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    cols = lambda t: {r["name"] for r in mem.db.execute(f"PRAGMA table_info({t})")}  # noqa: E731
    assert {"approver", "source", "expires"} <= cols("suppressions")
    assert {"source", "revoked_at", "revoked_by"} <= cols("deviations")
    assert "source" in cols("recategorizations") and "approval_source" in cols("findings")
    # old rows survive; their provenance is unknown, so they are NOT labelled cli
    assert mem.suppressions()[0]["reason"] == "old reason" and mem.suppressions()[0]["source"] == "legacy"
    assert mem.deviations()[0]["justification"] == "kept"
    assert mem.is_suppressed("fp1")
    assert mem.is_mandatory("MISRA-C:2012 Rule 15.5")
    # new tables work, and reopening is a no-op
    mem.audit("note", "x", actor="me")
    mem.db.close()
    assert MemoryStore(root).audit_entries()[0]["target"] == "x"


# ------------------------------------------- item 9: test_command (engine side)
def test_run_tests_uses_argv_not_a_shell(tmp_path):
    marker = tmp_path / "pwned"
    eng = LoopEngine(tmp_path)
    out = eng._run_tests(f'"{sys.executable}" -c "print(1)" ; touch {marker}')
    assert out["ran"] and not marker.exists()      # ';' is just another argument


def test_run_tests_reports_a_missing_executable(tmp_path):
    out = LoopEngine(tmp_path)._run_tests("definitely-not-a-real-binary-xyz --flag")
    assert out["ran"] is False and out["passed"] is False and out["error"]


@pytest.mark.skipif(os.name == "nt", reason="process groups differ on Windows")
def test_timeout_kills_the_whole_process_group(tmp_path):
    pidfile = tmp_path / "child.pid"
    script = tmp_path / "t.sh"
    script.write_text(f"#!/bin/sh\nsleep 60 &\necho $! > {pidfile}\nwait\n")
    script.chmod(0o755)
    out = LoopEngine(tmp_path)._run_tests(str(script), timeout=1)
    assert out["timed_out"] and not out["passed"] and "timed out" in out["error"]
    child = int(pidfile.read_text())
    for _ in range(50):
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        os.kill(child, 9)
        pytest.fail("the grandchild survived the timeout")


def test_test_command_sources_are_human_only(tmp_path, monkeypatch):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "m.c").write_text("int x;\n")
    monkeypatch.delenv("MAISHAC_TEST_COMMAND", raising=False)
    monkeypatch.delenv("MAISHAC_TEST_TIMEOUT", raising=False)
    eng = LoopEngine(tmp_path)
    s = eng.begin_session(["src"], {"analyzers": ["native"]}, force=True)["session_id"]
    cfg = eng.mem.get_session(s)["config"]
    assert cfg["test_command"] is None and cfg["test_timeout"] == 600
    # config.json
    (tmp_path / ".maishac" / "config.json").write_text(
        json.dumps({"test_command": "make check", "test_timeout": 42}))
    s = eng.begin_session(["src"], {"analyzers": ["native"]}, force=True)["session_id"]
    cfg = eng.mem.get_session(s)["config"]
    assert (cfg["test_command"], cfg["test_timeout"]) == ("make check", 42)
    # env beats config.json; an explicit (CLI) value beats env
    monkeypatch.setenv("MAISHAC_TEST_COMMAND", "make env")
    monkeypatch.setenv("MAISHAC_TEST_TIMEOUT", "7")
    s = eng.begin_session(["src"], {"analyzers": ["native"]}, force=True)["session_id"]
    cfg = eng.mem.get_session(s)["config"]
    assert (cfg["test_command"], cfg["test_timeout"]) == ("make env", 7.0)
    s = eng.begin_session(["src"], {"analyzers": ["native"], "test_command": "make cli",
                                    "test_timeout": 9}, force=True)["session_id"]
    cfg = eng.mem.get_session(s)["config"]
    assert (cfg["test_command"], cfg["test_timeout"]) == ("make cli", 9)
    assert "positive" in eng.begin_session(["src"], {"test_timeout": -1}, force=True)["error"]
