"""Finding lifecycle (items 13-15), SARIF path handling (17), fingerprint
identity (18) and the schema v4 migration."""

import json
import sqlite3

from maishac import report as report_mod
from maishac.engine import LoopEngine
from maishac.memory import SCHEMA_VERSION, MemoryStore
from maishac.model import Finding, assign_occurrences, compute_fingerprint, relpath

CLEAN = '#include <stdint.h>\nint32_t ok(void)\n{\n    return 0;\n}\n'
ONE_MALLOC = 'void *f(void)\n{\n    return malloc(4);\n}\n'
TWO_MALLOC = ('void f(void)\n{\n    char *a;\n    a = malloc(4);\n    free(a);\n'
              '    a = malloc(4);\n    free(a);\n}\n')
ONE_OF_TWO = 'void f(void)\n{\n    char *a;\n    a = malloc(4);\n    free(a);\n}\n'


def _fnd(line=3, file="a.c", content="p = malloc(10);", rule="MISRA-C:2012 Rule 21.3"):
    return Finding(rule_id=rule, standard="MISRA-C:2012", severity="critical", file=file,
                   line=line, message="m", analyzer="native", line_content=content,
                   context_symbol="f")


def _proj(tmp_path, body, name="m.c"):
    proj = tmp_path / "p"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / name).write_text(body)
    return proj


def _status(mem, fp):
    return mem.get_finding(fp)["status"]


# ------------------------------------------------------------ 13: lifecycle
def test_regressed_finding_that_is_still_present_stays_regressed(tmp_path):
    mem = MemoryStore(tmp_path)
    f = _fnd()
    mem.sync_scan([f], ["a.c"])
    mem.sync_scan([], ["a.c"])                       # resolved by the analyzer
    d = mem.sync_scan([f], ["a.c"])                  # comes back
    assert d["regressed"] == [f.fingerprint]
    mem.sync_scan([f], ["a.c"])                      # still there on the next scan
    row = mem.get_finding(f.fingerprint)
    assert row["status"] == "regressed" and row["regress_count"] == 1


def test_pending_finding_that_reappears_is_a_regression(tmp_path):
    mem = MemoryStore(tmp_path)
    f = _fnd()
    mem.sync_scan([f], ["a.c"])
    mem.sync_scan([], ["a.c"], gate=True)
    assert _status(mem, f.fingerprint) == "pending_verification"
    assert mem.get_finding(f.fingerprint)["analyzer_cleared_at"] is not None
    d = mem.sync_scan([f], ["a.c"], gate=True)
    row = mem.get_finding(f.fingerprint)
    assert d["regressed"] == [f.fingerprint]
    assert row["status"] == "regressed" and row["regress_count"] == 1
    assert row["analyzer_cleared_at"] is None
    # a second fix/reappear cycle keeps counting, so the oscillation freeze can trigger
    mem.sync_scan([], ["a.c"], gate=True)
    mem.sync_scan([f], ["a.c"], gate=True)
    assert mem.get_finding(f.fingerprint)["regress_count"] == 2


def test_regression_marks_fix_attempts_regressed_and_remembers_the_strategy(tmp_path):
    mem = MemoryStore(tmp_path)
    f = _fnd()
    mem.sync_scan([f], ["a.c"])
    mem.record_fix_attempt(f.fingerprint, "s1", "wrap in helper")
    mem.sync_scan([], ["a.c"], gate=True)            # fix looks good, pending
    mem.sync_scan([f], ["a.c"], gate=True)           # it did not hold
    assert [a["outcome"] for a in mem.attempts_for(f.fingerprint)] == ["regressed"]
    assert mem.failed_strategies(f.fingerprint) == ["wrap in helper"]


def test_ended_session_abandons_its_undecided_attempts(tmp_path):
    proj = _proj(tmp_path, ONE_MALLOC)
    eng = LoopEngine(proj)
    sid = eng.begin_session(["src"], {"analyzers": ["native"]})["session_id"]
    fp = eng.mem.open_findings()[0]["fingerprint"]
    eng.record_attempt(sid, fp, "try A")
    out = eng.abort_session(sid, "changed plans")
    assert out["attempts_abandoned"] == 1
    assert eng.mem.attempts_for(fp)[0]["outcome"] == "abandoned"
    assert eng.mem.failed_strategies(fp) == ["try A"]


# --------------------------------------------------------------- 14: stale
def test_finding_in_a_deleted_file_is_closed_as_stale(tmp_path):
    proj = _proj(tmp_path, ONE_MALLOC, "gone.c")
    (proj / "src" / "keep.c").write_text(ONE_MALLOC)
    eng = LoopEngine(proj)
    eng.scan(["src"], ["native"])
    fp = next(f["fingerprint"] for f in eng.mem.open_findings() if f["file"] == "src/gone.c")
    (proj / "src" / "gone.c").unlink()
    out = eng.scan(["src"], ["native"])
    assert out["diff"]["stale"] >= 1
    row = eng.mem.get_finding(fp)
    assert row["status"] == "resolved" and row["verification_method"] == "file_removed"
    assert all(f["file"] != "src/gone.c" for f in eng.mem.open_findings())
    assert any(f["file"] == "src/keep.c" for f in eng.mem.open_findings())


# ------------------------------------------------------- 15: imported findings
def _sarif(results, tool="ExternalQAC", artifacts=None):
    run = {"tool": {"driver": {"name": tool}}, "results": results}
    if artifacts:
        run["artifacts"] = [{"location": {"uri": u}} for u in artifacts]
    return {"version": "2.1.0", "runs": [run]}


def _res(uri, line, rule="misra-c2012-21.3", text="p = malloc(10);"):
    return {"ruleId": rule, "level": "warning", "message": {"text": "m"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": line, "snippet": {"text": text}}}}]}


def _write(proj, name, data):
    (proj / name).write_text(json.dumps(data))
    return str(proj / name)


def test_reimport_resolves_findings_absent_from_the_new_run(tmp_path):
    proj = _proj(tmp_path, CLEAN)
    eng = LoopEngine(proj)
    eng.import_sarif(_write(proj, "1.sarif", _sarif([
        _res("src/a.c", 5), _res("src/a.c", 9, text="q = malloc(20);"),
        _res("src/other.c", 2)])))
    assert len(eng.mem.open_findings()) == 3
    # newer run from the same tool: one finding in a.c fixed, other.c not mentioned
    out = eng.import_sarif(_write(proj, "2.sarif", _sarif(
        [_res("src/a.c", 9, text="q = malloc(20);")], artifacts=["src/a.c"])))
    assert out["diff"]["pending"] == 1                      # gated by default
    pend = eng.mem.pending_findings()
    assert [f["line_content"] for f in pend] == ["p = malloc(10);"]
    assert {f["file"] for f in eng.mem.open_findings()} == {"src/a.c", "src/other.c"}
    # imported findings can be approved like any other pending one
    assert eng.approve(pend[0]["fingerprint"], "lead@example.com").get("ok")
    assert _status(eng.mem, pend[0]["fingerprint"]) == "resolved"


def test_reimport_without_gate_resolves_directly_and_spares_other_tools(tmp_path):
    proj = _proj(tmp_path, CLEAN)
    eng = LoopEngine(proj)
    eng.import_sarif(_write(proj, "a.sarif", _sarif([_res("src/a.c", 5)], tool="ToolA")))
    eng.import_sarif(_write(proj, "b.sarif", _sarif(
        [_res("src/a.c", 6, text="z = malloc(1);")], tool="ToolB")))
    out = eng.import_sarif(_write(proj, "a2.sarif", _sarif([], tool="ToolA",
                                                           artifacts=["src/a.c"])), gate=False)
    assert out["diff"]["resolved"] == 1
    left = eng.mem.open_findings()
    assert [f["analyzer"] for f in left] == ["sarif:toolb"]


def test_imported_findings_are_counted_separately_and_do_not_block_convergence(tmp_path):
    proj = _proj(tmp_path, CLEAN)
    eng = LoopEngine(proj)
    eng.import_sarif(_write(proj, "x.sarif", _sarif([_res("src/m.c", 3)])))
    sid = eng.begin_session(["src"], {"analyzers": ["native"]})["session_id"]
    out = eng.verify(sid)
    assert out["state"] == "converged"
    assert out["open_imported"] == 1 and out["open_now"] == 0
    assert "imported" in out["reason"] and "open_imported" in out["reason"]
    assert len(eng.mem.open_findings()) == 1               # still on the books


# ----------------------------------------------------------- 17: path handling
def test_import_sarif_path_is_resolved_against_the_project_root(tmp_path, monkeypatch):
    proj = _proj(tmp_path, CLEAN)
    _write(proj, "ext.sarif", _sarif([_res("src/m.c", 3)]))
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    assert LoopEngine(proj).import_sarif("ext.sarif")["imported"] == 1


def test_import_sarif_falls_back_to_the_current_directory(tmp_path, monkeypatch):
    proj = _proj(tmp_path, CLEAN)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _write(elsewhere, "cwd.sarif", _sarif([_res("src/m.c", 3)]))
    monkeypatch.chdir(elsewhere)
    assert LoopEngine(proj).import_sarif("cwd.sarif")["imported"] == 1


def test_sarif_uris_normalize_to_one_project_relative_posix_path(tmp_path):
    root = tmp_path / "proj"
    (root / "src").mkdir(parents=True)
    forms = [
        "src/my file.c", "src/my%20file.c", "./src/my file.c", "src\\my file.c",
        f"file://{root}/src/my%20file.c", f"{root}/src/my file.c",
        f"file:{root}/src/my%20file.c", "src/sub/../my file.c",
    ]
    got = []
    for uri in forms:
        (f,) = report_mod.parse_sarif(_sarif([_res(uri, 4)]), root.resolve())
        got.append((f.file, f.fingerprint))
    assert len(set(got)) == 1, got
    assert got[0][0] == "src/my file.c"
    assert got[0][1] == compute_fingerprint("MISRA-C:2012 Rule 21.3", "src/my file.c",
                                            "p = malloc(10);")


def test_absolute_uri_outside_the_project_stays_absolute_posix(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    (f,) = report_mod.parse_sarif(_sarif([_res("file:///opt/other/x.c", 1)]), root)
    assert f.file == "/opt/other/x.c"


# ------------------------------------------------------- 18: fingerprint identity
def test_occurrence_zero_fingerprint_is_unchanged():
    """Pinned: fingerprints already in people's databases must stay valid."""
    assert compute_fingerprint("MISRA-C:2012 Rule 21.3", "src/a.c", "p = malloc(10);",
                               "f") == "a1af5baa3c762bf6"
    assert compute_fingerprint("MISRA-C:2012 Rule 21.3", "src/a.c", "p = malloc(10);",
                               "f", 0) == "a1af5baa3c762bf6"
    assert compute_fingerprint("MISRA-C:2012 Rule 21.3", "src/a.c", "p = malloc(10);",
                               "f", 1) != "a1af5baa3c762bf6"


def test_finding_fingerprints_ignore_path_separator_style():
    a = _fnd(file="src/a.c")
    b = _fnd(file="src\\a.c")
    assert b.file == "src/a.c" and a.fingerprint == b.fingerprint


def test_relpath_is_forward_slash(tmp_path):
    (tmp_path / "x" / "y").mkdir(parents=True)
    assert relpath(tmp_path / "x" / "y" / "z.c", tmp_path) == "x/y/z.c"


def test_assign_occurrences_keeps_first_and_separates_repeats():
    a, b, c = _fnd(line=4), _fnd(line=6), _fnd(line=6)
    base = a.fingerprint
    out = assign_occurrences([b, a, c])            # input order does not matter
    assert out == [b, a]                           # same-line repeat is still one finding
    assert a.fingerprint == base and b.fingerprint != base


def test_two_identical_violations_in_a_function_are_two_findings(tmp_path):
    proj = _proj(tmp_path, TWO_MALLOC)
    eng = LoopEngine(proj)
    eng.scan(["src"], ["native"])
    def mallocs():
        return [f for f in eng.mem.open_findings()
                if "21.3" in f["rule_id"] and "malloc" in f["line_content"]]

    hits = mallocs()
    assert len(hits) == 2 and hits[0]["fingerprint"] != hits[1]["fingerprint"]
    # fixing one leaves exactly one open
    (proj / "src" / "m.c").write_text(ONE_OF_TWO)
    eng.scan(["src"], ["native"])
    assert len(mallocs()) == 1


# --------------------------------------------------------------- migration
V3_SCHEMA = """
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
  approved_at REAL,
  approval_source TEXT           -- cli|mcp: which surface recorded the human approval
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
  ts REAL NOT NULL,
  source TEXT NOT NULL DEFAULT 'cli',
  revoked_at REAL,                    -- set by revoke_deviation; a revoked permit never applies
  revoked_by TEXT
);
CREATE TABLE IF NOT EXISTS suppressions (
  fingerprint TEXT PRIMARY KEY,
  reason TEXT NOT NULL,
  ts REAL NOT NULL,
  approver TEXT,                      -- who stood behind the suppression
  source TEXT NOT NULL DEFAULT 'cli', -- cli|mcp: which surface recorded it
  expires REAL                        -- optional; an expired suppression no longer applies
);
CREATE TABLE IF NOT EXISTS recategorizations (
  rule_id TEXT PRIMARY KEY,
  to_category TEXT NOT NULL,          -- mandatory|required|advisory|disapplied (GRP target)
  rationale TEXT NOT NULL,
  approver TEXT,
  ts REAL NOT NULL,
  source TEXT NOT NULL DEFAULT 'cli'
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
-- Append-only: rows are only ever inserted, never updated or deleted.
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  actor TEXT,
  source TEXT NOT NULL,            -- cli|mcp|engine
  action TEXT NOT NULL,
  target TEXT,
  details TEXT                     -- JSON
);
-- Changes an MCP agent asked for; they take effect only when a human accepts them.
CREATE TABLE IF NOT EXISTS proposals (
  id TEXT PRIMARY KEY,
  ts REAL NOT NULL,
  kind TEXT NOT NULL,              -- approve|deviate|suppress|recategorize
  payload TEXT NOT NULL,           -- JSON arguments, already validated
  summary TEXT,
  source TEXT NOT NULL DEFAULT 'mcp',
  status TEXT NOT NULL DEFAULT 'pending_human',   -- pending_human|accepted|rejected
  decided_by TEXT,
  decided_at REAL,
  decision_note TEXT,
  result TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_attempts_fp ON fix_attempts(fingerprint);
"""


def test_v3_database_migrates_in_place_to_v4(tmp_path):
    root = tmp_path / "old"
    (root / ".maishac").mkdir(parents=True)
    db = sqlite3.connect(root / ".maishac" / "memory.db")
    db.executescript(V3_SCHEMA)
    db.execute("PRAGMA user_version=3")
    db.execute("INSERT INTO sessions (id, status, config, history, started, updated)"
               " VALUES ('s1','converged','{}','[]',1.0,2.0)")
    db.commit()
    cols = {r[1] for r in db.execute("PRAGMA table_info(sessions)")}
    assert "end_reason" not in cols
    db.close()

    mem = MemoryStore(root)
    assert SCHEMA_VERSION >= 4
    assert mem.db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    cols = {r["name"] for r in mem.db.execute("PRAGMA table_info(sessions)")}
    assert {"ended", "end_reason"} <= cols
    old = mem.get_session("s1")
    assert old["status"] == "converged" and old["end_reason"] is None
    # and the new lifecycle works on the migrated file
    sid, _ = mem.create_session_if_free({"paths": ["."]})
    mem.update_session(sid, status="aborted", end_reason="test")
    assert mem.get_session(sid)["ended"] is not None
