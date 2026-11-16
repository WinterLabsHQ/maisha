"""Round 2 follow-ups A1-A4 (verify gate reason, migration re-pointing,
occurrence alignment across analyzers, schema 3/4 waiver provenance)."""

import sqlite3
import time

import pytest

from maishac import report as report_mod
from maishac.engine import LoopEngine
from maishac.memory import MemoryStore
from maishac.model import Finding, assign_occurrences, compute_fingerprint, occurrence_alignment

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


# ------------------------------------------------------------------ A2
RULE = "MISRA-C:2012 Rule 21.3"
CONTENT = "p = malloc(1);"
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


def _old_db(root, rows):
    (root / ".maishac").mkdir(parents=True)
    db = sqlite3.connect(root / ".maishac" / "memory.db")
    db.executescript(OLD_DDL)
    for fp, file, status in rows:
        db.execute("INSERT INTO findings (fingerprint, rule_id, file, line, line_content,"
                   " context_symbol, first_seen, last_seen, severity, analyzer, status)"
                   " VALUES (?,?,?,3,?,'f',1,1,'critical','native',?)",
                   (fp, RULE, file, CONTENT, status))
    db.commit()
    return db


def test_a2_dropped_duplicate_hands_its_suppression_attempts_and_approval_to_the_survivor(tmp_path):
    root = tmp_path / "win"
    old = compute_fingerprint(RULE, "src\\a.c", CONTENT, "f")
    live = compute_fingerprint(RULE, "src/a.c", CONTENT, "f")
    db = _old_db(root, [(old, "src\\a.c", "resolved"), (live, "src/a.c", "open")])
    db.execute("INSERT INTO suppressions VALUES (?, 'verified false positive', 1)", (old,))
    db.execute("INSERT INTO fix_attempts VALUES ('a1', ?, 's', 'try', 'persisting', '', 1)", (old,))
    db.execute("INSERT INTO fix_attempts VALUES ('a2', ?, 's', 'try2', 'pending', '', 2)", (live,))
    db.execute("ALTER TABLE findings ADD COLUMN approved_by TEXT")
    db.execute("ALTER TABLE findings ADD COLUMN approved_at REAL")
    db.execute("ALTER TABLE findings ADD COLUMN verification_method TEXT")
    db.execute("UPDATE findings SET approved_by='lead', approved_at=5, "
               "verification_method='human' WHERE fingerprint=?", (old,))
    db.commit()
    db.close()
    mem = MemoryStore(root)
    assert [r["fingerprint"] for r in mem.db.execute("SELECT * FROM findings")] == [live]
    assert mem.is_suppressed(live) and not mem.is_suppressed(old)
    assert {a["id"] for a in mem.attempts_for(live)} == {"a1", "a2"}
    assert mem.db.execute("SELECT COUNT(*) FROM fix_attempts WHERE fingerprint=?",
                          (old,)).fetchone()[0] == 0
    row = mem.get_finding(live)
    assert row["approved_by"] == "lead" and row["approval_source"] == "legacy"
    entry = [e for e in mem.audit_entries() if e["action"] == "path_migration_dropped_duplicate"]
    assert entry and entry[0]["details"]["from_fingerprint"] == old
    assert set(entry[0]["details"]["moved"]) >= {"fix_attempts", "suppressions", "approval"}


def test_a2_the_stronger_suppression_wins_when_both_rows_have_one(tmp_path):
    root = tmp_path / "win"
    old = compute_fingerprint(RULE, "src\\a.c", CONTENT, "f")
    live = compute_fingerprint(RULE, "src/a.c", CONTENT, "f")
    db = _old_db(root, [(old, "src\\a.c", "open"), (live, "src/a.c", "open")])
    db.execute("INSERT INTO suppressions VALUES (?, 'permanent reason', 1)", (old,))
    db.execute("INSERT INTO suppressions VALUES (?, 'short reason', 1)", (live,))
    db.execute("ALTER TABLE suppressions ADD COLUMN expires REAL")
    db.execute("UPDATE suppressions SET expires=99999999999 WHERE fingerprint=?", (live,))
    db.commit()
    db.close()
    mem = MemoryStore(root)
    rows = mem.db.execute("SELECT fingerprint, reason FROM suppressions").fetchall()
    assert [(r["fingerprint"], r["reason"]) for r in rows] == [(live, "permanent reason")]


def test_a2_renamed_row_keeps_a_suppression_even_when_the_new_key_is_taken(tmp_path):
    root = tmp_path / "win"
    old = compute_fingerprint(RULE, "src\\a.c", CONTENT, "f")
    new = compute_fingerprint(RULE, "src/a.c", CONTENT, "f")
    db = _old_db(root, [(old, "src\\a.c", "open")])
    db.execute("INSERT INTO suppressions VALUES (?, 'orphan from a rescan', 1)", (new,))
    db.execute("INSERT INTO suppressions VALUES (?, 'the real one', 1)", (old,))
    db.commit()
    db.close()
    mem = MemoryStore(root)
    assert mem.db.execute("SELECT COUNT(*) FROM suppressions").fetchone()[0] == 1
    assert mem.is_suppressed(new)


def test_a2_occurrence_recovery_has_no_fixed_cap(tmp_path):
    root = tmp_path / "win"
    n = 100                               # beyond the old cap of 64 identical siblings
    old_fps = [compute_fingerprint(RULE, "src\\a.c", CONTENT, "f", i) for i in range(n)]
    db = _old_db(root, [(fp, "src\\a.c", "open") for fp in old_fps])
    db.commit()
    db.close()
    mem = MemoryStore(root)
    got = {r["fingerprint"] for r in mem.db.execute("SELECT * FROM findings")}
    assert got == {compute_fingerprint(RULE, "src/a.c", CONTENT, "f", i) for i in range(n)}


def test_a2_migration_scales_linearly_in_rows(tmp_path):
    root = tmp_path / "win"
    n = 2000
    rows = [(compute_fingerprint(RULE, f"src\\f{i}.c", CONTENT, "f"), f"src\\f{i}.c", "open")
            for i in range(n)]
    _old_db(root, rows).close()
    t0 = time.time()
    mem = MemoryStore(root)
    assert time.time() - t0 < 30
    assert mem.db.execute("SELECT COUNT(*) FROM findings WHERE file LIKE '%\\%'").fetchone()[0] == 0


# ------------------------------------------------------------------ A3
def _occ(line, analyzer, content="p = malloc(1);"):
    return Finding(rule_id=RULE, standard="MISRA-C:2012", severity="critical", file="a.c",
                   line=line, message="m", analyzer=analyzer, line_content=content,
                   context_symbol="f")


def _fps(findings, aligned):
    return [f.fingerprint for f in assign_occurrences(findings, aligned)]


def test_a3_tools_disagreeing_by_one_line_still_share_identities():
    # native: lines 5 and 9; cppcheck points at the line after each (6 and 10)
    native, cpp = [_occ(5, "native"), _occ(9, "native")], [_occ(6, "cppcheck"), _occ(10, "cppcheck")]
    aligned = occurrence_alignment([native, cpp])
    n, c = _fps(native, aligned), _fps(cpp, aligned)
    assert n == c and n[0] != n[1]


def test_a3_one_tool_reports_only_the_second_violation_and_is_off_by_one():
    native, cpp = [_occ(5, "native"), _occ(9, "native")], [_occ(10, "cppcheck")]
    aligned = occurrence_alignment([native, cpp])
    n, c = _fps(native, aligned), _fps(cpp, aligned)
    assert c[0] == n[1] != n[0]


def test_a3_truly_ambiguous_reports_keep_per_analyzer_numbering():
    # native reports two neighbouring lines, cppcheck one between/next to them
    native, cpp = [_occ(5, "native"), _occ(6, "native")], [_occ(7, "cppcheck")]
    aligned = occurrence_alignment([native, cpp])
    assert aligned == {}
    assert _fps(cpp, aligned)[0] == _fps(native, aligned)[0]   # documented fallback


def test_a3_agreeing_tools_are_unchanged():
    native, cpp = [_occ(4, "native"), _occ(6, "native")], [_occ(6, "cppcheck")]
    aligned = occurrence_alignment([native, cpp])
    assert _fps(cpp, aligned)[0] == _fps(native, aligned)[1]


# ------------------------------------------------------------------ A4
def _v_db(root, version):
    """A database as written by schema 3/4 code: source columns exist, 'cli' labels on
    everything, but MCP tools could write them."""
    (root / ".maishac").mkdir(parents=True)
    db = sqlite3.connect(root / ".maishac" / "memory.db")
    db.executescript(OLD_DDL)
    for stmt in ("ALTER TABLE suppressions ADD COLUMN approver TEXT",
                 "ALTER TABLE suppressions ADD COLUMN source TEXT NOT NULL DEFAULT 'cli'",
                 "ALTER TABLE suppressions ADD COLUMN expires REAL",
                 "ALTER TABLE deviations ADD COLUMN source TEXT NOT NULL DEFAULT 'cli'",
                 "ALTER TABLE deviations ADD COLUMN revoked_at REAL",
                 "ALTER TABLE deviations ADD COLUMN revoked_by TEXT",
                 "ALTER TABLE recategorizations ADD COLUMN source TEXT NOT NULL DEFAULT 'cli'",
                 "ALTER TABLE findings ADD COLUMN approved_by TEXT",
                 "ALTER TABLE findings ADD COLUMN approved_at REAL",
                 "ALTER TABLE findings ADD COLUMN verification_method TEXT",
                 "ALTER TABLE findings ADD COLUMN approval_source TEXT",
                 """CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
                    actor TEXT, source TEXT NOT NULL, action TEXT NOT NULL, target TEXT,
                    details TEXT)"""):
        db.execute(stmt)
    db.execute(f"PRAGMA user_version={version}")
    return db


@pytest.mark.parametrize("version", [3, 4])
def test_a4_unprovable_cli_labels_become_legacy_and_proven_ones_stay(tmp_path, version):
    root = tmp_path / "v"
    db = _v_db(root, version)
    ins = ("INSERT INTO findings (fingerprint, rule_id, file, line, line_content, context_symbol,"
           " first_seen, last_seen, severity, analyzer, status, approved_by, approval_source)"
           " VALUES (?,?,?,3,'x','f',1,1,'critical','native','resolved','someone','cli')")
    db.execute(ins, ("fp-mcp", RULE, "a.c"))
    db.execute(ins, ("fp-human", RULE, "a.c"))
    db.execute("INSERT INTO deviations (id, rule_id, scope, justification, approver, ts, source)"
               " VALUES ('d-mcp', ?, '*', 'agent wrote this', 'agent', 1, 'cli')", (RULE,))
    db.execute("INSERT INTO deviations (id, rule_id, scope, justification, approver, ts, source)"
               " VALUES ('d-human', ?, '*', 'a person wrote this', 'lead', 1, 'cli')", (RULE,))
    db.execute("INSERT INTO suppressions (fingerprint, reason, ts, source) VALUES ('fp-mcp','r',1,'cli')")
    db.execute("INSERT INTO suppressions (fingerprint, reason, ts, source) VALUES ('fp-human','r',1,'cli')")
    db.execute("INSERT INTO recategorizations VALUES ('MISRA-C:2012 Rule 15.5','required','r','a',1,'cli')")
    audit = "INSERT INTO audit_log (ts, actor, source, action, target) VALUES (1,'x',?,?,?)"
    db.execute(audit, ("mcp", "add_deviation", "d-mcp"))
    db.execute(audit, ("cli", "add_deviation", "d-human"))
    db.execute(audit, ("mcp", "suppress", "fp-mcp"))
    db.execute(audit, ("cli", "suppress", "fp-human"))
    db.execute(audit, ("mcp", "approve_finding", "fp-mcp"))
    db.execute(audit, ("cli", "approve_finding", "fp-human"))
    db.commit()
    db.close()
    mem = MemoryStore(root)
    assert {d["id"]: d["source"] for d in mem.deviations()} == {"d-mcp": "legacy", "d-human": "cli"}
    assert {s["fingerprint"]: s["source"] for s in mem.suppressions()} == {
        "fp-mcp": "legacy", "fp-human": "cli"}
    assert mem.get_finding("fp-mcp")["approval_source"] == "legacy"
    assert mem.get_finding("fp-human")["approval_source"] == "cli"
    # no audit entry at all: cannot be proven human
    assert mem.recategorizations()["MISRA-C:2012 Rule 15.5"]["source"] == "legacy"
    assert any(e["action"] == "provenance_relabel" for e in mem.audit_entries())
    mem.close()
    again = MemoryStore(root)      # idempotent: version is now 5, nothing runs twice
    assert sum(e["action"] == "provenance_relabel" for e in again.audit_entries()) == 1
    assert "ORIGIN UNKNOWN" in report_mod.markdown_report(again)
