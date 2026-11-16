"""Phase 2: reports must not overstate compliance (scan log, "Not checked",
expired permits, GEP accuracy, matrix, SARIF export)."""

import json
import shutil
import sqlite3
import time
from pathlib import Path

import maishac
from maishac import report as report_mod
from maishac.coverage import analyzers_for
from maishac.engine import LoopEngine
from maishac.memory import SCHEMA_VERSION, MemoryStore
from maishac.model import Finding
from maishac.rules import REGISTRY

FIXTURE = Path(__file__).resolve().parent.parent / "examples" / "bad.c"
CLEAN = "int main(void)\n{\n    return 0;\n}\n"
STD = "MISRA-C:2012"


def _project(tmp_path, source=None, analyzers=("native",)):
    proj = tmp_path / "p"
    (proj / "src").mkdir(parents=True)
    if source is None:
        shutil.copy(FIXTURE, proj / "src" / "bad.c")
    else:
        (proj / "src" / "a.c").write_text(source)
    eng = LoopEngine(proj)
    if analyzers:
        eng.scan(["src"], list(analyzers))
    return eng


def _row(summary, gid):
    return next(g for g in summary["guidelines"] if g["guideline"] == gid)


def _only_non_native(prefix="cppcheck"):
    """A MISRA guideline only a non-native analyzer maps a check onto."""
    for gid in REGISTRY.all_ids(STD):
        a = [m.split(" ")[0] for m in analyzers_for(gid)]
        if a and "native" not in a and prefix in a:
            return gid
    raise AssertionError("no cppcheck-only guideline in the knowledge base")


def _native_only():
    """A non-mandatory guideline only the native analyzer checks (mandatory ones
    cannot take deviation permits)."""
    return next(g for g in REGISTRY.all_ids(STD) if analyzers_for(g) == ["native"]
                and REGISTRY.get(g)["category"] != "mandatory")


def _finding(rule="MISRA-C:2012 Rule 21.3", file="src/a.c", line=3, column=0,
             content="p = malloc(1);"):
    return Finding(rule_id=rule, standard=STD, severity="major", file=file, line=line,
                   column=column, message="m", line_content=content)


# ----------------------------------------------------------------- item 3: scans
def test_scan_is_recorded_with_toolchain_snapshot(tmp_path):
    eng = _project(tmp_path, CLEAN)
    last = eng.mem.last_scan()
    assert last["kind"] == "scan" and last["paths"] == ["src"]
    assert last["files_scanned"] == 1 and last["analyzers_used"] == ["native"]
    assert last["analyzers_failed"] == []
    assert last["maishac_version"] == maishac.__version__
    assert last["toolchain"]["versions"]["native"].startswith("maishac ")
    # the degraded flag is stored at scan time, not recomputed at report time
    assert last["degraded"] == eng.scan(["src"], ["native"])["toolchain"]["degraded"]


def test_verify_and_import_are_recorded(tmp_path):
    eng = _project(tmp_path, CLEAN, analyzers=None)
    sid = eng.begin_session(["src"], {"analyzers": ["native"]})["session_id"]
    eng.verify(sid)
    assert [s["kind"] for s in eng.mem.scans()][:2] == ["verify", "scan"]
    sf = tmp_path / "x.sarif"
    sf.write_text(json.dumps({"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Ext"}}, "results": []}]}))
    eng.import_sarif(str(sf))
    assert eng.mem.last_scan(("import",))["paths"] == [str(sf)]
    # an import is not an analysis run: it must not become "the last scan"
    assert eng.mem.last_scan()["kind"] == "verify"


def test_failed_analyzer_is_stored_and_degrades_the_scan(tmp_path, monkeypatch):
    eng = _project(tmp_path, CLEAN, analyzers=None)
    from maishac.analyzers import compiler as comp
    from maishac.analyzers.base import AnalysisResult

    def boom(self, *a, **k):
        return AnalysisResult(analyzer=self.name, status="failed", error="boom")

    monkeypatch.setattr(comp.CompilerAnalyzer, "run", boom)
    monkeypatch.setattr(comp.CompilerAnalyzer, "available", lambda self: True)
    eng.scan(["src"], ["native", "compiler"])
    last = eng.mem.last_scan()
    assert last["degraded"] is True
    assert [e["analyzer"] for e in last["analyzers_failed"]] == ["compiler"]
    assert last["analyzers_used"] == ["native"]
    info = report_mod.last_scan_info(eng.mem)
    assert info["analyzers_failed"] == ["compiler"] and info["checked_analyzers"] == ["native"]


# ------------------------------------------------- migration from the old schema
# Verbatim copy of maishac.memory._SCHEMA as of the commit before the scans table.
OLD_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
  fingerprint TEXT PRIMARY KEY,
  rule_id TEXT NOT NULL,
  standard TEXT,
  severity TEXT,
  file TEXT,
  line INTEGER,
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
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_attempts_fp ON fix_attempts(fingerprint);
"""


def test_old_database_migrates_in_place(tmp_path):
    root = tmp_path / "old"
    (root / ".maishac").mkdir(parents=True)
    db = sqlite3.connect(root / ".maishac" / "memory.db")
    db.executescript(OLD_SCHEMA)
    db.execute("INSERT INTO findings (fingerprint, rule_id, standard, severity, file, line,"
               " message, analyzer, status, first_seen, last_seen)"
               " VALUES ('fp1','MISRA-C:2012 Rule 21.3','MISRA-C:2012','major','src/a.c',3,"
               "'m','native','open',1.0,1.0)")
    db.commit()
    assert db.execute("PRAGMA user_version").fetchone()[0] == 0
    assert not db.execute("SELECT 1 FROM sqlite_master WHERE name='scans'").fetchone()
    assert "column" not in {r[1] for r in db.execute("PRAGMA table_info(findings)")}
    db.close()

    mem = MemoryStore(root)
    assert mem.db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    assert "column" in {r["name"] for r in mem.db.execute("PRAGMA table_info(findings)")}
    assert mem.last_scan() is None and mem.scans() == []
    old = mem.get_finding("fp1")
    assert old["status"] == "open" and old["column"] is None
    # new writes work on the migrated database, and reopening is a no-op
    mem.sync_scan([_finding(column=7)], ["src/a.c"])
    assert mem.get_finding(_finding().fingerprint)["column"] == 7
    mem.record_scan("scan", ["src"], 1, ["native"], [], {}, False)
    mem.db.close()
    again = MemoryStore(root)
    assert again.last_scan()["analyzers_used"] == ["native"]
    assert again.get_finding("fp1") is not None


# ------------------------------------------- item 4: Not checked / honest verdicts
def test_no_scan_recorded_is_not_assessed(tmp_path):
    eng = _project(tmp_path, CLEAN, analyzers=None)
    s = report_mod.misra_compliance_summary(eng.mem)
    assert s["verdict"].startswith("NOT ASSESSED")
    assert s["counts"]["compliant"] == 0
    assert s["counts"]["not_checked"] == s["carried"]
    assert all(g["status"] == "Not checked" for g in s["guidelines"])
    assert "No scan recorded" in report_mod.misra_compliance_markdown(eng.mem)


def test_unchecked_guidelines_are_never_compliant(tmp_path):
    eng = _project(tmp_path, CLEAN)
    s = report_mod.misra_compliance_summary(eng.mem)
    assert _row(s, "MISRA-C:2012 Dir 4.12")["status"] == "Not checked"   # reference-only
    assert "reference-only" in _row(s, "MISRA-C:2012 Dir 4.12")["not_checked_reason"]
    assert _row(s, _native_only())["status"] == "Compliant"              # native checked it, clean
    # narrowed to native: a cppcheck-only guideline was not examined, whether
    # or not cppcheck is installed on this machine
    assert _row(s, _only_non_native())["status"] == "Not checked"
    assert s["counts"]["not_checked"] > 0
    assert s["verdict"].startswith("NO VIOLATIONS FOUND IN CHECKED GUIDELINES (")
    assert "unchecked" in s["verdict"]
    assert s["verdict"] not in ("COMPLIANT", "COMPLIANT WITH DEVIATIONS")
    md = report_mod.misra_compliance_markdown(eng.mem)
    assert "Not checked" in md and "Last scan" in md


def test_failed_analyzer_makes_its_guidelines_not_checked(tmp_path):
    eng = _project(tmp_path, CLEAN)
    gid = _only_non_native()
    # pretend cppcheck ran but failed in the latest scan
    eng.mem.record_scan("scan", ["src"], 1, ["native", "cppcheck"],
                        [{"analyzer": "cppcheck", "status": "failed", "error": "boom",
                          "files_not_analyzed": 1}], {}, True)
    s = report_mod.misra_compliance_summary(eng.mem)
    assert _row(s, gid)["status"] == "Not checked"
    assert "(cppcheck)" in _row(s, gid)["not_checked_reason"]
    assert "last scan degraded or incomplete" in s["verdict"]
    # ...and when cppcheck did succeed, the same guideline counts as checked
    eng.mem.record_scan("scan", ["src"], 1, ["native", "cppcheck"], [], {}, False)
    assert _row(report_mod.misra_compliance_summary(eng.mem), gid)["status"] == "Compliant"


def test_zero_file_scan_checks_nothing(tmp_path):
    eng = _project(tmp_path, CLEAN, analyzers=None)
    eng.mem.record_scan("scan", ["empty"], 0, ["native"], [], {}, False)
    s = report_mod.misra_compliance_summary(eng.mem)
    assert s["counts"]["compliant"] == 0


def test_findings_from_any_source_still_count_without_a_scan(tmp_path):
    eng = _project(tmp_path, CLEAN, analyzers=None)
    eng.mem.sync_scan([_finding()], ["src/a.c"])
    s = report_mod.misra_compliance_summary(eng.mem)
    assert _row(s, "MISRA-C:2012 Rule 21.3")["status"] == "Violations"
    assert s["verdict"].startswith("NON-COMPLIANT")


def test_mandatory_not_checked_does_not_block(tmp_path):
    eng = _project(tmp_path, CLEAN, analyzers=None)
    s = report_mod.misra_compliance_summary(eng.mem)
    assert any(g["category"] == "mandatory" for g in s["guidelines"])
    assert s["blocking_guidelines"] == []


def test_expired_deviation_is_not_active(tmp_path):
    eng = _project(tmp_path)
    target = next(g["guideline"] for g in report_mod.misra_compliance_summary(eng.mem)["guidelines"]
                  if g["status"] == "Violations" and g["category"] != "mandatory")
    eng.mem.add_deviation(target, "src/**", "reviewed", approver="lead@example.com",
                          expires_days=365)
    row = _row(report_mod.misra_compliance_summary(eng.mem), target)
    assert row["status"] == "Deviations" and row["permits"] == 1

    # the permit lapses; no rescan has happened, finding rows still say 'deviated'
    eng.mem.db.execute("UPDATE deviations SET expires=?", (time.time() - 86400,))
    eng.mem.db.commit()
    s = report_mod.misra_compliance_summary(eng.mem)
    row = _row(s, target)
    assert row["status"] == "Violations" and row["permits"] == 0
    assert row["expired_permits"] == 1 and row["deviated"] == 0 and row["open"] > 0
    assert s["verdict"].startswith("NON-COMPLIANT")
    permit = next(d for d in s["deviation_permits"] if d["rule_id"] == target)
    assert permit["expired"] is True
    assert "EXPIRED" in report_mod.misra_compliance_markdown(eng.mem)


def test_expired_permit_without_findings_does_not_make_guideline_deviated(tmp_path):
    eng = _project(tmp_path, CLEAN)
    gid = _native_only()
    eng.mem.add_deviation(gid, "*", "j", approver="a@b.c", expires_days=1)
    assert _row(report_mod.misra_compliance_summary(eng.mem), gid)["status"] == "Deviations"
    eng.mem.db.execute("UPDATE deviations SET expires=?", (time.time() - 1,))
    eng.mem.db.commit()
    assert _row(report_mod.misra_compliance_summary(eng.mem), gid)["status"] == "Compliant"


# ------------------------------------------------------------- item 5: the GEP
def test_gep_checked_by_lists_only_mapped_tools(tmp_path):
    eng = _project(tmp_path, CLEAN)
    gep = report_mod.guideline_enforcement_plan(eng.mem)
    rows = {r["guideline"]: r for r in gep["guidelines"]}

    ref = rows["MISRA-C:2012 Dir 4.12"]            # reference-only
    assert ref["method"] == "Not enforced by tooling - requires separate method"
    assert ref["evidence"] == "none" and ref["checked_by"] == []

    gid = _native_only()
    assert rows[gid]["checked_by"] == ["native"]    # not cppcheck, clang-tidy, compiler
    assert rows[gid]["method"] == "Static analysis"

    cpp = rows[_only_non_native()]
    assert cpp["checked_by"] in (["cppcheck"], ["cppcheck (not installed)"])
    if cpp["checked_by"] == ["cppcheck (not installed)"]:
        assert cpp["evidence"] == "none" and "not checked" in cpp["method"]
    assert not any(r["evidence"] == "configured (tooling covers it)" for r in rows.values())

    md = report_mod.guideline_enforcement_markdown(eng.mem)
    assert "Not enforced by tooling - requires separate method" in md
    assert "Last scan" in md


# ------------------------------------------------------------ item 6: the matrix
def test_matrix_distinguishes_kb_detectable_and_clean(tmp_path):
    eng = _project(tmp_path, CLEAN)
    m = report_mod.compliance_matrix(eng.mem)[STD]
    assert m["rules_checked"] == m["rules_in_kb"] == len(REGISTRY.all_ids(STD))
    assert m["rules_detectable"] < m["rules_in_kb"]          # Dir 4.12 at least
    assert m["clean_among_checked"] is True
    assert m["clean"] is False       # unchecked rules exist: never "clean"
    assert m["analysis_recorded"] is True
    md = report_mod.markdown_report(eng.mem)
    assert "Clean among checked" in md and "## Last scan" in md


def test_matrix_pending_verification_is_not_clean(tmp_path):
    eng = _project(tmp_path, CLEAN)
    eng.mem.sync_scan([_finding()], ["src/a.c"])
    eng.mem.sync_scan([], ["src/a.c"], gate=True)
    assert eng.mem.count_pending() == 1
    m = report_mod.compliance_matrix(eng.mem)[STD]
    assert m["pending_verification"] == 1
    assert m["clean_among_checked"] is False and m["clean"] is False


def test_matrix_without_any_scan_is_not_clean(tmp_path):
    eng = _project(tmp_path, CLEAN, analyzers=None)
    m = report_mod.compliance_matrix(eng.mem)[STD]
    assert m["clean_among_checked"] is True and m["clean"] is False
    assert m["analysis_recorded"] is False


# ------------------------------------------------------------- item 7: the SARIF
def test_sarif_uses_package_version(tmp_path):
    eng = _project(tmp_path, CLEAN)
    doc = report_mod.sarif(eng.mem)
    assert doc["runs"][0]["tool"]["driver"]["version"] == maishac.__version__
    assert doc["runs"][0]["properties"]["maishac/analysisRecorded"] is True


def test_sarif_exports_suppressed_and_deviated_with_suppressions(tmp_path):
    eng = _project(tmp_path, CLEAN)
    sup = _finding(line=3, content="p = malloc(1);")
    dev = _finding(rule="MISRA-C:2012 Rule 21.6", line=5, content='printf("x");')
    live = _finding(rule="MISRA-C:2012 Rule 21.7", line=7, content="n = atoi(s);")
    eng.mem.sync_scan([sup, dev, live], ["src/a.c"])
    eng.mem.suppress(sup.fingerprint, "false positive: custom allocator")
    eng.mem.add_deviation("MISRA-C:2012 Rule 21.6", "src/**", "console shim approved",
                          approver="lead@example.com", expires_days=30)
    doc = report_mod.sarif(eng.mem)
    res = {r["partialFingerprints"]["maishac/v1"]: r for r in doc["runs"][0]["results"]}
    assert len(res) == 3
    assert "suppressions" not in res[live.fingerprint]
    s = res[sup.fingerprint]["suppressions"][0]
    assert s["kind"] == "external" and s["justification"] == "false positive: custom allocator"
    d = res[dev.fingerprint]["suppressions"][0]
    assert d["kind"] == "external" and d["justification"] == "console shim approved"
    assert d["properties"]["maishac/approver"] == "lead@example.com"


def test_sarif_expired_deviation_is_a_live_result(tmp_path):
    eng = _project(tmp_path, CLEAN)
    f = _finding(rule="MISRA-C:2012 Rule 21.6", content='printf("x");')
    eng.mem.sync_scan([f], ["src/a.c"])
    eng.mem.add_deviation(f.rule_id, "*", "j", approver="a@b.c", expires_days=1)
    eng.mem.db.execute("UPDATE deviations SET expires=?", (time.time() - 5,))
    eng.mem.db.commit()
    (r,) = report_mod.sarif(eng.mem)["runs"][0]["results"]
    assert "suppressions" not in r


def test_sarif_pending_verification_is_counted_not_listed(tmp_path):
    eng = _project(tmp_path, CLEAN)
    eng.mem.sync_scan([_finding()], ["src/a.c"])
    eng.mem.sync_scan([], ["src/a.c"], gate=True)
    run = report_mod.sarif(eng.mem)["runs"][0]
    assert run["results"] == [] and run["properties"]["maishac/pendingVerification"] == 1


def test_column_is_persisted_and_exported(tmp_path):
    eng = _project(tmp_path, CLEAN)
    f = _finding(column=12)
    eng.mem.sync_scan([f], ["src/a.c"])
    assert eng.mem.get_finding(f.fingerprint)["column"] == 12
    # a later scan that sees the finding at a new column updates it
    eng.mem.sync_scan([_finding(column=15)], ["src/a.c"])
    assert eng.mem.get_finding(f.fingerprint)["column"] == 15
    (r,) = report_mod.sarif(eng.mem)["runs"][0]["results"]
    assert r["locations"][0]["physicalLocation"]["region"]["startColumn"] == 15


def test_sarif_round_trip_keeps_suppression_and_column(tmp_path):
    eng = _project(tmp_path, CLEAN)
    sup = _finding(column=4)
    live = _finding(rule="MISRA-C:2012 Rule 21.7", line=7, column=9, content="n = atoi(s);")
    eng.mem.sync_scan([sup, live], ["src/a.c"])
    eng.mem.suppress(sup.fingerprint, "triaged")
    out = tmp_path / "out.sarif"
    out.write_text(json.dumps(report_mod.sarif(eng.mem)))

    other = tmp_path / "other"
    other.mkdir()
    eng2 = LoopEngine(other)
    res = eng2.import_sarif(str(out))
    assert res["imported"] == 2 and res["suppressions_carried"] == 1
    assert eng2.mem.get_finding(sup.fingerprint)["status"] == "suppressed"
    assert eng2.mem.get_finding(live.fingerprint)["column"] == 9
