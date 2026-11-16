"""Persistent project memory (SQLite, stored at <project>/.maishac/memory.db).

Memory is what turns a scanner into a harness. Five kinds of memory:

  findings      lifecycle of every defect fingerprint ever seen
                (open -> resolved -> regressed if it comes back)
  fix_attempts  what strategies were tried on each finding and how they went —
                the loop engine uses this to avoid repeating failed approaches
  deviations    formal, justified rule deviations (MISRA-style deviation
                records: scope, rationale, approver, expiry)
  suppressions  per-fingerprint false-positive markers with reasons
  notes         free-form learned knowledge: project conventions, allocator
                names, logging shims, architectural decisions
"""

from __future__ import annotations

import fnmatch
import json
import re
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Optional

from ..model import Finding, _normalize_line, compute_fingerprint


class MandatoryRuleError(ValueError):
    """Raised when something tries to waive a MISRA Mandatory guideline."""

# A fix to one of these is behavior-changing at edge cases (sentinel values,
# saturation limits, sign boundaries) in a way NO static rescan can catch — the
# rule only checks that the pattern is gone, never that the specific edit kept
# the intended meaning. Such findings always need human sign-off, never a bare
# "the warning stopped firing". See the sentinel-cast example in the tests.
_RISK_RULES = ("INT30", "INT31", "INT32", "INT33", "FLP",
               " 10.", " 11.", " 13.", " 14.", " 15.", " 16.")
_CAST_RE = re.compile(r"\(\s*(?:unsigned|signed|u?int\w*|char|short|long|size_t)\s*\)")
_HIGH_SEV = ("blocker", "critical")


def semantic_risk(rule_id: str, line_content: str) -> bool:
    if any(t in rule_id for t in _RISK_RULES):
        return True
    return bool(line_content and _CAST_RE.search(line_content))


def requires_human(row: dict) -> bool:
    """A pending finding an automated test pass may NOT resolve on its own:
    high-severity (MISRA mandatory/required-tier, CERT L1) or semantic-risk."""
    return bool(row.get("semantic_risk")) or row.get("severity") in _HIGH_SEV

_SCHEMA = """
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
  status TEXT NOT NULL DEFAULT 'active',   -- active|awaiting_verification|analysis_incomplete (live) | converged|budget_exhausted|stalled|needs_human|aborted (terminal)
  iteration INTEGER NOT NULL DEFAULT 0,
  config TEXT,
  history TEXT,          -- JSON list of iteration snapshots (open counts per iteration)
  started REAL NOT NULL,
  updated REAL NOT NULL,
  ended REAL,            -- when the session reached a terminal state
  end_reason TEXT        -- why it ended (the verify reason, or the abort reason)
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


# PRAGMA user_version of a fully migrated database. 0 = created before
# versioning existed (or brand new, before _migrate stamps it).
#   1: (implicit) verification-gate columns on findings
#   2: findings."column", scans table
#   3: source/approver/expiry on suppressions, source + revocation on deviations,
#      source on recategorizations, findings.approval_source, audit_log, proposals
#   4: sessions.ended / sessions.end_reason (session lifecycle: abort, needs_human)
#   5: backslash (Windows) paths rewritten to forward slashes with their fingerprints;
#      rows that predate `source` columns are labelled 'legacy', not 'cli'
SCHEMA_VERSION = 5

# Session states that end a session for good. Everything else (active,
# awaiting_verification, analysis_incomplete) can still be verified.
TERMINAL_SESSION_STATES = ("converged", "budget_exhausted", "stalled", "needs_human", "aborted")
_TERMINAL_SQL = ",".join(f"'{s}'" for s in TERMINAL_SESSION_STATES)


class MemoryStore:
    def __init__(self, project_root: str | Path):
        self.root = Path(project_root).resolve()
        self.dir = self.root / ".maishac"
        self.dir.mkdir(exist_ok=True)
        # check_same_thread=False: the MCP server runs tool bodies on worker
        # threads but serializes them with a lock, so the shared connection is
        # never used by two threads at once.
        self.db = sqlite3.connect(self.dir / "memory.db", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        # WAL lets a reader and a writer coexist, so a CI scan and a local
        # session on the same .maishac/memory.db don't block each other as hard.
        # busy_timeout must be set BEFORE the WAL switch: switching a brand-new
        # database to WAL needs a lock, and concurrent first-time opens used to
        # fail with "database is locked" because no busy handler was installed
        # yet. The switch is also retried, as SQLite can still return BUSY for it.
        self.db.execute("PRAGMA busy_timeout=5000")
        for attempt in range(5):
            try:
                self.db.execute("PRAGMA journal_mode=WAL")
                break
            except sqlite3.OperationalError:
                if attempt == 4:
                    raise
                time.sleep(0.05 * (attempt + 1))
        self.db.executescript(_SCHEMA)
        self._migrate()
        self.db.commit()

    def close(self) -> None:
        """Close the SQLite connection. Safe to call twice."""
        db = getattr(self, "db", None)
        if db is not None:
            try:
                db.close()
            finally:
                self.db = None

    def __enter__(self) -> "MemoryStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _migrate(self) -> None:
        """Add verification-gate columns to findings tables created before they existed."""
        cols = {r["name"] for r in self.db.execute("PRAGMA table_info(findings)")}
        legacy_approvals = "approval_source" not in cols
        for name, ddl in [("semantic_risk", "INTEGER NOT NULL DEFAULT 0"),
                          ("analyzer_cleared_at", "REAL"), ("verification_method", "TEXT"),
                          ("approved_by", "TEXT"), ("approved_at", "REAL"),
                          ("code_flow", "TEXT"), ('"column"', "INTEGER"),
                          ("approval_source", "TEXT")]:
            if name.strip('"') not in cols:
                self.db.execute(f"ALTER TABLE findings ADD COLUMN {name} {ddl}")
        if legacy_approvals:
            # Approvals recorded before provenance existed may have been made by an
            # MCP agent (the tools wrote them directly). Do not present them as human.
            self.db.execute("UPDATE findings SET approval_source='legacy' "
                            "WHERE approved_by IS NOT NULL AND approval_source IS NULL")
        for table, additions in (
                # Rows that predate the `source` column have unknown provenance:
                # earlier versions let MCP tools write them directly, so they are
                # labelled 'legacy', never 'cli'.
                ("suppressions", [("approver", "TEXT"), ("source", "TEXT NOT NULL DEFAULT 'legacy'"),
                                  ("expires", "REAL")]),
                ("deviations", [("source", "TEXT NOT NULL DEFAULT 'legacy'"),
                                ("revoked_at", "REAL"), ("revoked_by", "TEXT")]),
                ("recategorizations", [("source", "TEXT NOT NULL DEFAULT 'legacy'")]),
                ("sessions", [("ended", "REAL"), ("end_reason", "TEXT")])):
            have = {r["name"] for r in self.db.execute(f"PRAGMA table_info({table})")}
            for name, ddl in additions:
                if name not in have:
                    self.db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
        # `scans`, `audit_log` and `proposals` are created by _SCHEMA (CREATE TABLE
        # IF NOT EXISTS), which also runs against old databases.
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version in (3, 4):
            self._relabel_unproven_waivers()
        if version < 5:
            self._normalize_stored_paths()
        if self.db.execute("PRAGMA user_version").fetchone()[0] < SCHEMA_VERSION:
            self.db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

    def _relabel_unproven_waivers(self) -> None:
        """Schema 3/4 -> 5 (defence in depth): those versions already had a ``source``
        column, but MCP tools could still write rows labelled 'cli'. A waiver or
        approval keeps the 'cli' label only if the audit log has a latest entry for
        it written by the CLI (a human surface). Anything else is relabelled
        'legacy', which reports show as ORIGIN UNKNOWN. Never upgrades a label."""
        def proven(action: str, target: str) -> bool:
            row = self.db.execute(
                "SELECT source FROM audit_log WHERE action=? AND target=? "
                "ORDER BY id DESC LIMIT 1", (action, target)).fetchone()
            return row is not None and row["source"] == "cli"

        changed: dict[str, int] = {}
        for table, key, action in (("deviations", "id", "add_deviation"),
                                   ("suppressions", "fingerprint", "suppress"),
                                   ("recategorizations", "rule_id", "recategorize")):
            for r in self.db.execute(f"SELECT {key} AS k FROM {table} WHERE source='cli'").fetchall():
                if not proven(action, r["k"]):
                    self.db.execute(f"UPDATE {table} SET source='legacy' WHERE {key}=?", (r["k"],))
                    changed[table] = changed.get(table, 0) + 1
        for r in self.db.execute(
                "SELECT fingerprint FROM findings WHERE approval_source='cli'").fetchall():
            if not proven("approve_finding", r["fingerprint"]):
                self.db.execute("UPDATE findings SET approval_source='legacy' WHERE fingerprint=?",
                                (r["fingerprint"],))
                changed["approvals"] = changed.get("approvals", 0) + 1
        if changed:
            self.audit("provenance_relabel", "", source="engine", commit=False,
                       details={"label": "legacy", "reason": "origin not proven by the audit log",
                                "relabelled": changed})

    def _normalize_stored_paths(self) -> None:
        """One-time (schema v5): rewrite backslash paths recorded on Windows.

        Paths are now always stored with forward slashes, and the fingerprint
        covers the path, so a database built on Windows would otherwise never
        match its own files again: old rows stay open forever beside new
        duplicates. Each affected row gets its forward-slash path and the
        fingerprint Maisha would compute now (the occurrence index is recovered by
        matching the stored fingerprint). Fingerprints that Maisha did not compute
        (imported from an external tool) keep their value and only the path
        changes. Rows other tables hold by fingerprint follow the rename. If the
        new fingerprint already exists (a rescan ran first), the old row is
        dropped in favour of the live one. Each rewrite is audit-logged."""
        rows = self.db.execute(
            "SELECT * FROM findings WHERE file LIKE '%\\%'").fetchall()
        # Occurrence recovery. A row with occurrence index n implies n sibling rows
        # (same rule, file, normalized line, function) were recorded in the same scan,
        # and rows are never deleted, so n < size of the sibling group. Each group's
        # old-fingerprint -> n table is therefore built once, with a data-derived
        # bound: linear in the number of rows, not quadratic.
        groups: dict[tuple, list] = {}
        for r in rows:
            key = (r["rule_id"], r["file"], _normalize_line(r["line_content"] or ""),
                   r["context_symbol"] or "")
            groups.setdefault(key, []).append(r)
        recovered: dict[str, int] = {}
        for (rule, file, content, symbol), members in groups.items():
            for n in range(len(members)):
                recovered.setdefault(compute_fingerprint(rule, file, content, symbol, n), n)
        for r in rows:
            old_fp, old_file = r["fingerprint"], r["file"]
            new_file = old_file.replace("\\", "/")
            new_fp = old_fp
            n = recovered.get(old_fp)
            if n is not None:
                new_fp = compute_fingerprint(r["rule_id"], new_file, r["line_content"] or "",
                                             r["context_symbol"] or "", n)
            if new_fp != old_fp and self.db.execute(
                    "SELECT 1 FROM findings WHERE fingerprint=?", (new_fp,)).fetchone():
                # Duplicate: keep the live row, but carry over everything keyed by the
                # dropped fingerprint so no suppression, approval or attempt is lost.
                moved = self._repoint_fingerprint(old_fp, new_fp, drop_row=True)
                action = "path_migration_dropped_duplicate"
            else:
                self.db.execute("UPDATE findings SET file=?, fingerprint=? WHERE fingerprint=?",
                                (new_file, new_fp, old_fp))
                moved = (self._repoint_fingerprint(old_fp, new_fp, drop_row=False)
                         if new_fp != old_fp else {})
                action = "path_migration"
            self.audit(action, new_fp, source="engine", commit=False,
                       details={"from_file": old_file, "to_file": new_file,
                                "from_fingerprint": old_fp, "to_fingerprint": new_fp,
                                **({"moved": moved} if moved else {})})

    def _repoint_fingerprint(self, old_fp: str, new_fp: str, drop_row: bool) -> dict:
        """Move everything recorded against ``old_fp`` onto ``new_fp``.

        Fix attempts all move. Suppressions merge keeping the strongest (no expiry
        beats any expiry, a later expiry beats an earlier one, a tie keeps the
        surviving row's). When the old finding row is being dropped, its sign-off
        is copied onto the survivor if the survivor has none. Pending proposals
        that name the old fingerprint are re-pointed. The audit log is append-only
        and is not rewritten: the migration's own entry records old -> new.
        Deviations are scoped by file glob, not fingerprint, so they need no move."""
        moved: dict[str, int] = {}
        cur = self.db.execute("UPDATE fix_attempts SET fingerprint=? WHERE fingerprint=?",
                              (new_fp, old_fp))
        if cur.rowcount:
            moved["fix_attempts"] = cur.rowcount
        old_s = self.db.execute("SELECT * FROM suppressions WHERE fingerprint=?",
                                (old_fp,)).fetchone()
        if old_s is not None:
            new_s = self.db.execute("SELECT * FROM suppressions WHERE fingerprint=?",
                                    (new_fp,)).fetchone()
            inf = float("inf")
            if new_s is None or ((old_s["expires"] or inf) > (new_s["expires"] or inf)):
                self.db.execute("DELETE FROM suppressions WHERE fingerprint=?", (new_fp,))
                self.db.execute("UPDATE suppressions SET fingerprint=? WHERE fingerprint=?",
                                (new_fp, old_fp))
            else:
                self.db.execute("DELETE FROM suppressions WHERE fingerprint=?", (old_fp,))
            moved["suppressions"] = 1
        if drop_row:
            old_f = self.db.execute("SELECT * FROM findings WHERE fingerprint=?",
                                    (old_fp,)).fetchone()
            new_f = self.db.execute("SELECT * FROM findings WHERE fingerprint=?",
                                    (new_fp,)).fetchone()
            if old_f is not None and new_f is not None and old_f["approved_by"] \
                    and not new_f["approved_by"]:
                self.db.execute(
                    "UPDATE findings SET approved_by=?, approved_at=?, approval_source=?,"
                    " verification_method=COALESCE(verification_method, ?) WHERE fingerprint=?",
                    (old_f["approved_by"], old_f["approved_at"], old_f["approval_source"],
                     old_f["verification_method"], new_fp))
                moved["approval"] = 1
            self.db.execute("DELETE FROM findings WHERE fingerprint=?", (old_fp,))
        cur = self.db.execute(
            "UPDATE proposals SET payload=REPLACE(payload, ?, ?) "
            "WHERE status='pending_human' AND payload LIKE ?",
            (f'"{old_fp}"', f'"{new_fp}"', f'%"{old_fp}"%'))
        if cur.rowcount:
            moved["proposals"] = cur.rowcount
        return moved

    # ------------------------------------------------------------ scan sync
    def sync_scan(self, findings: list[Finding], scanned_files: list[str],
                  gate: bool = False, producers: set[str] | None = None,
                  analyzed: dict[str, set[str]] | None = None,
                  removed_files: set[str] | None = None,
                  hold_for_human: bool = False) -> dict:
        """Reconcile a fresh scan against memory.

        Returns a diff: {new, persisting, resolved, pending, regressed, suppressed,
        deviated} (lists of fingerprints). A previously-resolved fingerprint
        reappearing is a *regression* — the loop engine treats those with top priority.

        When ``gate`` is True, a finding whose pattern disappears does NOT go
        straight to ``resolved``; it goes to ``pending_verification``. The only
        judge of the fix so far is the same analyzer whose blind spots may have
        created the finding — a passing test run or a human must confirm it
        before it counts as resolved (see engine verification_policy).

        ``producers`` names the analyzers that ran this scan. A known finding
        absent from the scan is only cleared if one of *its* producers ran —
        so a native rescan never resolves findings imported from a qualified
        engine via SARIF. None = clear any absent finding (legacy behavior).

        ``analyzed`` is the stricter, per-file form: analyzer name -> the files
        it actually analyzed this run (a failed analyzer maps to an empty set).
        When given it replaces ``producers``. An absent finding is cleared only
        if at least one of its producers that took part in this run analyzed
        its file, and none of the producers that took part failed to analyze
        it. A crashed tool, a timeout or a file that did not compile therefore
        never resolves anything.

        ``removed_files`` are files on record that no longer exist on disk. The
        open findings in them are closed as stale (resolved, verification method
        ``file_removed``) and listed under ``stale`` in the diff. A path that
        vanished may have been moved or renamed rather than fixed, so a finding
        that needs human sign-off (see ``requires_human``), or any finding under
        ``gate``, goes to ``pending_verification`` instead.

        ``hold_for_human`` keeps the ungated path from resolving a finding that
        needs human sign-off (``requires_human``: high severity or semantic risk):
        those go to ``pending_verification`` even with ``gate=False``. Session
        verification sets it, so the ``analyzer_only`` policy cannot bypass the
        rule that such findings always need a person.

        Engine callers that act for an MCP agent always pass ``gate=True`` (see
        LoopEngine._effective_gate); only a human-run CLI scan may use gate=False.

        Lifecycle: a finding that reappears after being resolved *or* after
        being pending_verification is a regression (counted, so the oscillation
        freeze works under gated policies); one that is already ``regressed``
        and still present stays ``regressed``.
        """
        now = time.time()
        current = {f.fingerprint: f for f in findings}
        diff = {k: [] for k in ("new", "persisting", "resolved", "pending",
                                 "regressed", "suppressed", "deviated", "stale")}
        cur = self.db.execute("SELECT * FROM findings")
        known = {r["fingerprint"]: dict(r) for r in cur.fetchall()}
        scanned = {f.replace("\\", "/") for f in scanned_files}

        # Read the waiver tables once per scan, not once per finding.
        recats = {rid: r["to_category"] for rid, r in self.recategorizations().items()}
        mandatory: dict[str, bool] = {}
        now_ts = time.time()
        suppressed_fps = {r["fingerprint"] for r in self.db.execute(
            "SELECT fingerprint, expires FROM suppressions")
            if not (r["expires"] and r["expires"] < now_ts)}
        devs: dict[str, list[dict]] = {}
        for r in self.db.execute("SELECT * FROM deviations WHERE revoked_at IS NULL"):
            devs.setdefault(r["rule_id"], []).append(dict(r))

        for fp, f in current.items():
            if f.rule_id not in mandatory:
                mandatory[f.rule_id] = self.effective_category(f.rule_id, recats) == "mandatory"
            if mandatory[f.rule_id]:
                # A Mandatory guideline admits no waiver: any suppression or
                # permit that predates the guard (or a later GRP move to
                # Mandatory) is ignored, the finding stays open.
                status = "open"
            elif fp in suppressed_fps:
                diff["suppressed"].append(fp)
                status = "suppressed"
            elif self._deviation_for(f.rule_id, f.file, devs, now_ts):
                diff["deviated"].append(fp)
                status = "deviated"
            else:
                status = "open"

            if fp not in known:
                self.db.execute(
                    """INSERT INTO findings (fingerprint, rule_id, standard, severity, file,
                       line, "column", message, analyzer, line_content, context_symbol,
                       fix_hint, code_flow, status, semantic_risk, first_seen, last_seen)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (fp, f.rule_id, f.standard, f.severity, f.file, f.line, f.column, f.message,
                     f.analyzer, f.line_content, f.context_symbol, f.fix_hint,
                     json.dumps(f.code_flow) if f.code_flow else None,
                     status, int(semantic_risk(f.rule_id, f.line_content)), now, now))
                if status == "open":
                    diff["new"].append(fp)
            else:
                prev = known[fp]
                # A finding that was resolved, or that the analyzer had stopped
                # flagging (pending_verification), and is flagged again, did not
                # stay fixed: that is a regression. One already 'regressed' stays
                # so until it is resolved; it is not downgraded to plain 'open'.
                regressed = (status == "open"
                             and prev["status"] in ("resolved", "pending_verification"))
                still_regressed = status == "open" and prev["status"] == "regressed"
                new_status = "regressed" if (regressed or still_regressed) else status
                self.db.execute(
                    """UPDATE findings SET status=?, line=?, "column"=?,
                       seen_count=seen_count+1, last_seen=?,
                       regress_count=regress_count+?,
                       analyzer_cleared_at=CASE WHEN ? THEN NULL ELSE analyzer_cleared_at END
                       WHERE fingerprint=?""",
                    (new_status, f.line, f.column, now, 1 if regressed else 0,
                     1 if regressed else 0, fp))
                if regressed:
                    diff["regressed"].append(fp)
                    # the fixes tried on it did not hold
                    self.db.execute(
                        "UPDATE fix_attempts SET outcome='regressed' "
                        "WHERE fingerprint=? AND outcome IN ('pending','resolved')", (fp,))
                elif status == "open":
                    diff["persisting"].append(fp)

        # anything known-open in a scanned file but absent now => cleared by the analyzer
        for fp, prev in known.items():
            if fp in current:
                continue
            if (removed_files and prev["file"] in removed_files
                    and prev["status"] in ("open", "regressed", "pending_verification")):
                if prev["status"] == "pending_verification":
                    continue   # already awaiting its verdict; a missing file adds nothing
                if gate or requires_human(prev):
                    # A file that vanished from its path may have been moved or
                    # renamed, not fixed: closing it here would let a blocker
                    # disappear without sign-off. It waits for verification.
                    self.db.execute(
                        "UPDATE findings SET status='pending_verification', "
                        "analyzer_cleared_at=? WHERE fingerprint=?", (now, fp))
                    diff["pending"].append(fp)
                    continue
                self.db.execute(
                    "UPDATE findings SET status='resolved', resolved_at=?, "
                    "verification_method='file_removed' WHERE fingerprint=?", (now, fp))
                self.db.execute(
                    "UPDATE fix_attempts SET outcome='resolved' "
                    "WHERE fingerprint=? AND outcome='pending'", (fp,))
                diff["stale"].append(fp)
                continue
            if analyzed is not None:
                took_part = [a for a in (prev["analyzer"] or "").split("+") if a in analyzed]
                if not took_part:
                    continue  # none of its analyzers ran — can't judge it cleared
                if any(prev["file"] not in analyzed[a] for a in took_part):
                    continue  # one of them failed on this file — can't judge it cleared
            elif producers is not None and not any(
                    a in producers for a in (prev["analyzer"] or "").split("+")):
                continue  # this finding's analyzer didn't run — can't judge it cleared
            if prev["status"] in ("open", "regressed") and prev["file"] in scanned:
                if gate or (hold_for_human and requires_human(prev)):
                    self.db.execute(
                        "UPDATE findings SET status='pending_verification', "
                        "analyzer_cleared_at=? WHERE fingerprint=?", (now, fp))
                    diff["pending"].append(fp)
                else:
                    self.db.execute(
                        "UPDATE findings SET status='resolved', resolved_at=?, "
                        "verification_method='analyzer' WHERE fingerprint=?", (now, fp))
                    self.db.execute(
                        "UPDATE fix_attempts SET outcome='resolved' "
                        "WHERE fingerprint=? AND outcome='pending'", (fp,))
                    diff["resolved"].append(fp)
        self.db.commit()
        return diff

    def tracked_files(self) -> set[str]:
        """Files with an unresolved finding that Maisha's own analyzers produced
        (imported findings are excluded: their files may live on another machine)."""
        return {r["file"] for r in self.db.execute(
            "SELECT file, analyzer FROM findings WHERE status IN"
            " ('open','regressed','pending_verification') AND file != ''")
            if not all(a.startswith("sarif:") for a in (r["analyzer"] or "").split("+"))}

    # ----------------------------------------------------------------- scans
    def record_scan(self, kind: str, paths: list[str], files_scanned: int,
                    analyzers_used: list[str], analyzers_failed: list[dict],
                    toolchain: dict, degraded: bool) -> int:
        """Append one row to the scan log (kind: scan|verify|import). This is the
        evidence reports use to say what the last analysis did and did not check."""
        from .. import __version__
        cur = self.db.execute(
            "INSERT INTO scans (ts, kind, paths, files_scanned, analyzers_used,"
            " analyzers_failed, toolchain, degraded, maishac_version)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (time.time(), kind, json.dumps(paths), files_scanned,
             json.dumps(analyzers_used), json.dumps(analyzers_failed),
             json.dumps(toolchain), int(bool(degraded)), __version__))
        self.db.commit()
        return cur.lastrowid

    @staticmethod
    def _scan_row(r) -> dict:
        d = dict(r)
        for k in ("paths", "analyzers_used", "analyzers_failed", "toolchain"):
            d[k] = json.loads(d[k]) if d.get(k) else ([] if k != "toolchain" else {})
        d["degraded"] = bool(d["degraded"])
        return d

    def last_scan(self, kinds: tuple[str, ...] = ("scan", "verify")) -> Optional[dict]:
        """Most recent recorded analysis run. Defaults to runs that executed
        analyzers; pass kinds=("import",) for the last SARIF import."""
        q = ",".join("?" * len(kinds))
        r = self.db.execute(
            f"SELECT * FROM scans WHERE kind IN ({q}) ORDER BY id DESC LIMIT 1",
            kinds).fetchone()
        return self._scan_row(r) if r else None

    def scans(self, limit: int = 20) -> list[dict]:
        return [self._scan_row(r) for r in self.db.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))]

    # ------------------------------------------------------------- lifecycle
    def open_findings(self, limit: int = 200, severities: list[str] | None = None) -> list[dict]:
        q = "SELECT * FROM findings WHERE status IN ('open','regressed')"
        args: list = []
        if severities:
            q += f" AND severity IN ({','.join('?' * len(severities))})"
            args += severities
        q += (" ORDER BY CASE status WHEN 'regressed' THEN 0 ELSE 1 END,"
              " CASE severity WHEN 'blocker' THEN 0 WHEN 'critical' THEN 1"
              " WHEN 'major' THEN 2 WHEN 'minor' THEN 3 ELSE 4 END, file, line LIMIT ?")
        args.append(limit)
        return [dict(r) for r in self.db.execute(q, args)]

    def get_finding(self, fingerprint: str) -> Optional[dict]:
        r = self.db.execute("SELECT * FROM findings WHERE fingerprint=?",
                            (fingerprint,)).fetchone()
        return dict(r) if r else None

    # ----------------------------------------------------- verification gate
    def pending_findings(self, require_human: bool | None = None) -> list[dict]:
        rows = [dict(r) for r in self.db.execute(
            "SELECT * FROM findings WHERE status='pending_verification'")]
        if require_human is None:
            return rows
        return [r for r in rows if requires_human(r) == require_human]

    def count_pending(self, require_human: bool | None = None) -> int:
        return len(self.pending_findings(require_human))

    def _mark_resolved(self, fingerprint: str, method: str,
                       approved_by: str | None = None, source: str | None = None) -> None:
        now = time.time()
        self.db.execute(
            "UPDATE findings SET status='resolved', resolved_at=?, verification_method=?, "
            "approved_by=?, approved_at=?, approval_source=? WHERE fingerprint=?",
            (now, method, approved_by, now if approved_by else None,
             source if approved_by else None, fingerprint))
        self.db.execute("UPDATE fix_attempts SET outcome='resolved' "
                        "WHERE fingerprint=? AND outcome='pending'", (fingerprint,))

    def confirm_pending_by_test(self) -> list[str]:
        """A passing test run confirms pending findings — EXCEPT those that
        require explicit human sign-off (high-severity / semantic-risk)."""
        confirmed = []
        for r in self.pending_findings():
            if requires_human(r):
                continue
            self._mark_resolved(r["fingerprint"], "test")
            self.audit("confirm_by_test", r["fingerprint"], actor="test", source="engine",
                       commit=False)
            confirmed.append(r["fingerprint"])
        self.db.commit()
        return confirmed

    def approve_finding(self, fingerprint: str, approved_by: str, source: str = "cli") -> dict:
        r = self.get_finding(fingerprint)
        if not r:
            return {"error": f"No finding with fingerprint '{fingerprint}'."}
        if r["status"] == "resolved":
            return {"ok": True, "already": "resolved", "fingerprint": fingerprint}
        if r["status"] != "pending_verification":
            return {"error": f"Finding is '{r['status']}', not pending_verification — the "
                             "analyzer still flags it. Fix it (and re-verify) before approving."}
        self._mark_resolved(fingerprint, "human", approved_by, source)
        self.audit("approve_finding", fingerprint, actor=approved_by, source=source,
                   details={"rule_id": r["rule_id"], "file": r["file"]}, commit=False)
        self.db.commit()
        return {"ok": True, "resolved": fingerprint, "approved_by": approved_by,
                "source": source}

    # ---------------------------------------------------------- fix attempts
    def record_fix_attempt(self, fingerprint: str, session_id: str,
                           strategy: str, notes: str = "") -> str:
        aid = uuid.uuid4().hex[:12]
        self.db.execute(
            "INSERT INTO fix_attempts (id, fingerprint, session_id, strategy, outcome, notes, ts)"
            " VALUES (?,?,?,?,?,?,?)",
            (aid, fingerprint, session_id, strategy, "pending", notes, time.time()))
        self.db.commit()
        return aid

    def close_pending_attempts(self, fingerprint: str, outcome: str) -> None:
        self.db.execute("UPDATE fix_attempts SET outcome=? WHERE fingerprint=? AND outcome='pending'",
                        (outcome, fingerprint))
        self.db.commit()

    def close_pending_attempts_for_open(self, outcome: str) -> int:
        """One UPDATE: every undecided fix attempt on a still-open (open or
        regressed) finding gets ``outcome``."""
        cur = self.db.execute(
            "UPDATE fix_attempts SET outcome=? WHERE outcome='pending' AND fingerprint IN"
            " (SELECT fingerprint FROM findings WHERE status IN ('open','regressed'))",
            (outcome,))
        self.db.commit()
        return cur.rowcount

    def abandon_session_attempts(self, session_id: str) -> int:
        """A session ended without resolving everything: its fix attempts that
        are still undecided become 'abandoned' (and so count as failed strategies).
        Attempts on findings that are only awaiting verification are left alone,
        since the fix may still be confirmed."""
        cur = self.db.execute(
            "UPDATE fix_attempts SET outcome='abandoned' WHERE session_id=? AND outcome='pending'"
            " AND fingerprint NOT IN (SELECT fingerprint FROM findings"
            "  WHERE status IN ('pending_verification','resolved'))", (session_id,))
        self.db.commit()
        return cur.rowcount

    def attempts_for(self, fingerprint: str) -> list[dict]:
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM fix_attempts WHERE fingerprint=? ORDER BY ts", (fingerprint,))]

    def failed_strategies(self, fingerprint: str) -> list[str]:
        return [r["strategy"] for r in self.db.execute(
            "SELECT strategy FROM fix_attempts WHERE fingerprint=? "
            "AND outcome IN ('persisting','regressed','abandoned')", (fingerprint,))]

    # ------------------------------------------------------------ audit log
    def audit(self, action: str, target: str = "", actor: str = "", source: str = "cli",
              details: dict | None = None, commit: bool = True) -> None:
        """Append one row to the audit log. The table is insert-only: nothing in
        Maisha updates or deletes it, so it keeps what an overwrite would erase."""
        self.db.execute(
            "INSERT INTO audit_log (ts, actor, source, action, target, details)"
            " VALUES (?,?,?,?,?,?)",
            (time.time(), actor or "", source, action, target or "",
             json.dumps(details, default=str) if details else None))
        if commit:
            self.db.commit()

    def last_audit(self, action: str) -> Optional[dict]:
        rows = self.audit_entries(1, action)
        return rows[0] if rows else None

    def audit_entries(self, limit: int = 100, action: str | None = None) -> list[dict]:
        q, args = "SELECT * FROM audit_log", []
        if action:
            q += " WHERE action=?"
            args.append(action)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        out = []
        for r in self.db.execute(q, args):
            d = dict(r)
            d["details"] = json.loads(d["details"]) if d["details"] else {}
            out.append(d)
        return out

    # ------------------------------------------------- effective categories
    def effective_category(self, rule_id: str,
                           recats: dict[str, str] | None = None) -> Optional[str]:
        """A guideline's category after this project's GRP re-categorizations
        (mandatory|required|advisory|disapplied), or None for an unknown rule.
        ``recats`` (rule id -> category) lets a bulk caller such as sync_scan
        load the re-categorizations once instead of querying per call."""
        from ..rules import REGISTRY
        meta = REGISTRY.get(rule_id) or REGISTRY.resolve(rule_id)
        rid = meta["id"] if meta else rule_id
        if recats is not None:
            if rid in recats:
                return recats[rid]
        else:
            r = self.db.execute("SELECT to_category FROM recategorizations WHERE rule_id=?",
                                (rid,)).fetchone()
            if r:
                return r["to_category"]
        return (meta.get("category") if meta else None)

    def is_mandatory(self, rule_id: str) -> bool:
        return self.effective_category(rule_id) == "mandatory"

    def _require_resolvable(self, rule_id: str, what: str, strict: bool = True) -> None:
        """Refuse a rule reference the registry cannot pin to one guideline. An
        ambiguous id (a bare "4.1" that is both a Rule and a Directive) could name a
        Mandatory guideline, so the Mandatory check below would be guessing; failing
        open there would let a waiver through. ``strict=False`` lets an id the
        registry does not know at all pass (imported findings carry foreign tool
        ids), but still refuses an ambiguous one."""
        from ..rules import REGISTRY
        if REGISTRY.get(rule_id) or REGISTRY.resolve(rule_id):
            return
        if strict or REGISTRY.candidates(rule_id):
            raise ValueError(f"Cannot record a {what}: " + REGISTRY.resolve_error(rule_id))

    def _require_not_mandatory(self, rule_id: str, what: str) -> None:
        if self.is_mandatory(rule_id):
            from ..rules import REGISTRY
            meta = REGISTRY.get(rule_id) or REGISTRY.resolve(rule_id)
            raise MandatoryRuleError(
                f"{meta['id'] if meta else rule_id} is a MISRA Mandatory guideline; "
                f"{what} is not permitted against it. It must be fixed, not waived.")

    # ------------------------------------------------------------ deviations
    def add_deviation(self, rule_id: str, scope: str, justification: str,
                      approver: str = "", expires_days: float | None = None,
                      expires_at: float | None = None, source: str = "cli") -> str:
        """Record a formal deviation permit.

        Raises MandatoryRuleError for MISRA Mandatory guidelines, judged on the
        *effective* category (so a guideline a GRP entry made Mandatory is
        covered too). MISRA Compliance:2020 is unambiguous that Mandatory
        guidelines admit no deviation whatsoever — the only permitted compliance
        state is Compliant, reached by actually fixing the code. The guard lives
        here rather than in the CLI/MCP layers so no caller can route around it.
        Raises ValueError for a negative or already-past expiry.
        """
        from ..rules import REGISTRY
        self._require_resolvable(rule_id, "deviation")
        self._require_not_mandatory(rule_id, "deviation")
        meta = REGISTRY.get(rule_id) or REGISTRY.resolve(rule_id)
        if meta:
            rule_id = meta["id"]
        now = time.time()
        if expires_days is not None and expires_days < 0:
            raise ValueError("expires_days must not be negative.")
        if expires_at is not None and expires_at <= now:
            raise ValueError("The deviation's expiry is already in the past.")
        did = uuid.uuid4().hex[:12]
        expires = expires_at if expires_at is not None else (
            now + expires_days * 86400 if expires_days else None)
        self.db.execute(
            "INSERT INTO deviations (id, rule_id, scope, justification, approver, expires, ts,"
            " source) VALUES (?,?,?,?,?,?,?,?)",
            (did, rule_id, scope, justification, approver, expires, now, source))
        self.audit("add_deviation", did, actor=approver, source=source,
                   details={"rule_id": rule_id, "scope": scope, "justification": justification,
                            "expires": expires}, commit=False)
        # Retroactively cover findings already on record that fall under this
        # permit's scope, so a compliance report reflects the deviation now
        # instead of only after the next rescan. (Expiry is reconciled at scan
        # time by matching_deviation; ponytail: no scheduled re-open of expired
        # permits — a rescan does it.)
        for r in self.db.execute(
                "SELECT fingerprint, file FROM findings WHERE rule_id=?"
                " AND status IN ('open','regressed')", (rule_id,)).fetchall():
            if fnmatch.fnmatch(r["file"], scope):
                self.db.execute("UPDATE findings SET status='deviated' WHERE fingerprint=?",
                                (r["fingerprint"],))
        self.db.commit()
        return did

    def matching_deviation(self, rule_id: str, file: str) -> Optional[dict]:
        now = time.time()
        if self.is_mandatory(rule_id):
            return None  # a permit on a Mandatory guideline is void, whenever it was made
        for r in self.db.execute(
                "SELECT * FROM deviations WHERE rule_id=? AND revoked_at IS NULL", (rule_id,)):
            if r["expires"] and r["expires"] < now:
                continue
            if fnmatch.fnmatch(file, r["scope"]):
                return dict(r)
        return None

    @staticmethod
    def _deviation_for(rule_id: str, file: str, devs: dict[str, list[dict]],
                       now: float) -> Optional[dict]:
        """matching_deviation over preloaded permits (caller has already ruled
        out Mandatory guidelines)."""
        for r in devs.get(rule_id, []):
            if r["expires"] and r["expires"] < now:
                continue
            if fnmatch.fnmatch(file, r["scope"]):
                return r
        return None

    def deviations(self, include_revoked: bool = False) -> list[dict]:
        q = "SELECT * FROM deviations"
        if not include_revoked:
            q += " WHERE revoked_at IS NULL"
        return [dict(r) for r in self.db.execute(q + " ORDER BY ts")]

    def revoke_deviation(self, deviation_id: str, revoked_by: str = "",
                         source: str = "cli", reason: str = "") -> dict:
        r = self.db.execute("SELECT * FROM deviations WHERE id=?", (deviation_id,)).fetchone()
        if not r:
            return {"error": f"No deviation with id '{deviation_id}'."}
        if r["revoked_at"]:
            return {"error": f"Deviation '{deviation_id}' is already revoked."}
        self.db.execute("UPDATE deviations SET revoked_at=?, revoked_by=? WHERE id=?",
                        (time.time(), revoked_by, deviation_id))
        self.audit("revoke_deviation", deviation_id, actor=revoked_by, source=source,
                   details={"rule_id": r["rule_id"], "scope": r["scope"], "reason": reason},
                   commit=False)
        # Findings that were deviated only by this permit go back on the books.
        reopened = []
        for f in self.db.execute("SELECT fingerprint, file, rule_id FROM findings"
                                 " WHERE status='deviated' AND rule_id=?", (r["rule_id"],)).fetchall():
            if fnmatch.fnmatch(f["file"], r["scope"]) \
                    and not self.matching_deviation(f["rule_id"], f["file"]):
                self.db.execute("UPDATE findings SET status='open' WHERE fingerprint=?",
                                (f["fingerprint"],))
                reopened.append(f["fingerprint"])
        self.db.commit()
        return {"ok": True, "revoked": deviation_id, "rule_id": r["rule_id"],
                "findings_reopened": len(reopened)}

    # ------------------------------------------------- GRP (re-categorization)
    def add_recategorization(self, rule_id: str, to_category: str,
                             rationale: str, approver: str = "", source: str = "cli") -> None:
        """Record a Guideline Re-categorization Plan entry. Legality (which
        moves MISRA permits) is enforced by the caller (engine.recategorize).
        An entry it replaces is kept in the audit log."""
        self._require_resolvable(rule_id, "re-categorization")
        prev = self.db.execute("SELECT * FROM recategorizations WHERE rule_id=?",
                               (rule_id,)).fetchone()
        self.db.execute(
            "INSERT OR REPLACE INTO recategorizations"
            " (rule_id, to_category, rationale, approver, ts, source) VALUES (?,?,?,?,?,?)",
            (rule_id, to_category, rationale, approver, time.time(), source))
        self.audit("recategorize", rule_id, actor=approver, source=source,
                   details={"to_category": to_category, "rationale": rationale,
                            "replaced": dict(prev) if prev else None}, commit=False)
        self.db.commit()

    def recategorizations(self) -> dict[str, dict]:
        return {r["rule_id"]: dict(r)
                for r in self.db.execute("SELECT * FROM recategorizations ORDER BY rule_id")}

    def remove_recategorization(self, rule_id: str, removed_by: str = "",
                                source: str = "cli", reason: str = "") -> dict:
        from ..rules import REGISTRY
        meta = REGISTRY.get(rule_id) or REGISTRY.resolve(rule_id)
        rid = meta["id"] if meta else rule_id
        prev = self.db.execute("SELECT * FROM recategorizations WHERE rule_id=?",
                               (rid,)).fetchone()
        if not prev:
            return {"error": f"No re-categorization on record for '{rule_id}'."}
        self.db.execute("DELETE FROM recategorizations WHERE rule_id=?", (rid,))
        self.audit("remove_recategorization", rid, actor=removed_by, source=source,
                   details={"removed": dict(prev), "reason": reason}, commit=False)
        self.db.commit()
        return {"ok": True, "removed": rid, "was": prev["to_category"]}

    # ----------------------------------------------------------- suppressions
    def suppress(self, fingerprint: str, reason: str, approver: str = "",
                 source: str = "cli", expires_at: float | None = None,
                 rule_id: str | None = None) -> None:
        """Suppress one finding as a false positive.

        Raises MandatoryRuleError when the finding's rule is Mandatory after GRP
        re-categorization, and ValueError for an unknown fingerprint (unless the
        caller names ``rule_id``, as a SARIF import does for a finding that is
        not on record yet) or a past expiry. Replacing an earlier suppression
        keeps the earlier reason in the audit log.
        """
        f = self.get_finding(fingerprint)
        if not f and rule_id is None:
            raise ValueError(f"No finding with fingerprint '{fingerprint}'.")
        self._require_resolvable(f["rule_id"] if f else rule_id, "suppression", strict=False)
        self._require_not_mandatory(f["rule_id"] if f else rule_id, "suppression")
        now = time.time()
        if expires_at is not None and expires_at <= now:
            raise ValueError("The suppression's expiry is already in the past.")
        prev = self.db.execute("SELECT * FROM suppressions WHERE fingerprint=?",
                               (fingerprint,)).fetchone()
        self.db.execute(
            "INSERT OR REPLACE INTO suppressions"
            " (fingerprint, reason, ts, approver, source, expires) VALUES (?,?,?,?,?,?)",
            (fingerprint, reason, now, approver, source, expires_at))
        self.db.execute("UPDATE findings SET status='suppressed' WHERE fingerprint=?",
                        (fingerprint,))
        self.audit("suppress", fingerprint, actor=approver, source=source,
                   details={"rule_id": f["rule_id"] if f else rule_id, "reason": reason,
                            "expires": expires_at,
                            "replaced": dict(prev) if prev else None}, commit=False)
        self.db.commit()

    def is_suppressed(self, fingerprint: str) -> bool:
        r = self.db.execute("SELECT expires FROM suppressions WHERE fingerprint=?",
                            (fingerprint,)).fetchone()
        return r is not None and not (r["expires"] and r["expires"] < time.time())

    def suppressions(self) -> list[dict]:
        return [dict(r) for r in self.db.execute("SELECT * FROM suppressions ORDER BY ts")]

    def unsuppress(self, fingerprint: str, removed_by: str = "", source: str = "cli",
                   reason: str = "") -> dict:
        prev = self.db.execute("SELECT * FROM suppressions WHERE fingerprint=?",
                               (fingerprint,)).fetchone()
        if not prev:
            return {"error": f"No suppression on record for '{fingerprint}'."}
        self.db.execute("DELETE FROM suppressions WHERE fingerprint=?", (fingerprint,))
        f = self.get_finding(fingerprint)
        if f and f["status"] == "suppressed":
            status = "deviated" if self.matching_deviation(f["rule_id"], f["file"]) else "open"
            self.db.execute("UPDATE findings SET status=? WHERE fingerprint=?",
                            (status, fingerprint))
        self.audit("unsuppress", fingerprint, actor=removed_by, source=source,
                   details={"removed": dict(prev), "reason": reason}, commit=False)
        self.db.commit()
        return {"ok": True, "unsuppressed": fingerprint}

    # ------------------------------------------------------------- proposals
    def add_proposal(self, kind: str, payload: dict, summary: str = "",
                     source: str = "mcp") -> str:
        pid = uuid.uuid4().hex[:12]
        self.db.execute(
            "INSERT INTO proposals (id, ts, kind, payload, summary, source) VALUES (?,?,?,?,?,?)",
            (pid, time.time(), kind, json.dumps(payload), summary, source))
        self.audit("propose_" + kind, pid, actor="", source=source,
                   details={"summary": summary, "payload": payload}, commit=False)
        self.db.commit()
        return pid

    @staticmethod
    def _proposal_row(r) -> dict:
        d = dict(r)
        d["payload"] = json.loads(d["payload"])
        d["result"] = json.loads(d["result"]) if d["result"] else None
        return d

    def get_proposal(self, pid: str) -> Optional[dict]:
        r = self.db.execute("SELECT * FROM proposals WHERE id=?", (pid,)).fetchone()
        return self._proposal_row(r) if r else None

    def proposals(self, status: str | None = "pending_human") -> list[dict]:
        q, args = "SELECT * FROM proposals", []
        if status:
            q += " WHERE status=?"
            args.append(status)
        return [self._proposal_row(r) for r in self.db.execute(q + " ORDER BY ts", args)]

    def decide_proposal(self, pid: str, status: str, decided_by: str,
                        note: str = "", result: dict | None = None,
                        actor_context: dict | None = None) -> None:
        self.db.execute(
            "UPDATE proposals SET status=?, decided_by=?, decided_at=?, decision_note=?, result=?"
            " WHERE id=?", (status, decided_by, time.time(), note,
                            json.dumps(result, default=str) if result is not None else None, pid))
        self.audit(f"proposal_{status}", pid, actor=decided_by, source="cli",
                   details={"note": note, "result": result,
                            **({"actor_context": actor_context} if actor_context else {})},
                   commit=False)
        self.db.commit()

    # ----------------------------------------------------------------- notes
    def add_note(self, content: str, topic: str = "", tags: str = "") -> str:
        nid = uuid.uuid4().hex[:12]
        self.db.execute("INSERT INTO notes VALUES (?,?,?,?,?)",
                        (nid, topic, content, tags, time.time()))
        self.db.commit()
        return nid

    def search_notes(self, query: str, limit: int = 10) -> list[dict]:
        # % and _ in the query are literal characters, not LIKE wildcards.
        esc = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        like = f"%{esc}%"
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM notes WHERE content LIKE ? ESCAPE '\\' OR topic LIKE ? ESCAPE '\\'"
            " OR tags LIKE ? ESCAPE '\\' ORDER BY ts DESC LIMIT ?",
            (like, like, like, limit))]

    def all_notes(self, limit: int = 50) -> list[dict]:
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM notes ORDER BY ts DESC LIMIT ?", (limit,))]

    # --------------------------------------------------------------- sessions
    def create_session(self, config: dict) -> str:
        sid = uuid.uuid4().hex[:12]
        now = time.time()
        self.db.execute("INSERT INTO sessions (id, config, history, started, updated)"
                        " VALUES (?,?,?,?,?)",
                        (sid, json.dumps(config), "[]", now, now))
        self.db.commit()
        return sid

    def latest_session(self) -> Optional[dict]:
        r = self.db.execute("SELECT id FROM sessions ORDER BY started DESC LIMIT 1").fetchone()
        return self.get_session(r["id"]) if r else None

    def get_session(self, sid: str) -> Optional[dict]:
        r = self.db.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["config"] = json.loads(d["config"] or "{}")
        d["history"] = json.loads(d["history"] or "[]")
        return d

    def create_session_if_free(self, config: dict, force: bool = False) -> tuple[str | None, dict | None]:
        """Atomically check for an active session and create a new one.

        Returns (session_id, None) or (None, existing_active_session). The check
        and the insert share one write transaction (BEGIN IMMEDIATE), so two
        processes starting a session at once cannot both succeed."""
        self.db.commit()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            r = self.db.execute(
                f"SELECT id FROM sessions WHERE status NOT IN ({_TERMINAL_SQL})"
                " ORDER BY started DESC LIMIT 1").fetchone()
            if r and not force:
                self.db.execute("ROLLBACK")
                return None, self.get_session(r["id"])
            sid = uuid.uuid4().hex[:12]
            now = time.time()
            self.db.execute("INSERT INTO sessions (id, config, history, started, updated)"
                            " VALUES (?,?,?,?,?)", (sid, json.dumps(config), "[]", now, now))
            self.db.execute("COMMIT")
            return sid, None
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def delete_session(self, sid: str) -> None:
        """Drop a session that never started (its baseline scan failed)."""
        self.db.execute("DELETE FROM sessions WHERE id=?", (sid,))
        self.db.commit()

    def update_session(self, sid: str, *, status: str | None = None,
                       iteration: int | None = None,
                       history: list | None = None,
                       end_reason: str | None = None,
                       expect_status: str | None = None,
                       expect_iteration: int | None = None) -> bool:
        """Write session fields. With ``expect_status`` / ``expect_iteration`` the
        write is a compare-and-set: it applies only if the row still has that
        status/iteration, so a slow verify cannot overwrite a concurrent abort or
        another verify. Returns False when nothing was written."""
        sets, args = ["updated=?"], [time.time()]
        if status is not None:
            sets.append("status=?"); args.append(status)
            if status in TERMINAL_SESSION_STATES:
                sets.append("ended=?"); args.append(time.time())
        if end_reason is not None:
            sets.append("end_reason=?"); args.append(end_reason)
        if iteration is not None:
            sets.append("iteration=?"); args.append(iteration)
        if history is not None:
            sets.append("history=?"); args.append(json.dumps(history))
        args.append(sid)
        where = "id=?"
        if expect_status is not None:
            where += " AND status=?"; args.append(expect_status)
        if expect_iteration is not None:
            where += " AND iteration=?"; args.append(expect_iteration)
        cur = self.db.execute(f"UPDATE sessions SET {', '.join(sets)} WHERE {where}", args)
        self.db.commit()
        return cur.rowcount > 0

    def latest_active_session(self) -> Optional[dict]:
        """The newest session that has not ended (active, awaiting_verification
        or analysis_incomplete)."""
        r = self.db.execute(
            f"SELECT id FROM sessions WHERE status NOT IN ({_TERMINAL_SQL})"
            " ORDER BY started DESC LIMIT 1").fetchone()
        return self.get_session(r["id"]) if r else None

    # ------------------------------------------------------------------ stats
    def stats(self) -> dict:
        by_status = {r["status"]: r["n"] for r in self.db.execute(
            "SELECT status, COUNT(*) n FROM findings GROUP BY status")}
        by_std = {r["standard"]: r["n"] for r in self.db.execute(
            "SELECT standard, COUNT(*) n FROM findings"
            " WHERE status IN ('open','regressed') GROUP BY standard")}
        return {
            "findings_by_status": by_status,
            "open_by_standard": by_std,
            "deviations": self.db.execute("SELECT COUNT(*) n FROM deviations").fetchone()["n"],
            "suppressions": self.db.execute("SELECT COUNT(*) n FROM suppressions").fetchone()["n"],
            "notes": self.db.execute("SELECT COUNT(*) n FROM notes").fetchone()["n"],
            "fix_attempts": self.db.execute("SELECT COUNT(*) n FROM fix_attempts").fetchone()["n"],
        }
