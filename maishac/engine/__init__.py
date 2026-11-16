"""The engineered fix loop.

Maisha deliberately splits responsibilities:

  deterministic side (this engine)      probabilistic side (the IDE's LLM)
  ------------------------------------  ----------------------------------
  scanning, fingerprinting, memory      reading code, writing the fix
  prioritization and batching           choosing a strategy
  verification and regression diffing   explaining/deviating when justified
  budgets, stall & oscillation guards

The loop, as seen by the host agent:

    begin  -> baseline scan, memory sync, session created
    repeat:
      next_batch -> small, file-grouped batch of findings + per-finding brief
                    (rule guidance, previously FAILED strategies to avoid,
                    relevant project memory notes)
      [agent records intended strategy, edits code]
      verify     -> rescan, memory sync, diff (resolved/new/regressed),
                    convergence decision
    until state in {converged, budget_exhausted, stalled}

Guards:
  * iteration budget         hard cap on loop turns
  * stall detection          N consecutive verifies with no net progress
  * oscillation detection    a finding that resolves then regresses twice is
                             frozen ("needs_human") so the agent stops thrashing
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import shlex
import signal
import subprocess
import time
from pathlib import Path

from ..analyzers import ALL_ANALYZERS, run_scan_detailed
from ..analyzers.base import validate_compiler_flags
from ..model import relpath
from ..memory import (TERMINAL_SESSION_STATES, MandatoryRuleError, MemoryStore,
                      requires_human)
from ..rules import REGISTRY

DEFAULT_CONFIG = {
    "max_iterations": 10,
    "batch_size": 5,
    "stall_limit": 2,           # consecutive no-progress verifies before stalling
    "oscillation_limit": 2,     # regress_count at which a finding is frozen
    "severity_floor": "minor",  # ignore anything below this
    "analyzers": None,          # None = all available
    # How a finding is allowed to leave the queue as 'resolved':
    #   analyzer_only  the analyzer stopped flagging it (NOT recommended for
    #                  compliance work — the analyzer is the only judge of its
    #                  own blind spot; see the sentinel-cast trap in the tests)
    #   test_gated     a configured test/build command must exit 0 first
    #   human_gated    a human must call approve_finding first
    # None => auto: test_gated if test_command is set, else human_gated.
    "verification_policy": None,
    "test_command": None,       # argv-style command (shlex, no shell); exit 0 confirms pending fixes.
                                # Human-set only: CLI flag, MAISHAC_TEST_COMMAND or .maishac/config.json
    "test_timeout": None,       # seconds; default 600 (MAISHAC_TEST_TIMEOUT / config.json / --test-timeout)
    "include_paths": None,      # -I dirs forwarded to cppcheck/clang-tidy
    "exclude": None,            # extra fnmatch patterns for directories to skip
    "default_excludes": True,   # also skip .git, build, node_modules, ... (see analyzers.base)
    "std": None,                # C standard for compiler/clang-tidy (default c11)
    "compiler_flags": None,     # extra -D/-U/-I/-std flags (closed list, validated)
    "compile_commands": None,   # compile_commands.json to take per-file flags from
}

# Human sign-off kinds an MCP agent may only *propose* (see LoopEngine.propose).
PROPOSAL_KINDS = ("approve", "deviate", "suppress", "recategorize")
MIN_JUSTIFICATION = 15   # chars: deviation rationale
MIN_REASON = 10          # chars: suppression reason
DEFAULT_TEST_TIMEOUT = 600

ALLOW_AGENT_APPROVALS_ENV = "MAISHAC_ALLOW_AGENT_APPROVALS"


def agent_approvals_allowed() -> bool:
    """True when the operator opted in to letting MCP tools approve, deviate,
    suppress and recategorize directly. Unsafe: the agent then grades its own work."""
    return os.environ.get(ALLOW_AGENT_APPROVALS_ENV, "").strip().lower() in ("1", "true", "yes")


def load_project_config(root: Path) -> dict:
    """Human-controlled settings from <project>/.maishac/config.json (test_command,
    test_timeout). Unreadable/invalid files are ignored with no effect."""
    try:
        data = json.loads((Path(root) / ".maishac" / "config.json").read_text("utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _parse_expiry(expires_days, expires) -> tuple[float | None, str]:
    """-> (absolute expiry timestamp or None, error). ``expires`` is YYYY-MM-DD and
    means the END of that day (local time); ``expires_days`` is a lifetime from now."""
    at = None
    if expires_days not in (None, 0, 0.0):
        try:
            days = float(expires_days)
        except (TypeError, ValueError):
            return None, f"expires_days must be a number (got '{expires_days}')."
        if days < 0:
            return None, "expires_days must not be negative."
        at = time.time() + days * 86400
    if expires:
        try:
            d = _dt.datetime.strptime(str(expires), "%Y-%m-%d")
        except ValueError:
            return None, f"expires must be YYYY-MM-DD (got '{expires}')."
        at = d.replace(hour=23, minute=59, second=59).timestamp()
        if at <= time.time():
            return None, f"expires {expires} is already in the past."
    return at, ""


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill the test command AND everything it spawned."""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=30)
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        proc.kill()
    except OSError:
        pass


_VALID_POLICIES = ("analyzer_only", "test_gated", "human_gated")

_SEV_ORDER = ["blocker", "critical", "major", "minor", "info"]
ANALYZER_NAMES = [cls.name for cls in ALL_ANALYZERS]


def _is_imported(f: dict) -> bool:
    """A finding that came from an imported SARIF file only (native rescans
    cannot judge it, so it never counts toward a session's convergence)."""
    parts = (f.get("analyzer") or "").split("+")
    return bool(f.get("analyzer")) and all(a.startswith("sarif:") for a in parts)


def validate_analyzer_names(names) -> str:
    """Error message for an unknown analyzer name, or ''."""
    if names is None:
        return ""
    if isinstance(names, str) or not all(isinstance(n, str) for n in names):
        return f"analyzers must be a list of names (valid: {', '.join(ANALYZER_NAMES)})."
    bad = [n for n in names if n not in ANALYZER_NAMES]
    if bad:
        return (f"Unknown analyzer(s): {', '.join(bad)}. "
                f"Valid names: {', '.join(ANALYZER_NAMES)}.")
    return ""


FAIL_ON_CHOICES = [*_SEV_ORDER, "any", "none"]

# CI gate exit codes (`maishac scan --fail-on ...`, `maishac gate`).
EXIT_OK, EXIT_FINDINGS, EXIT_DEGRADED = 0, 1, 2


def gate_verdict(result: dict, fail_on: str, allow_degraded: bool = False) -> dict:
    """Turn a scan() result into a CI verdict.

    ``fail_on`` is a severity (blocker|critical|major|minor|info: fail when an
    open finding of that severity or worse exists), ``any`` (any open finding,
    same as ``info``) or ``none`` (never fail on findings, only on a degraded
    analysis). Exit codes: 1 findings at/above the threshold; 2 the analysis was
    degraded (an analyzer failed or crashed, or a recommended analyzer is not
    installed) and ``allow_degraded`` is False; 0 otherwise. Findings win over
    degradation: they are real whatever else is missing, whereas a degraded run
    only makes a clean result untrustworthy, so a failing build never reads as
    "tool problem" when it actually has violations."""
    if fail_on not in FAIL_ON_CHOICES:
        raise ValueError(f"Unknown --fail-on '{fail_on}'. Valid: {', '.join(FAIL_ON_CHOICES)}.")
    counts = result.get("open_by_severity", {})
    if fail_on == "none":
        blocking = 0
    else:
        floor = "info" if fail_on == "any" else fail_on
        blocking = sum(counts.get(sev, 0) for sev in _severities_at_or_above(floor))
    errors = result.get("analyzer_errors") or []
    toolchain = result.get("toolchain") or {}
    degraded = bool(errors or toolchain.get("degraded"))
    if blocking:
        code, why = EXIT_FINDINGS, (
            f"{blocking} open finding(s) at or above '{fail_on}'.")
    elif degraded and not allow_degraded:
        code, why = EXIT_DEGRADED, (
            "analysis degraded: " + ("; ".join(f"{e['analyzer']} {e['status']}" for e in errors)
                                     if errors else "a recommended analyzer is not installed")
            + ". A clean result cannot be trusted (pass --allow-degraded to accept it).")
    else:
        code, why = EXIT_OK, "gate passed."
    return {"fail_on": fail_on, "allow_degraded": allow_degraded, "exit_code": code,
            "blocking_findings": blocking, "degraded": degraded, "reason": why}


def _severities_at_or_above(floor: str) -> list[str]:
    idx = _SEV_ORDER.index(floor) if floor in _SEV_ORDER else 3
    return _SEV_ORDER[: idx + 1]


class LoopEngine:
    def __init__(self, project_root: str | Path, source: str = "cli"):
        self.root = Path(project_root).resolve()
        self.mem = MemoryStore(self.root)
        self.source = source   # cli|mcp: recorded on every audited action

    def close(self) -> None:
        """Release the project's SQLite connection."""
        self.mem.close()

    def __enter__(self) -> "LoopEngine":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------ scan
    def _effective_gate(self, gate: bool) -> bool:
        """An MCP-originated scan always runs gated: an agent that edits code and
        rescans must not see its own findings go straight to ``resolved``. Only
        the operator's MAISHAC_ALLOW_AGENT_APPROVALS=1 lifts this."""
        if self.source == "mcp" and not agent_approvals_allowed():
            return True
        return gate

    def scan(self, paths: list[str], analyzers: list[str] | None = None,
             gate: bool = False, include_paths: list[str] | None = None,
             exclude: list[str] | None = None, default_excludes: bool = True,
             std: str | None = None, compiler_flags: list[str] | None = None,
             compile_commands: str | None = None, kind: str = "scan",
             hold_for_human: bool = False) -> dict:
        gate = self._effective_gate(gate)
        err = validate_analyzer_names(analyzers)
        if err:
            return {"error": err}
        flags = validate_compiler_flags(compiler_flags)
        options = {"std": std, "compiler_flags": flags, "compile_commands": compile_commands}
        sr = run_scan_detailed(paths, self.root, analyzers, include_paths,
                               exclude, default_excludes, options)
        if not sr.files:
            # Zero files means zero evidence. Syncing it would report "0 open"
            # and let a session converge on a typo'd path.
            return {"error": "No C source files (.c/.h) were found under "
                             f"{', '.join(map(str, paths)) or '(no paths)'}; nothing was scanned, "
                             "so no result can be given. Check the paths and exclude patterns.",
                    "files_scanned": 0}
        findings = sr.findings
        used = sr.analyzers_used
        scanned = [relpath(f, self.root) for f in sr.files]
        # Only files an analyzer really analyzed can have findings cleared by
        # it: a crashed/timed-out/non-compiling run must never look like a fix.
        # Findings in files that have since been deleted are closed as stale.
        removed = {f for f in self.mem.tracked_files() if not (self.root / f).exists()}
        diff = self.mem.sync_scan(findings, scanned, gate=gate, analyzed=sr.analyzed,
                                  removed_files=removed, hold_for_human=hold_for_human)
        # Every scan states what it could NOT check. Without this a native-only
        # run returns a clean result indistinguishable from a full-toolchain
        # clean result, which silently overstates compliance.
        from ..coverage import analyzer_failure_warning, toolchain_status, toolchain_warning
        tc = toolchain_status(analyzers)
        errors = sr.errors
        # Scan log: what this run did and did not check, for reports.
        from ..coverage import toolchain_snapshot
        self.mem.record_scan(kind, list(paths), len(scanned), used, errors,
                             toolchain_snapshot(tc), bool(tc["degraded"] or errors))
        open_rows = self.mem.open_findings(limit=100000)
        out = {
            "analyzers_used": used,
            "files_scanned": len(scanned),
            "total_findings": len(findings),
            "diff": {k: len(v) for k, v in diff.items()},
            "open": len(open_rows),
            "open_imported": sum(_is_imported(f) for f in open_rows),
            "open_by_severity": {sev: sum(f["severity"] == sev for f in open_rows)
                                 for sev in _SEV_ORDER},
            "pending_verification": self.mem.count_pending(),
            "toolchain": tc,
            "analyzer_errors": errors,
            "analysis_complete": not errors,
        }
        warnings = [w for w in (toolchain_warning(tc) if tc["degraded"] else "",
                                analyzer_failure_warning(errors)) if w]
        if warnings:
            out["coverage_warning"] = "\n".join(warnings)
        return out

    def _resolve_input_path(self, path: str | Path) -> Path:
        """A relative path is looked up under the project root first (as the tool
        docs say), then under the current directory."""
        p = Path(path)
        if p.is_absolute():
            return p
        for base in (self.root, Path.cwd()):
            if (base / p).exists():
                return base / p
        return self.root / p      # not found anywhere: report the project-relative path

    def import_sarif(self, path: str | Path, carry_suppressions: bool = True,
                     gate: bool = True) -> dict:
        """Ingest findings from an external SARIF file (e.g. a qualified engine
        like Helix QAC / Polyspace, or cppcheck's own --sarif output) into the
        same memory/loop/gate machinery as a native scan. Imported findings are
        not cleared by native rescans (see sync_scan producers).

        SARIF ``result.suppressions`` are honored: a finding the engine already
        marked suppressed/baselined is imported as *suppressed* (with its
        justification preserved) rather than resurfacing as a fresh violation —
        this is how a team brings its existing triage across.

        Re-importing a newer file from the same tool is how imported findings get
        resolved: one that is absent from the new import, in a file the new run
        covers, is cleared (``pending_verification`` when ``gate`` is True, so a
        person still confirms it with ``approve``; ``resolved`` otherwise).
        Findings of other tools, and files the run does not mention, are left alone."""
        from .. import report as report_mod
        src = self._resolve_input_path(path)
        data = json.loads(src.read_text("utf-8"))
        gate = self._effective_gate(gate)
        findings = report_mod.parse_sarif(data, self.root)
        # Pre-record incoming suppressions so sync_scan buckets them as
        # suppressed instead of new/open (bring-your-own-triage).
        carried, refused, ignored = 0, 0, 0
        for f in findings:
            if not f.suppression:
                continue
            if not carry_suppressions:
                ignored += 1       # an agent-driven import must not launder findings
            elif self.mem.is_mandatory(f.rule_id):
                refused += 1       # Mandatory guidelines admit no suppression
            else:
                self.mem.suppress(f.fingerprint, f.suppression.get("justification")
                                  or "suppressed in imported SARIF",
                                  approver="sarif-import", source="import",
                                  rule_id=f.rule_id)
                carried += 1
        scope = report_mod.sarif_scope(data, self.root)
        covered = set().union(*scope.values()) if scope else set()
        diff = self.mem.sync_scan(findings, sorted(covered), gate=gate, analyzed=scope)
        tools = sorted({f.analyzer for f in findings})
        # Imports run no analyzer here, so there is no toolchain to snapshot;
        # the row records provenance only and is not an analysis run.
        self.mem.record_scan("import", [str(path)], 0, tools, [], {}, False)
        return {
            "source": str(path),
            "tools": tools,
            "imported": len(findings),
            "suppressions_carried": carried,
            **({"suppressions_refused_mandatory": refused,
                "warning": f"{refused} imported suppression(s) target MISRA Mandatory "
                           "guidelines and were NOT applied; those findings stay open."}
               if refused else {}),
            **({"suppressions_ignored": ignored,
                "note": f"{ignored} suppression(s) in the SARIF were not applied because "
                        "this import was started by an agent; run `maishac import` from "
                        "the CLI to carry them over."} if ignored else {}),
            "diff": {k: len(v) for k, v in diff.items()},
            "open": len(self.mem.open_findings(limit=100000)),
        }

    def check_snippet(self, code: str, filename: str = "draft.c") -> dict:
        """Proactively lint a draft source string in memory — no scan record,
        no memory writes — so an agent can self-correct *before* writing to a
        file. Native (lexical) checks only: cppcheck/clang-tidy need a real file
        and build model, so this catches the syntactic MISRA/CERT/BARR subset,
        not the whole-program rules. Each finding carries a fix hint so the
        agent can rewrite the line compliantly on the spot."""
        from ..analyzers.native import NativeAnalyzer
        from .. import patterns as patterns_mod
        findings = NativeAnalyzer().analyze_source(code, filename, self.root)

        def _brief_finding(f):
            pats = patterns_mod.for_rule(f.rule_id)
            out = {
                "rule_id": f.rule_id, "standard": f.standard, "severity": f.severity,
                "line": f.line, "message": f.message,
                "fix_hint": f.fix_hint or (REGISTRY.get(f.rule_id) or {}).get("fix", ""),
                "rule_summary": (REGISTRY.get(f.rule_id) or {}).get("summary", ""),
                "equivalent_rules": f.cross_refs,
            }
            if pats:  # teach the compliant idiom, not just the violation
                out["compliant_pattern"] = {"prefer": pats[0]["prefer"], "why": pats[0]["why"]}
            return out

        return {
            "filename": filename,
            "clean": not findings,
            "findings": [_brief_finding(f) for f in findings],
        }

    def guidance(self, topic: str, limit: int = 5) -> dict:
        """Proactive author-time lookup: given what you're about to write, return
        the compliant idioms to reach for (avoid/prefer/why + the rules each
        satisfies). Use BEFORE writing, so the code is compliant on first draft."""
        from .. import patterns as patterns_mod
        return {"topic": topic, "patterns": patterns_mod.guidance(topic, limit)}

    @staticmethod
    def _scan_kwargs(cfg: dict) -> dict:
        """Session config -> scan() keyword arguments."""
        return {"include_paths": cfg.get("include_paths"),
                "exclude": cfg.get("exclude"),
                "default_excludes": cfg.get("default_excludes", True),
                "std": cfg.get("std"),
                "compiler_flags": cfg.get("compiler_flags"),
                "compile_commands": cfg.get("compile_commands")}

    @staticmethod
    def _policy(cfg: dict) -> str:
        p = cfg.get("verification_policy")
        if p in _VALID_POLICIES:
            return p
        return "test_gated" if cfg.get("test_command") else "human_gated"

    def _run_tests(self, cmd: str, timeout: float | None = None) -> dict:
        """Run the human-configured test command. It is split with shlex and run
        WITHOUT a shell (no injection through metacharacters; use `sh -c '...'`
        explicitly if pipes or && are needed). It gets its own process group so a
        timeout kills the whole tree, not just the top process."""
        # ponytail: pass/fail on exit code only — doesn't diff new-vs-baseline
        # failures. Add a baseline capture if a flaky suite needs delta scoring.
        timeout = DEFAULT_TEST_TIMEOUT if timeout in (None, 0) else float(timeout)
        try:
            argv = shlex.split(cmd, posix=os.name != "nt")
            if not argv:
                raise ValueError("test command is empty")
            popen_kw = ({"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
                        if os.name == "nt" else {"start_new_session": True})
            proc = subprocess.Popen(argv, cwd=self.root, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, errors="replace", **popen_kw)
        except Exception as e:  # noqa: BLE001 — surface any launch failure to the loop
            return {"ran": False, "passed": False, "error": str(e), "command": cmd}
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_tree(proc)
            try:
                out, err = proc.communicate(timeout=10)
            except Exception:  # noqa: BLE001
                out, err = "", ""
            return {"ran": False, "passed": False, "timed_out": True, "command": cmd,
                    "error": f"test command timed out after {timeout:g}s and was killed",
                    "output_tail": ((out or "") + (err or ""))[-2000:]}
        except Exception as e:  # noqa: BLE001
            _kill_tree(proc)
            return {"ran": False, "passed": False, "error": str(e), "command": cmd}
        return {"ran": True, "passed": proc.returncode == 0, "exit_code": proc.returncode,
                "command": cmd, "output_tail": ((out or "") + (err or ""))[-2000:]}

    # MISRA Compliance:2020 §5.4: which re-categorizations are permitted, keyed
    # by the guideline's *original* category. A Mandatory guideline may not be
    # re-categorized at all; a Required guideline may not become Advisory or
    # Disapplied (only Mandatory); Advisory may go anywhere.
    _GRP_ALLOWED = {
        "mandatory": set(),
        "required": {"mandatory"},
        "advisory": {"mandatory", "required", "disapplied"},
    }

    # ----------------------------------------------- audited human sign-offs
    # Every method below is the single implementation behind both the CLI and the
    # MCP tools, so validation cannot drift. An MCP agent reaches them only via
    # propose()/accept_proposal() unless the operator set
    # MAISHAC_ALLOW_AGENT_APPROVALS=1.

    def _check_recategorize(self, rule, to_category, rationale, approver="") -> dict:
        meta = REGISTRY.resolve(rule)
        if not meta:
            return {"error": REGISTRY.resolve_error(rule)}
        target = (to_category or "").strip().lower()
        valid = {"mandatory", "required", "advisory", "disapplied"}
        if target not in valid:
            return {"error": f"to_category must be one of {sorted(valid)} (got '{to_category}')"}
        if not (rationale or "").strip():
            return {"error": "a rationale is required for a re-categorization"}
        current = (meta.get("category") or "required").lower()
        if target != current and target not in self._GRP_ALLOWED.get(current, set()):
            return {"error": f"MISRA Compliance:2020 forbids re-categorizing a "
                             f"{current.capitalize()} guideline to {target.capitalize()} "
                             f"({meta['id']}). Allowed from {current}: "
                             f"{sorted(self._GRP_ALLOWED.get(current, set())) or 'none'}."}
        return {"rule": meta["id"], "to_category": target, "rationale": rationale.strip(),
                "approver": (approver or "").strip(), "_current": current}

    def recategorize(self, rule: str, to_category: str, rationale: str,
                     approver: str = "", source: str | None = None) -> dict:
        """Record a GRP re-categorization, enforcing MISRA's legality rules."""
        c = self._check_recategorize(rule, to_category, rationale, approver)
        if "error" in c:
            return c
        self.mem.add_recategorization(c["rule"], c["to_category"], c["rationale"],
                                      c["approver"], source or self.source)
        return {"rule_id": c["rule"], "from_category": c["_current"],
                "to_category": c["to_category"], "approver": c["approver"] or None}

    def _check_approve(self, fingerprint, approved_by="", need_identity=True) -> dict:
        f = self.mem.get_finding(fingerprint)
        if not f:
            return {"error": f"No finding with fingerprint '{fingerprint}'."}
        if need_identity and not (approved_by or "").strip():
            return {"error": "approved_by is required — record who signed off on this fix."}
        if f["status"] not in ("pending_verification", "resolved"):
            return {"error": f"Finding is '{f['status']}', not pending_verification — the "
                             "analyzer still flags it. Fix it (and re-verify) before approving."}
        return {"fingerprint": fingerprint, "approved_by": (approved_by or "").strip()}

    def approve(self, fingerprint: str, approved_by: str, source: str | None = None) -> dict:
        c = self._check_approve(fingerprint, approved_by)
        if "error" in c:
            return c
        return self.mem.approve_finding(fingerprint, c["approved_by"], source or self.source)

    def _check_deviate(self, rule, scope="*", justification="", approver="",
                       expires_days=None, expires=None) -> dict:
        meta = REGISTRY.resolve(rule)
        if not meta:
            return {"error": REGISTRY.resolve_error(rule)}
        if len((justification or "").strip()) < MIN_JUSTIFICATION:
            return {"error": "Justification too short; write a real engineering rationale "
                             f"(at least {MIN_JUSTIFICATION} characters)."}
        if not (scope or "").strip():
            return {"error": "scope must be a non-empty glob over project-relative paths."}
        at, err = _parse_expiry(expires_days, expires)
        if err:
            return {"error": err}
        if self.mem.is_mandatory(meta["id"]):
            return {"error": f"{meta['id']} is a MISRA Mandatory guideline; deviations are "
                             "not permitted against it. It must be fixed, not waived."}
        return {"rule": meta["id"], "scope": scope.strip(), "justification": justification.strip(),
                "approver": (approver or "").strip(), "expires_at": at}

    def deviate(self, rule: str, scope: str = "*", justification: str = "", approver: str = "",
                expires_days: float | None = None, expires: str | None = None,
                source: str | None = None) -> dict:
        c = self._check_deviate(rule, scope, justification, approver, expires_days, expires)
        if "error" in c:
            return c
        try:
            did = self.mem.add_deviation(c["rule"], c["scope"], c["justification"],
                                         c["approver"], expires_at=c["expires_at"],
                                         source=source or self.source)
        except (MandatoryRuleError, ValueError) as e:
            return {"error": str(e)}
        return {"deviation_id": did, "rule_id": c["rule"], "scope": c["scope"],
                "note": "Re-run scan or verify to apply."}

    def _check_suppress(self, fingerprint, reason="", approver="",
                        expires_days=None, expires=None) -> dict:
        f = self.mem.get_finding(fingerprint)
        if not f:
            return {"error": f"No finding with fingerprint '{fingerprint}'."}
        if len((reason or "").strip()) < MIN_REASON:
            return {"error": "Reason too short; explain why the analyzer is wrong here "
                             f"(at least {MIN_REASON} characters)."}
        at, err = _parse_expiry(expires_days, expires)
        if err:
            return {"error": err}
        if self.mem.is_mandatory(f["rule_id"]):
            return {"error": f"{f['rule_id']} is a MISRA Mandatory guideline; suppression is "
                             "not permitted against it. It must be fixed, not waived."}
        return {"fingerprint": fingerprint, "reason": reason.strip(),
                "approver": (approver or "").strip(), "expires_at": at}

    def suppress(self, fingerprint: str, reason: str, approver: str = "",
                 expires_days: float | None = None, expires: str | None = None,
                 source: str | None = None) -> dict:
        c = self._check_suppress(fingerprint, reason, approver, expires_days, expires)
        if "error" in c:
            return c
        try:
            self.mem.suppress(fingerprint, c["reason"], c["approver"],
                              source or self.source, c["expires_at"])
        except (MandatoryRuleError, ValueError) as e:
            return {"error": str(e)}
        return {"suppressed": fingerprint}

    # --------------------------------------------------------- revocations
    def unsuppress(self, fingerprint: str, removed_by: str = "", reason: str = "",
                   source: str | None = None) -> dict:
        return self.mem.unsuppress(fingerprint, removed_by, source or self.source, reason)

    def revoke_deviation(self, deviation_id: str, revoked_by: str = "", reason: str = "",
                         source: str | None = None) -> dict:
        return self.mem.revoke_deviation(deviation_id, revoked_by, source or self.source, reason)

    def remove_recategorization(self, rule: str, removed_by: str = "", reason: str = "",
                                source: str | None = None) -> dict:
        meta = REGISTRY.resolve(rule)
        if not meta:
            return {"error": REGISTRY.resolve_error(rule)}
        return self.mem.remove_recategorization(meta["id"], removed_by,
                                                source or self.source, reason)

    # ------------------------------------------------------------- proposals
    _CHECKS = {"approve": "_check_approve", "deviate": "_check_deviate",
               "suppress": "_check_suppress", "recategorize": "_check_recategorize"}
    # which payload key carries the human who takes responsibility on accept
    _IDENTITY_KEY = {"approve": "approved_by", "deviate": "approver",
                     "suppress": "approver", "recategorize": "approver"}

    def propose(self, kind: str, **args) -> dict:
        """Record a sign-off an agent asked for. Nothing takes effect until a human
        runs `maishac proposals accept <id> --by <name>` (or the direct command)."""
        if kind not in PROPOSAL_KINDS:
            return {"error": f"Unknown proposal kind '{kind}'."}
        check = getattr(self, self._CHECKS[kind])
        c = (check(args.get("fingerprint"), args.get("approved_by", ""), need_identity=False)
             if kind == "approve" else check(**args))
        if "error" in c:
            return c
        payload = {k: v for k, v in args.items() if v not in (None, "")}
        if kind in ("deviate", "recategorize"):
            payload["rule"] = c["rule"]   # store the canonical id, not the typed form
        summary = self._summarize(kind, payload)
        pid = self.mem.add_proposal(kind, payload, summary, source=self.source)
        return {"proposal_id": pid, "status": "pending_human", "summary": summary,
                "note": "NOT applied. A human must finalize it with the CLI: "
                        f"`maishac proposals accept {pid} --by <name>` "
                        "(list pending ones with `maishac proposals list`). "
                        "Tell the user this is awaiting their decision; do not retry."}

    @staticmethod
    def _summarize(kind: str, p: dict) -> str:
        if kind == "approve":
            return f"approve fix for finding {p.get('fingerprint')}"
        if kind == "suppress":
            return f"suppress finding {p.get('fingerprint')}: {p.get('reason', '')[:80]}"
        if kind == "deviate":
            return f"deviate from {p.get('rule')} in '{p.get('scope', '*')}': " \
                   f"{p.get('justification', '')[:80]}"
        return f"recategorize {p.get('rule')} to {p.get('to_category')}: {p.get('rationale', '')[:80]}"

    def accept_proposal(self, pid: str, by: str) -> dict:
        by = (by or "").strip()
        if not by:
            return {"error": "--by is required: record the human who accepts this."}
        prop = self.mem.get_proposal(pid)
        if not prop:
            return {"error": f"No proposal '{pid}'."}
        if prop["status"] != "pending_human":
            return {"error": f"Proposal '{pid}' is already {prop['status']}."}
        payload = dict(prop["payload"])
        payload[self._IDENTITY_KEY[prop["kind"]]] = by
        method = {"approve": self.approve, "deviate": self.deviate,
                  "suppress": self.suppress, "recategorize": self.recategorize}[prop["kind"]]
        result = method(**payload, source="cli")
        if "error" in result:
            return {"error": f"Proposal '{pid}' can no longer be applied: {result['error']}",
                    "proposal_id": pid, "status": "pending_human"}
        self.mem.decide_proposal(pid, "accepted", by, result=result)
        return {"proposal_id": pid, "status": "accepted", "result": result}

    def reject_proposal(self, pid: str, by: str, note: str = "") -> dict:
        by = (by or "").strip()
        if not by:
            return {"error": "--by is required: record the human who rejects this."}
        prop = self.mem.get_proposal(pid)
        if not prop:
            return {"error": f"No proposal '{pid}'."}
        if prop["status"] != "pending_human":
            return {"error": f"Proposal '{pid}' is already {prop['status']}."}
        self.mem.decide_proposal(pid, "rejected", by, note)
        return {"proposal_id": pid, "status": "rejected"}

    def list_proposals(self, status: str | None = "pending_human") -> list[dict]:
        return self.mem.proposals(status)

    # --------------------------------------------------------------- session
    def _validate_session_config(self, cfg: dict) -> str:
        """Error message for an unusable session setting, or ''."""
        paths = cfg.get("paths")
        if not paths or not isinstance(paths, (list, tuple)) or not all(
                isinstance(p, str) and p for p in paths):
            return "paths must be a non-empty list of file or directory paths."
        err = validate_analyzer_names(cfg.get("analyzers"))
        if err:
            return err
        policy = cfg.get("verification_policy")
        if policy is not None and policy not in _VALID_POLICIES:
            return (f"Unknown verification_policy '{policy}'. "
                    f"Valid: {', '.join(_VALID_POLICIES)}.")
        if (policy == "analyzer_only" and self.source == "mcp"
                and not agent_approvals_allowed()):
            return ("verification_policy 'analyzer_only' cannot be chosen through MCP: it "
                    "would let the agent resolve findings by silencing the analyzer. Use "
                    "test_gated or human_gated (the operator can set "
                    f"{ALLOW_AGENT_APPROVALS_ENV}=1 to allow it).")
        if cfg.get("severity_floor") not in _SEV_ORDER:
            return (f"Unknown severity_floor '{cfg.get('severity_floor')}'. "
                    f"Valid: {', '.join(_SEV_ORDER)}.")
        for key in ("max_iterations", "batch_size", "stall_limit", "oscillation_limit"):
            v = cfg.get(key)
            if isinstance(v, bool) or not isinstance(v, int) or v < 1:
                return f"{key} must be a positive integer (got {v!r})."
        return ""

    def _scope_prefixes(self, cfg: dict) -> list[str] | None:
        """Project-relative POSIX prefixes of the session's paths; None = everything."""
        out: list[str] = []
        for p in cfg.get("paths") or ["."]:
            pth = Path(p) if Path(p).is_absolute() else self.root / p
            rel = relpath(pth, self.root).rstrip("/")
            if rel in (".", ""):
                return None
            out.append(rel)
        return out

    @staticmethod
    def _in_paths(file: str, prefixes: list[str] | None) -> bool:
        if prefixes is None:
            return True
        return any(file == p or file.startswith(p + "/") for p in prefixes)

    def _in_scope(self, f: dict, cfg: dict, prefixes) -> bool:
        return (f["severity"] in _severities_at_or_above(cfg.get("severity_floor", "minor"))
                and self._in_paths(f["file"], prefixes))

    def _open_split(self, cfg: dict) -> dict:
        """Open findings split by how they bear on this session: ``in_scope`` (native
        findings at/above the severity floor under the session paths: these decide
        convergence), ``imported`` (SARIF-imported, not clearable by a native rescan)
        and ``out_of_scope`` (below the floor or outside the paths)."""
        prefixes = self._scope_prefixes(cfg)
        in_scope, imported, out = [], [], []
        for f in self.mem.open_findings(limit=100000):
            if _is_imported(f):
                imported.append(f)
            elif self._in_scope(f, cfg, prefixes):
                in_scope.append(f)
            else:
                out.append(f)
        return {"in_scope": in_scope, "imported": imported, "out_of_scope": out}

    def _terminal_error(self, sess: dict, action: str) -> dict | None:
        if sess["status"] in TERMINAL_SESSION_STATES:
            return {"error": f"Session {sess['id']} has ended ({sess['status']}); {action} is "
                             "not allowed on it. Start a new session with begin_session.",
                    "session_id": sess["id"], "state": sess["status"]}
        return None

    def begin_session(self, paths: list[str], config: dict | None = None,
                      force: bool = False) -> dict:
        # an unset (None) option keeps its default rather than blanking it
        cfg = {**DEFAULT_CONFIG,
               **{k: v for k, v in (config or {}).items()
                  if not (v is None and DEFAULT_CONFIG.get(k) is not None)},
               "paths": paths}
        err = self._validate_session_config(cfg)
        if err:
            return {"error": err}
        # The test command runs on the host, so it comes only from human-controlled
        # places: the CLI flag, MAISHAC_TEST_COMMAND, or .maishac/config.json.
        # The MCP tools have no way to set it.
        project_cfg = load_project_config(self.root)
        if not cfg.get("test_command"):
            cfg["test_command"] = (os.environ.get("MAISHAC_TEST_COMMAND", "").strip()
                                   or project_cfg.get("test_command") or None)
        if not cfg.get("test_timeout"):
            env_t = os.environ.get("MAISHAC_TEST_TIMEOUT", "").strip()
            try:
                cfg["test_timeout"] = float(env_t or project_cfg.get("test_timeout")
                                            or DEFAULT_TEST_TIMEOUT)
            except (TypeError, ValueError):
                return {"error": "test_timeout must be a number of seconds."}
        if cfg["test_timeout"] <= 0:
            return {"error": "test_timeout must be a positive number of seconds."}
        # Guard against two sessions racing on the same .maishac/memory.db
        # (e.g. a CI job and a local run). They'd fight over finding state. The
        # check and the insert are one transaction, so both cannot win; the row
        # is reserved before the (slow) baseline scan.
        sid, existing = self.mem.create_session_if_free(cfg, force)
        if sid is None:
            return {"error": "A session is already active on this project "
                             f"({existing['id']}). Resume it (session_status/next_batch), "
                             "or pass force to start a fresh one anyway.",
                    "active_session_id": existing["id"]}
        try:
            baseline = self.scan(cfg["paths"], cfg.get("analyzers"), **self._scan_kwargs(cfg))
        except BaseException:
            self.mem.delete_session(sid)
            raise
        if "error" in baseline:
            self.mem.delete_session(sid)     # never started: leave no live session behind
            return {"error": baseline["error"]}
        self.mem.audit("session_start", sid, source=self.source,
                       details={"paths": paths, "verification_policy": self._policy(cfg),
                                "test_command_configured": bool(cfg.get("test_command"))})
        split = self._open_split(cfg)
        self.mem.update_session(sid, history=[{
            "iteration": 0, "event": "baseline",
            "open": len(split["in_scope"]), "open_imported": len(split["imported"]),
            "ts": time.time(),
        }])
        out = {
            "session_id": sid,
            "state": "active",
            "baseline": baseline,
            "guidance": ("Call next_batch to receive the highest-priority findings. "
                          "Before editing, call record_attempt with your intended strategy. "
                          "After editing, call verify. Repeat until the session converges."),
        }
        # A session is the start of a whole compliance campaign, so a narrowed
        # toolchain is hoisted out of the nested baseline to the top level —
        # converging this session must not be mistaken for "the code complies".
        if baseline.get("coverage_warning"):
            out["coverage_warning"] = baseline["coverage_warning"]
            out["guidance"] += (
                " NOTE: this session cannot check every rule Maisha knows — see "
                "coverage_warning. Report that limitation to the user rather than "
                "presenting convergence as full compliance.")
        return out

    def next_batch(self, session_id: str) -> dict:
        sess = self._require(session_id)
        err = self._terminal_error(sess, "next_batch")
        if err:
            return err
        cfg = sess["config"]
        prefixes = self._scope_prefixes(cfg)
        sevs = _severities_at_or_above(cfg.get("severity_floor", "minor"))
        opens = [f for f in self.mem.open_findings(limit=500, severities=sevs)
                 if self._in_paths(f["file"], prefixes)]

        # freeze oscillating findings
        frozen, workable = [], []
        for f in opens:
            if f["regress_count"] >= cfg.get("oscillation_limit", 2):
                frozen.append(f)
            else:
                workable.append(f)

        if not workable:
            return {"session_id": session_id, "batch": [], "frozen_needs_human": self._brief_many(frozen),
                    "message": "No workable open findings. Call verify to close out the session."}

        # group by file: take the file of the top-priority finding first
        batch, seen_files = [], []
        size = cfg.get("batch_size", 5)
        for f in workable:
            if len(batch) >= size:
                break
            if f["file"] in seen_files or not seen_files or len(seen_files) < 2:
                batch.append(f)
                if f["file"] not in seen_files:
                    seen_files.append(f["file"])

        return {
            "session_id": session_id,
            "iteration": sess["iteration"],
            "remaining_open": len(opens),
            "frozen_needs_human": self._brief_many(frozen),
            "batch": [self._brief(f) for f in batch],
            "instructions": (
                "Fix ONLY these findings; do not refactor unrelated code. "
                "Preserve behavior. Prefer the fix_hint approach unless it appears in "
                "failed_strategies. When done editing, call verify."),
        }

    def record_attempt(self, session_id: str, fingerprint: str,
                       strategy: str, notes: str = "") -> dict:
        err = self._terminal_error(self._require(session_id), "record_attempt")
        if err:
            return err
        aid = self.mem.record_fix_attempt(fingerprint, session_id, strategy, notes)
        return {"attempt_id": aid, "fingerprint": fingerprint, "recorded": True}

    def abort_session(self, session_id: str, reason: str = "", by: str = "") -> dict:
        """End a session on purpose. Its undecided fix attempts are marked
        abandoned and the end is audit-logged. A session that already ended
        cannot be aborted."""
        sess = self._require(session_id)
        if sess["status"] in TERMINAL_SESSION_STATES:
            return {"error": f"Session {session_id} has already ended ({sess['status']}).",
                    "session_id": session_id, "state": sess["status"]}
        reason = (reason or "").strip() or "aborted on request"
        if not self.mem.update_session(session_id, status="aborted", end_reason=reason,
                                       expect_status=sess["status"]):
            now = self._require(session_id)["status"]
            return {"error": f"Session {session_id} changed while aborting (now {now}); "
                             "nothing was changed. Check session_status and retry.",
                    "session_id": session_id, "state": now}
        abandoned = self.mem.abandon_session_attempts(session_id)
        self.mem.audit("session_end", session_id, actor=by, source=self.source,
                       details={"state": "aborted", "iteration": sess["iteration"],
                                "reason": reason, "attempts_abandoned": abandoned})
        return {"session_id": session_id, "state": "aborted", "reason": reason,
                "attempts_abandoned": abandoned}

    def verify(self, session_id: str) -> dict:
        sess = self._require(session_id)
        err = self._terminal_error(sess, "verify")   # awaiting_verification is not terminal
        if err:
            return err
        cfg = sess["config"]
        policy = self._policy(cfg)
        want_gate = policy != "analyzer_only"
        forced_gate = self._effective_gate(want_gate) and not want_gate
        result = self.scan(cfg["paths"], cfg.get("analyzers"), gate=want_gate,
                           kind="verify", hold_for_human=True, **self._scan_kwargs(cfg))
        if "error" in result:
            return {"session_id": session_id, "state": sess["status"], "error": result["error"]}
        analyzer_errors = result["analyzer_errors"]
        iteration = sess["iteration"] + 1
        history = sess["history"]
        split = self._open_split(cfg)
        # Convergence is judged on native findings inside the session's severity
        # floor and paths. Imported findings (a native rescan cannot clear them)
        # and findings outside the scope are counted and reported, not blocking.
        open_now = len(split["in_scope"])
        open_imported = len(split["imported"])
        open_out = len(split["out_of_scope"])
        prev_open = history[-1]["open"] if history else open_now

        # close pending attempts on findings that persist
        self.mem.close_pending_attempts_for_open("persisting")

        # verification gate: a fix that merely silenced the analyzer is NOT
        # resolved until a passing test run or a human confirms it.
        test_run, confirmed_by_test = None, []
        if policy == "test_gated" and cfg.get("test_command"):
            test_run = self._run_tests(cfg["test_command"], cfg.get("test_timeout"))
            if test_run.get("passed"):
                confirmed_by_test = self.mem.confirm_pending_by_test()

        prefixes = self._scope_prefixes(cfg)
        pending_rows = [f for f in self.mem.pending_findings() if self._in_scope(f, cfg, prefixes)]
        pending = len(pending_rows)
        awaiting_human = sum(requires_human(f) for f in pending_rows)
        history.append({"iteration": iteration, "event": "verify", "open": open_now,
                        "open_imported": open_imported, "pending": pending,
                        "diff": result["diff"], "ts": time.time()})

        frozen_now = [f for f in split["in_scope"]
                      if f["regress_count"] >= cfg.get("oscillation_limit", 2)]
        state, reason = "active", ""
        max_iter = cfg.get("max_iterations", 10)
        if analyzer_errors and open_now == 0:
            # An analyzer that failed cannot vouch for anything, so "no open
            # findings" is not evidence of compliance: never converge on it.
            names = ", ".join(sorted({e["analyzer"] for e in analyzer_errors}))
            if iteration >= max_iter:
                state = "budget_exhausted"
                reason = (f"Iteration budget ({max_iter}) reached while "
                          f"{names} was still failing or only partly running; the "
                          "analysis is incomplete, so this is NOT a compliant result.")
            else:
                # Not terminal: fix the toolchain and verify again (the iteration
                # budget still bounds the loop).
                state = "analysis_incomplete"
                reason = (f"Analysis incomplete: {names} failed or only partly ran, so a "
                          "clean result cannot be trusted and nothing was resolved on its "
                          "account. See analyzer_errors, fix the cause, then verify again.")
            if pending:
                reason += f" {pending} fix(es) are also still awaiting verification."
        elif open_now == 0 and pending == 0:
            state, reason = "converged", "All findings resolved, suppressed, or deviated."
        elif open_now == 0 and pending > 0:
            need = []
            if awaiting_human:
                need.append(f"{awaiting_human} require human approval (call approve_finding)")
            if policy == "test_gated" and not cfg.get("test_command"):
                need.append("no test_command configured to auto-confirm the rest")
            elif policy == "human_gated":
                need.append(f"{pending - awaiting_human} more await approval under human_gated policy")
            if policy == "analyzer_only" and forced_gate:
                need.append(
                    f"{pending - awaiting_human} held for a human because the session's "
                    "policy 'analyzer_only' was forced to gated: this verification came "
                    "through MCP (agent origin), and an agent may not mark its own fixes "
                    "resolved by rescanning. A person can run `maishac approve` "
                    "(a CLI `maishac session verify` does not force the gate)")
            state = "awaiting_verification"
            reason = ("Analyzer-clean, but the fixes are UNVERIFIED — "
                      + "; ".join(need) + ". They do not count as resolved until confirmed.")
        elif len(frozen_now) == open_now:
            # every remaining finding keeps coming back: more iterations only thrash
            state = "needs_human"
            reason = (f"{open_now} open finding(s) regressed {cfg.get('oscillation_limit', 2)} or "
                      "more times and are frozen: fixing them keeps being undone. A person must "
                      "decide (change approach, deviate with justification, or fix by hand).")
        elif iteration >= max_iter:
            state, reason = "budget_exhausted", f"Iteration budget ({max_iter}) reached."
        else:
            limit = cfg.get("stall_limit", 2)
            verifies = [i for i, h in enumerate(history) if h["event"] == "verify"]
            if len(verifies) >= limit:
                # open count just before the window of `limit` verifies, vs now
                start_open = history[max(0, verifies[-limit] - 1)]["open"]
                if open_now >= start_open:
                    state, reason = "stalled", (
                        f"No net progress across the last {limit} iterations "
                        f"({start_open} open before, {open_now} now). Escalate to a human, "
                        "add deviations for justified findings, or change approach.")

        if state == "converged":
            notes = []
            if open_imported:
                notes.append(
                    f"{open_imported} imported finding(s) are still open (open_imported): "
                    "a native rescan cannot clear them. They did not block convergence; "
                    "resolve them by re-importing a newer SARIF from the same tool, or "
                    "by approve/suppress/deviate.")
            if open_out:
                notes.append(
                    f"{open_out} open finding(s) are outside this session's severity floor "
                    "or paths and were not part of it.")
            if notes:
                reason += " " + " ".join(notes)

        ending = state in TERMINAL_SESSION_STATES
        # Compare-and-set: the scan above can take minutes, and an abort (CLI) or a
        # second verify may have landed meanwhile. Never overwrite it.
        if not self.mem.update_session(session_id, status=state, iteration=iteration,
                                       history=history, end_reason=reason if ending else None,
                                       expect_status=sess["status"],
                                       expect_iteration=sess["iteration"]):
            now = self._require(session_id)["status"]
            return {"session_id": session_id, "state": now,
                    "error": f"Session {session_id} changed while verify was running "
                             f"(now {now}); this verify result was not recorded. "
                             "Call session_status and verify again if it is still live."}
        if ending:
            if state != "converged":
                self.mem.abandon_session_attempts(session_id)
            self.mem.audit("session_end", session_id, source=self.source,
                           details={"state": state, "iteration": iteration, "reason": reason})
        return {
            "session_id": session_id,
            "iteration": iteration,
            "state": state,
            "reason": reason,
            "verification_policy": policy,
            "open_before": prev_open,
            "open_now": open_now,
            "open_imported": open_imported,
            "open_out_of_scope": open_out,
            "pending_verification": pending,
            "awaiting_human_approval": awaiting_human,
            "confirmed_by_test": confirmed_by_test,
            "test_run": test_run,
            "diff": result["diff"],
            "analyzer_errors": analyzer_errors,
            "analysis_complete": result["analysis_complete"],
            **({"coverage_warning": result["coverage_warning"]}
               if result.get("coverage_warning") else {}),
            "pending_findings": self._brief_many(pending_rows),
            "regressions": self._brief_many(
                [f for f in split["in_scope"] if f["status"] == "regressed"]),
            "frozen_needs_human": self._brief_many(frozen_now),
            "next": ("Session complete." if state == "converged"
                     else ("A person must confirm these fixes from the CLI: run "
                           "`maishac approve <fingerprint>` (see `maishac findings`), then "
                           "call session_status.") if state == "awaiting_verification"
                     and policy == "analyzer_only" and forced_gate
                     else "Approve verified fixes (approve_finding) or call next_batch."
                     if state == "awaiting_verification"
                     else "Fix the analyzer failure (see analyzer_errors) and call verify again."
                     if state == "analysis_incomplete"
                     else "Call next_batch for the next set of findings." if state == "active"
                     else "A person must review the frozen findings." if state == "needs_human"
                     else "Session ended."),
        }

    def session_status(self, session_id: str) -> dict:
        sess = self._require(session_id)
        return {"session_id": session_id, "state": sess["status"],
                "iteration": sess["iteration"], "history": sess["history"],
                "config": sess["config"]}

    # ------------------------------------------------------------- briefings
    def _brief(self, f: dict) -> dict:
        meta = REGISTRY.get(f["rule_id"]) or {}
        failed = self.mem.failed_strategies(f["fingerprint"])
        notes = self.mem.search_notes(f["rule_id"], limit=2) + \
                self.mem.search_notes(f["file"], limit=2)
        return {
            "fingerprint": f["fingerprint"],
            "rule_id": f["rule_id"],
            "standard": f["standard"],
            "severity": f["severity"],
            "status": f["status"],
            "location": f"{f['file']}:{f['line']}",
            "line_content": f["line_content"],
            "function": f["context_symbol"],
            "message": f["message"],
            "rule_summary": meta.get("summary", ""),
            "fix_hint": f["fix_hint"] or meta.get("fix", ""),
            "equivalent_rules": REGISTRY.cross_refs(f["rule_id"]),
            "code_flow": json.loads(f["code_flow"]) if f.get("code_flow") else [],
            "failed_strategies": failed,
            "relevant_memory": [{"topic": n["topic"], "content": n["content"]}
                                 for n in {n["id"]: n for n in notes}.values()][:3],
            "times_seen": f["seen_count"],
            "times_regressed": f["regress_count"],
        }

    def _brief_many(self, fs: list[dict]) -> list[dict]:
        return [self._brief(f) for f in fs]

    def _require(self, session_id: str) -> dict:
        sess = self.mem.get_session(session_id)
        if not sess:
            raise ValueError(
                f"Unknown session '{session_id}'. Call begin_session first, or use "
                "session_status with a valid id.")
        return sess
