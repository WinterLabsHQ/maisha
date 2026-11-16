"""Maisha command line interface.

    maishac doctor                        diagnose install, toolchain and coverage
    maishac scan src/                     scan + sync memory
    maishac scan src/ --fail-on major     CI gate: exit 1 on findings, 2 if degraded
    maishac gate src/                     same as scan --fail-on any
    maishac guide "dynamic memory"        author-time: the compliant idiom to reach for
    maishac check draft.c                 lint a draft in memory (no store); '-' = stdin
    maishac findings --limit 20           list open findings
    maishac rule "MISRA 21.3"             explain a rule
    maishac session begin src/            start an engineered fix session
    maishac session batch <id>            next prioritized batch (JSON)
    maishac session verify <id>           rescan + converge check
    maishac session abort <id>            end a session (audit-logged)
    maishac deviate "MISRA 21.6" -s "src/debug/*" -j "..."
    maishac suppress <fingerprint> -r "false positive because ..."
    maishac note "Use pool_alloc() instead of malloc" -t allocator
    maishac recategorize "MISRA 15.5" --to advisory -r "..."   MISRA GRP entry
    maishac report [--format markdown|json|sarif|misra-compliance|gep|grp] [-o file]
    maishac import findings.sarif         ingest an external engine's SARIF
    maishac approve <fingerprint> --by me  human sign-off on a verified fix
    maishac unsuppress <fingerprint> | revoke-deviation <id> | uncategorize "MISRA 15.5"
    maishac proposals list|accept <id> --by me|reject <id> --by me   agent-proposed sign-offs
    maishac audit [--limit N] [--json]    append-only history of every sign-off
    maishac serve                         run the MCP server (stdio)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import __version__
from .engine import FAIL_ON_CHOICES, LoopEngine, gate_verdict
from .rules import REGISTRY
from . import report as report_mod


# Engines opened by the running command; main() closes them when it finishes.
_OPEN_ENGINES: list[LoopEngine] = []


def _engine(args) -> LoopEngine:
    eng = LoopEngine(getattr(args, "project", None) or os.getcwd())
    _OPEN_ENGINES.append(eng)
    return eng


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _warn_coverage(result: dict) -> None:
    """Surface a narrowed toolchain on stderr.

    stderr specifically: stdout is JSON that gets piped into jq and CI steps, so
    the warning must not corrupt it — but it must also not be invisible to the
    human running the command, which is the whole point.
    """
    warning = result.get("coverage_warning")
    if warning:
        print(f"\nWARNING: {warning}\n", file=sys.stderr)
    elif result.get("analyzer_errors"):
        # verify()/scan results always carry coverage_warning when analyzers
        # failed; this is the belt-and-braces path for any other caller.
        for e in result["analyzer_errors"]:
            print(f"\nWARNING: {e['analyzer']} {e['status']}: {e['error']}\n", file=sys.stderr)


def _scan_options(args) -> dict:
    """Shared scan-option flags -> engine keyword arguments."""
    return {"include_paths": args.include,
            "exclude": args.exclude,
            "default_excludes": not args.no_default_excludes,
            "std": args.std,
            "compiler_flags": args.compiler_flag,
            "compile_commands": args.compile_commands}


def _add_gate_options(s, default_fail_on: str | None) -> None:
    s.add_argument("--fail-on", choices=FAIL_ON_CHOICES, default=default_fail_on,
                   metavar="SEVERITY",
                   help="CI gate. Exit 1 if an open finding is at or above SEVERITY "
                        "(blocker|critical|major|minor|info; 'any' = every open finding; "
                        "'none' = never fail on findings). Exit 2 if no findings fail but the "
                        "analysis was degraded (an analyzer failed, or a recommended one is "
                        "not installed) unless --allow-degraded. Findings take precedence "
                        "over degradation. Without this flag scan always exits 0."
                        + (" Default for 'gate': any." if default_fail_on else ""))
    s.add_argument("--allow-degraded", action="store_true",
                   help="With --fail-on: do not exit 2 for a degraded analysis.")


def _add_scan_options(s) -> None:
    s.add_argument("--include", "-I", action="append",
                   help="Include dir forwarded to cppcheck/clang-tidy/the compiler as -I "
                        "(repeatable). Without these, headers outside the "
                        "scanned paths cause misconfiguration false positives.")
    s.add_argument("--exclude", action="append",
                   help="fnmatch pattern of directories/files to skip when walking a "
                        "directory (repeatable), e.g. third_party or 'gen/*'. Added to "
                        "the defaults (.git, .maishac, build, dist, node_modules, ...).")
    s.add_argument("--no-default-excludes", action="store_true",
                   help="Do not skip the default directories (.git, build, node_modules, ...).")
    s.add_argument("--std", help="C standard for the compiler/clang-tidy checks (default c11).")
    s.add_argument("--compiler-flag", action="append", metavar="FLAG",
                   help="Extra compiler flag, e.g. -DNDEBUG or -Iinc (repeatable; only "
                        "-D/-U/-I/-isystem/-iquote/-std= and a few target flags are accepted).")
    s.add_argument("--compile-commands", metavar="FILE",
                   help="compile_commands.json to take per-file -D/-I/-std flags from.")


def cmd_scan(args):
    eng = _engine(args)
    analyzers = ([a.strip() for a in args.analyzers.split(",") if a.strip()]
                 if args.analyzers else None)
    result = eng.scan(args.paths, analyzers, **_scan_options(args))
    if "error" in result:
        print(result["error"], file=sys.stderr)
        sys.exit(1)
    verdict = None
    if args.fail_on:
        verdict = gate_verdict(result, args.fail_on, args.allow_degraded)
        result["gate"] = verdict
    _print(result)
    _warn_coverage(result)
    if verdict:
        print(f"gate: {verdict['reason']} (exit {verdict['exit_code']})", file=sys.stderr)
        if verdict["exit_code"]:
            sys.exit(verdict["exit_code"])


def cmd_check(args):
    eng = _engine(args)
    if args.file in ("-", None):
        code, name = sys.stdin.read(), "draft.c"
    else:
        # A missing/unreadable draft must fail cleanly, and odd byte encodings
        # must not crash the linter (errors='replace'), matching the CLI's other
        # input-handling paths.
        try:
            code = Path(args.file).read_text("utf-8", errors="replace")
        except (FileNotFoundError, IsADirectoryError, PermissionError, OSError) as e:
            print(f"Cannot read '{args.file}': {e}", file=sys.stderr)
            sys.exit(1)
        name = args.file
    _print(eng.check_snippet(code, name))


def cmd_guide(args):
    eng = _engine(args)
    _print(eng.guidance(args.topic, args.limit))


def _emit(out: dict) -> None:
    """Print an engine result; an {"error": ...} result is a clean exit 1."""
    if "error" in out:
        print(out["error"], file=sys.stderr)
        sys.exit(1)
    _print(out)


def cmd_recategorize(args):
    eng = _engine(args)
    _emit(eng.recategorize(args.rule, args.to, args.rationale, args.approver))


def cmd_uncategorize(args):
    eng = _engine(args)
    _emit(eng.remove_recategorization(args.rule, args.by, args.reason))


def cmd_findings(args):
    eng = _engine(args)
    rows = eng.mem.open_findings(limit=args.limit)
    if args.json:
        _print(eng._brief_many(rows))
        return
    if not rows:
        print("No open findings.")
        return
    for f in rows:
        flag = "↩REGRESSED " if f["status"] == "regressed" else ""
        print(f"[{f['severity']:>8}] {flag}{f['rule_id']:<28} {f['file']}:{f['line']}"
              f"  {f['message'][:80]}  ({f['fingerprint']})")


def cmd_rule(args):
    meta = REGISTRY.resolve(args.rule)
    if not meta:
        print(f"Rule '{args.rule}' not found. Closest:", file=sys.stderr)
        for h in REGISTRY.search(args.rule):
            print(f"  {h['id']}", file=sys.stderr)
        sys.exit(1)
    out = dict(meta)
    out["equivalent_rules"] = REGISTRY.cross_refs(meta["id"])
    _print(out)


def cmd_session(args):
    eng = _engine(args)
    if args.action == "begin":
        # for 'begin', the first positional is a path, not a session id
        paths = ([args.session_id] if args.session_id else []) + list(args.paths or [])
        args.paths = paths or ["."]
        out = eng.begin_session(args.paths, {
            "max_iterations": args.max_iterations, "batch_size": args.batch_size,
            "severity_floor": args.severity_floor,
            "verification_policy": args.verification_policy,
            "test_command": args.test_command, "test_timeout": args.test_timeout,
            **_scan_options(args)}, force=args.force)
        _emit(out)
        _warn_coverage(out)
    elif args.action == "batch":
        _emit(eng.next_batch(args.session_id))
    elif args.action == "verify":
        out = eng.verify(args.session_id)
        _emit(out)
        _warn_coverage(out)
    elif args.action == "status":
        _print(eng.session_status(args.session_id))
    elif args.action == "abort":
        _emit(eng.abort_session(args.session_id, args.reason or "", args.by or ""))


def cmd_approve(args):
    eng = _engine(args)
    _print(eng.approve(args.fingerprint, args.by))


def cmd_import(args):
    eng = _engine(args)
    if args.format != "sarif":
        print(f"Unsupported import format '{args.format}' (only 'sarif').", file=sys.stderr)
        sys.exit(1)
    # A compliance tool's import command must fail cleanly on a missing or
    # malformed file, not spill an unhandled traceback (cf. the report-output
    # hardening in main()).
    try:
        _print(eng.import_sarif(args.file))
    except FileNotFoundError:
        print(f"SARIF file not found: '{args.file}'", file=sys.stderr)
        sys.exit(1)
    except (json.JSONDecodeError, ValueError) as e:
        print(f"'{args.file}' is not valid SARIF JSON: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_deviate(args):
    eng = _engine(args)
    _emit(eng.deviate(args.rule, args.scope, args.justification, args.approver,
                      args.expires_days or None, args.expires))


def cmd_revoke_deviation(args):
    eng = _engine(args)
    _emit(eng.revoke_deviation(args.id, args.by, args.reason))


def cmd_doctor(args):
    from . import doctor
    report = doctor.diagnose(getattr(args, "project", None) or os.getcwd())
    if args.json:
        _print(report)
    else:
        print(doctor.render(report))
    # Non-zero on errors so CI can gate on a usable toolchain. Warnings are
    # informational — a native-only install is legitimate, just narrower.
    sys.exit(0 if report["healthy"] else 1)


def cmd_suppress(args):
    eng = _engine(args)
    _emit(eng.suppress(args.fingerprint, args.reason, args.approver,
                       args.expires_days or None, args.expires))


def cmd_unsuppress(args):
    eng = _engine(args)
    _emit(eng.unsuppress(args.fingerprint, args.by, args.reason))


def cmd_proposals(args):
    eng = _engine(args)
    if args.action == "list":
        status = None if args.all else "pending_human"
        rows = eng.list_proposals(status)
        if args.json:
            _print(rows)
        elif not rows:
            print("No pending proposals." if status else "No proposals.")
        else:
            for r in rows:
                print(f"{r['id']}  [{r['status']}] {r['kind']:<12} {r['summary']}")
        return
    if not args.id:
        print(f"proposals {args.action} needs a proposal id.", file=sys.stderr)
        sys.exit(1)
    if args.action == "accept":
        _emit(eng.accept_proposal(args.id, args.by or ""))
    else:
        _emit(eng.reject_proposal(args.id, args.by or "", args.reason or ""))


def cmd_audit(args):
    eng = _engine(args)
    rows = eng.mem.audit_entries(args.limit, args.action)
    if args.json:
        _print(rows)
        return
    if not rows:
        print("Audit log is empty.")
        return
    for r in rows:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"]))
        mark = "  [AGENT]" if r["source"] == "mcp" else ""
        print(f"{ts}  {r['source']:<6} {r['action']:<24} {r['actor'] or '-':<18} "
              f"{r['target']}{mark}")


def cmd_note(args):
    eng = _engine(args)
    nid = eng.mem.add_note(args.content, args.topic, args.tags)
    _print({"note_id": nid})


def cmd_report(args):
    eng = _engine(args)
    if args.format == "sarif":
        text = json.dumps(report_mod.sarif(eng.mem), indent=2)
    elif args.format == "json":
        text = json.dumps(report_mod.compliance_matrix(eng.mem), indent=2)
    elif args.format == "misra-compliance":
        text = report_mod.misra_compliance_markdown(eng.mem, project_name=eng.root.name)
    elif args.format == "gep":
        text = report_mod.guideline_enforcement_markdown(eng.mem, project_name=eng.root.name)
    elif args.format == "grp":
        text = report_mod.guideline_recategorization_markdown(eng.mem, project_name=eng.root.name)
    else:
        text = report_mod.markdown_report(eng.mem, project_name=eng.root.name)
    if args.output:
        Path(args.output).write_text(text, "utf-8")
        print(f"Wrote {args.output}")
    else:
        print(text)


def cmd_serve(args):
    if getattr(args, "project", None):
        os.environ["MAISHAC_PROJECT"] = str(Path(args.project).resolve())
    try:
        from .mcp_server import main as serve_main
    except ModuleNotFoundError as e:
        sys.exit(f"The MCP server needs the 'mcp' package (missing: {e.name}). Install it with: pip install mcp")
    serve_main()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="maishac",
                                description="Agent harness for MISRA C, BARR-C and CERT C.")
    p.add_argument("--version", action="version", version=f"maishac {__version__}")
    p.add_argument("--project", "-p", help="Project root (default: cwd)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Scan paths and sync memory")
    s.add_argument("paths", nargs="+")
    s.add_argument("--analyzers", help="Comma list: native,cppcheck,clang-tidy,compiler")
    _add_scan_options(s)
    _add_gate_options(s, None)
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("gate", help="CI gate: scan, then exit 1 on open findings, 2 on a "
                                    "degraded analysis (alias of 'scan --fail-on any')")
    s.add_argument("paths", nargs="+")
    s.add_argument("--analyzers", help="Comma list: native,cppcheck,clang-tidy,compiler")
    _add_scan_options(s)
    _add_gate_options(s, "any")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("findings", help="List open findings")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_findings)

    s = sub.add_parser("check", help="Lint a draft snippet in memory (no scan/store) "
                                     "for proactive authoring; reads a file or stdin")
    s.add_argument("file", nargs="?", default="-",
                   help="C file to check, or '-'/omitted to read stdin")
    s.set_defaults(fn=cmd_check)

    s = sub.add_parser("guide", help="Author-time guidance: the compliant idiom to "
                                     "reach for BEFORE writing code on a topic")
    s.add_argument("topic", help='e.g. "dynamic memory", "string copy", "switch", "recursion"')
    s.add_argument("--limit", type=int, default=5)
    s.set_defaults(fn=cmd_guide)

    s = sub.add_parser("recategorize", help="Record a MISRA Guideline Re-categorization "
                                            "Plan (GRP) entry (legality enforced)")
    s.add_argument("rule", help='e.g. "MISRA 15.5"')
    s.add_argument("--to", required=True,
                   choices=["mandatory", "required", "advisory", "disapplied"],
                   help="target category")
    s.add_argument("--rationale", "-r", required=True, help="why (agreed by acquirer/supplier)")
    s.add_argument("--approver", default="")
    s.set_defaults(fn=cmd_recategorize)

    s = sub.add_parser("doctor", help="Diagnose install, analyzer toolchain, rule "
                                      "coverage on this machine, and project memory")
    s.add_argument("--json", action="store_true", help="machine-readable output")
    s.set_defaults(fn=cmd_doctor)

    s = sub.add_parser("rule", help="Explain a rule")
    s.add_argument("rule")
    s.set_defaults(fn=cmd_rule)

    s = sub.add_parser("session", help="Engineered fix-loop sessions")
    s.add_argument("action", choices=["begin", "batch", "verify", "status", "abort"])
    s.add_argument("session_id", nargs="?")
    s.add_argument("paths", nargs="*")
    s.add_argument("--max-iterations", type=int, default=10)
    s.add_argument("--batch-size", type=int, default=5)
    s.add_argument("--severity-floor", choices=["blocker", "critical", "major", "minor", "info"],
                   default="minor",
                   help="Ignore findings below this severity for convergence (default minor).")
    s.add_argument("--reason", help="(abort) why the session is being ended.")
    s.add_argument("--by", help="(abort) who is ending it, for the audit log.")
    s.add_argument("--verification-policy",
                   choices=["analyzer_only", "test_gated", "human_gated"],
                   help="How a fix is confirmed resolved (default: test_gated if "
                        "--test-command is set, else human_gated).")
    s.add_argument("--test-command",
                   help="Command that must exit 0 to confirm fixes (e.g. 'make test'). Split "
                        "with shlex and run WITHOUT a shell; use \"sh -c '...'\" for pipes. "
                        "Falls back to MAISHAC_TEST_COMMAND, then .maishac/config.json.")
    s.add_argument("--test-timeout", type=float, metavar="SECONDS",
                   help="Kill the test command (and its children) after this long "
                        "(default 600; MAISHAC_TEST_TIMEOUT / config.json 'test_timeout').")
    s.add_argument("--force", action="store_true",
                   help="Start a new session even if one is already active on this project.")
    _add_scan_options(s)
    s.set_defaults(fn=cmd_session)

    s = sub.add_parser("approve", help="Approve a pending_verification finding as resolved")
    s.add_argument("fingerprint")
    s.add_argument("--by", required=True, help="Who is signing off (recorded in the audit trail).")
    s.set_defaults(fn=cmd_approve)

    s = sub.add_parser("import", help="Import findings from an external SARIF file")
    s.add_argument("file")
    s.add_argument("--format", choices=["sarif"], default="sarif")
    s.set_defaults(fn=cmd_import)

    s = sub.add_parser("deviate", help="Record a formal rule deviation")
    s.add_argument("rule")
    s.add_argument("--scope", "-s", default="*")
    s.add_argument("--justification", "-j", required=True)
    s.add_argument("--approver", default="")
    s.add_argument("--expires", help="permit expiry as an absolute date, YYYY-MM-DD")
    s.add_argument("--expires-days", type=float, default=0,
                   help="permit lifetime in days from now (alternative to --expires)")
    s.set_defaults(fn=cmd_deviate)

    s = sub.add_parser("revoke-deviation", help="Revoke a deviation permit (kept in the audit log)")
    s.add_argument("id")
    s.add_argument("--by", default="", help="who is revoking it")
    s.add_argument("--reason", "-r", default="")
    s.set_defaults(fn=cmd_revoke_deviation)

    s = sub.add_parser("suppress", help="Suppress a false positive")
    s.add_argument("fingerprint")
    s.add_argument("--reason", "-r", required=True)
    s.add_argument("--approver", default="", help="who stands behind this suppression")
    s.add_argument("--expires", help="suppression expiry as a date, YYYY-MM-DD (end of that day)")
    s.add_argument("--expires-days", type=float, default=0)
    s.set_defaults(fn=cmd_suppress)

    s = sub.add_parser("unsuppress", help="Remove a suppression (kept in the audit log)")
    s.add_argument("fingerprint")
    s.add_argument("--by", default="", help="who is removing it")
    s.add_argument("--reason", "-r", default="")
    s.set_defaults(fn=cmd_unsuppress)

    s = sub.add_parser("uncategorize", help="Remove a GRP re-categorization (kept in the audit log)")
    s.add_argument("rule")
    s.add_argument("--by", default="")
    s.add_argument("--reason", "-r", default="")
    s.set_defaults(fn=cmd_uncategorize)

    s = sub.add_parser("proposals", help="Review sign-offs an MCP agent proposed "
                                         "(approve/deviate/suppress/recategorize)")
    s.add_argument("action", choices=["list", "accept", "reject"])
    s.add_argument("id", nargs="?")
    s.add_argument("--by", help="the human accepting/rejecting (recorded as approver)")
    s.add_argument("--reason", "-r", default="", help="note when rejecting")
    s.add_argument("--all", action="store_true", help="list: include decided proposals")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_proposals)

    s = sub.add_parser("audit", help="Show the append-only audit log of sign-offs and sessions")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--action", help="only this action, e.g. suppress")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_audit)

    s = sub.add_parser("note", help="Persist project knowledge")
    s.add_argument("content")
    s.add_argument("--topic", "-t", default="")
    s.add_argument("--tags", default="")
    s.set_defaults(fn=cmd_note)

    s = sub.add_parser("report", help="Compliance report")
    s.add_argument("--format",
                   choices=["markdown", "json", "sarif", "misra-compliance", "gep", "grp"],
                   default="markdown")
    s.add_argument("--output", "-o")
    s.set_defaults(fn=cmd_report)

    s = sub.add_parser("serve", help="Run the MCP server (stdio)")
    s.set_defaults(fn=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> None:
    # On Windows, stdout/stderr default to the console's legacy codepage
    # (e.g. cp1252), which can't represent arbitrary Unicode that ends up in
    # report text, finding messages, or user-supplied notes/justifications.
    # Without this, printing such a character crashes the whole CLI instead
    # of just degrading that one character.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="replace")
            except Exception:  # noqa: BLE001 — never let output-hardening itself crash the CLI
                pass
    args = build_parser().parse_args(argv)
    project = getattr(args, "project", None)
    if project and not Path(project).is_dir():
        print(f"error: --project '{project}' is not an existing directory.", file=sys.stderr)
        sys.exit(1)
    try:
        args.fn(args)
    except ValueError as e:
        # Expected user errors (unknown session, invalid argument, refused
        # sign-off) are a message and exit 1, never a traceback.
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        while _OPEN_ENGINES:
            _OPEN_ENGINES.pop().close()


if __name__ == "__main__":
    main()
