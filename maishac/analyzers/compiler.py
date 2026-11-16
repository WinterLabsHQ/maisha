"""Compiler-warnings adapter (gcc / clang -Wall -Wextra).

A C compiler at a high warning level is a legitimate MISRA/BARR-C enforcement
source — it flags exactly the kind of latent defects (sign-compare, uninitialized
reads, VLAs, float equality, ignored results) several guidelines target, and the
GEP can cite it as a checking tool. This adapter runs the compiler in
syntax-only mode, parses `file:line:col: warning: msg [-Wflag]`, and maps the
`-Wflag` onto a registry rule where a clear equivalence exists; unmapped warnings
survive as `compiler:-Wflag` evidence. It degrades to nothing when no compiler is
installed.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from .base import (AnalysisResult, Analyzer, SourceLines, _tail, load_compile_commands,
                   parallel_map, validate_compiler_flags)
from ..model import Finding, relpath
from ..rules import REGISTRY

# gcc/clang `-Wflag` -> registry rule (fuzzy id). Only clear, defensible
# equivalences; every target must resolve in the knowledge base.
WFLAG_TO_RULE = {
    "vla": "MISRA 18.8",                       # variable-length array
    "vla-extension": "MISRA 18.8",
    "float-equal": "CERT FLP37-C",             # exact float comparison
    "switch": "MISRA 16.4",                    # switch missing a case/default
    "switch-default": "MISRA 16.4",
    "uninitialized": "CERT EXP33-C",           # read of uninitialized object
    "maybe-uninitialized": "CERT EXP33-C",
    "sometimes-uninitialized": "CERT EXP33-C",
    "sign-compare": "CERT INT31-C",            # signed/unsigned comparison
    "sign-conversion": "CERT INT31-C",
    "unused-result": "MISRA 17.7",             # ignored non-void return
}

_DIAG = re.compile(
    # non-greedy file group so a Windows drive-letter colon isn't mistaken for
    # the line:col separator (same care as the clang-tidy adapter).
    r"^(?P<file>.+?):(?P<line>\d+):(?P<col>\d+):\s+(?P<sev>warning|error):\s+"
    r"(?P<msg>.*?)\s+\[-W(?P<flag>[\w=+-]+)\]\s*$", re.MULTILINE)

# Any error-level diagnostic, with or without a [-Wflag] suffix. A plain
# `error:` / `fatal error:` (missing header, syntax error) means the file did
# not compile, so the absence of warnings for it says nothing.
_ERROR = re.compile(r"^(?P<file>.+?):(?P<line>\d+):(?:\d+:)?\s+(?:fatal )?error:\s+(?P<msg>.*?)"
                    r"(?:\s+\[-W[\w=+-]+\])?\s*$", re.MULTILINE)


class CompilerAnalyzer(Analyzer):
    name = "compiler"
    requires = None  # resolved dynamically (gcc or clang); see available()
    options = "-fsyntax-only -Wall -Wextra (gcc/clang warnings)"

    @staticmethod
    def _compiler() -> str | None:
        for cc in ("gcc", "clang", "cc"):
            if shutil.which(cc):
                return cc
        return None

    def available(self) -> bool:
        return self._compiler() is not None

    def version(self) -> str:
        cc = self._compiler()
        if not cc:
            return "unknown"
        try:
            proc = self._run([cc, "--version"], timeout=10)
            first = (proc.stdout or proc.stderr).strip().splitlines()
            return first[0].strip() if first else cc
        except Exception:  # noqa: BLE001 — a missing/odd compiler must not break the GEP
            return cc

    def run(self, files: list[Path], root: Path,
            include_paths: list[str] | None = None,
            options: dict | None = None) -> AnalysisResult:
        res = AnalysisResult(self.name)
        cc = self._compiler()
        if not cc:
            res.status = "failed"
            res.error = "no C compiler (gcc, clang or cc) found on PATH"
            res.failed_files = [relpath(f, root) for f in files if f.suffix == ".c"]
            return res
        c_files = [f for f in files if f.suffix == ".c"]
        res.skipped_files = [relpath(f, root) for f in files if f.suffix != ".c"]
        if not c_files:
            return res
        opts = options or {}
        include_flags = [f"-I{p}" for p in (include_paths or [])]
        std = opts.get("std") or "c11"
        extra = validate_compiler_flags(opts.get("compiler_flags"))
        per_file: dict[str, list[str]] = {}
        if opts.get("compile_commands"):
            per_file = load_compile_commands(opts["compile_commands"], root)
        src = SourceLines(root)

        # -fsyntax-only: warn without producing objects or linking. Compile each
        # file on its own so one file's fatal error (a missing header) can't
        # suppress warnings from the others.
        def one(f: Path):
            flags = per_file.get(str(f.resolve()))
            cmd = [cc, "-fsyntax-only", f"-std={std}", "-Wall", "-Wextra"] \
                + include_flags + (flags if flags is not None else []) + extra + [str(f)]
            try:
                proc = self._run(cmd, timeout=120)
            except Exception as e:  # noqa: BLE001 — a compiler that did not run proves nothing
                return f, [], f"{cc} did not run on {relpath(f, root)}: {type(e).__name__}: {e}"
            text = (proc.stdout or "") + "\n" + (proc.stderr or "")
            found = self._parse(text, root, src)
            err = next(iter(_ERROR.finditer(text)), None)
            # An error that carries a [-Wflag] is a promoted warning (e.g.
            # -Werror=...): the file was still analyzed. Anything else is a
            # compile failure.
            hard = next((m for m in _ERROR.finditer(text)
                         if not re.search(r"\[-W[\w=+-]+\]\s*$", m.group(0))), None)
            if hard is not None:
                return f, found, (f"{cc} could not compile {relpath(f, root)}: "
                                  f"{hard.group('msg')} (line {hard.group('line')})")
            rc = getattr(proc, "returncode", 0) or 0
            if rc != 0 and err is None:
                return f, found, (f"{cc} exited {rc} on {relpath(f, root)}: "
                                  + (_tail(text) or "no output"))
            return f, found, ""

        for f, found, err in parallel_map(one, c_files):
            res.findings.extend(found)
            rel = relpath(f, root)
            if err:
                res.failed_files.append(rel)
                res.error = res.error or err
            else:
                res.analyzed_files.append(rel)
        if res.failed_files:
            res.status = "partial" if res.analyzed_files else "failed"
        return res

    def _parse(self, text: str, root: Path, src: SourceLines | None = None) -> list[Finding]:
        src = src or SourceLines(root)
        findings: list[Finding] = []
        for m in _DIAG.finditer(text):
            flag = m.group("flag").split("=", 1)[0]  # -Wformat=2 -> format
            fpath = m.group("file")
            rel = relpath(fpath, root)
            line = int(m.group("line"))
            line_content, ctx = src.line_of(fpath, line)
            ref = WFLAG_TO_RULE.get(flag)
            meta = REGISTRY.resolve(ref) if ref else None
            if meta:
                findings.append(Finding(
                    rule_id=meta["id"], standard=meta["standard"],
                    severity=meta.get("severity", "major"),
                    file=rel, line=line, column=int(m.group("col")),
                    message=m.group("msg"), analyzer=self.name,
                    line_content=line_content, context_symbol=ctx,
                    fix_hint=meta.get("fix", ""), cross_refs=REGISTRY.cross_refs(meta["id"]),
                ))
            else:
                findings.append(Finding(
                    rule_id=f"compiler:-W{flag}", standard="generic",
                    severity="major" if m.group("sev") == "warning" else "critical",
                    file=rel, line=line, column=int(m.group("col")),
                    message=m.group("msg"), analyzer=self.name,
                    line_content=line_content, context_symbol=ctx))
        return findings
