"""Analyzer plugin interface.

Every evidence source (native lexer, cppcheck, clang-tidy, compiler) subclasses
Analyzer and yields normalized Finding objects. The harness merges and
deduplicates them by fingerprint so overlapping tools reinforce rather than
duplicate each other.

Each run reports an explicit outcome (:class:`AnalysisResult`): whether the
tool really ran, and which files it actually analyzed. A tool that crashed,
timed out or could not compile a file produces *no findings*, which is
indistinguishable from "no violations" unless the outcome says so; the memory
store therefore only treats a finding as cleared by a tool that demonstrably
analyzed that file.
"""

from __future__ import annotations

import fnmatch
import os
import json
import shlex
import shutil
import subprocess
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from ..model import Finding, enclosing_function, relpath

C_EXTENSIONS = {".c", ".h"}

# Directories that hold VCS data, build output or vendored dependencies, never
# the project's own sources. Matched against every path component below a
# scanned directory (a directory named explicitly on the command line is never
# excluded, so `maishac scan build/` still works).
DEFAULT_EXCLUDES = (".git", ".hg", ".svn", ".maishac", "build", "dist", "node_modules",
                    ".venv", "venv", "__pycache__", ".tox", "CMakeFiles", ".cache")


def _excluded(rel_parts: tuple[str, ...], patterns: list[str]) -> bool:
    # every leading portion of the path, so "src/gen" excludes src/gen/**
    prefixes = ["/".join(rel_parts[:i]) for i in range(1, len(rel_parts) + 1)]
    for pat in patterns:
        if "/" in pat:
            if any(fnmatch.fnmatch(pre, pat.strip("/")) for pre in prefixes):
                return True
        elif any(fnmatch.fnmatch(part, pat) for part in rel_parts):
            return True
    return False


def collect_c_files(paths: list[str], root: Path, exclude: list[str] | None = None,
                    default_excludes: bool = True) -> list[Path]:
    """Collect .c/.h files below ``paths``.

    ``exclude`` are extra fnmatch patterns (a bare name such as ``third_party``
    or ``*_gen`` matches any path component, a pattern containing ``/`` matches
    the path relative to the scanned directory). Excludes only filter files
    discovered by walking a directory; a file named explicitly is always kept.
    """
    patterns = list(DEFAULT_EXCLUDES if default_excludes else ()) + list(exclude or [])
    out: list[Path] = []
    for p in paths:
        pth = (root / p) if not Path(p).is_absolute() else Path(p)
        if pth.is_dir():
            for f in sorted(pth.rglob("*")):
                if f.suffix not in C_EXTENSIONS:
                    continue
                if patterns and _excluded(f.relative_to(pth).parts, patterns):
                    continue
                out.append(f)
        elif pth.suffix in C_EXTENSIONS and pth.exists():
            out.append(pth)
    # dedupe preserving order
    seen, uniq = set(), []
    for f in out:
        r = f.resolve()
        if r not in seen:
            seen.add(r)
            uniq.append(f)
    return uniq


class SourceLines:
    """Per-run cache of source files, so N diagnostics in one file read it once."""

    def __init__(self, root: Path):
        self.root = root
        self._cache: dict[str, list[str] | None] = {}

    def lines(self, fpath: str | Path) -> list[str] | None:
        key = str(fpath)
        if key not in self._cache:
            try:
                p = Path(fpath)
                if not p.is_absolute():
                    p = self.root / p
                self._cache[key] = p.read_text("utf-8", errors="replace").splitlines()
            except OSError:
                self._cache[key] = None
        return self._cache[key]

    def line_of(self, fpath: str | Path, line: int) -> tuple[str, str]:
        """(source line, enclosing function) for a 1-based line, or ("", "")."""
        lines = self.lines(fpath)
        if lines and 0 < line <= len(lines):
            return lines[line - 1], enclosing_function(lines, line - 1)
        return "", ""


# Compiler flags accepted from configuration (CLI, MCP, compile_commands.json).
# Deliberately a closed list: a flag such as -fplugin= makes the compiler load
# and run arbitrary code, and scan options can be set by an agent.
_FLAG_PREFIXES = ("-D", "-U", "-I", "-isystem", "-iquote", "-std=")
_FLAG_EXACT = {"-ffreestanding", "-fno-builtin", "-fsigned-char", "-funsigned-char",
               "-fshort-enums", "-fno-short-enums", "-m32", "-m64", "-pedantic"}


def validate_compiler_flags(flags: list[str] | None) -> list[str]:
    """Return ``flags`` unchanged if every one is allowed, else raise ValueError."""
    out = []
    for fl in flags or []:
        if not isinstance(fl, str) or not (fl in _FLAG_EXACT or (
                fl.startswith(_FLAG_PREFIXES) and len(fl) > 2 and not fl.startswith("-std=-"))):
            raise ValueError(
                f"Unsupported compiler flag {fl!r}. Allowed: -D<m>, -U<m>, -I<dir>, "
                f"-isystem<dir>, -iquote<dir>, -std=<std> (attached values) and "
                f"{', '.join(sorted(_FLAG_EXACT))}.")
        out.append(fl)
    return out


_MAX_COMPILE_COMMANDS_BYTES = 20 * 1024 * 1024


def load_compile_commands(path: str | Path, root: Path) -> dict[str, list[str]]:
    """Map resolved source path -> allowed flags from a compile_commands.json.

    Only flags in the closed list above are kept; separate-argument forms
    (``-I dir``) are joined. Raises ValueError for unreadable/oversized input.
    """
    p = Path(path)
    if not p.is_absolute():
        p = root / p
    try:
        if p.stat().st_size > _MAX_COMPILE_COMMANDS_BYTES:
            raise ValueError(f"{p} is larger than 20 MB; refusing to load it")
        entries = json.loads(p.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"Cannot read compile_commands file {p}: {e}") from e
    result: dict[str, list[str]] = {}
    for ent in entries if isinstance(entries, list) else []:
        if not isinstance(ent, dict) or "file" not in ent:
            continue
        directory = Path(ent.get("directory") or root)
        src = Path(ent["file"])
        if not src.is_absolute():
            src = directory / src
        argv = ent.get("arguments")
        if not isinstance(argv, list):
            try:
                argv = shlex.split(ent.get("command", ""))
            except ValueError:
                argv = []
        flags: list[str] = []
        i = 1
        while i < len(argv):
            tok = str(argv[i])
            if tok in ("-I", "-isystem", "-iquote", "-D", "-U") and i + 1 < len(argv):
                tok, i = tok + str(argv[i + 1]), i + 1
            if tok.startswith(("-I", "-isystem", "-iquote")):
                pre = "-isystem" if tok.startswith("-isystem") else \
                    "-iquote" if tok.startswith("-iquote") else "-I"
                d = Path(tok[len(pre):])
                if not d.is_absolute():
                    d = directory / d
                tok = pre + str(d)
            try:
                if tok.startswith(("-D", "-U", "-I", "-isystem", "-iquote", "-std=")) \
                        or tok in _FLAG_EXACT:
                    flags.append(validate_compiler_flags([tok])[0])
            except ValueError:
                pass
            i += 1
        result[str(src.resolve())] = flags
    return result


@dataclass
class AnalysisResult:
    """What one analyzer actually did on one run.

    status:
      success  the tool ran and analyzed every file it was given that it handles
      partial  it ran, but some files could not be analyzed (see failed_files)
      failed   it did not produce a usable result (crash, timeout, bad output)

    ``analyzed_files`` are project-relative paths the tool really covered; only
    those can have findings cleared by this tool. ``skipped_files`` are files
    the tool does not handle by design (e.g. headers for the compiler); they
    are neither analyzed nor failures.
    """
    analyzer: str
    status: str = "success"
    findings: list[Finding] = field(default_factory=list)
    analyzed_files: list[str] = field(default_factory=list)
    failed_files: list[str] = field(default_factory=list)
    skipped_files: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "success"

    def error_dict(self) -> dict:
        return {"analyzer": self.analyzer, "status": self.status, "error": self.error,
                "files_not_analyzed": len(self.failed_files),
                "examples": self.failed_files[:5]}

    @classmethod
    def failure(cls, analyzer: str, files: list[Path], root: Path, error: str,
                findings: list[Finding] | None = None) -> "AnalysisResult":
        return cls(analyzer, "failed", findings or [], [],
                   [relpath(f, root) for f in files], [], error)


def parallel_map(fn, items: list, max_workers: int = 4) -> list:
    """``[fn(i) for i in items]`` on a small thread pool, results in input order.

    The work is subprocess launches, so threads are enough; the cap keeps a
    large tree from spawning dozens of compilers at once.
    """
    if len(items) < 2:
        return [fn(i) for i in items]
    workers = max(1, min(max_workers, os.cpu_count() or 1, len(items)))
    if workers == 1:
        return [fn(i) for i in items]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(fn, items))


def _tail(text: str, n: int = 300) -> str:
    text = (text or "").strip()
    return text[-n:] if len(text) > n else text


class Analyzer(ABC):
    name: str = "base"
    requires: str | None = None  # executable dependency, if any
    options: str = ""            # invocation options Maisha uses (for the GEP tool record)

    def available(self) -> bool:
        return self.requires is None or shutil.which(self.requires) is not None

    def version(self) -> str:
        """Version string of the underlying tool, for the Guideline Enforcement
        Plan's tool record. Best-effort; '<name> --version' first line."""
        if self.requires is None:
            return "built-in"
        try:
            proc = self._run([self.requires, "--version"], timeout=10)
            first = (proc.stdout or proc.stderr).strip().splitlines()
            return first[0].strip() if first else "unknown"
        except Exception:  # noqa: BLE001 — a missing/odd tool must not break the GEP
            return "unknown"

    @abstractmethod
    def run(self, files: list[Path], root: Path,
            include_paths: list[str] | None = None,
            options: dict | None = None) -> AnalysisResult:
        """Analyze ``files`` and report an explicit outcome.

        ``options`` may carry ``std``, ``compiler_flags`` and ``compile_commands``
        (see engine config); analyzers ignore keys they have no use for.
        """

    def analyze(self, files: list[Path], root: Path,
                include_paths: list[str] | None = None) -> list[Finding]:
        """Findings only (outcome discarded). Prefer :meth:`run`."""
        return self.run(files, root, include_paths).findings

    @staticmethod
    def _run(cmd: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
