"""Analyzer orchestration: run every available evidence source and merge."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .base import AnalysisResult, Analyzer, collect_c_files
from .native import NativeAnalyzer
from .cppcheck import CppcheckAnalyzer
from .clang_tidy import ClangTidyAnalyzer
from .compiler import CompilerAnalyzer
from ..model import Finding

ALL_ANALYZERS: list[type[Analyzer]] = [NativeAnalyzer, CppcheckAnalyzer,
                                       ClangTidyAnalyzer, CompilerAnalyzer]


def available_analyzers(only: list[str] | None = None) -> list[Analyzer]:
    out = []
    for cls in ALL_ANALYZERS:
        inst = cls()
        if only and inst.name not in only:
            continue
        if inst.available():
            out.append(inst)
    return out


@dataclass
class ScanResult:
    """Everything one scan produced: findings plus what each analyzer really did."""
    findings: list[Finding]
    files: list[Path]
    results: list[AnalysisResult] = field(default_factory=list)

    @property
    def analyzers_used(self) -> list[str]:
        """Analyzers that ran and produced a usable (success or partial) result."""
        return [r.analyzer for r in self.results if r.status != "failed"]

    @property
    def errors(self) -> list[dict]:
        """One entry per analyzer that failed or only partly worked."""
        return [r.error_dict() for r in self.results if r.status != "success"]

    @property
    def analyzed(self) -> dict[str, set[str]]:
        """analyzer -> project-relative files it actually analyzed. A failed
        analyzer maps to an empty set: it ran, but can clear nothing."""
        return {r.analyzer: set(r.analyzed_files) for r in self.results}


def run_scan_detailed(paths: list[str], root: Path,
                      analyzers: list[str] | None = None,
                      include_paths: list[str] | None = None,
                      exclude: list[str] | None = None,
                      default_excludes: bool = True,
                      options: dict | None = None) -> ScanResult:
    """Run all (or the named) available analyzers and merge their findings.

    include_paths are forwarded to analyzers that compile/parse (cppcheck,
    clang-tidy) as -I flags — without them, headers outside the scanned paths
    (e.g. a project's FreeRTOSConfig.h) are invisible and those analyzers
    misreport "undefined"/"file not found" false positives (see BENCHMARKS.md).

    ``exclude``/``default_excludes`` control which directories are skipped when
    a scanned path is walked (see :func:`collect_c_files`). ``options`` carries
    ``std``, ``compiler_flags`` and ``compile_commands`` for the compiling
    analyzers.

    An analyzer that raises is recorded as failed rather than aborting the scan
    or being mistaken for a clean run.

    Dedup rule: fingerprint collision keeps the first occurrence but records the
    extra analyzer as reinforcing evidence in the message.
    """
    files = collect_c_files(paths, root, exclude, default_excludes)
    active = available_analyzers(analyzers)
    merged: dict[str, Finding] = {}
    results: list[AnalysisResult] = []
    for an in active:
        try:
            res = an.run(files, root, include_paths, options)
        except ValueError:
            raise  # invalid configuration (e.g. a disallowed compiler flag)
        except Exception as e:  # noqa: BLE001 — an analyzer bug must not look like a clean run
            res = AnalysisResult.failure(an.name, files, root,
                                         f"{type(e).__name__}: {e}")
        results.append(res)
        for fnd in res.findings:
            key = fnd.fingerprint
            if key in merged:
                prior = merged[key]
                if an.name not in prior.analyzer:
                    prior.analyzer = f"{prior.analyzer}+{an.name}"
            else:
                merged[key] = fnd
    findings = sorted(
        merged.values(),
        key=lambda f: ({"blocker": 0, "critical": 1, "major": 2, "minor": 3, "info": 4}
                       .get(f.severity, 5), f.file, f.line),
    )
    return ScanResult(findings, files, results)


def run_scan(paths: list[str], root: Path,
             analyzers: list[str] | None = None,
             include_paths: list[str] | None = None) -> tuple[list[Finding], list[str]]:
    """Compatibility wrapper: (deduped findings, names of analyzers that ran).

    Prefer :func:`run_scan_detailed`, which also reports analyzer failures.
    """
    res = run_scan_detailed(paths, root, analyzers, include_paths)
    return res.findings, res.analyzers_used
