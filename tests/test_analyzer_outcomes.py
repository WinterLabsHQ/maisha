"""An analyzer that fails must never look like a fix.

Before explicit run outcomes, cppcheck/clang-tidy turned every crash, timeout
and unparseable report into `return []`, and the compiler adapter ignored
`error:` lines that carried no `[-Wflag]`. run_scan still listed the analyzer
as having run, so the memory store treated "no findings" as "cleared" and
resolved (or moved to pending_verification) findings nobody had fixed.

These tests drive the adapters with synthetic tool behaviour (no cppcheck
needed) plus the real gcc/clang where present.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from maishac.analyzers import run_scan_detailed
from maishac.analyzers.base import (SourceLines, collect_c_files, load_compile_commands,
                                    validate_compiler_flags)
from maishac.analyzers.clang_tidy import ClangTidyAnalyzer
from maishac.analyzers.compiler import CompilerAnalyzer
from maishac.analyzers.cppcheck import CppcheckAnalyzer
from maishac.analyzers.native import NativeAnalyzer
from maishac.engine import LoopEngine
from maishac.memory import MemoryStore
from maishac.model import Finding

CLEAN_C = "#include <stdint.h>\n\nuint32_t add(uint32_t a, uint32_t b)\n{\n    return a + b;\n}\n"

CPPCHECK_OK = """<?xml version="1.0"?>
<results version="2"><cppcheck version="2.17"/><errors>
<error id="nullPointer" severity="error" msg="Possible null pointer dereference: p">
  <location file="{file}" line="2" column="5"/></error>
</errors></results>"""
CPPCHECK_EMPTY = '<?xml version="1.0"?><results version="2"><cppcheck version="2.17"/><errors/></results>'


def _proc(stdout="", stderr="", rc=0):
    return subprocess.CompletedProcess(["x"], rc, stdout=stdout, stderr=stderr)


def _use_fake_cppcheck(monkeypatch, behaviour):
    """Install a cppcheck whose `_run` calls behaviour(cmd); available() is True."""
    monkeypatch.setattr(CppcheckAnalyzer, "available", lambda self: True)
    monkeypatch.setattr(CppcheckAnalyzer, "_run",
                        staticmethod(lambda cmd, timeout=300: behaviour(cmd)))


# ------------------------------------------------------------------ cppcheck
def test_cppcheck_launch_failure_is_a_failed_run_not_clean(monkeypatch, tmp_path):
    def boom(cmd, timeout=300):
        raise subprocess.TimeoutExpired(cmd, timeout)
    monkeypatch.setattr(CppcheckAnalyzer, "_run", staticmethod(boom))
    res = CppcheckAnalyzer().run([Path("src/a.c")], tmp_path)
    assert res.status == "failed"
    assert res.findings == [] and res.analyzed_files == []
    assert res.failed_files == [str(Path("src/a.c"))]
    assert "TimeoutExpired" in res.error


@pytest.mark.parametrize("stderr", ["garbage, not xml", ""])
def test_cppcheck_without_xml_report_is_failed(monkeypatch, tmp_path, stderr):
    monkeypatch.setattr(CppcheckAnalyzer, "_run",
                        staticmethod(lambda cmd, timeout=300: _proc(stderr=stderr)))
    res = CppcheckAnalyzer().run([Path("src/a.c")], tmp_path)
    assert res.status == "failed" and res.analyzed_files == []
    assert "no XML report" in res.error


def test_cppcheck_truncated_xml_is_failed(monkeypatch, tmp_path):
    monkeypatch.setattr(CppcheckAnalyzer, "_run", staticmethod(
        lambda cmd, timeout=300: _proc(stderr="<results><errors><error id='x'")))
    # contains "<results" but is not well-formed
    res = CppcheckAnalyzer().run([Path("src/a.c")], tmp_path)
    assert res.status == "failed"
    assert "could not be parsed" in res.error


def test_cppcheck_success_marks_every_file_analyzed(monkeypatch, tmp_path):
    monkeypatch.setattr(CppcheckAnalyzer, "_run",
                        staticmethod(lambda cmd, timeout=300: _proc(stderr=CPPCHECK_EMPTY)))
    res = CppcheckAnalyzer().run([tmp_path / "a.c", tmp_path / "b.h"], tmp_path)
    assert res.status == "success" and res.error == ""
    assert res.analyzed_files == ["a.c", "b.h"]


def test_cppcheck_syntax_error_file_is_not_analyzed(monkeypatch, tmp_path):
    xml = ('<results version="2"><errors>'
           '<error id="syntaxError" severity="error" msg="bad">'
           f'<location file="{tmp_path}/b.c" line="1" column="1"/></error></errors></results>')
    monkeypatch.setattr(CppcheckAnalyzer, "_run",
                        staticmethod(lambda cmd, timeout=300: _proc(stderr=xml)))
    res = CppcheckAnalyzer().run([tmp_path / "a.c", tmp_path / "b.c"], tmp_path)
    assert res.status == "partial"
    assert res.analyzed_files == ["a.c"] and res.failed_files == ["b.c"]


def test_cppcheck_missing_misra_addon_claims_nothing_analyzed(monkeypatch, tmp_path):
    calls = []

    def fake(cmd, timeout=300):
        calls.append(cmd)
        return _proc(stderr="" if any(c.startswith("--addon") for c in cmd) else CPPCHECK_EMPTY)
    monkeypatch.setattr(CppcheckAnalyzer, "_run", staticmethod(fake))
    res = CppcheckAnalyzer().run([tmp_path / "a.c"], tmp_path)
    assert len(calls) == 2
    assert res.status == "partial" and res.analyzed_files == []
    assert "addon" in res.error


def test_cppcheck_uses_file_list_not_argv(monkeypatch, tmp_path):
    seen = {}

    def fake(cmd, timeout=300):
        seen["cmd"] = cmd
        lf = next(c for c in cmd if c.startswith("--file-list="))
        seen["listed"] = Path(lf.split("=", 1)[1]).read_text().split()
        return _proc(stderr=CPPCHECK_EMPTY)
    monkeypatch.setattr(CppcheckAnalyzer, "_run", staticmethod(fake))
    files = [tmp_path / f"f{i}.c" for i in range(3000)]
    CppcheckAnalyzer().run(files, tmp_path)
    assert sum(len(c) for c in seen["cmd"]) < 2000      # not one arg per file
    assert len(seen["listed"]) == 3000
    assert not Path(next(c for c in seen["cmd"] if c.startswith("--file-list="))
                    .split("=", 1)[1]).exists()          # temp list cleaned up


def test_cppcheck_misra_directive_id_is_kept(monkeypatch, tmp_path):
    xml = ('<results version="2"><errors>'
           '<error id="misra-c2012-dir-4.6" severity="style" msg="misra violation">'
           '<location file="a.c" line="1" column="1"/></error>'
           '<error id="misra-c2012-10.1" severity="style" msg="misra violation">'
           '<location file="a.c" line="1" column="1"/></error></errors></results>')
    monkeypatch.setattr(CppcheckAnalyzer, "_run",
                        staticmethod(lambda cmd, timeout=300: _proc(stderr=xml)))
    ids = {f.rule_id for f in CppcheckAnalyzer().analyze([tmp_path / "a.c"], tmp_path)}
    assert "MISRA-C:2012 Dir 4.6" in ids
    assert "MISRA-C:2012 Rule 10.1" in ids


def test_analyze_compat_still_returns_plain_list(monkeypatch, tmp_path):
    monkeypatch.setattr(CppcheckAnalyzer, "_run", staticmethod(
        lambda cmd, timeout=300: (_ for _ in ()).throw(OSError("gone"))))
    assert CppcheckAnalyzer().analyze([Path("a.c")], tmp_path) == []


# ---------------------------------------------------------------- clang-tidy
def test_clang_tidy_timeout_is_failed(monkeypatch, tmp_path):
    def boom(cmd, timeout=600):
        raise subprocess.TimeoutExpired(cmd, timeout)
    monkeypatch.setattr(ClangTidyAnalyzer, "_run", staticmethod(boom))
    res = ClangTidyAnalyzer().run([tmp_path / "a.c"], tmp_path)
    assert res.status == "failed" and res.analyzed_files == ["a.c"][:0]
    assert res.failed_files == ["a.c"]


def test_clang_tidy_compile_error_marks_only_that_file_failed(monkeypatch, tmp_path):
    def fake(cmd, timeout=600):
        target = next(c for c in cmd if c.endswith(".c") and not c.startswith("-"))
        if target.endswith("bad.c"):
            return _proc(stdout=f"{target}:1:10: error: 'nope.h' file not found "
                                "[clang-diagnostic-error]\n",
                         stderr=f"Error while processing {target}.\n", rc=1)
        return _proc()
    monkeypatch.setattr(ClangTidyAnalyzer, "_run", staticmethod(fake))
    res = ClangTidyAnalyzer().run([tmp_path / "ok.c", tmp_path / "bad.c"], tmp_path)
    assert res.status == "partial"
    assert res.analyzed_files == ["ok.c"] and res.failed_files == ["bad.c"]
    assert "nope.h" in res.error


def test_clang_tidy_nonzero_exit_without_diagnostics_is_failed(monkeypatch, tmp_path):
    monkeypatch.setattr(ClangTidyAnalyzer, "_run", staticmethod(
        lambda cmd, timeout=600: _proc(stderr="Error: no checks enabled.", rc=1)))
    res = ClangTidyAnalyzer().run([tmp_path / "a.c"], tmp_path)
    assert res.status == "failed" and "no checks enabled" in res.error


def test_clang_tidy_headers_are_skipped_not_analyzed(monkeypatch, tmp_path):
    cmds = []
    monkeypatch.setattr(ClangTidyAnalyzer, "_run", staticmethod(
        lambda cmd, timeout=600: cmds.append(cmd) or _proc()))
    res = ClangTidyAnalyzer().run([tmp_path / "a.c", tmp_path / "a.h"], tmp_path)
    assert res.status == "success"
    assert res.analyzed_files == ["a.c"] and res.skipped_files == ["a.h"]
    assert len(cmds) == 1 and "--header-filter=^$" in cmds[0]


# ------------------------------------------------------------------ compiler
@pytest.fixture
def need_cc():
    if CompilerAnalyzer._compiler() is None:
        pytest.skip("no C compiler installed")


def test_compiler_missing_header_is_a_failed_file(need_cc, tmp_path):
    (tmp_path / "ok.c").write_text(CLEAN_C)
    (tmp_path / "bad.c").write_text('#include "does_not_exist.h"\nint x;\n')
    res = CompilerAnalyzer().run([tmp_path / "ok.c", tmp_path / "bad.c"], tmp_path)
    assert res.status == "partial"
    assert res.analyzed_files == ["ok.c"] and res.failed_files == ["bad.c"]
    assert "does_not_exist.h" in res.error


def test_compiler_include_path_fixes_the_failure(need_cc, tmp_path):
    (tmp_path / "inc").mkdir()
    (tmp_path / "inc" / "cfg.h").write_text("#define N 1\n")
    (tmp_path / "a.c").write_text('#include "cfg.h"\nint x = N;\n')
    assert CompilerAnalyzer().run([tmp_path / "a.c"], tmp_path).status == "failed"
    res = CompilerAnalyzer().run([tmp_path / "a.c"], tmp_path, include_paths=[str(tmp_path / "inc")])
    assert res.status == "success" and res.analyzed_files == ["a.c"]


def test_compiler_plain_error_without_wflag_fails_file(monkeypatch, tmp_path):
    monkeypatch.setattr(CompilerAnalyzer, "_compiler", staticmethod(lambda: "gcc"))
    out = "src/a.c:1:10: fatal error: nope.h: No such file or directory\n"
    monkeypatch.setattr(CompilerAnalyzer, "_run", staticmethod(
        lambda cmd, timeout=120: _proc(stderr=out, rc=1)))
    res = CompilerAnalyzer().run([tmp_path / "a.c"], tmp_path)
    assert res.status == "failed" and "nope.h" in res.error


def test_compiler_promoted_warning_error_with_wflag_is_still_analyzed(monkeypatch, tmp_path):
    monkeypatch.setattr(CompilerAnalyzer, "_compiler", staticmethod(lambda: "gcc"))
    out = "a.c:3:5: error: comparing floating-point with '==' is unsafe [-Werror=float-equal]\n"
    monkeypatch.setattr(CompilerAnalyzer, "_run", staticmethod(
        lambda cmd, timeout=120: _proc(stderr=out, rc=1)))
    res = CompilerAnalyzer().run([tmp_path / "a.c"], tmp_path)
    assert res.status == "success" and res.analyzed_files == ["a.c"]
    assert len(res.findings) == 1


def test_compiler_no_compiler_is_failed_when_run_directly(monkeypatch, tmp_path):
    monkeypatch.setattr(CompilerAnalyzer, "_compiler", staticmethod(lambda: None))
    res = CompilerAnalyzer().run([tmp_path / "a.c"], tmp_path)
    assert res.status == "failed" and "no C compiler" in res.error


def test_compiler_std_and_flags_are_configurable(monkeypatch, tmp_path):
    monkeypatch.setattr(CompilerAnalyzer, "_compiler", staticmethod(lambda: "gcc"))
    cmds = []
    monkeypatch.setattr(CompilerAnalyzer, "_run", staticmethod(
        lambda cmd, timeout=120: cmds.append(cmd) or _proc()))
    CompilerAnalyzer().run([tmp_path / "a.c"], tmp_path,
                           options={"std": "c99", "compiler_flags": ["-DFOO=1", "-Iinc"]})
    assert "-std=c99" in cmds[0] and "-std=c11" not in cmds[0]
    assert "-DFOO=1" in cmds[0] and "-Iinc" in cmds[0]


def test_compiler_rejects_flags_that_can_run_code(monkeypatch, tmp_path):
    for bad in ("-fplugin=/tmp/x.so", "-Wl,--wrap", "-o", "--version"):
        with pytest.raises(ValueError):
            validate_compiler_flags([bad])
    assert validate_compiler_flags(["-DX", "-I/inc", "-std=c99", "-ffreestanding"])


def test_compile_commands_supply_per_file_flags(monkeypatch, tmp_path):
    import json
    src = tmp_path / "a.c"
    other = tmp_path / "b.c"
    (tmp_path / "compile_commands.json").write_text(json.dumps([
        {"directory": str(tmp_path), "file": "a.c",
         "command": "cc -c -DMODE=2 -I inc -std=c99 -fplugin=/x.so -O2 a.c"},
        {"directory": str(tmp_path), "file": str(other), "arguments": ["cc", "-DOTHER", "b.c"]},
    ]))
    table = load_compile_commands("compile_commands.json", tmp_path)
    assert table[str(src.resolve())] == ["-DMODE=2", f"-I{tmp_path / 'inc'}", "-std=c99"]
    monkeypatch.setattr(CompilerAnalyzer, "_compiler", staticmethod(lambda: "gcc"))
    cmds = []
    monkeypatch.setattr(CompilerAnalyzer, "_run", staticmethod(
        lambda cmd, timeout=120: cmds.append(cmd) or _proc()))
    CompilerAnalyzer().run([src, other], tmp_path,
                           options={"compile_commands": "compile_commands.json"})
    by_file = {c[-1]: c for c in cmds}
    assert "-DMODE=2" in by_file[str(src)] and "-DOTHER" not in by_file[str(src)]
    assert "-DOTHER" in by_file[str(other)]


def test_compile_commands_unreadable_is_a_clear_error(tmp_path):
    with pytest.raises(ValueError, match="compile_commands"):
        load_compile_commands("missing.json", tmp_path)


# -------------------------------------------------------------------- native
def test_native_unreadable_file_is_failed_not_clean(tmp_path):
    (tmp_path / "ok.c").write_text(CLEAN_C)
    res = NativeAnalyzer().run([tmp_path / "ok.c", tmp_path / "gone.c"], tmp_path)
    assert res.status == "partial"
    assert res.analyzed_files == ["ok.c"] and res.failed_files == ["gone.c"]


def test_run_scan_records_a_raising_analyzer_as_failed(monkeypatch, tmp_path):
    (tmp_path / "a.c").write_text(CLEAN_C)

    def explode(self, files, root, include_paths=None, options=None):
        raise RuntimeError("segfault in tool")
    monkeypatch.setattr(NativeAnalyzer, "run", explode)
    sr = run_scan_detailed(["a.c"], tmp_path, ["native"])
    assert sr.analyzers_used == []
    assert sr.errors and sr.errors[0]["analyzer"] == "native"
    assert "segfault" in sr.errors[0]["error"]
    assert sr.analyzed == {"native": set()}


# ------------------------------------------------- memory: who may clear what
def _finding(analyzer="cppcheck", file="a.c"):
    return Finding(rule_id="CERT EXP34-C", standard="CERT-C", severity="critical",
                   file=file, line=2, message="m", analyzer=analyzer,
                   line_content="*p = 1;", context_symbol="f")


@pytest.mark.parametrize("gate,expected", [(False, "resolved"), (True, "pending")])
def test_sync_scan_clears_only_when_the_producer_analyzed_the_file(tmp_path, gate, expected):
    mem = MemoryStore(tmp_path)
    f = _finding()
    mem.sync_scan([f], ["a.c"], analyzed={"cppcheck": {"a.c"}})
    diff = mem.sync_scan([], ["a.c"], gate=gate, analyzed={"cppcheck": {"a.c"}})
    assert diff[expected] == [f.fingerprint]


@pytest.mark.parametrize("analyzed", [
    {"cppcheck": set()},                                # tool failed outright
    {"cppcheck": {"other.c"}},                          # tool skipped this file
])
@pytest.mark.parametrize("gate", [False, True])
def test_sync_scan_failed_producer_clears_nothing(tmp_path, analyzed, gate):
    mem = MemoryStore(tmp_path)
    f = _finding()
    mem.sync_scan([f], ["a.c"], analyzed={"cppcheck": {"a.c"}})
    diff = mem.sync_scan([], ["a.c"], gate=gate, analyzed=analyzed)
    assert diff["resolved"] == [] and diff["pending"] == []
    assert mem.get_finding(f.fingerprint)["status"] == "open"


def test_sync_scan_merged_finding_needs_every_participating_producer(tmp_path):
    mem = MemoryStore(tmp_path)
    f = _finding(analyzer="native+cppcheck")
    mem.sync_scan([f], ["a.c"], analyzed={"native": {"a.c"}, "cppcheck": {"a.c"}})
    # native analyzed the file and found nothing, but cppcheck failed on it
    diff = mem.sync_scan([], ["a.c"], analyzed={"native": {"a.c"}, "cppcheck": set()})
    assert diff["resolved"] == []
    # cppcheck not part of the run at all (deselected): legacy behaviour, native decides
    diff = mem.sync_scan([], ["a.c"], analyzed={"native": {"a.c"}})
    assert diff["resolved"] == [f.fingerprint]


def test_sync_scan_never_clears_imported_findings(tmp_path):
    mem = MemoryStore(tmp_path)
    f = _finding(analyzer="qac")
    mem.sync_scan([f], [], analyzed={})
    diff = mem.sync_scan([], ["a.c"], analyzed={"native": {"a.c"}})
    assert diff["resolved"] == [] and diff["pending"] == []


# ---------------------------------------------------------- engine, end to end
def _project(tmp_path, body="int *p;\nvoid f(void) { *p = 1; }\n"):
    (tmp_path / "a.c").write_text(body)
    return LoopEngine(tmp_path)


def test_scan_failure_does_not_resolve_and_is_reported(monkeypatch, tmp_path):
    eng = _project(tmp_path)
    mode = {"fail": False}

    def behaviour(cmd):
        if mode["fail"]:
            raise subprocess.TimeoutExpired(cmd, 300)
        return _proc(stderr=CPPCHECK_OK.format(file=tmp_path / "a.c"))
    _use_fake_cppcheck(monkeypatch, behaviour)

    first = eng.scan(["a.c"], ["cppcheck"])
    assert first["analysis_complete"] is True and first["analyzer_errors"] == []
    assert first["open"] == 1
    fp = eng.mem.open_findings()[0]["fingerprint"]

    mode["fail"] = True
    for gate in (False, True):
        second = eng.scan(["a.c"], ["cppcheck"], gate=gate)
        assert second["analysis_complete"] is False
        assert second["analyzers_used"] == []
        assert second["analyzer_errors"][0]["analyzer"] == "cppcheck"
        assert "TimeoutExpired" in second["analyzer_errors"][0]["error"]
        assert "Analysis incomplete" in second["coverage_warning"]
        assert second["diff"]["resolved"] == 0 and second["diff"]["pending"] == 0
        assert eng.mem.get_finding(fp)["status"] == "open"


def test_verify_cannot_converge_while_an_analyzer_is_failing(monkeypatch, tmp_path):
    eng = _project(tmp_path, CLEAN_C)
    _use_fake_cppcheck(monkeypatch, lambda cmd: (_ for _ in ()).throw(OSError("no exec")))
    begun = eng.begin_session(["a.c"], {"analyzers": ["native", "cppcheck"]})
    assert begun["baseline"]["open"] == 0
    assert "Analysis incomplete" in begun["coverage_warning"]
    v = eng.verify(begun["session_id"])
    assert v["state"] == "analysis_incomplete"
    assert v["state"] != "converged"
    assert v["analyzer_errors"][0]["analyzer"] == "cppcheck"
    assert "cppcheck" in v["reason"]
    assert eng.mem.get_session(begun["session_id"])["status"] == "analysis_incomplete"

    # once the tool works again the same session converges
    _use_fake_cppcheck(monkeypatch, lambda cmd: _proc(stderr=CPPCHECK_EMPTY))
    v = eng.verify(begun["session_id"])
    assert v["state"] == "converged" and v["analysis_complete"] is True


def test_failing_analyzer_still_ends_in_budget_exhausted(monkeypatch, tmp_path):
    eng = _project(tmp_path, CLEAN_C)
    _use_fake_cppcheck(monkeypatch, lambda cmd: (_ for _ in ()).throw(OSError("no exec")))
    sid = eng.begin_session(["a.c"], {"analyzers": ["native", "cppcheck"],
                                      "max_iterations": 2})["session_id"]
    assert eng.verify(sid)["state"] == "analysis_incomplete"
    assert eng.verify(sid)["state"] == "budget_exhausted"


def test_compile_failure_keeps_compiler_findings_open(need_cc, tmp_path):
    """A missing header used to silence the compiler adapter, resolving its findings."""
    body = '#include "cfg.h"\nint f(int a, unsigned b) { return a < b; }\n'
    (tmp_path / "inc").mkdir()
    (tmp_path / "inc" / "cfg.h").write_text("#define N 1\n")
    (tmp_path / "a.c").write_text(body)
    eng = LoopEngine(tmp_path)
    r1 = eng.scan(["a.c"], ["compiler"], include_paths=[str(tmp_path / "inc")])
    assert r1["analysis_complete"] and r1["total_findings"] >= 1
    before = {f["fingerprint"] for f in eng.mem.open_findings()}
    assert before
    r2 = eng.scan(["a.c"], ["compiler"], gate=True)           # include path forgotten
    assert not r2["analysis_complete"]
    assert r2["analyzer_errors"][0]["analyzer"] == "compiler"
    assert {f["fingerprint"] for f in eng.mem.open_findings()} == before
    assert eng.mem.count_pending() == 0


def test_cli_prints_analyzer_failure_on_stderr(monkeypatch, tmp_path, capsys):
    from maishac import cli
    (tmp_path / "a.c").write_text(CLEAN_C)
    _use_fake_cppcheck(monkeypatch, lambda cmd: (_ for _ in ()).throw(OSError("no exec")))
    cli.main(["--project", str(tmp_path), "scan", "a.c", "--analyzers", "native,cppcheck"])
    cap = capsys.readouterr()
    assert "Analysis incomplete" in cap.err and "cppcheck" in cap.err
    assert '"analysis_complete": false' in cap.out


def test_scan_rejects_disallowed_compiler_flag(tmp_path):
    eng = _project(tmp_path, CLEAN_C)
    with pytest.raises(ValueError, match="Unsupported compiler flag"):
        eng.scan(["a.c"], ["native"], compiler_flags=["-fplugin=/tmp/x.so"])


# ------------------------------------------------------- plumbing (item 2)
def test_default_excludes_skip_vcs_build_and_dependency_dirs(tmp_path):
    for d in ("src", ".git", "build", "node_modules/pkg", "src/third_party", ".maishac"):
        (tmp_path / d).mkdir(parents=True)
        (tmp_path / d / "x.c").write_text("int x;\n")
    names = lambda fs: sorted(str(f.relative_to(tmp_path)) for f in fs)
    assert names(collect_c_files(["."], tmp_path)) == [
        "src/third_party/x.c", "src/x.c"]
    assert names(collect_c_files(["."], tmp_path, exclude=["third_party"])) == ["src/x.c"]
    assert names(collect_c_files(["."], tmp_path, exclude=["src/third_party"])) == ["src/x.c"]
    assert "build/x.c" in names(collect_c_files(["."], tmp_path, default_excludes=False))
    # naming an excluded directory (or file) explicitly still works
    assert names(collect_c_files(["build"], tmp_path)) == ["build/x.c"]
    assert names(collect_c_files(["build/x.c"], tmp_path)) == ["build/x.c"]


def test_engine_scan_honours_exclude(tmp_path):
    (tmp_path / "gen").mkdir()
    (tmp_path / "gen" / "g.c").write_text("int g;\n")
    (tmp_path / "m.c").write_text("int m;\n")
    eng = LoopEngine(tmp_path)
    assert eng.scan(["."], ["native"])["files_scanned"] == 2
    assert eng.scan(["."], ["native"], exclude=["gen"])["files_scanned"] == 1


def test_source_lines_reads_each_file_once(monkeypatch, tmp_path):
    (tmp_path / "a.c").write_text("int f(void)\n{\n    return 1;\n}\n")
    reads = []
    orig = Path.read_text
    monkeypatch.setattr(Path, "read_text",
                        lambda self, *a, **k: reads.append(self) or orig(self, *a, **k))
    src = SourceLines(tmp_path)
    assert src.line_of("a.c", 3)[0].strip() == "return 1;"
    assert src.line_of("a.c", 3)[1] == "f"
    assert src.line_of("a.c", 99) == ("", "")
    assert src.line_of("missing.c", 1) == ("", "")
    assert src.line_of("missing.c", 2) == ("", "")
    assert len([r for r in reads if r.name == "a.c"]) == 1


def test_line_of_is_defined_once():
    import maishac.analyzers.clang_tidy as ct
    import maishac.analyzers.compiler as cc
    import maishac.analyzers.cppcheck as cp
    for mod, cls in ((ct, ct.ClangTidyAnalyzer), (cc, cc.CompilerAnalyzer),
                     (cp, cp.CppcheckAnalyzer)):
        assert not hasattr(cls, "_line_of"), mod.__name__
