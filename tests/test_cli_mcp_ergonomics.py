"""CLI/MCP/CI-gate ergonomics and performance (review items 19-23).

* ``scan --fail-on`` / ``gate`` exit codes
* CLI turns expected errors into a message + exit 1, validates --project and
  closes its SQLite connections
* the MCP server runs tool bodies off the event loop, serialized, and confines
  path arguments to the project root
* search_notes treats % and _ literally
* sync_scan / verify do not issue per-finding queries
"""

from __future__ import annotations

import asyncio
import json
import threading
import time

import pytest

from maishac import cli
from maishac.engine import LoopEngine, gate_verdict
from maishac.memory import MemoryStore
from maishac.model import Finding

BAD_C = ("#include <stdlib.h>\nvoid f(void)\n{\n    char *p = malloc(4);\n"
         "    free(p);\n}\n")
CLEAN_C = ("#include <stdint.h>\nstatic int32_t add(int32_t a, int32_t b)\n{\n"
           "    return a + b;\n}\n")


def run(argv, capsys):
    code = 0
    try:
        cli.main(argv)
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
    cap = capsys.readouterr()
    try:
        out = json.loads(cap.out)
    except ValueError:
        out = cap.out
    return out, cap.err, code


def _proj(tmp_path, text):
    (tmp_path / "src").mkdir(exist_ok=True)
    (tmp_path / "src" / "m.c").write_text(text)
    return tmp_path


# ---------------------------------------------------------------- item 19
def test_scan_without_fail_on_exits_zero_even_with_findings(tmp_path, capsys):
    p = _proj(tmp_path, BAD_C)
    out, _, code = run(["-p", str(p), "scan", "src", "--analyzers", "native"], capsys)
    assert code == 0 and out["total_findings"] >= 1 and "gate" not in out


def test_fail_on_any_exits_1_on_findings(tmp_path, capsys):
    p = _proj(tmp_path, BAD_C)
    out, err, code = run(["-p", str(p), "scan", "src", "--analyzers", "native",
                          "--fail-on", "any", "--allow-degraded"], capsys)
    assert code == 1
    assert out["gate"]["exit_code"] == 1 and out["gate"]["blocking_findings"] >= 1
    assert "gate:" in err


def test_findings_take_precedence_over_degraded(tmp_path, capsys):
    p = _proj(tmp_path, BAD_C)
    # native-only is a degraded toolchain, but the findings still decide: exit 1
    _, _, code = run(["-p", str(p), "scan", "src", "--analyzers", "native",
                      "--fail-on", "any"], capsys)
    assert code == 1


def test_clean_degraded_scan_exits_2_unless_allowed(tmp_path, capsys):
    p = _proj(tmp_path, CLEAN_C)
    out, _, code = run(["-p", str(p), "scan", "src", "--analyzers", "native",
                        "--fail-on", "any"], capsys)
    assert out["open"] == 0
    assert code == 2 and out["gate"]["degraded"] is True
    _, _, code = run(["-p", str(p), "scan", "src", "--analyzers", "native",
                      "--fail-on", "any", "--allow-degraded"], capsys)
    assert code == 0


def test_fail_on_none_never_fails_on_findings(tmp_path, capsys):
    p = _proj(tmp_path, BAD_C)
    _, _, code = run(["-p", str(p), "scan", "src", "--analyzers", "native",
                      "--fail-on", "none", "--allow-degraded"], capsys)
    assert code == 0
    _, _, code = run(["-p", str(p), "scan", "src", "--analyzers", "native",
                      "--fail-on", "none"], capsys)
    assert code == 2     # ...but a degraded analysis still is reported


def test_gate_command_defaults_to_any(tmp_path, capsys):
    p = _proj(tmp_path, BAD_C)
    out, _, code = run(["-p", str(p), "gate", "src", "--analyzers", "native",
                        "--allow-degraded"], capsys)
    assert code == 1 and out["gate"]["fail_on"] == "any"


def test_fail_on_rejects_unknown_value(tmp_path, capsys):
    p = _proj(tmp_path, BAD_C)
    _, err, code = run(["-p", str(p), "scan", "src", "--fail-on", "severe"], capsys)
    assert code == 2 and "invalid choice" in err      # argparse usage error


def test_gate_verdict_severity_thresholds():
    res = {"open_by_severity": {"blocker": 0, "critical": 0, "major": 2, "minor": 5, "info": 1},
           "analyzer_errors": [], "toolchain": {"degraded": False}}
    assert gate_verdict(res, "blocker")["exit_code"] == 0
    assert gate_verdict(res, "critical")["exit_code"] == 0
    assert gate_verdict(res, "major")["exit_code"] == 1
    assert gate_verdict(res, "major")["blocking_findings"] == 2
    assert gate_verdict(res, "minor")["blocking_findings"] == 7
    assert gate_verdict(res, "any")["blocking_findings"] == 8
    assert gate_verdict(res, "none")["exit_code"] == 0
    with pytest.raises(ValueError):
        gate_verdict(res, "bogus")


def test_gate_verdict_analyzer_failure_is_exit_2():
    res = {"open_by_severity": {}, "toolchain": {"degraded": False},
           "analyzer_errors": [{"analyzer": "cppcheck", "status": "failed", "error": "boom"}]}
    v = gate_verdict(res, "any")
    assert v["exit_code"] == 2 and "cppcheck" in v["reason"]
    assert gate_verdict(res, "any", allow_degraded=True)["exit_code"] == 0
    # real findings still win
    res["open_by_severity"] = {"major": 1}
    assert gate_verdict(res, "any")["exit_code"] == 1


# ---------------------------------------------------------------- item 20
def test_unknown_session_is_a_clean_error(tmp_path, capsys):
    p = _proj(tmp_path, BAD_C)
    for action in ("batch", "verify", "status"):
        out, err, code = run(["-p", str(p), "session", action, "nosuchid"], capsys)
        assert code == 1, action
        assert "Unknown session" in err and "Traceback" not in err


def test_missing_project_dir_is_rejected(tmp_path, capsys):
    _, err, code = run(["-p", str(tmp_path / "nope"), "findings"], capsys)
    assert code == 1 and "--project" in err
    assert not (tmp_path / "nope").exists()


def test_scan_unknown_analyzer_lists_valid_names(tmp_path, capsys):
    p = _proj(tmp_path, BAD_C)
    _, err, code = run(["-p", str(p), "scan", "src", "--analyzers", "native,lint"], capsys)
    assert code == 1
    assert "lint" in err and "compiler" in err and "clang-tidy" in err


def test_scan_analyzers_tolerates_spaces(tmp_path, capsys):
    p = _proj(tmp_path, BAD_C)
    out, _, code = run(["-p", str(p), "scan", "src", "--analyzers", "native, "], capsys)
    assert code == 0 and out["analyzers_used"] == ["native"]


def test_cli_closes_its_database_connections(tmp_path, capsys, monkeypatch):
    p = _proj(tmp_path, BAD_C)
    opened: list[LoopEngine] = []

    class Spy(LoopEngine):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            opened.append(self)

    monkeypatch.setattr(cli, "LoopEngine", Spy)
    run(["-p", str(p), "scan", "src", "--analyzers", "native"], capsys)
    run(["-p", str(p), "session", "batch", "nosuchid"], capsys)      # error path too
    assert len(opened) == 2
    assert all(e.mem.db is None for e in opened)


def test_memory_store_close_and_context_manager(tmp_path):
    with MemoryStore(tmp_path) as mem:
        mem.add_note("x")
        db = mem.db
    assert mem.db is None
    with pytest.raises(Exception):
        db.execute("SELECT 1")
    mem.close()          # idempotent


# ---------------------------------------------------------------- item 22
def test_search_notes_escapes_like_wildcards(tmp_path):
    with MemoryStore(tmp_path) as mem:
        mem.add_note("coverage is 100% done", "status")
        mem.add_note("plain note", "misc")
        mem.add_note("snake_case naming", "style")
        mem.add_note("snakeXcase different", "style2")
        assert [n["content"] for n in mem.search_notes("%")] == ["coverage is 100% done"]
        assert mem.search_notes("100%") and not mem.search_notes("10%0")
        assert [n["content"] for n in mem.search_notes("snake_case")] == ["snake_case naming"]
        assert [n["content"] for n in mem.search_notes("_")] == ["snake_case naming"]
        assert len(mem.search_notes("note")) == 1
        assert [n["content"] for n in mem.search_notes("a\\b")] == []


# ---------------------------------------------------------------- item 23
def _finding(i: int, rule="MISRA-C:2012 Rule 21.3") -> Finding:
    return Finding(rule_id=rule, standard="MISRA-C:2012", severity="critical",
                   file=f"src/f{i}.c", line=i + 1, message="m", analyzer="native",
                   line_content=f"x{i} = malloc({i});", context_symbol="f")


def _count(mem, tables, fn):
    stmts: list[str] = []
    mem.db.set_trace_callback(stmts.append)
    try:
        fn()
    finally:
        mem.db.set_trace_callback(None)
    return {t: sum(1 for s in stmts if s.lstrip().upper().startswith("SELECT") and t in s)
            for t in tables}, stmts


def test_sync_scan_reads_waiver_tables_once_not_per_finding(tmp_path):
    tables = ("suppressions", "deviations", "recategorizations")
    results = {}
    for n in (3, 40):
        (tmp_path / f"p{n}").mkdir()
        with MemoryStore(tmp_path / f"p{n}") as mem:
            mem.add_deviation("MISRA 21.6", "src/f1.c", "justification long enough")
            findings = [_finding(i, "MISRA-C:2012 Rule 21.6" if i % 2 else "CERT STR31-C")
                        for i in range(n)]
            counts, _ = _count(mem, tables, lambda: mem.sync_scan(
                findings, [f.file for f in findings]))
            results[n] = counts
    assert results[3] == results[40]
    assert all(c <= 1 for c in results[40].values()), results[40]


def test_sync_scan_waiver_behavior_unchanged(tmp_path):
    with MemoryStore(tmp_path) as mem:
        a, b, c = _finding(1, "MISRA-C:2012 Rule 21.6"), _finding(2, "MISRA-C:2012 Rule 21.6"), \
            _finding(3, "CERT STR31-C")
        mem.sync_scan([a, b, c], [a.file, b.file, c.file])
        mem.add_deviation("MISRA 21.6", a.file, "justification long enough")
        mem.suppress(c.fingerprint, "reason is long enough")
        diff = mem.sync_scan([a, b, c], [a.file, b.file, c.file])
        assert diff["deviated"] == [a.fingerprint]
        assert diff["suppressed"] == [c.fingerprint]
        assert diff["persisting"] == [b.fingerprint]


def test_verify_closes_pending_attempts_with_one_update(tmp_path):
    p = _proj(tmp_path, "#include <stdlib.h>\n"
              + "".join(f"void f{i}(void)\n{{\n    char *p{i} = malloc({i + 1});\n"
                        f"    free(p{i});\n}}\n" for i in range(6)))
    eng = LoopEngine(p)
    sid = eng.begin_session(["src"], {"analyzers": ["native"],
                                      "verification_policy": "human_gated"})["session_id"]
    batch = eng.next_batch(sid)["batch"]
    assert len(batch) >= 3
    for f in batch:
        eng.record_attempt(sid, f["fingerprint"], "try something")
    _, stmts = _count(eng.mem, (), lambda: eng.verify(sid))
    closes = [s for s in stmts if "UPDATE fix_attempts" in s and "'persisting'" in s]
    assert len(closes) == 1
    assert {a["outcome"] for f in batch for a in eng.mem.attempts_for(f["fingerprint"])} \
        == {"persisting"}
    eng.close()


# ---------------------------------------------------------------- item 21
mcp_mod = pytest.importorskip("mcp.server.fastmcp")
from maishac import mcp_server as m  # noqa: E402


@pytest.fixture
def mproj(tmp_path, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()
    _proj(proj, BAD_C)
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "x.c").write_text(BAD_C)
    monkeypatch.setenv("MAISHAC_PROJECT", str(proj))
    monkeypatch.delenv("MAISHAC_ALLOW_OUTSIDE_PROJECT", raising=False)
    monkeypatch.setattr(m, "_ENGINE", None)
    yield proj
    if m._ENGINE is not None:
        m._ENGINE.close()


def test_mcp_scan_inside_project_is_allowed(mproj):
    out = json.loads(m.compliance_scan(["src"], analyzers=["native"]))
    assert out["total_findings"] >= 1


@pytest.mark.parametrize("bad", ["../outside", "../outside/x.c", "/etc", "src/../../outside"])
def test_mcp_scan_rejects_paths_outside_project(mproj, bad):
    out = json.loads(m.compliance_scan([bad], analyzers=["native"]))
    assert "outside the project root" in out["error"]


def test_mcp_absolute_path_inside_project_is_fine(mproj):
    out = json.loads(m.compliance_scan([str(mproj / "src")], analyzers=["native"]))
    assert "error" not in out


def test_mcp_symlink_escape_is_rejected(mproj, tmp_path):
    link = mproj / "link"
    try:
        link.symlink_to(tmp_path / "outside", target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable")
    out = json.loads(m.compliance_scan(["link"], analyzers=["native"]))
    assert "outside the project root" in out["error"]


def test_mcp_rejects_outside_include_exclude_compile_commands_and_flags(mproj):
    for kw in ({"include_paths": ["../outside"]}, {"exclude": ["../outside"]},
               {"exclude": ["/abs"]}, {"compile_commands": "../outside/cc.json"},
               {"compiler_flags": ["-I../outside"]}, {"compiler_flags": ["-isystem/etc"]}):
        out = json.loads(m.compliance_scan(["src"], analyzers=["native"], **kw))
        assert "outside the project root" in out.get("error", ""), kw
    ok = json.loads(m.compliance_scan(["src"], analyzers=["native"], exclude=["gen/*"],
                                      include_paths=["src"], compiler_flags=["-DX=1"]))
    assert "error" not in ok


def test_mcp_begin_session_rejects_outside_paths(mproj):
    out = json.loads(m.compliance_begin_session(["../outside"]))
    assert "outside the project root" in out["error"]
    assert "session_id" not in out


def test_mcp_import_sarif_rejects_outside_path(mproj, tmp_path):
    sarif = tmp_path / "outside" / "r.sarif"
    sarif.write_text(json.dumps({"version": "2.1.0", "runs": []}))
    out = json.loads(m.compliance_import_sarif(str(sarif)))
    assert "outside the project root" in out["error"]
    out = json.loads(m.compliance_import_sarif("../outside/r.sarif"))
    assert "outside the project root" in out["error"]


def test_mcp_outside_project_override(mproj, monkeypatch):
    monkeypatch.setenv("MAISHAC_ALLOW_OUTSIDE_PROJECT", "1")
    out = json.loads(m.compliance_scan(["../outside"], analyzers=["native"]))
    assert "error" not in out and out["files_scanned"] == 1


def test_mcp_tools_run_off_the_event_loop_one_at_a_time(mproj, monkeypatch):
    seen: list[int] = []
    active = {"now": 0, "max": 0}

    class FakeMem:
        def stats(self):
            seen.append(threading.get_ident())
            active["now"] += 1
            active["max"] = max(active["max"], active["now"])
            time.sleep(0.05)
            active["now"] -= 1
            return {}

    class FakeEngine:
        mem = FakeMem()

    monkeypatch.setattr(m, "_engine", lambda: FakeEngine())

    async def go():
        loop_thread = threading.get_ident()
        # the event loop stays responsive while the tool bodies block
        ticks = []

        async def ticker():
            for _ in range(5):
                ticks.append(1)
                await asyncio.sleep(0.01)

        await asyncio.gather(ticker(), *[m.mcp.call_tool("memory_stats", {}) for _ in range(4)])
        return loop_thread, len(ticks)

    loop_thread, ticks = asyncio.run(go())
    assert len(seen) == 4 and loop_thread not in seen
    assert active["max"] == 1          # serialized by the lock
    assert ticks == 5


def test_mcp_engine_is_usable_from_different_worker_threads(mproj):
    async def go():
        for _ in range(3):
            await m.mcp.call_tool("memory_note", {"content": "hello"})
        return await m.mcp.call_tool("compliance_scan",
                                     {"paths": ["src"], "analyzers": ["native"]})

    asyncio.run(go())
    assert len(m._engine().mem.search_notes("hello")) == 3


def test_mcp_tool_functions_stay_plain_callables():
    import inspect
    assert not inspect.iscoroutinefunction(m.compliance_scan)
    tools = asyncio.run(m.mcp.list_tools())
    assert {"compliance_scan", "compliance_abort_session"} <= {t.name for t in tools}
    scan = next(t for t in tools if t.name == "compliance_scan")
    assert "paths" in scan.inputSchema["properties"]
