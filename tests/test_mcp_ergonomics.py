"""MCP server ergonomics (review item 21): tool bodies run off the event loop,
serialized, and path arguments are confined to the project root. Skipped when
the optional ``mcp`` extra is not installed."""

from __future__ import annotations

import asyncio
import json
import threading
import time

import pytest

BAD_C = ("#include <stdlib.h>\nvoid f(void)\n{\n    char *p = malloc(4);\n"
         "    free(p);\n}\n")


def _proj(tmp_path, text):
    (tmp_path / "src").mkdir(exist_ok=True)
    (tmp_path / "src" / "m.c").write_text(text)
    return tmp_path


# ---------------------------------------------------------------- item 21
mcp_mod = pytest.importorskip("mcp.server.fastmcp")  # noqa: F841
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
