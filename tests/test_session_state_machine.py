"""Session state machine (item 16): validation, terminal-state guards, abort,
atomic begin, scope-aware convergence, stall / budget / needs_human endings."""

import json
import threading

import pytest

from maishac import cli
from maishac.engine import LoopEngine

CLEAN = '#include <stdint.h>\nint32_t ok(void)\n{\n    return 0;\n}\n'
MALLOC = 'void *f(void)\n{\n    return malloc(4);\n}\n'
MALLOC_TWICE = MALLOC + 'void *g(void)\n{\n    return malloc(8);\n}\n'
RISKY = 'int f(int x)\n{\n    if (x > 0)\n        return 1;\n    return 0;\n}\n'
NATIVE = {"analyzers": ["native"]}


def _proj(tmp_path, body, name="m.c"):
    proj = tmp_path / "p"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / name).write_text(body)
    return proj


def _begin(eng, cfg=None, paths=("src",)):
    out = eng.begin_session(list(paths), {**NATIVE, **(cfg or {})})
    assert "session_id" in out, out
    return out["session_id"]


def _sessions(eng):
    return eng.mem.db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]


# ------------------------------------------------------------- validation
@pytest.mark.parametrize("cfg, needle", [
    ({"verification_policy": "yolo"}, "verification_policy"),
    ({"severity_floor": "urgent"}, "severity_floor"),
    ({"max_iterations": 0}, "max_iterations"),
    ({"max_iterations": -3}, "max_iterations"),
    ({"batch_size": "five"}, "batch_size"),
    ({"batch_size": True}, "batch_size"),
    ({"stall_limit": 0}, "stall_limit"),
    ({"analyzers": ["native", "nope"]}, "nope"),
])
def test_begin_session_rejects_bad_settings(tmp_path, cfg, needle):
    eng = LoopEngine(_proj(tmp_path, CLEAN))
    out = eng.begin_session(["src"], cfg)
    assert "error" in out and needle in out["error"]
    assert _sessions(eng) == 0


def test_unknown_analyzer_error_lists_valid_names(tmp_path):
    eng = LoopEngine(_proj(tmp_path, CLEAN))
    out = eng.scan(["src"], ["cpcheck"])
    assert "error" in out
    for name in ("native", "cppcheck", "clang-tidy", "compiler"):
        assert name in out["error"]


# ------------------------------------------------------------ empty scans
def test_begin_session_on_no_files_is_an_error_and_leaves_no_session(tmp_path):
    eng = LoopEngine(_proj(tmp_path, CLEAN))
    out = eng.begin_session(["no_such_dir"], NATIVE)
    assert "error" in out and "No C source files" in out["error"]
    assert _sessions(eng) == 0
    assert eng.mem.latest_active_session() is None


def test_scan_on_no_files_is_an_error_and_records_nothing(tmp_path):
    eng = LoopEngine(_proj(tmp_path, CLEAN))
    out = eng.scan(["no_such_dir"], ["native"])
    assert "error" in out
    assert eng.mem.last_scan() is None


def test_verify_never_converges_when_the_files_have_vanished(tmp_path):
    proj = _proj(tmp_path, MALLOC)
    eng = LoopEngine(proj)
    sid = _begin(eng)
    (proj / "src" / "m.c").unlink()
    out = eng.verify(sid)
    assert "error" in out and out.get("state") != "converged"
    assert eng.session_status(sid)["state"] == "active"


# ----------------------------------------------------------- terminal guards
def test_ended_sessions_refuse_further_work(tmp_path):
    proj = _proj(tmp_path, CLEAN)
    eng = LoopEngine(proj)
    sid = _begin(eng)
    assert eng.verify(sid)["state"] == "converged"
    for call in (lambda: eng.next_batch(sid), lambda: eng.verify(sid),
                 lambda: eng.record_attempt(sid, "abc", "s"),
                 lambda: eng.abort_session(sid)):
        out = call()
        assert "error" in out and out["state"] == "converged"
    assert eng.session_status(sid)["iteration"] == 1     # the refused verify did not run


@pytest.mark.parametrize("state", ["converged", "budget_exhausted", "stalled",
                                   "needs_human", "aborted"])
def test_every_terminal_state_is_guarded(tmp_path, state):
    eng = LoopEngine(_proj(tmp_path, CLEAN))
    sid = _begin(eng)
    eng.mem.update_session(sid, status=state)
    assert "error" in eng.next_batch(sid)
    assert "error" in eng.verify(sid)
    assert "error" in eng.record_attempt(sid, "x", "s")


@pytest.mark.parametrize("state", ["active", "awaiting_verification", "analysis_incomplete"])
def test_live_states_still_accept_work(tmp_path, state):
    eng = LoopEngine(_proj(tmp_path, MALLOC))
    sid = _begin(eng)
    eng.mem.update_session(sid, status=state)
    assert "error" not in eng.next_batch(sid)
    assert "error" not in eng.record_attempt(sid, "x", "s")
    assert "error" not in eng.verify(sid)


def test_awaiting_verification_goes_on_to_converge_after_approval(tmp_path):
    proj = _proj(tmp_path, RISKY)
    eng = LoopEngine(proj)
    sid = _begin(eng)                                    # no test command => human_gated
    (proj / "src" / "m.c").write_text(CLEAN)
    out = eng.verify(sid)
    assert out["state"] == "awaiting_verification" and out["pending_verification"] >= 1
    assert "error" not in eng.next_batch(sid)            # not terminal
    for f in eng.mem.pending_findings():
        assert eng.approve(f["fingerprint"], "lead@example.com").get("ok")
    out = eng.verify(sid)
    assert out["state"] == "converged"


# ------------------------------------------------------------------ abort
def test_abort_ends_the_session_and_is_audit_logged(tmp_path):
    eng = LoopEngine(_proj(tmp_path, MALLOC))
    sid = _begin(eng)
    out = eng.abort_session(sid, "user changed plans", by="lead")
    assert out["state"] == "aborted"
    assert eng.session_status(sid)["state"] == "aborted"
    (entry,) = [e for e in eng.mem.audit_entries(action="session_end")
                if e["target"] == sid]
    assert entry["details"]["state"] == "aborted"
    assert entry["details"]["reason"] == "user changed plans"
    assert entry["actor"] == "lead"
    assert "error" in eng.abort_session(sid)             # twice is an error
    # the project can begin a fresh session now
    assert "session_id" in eng.begin_session(["src"], NATIVE)


def test_abort_unknown_session_raises_like_the_other_calls(tmp_path):
    eng = LoopEngine(_proj(tmp_path, CLEAN))
    with pytest.raises(ValueError):
        eng.abort_session("nope")


def test_cli_session_abort(tmp_path, capsys):
    proj = _proj(tmp_path, MALLOC)
    eng = LoopEngine(proj)
    sid = _begin(eng)
    cli.main(["--project", str(proj), "session", "abort", sid, "--reason", "done here"])
    out = json.loads(capsys.readouterr().out)
    assert out["state"] == "aborted" and out["reason"] == "done here"
    with pytest.raises(SystemExit) as e:
        cli.main(["--project", str(proj), "session", "abort", sid])
    assert e.value.code == 1


def test_cli_session_begin_severity_floor_and_validation(tmp_path, capsys):
    proj = _proj(tmp_path, CLEAN)
    cli.main(["--project", str(proj), "session", "begin", "src", "--severity-floor", "major"])
    sid = json.loads(capsys.readouterr().out)["session_id"]
    assert LoopEngine(proj).mem.get_session(sid)["config"]["severity_floor"] == "major"
    with pytest.raises(SystemExit) as e:
        cli.main(["--project", str(proj), "session", "begin", "src", "--max-iterations", "0",
                  "--force"])
    assert e.value.code == 1
    assert "max_iterations" in capsys.readouterr().err


def test_mcp_abort_tool(tmp_path, monkeypatch):
    pytest.importorskip("mcp")
    from maishac import mcp_server as m
    proj = _proj(tmp_path, MALLOC)
    monkeypatch.setenv("MAISHAC_PROJECT", str(proj))
    monkeypatch.setattr(m, "_ENGINE", None)
    sid = json.loads(m.compliance_begin_session(["src"]))["session_id"]
    out = json.loads(m.compliance_abort_session(sid, "no longer needed"))
    assert out["state"] == "aborted"
    assert "error" in json.loads(m.compliance_next_batch(sid))


# ------------------------------------------------------------ atomic begin
def test_concurrent_begin_session_creates_exactly_one_session(tmp_path):
    proj = _proj(tmp_path, MALLOC)
    LoopEngine(proj)                                     # create the database up front
    n = 6
    barrier = threading.Barrier(n, timeout=30)
    results, lock = [], threading.Lock()

    def worker():
        eng = LoopEngine(proj)
        barrier.wait()
        out = eng.begin_session(["src"], NATIVE)
        with lock:
            results.append(out)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert len(results) == n
    started = [r for r in results if "session_id" in r]
    refused = [r for r in results if "error" in r]
    assert len(started) == 1 and len(refused) == n - 1, results
    assert _sessions(LoopEngine(proj)) == 1


# ------------------------------------------------- scope-aware convergence
def test_convergence_respects_the_severity_floor(tmp_path):
    proj = _proj(tmp_path, MALLOC)                       # a 'critical' finding
    eng = LoopEngine(proj)
    sid = _begin(eng, {"severity_floor": "blocker"})
    out = eng.verify(sid)
    assert out["state"] == "converged"
    assert out["open_now"] == 0 and out["open_out_of_scope"] >= 1
    assert "outside this session" in out["reason"]
    assert eng.next_batch(sid).get("error")              # ended; and it never listed them


def test_findings_below_the_floor_are_not_in_the_batch(tmp_path):
    eng = LoopEngine(_proj(tmp_path, MALLOC))
    sid = _begin(eng, {"severity_floor": "blocker"})
    assert eng.next_batch(sid)["batch"] == []


def test_convergence_respects_the_session_paths(tmp_path):
    proj = _proj(tmp_path, CLEAN)
    (proj / "other").mkdir()
    (proj / "other" / "bad.c").write_text(MALLOC)
    eng = LoopEngine(proj)
    eng.scan(["other"], ["native"])                      # finding on record outside src/
    sid = _begin(eng)
    out = eng.verify(sid)
    assert out["state"] == "converged" and out["open_out_of_scope"] >= 1


def test_next_batch_only_lists_findings_under_the_session_paths(tmp_path):
    proj = _proj(tmp_path, MALLOC)
    (proj / "other").mkdir()
    (proj / "other" / "bad.c").write_text(MALLOC)
    eng = LoopEngine(proj)
    eng.scan(["other"], ["native"])
    sid = _begin(eng)
    locs = [b["location"] for b in eng.next_batch(sid)["batch"]]
    assert locs and all(loc.startswith("src/") for loc in locs)


# -------------------------------------------------------- endings
def test_stalled_when_nothing_improves(tmp_path):
    eng = LoopEngine(_proj(tmp_path, MALLOC))
    sid = _begin(eng)
    assert eng.verify(sid)["state"] == "active"
    out = eng.verify(sid)
    assert out["state"] == "stalled" and "No net progress" in out["reason"]


def test_progress_inside_the_window_prevents_a_stall(tmp_path):
    proj = _proj(tmp_path, MALLOC_TWICE)
    eng = LoopEngine(proj)
    sid = _begin(eng)
    (proj / "src" / "m.c").write_text(MALLOC)            # one fixed
    assert eng.verify(sid)["state"] == "active"
    assert eng.verify(sid)["state"] == "active"          # window start was higher


def test_stall_compares_the_window_start_with_now(tmp_path):
    """A count that rose and fell back to where the window began is no progress."""
    proj = _proj(tmp_path, MALLOC)
    eng = LoopEngine(proj)
    sid = _begin(eng)
    (proj / "src" / "m.c").write_text(MALLOC_TWICE)      # gets worse
    assert eng.verify(sid)["state"] == "active"
    (proj / "src" / "m.c").write_text(MALLOC)            # back to the start
    out = eng.verify(sid)
    assert out["state"] == "stalled", out


def test_budget_exhausted_ends_the_session_and_abandons_attempts(tmp_path):
    eng = LoopEngine(_proj(tmp_path, MALLOC))
    sid = _begin(eng, {"max_iterations": 1, "stall_limit": 5})
    fp = eng.mem.open_findings()[0]["fingerprint"]
    eng.record_attempt(sid, fp, "first idea")
    out = eng.verify(sid)
    assert out["state"] == "budget_exhausted"
    # verify first grades the attempt on a still-open finding as persisting
    assert eng.mem.attempts_for(fp)[0]["outcome"] == "persisting"
    assert eng.mem.get_session(sid)["end_reason"]
    ends = [e for e in eng.mem.audit_entries(action="session_end") if e["target"] == sid]
    assert ends and ends[0]["details"]["state"] == "budget_exhausted"


def test_oscillating_findings_end_the_session_as_needs_human(tmp_path):
    proj = _proj(tmp_path, MALLOC)
    eng = LoopEngine(proj)
    sid = _begin(eng, {"stall_limit": 10})
    bad = (proj / "src" / "m.c")

    def cycle():
        bad.write_text(CLEAN)
        assert eng.verify(sid)["state"] == "awaiting_verification"   # gated, not resolved
        bad.write_text(MALLOC)
        return eng.verify(sid)

    assert cycle()["state"] == "active"                  # regressed once
    out = cycle()                                        # regressed twice => frozen
    assert out["state"] == "needs_human"
    assert out["frozen_needs_human"] and "frozen" in out["reason"]
    assert eng.session_status(sid)["state"] == "needs_human"
    assert "error" in eng.verify(sid)
    ends = [e for e in eng.mem.audit_entries(action="session_end") if e["target"] == sid]
    assert ends[0]["details"]["state"] == "needs_human"


def test_analyzer_failure_never_converges(tmp_path, monkeypatch):
    """analysis_incomplete stays non-terminal (it can be verified again)."""
    from maishac.analyzers.base import AnalysisResult
    from maishac.analyzers.native import NativeAnalyzer
    proj = _proj(tmp_path, CLEAN)
    eng = LoopEngine(proj)
    sid = _begin(eng)

    def boom(self, files, root, include_paths=None, options=None):
        return AnalysisResult.failure(self.name, files, root, "boom")
    monkeypatch.setattr(NativeAnalyzer, "run", boom)
    out = eng.verify(sid)
    assert out["state"] == "analysis_incomplete"
    monkeypatch.undo()
    assert eng.verify(sid)["state"] == "converged"
