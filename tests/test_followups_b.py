"""Round 2 follow-ups B1 (kill-tree platform branches) and B5 (MISRA 15.2)."""

import signal
import subprocess

from maishac.engine import _kill_tree


class _Proc:
    pid = 4242

    def __init__(self, kill_exc=None):
        self.killed = 0
        self._exc = kill_exc

    def kill(self):
        self.killed += 1
        if self._exc:
            raise self._exc


def test_b1_windows_uses_taskkill_tree_then_proc_kill():
    calls = []
    proc = _Proc()
    _kill_tree(proc, os_name="nt", run=lambda *a, **k: calls.append((a, k)),
               killpg=lambda *a: calls.append("killpg"))
    assert calls == [((["taskkill", "/F", "/T", "/PID", "4242"],),
                      {"capture_output": True, "timeout": 30})]
    assert proc.killed == 1


def test_b1_windows_errors_are_swallowed_and_proc_kill_still_runs():
    for exc in (OSError("no taskkill"),
                subprocess.TimeoutExpired("taskkill", 30),
                subprocess.SubprocessError("boom")):
        def run(*a, **k):
            raise exc
        proc = _Proc()
        _kill_tree(proc, os_name="nt", run=run)
        assert proc.killed == 1


def test_b1_proc_kill_oserror_is_swallowed():
    _kill_tree(_Proc(kill_exc=OSError("gone")), os_name="nt", run=lambda *a, **k: None)


def test_b1_posix_kills_process_group_not_taskkill():
    sent = []
    proc = _Proc()

    def run(*a, **k):
        raise AssertionError("taskkill must not run on POSIX")
    _kill_tree(proc, os_name="posix", run=run, killpg=lambda pid, sig: sent.append((pid, sig)))
    assert sent == [(4242, signal.SIGKILL)]
    assert proc.killed == 1


def test_b1_posix_killpg_failure_falls_back_to_proc_kill():
    def killpg(pid, sig):
        raise ProcessLookupError()
    proc = _Proc()
    _kill_tree(proc, os_name="posix", killpg=killpg)
    assert proc.killed == 1
