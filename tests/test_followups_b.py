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


# ---- B5: MISRA C:2012 Rule 15.2 ------------------------------------------

from maishac.analyzers.native import NATIVE_RULES, NativeAnalyzer  # noqa: E402


def _r152(tmp_path, code):
    f = tmp_path / "t.c"
    f.write_text(code)
    return [x.line for x in NativeAnalyzer().analyze([f], tmp_path)
            if x.rule_id.endswith(" 15.2")]


def test_b5_registered_as_native():
    assert "MISRA 15.2" in NATIVE_RULES


def test_b5_backward_goto_flagged_forward_goto_not(tmp_path):
    code = (
        "int f(int a)\n{\n"                     # 1-2
        "again:\n"                              # 3
        "    if (a > 0) {\n"                    # 4
        "        a--;\n"                        # 5
        "        goto again;\n"                 # 6  backward
        "    }\n"
        "    if (a < 0) {\n"
        "        goto out;\n"                   # 9  forward
        "    }\n"
        "out:\n"
        "    return a;\n}\n")
    assert _r152(tmp_path, code) == [6]


def test_b5_multiline_signatures_and_repeated_goto_cleanup(tmp_path):
    """The failure mode that got 15.2 withdrawn: every function has its own
    `cleanup:` and wrapped signatures hid the frames."""
    funcs = []
    for n in range(6):
        funcs.append(
            f"static int fn{n}(int alpha,\n"
            "               int beta,\n"
            "               char *gamma)\n"
            "{\n"
            "    int rc = 0;\n"
            "    if (alpha) {\n"
            "        goto cleanup;\n"
            "    }\n"
            "    if (beta) {\n"
            "        goto cleanup;\n"
            "    }\n"
            "cleanup:\n"
            "    return rc;\n"
            "}\n\n")
    assert _r152(tmp_path, "".join(funcs)) == []


def test_b5_label_of_another_function_is_not_resolved(tmp_path):
    code = (
        "int first(int a)\n{\n"
        "retry:\n"
        "    return a;\n}\n\n"
        "int second(int a,\n"
        "           int b)\n{\n"
        "    if (a) {\n"
        "        goto retry;\n"      # 11: no such label here -> not 15.2
        "    }\n"
        "    return b;\n}\n")
    assert _r152(tmp_path, code) == []


def test_b5_backward_goto_in_multiline_signature_function(tmp_path):
    code = (
        "int g(int a,\n"
        "      int b)\n"
        "{\n"
        "top:\n"
        "    a++;\n"
        "    if (a < b) {\n"
        "        goto top;\n"        # 7
        "    }\n"
        "    return a;\n}\n"
        "int h(int a)\n{\n"
        "    goto end;\n"
        "end:\n"
        "    return a;\n}\n")
    assert _r152(tmp_path, code) == [7]


def test_b5_case_default_ternary_and_ambiguous_labels_are_not_labels(tmp_path):
    code = (
        "int f(int a, int b)\n{\n"
        "    int r;\n"
        "    goto done;\n"                       # 4
        "    switch (a) {\n"
        "    case 1:\n"
        "        r = a ? b\n"
        "            : 0;\n"
        "        break;\n"
        "    default:\n"
        "        r = a ?\n"
        "            done :\n"
        "            b;\n"
        "        break;\n"
        "    }\n"
        "done:\n"
        "    return r;\n}\n")
    assert _r152(tmp_path, code) == []
    dup = (
        "int f(int a)\n{\n"
        "#if A\n"
        "x:\n"
        "#else\n"
        "x:\n"
        "#endif\n"
        "    if (a) {\n"
        "        goto x;\n"
        "    }\n"
        "    return a;\n}\n")
    assert _r152(tmp_path, dup) == []


def test_b5_no_function_frame_reports_nothing(tmp_path):
    assert _r152(tmp_path, "lbl:\n    goto lbl;\n") == []


def test_b5_goto_inside_macro_continuation_is_ignored(tmp_path):
    code = (
        "int f(int a)\n{\n"
        "again:\n"
        "#define RETRY() \\\n"
        "    goto again; \\\n"
        "    (void)0\n"
        "    return a;\n}\n")
    assert _r152(tmp_path, code) == []


def test_b5_readme_coverage_counts_derive_from_the_generator():
    """README quotes the enforced total and the native/clang-tidy/gcc reachable
    count; both come from maishac.coverage, so they cannot drift silently."""
    from pathlib import Path

    from maishac.coverage import analyzers_for, enforced_ids
    from maishac.rules import REGISTRY
    enforced = enforced_ids()
    reachable = sum(1 for r in enforced
                    if {a.split()[0] for a in analyzers_for(r)} & {"native", "clang-tidy", "compiler"})
    total = len(REGISTRY.all_ids())
    readme = (Path(__file__).resolve().parent.parent / "README.md").read_text("utf-8")
    assert f"| **Total** | **{total}** | **{len(enforced)}** |" in readme
    assert f"{reachable}/{len(enforced)} detectable rules active" in readme
    assert f"({reachable} of {len(enforced)} with native" in readme
