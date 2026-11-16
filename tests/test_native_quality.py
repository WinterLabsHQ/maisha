"""Native analyzer quality: banned-call false positives, braceless-body parsing,
and the explicit rule registry (hardening items 24-27)."""

from __future__ import annotations

import re
from pathlib import Path

from maishac.analyzers import native
from maishac.analyzers.native import NativeAnalyzer


def _scan(code: str, tmp_path: Path):
    return NativeAnalyzer().analyze_source(code, "t.c", tmp_path)


def _lines(findings, rule_fragment: str) -> list[int]:
    return sorted(f.line for f in findings if rule_fragment in f.rule_id)


# ------------------------------------------------ 24: banned-call false positives
def test_member_access_is_not_a_banned_call(tmp_path):
    code = (
        "void g(struct ops *o, struct ops p, void *x) {\n"
        "    o->free(x);\n"
        "    p.free(x);\n"
        "    p.system();\n"
        "    o -> exit(1);\n"
        "}\n"
    )
    f = _scan(code, tmp_path)
    assert not [x for x in f if "banned function" in x.message], [x.message for x in f]


def test_declarations_and_definitions_are_not_banned_calls(tmp_path):
    code = (
        "char *strcpy(char *dest, const char *src);\n"
        "extern void exit_handler(void);\n"
        "static void *signal(int sig);\n"
        "void my_free(void *p) { }\n"
        "void exit_handler(void) { }\n"
        "int raise(int sig) { return sig; }\n"
        "#define free(p) my_free(p)\n"
    )
    f = _scan(code, tmp_path)
    assert not [x for x in f if "banned function" in x.message], [x.message for x in f]


def test_return_type_on_previous_line_is_a_definition_not_a_call(tmp_path):
    code = (
        "void\n"
        "free(void *p)\n"
        "{\n"
        "    my_free(p);\n"
        "}\n"
        "static char *\n"
        "strcpy(char *d, const char *s);\n"
        "void g(void *x) {\n"
        "    int a;\n"
        "    free(x);\n"
        "}\n"
    )
    f = _scan(code, tmp_path)
    assert _lines(f, "21.3") == [10], [x.message for x in f]
    assert not _lines(f, "STR31")


def test_banned_call_after_keyword_line_is_still_flagged(tmp_path):
    code = "void g(int c, void *x) {\nif (c)\nfree(x);\nelse\nfree(x);\n}\n"
    f = _scan(code, tmp_path)
    assert _lines(f, "21.3") == [3, 5], [x.message for x in f]


def test_real_banned_calls_still_flagged(tmp_path):
    code = (
        "void g(char *d, const char *s, void *x) {\n"
        "    free(x);\n"
        "    strcpy(d, s);\n"
        "    if (x) exit(1);\n"
        "    else abort();\n"
        "    d = (char *)malloc(4);\n"
        "    x = foo(system(\"ls\"));\n"
        "}\n"
        "int h(void) { return rand(); }\n"
    )
    f = _scan(code, tmp_path)
    got = {m.group(1) for x in f if (m := re.search(r"'(\w+)'", x.message))
           and "banned function" in x.message}
    assert got == {"free", "strcpy", "exit", "abort", "malloc", "system", "rand"}


# ------------------------------------------------------ 25: braceless control bodies
def test_do_while_tail_with_nested_call_is_not_15_6(tmp_path):
    code = (
        "int g(int);\n"
        "void f(int a, int b) {\n"
        "    do {\n"
        "        a++;\n"
        "    }\n"
        "    while (g(a) && g(b));\n"
        "    do\n"
        "    {\n"
        "        a++;\n"
        "    }\n"
        "    while (g(a));\n"
        "}\n"
    )
    assert _lines(_scan(code, tmp_path), "15.6") == []


def test_empty_body_loops_are_15_6(tmp_path):
    code = (
        "int g(int);\n"
        "void f(int a) {\n"
        "    if (a) {\n"
        "        a++;\n"
        "    }\n"
        "    while (g(a));\n"
        "    for (;;);\n"
        "}\n"
    )
    assert _lines(_scan(code, tmp_path), "15.6") == [6, 7]


def test_braceless_bodies_with_nested_parens_still_flagged(tmp_path):
    code = (
        "void f(int a, int b) {\n"
        "    if (g(a) && g(b)) b = g(a);\n"
        "    for (int i = 0; i < g(2); i++) b += i;\n"
        "    while (a) a--;\n"
        "}\n"
    )
    assert _lines(_scan(code, tmp_path), "15.6") == [2, 3, 4]


def test_braced_body_opening_on_header_line_is_not_15_6(tmp_path):
    code = (
        "void f(int a) {\n"
        "    if (g(a)) { a++;\n"
        "    }\n"
        "}\n"
    )
    assert _lines(_scan(code, tmp_path), "15.6") == []


# --------------------------------------------------------- 27: NATIVE_RULES registry
_QUERY_RE = re.compile(r'"((?:MISRA|CERT|BARR) [^"\n]*)"')


def test_native_rules_registry_matches_checks_in_source():
    """Every rule query written in native.py is registered, and vice versa.

    The scan lives in the test only; coverage.native_ids() reads the registry.
    """
    src = Path(native.__file__).read_text("utf-8")
    written = set(_QUERY_RE.findall(src))
    assert written, "source scan found nothing; the pattern is stale"
    assert written == set(native.NATIVE_RULES), (
        sorted(written - native.NATIVE_RULES), sorted(native.NATIVE_RULES - written))


def test_every_registered_rule_resolves_in_the_kb():
    from maishac.rules import REGISTRY
    assert [q for q in native.NATIVE_RULES if REGISTRY.resolve(q) is None] == []


def test_coverage_native_ids_reads_the_registry_not_the_source():
    from maishac import coverage
    from maishac.rules import REGISTRY
    assert coverage.native_ids() == {REGISTRY.resolve(q)["id"] for q in native.NATIVE_RULES}
    assert not hasattr(coverage, "_NATIVE_SRC")


def test_analyzer_refuses_an_unregistered_rule(tmp_path):
    import pytest
    a = NativeAnalyzer()
    with pytest.raises(ValueError):
        a._mk("MISRA 1.1", tmp_path / "x.c", tmp_path, 1, ["int x;"], "x")
