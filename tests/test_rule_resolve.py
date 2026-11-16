"""REGISTRY.resolve must be exact: authoritative operations (deviate, suppress,
recategorize, SARIF mapping) may never bind to a rule by substring."""

import pytest

from maishac.rules import REGISTRY


@pytest.mark.parametrize("query,expected", [
    ("MISRA 21.3", "MISRA-C:2012 Rule 21.3"),
    ("21.3", "MISRA-C:2012 Rule 21.3"),
    ("MISRA Rule 21.3", "MISRA-C:2012 Rule 21.3"),
    ("MISRA-C:2012 Rule 21.3", "MISRA-C:2012 Rule 21.3"),
    ("MISRA Dir 4.6", "MISRA-C:2012 Dir 4.6"),
    ("misra directive 4.6", "MISRA-C:2012 Dir 4.6"),
    ("MISRA 4.6", "MISRA-C:2012 Dir 4.6"),
    ("str31-c", "CERT STR31-C"),
    ("CERT STR31-C", "CERT STR31-C"),
    ("barr 1.3a", "BARR-C 1.3a"),
    ("BARR-C 1.3a", "BARR-C 1.3a"),
])
def test_resolve_accepts_explicit_references(query, expected):
    assert REGISTRY.resolve(query)["id"] == expected


@pytest.mark.parametrize("query", ["misra", "21", "MISRA", "cert", "Rule", "3", "str31",
                                   "MISRA 21.", "21.3.1", "", "   ", "MISRA 99.99"])
def test_resolve_rejects_partial_or_unknown(query):
    assert REGISTRY.resolve(query) is None


def test_dir_prefix_never_resolves_to_a_rule():
    # Rule 4.2 exists; there is no Directive 4.2.
    assert REGISTRY.resolve("MISRA Rule 4.2")["id"] == "MISRA-C:2012 Rule 4.2"
    assert REGISTRY.resolve("MISRA Dir 4.2") is None
    assert REGISTRY.resolve("Dir 4.2") is None


def test_ambiguous_bare_number_is_not_guessed(monkeypatch):
    rule = dict(REGISTRY.get("MISRA-C:2012 Rule 4.2"))
    d = dict(rule, id="MISRA-C:2012 Dir 4.2")
    monkeypatch.setitem(REGISTRY._rules, "MISRA-C:2012 Dir 4.2", d)
    assert REGISTRY.resolve("MISRA 4.2") is None
    assert "ambiguous" in REGISTRY.resolve_error("MISRA 4.2")
    assert REGISTRY.resolve("MISRA Rule 4.2")["id"] == "MISRA-C:2012 Rule 4.2"
    assert REGISTRY.resolve("MISRA Dir 4.2")["id"] == "MISRA-C:2012 Dir 4.2"


def test_error_message_is_helpful():
    msg = REGISTRY.resolve_error("misra")
    assert "Unknown rule" in msg and "MISRA 21.3" in msg


def test_loose_lookup_only_for_kb_cross_refs():
    assert REGISTRY.resolve("BARR-C 5.6") is None
    assert REGISTRY.resolve_loose("BARR-C 5.6")["id"] == "BARR-C 5.6a"
