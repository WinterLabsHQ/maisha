"""An MCP agent must not be able to grade its own work. By default the MCP
sign-off tools only record proposals; a person finalizes them with the CLI."""

import inspect
import json

import pytest

pytest.importorskip("mcp.server.fastmcp")

from maishac import mcp_server as m  # noqa: E402
from maishac import report as report_mod  # noqa: E402
from maishac.cli import main  # noqa: E402
from maishac.engine import LoopEngine  # noqa: E402

BAD_C = ("#include <stdlib.h>\nvoid f(void)\n{\n    char *p = malloc(4);\n"
         "    free(p);\n}\n")
LONG_OK = "a justification that is long enough"


@pytest.fixture
def proj(tmp_path, monkeypatch):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "m.c").write_text(BAD_C)
    monkeypatch.setenv("MAISHAC_PROJECT", str(tmp_path))
    monkeypatch.delenv("MAISHAC_ALLOW_AGENT_APPROVALS", raising=False)
    monkeypatch.setattr(m, "_ENGINE", None)
    m.compliance_scan(["src"], analyzers=["native"])
    return tmp_path


def _fp(proj):
    return LoopEngine(proj).mem.open_findings()[0]["fingerprint"]


def _human(proj):
    return LoopEngine(proj)   # source="cli"


def test_suppress_is_only_a_proposal_by_default(proj):
    fp = _fp(proj)
    out = json.loads(m.compliance_suppress_finding(fp, LONG_OK))
    assert out["status"] == "pending_human" and "suppressed" not in out
    assert not _human(proj).mem.is_suppressed(fp)
    assert _human(proj).mem.get_finding(fp)["status"] == "open"


def test_deviation_and_recategorize_are_only_proposals(proj):
    d = json.loads(m.compliance_add_deviation("MISRA 21.3", "*", LONG_OK))
    r = json.loads(m.compliance_recategorize("MISRA 15.5", "required", "agreed with acquirer"))
    assert d["status"] == r["status"] == "pending_human"
    mem = _human(proj).mem
    assert mem.deviations() == [] and mem.recategorizations() == {}


def test_approve_is_only_a_proposal(proj):
    eng = _human(proj)
    fp = _fp(proj)
    eng.mem.db.execute("UPDATE findings SET status='pending_verification'")
    eng.mem.db.commit()
    out = json.loads(m.compliance_approve_finding(fp, "me"))
    assert out["status"] == "pending_human"
    assert _human(proj).mem.get_finding(fp)["status"] == "pending_verification"


def test_invalid_requests_fail_at_proposal_time(proj):
    fp = _fp(proj)
    assert "error" in json.loads(m.compliance_suppress_finding(fp, "short"))
    assert "error" in json.loads(m.compliance_suppress_finding("deadbeef", LONG_OK))
    assert "error" in json.loads(m.compliance_add_deviation("misra", "*", LONG_OK))
    assert "error" in json.loads(m.compliance_add_deviation("MISRA 22.2", "*", LONG_OK))
    assert "error" in json.loads(m.compliance_recategorize("MISRA 17.6", "advisory", "why not"))
    assert _human(proj).list_proposals() == []


def test_human_accepts_with_cli_and_is_recorded_as_approver(proj, capsys):
    fp = _fp(proj)
    pid = json.loads(m.compliance_suppress_finding(fp, LONG_OK))["proposal_id"]
    main(["-p", str(proj), "proposals", "list"])
    assert pid in capsys.readouterr().out
    with pytest.raises(SystemExit):                      # --by is mandatory
        main(["-p", str(proj), "proposals", "accept", pid])
    capsys.readouterr()
    main(["-p", str(proj), "proposals", "accept", pid, "--by", "lead@example.com"])
    mem = _human(proj).mem
    assert mem.is_suppressed(fp)
    sup = mem.suppressions()[0]
    assert sup["approver"] == "lead@example.com" and sup["source"] == "cli"
    assert mem.get_proposal(pid)["status"] == "accepted"
    with pytest.raises(SystemExit):                      # cannot be accepted twice
        main(["-p", str(proj), "proposals", "accept", pid, "--by", "lead"])
    actions = [a["action"] for a in mem.audit_entries()]
    assert "propose_suppress" in actions and "proposal_accepted" in actions


def test_accepting_a_deviation_proposal(proj):
    pid = json.loads(m.compliance_add_deviation(
        "MISRA 21.3", "src/*", LONG_OK, expires_days=30))["proposal_id"]
    out = _human(proj).accept_proposal(pid, "lead")
    assert out["status"] == "accepted"
    dev = _human(proj).mem.deviations()[0]
    assert dev["rule_id"] == "MISRA-C:2012 Rule 21.3" and dev["approver"] == "lead"
    assert dev["expires"] and dev["source"] == "cli"


def test_accept_revalidates(proj):
    pid = json.loads(m.compliance_recategorize(
        "MISRA 15.5", "mandatory", "agreed with acquirer"))["proposal_id"]
    pid2 = json.loads(m.compliance_add_deviation("MISRA 15.5", "*", LONG_OK))["proposal_id"]
    eng = _human(proj)
    assert eng.accept_proposal(pid, "lead")["status"] == "accepted"
    # 15.5 is Mandatory now: the earlier deviation proposal can no longer be applied
    out = eng.accept_proposal(pid2, "lead")
    assert "Mandatory" in out["error"] and eng.mem.get_proposal(pid2)["status"] == "pending_human"


def test_reject(proj, capsys):
    fp = _fp(proj)
    pid = json.loads(m.compliance_suppress_finding(fp, LONG_OK))["proposal_id"]
    main(["-p", str(proj), "proposals", "reject", pid, "--by", "lead", "-r", "not a false positive"])
    mem = _human(proj).mem
    assert mem.get_proposal(pid)["status"] == "rejected" and not mem.is_suppressed(fp)
    assert json.loads(m.compliance_list_proposals()) == []


def test_opt_in_env_restores_direct_behaviour_and_flags_it(proj, monkeypatch):
    monkeypatch.setenv("MAISHAC_ALLOW_AGENT_APPROVALS", "1")
    fp = _fp(proj)
    assert json.loads(m.compliance_suppress_finding(fp, LONG_OK))["suppressed"] == fp
    dev = json.loads(m.compliance_add_deviation("MISRA 21.4", "*", LONG_OK))
    assert "deviation_id" in dev
    mem = _human(proj).mem
    assert mem.suppressions()[0]["source"] == "mcp"
    assert mem.deviations()[0]["source"] == "mcp"
    assert mem.audit_entries()[0]["source"] == "mcp"
    md = report_mod.markdown_report(mem)
    assert "AGENT-ORIGINATED" in md and "applied directly by an MCP agent" in md
    assert "**[AGENT]**" in md
    assert report_mod.sarif(mem)["runs"][0]["results"]    # still exports


def test_opt_in_still_cannot_touch_mandatory_rules(proj, monkeypatch):
    monkeypatch.setenv("MAISHAC_ALLOW_AGENT_APPROVALS", "1")
    assert "Mandatory" in json.loads(m.compliance_add_deviation("MISRA 22.2", "*", LONG_OK))["error"]


def test_agent_driven_sarif_import_does_not_carry_suppressions(proj, tmp_path):
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "qe"}}, "results": [{
        "ruleId": "MISRA-C:2012 Rule 21.3", "message": {"text": "m"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/m.c"},
                                            "region": {"startLine": 4}}}],
        "suppressions": [{"kind": "external", "justification": "hide me"}]}]}]}
    f = tmp_path / "in.sarif"
    f.write_text(json.dumps(sarif))
    out = json.loads(m.compliance_import_sarif(str(f)))
    assert out["suppressions_carried"] == 0 and out["suppressions_ignored"] == 1
    assert out["open"] >= 1
    out = _human(proj).import_sarif(f)          # a person's import still carries them
    assert out["suppressions_carried"] == 1


def test_begin_session_has_no_test_command_argument():
    assert "test_command" not in inspect.signature(m.compliance_begin_session).parameters


def test_agent_cannot_set_test_command_through_begin_session(proj, monkeypatch):
    monkeypatch.delenv("MAISHAC_TEST_COMMAND", raising=False)
    with pytest.raises(TypeError):
        m.compliance_begin_session(["src"], test_command="touch /tmp/pwned")
    sid = json.loads(m.compliance_begin_session(["src"], force=True))["session_id"]
    cfg = m._engine().mem.get_session(sid)["config"]
    assert cfg["test_command"] is None


def test_mcp_engine_is_marked_as_agent_source(proj):
    assert m._engine().source == "mcp"
    sid = json.loads(m.compliance_begin_session(["src"], force=True))["session_id"]
    start = [a for a in m._engine().mem.audit_entries() if a["action"] == "session_start"][0]
    assert start["source"] == "mcp" and start["target"] == sid
