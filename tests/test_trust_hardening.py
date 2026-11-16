"""Trust hardening (A5): human confirmation for `proposals accept`, actor audit,
and test_command integrity. These raise the cost of an agent with a shell; they
do not stop one that can edit .maishac/memory.db (see SECURITY.md)."""

import json
import sqlite3
import sys

import pytest

from maishac import doctor, report, trust
from maishac.cli import main
from maishac.engine import LoopEngine
from maishac.memory import MemoryStore

BAD_C = "#include <stdlib.h>\nvoid f(void)\n{\n    char *p = malloc(4);\n    free(p);\n}\n"
LONG_OK = "a justification that is long enough"


@pytest.fixture
def proj(tmp_path, monkeypatch):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "m.c").write_text(BAD_C)
    monkeypatch.setenv("MAISHAC_USER_DIR", str(tmp_path / "userdir"))
    for v in ("MAISHAC_HUMAN", "MAISHAC_CONFIRM_TOKEN", "MAISHAC_TEST_COMMAND",
              "MAISHAC_ALLOW_AGENT_APPROVALS"):
        monkeypatch.delenv(v, raising=False)
    return tmp_path


def _proposal(proj):
    eng = LoopEngine(proj)
    eng.scan(["src"], ["native"])
    fp = eng.mem.open_findings(limit=1)[0]["fingerprint"]
    pid = eng.propose("suppress", fingerprint=fp, reason=LONG_OK)["proposal_id"]
    eng.close()
    return pid, fp


def _accept(proj, pid, *extra):
    return main(["-p", str(proj), "proposals", "accept", pid, "--by", "lead", *extra])


def _status(proj, pid):
    mem = MemoryStore(proj)
    try:
        return mem.get_proposal(pid)["status"]
    finally:
        mem.close()


def _tty(monkeypatch, value):
    monkeypatch.setattr(trust, "_is_tty", lambda: value)


def test_non_tty_accept_refused_even_with_yes(proj, monkeypatch, capsys):
    pid, _ = _proposal(proj)
    _tty(monkeypatch, False)
    with pytest.raises(SystemExit) as e:
        _accept(proj, pid, "--yes")
    assert e.value.code == 1 and "terminal" in capsys.readouterr().err
    assert _status(proj, pid) == "pending_human"


def test_non_tty_yes_and_human_env_still_needs_token(proj, monkeypatch, capsys):
    pid, _ = _proposal(proj)
    _tty(monkeypatch, False)
    monkeypatch.setenv("MAISHAC_HUMAN", "1")
    with pytest.raises(SystemExit):
        _accept(proj, pid, "--yes")                 # no token registered
    trust.set_confirm_token("s3cret-token")
    with pytest.raises(SystemExit):
        _accept(proj, pid, "--yes")                 # registered, none supplied
    monkeypatch.setenv("MAISHAC_CONFIRM_TOKEN", "wrong-token-x")
    with pytest.raises(SystemExit):
        _accept(proj, pid, "--yes")
    assert _status(proj, pid) == "pending_human"


def test_non_tty_token_accept_works_and_records_actor(proj, monkeypatch):
    pid, fp = _proposal(proj)
    _tty(monkeypatch, False)
    trust.set_confirm_token("s3cret-token")
    monkeypatch.setenv("MAISHAC_HUMAN", "1")
    monkeypatch.setenv("MAISHAC_CONFIRM_TOKEN", "s3cret-token")
    _accept(proj, pid, "--yes")
    mem = MemoryStore(proj)
    assert mem.get_proposal(pid)["status"] == "accepted"
    entry = mem.last_audit("proposal_accepted")
    ctx = entry["details"]["actor_context"]
    assert ctx["os_user"] and ctx["tty"] is False and ctx["confirm_method"] == "token"
    assert ctx["confirmed_at"] > 0
    mem.close()


def test_tty_prompt_requires_typing_the_id(proj, monkeypatch, capsys):
    pid, _ = _proposal(proj)
    _tty(monkeypatch, True)
    monkeypatch.setattr("builtins.input", lambda *_: "yes")
    with pytest.raises(SystemExit):
        _accept(proj, pid)
    assert _status(proj, pid) == "pending_human"
    monkeypatch.setattr("builtins.input", lambda *_: pid)
    _accept(proj, pid)
    mem = MemoryStore(proj)
    ctx = mem.last_audit("proposal_accepted")["details"]["actor_context"]
    assert ctx["tty"] is True and ctx["confirm_method"] == "tty-prompt"
    mem.close()


def test_tty_yes_without_human_signal_still_prompts(proj, monkeypatch):
    pid, _ = _proposal(proj)
    _tty(monkeypatch, True)
    monkeypatch.setattr("builtins.input", lambda *_: "")
    with pytest.raises(SystemExit):
        _accept(proj, pid, "--yes")
    assert _status(proj, pid) == "pending_human"


def test_confirm_token_is_stored_hashed(proj):
    path = trust.set_confirm_token("s3cret-token")
    assert "s3cret-token" not in path.read_text()
    assert trust.verify_confirm_token("s3cret-token")
    assert not trust.verify_confirm_token("nope")
    with pytest.raises(ValueError):
        trust.set_confirm_token("short")


def test_token_record_format_is_versioned_kdf(proj):
    import json

    path = trust.set_confirm_token("s3cret-token")
    rec = json.loads(path.read_text())["hash"]
    assert rec.startswith(("scrypt$16384$8$1$", "pbkdf2$"))
    assert "s3cret-token" not in rec
    assert trust.token_configured()
    assert trust.verify_confirm_token("s3cret-token")
    assert not trust.verify_confirm_token("s3cret-tokeN")
    assert not trust.verify_confirm_token("")


def test_pbkdf2_fallback_when_scrypt_missing(proj, monkeypatch):
    monkeypatch.delattr(trust.hashlib, "scrypt")
    path = trust.set_confirm_token("s3cret-token")
    assert "pbkdf2$600000$" in path.read_text()
    assert trust.verify_confirm_token("s3cret-token")
    assert not trust.verify_confirm_token("wrong-token")


def test_old_sha256_record_is_rejected_cleanly(proj, monkeypatch):
    import hashlib
    import json

    path = trust._token_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    salt = "ab" * 16
    old = hashlib.sha256((salt + "s3cret-token").encode()).hexdigest()
    path.write_text(json.dumps({"salt": salt, "sha256": old}))
    assert not trust.token_configured()
    assert not trust.verify_confirm_token("s3cret-token")
    path.write_text("not json")
    assert not trust.token_configured()
    monkeypatch.setattr(trust, "_is_tty", lambda: False)
    monkeypatch.setenv(trust.HUMAN_ENV, "1")
    monkeypatch.setenv(trust.TOKEN_ENV, "s3cret-token")
    ctx, why = trust.confirm_accept("p1", "x", True)
    assert ctx is None and "set-token" in why


def test_reject_and_agent_approval_optout_unaffected(proj, monkeypatch):
    pid, _ = _proposal(proj)
    _tty(monkeypatch, False)
    main(["-p", str(proj), "proposals", "reject", pid, "--by", "lead", "-r", "no"])
    assert _status(proj, pid) == "rejected"
    monkeypatch.setenv("MAISHAC_ALLOW_AGENT_APPROVALS", "1")
    from maishac.engine import agent_approvals_allowed
    assert agent_approvals_allowed()


def _write_cfg(proj, cmd):
    d = proj / ".maishac"
    d.mkdir(exist_ok=True)
    (d / "config.json").write_text(json.dumps({"test_command": cmd}))


def _session(proj):
    eng = LoopEngine(proj)
    out = eng.begin_session(["src"], {"analyzers": ["native"]})
    sid = out["session_id"]
    eng.mem.update_session(sid, status="aborted")
    return eng, sid


def test_test_command_change_is_audit_logged(proj):
    _write_cfg(proj, f"{sys.executable} -c pass")
    eng, _ = _session(proj)
    first = eng.mem.last_audit("test_command_change")
    assert first["details"]["old_sha256"] == "" and first["details"]["origin"] == "config"
    assert first["details"]["config_mtime"] > 0
    _write_cfg(proj, f"{sys.executable} -c 'print(1)'")
    eng2, _ = _session(proj)
    last = eng2.mem.last_audit("test_command_change")
    assert last["details"]["old_sha256"] == first["details"]["new_sha256"]
    assert last["details"]["new_sha256"] != first["details"]["new_sha256"]
    assert last["actor"]
    n = len(eng2.mem.audit_entries(500, "test_command_change"))
    _session(proj)                                   # unchanged: no new entry
    assert len(eng2.mem.audit_entries(500, "test_command_change")) == n


def test_session_records_hash_and_report_flags_difference(proj):
    _write_cfg(proj, f"{sys.executable} -c pass")
    eng, sid = _session(proj)
    sess = eng.mem.get_session(sid)
    assert sess["config"]["test_command_sha256"] == trust.sha(f"{sys.executable} -c pass")
    md = report.markdown_report(eng.mem)
    assert "Test command: sha256" in md and "WARNING: the test command" not in md
    _write_cfg(proj, "true")                         # edited after the session began
    md = report.markdown_report(eng.mem)
    assert "WARNING: the test command now configured differs" in md
    assert report.last_scan_info(eng.mem)["test_command"]["differs_from_session"]
    assert "WARNING: the test command" in report.misra_compliance_markdown(eng.mem)


def test_doctor_shows_test_command_and_warns_on_change(proj):
    _write_cfg(proj, f"{sys.executable} -c pass")
    eng, _ = _session(proj)
    eng.mem.db.commit()

    def check():
        rep = doctor.diagnose(proj)
        return next(c for g in rep["groups"] for c in g["checks"] if c["name"] == "test command")
    c = check()
    assert c["status"] == "ok" and "sha256" in c["detail"] and "config.json modified" in c["detail"]
    _write_cfg(proj, "true")
    assert check()["status"] == "warn"


def test_old_sessions_without_hash_are_not_flagged(proj):
    eng = LoopEngine(proj)
    sid = eng.mem.create_session({"paths": ["src"]})
    _write_cfg(proj, "true")
    assert not report.test_command_info(eng.mem)["differs_from_session"]
    assert sid
    con = sqlite3.connect(proj / ".maishac" / "memory.db")
    con.close()
