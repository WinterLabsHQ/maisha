"""Human-confirmation and test-command integrity helpers.

Scope, stated plainly: these checks raise the cost of an agent that has a shell
and wants to grade its own work, and they leave a record. They cannot stop an
agent that can run arbitrary commands as the same OS user (it can edit
`.maishac/memory.db` or `.maishac/config.json` directly). See SECURITY.md.

Accepting an agent proposal (`maishac proposals accept`) needs one of:

1. an interactive terminal: stdin is a TTY and the person types the proposal id;
2. no TTY (CI, scripts): ``--yes`` AND ``MAISHAC_HUMAN=1`` AND a confirm token.
   The token is set once by a person on a terminal with
   ``maishac proposals set-token``; only a salted scrypt hash is stored, in the
   user's own directory (``~/.maishac/``, or ``MAISHAC_USER_DIR``), not in the
   project. It is supplied through ``MAISHAC_CONFIRM_TOKEN``.

On a TTY, ``--yes`` together with ``MAISHAC_HUMAN=1`` skips the typed prompt.
"""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from pathlib import Path

HUMAN_ENV = "MAISHAC_HUMAN"
TOKEN_ENV = "MAISHAC_CONFIRM_TOKEN"
USER_DIR_ENV = "MAISHAC_USER_DIR"
_TRUE = ("1", "true", "yes")


def user_dir() -> Path:
    return Path(os.environ.get(USER_DIR_ENV) or (Path.home() / ".maishac"))


def _token_path() -> Path:
    return user_dir() / "confirm_token.json"


_SCRYPT = (2**14, 8, 1)  # n, r, p
_PBKDF2_ITERATIONS = 600_000
_REHASH_HINT = "run `maishac proposals set-token` again"


def _kdf(token: str, scheme: str, params: tuple[int, ...], salt: bytes) -> bytes:
    data = token.encode("utf-8")
    if scheme == "scrypt":
        n, r, p = params
        return hashlib.scrypt(data, salt=salt, n=n, r=r, p=p, dklen=32,
                              maxmem=128 * n * r * 2 + (1 << 20))
    if scheme == "pbkdf2":
        return hashlib.pbkdf2_hmac("sha256", data, salt, params[0], dklen=32)
    raise ValueError("unknown scheme")


def _hash_token(token: str) -> str:
    """-> ``scheme$params$salt_hex$hash_hex``; scrypt, or PBKDF2 when scrypt is missing."""
    salt = secrets.token_bytes(16)
    try:
        h = _kdf(token, "scrypt", _SCRYPT, salt)
        return "scrypt$" + "$".join(str(x) for x in _SCRYPT) + f"${salt.hex()}${h.hex()}"
    except (AttributeError, ValueError, MemoryError):  # scrypt not in this OpenSSL build
        h = _kdf(token, "pbkdf2", (_PBKDF2_ITERATIONS,), salt)
        return f"pbkdf2${_PBKDF2_ITERATIONS}${salt.hex()}${h.hex()}"


def _parse_record(record: object) -> tuple[str, tuple[int, ...], bytes, bytes]:
    """Parse a stored record; raise ValueError for anything not in the current format."""
    if not isinstance(record, str):
        raise ValueError("not a record")
    parts = record.split("$")
    if parts[0] == "scrypt" and len(parts) == 6:
        params = tuple(int(x) for x in parts[1:4])
    elif parts[0] == "pbkdf2" and len(parts) == 4:
        params = (int(parts[1]),)
    else:
        raise ValueError("unrecognised record")
    salt, digest = bytes.fromhex(parts[-2]), bytes.fromhex(parts[-1])
    if len(salt) < 16 or len(digest) != 32 or min(params) < 1:
        raise ValueError("malformed record")
    return parts[0], params, salt, digest


def _load_record() -> tuple[str, tuple[int, ...], bytes, bytes] | None:
    try:
        d = json.loads(_token_path().read_text("utf-8"))
        return _parse_record(d.get("hash"))
    except (OSError, ValueError, AttributeError, TypeError):
        return None


def set_confirm_token(token: str) -> Path:
    """Store a salted scrypt (or PBKDF2) hash of ``token`` for non-interactive accepts."""
    if len(token) < 8:
        raise ValueError("the confirm token must be at least 8 characters.")
    path = _token_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"hash": _hash_token(token)}), "utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def token_configured() -> bool:
    """True only for a valid record in the current format; an old one counts as none."""
    return _load_record() is not None


def verify_confirm_token(token: str) -> bool:
    rec = _load_record()
    if rec is None:
        return False
    scheme, params, salt, digest = rec
    try:
        return hmac.compare_digest(_kdf(token or "", scheme, params, salt), digest)
    except (ValueError, AttributeError, MemoryError):
        return False


def _is_tty() -> bool:
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False


def human_signal() -> bool:
    return os.environ.get(HUMAN_ENV, "").strip().lower() in _TRUE


def os_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # no passwd entry, no env: still record that it was unknown
        return "unknown"


def actor_context(method: str) -> dict:
    """Who confirmed, for the audit log."""
    return {"os_user": os_user(), "tty": _is_tty(), "confirm_method": method,
            "confirmed_at": time.time()}


def confirm_accept(pid: str, summary: str, yes: bool) -> tuple[dict | None, str]:
    """-> (actor context, "") when the accept is confirmed, else (None, why not)."""
    tty = _is_tty()
    if tty:
        if yes and human_signal():
            return actor_context("tty-yes"), ""
        print(f"Proposal {pid}: {summary}", file=sys.stderr)
        try:
            answer = input(f"Type the proposal id ({pid}) to accept it, anything else cancels: ")
        except EOFError:
            answer = ""
        if answer.strip() != pid:
            return None, "Cancelled: the proposal id was not typed; nothing was accepted."
        return actor_context("tty-prompt"), ""
    # no terminal: only the documented human-only token channel is accepted
    if not (yes and human_signal()):
        return None, ("Refusing to accept without a terminal. Run this in an interactive "
                      f"shell, or non-interactively pass --yes with {HUMAN_ENV}=1 and "
                      f"{TOKEN_ENV} set to the token registered with "
                      "`maishac proposals set-token`.")
    if not token_configured():
        return None, ("No valid confirm token is registered (a token from an older format is "
                      "not accepted). A person must run `maishac proposals set-token` "
                      "in an interactive shell first.")
    if not verify_confirm_token(os.environ.get(TOKEN_ENV, "")):
        return None, f"{TOKEN_ENV} is missing or does not match the registered token."
    return actor_context("token"), ""


# ------------------------------------------------------------- test command
def sha(text: str | None) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest() if text else ""


def test_command_state(root: str | Path) -> dict:
    """The project-level test command (environment, then .maishac/config.json) with
    its provenance. ``sha256`` is "" when none is set. A command given with the
    CLI flag lives only in a session and is recorded there."""
    root = Path(root)
    cfg_path = root / ".maishac" / "config.json"
    cfg_cmd = None
    try:
        data = json.loads(cfg_path.read_text("utf-8"))
        if isinstance(data, dict) and data.get("test_command"):
            cfg_cmd = str(data["test_command"])
    except (OSError, ValueError):
        pass
    try:
        mtime = cfg_path.stat().st_mtime
    except OSError:
        mtime = None
    env_cmd = os.environ.get("MAISHAC_TEST_COMMAND", "").strip()
    cmd = env_cmd or cfg_cmd
    return {"configured": bool(cmd), "command": cmd or None,
            "source": "env" if env_cmd else ("config" if cfg_cmd else None),
            "sha256": sha(cmd), "config_mtime": mtime if cfg_cmd else None,
            "config_file_mtime": mtime}
