# Security Policy

## Supported Versions

Maisha is pre-1.0 (current release: `0.5.0`) and maintains one supported
release line. Security fixes are made against `main` and shipped in the next
release of the latest minor version.

| Version         | Supported          |
| --------------- | ------------------ |
| `main` (latest) | :white_check_mark: |
| `0.5.x`         | :white_check_mark: |
| < `0.5.0`       | :x:                |

Releases before 0.5.0 lack the provenance tracking and human-accept gate
described under Scope below. Upgrade rather than wait for a backport.

Once Maisha reaches 1.0, this table will track supported minor lines and this
policy will be updated accordingly.

## Scope

Maisha is a compliance-workflow orchestrator, not a sandboxed service. Its
relevant attack surface is local, not network-facing:

- **Subprocess execution** — `maishac scan`/`session verify` shell out to
  `cppcheck` and `clang-tidy` on files you point it at, and `session begin
  --test-command` runs a command you configure (shlex-split, no shell, 600 s
  default timeout, process group killed on timeout). The test command can only
  be set by a human (CLI flag, `MAISHAC_TEST_COMMAND`, `.maishac/config.json`),
  never through an MCP tool; treat the command, that config file and scanned
  paths as trusted input, the same as any other local build tooling.
- **Agent sign-offs** — over MCP, approve/deviate/suppress/recategorize only
  create proposals a person must accept on the CLI, unless the operator sets
  `MAISHAC_ALLOW_AGENT_APPROVALS=1` (unsafe; flagged in reports). MISRA Mandatory
  guidelines can never be suppressed or deviated.
- **Trust boundary: the MCP surface only.** The sign-off gate assumes the agent can reach Maisha
  *only* through the MCP tools. Run the agent without shell access to the project, or in a sandbox
  where Maisha, `.maishac/` and your home directory are out of reach.
  MCP-originated scans are always gated (a rescan never resolves a finding by itself) and the
  `analyzer_only` policy is refused over MCP, unless `MAISHAC_ALLOW_AGENT_APPROVALS=1`.
  Under `test_gated`, an agent that can edit the test suite also controls what "passing" means for
  non-semantic findings; blocker/critical and semantic-risk findings always need a person.
- **Hardening against an agent with a shell (raises the cost, not a boundary).**
  - `maishac proposals accept` needs a person at a terminal: stdin must be a TTY and the person
    types the proposal id. Without a TTY it is refused unless `--yes`, `MAISHAC_HUMAN=1` and
    `MAISHAC_CONFIRM_TOKEN` are all given, and the token matches the salted scrypt hash (PBKDF2-SHA256, 600000 iterations, if scrypt is
    unavailable) a person
    registered with `maishac proposals set-token` (stored in `~/.maishac/confirm_token.json`,
    or `$MAISHAC_USER_DIR`, outside the project). On a TTY, `--yes` with `MAISHAC_HUMAN=1`
    skips the typed prompt.
  - The accept is audit-logged with the OS user, TTY or no TTY, confirmation method and time.
  - The effective test command (`MAISHAC_TEST_COMMAND` or `.maishac/config.json`) is hashed.
    A change is audit-logged (`test_command_change`: old and new hash, origin, config.json
    mtime), shown in `maishac doctor`, and sessions record the hash they started with. Reports
    carry a warning when the command now configured differs from the one the latest session
    started with.
- **Out of scope: an agent with arbitrary shell access as the same OS user.** It can edit
  `.maishac/memory.db` (including the audit log) or `.maishac/config.json` directly, read your
  environment, set `MAISHAC_HUMAN=1`, drive a pseudo-terminal to answer the prompt, or run the
  `maishac approve` command. The checks above make that visible and less accidental. They are
  not a defence, and the audit log is not tamper-proof. The confirm token only helps if the
  agent cannot read it: do not export `MAISHAC_CONFIRM_TOKEN` in a shell the agent shares.
  The token is stored as a salted, deliberately slow hash, which slows offline guessing but does
  not stop it: anyone who can read `confirm_token.json` can still guess a short or low-entropy
  token offline. Use a long random token.
- **SARIF import** (`maishac import`, `compliance_import_sarif`) parses
  external JSON/XML. Only import SARIF files from analyzers you trust.
- **Project memory** (`.maishac/memory.db`) is a local SQLite file with no
  access control beyond the filesystem; do not commit it, and treat it as
  sensitive if your findings/notes contain proprietary code excerpts.
- The **MCP server** (`maishac serve`) runs over stdio for a single local
  agentic IDE session — it is not designed or hardened to be exposed over a
  network transport.

If you find an issue outside this scope (e.g. in a bundled dependency), please
still report it — we'll help route it upstream if needed.

## Reporting a Vulnerability

Please report security issues privately using **GitHub Security Advisories**:

**https://github.com/WinterLabsHQ/maisha/security/advisories/new**

Do not open a public issue for a suspected vulnerability.

Include, if possible:

- A description of the issue and its potential impact
- Steps to reproduce (a minimal repro project/command is ideal)
- The Maisha version / commit SHA you tested against

### What to expect

- **Acknowledgement:** within 5 business days.
- **Status updates:** at least every 2 weeks while the report is triaged and
  fixed.
- **If accepted:** we'll agree a disclosure timeline with you, prepare a fix
  and a patched release, and credit you in the advisory (unless you prefer
  otherwise).
- **If declined:** we'll explain why (e.g. out of scope, not exploitable,
  working as intended) and remain open to discussion if you disagree.

Given the tool's disclaimed scope — Maisha is a workflow/orchestration layer,
not a certified static-analysis engine (see [README's Scope &
Limitations](README.md#scope--limitations)) — findings about *missed*
MISRA/CERT/BARR-C violations are a quality/coverage issue (see
[COVERAGE.md](COVERAGE.md) and [BENCHMARKS.md](BENCHMARKS.md)), not a security
vulnerability; please file those as a regular issue instead.
