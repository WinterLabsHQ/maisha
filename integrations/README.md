# IDE integration snippets

Install the optional MCP extra first: `pipx install 'maishac[mcp]'` (or
`pip install 'maishac[mcp]'`). The package pins `mcp>=1.2.0,<2`; without the
extra, `maishac serve` exits with an install hint.

All hosts use the same stdio MCP server: command `maishac`, args `["serve"]`,
env `MAISHAC_PROJECT` pointing at the project root to scan.

- **Claude Code** — copy `claude-code.mcp.json` contents into `.mcp.json` at your
  project root (Claude Code substitutes the workspace path automatically; if your
  version doesn't support `${workspaceFolder}`, use an absolute path).
- **Cursor** — merge `cursor.mcp.json` into `~/.cursor/mcp.json` (or the
  per-project `.cursor/mcp.json`), with an absolute project path.
- **Anything else (Windsurf, Zed, custom hosts)** — `generic-mcp.json` shows the
  three fields every MCP host asks for.

**Sign-offs need a human.** Through MCP the approve / deviate / suppress /
recategorize tools only create proposals; a person finalizes them with
`maishac proposals list` and `maishac proposals accept <id> --by <name>` (interactive
terminal confirmation; see SECURITY.md for the non-interactive token mode). The test
command is not settable by the agent either: use `--test-command`,
`MAISHAC_TEST_COMMAND` or `.maishac/config.json`. To let the agent decide for
itself (unsafe, flagged in every report) add `"MAISHAC_ALLOW_AGENT_APPROVALS": "1"`
to the `env` block of the server entry.

Tool arguments that name files (`paths`, `exclude`, `compile_commands`, SARIF
`path`, `-I` flags) must stay inside the project root unless the server's `env`
sets `MAISHAC_ALLOW_OUTSIDE_PROJECT=1`. Tools run one at a time on a worker thread,
so a long scan does not freeze the connection. `.maishac/config.json` is only
human-controlled if the agent cannot write to the project directory.

After connecting, paste `AGENT_PLAYBOOK.md` into your agent's rules file and ask
it to begin a compliance session.
