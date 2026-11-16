# IDE integration snippets

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
`maishac proposals list` and `maishac proposals accept <id> --by <name>`. The test
command is not settable by the agent either: use `--test-command`,
`MAISHAC_TEST_COMMAND` or `.maishac/config.json`. To let the agent decide for
itself (unsafe, flagged in every report) add `"MAISHAC_ALLOW_AGENT_APPROVALS": "1"`
to the `env` block of the server entry.

After connecting, paste `AGENT_PLAYBOOK.md` into your agent's rules file and ask
it to begin a compliance session.
