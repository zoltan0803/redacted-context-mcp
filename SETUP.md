# Setup Guide

This guide walks through the recommended two-folder setup for Claude Code,
Codex, or another local MCP client.

## 1. Create The Folder Layout

Use neutral names where possible:

```text
/work/
  agent-workdir/
  source-private/
```

`agent-workdir/` is where the coding agent runs. `source-private/` contains
the private context repository or documentation tree.

Do not copy private context folders into `agent-workdir/`.

For stronger isolation, make sure the agent process cannot read
`source-private/` directly. Redaction is a useful workflow guardrail, but it is
not a hard security boundary if the agent can still run raw shell reads against
the private folder.

## 2. Install The Tool

From the `redacted-context-mcp` checkout:

```sh
python3 -m pip install -e .
```

Confirm commands are available:

```sh
redctx --help
redctx-mcp --help
```

Optional, for local entity discovery:

```sh
ollama pull gemma4:e4b
```

## 3. Configure MCP

### Claude Code

Create `agent-workdir/.mcp.json`:

```json
{
  "mcpServers": {
    "redacted_context": {
      "type": "stdio",
      "command": "redctx-mcp",
      "args": [
        "--root",
        "../source-private"
      ]
    }
  }
}
```

### Codex

Add this to `~/.codex/config.toml`, or to
`agent-workdir/.codex/config.toml` for a trusted project-scoped setup:

```toml
[mcp_servers.redacted_context]
command = "redctx-mcp"
args = ["--root", "../source-private"]
enabled = true
required = true
```

See `examples/codex-config.example.toml`.

### Other MCP Clients

Configure the client to launch this stdio command:

```sh
redctx-mcp --root /work/source-private
```

## 4. Add Agent Guardrails

Create `agent-workdir/.claude/settings.local.json` from the example:

```sh
mkdir -p /work/agent-workdir/.claude
cp examples/claude-settings.example.json /work/agent-workdir/.claude/settings.local.json
```

Adjust `source-private` paths if you chose a different folder name.

For Claude Code, copy the example `CLAUDE.md`:

```sh
cp examples/agent-CLAUDE.md /work/agent-workdir/CLAUDE.md
```

For Codex, copy the example `AGENTS.md`:

```sh
cp examples/agent-AGENTS.md /work/agent-workdir/AGENTS.md
```

Restart Claude Code or Codex after adding or changing the guidance file.

## 5. Add Exact Redaction Terms

Create `/work/source-private/.agent-context-redactor.toml`:

```toml
[redaction]
salt = "local-random-string-kept-private"
clients = ["Client Legal Name", "Client Acronym"]
organizations = ["Supplier Name", "Partner Company"]
people = ["Person One", "Person Two"]
terms = ["project codename", "internal programme name"]
allow = ["Azure", "PostgreSQL", "Kubernetes"]

[github.repos.context]
owner = "private-org-or-user"
repo = "private-context-repo"
token_env = "GITHUB_TOKEN"
```

Keep this file local and untracked.

The optional `salt` keeps opaque path ids and placeholders stable for your
private context without making them guessable from common filenames. You can
also provide it with `REDACTED_CONTEXT_SALT`.

The GitHub section is optional. If you enable it for a private repo, export the
token in the shell that starts the agent or MCP server:

```sh
export GITHUB_TOKEN="<github-token>"
redctx --root /work/source-private github issues context --limit 10
```

You can draft this file with a local Ollama model instead of writing all names
manually:

```sh
ollama pull gemma4:e4b
redctx --root /work/source-private discover context progress archive \
  --model gemma4:e4b \
  --glob "*.md" \
  --output .agent-context-redactor.toml
```

If you switch models, run `ollama list` and use the exact value shown in the
`NAME` column for `--model`.

Review the generated file before use. It intentionally contains raw names, so
run this yourself during setup rather than asking an agent to run it.

The generated output is cleaned with generic rules that omit public terms
already allowed by default, move other likely tool/package names to `allow`, and
drop obvious filenames, meeting IDs, roles, countries, and generic
workflow/process labels. Use `--raw-discovery` if you want the local model's
unfiltered categories.

## 6. Verify

From `agent-workdir/`:

```sh
redctx --root ../source-private doctor
redctx --root ../source-private tree . --max-depth 2
claude mcp list
```

Expected MCP line:

```text
redacted_context: redctx-mcp --root ../source-private - ✓ Connected
```

For Codex, start a session and use `/mcp` in the TUI to inspect configured MCP
servers.

## 7. Start The Agent

```sh
cd /work/agent-workdir
claude
# or
codex
```

Ask the agent to use `redctx_*` tools for project context.
