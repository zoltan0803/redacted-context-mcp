# Redacted Context MCP

Read-only, redacted local knowledgebase context for coding agents.

`redacted-context-mcp` lets Claude Code, Codex, or another MCP client inspect a
private local knowledgebase through redacted tools instead of raw filesystem
reads. It is designed for the common case where a coding agent needs
architecture notes, meeting notes, transcripts, support history, project
documentation, or issue context, but should not see client names, stakeholder
names, email addresses, URLs, phone numbers, or meaningful filenames.

The core workflow is:

```text
agent workspace
  -> redacted MCP tools
    -> private source folder
      -> redacted output with opaque @p_<id> file references
```

## Features

- MCP stdio server with `redctx_*` tools.
- Redacted MCP resources using `redctx://p_<id>` URIs.
- Optional MCP `redctx_submit_doc` tool for controlled writes of generated
  redacted documents back into a configured private-root subdirectory.
- CLI fallback with the same redaction behavior.
- Local-salted opaque stable path ids such as `@p_1a2b3c4d5e6f`.
- Deterministic HMAC placeholders such as `[PERSON_1a2b3c4d]`.
- Redacted `tree`, `list`, `read`, `search`, `stat`, and `bundle` operations.
- CLI-only `rehydrate` command for restoring redacted exports locally from the
  private source root.
- Local ignored redaction config for exact client, person, organization, and
  project terms.
- Optional local-LLM discovery command to draft that config from private files
  without sending content to Claude or a hosted model.
- No runtime Python dependencies.
- Works well with a neutral agent workspace that does not contain raw context
  files.

## Who This Is For

Use this when you want an agent to reason over a private local folder without
handing the model the raw names and identifiers in that folder.

Good fits:

- consulting or client delivery knowledgebases;
- internal project notes, stakeholder notes, and transcripts;
- architecture or governance documentation with private names mixed in;
- private GitHub issues that should be summarized through neutral aliases.

Do not treat this as a formal anonymization or data-loss-prevention system.
Redaction is a practical workflow guardrail. For hard isolation, run the agent
as a separate OS user or in a container that cannot read the private source
folder directly.

## Install

After the package is published:

```sh
python3 -m pip install redacted-context-mcp
```

For isolated command installs, `pipx` also works:

```sh
pipx install redacted-context-mcp
```

Until then, install directly from the repository or from a checkout:

```sh
python3 -m pip install "git+https://github.com/zoltan0803/redacted-context-mcp.git"
```

```sh
python3 -m pip install -e .
```

This installs two console commands:

```sh
redctx      # CLI
redctx-mcp  # MCP stdio server
```

Python 3.11 or newer is required.

For `redctx discover`, install [Ollama](https://ollama.com/) separately and
pull a local model such as `gemma4:e4b`. The core redacted CLI and MCP server do
not require Ollama.

Model tags must match Ollama exactly. Check installed tags with `ollama list`
and pass the full value shown in the `NAME` column to `--model`.

## Recommended Layout

Use two sibling folders under a neutral parent:

```text
/work/
  agent-workdir/    # Claude Code starts here; no raw context files
  source-private/   # private project/context repository
```

The agent starts in `agent-workdir/`. The MCP server reads
`source-private/`, redacts output, and returns only redacted text.

Keep the private folder outside the active agent workspace when possible. If
the agent can still run shell commands against the raw private folder, the MCP
redaction layer is only an instruction-level guardrail, not a hard boundary.

## Claude Code MCP Config

If `redctx-mcp` is installed, put this in `agent-workdir/.mcp.json`:

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

If running directly from a source checkout without installing:

```json
{
  "mcpServers": {
    "redacted_context": {
      "type": "stdio",
      "command": "python3",
      "args": [
        "../redacted-context-mcp/src/redacted_context_mcp/server.py",
        "--root",
        "../source-private"
      ]
    }
  }
}
```

Then start Claude Code from the agent workspace:

```sh
cd /work/agent-workdir
claude
```

If Claude Code was already running, restart it or reconnect MCP servers with
`/mcp`.

For persistent Claude Code guidance, copy `examples/agent-CLAUDE.md` into
`agent-workdir/CLAUDE.md`.

## Codex MCP Config

Codex supports local stdio MCP servers through `config.toml`. Put this in
`~/.codex/config.toml`, or in `agent-workdir/.codex/config.toml` for a trusted
project-scoped setup:

```toml
[mcp_servers.redacted_context]
command = "redctx-mcp"
args = ["--root", "../source-private"]
enabled = true
required = true
```

If running directly from a source checkout without installing:

```toml
[mcp_servers.redacted_context]
command = "python3"
args = [
  "../redacted-context-mcp/src/redacted_context_mcp/server.py",
  "--root",
  "../source-private",
]
enabled = true
required = true
```

For persistent Codex guidance, copy `examples/agent-AGENTS.md` into
`agent-workdir/AGENTS.md`. Codex reads `AGENTS.md` when a session starts, so
restart Codex after adding or changing it.

## Generic MCP Clients

Any MCP client that can launch a stdio server can run:

```sh
redctx-mcp --root /absolute/path/to/source-private
```

Use the client-specific configuration format to pass that command and args.
The server advertises instructions and exposes only redacted `redctx_*` tools.

## MCP Tools

The server exposes:

- `redctx_tree` — show a redacted file tree with opaque ids
- `redctx_list` — list redacted directory entries
- `redctx_read` — read redacted file contents by path or `@p_<id>`
- `redctx_search` — search redacted text
- `redctx_stat` — inspect redacted metadata
- `redctx_bundle` — concatenate redacted context files
- `redctx_doctor` — show config counts without sensitive terms

Agents should carry `@p_<id>` references between calls rather than using raw
filenames.

The MCP server also exposes redacted text files as resources:

- `resources/list` returns `redctx://p_<id>` resource URIs with redacted titles.
- `resources/read` returns redacted file text for those opaque resource URIs.

### Controlled MCP Writes

By default, the MCP server exposes only read-only tools. To let an agent submit
new redacted documents back into the private source root, start the server with
an explicit write subdirectory:

```sh
redctx-mcp --root ../source-private --enable-writes --write-subdir incoming
```

This adds `redctx_submit_doc`. The tool accepts a relative `target_path`,
redacted `text`, and optional `overwrite`. The server rehydrates known
placeholders locally, rejects unresolved redaction tokens, and writes only under
the configured write subdirectory. Tool responses use redacted paths and opaque
ids; they do not return the raw restored path.

## CLI Fallback

The CLI is useful for smoke tests or clients without MCP:

```sh
redctx --root ../source-private doctor
redctx --root ../source-private tree context --max-depth 2
redctx --root ../source-private search "governance" context --ignore-case --context 2
redctx --root ../source-private read @p_1a2b3c4d5e6f --start-line 1 --end-line 80
redctx --root ../source-private bundle context --glob "*.md" --max-files 10
```

### Local Rehydration

The `rehydrate` command restores redacted text by scanning the private source
root with the same salt and config, rebuilding the placeholder map, and applying
it to a redacted file or folder. This emits raw private text, so it is CLI-only
and requires an explicit acknowledgement flag.

```sh
redctx --root ../source-private rehydrate ./redacted-output.md --allow-raw-output > raw-output.md
redctx --root ../source-private rehydrate ./redacted-folder \
  --output ./raw-folder \
  --allow-raw-output
```

Rehydration is not cryptographic reversal. A redacted file alone is not enough;
the command needs access to the original private root or equivalent local
source material to rebuild the mapping.

## Local Redaction Config

Create `.agent-context-redactor.toml` in the private source root. This file is
ignored by the example `.gitignore` because it may contain exact sensitive
terms.

```toml
[redaction]
salt = "local-random-string-kept-private"
clients = ["Client Legal Name", "Client Acronym"]
organizations = ["Supplier Name", "Partner Company"]
people = ["Person One", "Person Two"]
terms = ["project codename", "internal programme name"]
allow = ["Azure", "PostgreSQL", "Kubernetes"]
term_files = ["private-redaction-terms.txt"]

[github.repos.context]
owner = "private-org-or-user"
repo = "private-context-repo"
token_env = "GITHUB_TOKEN"
```

The tool also derives likely aliases from the private source folder name and
accepts additional comma- or newline-separated terms through
`REDACTED_CONTEXT_TERMS`.

The optional `salt` controls opaque path ids and deterministic placeholders. If
omitted, a local fallback is derived from the private root/config. You can also
set `REDACTED_CONTEXT_SALT` in the environment that starts `redctx` or
`redctx-mcp`.

GitHub repo entries are optional. Use neutral aliases such as `context`; agents
use the alias, while the real `owner/repo` stays in this local config. Private
repos require the named token environment variable in the shell that starts
`redctx` or `redctx-mcp`.

## Redacted GitHub Issues

Configured GitHub issues can be read through the same redaction layer:

```sh
export GITHUB_TOKEN="<github-token>"
redctx --root ../source-private github repos
redctx --root ../source-private github issues context --state open --limit 20
redctx --root ../source-private github issue context 123 --comments
redctx --root ../source-private github search context "policy controls"
```

The MCP server exposes the same flow with:

- `redctx_github_repos`
- `redctx_github_list_issues`
- `redctx_github_read_issue`
- `redctx_github_search_issues`

Outputs redact titles, bodies, labels, and comments. Raw author logins and raw
GitHub URLs are not printed; authors are shown as stable opaque ids.

## Discover Terms With A Local LLM

`redctx discover` can draft `.agent-context-redactor.toml` using a local
Ollama model. This is a human setup command, not an MCP tool, because its output
intentionally contains the raw names you want to redact.

Example with a small local model:

```sh
ollama pull gemma4:e4b
redctx --root ../source-private discover context progress archive \
  --model gemma4:e4b \
  --glob "*.md" \
  --output .agent-context-redactor.toml
```

If you switch models, use the exact tag from `ollama list`.

Review the generated file before use. To avoid overwriting an existing config,
the command refuses to write over `--output` unless `--force` is passed.

Discovery output is post-processed with generic cleanup rules. The cleanup
does not include project-specific names; it only:

- omits public/default-allowed terms that the redactor already allows;
- moves other likely tool/package names to `allow`;
- drops obvious filenames, meeting/ticket IDs, country-only values, job titles,
  and generic workflow/process labels;
- strips role notes from full names such as `Alice Example (CIO)`;
- ignores single first names by default because they over-redact.

Use `--raw-discovery` if you want the local model's categories with only basic
dedupe.

Useful options:

```sh
redctx --root ../source-private discover --help
redctx --root ../source-private discover context --format json
redctx --root ../source-private discover context --raw-discovery
redctx --root ../source-private discover context --max-files 20 --max-chars-per-file 8000
redctx --root ../source-private discover context --endpoint http://localhost:11434
```

The command uses Ollama's local `/api/generate` endpoint with streaming disabled
and JSON output requested. No hosted LLM is called by this feature.

## Claude Code Permissions

MCP routing is the main workflow. Claude Code permissions can add guardrails by
denying direct reads/searches into the private source folder and allowing only
the redacted MCP tools. See
[examples/claude-settings.example.json](examples/claude-settings.example.json).

## Security Model

This project is a practical privacy guardrail, not a formal de-identification
system.

It helps because:

- the agent starts in a neutral folder with no raw context files;
- the useful operations are exposed as redacted MCP tools;
- filenames can be navigated through opaque ids;
- raw names, emails, URLs, phones, and configured terms are redacted.

The `rehydrate` command intentionally reverses redacted exports for the local
operator. `redctx_submit_doc` can also rehydrate generated redacted text, but
only when MCP writes are explicitly enabled and only into the configured write
subdirectory. Do not run rehydration workflows from an agent workspace where the
model can read raw output.

It is not a hard security boundary if the agent process runs as the same OS
user that can read the private source folder. For hard enforcement, run the
agent as a separate OS user or container without filesystem access to the
private source folder, and expose only the MCP server or a separate redaction
service.

## Development

See `ARCHITECTURE.md` for the design boundaries and `CONTRIBUTING.md` for local
development and release checks.

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m py_compile src/redacted_context_mcp/core.py src/redacted_context_mcp/server.py
```

## License

MIT.
