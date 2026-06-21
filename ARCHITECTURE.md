# Architecture

`redacted-context-mcp` exposes a private local knowledgebase through a narrow
redaction layer. The default MCP surface is read-only; controlled writes are
available only when the server is started with explicit write flags. The project
is intentionally small: it avoids runtime dependencies, stores no persistent
index, and keeps all sensitive configuration local.

## Data Flow

```text
agent workspace
  -> MCP client or redctx CLI
    -> redaction layer
      -> private source root
        -> redacted text plus opaque path references
```

The agent should start from a neutral workspace that does not contain the raw
private context files. The MCP server receives tool calls, resolves paths inside
the configured root, reads allowed text files, redacts output, and returns only
the redacted result. If controlled writes are enabled, generated redacted text
can be rehydrated locally and written under a configured private-root
subdirectory.

## Core Boundaries

- The server is read-only by default.
- Controlled MCP writes require `--enable-writes` and are constrained to
  `--write-subdir`.
- Path resolution is constrained to the configured root.
- Known private/cache paths and binary-like files are excluded by default.
- File navigation uses local-salted HMAC ids such as `@p_1a2b3c4d5e6f`.
- Filesystem traversal starts from validated paths, skips symlink and reparse
  entries, and revalidates paths before content reads and opaque-id resolution.
- Redacted files are available as MCP resources with `redctx://p_<id>` URIs.
- MCP resource content is cached only after redaction and is bounded by byte
  limits.
- Redaction happens before file content, file paths, search results, bundles,
  and GitHub issue text are returned.

## Module Layout

- `core.py`: CLI commands, parser setup, and compatibility re-exports.
- `server.py`: minimal stdio MCP JSON-RPC server.
- `defaults.py`: default limits, allow lists, exclude lists, and compiled
  patterns.
- `models.py`: shared dataclasses.
- `redaction.py`: text/path redaction logic.
- `config.py`: local TOML config loading and validation.
- `paths.py`: root-constrained path resolution and opaque path ids.
- `filesystem.py`: read-only filesystem traversal and text-file detection.
- `discovery.py`: local Ollama discovery workflow and post-processing.
- `github.py`: read-only GitHub issue access through neutral aliases.

## Controlled Write Path

`redctx_submit_doc` is hidden unless the server starts with `--enable-writes`.
When enabled, it accepts generated redacted text, rebuilds the local
rehydration map from the private source root, rejects unresolved placeholders,
and writes the restored document only under `--write-subdir`.

The write tool does not accept arbitrary workspace file paths. It accepts text
content directly and a relative target path. Overwrites require an explicit
`overwrite` argument. Tool results return only redacted path metadata and opaque
ids.

## Redaction Model

Redaction combines configured exact terms with conservative generic patterns:

- configured clients, organizations, people, and sensitive terms;
- email addresses, URLs, phone numbers, handles, secrets, tokens, common
  personal identifiers, IP addresses, UUIDs, and domains;
- organization suffix patterns;
- multi-token proper names;
- stricter titlecase/acronym handling in `strict` mode.

The allow list prevents common public technologies and generic vocabulary from
being over-redacted. Project-specific allow-list entries belong in the local
`.agent-context-redactor.toml`, not in source control.

Placeholders are deterministic 128-bit HMAC aliases derived from the local
salt, for example `[PERSON_1a2b3c4d5e6f7890a1b2c3d4e5f60718]`. The same raw
value maps to the same placeholder for one private config without exposing the
raw value. Placeholder collisions are detected and fail closed instead of
building an ambiguous rehydration map.

## Configuration

The local `.agent-context-redactor.toml` file is intentionally ignored by git.
It may contain exact client names, stakeholder names, project codenames, private
repo names, and token environment variable names.

If a config or environment salt is not supplied, the loader creates or reuses a
random 256-bit vault salt in user-local state. Salt creation uses an exclusive
lock and atomic replacement; empty, malformed, or root-contained state files
fail closed instead of rotating aliases silently. `redctx doctor` reports the
salt source.

`redctx discover` can draft that file with a local Ollama model. It is a setup
command for a human operator, not an MCP tool, because its output intentionally
contains raw sensitive terms.

## GitHub Issue Access

GitHub repositories are configured by neutral aliases under
`[github.repos.<alias>]`. The alias is what the agent sees. Raw owner/repo names
and author logins are not printed in tool output. Author aliases are HMACs over
the local vault salt, repo alias, and login so they are not linkable across
vaults or repo aliases.

The GitHub integration is read-only and uses the token environment variable
named in local config.

## Security Posture

This project is a privacy guardrail, not a hard isolation boundary. If the agent
process can read the private source folder directly, prompts and MCP routing
are not enough. For stronger enforcement, run the agent as a separate OS user or
inside a container that cannot access the private folder directly, and expose
only the redacted MCP server.
