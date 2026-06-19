# Architecture

`redacted-context-mcp` exposes a private local knowledgebase through a narrow,
read-only redaction layer. The project is intentionally small: it avoids runtime
dependencies, stores no index, and keeps all sensitive configuration local.

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
the redacted result.

## Core Boundaries

- The server is read-only. It does not edit, delete, or move source files.
- Path resolution is constrained to the configured root.
- Known private/cache paths and binary-like files are excluded by default.
- File navigation uses local-salted HMAC ids such as `@p_1a2b3c4d5e6f`.
- Redacted files are available as MCP resources with `redctx://p_<id>` URIs.
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

Placeholders are deterministic HMAC aliases derived from the local salt, for
example `[PERSON_1a2b3c4d]`. The same raw value maps to the same placeholder for
one private config without exposing the raw value.

## Configuration

The local `.agent-context-redactor.toml` file is intentionally ignored by git.
It may contain exact client names, stakeholder names, project codenames, private
repo names, and token environment variable names.

`redctx discover` can draft that file with a local Ollama model. It is a setup
command for a human operator, not an MCP tool, because its output intentionally
contains raw sensitive terms.

## GitHub Issue Access

GitHub repositories are configured by neutral aliases under
`[github.repos.<alias>]`. The alias is what the agent sees. Raw owner/repo names
and author logins are not printed in tool output.

The GitHub integration is also read-only and uses the token environment
variable named in local config.

## Security Posture

This project is a privacy guardrail, not a hard isolation boundary. If the agent
process can read the private source folder directly, prompts and MCP routing
are not enough. For stronger enforcement, run the agent as a separate OS user or
inside a container that cannot access the private folder directly, and expose
only the redacted MCP server.
